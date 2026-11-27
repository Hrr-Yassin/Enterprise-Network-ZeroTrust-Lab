"""Run the acceptance suite and assemble evidence inside the detached guest."""

import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from lab import ansible, ids, observability, visible_browser
from lab.guest import PYTHON, RUN, SECRETS, TELEMETRY, command, guard, run, source_namespace, start, write_json
from lab.model import address, endpoint, firewall
from lab.probe import perform
from lab.runtime import emit
from lab.sensor import CANARY, SIGNATURE
from lab.services import Fixtures

CAPTURE_FILTER = (
    "udp and src host 10.77.20.10 and dst host 10.77.40.10 and dst port 53 "
    "and udp[20:2] = 0x0969 and udp[22:4] = 0x64732d63 and udp[26:4] = 0x6865636b"
)


def probe(lab, source, protocol, host, port, *options):
    with source_namespace(lab.namespace(source)):
        return perform(lab.policy, protocol, host, port, *options)


def http(lab, source, service, identity="-", path="/", host=None, name=None):
    destination = lab.services[service]
    options = (service, identity, path)
    if name:
        options += (name,)
    return probe(lab, source, "http", host or address(lab.policy, destination["node"]), destination["port"], *options)


def dns(lab, source, protocol="udp", name="app.lab.test"):
    return probe(lab, source, "dns", address(lab.policy, "resolver"), lab.services["dns"]["port"], protocol, name)


def status(result):
    return result.get("status", result["result"])


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def await_sample(path, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            data = json.loads(path.read_text())
            if predicate(data):
                return data
        time.sleep(0.08)
    raise AssertionError(f"Expected telemetry did not appear in {path.name}")


def provision(lab):
    fixtures = Fixtures(lab)
    fixtures.provision()
    log = TELEMETRY / "events/sensor.log"
    with log.open("ab") as output:
        sensor = start("monitor", PYTHON, "-m", "lab.sensor", stdout=output, stderr=output)
    try:
        await_sample(TELEMETRY / "sensor.json", lambda _data: True, timeout=14)
    except AssertionError as error:
        raise RuntimeError(f"Passive sensor exited {sensor.poll()}: {log.read_text()[-900:]}") from error
    snapshot(lab)
    return fixtures


def verify_ids(lab):
    engines = ids.start_engines()
    try:
        reply = dns(lab, "employee", name=CANARY)
        expect(reply.get("answers") == [address(lab.policy, "api")], f"Canary DNS fixture returned {reply}")
        return ids.check(engines, address(lab.policy, "employee"), address(lab.policy, "resolver"),
                         lambda: dns(lab, "employee"))
    finally:
        ids.stop_engines(engines)


def snapshot(lab):
    probes = {
        "Application": lambda: status(http(lab, "monitor", "app", "observer", "/health")) == 200,
        "Admin service": lambda: status(http(lab, "admin", "ops", "operator", "/health")) == 200,
        "Restricted tier": lambda: status(http(lab, "admin", "vault", "operator", "/health")) == 200,
        "Public DMZ": lambda: status(http(lab, "outside", "public_web", path="/health",
                                           host=address(lab.policy, "edge"))) == 200,
        "Lab DNS": lambda: address(lab.policy, "api") in dns(lab, "employee").get("answers", []),
        "Guest egress": lambda: status(http(lab, "guest", "egress", path="/health")) == 200,
    }
    availability = {}
    for name, action in probes.items():
        started = time.monotonic()
        availability[name] = {"up": action(), "latency_ms": round(1000 * (time.monotonic() - started), 1)}
    memory = {line.partition(":")[0]: int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
              if line.startswith(("MemTotal:", "MemAvailable:"))}
    data = {
        "sampled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "segments": lab.segment_status(), "firewall": lab.firewall_metrics(), "firewall_events": lab.firewall_events(),
        "vpn": lab.peer_status(), "sensor": json.loads((TELEMETRY / "sensor.json").read_text()),
        "ids": ids.telemetry(),
        "health": availability, "compliant": lab.fingerprint() == lab.baseline,
        "infrastructure": {"memory_total_mib": round(memory["MemTotal"] / 1024),
                           "memory_available_mib": round(memory["MemAvailable"] / 1024),
                           "load_one_minute": float(Path("/proc/loadavg").read_text().split()[0]),
                           "uptime_seconds": round(float(Path("/proc/uptime").read_text().split()[0]), 1)},
    }
    write_json(TELEMETRY / "status.json", data)
    return data


class Suite:
    def __init__(self, lab, fixtures):
        self.lab = lab
        self.fixtures = fixtures
        self.checks = []

    def check(self, name, area, operation, row=None):
        try:
            details = operation()
            passed = True
        except (AssertionError, OSError, RuntimeError, ValueError) as error:
            details = str(error)
            passed = False
            print(f"ZTLAB FAIL {name} {details[:380]}", flush=True)
        self.checks.append({"id": name, "area": area, "policy_row": row, "passed": passed, "result": details})

    def permits(self):
        for rule in self.lab.policy["permits"]:
            for protocol in rule["protocols"]:
                self.check(f'{rule["id"]}_{protocol}', "allow",
                           lambda rule=rule, protocol=protocol: self.permit(rule, protocol), row=rule["id"])

    def permit(self, rule, protocol):
        lab = self.lab
        name, source = rule["service"], rule["from"]
        service = lab.services[name]
        host, port = endpoint(lab.policy, rule, True)
        prior = lab.counters()[rule["id"]]
        if service["kind"] == "dns":
            outcome = dns(lab, source, protocol)
            expect(outcome.get("answers") == [address(lab.policy, "api")], f"Expected internal DNS answer: {outcome}")
            detail = f'DNS {protocol.upper()} returned {outcome["answers"][0]}'
        elif service["kind"] == "wireguard":
            peer_id, peer = next((key, value) for key, value in lab.peers.items() if value["transport"] == source)
            response = http(lab, peer_id, peer["service"], peer["identity"])
            state = lab.peer_status()[peer_id]
            expect(status(response) == 200 and state["handshake_recent"] and state["rx_bytes"] > 0,
                   f"Expected a WireGuard handshake and application response: {status(response)}, {state}")
            detail = f"{peer_id} authenticated and used its assigned service"
        else:
            response = http(lab, source, name, rule.get("identity", "-"), rule.get("path", "/"), host=host)
            expect(status(response) == 200, f"Expected HTTP 200 on {host}:{port}: {status(response)}")
            detail = "HTTP 200"
            if rule.get("nat") in {"snat", "dnat"}:
                source_address = (address(lab.policy, "edge") if rule["nat"] == "snat"
                                  else address(lab.policy, source))
                payload = json.loads(response["body"])
                expect(payload["observed_source"] == source_address and payload["service"] == name,
                       f"NAT result did not match translated session: {payload}")
                detail += f"; {rule['nat'].upper()} backend saw {source_address}"
        delta = lab.counters()[rule["id"]] - prior
        expect(delta > 0, f"Allow rule {rule['id']} did not see the flow")
        return f"{detail}; allow counter +{delta}"

    def denials(self):
        for rule in self.lab.policy["denials"]:
            self.check(rule["id"], "drop", lambda rule=rule: self.deny(rule), row=rule["id"])

    def deny(self, rule):
        lab = self.lab
        host, port = endpoint(lab.policy, rule, False)
        bucket = "deny_input" if host == address(lab.policy, "edge") else "deny_forward"
        before = lab.counters()[bucket]
        if rule["service"] == "dns":
            result = probe(lab, rule["from"], "dns", host, port, rule["protocol"], "app.lab.test")
        else:
            result = probe(lab, rule["from"], rule["protocol"], host, port)
        delta = lab.counters()[bucket] - before
        expect(result["result"] == "timeout" and delta > 0, f"{host}:{port} returned {result}; drop counter +{delta}")
        return f"Timed out at {host}:{port}; {bucket} +{delta}"

    def identity(self, source, service, role, expected, path="/", name=None):
        result = http(self.lab, source, service, role, path, name=name)
        expect(status(result) == expected, f"Expected {expected}, got {status(result)}")
        return f"{role} returned {expected}" + (f" ({result['reason']})" if "reason" in result else "")

    def certificate_revocation(self):
        self.fixtures.role_status("app", "employee", False)
        try:
            self.identity("employee", "app", "employee", 403)
            self.identity("user_vpn", "app", "remote_user", 200)
        finally:
            self.fixtures.role_status("app", "employee", True)
        self.identity("employee", "app", "employee", 200)
        return "Removed certificate fingerprint, observed HTTP 403, preserved other role and restored HTTP 200"

    def peer_revocation(self):
        lab = self.lab
        self.identity("user_vpn", "app", "remote_user", 200)
        lab.revoke_peer("user_vpn")
        try:
            result = http(lab, "user_vpn", "app", "remote_user")
            expect(status(result) in {"timeout", "os_error"} and not lab.peer_status()["user_vpn"]["authorized"],
                   f"Revoked WireGuard peer remained authorized: {status(result)}")
            self.identity("ops_vpn", "ops", "operator", 200)
        finally:
            lab.authorize_peer("user_vpn")
            lab.configure_remote_peer("user_vpn", reset=True)
        for _ in range(10):
            result = http(lab, "user_vpn", "app", "remote_user")
            if status(result) == 200:
                restored = lab.peer_status()["user_vpn"]
                events = [json.loads(line) for line in (TELEMETRY / "vpn-events.jsonl").read_text().splitlines()]
                expect(restored["handshake_recent"] and any(not event["authorized"] and event["peer"] == "user_vpn"
                                                            for event in events),
                       "WireGuard observation log did not capture revocation and the restored handshake")
                return "Removed one peer from live WireGuard; that peer lost access, ops remained active, then reauthorized"
            time.sleep(0.6)
        raise AssertionError("The restored peer did not renegotiate its session")

    def valid_admin_from_guest(self):
        before = self.lab.counters()["deny_forward"]
        result = http(self.lab, "guest", "ops", "operator")
        expect(status(result) == "timeout" and self.lab.counters()["deny_forward"] > before,
               "Valid application identity bypassed the Guest firewall boundary")
        return "Operator certificate could not reach the management endpoint from Guest"

    def unassigned_source(self):
        lab = self.lab
        client = address(lab.policy, "guest")
        alternate = client.rsplit(".", 1)[0] + ".11"
        expect(alternate not in {node["ip"] for node in lab.nodes.values()}, "Alternate IP belongs to another fixture")
        before = lab.counters()["drop_spoof"]
        run("ip", "addr", "add", f"{alternate}/32", "dev", "eth0", namespace="guest")
        try:
            result = probe(lab, "guest", "tcp", address(lab.policy, "api"), lab.services["app"]["port"], alternate)
            expect(result["result"] == "timeout" and lab.counters()["drop_spoof"] > before,
                   "Unassigned source did not trigger ingress anti-spoofing")
        finally:
            run("ip", "addr", "del", f"{alternate}/32", "dev", "eth0", namespace="guest")
        return "The edge dropped a test packet sourced from an unassigned Guest address"

    def edge_output(self):
        before = self.lab.counters()["deny_output"]
        result = probe(self.lab, "edge", "tcp", address(self.lab.policy, "upstream"), self.lab.services["egress"]["port"])
        expect(result["result"] == "timeout" and self.lab.counters()["deny_output"] > before,
               "Unsolicited firewall-originated WAN data escaped the output policy")
        return "Denied a new connection from the firewall to the closed WAN simulator"

    def nonrecursive(self):
        result = dns(self.lab, "employee", name="unregistered.example.test")
        expect(result.get("rcode") in {2, 3, 5} and not result.get("answers"),
               f"Outside the authoritative lab zone, expected failure: {result}")
        return f"External namespace returned DNS RCODE {result['rcode']} with no answers"

    def bad_firewall(self):
        lab = self.lab
        prior = lab.fingerprint()
        try:
            lab.apply("flush ruleset\nthis is invalid\n")
        except RuntimeError:
            expect(lab.fingerprint() == prior, "Policy changed on invalid candidate")
            return "Kernel validation rejected an invalid candidate and the active policy was preserved"
        raise AssertionError("Invalid policy passed validation")

    def backup_restore(self):
        lab = self.lab
        backup = TELEMETRY / "firewall-backup.nft"
        backup.write_text(lab.backup(), encoding="utf-8")
        expect(lab.fingerprint() == lab.baseline, "Baseline was already out of compliance")
        lab.apply(firewall(lab.policy, disabled={"guest_egress"}))
        try:
            expect(lab.fingerprint() != lab.baseline, "Drift was not detected")
            result = http(lab, "guest", "egress")
            expect(status(result) == "timeout", "Controlled policy change did not disable egress")
        finally:
            lab.apply(backup.read_text(encoding="utf-8"))
        expect(lab.fingerprint() == lab.baseline, "Snapshot restore differed from baseline")
        expect(status(http(lab, "guest", "egress")) == 200, "Restore did not recover guest egress")
        return "Detected removal of one permit, observed denial, restored the kernel ruleset snapshot and connectivity"

    def recovery(self):
        self.fixtures.stop("app")
        try:
            down = http(self.lab, "employee", "app", "employee")
            expect(status(down) != 200, "Stopped service still returned success")
            expect(not snapshot(self.lab)["health"]["Application"]["up"], "Dashboard health did not show the outage")
        finally:
            self.fixtures.restart("app")
        self.identity("employee", "app", "employee", 200)
        expect(snapshot(self.lab)["health"]["Application"]["up"], "Dashboard health did not recover")
        return "Stopped the app, measured unavailability, restored it and measured a healthy response"

    def canary(self):
        pcap = TELEMETRY / "synthetic-dns.pcap"
        log = TELEMETRY / "events/capture.log"
        with log.open("wb") as output:
            process = start("monitor", "tcpdump", "-n", "-i", "mon0", "-s", "128", "-U", "-c", "1",
                            "-Z", "root", "-w", pcap, CAPTURE_FILTER, stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 6
            while "listening on mon0" not in log.read_text():
                expect(process.poll() is None and time.monotonic() < deadline, f"Capture failed: {log.read_text()[-280:]}")
                time.sleep(0.05)
            reply = dns(self.lab, "employee", name=CANARY)
            expect(reply.get("answers") == [address(self.lab.policy, "api")], f"Canary DNS fixture returned {reply}")
            try:
                result = process.wait(5)
            except subprocess.TimeoutExpired:
                raise AssertionError("No matching canary packet reached the sensor tap") from None
            expect(result == 0, f"Capture exited {result}")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        decoded = run("tcpdump", "-nn", "-Z", "root", "-r", pcap)
        expect(CANARY in decoded, f"Sanitized packet did not include {CANARY}")
        (TELEMETRY / "packet-summary.txt").write_text(decoded, encoding="utf-8")
        sensor = await_sample(TELEMETRY / "sensor.json", lambda data: any(
            alert["signature"] == SIGNATURE and alert["source"] == address(self.lab.policy, "employee")
            for alert in data["alerts"]
        ))
        expect(any(item["name"] == CANARY for item in sensor["dns_sample"]), "DNS telemetry did not contain the canary")
        return "A mirrored Ethernet frame produced one tcpdump record, a DNS telemetry record and a canary alert"

    def dashboard(self):
        lab = self.lab
        self.deny(next(rule for rule in lab.policy["denials"] if rule["id"] == "guest_app"))
        data = snapshot(lab)
        response = http(lab, "admin", "dashboard", "operator", "/api/status")
        expect(status(response) == 200 and json.loads(response["body"]) == data, "Dashboard JSON differed from snapshot")
        expect(all(item["up"] for item in data["segments"]) and all(item["up"] for item in data["health"].values()),
               "Dashboard did not show healthy links and services")
        expect(data["sensor"]["packets"] > 0 and data["sensor"]["tcp_flows"] > 0 and data["sensor"]["alert_count"] > 0,
               "Dashboard telemetry lacked mirrored packets, flows or alerts")
        expect(any(item["source"] == address(lab.policy, "guest") and item["destination"] == address(lab.policy, "api")
                   for item in data["sensor"]["tcp_sample"]), "The tap missed the denied Guest-to-API SYN")
        expect(data["firewall"]["allowed_new_packets"] > 0 and data["firewall"]["dropped_packets"] > 0
               and any(event.startswith("ALLOW") for event in data["firewall_events"])
               and any(event.startswith("DROP") for event in data["firewall_events"]),
               "Firewall counters or kernel events missing from dashboard")
        expect(data["compliant"] and all(item["handshake_recent"] for item in data["vpn"].values()),
               "Dashboard did not show a compliant firewall and two recent VPN handshakes")
        metrics = http(lab, "monitor", "dashboard", "observer", "/metrics")
        expect(status(metrics) == 200 and "ztlab_policy_compliant 1" in metrics["body"], "Metrics endpoint did not return live data")
        self.identity("monitor", "dashboard", "observer", 403)
        page = http(lab, "admin", "dashboard", "operator")
        expect(status(page) == 200 and all(label in page["body"] for label in
               ("Policy Compliant", "Network segments", "Service availability", "Security alerts", "WireGuard peers")),
               "Dashboard HTML did not expose the required information")
        (TELEMETRY / "dashboard.html").write_text(page["body"], encoding="utf-8")
        return "Verified authorized HTTPS and metrics responses against live data, including DENY and ALLOW logs"

    def guest_isolation(self):
        root_routes = json.loads(run("ip", "-j", "route", "show", "table", "main"))
        edge_routes = json.loads(self.lab.edge("ip", "-j", "route", "show", "table", "main"))
        links = json.loads(run("ip", "-j", "link", "show"))
        expect(not root_routes and all(item["dst"] != "default" for item in edge_routes),
               "The guest root or edge has a default route")
        expect(all(link["ifname"] in {"lo", "br-wan"} or link["ifname"].startswith("wan") for link in links),
               "Unexpected guest root network interface")
        expect(all(self.lab.edge("ip", "-6", "addr", "show", "dev", segment["interface"]).strip() == ""
                   for segment in self.lab.segments.values()), "An IPv6 address appeared on the edge")
        return "Root guest and edge have no default route, the WAN is a local bridge, and edge IPv6 is disabled"


def verify_baseline(suite):
    lab = suite.lab
    print("ZTLAB SERVICES READY. Running matrix probes.", flush=True)
    suite.check("guest_no_uplink", "isolation", suite.guest_isolation)
    suite.permits()
    suite.denials()
    print("ZTLAB MATRIX COMPLETE. Running identity, recovery and monitoring checks.", flush=True)
    tests = [
        ("unassigned_ingress_source", "isolation", suite.unassigned_source),
        ("edge_unsolicited_output", "isolation", suite.edge_output),
        ("mtls_certificate_required", "identity", lambda: suite.identity("employee", "app", "-", "rejected")),
        ("mtls_untrusted_ca", "identity", lambda: suite.identity("employee", "app", "foreign", "rejected")),
        ("mtls_valid_certificate_without_role", "identity", lambda: suite.identity("employee", "app", "unassigned", 403)),
        ("mtls_wrong_role", "identity", lambda: suite.identity("admin", "ops", "employee", 403)),
        ("mtls_admin_credential_from_guest", "identity", suite.valid_admin_from_guest),
        ("mtls_observer_data_denied", "identity", lambda: suite.identity("monitor", "app", "observer", 403)),
        ("tls_service_hostname_mismatch", "identity", lambda: suite.identity("employee", "app", "employee",
                                                                             "certificate_error", name="wrong.lab.test")),
        ("mtls_role_revocation", "identity", suite.certificate_revocation),
        ("wireguard_individual_revocation", "vpn", suite.peer_revocation),
        ("dns_no_external_recursion", "dns", suite.nonrecursive),
        ("invalid_policy_rejected", "change_control", suite.bad_firewall),
        ("backup_restore_and_drift", "change_control", suite.backup_restore),
        ("application_failure_and_recovery", "recovery", suite.recovery),
        ("mirrored_dns_and_canary_alert", "monitoring", suite.canary),
        ("operator_dashboard_and_metrics", "monitoring", suite.dashboard),
    ]
    for name, area, operation in tests:
        suite.check(name, area, operation)
    from lab.browser import BROWSER, screenshot
    if Path(BROWSER).is_file():
        suite.check("chromium_dashboard_render", "monitoring", screenshot)


def verify_extensions(suite):
    lab = suite.lab
    if observability.enabled():
        def exercise():
            prior = json.loads((TELEMETRY / "sensor.json").read_text())["alert_count"]
            if ids.enabled():
                suite.check("suricata_zeek_live", "monitoring", lambda: verify_ids(lab))
            reply = dns(lab, "employee", name=CANARY)
            expect(reply.get("answers") == [address(lab.policy, "api")], "DNS canary did not return the fixture answer")
            await_sample(TELEMETRY / "sensor.json", lambda sample: sample["alert_count"] > prior)
            for name, peer in lab.peers.items():
                expect(status(http(lab, name, peer["service"], peer["identity"])) == 200,
                       "Fixture VPN service did not supply the monitoring sample")
            suite.deny(next(rule for rule in lab.policy["denials"] if rule["id"] == "guest_app"))
            snapshot(lab)

        def visible_dashboards():
            response = http(lab, "admin", "dashboard", "operator")
            expect(status(response) == 200, "The live HTTPS operator dashboard did not authorize its fixture operator")
            password = (observability.STATE / "grafana-operator-password").read_text().strip()
            return visible_browser.verify(response["body"], password)

        browser_check = (lambda: suite.check("chromium_live_dashboards", "monitoring", visible_dashboards)) \
            if visible_browser.enabled() else None
        suite.check("prometheus_grafana_live", "monitoring", lambda: observability.verify(
            exercise, browser_check, require_ids=ids.enabled(),
        ))
    elif ids.enabled():
        suite.check("suricata_zeek_live", "monitoring", lambda: verify_ids(lab))
    if ids.enabled():
        suite.check("suricata_inline_prevention", "monitoring", lambda: ids.verify_inline(
            lab, lambda name: dns(lab, "employee", name=name),
        ))
    if ansible.enabled():
        suite.check("ansible_guest_execution", "automation", lambda: ansible.verify(lab))


def verify(lab, addons_only=False):
    guard()
    suite = Suite(lab, provision(lab))
    if addons_only:
        print("ZTLAB SERVICES READY. Running targeted extension acceptance.", flush=True)
    else:
        verify_baseline(suite)
    verify_extensions(suite)
    for name in ("synthetic-dns.pcap", "packet-summary.txt", "dashboard.html", "dashboard.png", "firewall-backup.nft",
                 "vpn-events.jsonl", "ids-observations.json", "ips-observations.json", "observability.json", "grafana.png",
                 "dashboard-visible.png", "browser-observations.json", "ansible-observations.json"):
        path = TELEMETRY / name
        if path.is_file():
            emit(name, path.read_bytes())
    emit("network.json", json.dumps({"segments": lab.segment_status(), "firewall_sha256": lab.baseline}, indent=2).encode())
    emit("telemetry.json", (TELEMETRY / "status.json").read_bytes())
    emit("firewall-events.log", ("\n".join(lab.firewall_events()) + "\n").encode())
    emit("identity-events.jsonl", ("\n".join(json.dumps(row, sort_keys=True) for row in suite.fixtures.events()) + "\n").encode())
    report = {"checks": suite.checks,
              "tested_permits": 0 if addons_only else sum(len(rule["protocols"]) for rule in lab.policy["permits"]),
              "tested_denials": 0 if addons_only else len(lab.policy["denials"])}
    emit("checks.json", (json.dumps(report, indent=2) + "\n").encode())
    passed = sum(check["passed"] for check in suite.checks)
    print(f"ZTLAB ACCEPTANCE {passed}/{len(suite.checks)} passed", flush=True)


def verify_identity(lab):
    guard()
    provision(lab)
    expect(status(http(lab, "employee", "app", "employee")) == 200, "New employee enrollment did not authenticate")
    expect(status(http(lab, "admin", "ops", "operator")) == 200, "New operator enrollment did not authenticate")
    for name, peer in lab.peers.items():
        expect(status(http(lab, name, peer["service"], peer["identity"])) == 200 and
               lab.peer_status()[name]["handshake_recent"], "New WireGuard peer enrollment did not authenticate")
    paths = {"services_ca": SECRETS / "services.pem", "clients_ca": SECRETS / "clients.pem",
             "employee": SECRETS / "employee.pem", "operator": SECRETS / "operator.pem",
             "app_service": RUN / "services/app/server.pem"}
    for name in ("employee", "operator", "app_service"):
        expect(command("openssl", "x509", "-noout", "-checkend", "86400", "-in", paths[name], check=False).returncode == 0,
               "A newly enrolled leaf expires too early")
        expect(command("openssl", "x509", "-noout", "-checkend", "172801", "-in", paths[name], check=False).returncode != 0,
               "A newly enrolled leaf exceeds its two-day lifetime")
    expect(not any((SECRETS / f"{ca}.key").exists() for ca in ("services", "clients", "untrusted")),
           "An issuer private key survived enrollment")
    peers = {name: hashlib.sha256(key.encode()).hexdigest() for name, key in lab.peer_keys.items()}
    evidence = {"cert_fingerprints": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()},
                "wireguard_public_key_digests": peers, "authenticated_mtls_roles": ["employee", "operator"],
                "authenticated_wireguard_peers": sorted(peers), "leaf_lifetime_hours": 48, "issuer_keys_removed": True}
    emit("identity-boot.json", json.dumps(evidence, indent=2).encode())
    print("ZTLAB IDENTITY ENROLLMENT PASSED. Fresh TLS identities and two WireGuard peers authenticated.", flush=True)


def live(lab):
    provision(lab)
    if ansible.enabled():
        print(ansible.verify(lab), flush=True)
    engines = ids.start_engines() if ids.enabled() else None
    try:
        if observability.enabled():
            observability.launch()
    except Exception:
        if engines is not None:
            ids.stop_engines(engines)
        raise
    if os.fork() == 0:
        try:
            while True:
                time.sleep(10)
                snapshot(lab)
        finally:
            os._exit(0)
    print("ZTLAB LIVE READY. Fetch the dashboard from the admin namespace at monitor.lab.test:8443.", flush=True)
