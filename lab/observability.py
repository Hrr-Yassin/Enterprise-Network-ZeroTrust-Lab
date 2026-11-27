"""Stage local release files and run metrics services on the guest monitor loopback."""

import base64
import hashlib
import http.client as http_client
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from string import Template
from urllib.parse import urlencode

from lab.guest import RUN, SECRETS, TELEMETRY, guard, source_namespace, write_json
from lab.model import ROOT, address, load

INSTALL = Path("/opt/ztlab-observability")
STATE = RUN / "observability"
MONITORING = ROOT / "monitoring"
BUNDLED_PROMETHEUS = "grafana/data/plugins-bundled/prometheus"
BINARIES = ("prometheus/prometheus", "prometheus/promtool", "grafana/bin/grafana",
            BUNDLED_PROMETHEUS + "/gpx_grafana-prometheus-datasource_linux_amd64")
LOADER = "/lib64/ld-linux-x86-64.so.2"
PROMETHEUS_UID = 13001
GRAFANA_UID = 13002
PROMETHEUS_PORT = 9090
GRAFANA_PORT = 3000
OPERATOR = "operator"
DATASOURCE = "ztlab-prom"
DASHBOARD = "ztlab-observability"
JOB = "isolated-ztlab"


@dataclass(frozen=True)
class ReleaseBundle:
    directory: Path
    files: tuple[Path, ...]
    dependencies: dict[str, Path]


def bundle_path(directory, name, kind, optional=False):
    path = directory
    for part in Path(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"Symlinks are unsupported in observability bundles: {name}")
    if optional and not path.exists():
        return None
    if kind == "file" and path.is_file() or kind == "directory" and path.is_dir():
        return path
    raise ValueError(f"Observability bundle is missing its {kind}: {name}")


def asset_files(directory, name, optional=False):
    assets = bundle_path(directory, name, "directory", optional=optional)
    if assets is None:
        return []
    files = []
    for path in sorted(assets.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            files.append(path)
        elif not stat.S_ISDIR(mode):
            raise ValueError(f"Unsupported release asset type: {path.relative_to(directory)}")
    return files


def elf_dependencies(path):
    with path.open("rb") as stream:
        header = stream.read(20)
    if header[:7] != b"\x7fELF\x02\x01\x01" or header[18:20] != b"\x3e\x00":
        raise ValueError(f"Observability requires a Linux x86-64 ELF binary: {path.name}")
    try:
        metadata = subprocess.run(("readelf", "-l", "-d", "-W", path), check=True, timeout=10,
                                  text=True, capture_output=True, env={**os.environ, "LC_ALL": "C"}).stdout
    except FileNotFoundError:
        raise RuntimeError("Observability bundle validation requires readelf (binutils)") from None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError(f"Unreadable ELF metadata for {path.name}") from None
    interpreter = re.search(r"\[Requesting program interpreter: ([^\]]+)\]", metadata)
    if interpreter and interpreter[1] != LOADER:
        raise ValueError(f"Unsupported ELF interpreter for {path.name}: {interpreter[1]}")
    return bool(interpreter), re.findall(r"\(NEEDED\).+\[([A-Za-z0-9_.+-]+)\]", metadata)


def library_paths(binaries, preferred=None):
    libraries = {}
    pending = list(binaries)
    known = None
    while pending:
        interpreter, requires = elf_dependencies(pending.pop())
        if interpreter:
            if not Path(LOADER).is_file():
                raise RuntimeError(f"Missing compatible local ELF interpreter: {LOADER}")
            libraries[LOADER] = Path(LOADER)
        if requires and known is None:
            cache = subprocess.run(("ldconfig", "-p"), check=True, timeout=10, text=True, capture_output=True).stdout
            known = dict(preferred or {})
            for name, location in re.findall(r"^\s*(\S+) \([^)]*x86-64[^)]*\) => (\S+)", cache, re.MULTILINE):
                if "/glibc-hwcaps/" not in location:
                    known.setdefault(name, Path(location))
        for name in requires:
            target = f"/lib64/{name}"
            if target not in libraries:
                library = known.get(name)
                if library is None or not library.is_file():
                    raise RuntimeError(f"Missing compatible local runtime library: {name}")
                libraries[target] = library
                pending.append(library)
    return libraries


def validate_bundle(source):
    """Inspect release layout and ELF metadata without executing the supplied files."""
    directory = source.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("The observability bundle must be a directory of extracted releases")
    binaries = [bundle_path(directory, name, "file") for name in BINARIES]
    if any(not os.access(path, os.X_OK) for path in binaries):
        raise ValueError("Observability release binaries must have their executable mode set")
    defaults = bundle_path(directory, "grafana/conf/defaults.ini", "file")
    if not defaults.stat().st_size:
        raise ValueError("Grafana conf/defaults.ini is empty")
    bundle_path(directory, "grafana/public/build", "directory")
    assets = asset_files(directory, "grafana/public")
    if not any(path.suffix == ".js" and Path("build") in path.relative_to(directory / "grafana/public").parents
               for path in assets):
        raise ValueError("Grafana public/build does not contain release JavaScript")
    assets.extend(path for path in asset_files(directory, BUNDLED_PROMETHEUS) if path not in binaries)
    dependencies = library_paths(binaries)
    return ReleaseBundle(directory, (*binaries, defaults, *assets), dependencies)


def stage_bundle(staging, source):
    bundle = validate_bundle(source)
    destination = staging / INSTALL.relative_to("/")
    for original in bundle.files:
        target = destination / original.relative_to(bundle.directory)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        target.chmod(0o755 if original.stat().st_mode & 0o111 else 0o644)
    for guest_path, original in bundle.dependencies.items():
        target = staging / guest_path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(original, target)
            target.chmod(0o755)
    hashes = {}
    for name in BINARIES:
        with (destination / name).open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    write_json(destination / "manifest.json", hashes)
    with (staging / "etc/passwd").open("a", encoding="utf-8") as users, \
         (staging / "etc/group").open("a", encoding="utf-8") as groups:
        for name, uid in (("prometheus", PROMETHEUS_UID), ("grafana", GRAFANA_UID)):
            users.write(f"lab-{name}:x:{uid}:{uid}:{name}:{STATE / name}:/bin/sh\n")
            groups.write(f"lab-{name}:x:{uid}:\n")


def enabled():
    return (INSTALL / "manifest.json").is_file()


def private_dir(path, uid):
    path.mkdir(mode=0o700)
    os.chown(path, uid, uid)


def write_config(path, data, mode=0o644, group=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(data)
        stream.flush()
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)


def configure():
    policy = load()
    monitor = policy["services"]["dashboard"]
    if monitor["node"] != "monitor" or monitor["kind"] != "mtls":
        raise RuntimeError("Prometheus requires the mTLS metrics endpoint in the monitor namespace")
    target = address(policy, monitor["node"]) + f":{monitor['port']}"
    STATE.mkdir(mode=0o755)
    for name in ("services.pem", "observer.pem", "observer.key"):
        write_config(STATE / name, (SECRETS / name).read_text(), mode=0o440, group=PROMETHEUS_UID)
    config = Template((MONITORING / "prometheus.yml").read_text())
    write_config(STATE / "prometheus.yml", config.substitute(monitor_name=monitor["host"], monitor_target=target))
    shutil.copyfile(MONITORING / "alerts.yml", STATE / "alerts.yml")
    private_dir(STATE / "prometheus", PROMETHEUS_UID)
    grafana = STATE / "grafana"
    grafana.mkdir(mode=0o755)
    for name in ("data", "logs", "plugins"):
        private_dir(grafana / name, GRAFANA_UID)
    provisioning = grafana / "provisioning"
    for kind, source in (("datasources", "grafana-datasource.yml"), ("dashboards", "grafana-dashboard.yml")):
        directory = provisioning / kind
        directory.mkdir(parents=True)
        shutil.copyfile(MONITORING / source, directory / "ztlab.yml")
    dashboards = grafana / "dashboards"
    dashboards.mkdir()
    shutil.copyfile(MONITORING / "grafana.json", dashboards / "ztlab.json")
    password = secrets.token_urlsafe(36)
    write_config(STATE / "grafana-operator-password", password + "\n", mode=0o600)
    config = Template((MONITORING / "grafana.ini").read_text())
    write_config(grafana / "grafana.ini", config.substitute(password=password), mode=0o440, group=GRAFANA_UID)
    return target


def http(port, path, password=None, *, payload=None):
    headers = {}
    if password is not None:
        token = base64.b64encode(f"{OPERATOR}:{password}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    method, body = "GET", None
    if payload is not None:
        method, body = "POST", json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    with closing(http_client.HTTPConnection("127.0.0.1", port, timeout=3)) as connection:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        return response.status, response.read(2_000_000)


def get_json(port, path, password=None, *, payload=None):
    code, body = http(port, path, password, payload=payload)
    if code != 200:
        try:
            detail = json.loads(body).get("message", "")
        except (AttributeError, ValueError):
            detail = ""
        raise RuntimeError(f"Loopback API {path} returned HTTP {code}. {str(detail)[:200]}")
    return json.loads(body)


def await_http(processes, port, path, timeout=75):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for name, process in processes.items():
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited during startup with status {process.returncode}. See its private guest log")
        try:
            if http(port, path)[0] == 200:
                return
        except (OSError, http_client.HTTPException):
            pass
        time.sleep(1)
    raise RuntimeError(f"Loopback service on port {port} did not become ready")


def stop(processes):
    for process in processes.values():
        if process.poll() is None:
            process.terminate()
    for process in processes.values():
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def private_log(name):
    fd = os.open(STATE / f"{name}.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def start_service(name, argv, uid, cwd):
    with private_log(name) as log:
        return subprocess.Popen(argv, cwd=cwd, user=uid, group=uid, extra_groups=[],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)


def launch():
    """Validate the configuration and start real services as guest-only unprivileged users."""
    guard()
    if not enabled():
        raise RuntimeError("The guest image contains no observability release bundle")
    target = configure()
    processes = {}
    with source_namespace("monitor"):
        try:
            with private_log("promtool") as log:
                result = subprocess.run((INSTALL / "prometheus/promtool", "check", "config",
                                         STATE / "prometheus.yml"), user=PROMETHEUS_UID, group=PROMETHEUS_UID,
                                        extra_groups=[], stdout=log, stderr=subprocess.STDOUT, timeout=40)
            if result.returncode:
                raise RuntimeError("promtool rejected the staged config. See its private guest log")
            processes["prometheus"] = start_service(
                "prometheus", (INSTALL / "prometheus/prometheus",
                               f"--config.file={STATE / 'prometheus.yml'}",
                               f"--storage.tsdb.path={STATE / 'prometheus'}",
                               "--storage.tsdb.retention.time=6h", "--storage.tsdb.retention.size=64MB",
                               f"--web.listen-address=127.0.0.1:{PROMETHEUS_PORT}"),
                PROMETHEUS_UID, STATE / "prometheus",
            )
            grafana = INSTALL / "grafana"
            processes["grafana"] = start_service(
                "grafana", (grafana / "bin/grafana", "server", f"--homepath={grafana}",
                            f"--config={STATE / 'grafana/grafana.ini'}"),
                GRAFANA_UID, grafana,
            )
            await_http(processes, PROMETHEUS_PORT, "/-/ready")
            await_http(processes, GRAFANA_PORT, "/api/health")
        except subprocess.TimeoutExpired:
            stop(processes)
            raise RuntimeError("promtool configuration check timed out") from None
        except BaseException:
            stop(processes)
            raise
    return processes, target


def checked_api(port, path, password=None):
    response = get_json(port, path, password)
    if not isinstance(response, dict):
        raise RuntimeError(f"Unexpected response from {path}")
    return response


def prometheus_data(path, port=PROMETHEUS_PORT, password=None):
    response = checked_api(port, path, password)
    if response.get("status") != "success" or not isinstance(response.get("data"), dict):
        raise RuntimeError(f"Prometheus failed to return successful data for {path}")
    return response["data"]


def scrape_target(target):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        targets = prometheus_data("/api/v1/targets").get("activeTargets", [])
        for item in targets:
            if item.get("labels", {}).get("job") == JOB and item.get("scrapeUrl") == f"https://{target}/metrics":
                if item.get("health") == "up" and item.get("lastError") == "":
                    return
        time.sleep(1)
    raise RuntimeError("Prometheus did not record a healthy mTLS scrape of the monitor metrics endpoint")


def evaluated_rules():
    expected = {"LabServiceUnavailable", "LabFirewallPolicyDrift", "LabIDSCanarySeen"}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        rule_data = prometheus_data("/api/v1/rules")
        rules = {rule.get("name"): rule.get("health") for group in rule_data.get("groups", [])
                 if group.get("name") == "ztlab" for rule in group.get("rules", [])}
        if set(rules) == expected and all(health == "ok" for health in rules.values()):
            return sorted(rules)
        if "err" in rules.values():
            break
        time.sleep(1)
    raise RuntimeError("Prometheus did not load and evaluate all observability alert rules")


def verify_canary(require_ids):
    names = ["ztlab_sensor_alerts_total"]
    if require_ids:
        names.extend(("ztlab_ids_suricata_alerts", "ztlab_ids_zeek_dns", "ztlab_ids_zeek_connections"))
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        sample = {}
        for name in names:
            query = "/api/v1/query?" + urlencode({"query": name})
            rows = prometheus_data(query).get("result", [])
            if len(rows) == 1 and rows[0].get("metric", {}).get("job") == JOB:
                sample[name] = float(rows[0]["value"][1])
        rules = prometheus_data("/api/v1/rules").get("groups", [])
        firing = any(rule.get("name") == "LabIDSCanarySeen" and rule.get("state") == "firing"
                     for group in rules for rule in group.get("rules", []))
        if set(sample) == set(names) and min(sample.values()) > 0 and firing:
            return sample
        time.sleep(0.7)
    raise RuntimeError("Prometheus did not ingest the IDS canary and fire the expected alert")


def loopback_listeners():
    required = {PROMETHEUS_PORT, GRAFANA_PORT}
    for file in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in Path(file).read_text().splitlines()[1:]:
            _, endpoint, _, state, *_ = line.split()
            host, port_hex = endpoint.split(":")
            port = int(port_hex, 16)
            if state == "0A" and port in {PROMETHEUS_PORT, GRAFANA_PORT}:
                if host != "0100007F":
                    raise RuntimeError("An observability service bound outside the monitor IPv4 loopback")
                required.discard(port)
    if required:
        raise RuntimeError("Expected Prometheus and Grafana loopback listeners are missing")


def grafana_samples(expression, password):
    request = {
        "from": "now-5m", "to": "now",
        "queries": [{"refId": "A", "datasource": {"uid": DATASOURCE, "type": "prometheus"},
                     "expr": expression, "format": "time_series", "instant": True, "range": False,
                     "intervalMs": 1000, "maxDataPoints": 100}],
    }
    result = get_json(GRAFANA_PORT, "/api/ds/query", password, payload=request)["results"]["A"]
    return [value for frame in result.get("frames", []) for field, values in
            zip(frame["schema"]["fields"], frame["data"]["values"], strict=True)
            if field.get("type") == "number" for value in values if isinstance(value, (int, float))]


def measure():
    loopback_listeners()
    password = (STATE / "grafana-operator-password").read_text().strip()
    query = "/api/v1/query?" + urlencode({"query": "ztlab_policy_compliant"})
    dashboard_path = f"/api/dashboards/uid/{DASHBOARD}"
    if http(GRAFANA_PORT, dashboard_path)[0] not in {401, 403}:
        raise RuntimeError("The Grafana dashboard API accepted unauthenticated access")
    datasource = checked_api(GRAFANA_PORT, f"/api/datasources/uid/{DATASOURCE}", password)
    if (datasource.get("type"), datasource.get("access"), datasource.get("url")) != (
        "prometheus", "proxy", f"http://127.0.0.1:{PROMETHEUS_PORT}"
    ):
        raise RuntimeError("Grafana did not provision the in-guest Prometheus data source")
    dashboard = checked_api(GRAFANA_PORT, dashboard_path, password).get("dashboard", {})
    expected = json.loads((MONITORING / "grafana.json").read_text())
    if dashboard.get("uid") != DASHBOARD or [panel.get("id") for panel in dashboard.get("panels", [])] != [
        panel["id"] for panel in expected["panels"]
    ]:
        raise RuntimeError("Grafana did not provision the expected dashboard panels")
    direct = prometheus_data(query).get("result", [])
    if len(direct) != 1 or direct[0].get("metric", {}).get("job") != JOB or direct[0].get("value", [None])[-1] != "1":
        raise RuntimeError("Prometheus compliance metric was missing or unhealthy")
    if grafana_samples("ztlab_policy_compliant", password) != [1]:
        raise RuntimeError("Grafana did not return the live compliance value")
    panels = {}
    for panel in expected["panels"]:
        expressions = [target["expr"] for target in panel.get("targets", [])]
        for expression in expressions:
            if not grafana_samples(expression, password):
                raise RuntimeError(f"Grafana panel has no live isolated-lab series: {panel['title']}")
        panels[panel["title"]] = len(expressions)
    rules = evaluated_rules()
    grafana_health = checked_api(GRAFANA_PORT, "/api/health")
    prometheus_build = prometheus_data("/api/v1/status/buildinfo")
    if grafana_health.get("database") != "ok" or not grafana_health.get("version") or not prometheus_build.get("version"):
        raise RuntimeError("Observability service health responses did not identify the two engines")
    return {
        "listeners": "monitor namespace IPv4 loopback",
        "prometheus": {"version": prometheus_build["version"], "scrape_job": JOB, "mtls_target_health": "up",
                       "evaluated_alert_rules": rules, "compliance_sample": 1},
        "grafana": {"version": grafana_health["version"], "dashboard_uid": DASHBOARD, "panel_count": len(dashboard["panels"]),
                    "datasource_uid": DATASOURCE, "proxied_compliance_sample": 1, "unauthenticated_dashboard_rejected": True,
                    "live_panel_queries": panels},
    }


def verify(exercise=None, browser_check=None, require_ids=False):
    processes, target = launch()
    try:
        with source_namespace("monitor"):
            scrape_target(target)
        if exercise is not None:
            exercise()
        with source_namespace("monitor"):
            signals = verify_canary(require_ids) if exercise is not None else {}
            evidence = measure()
        if signals:
            evidence["prometheus"]["canary_alert_fired"] = True
            evidence["prometheus"]["observed_canary_metrics"] = signals
        evidence["release_sha256"] = json.loads((INSTALL / "manifest.json").read_text())
        write_json(TELEMETRY / "observability.json", evidence)
        if browser_check is not None:
            browser_check()
        return "Prometheus scraped the mTLS endpoint and Grafana served live data for every provisioned panel"
    except http_client.HTTPException as error:
        raise RuntimeError(f"Observability loopback request failed: {type(error).__name__}") from error
    finally:
        stop(processes)


if __name__ == "__main__":
    with source_namespace("monitor"):
        print(json.dumps(measure(), indent=2, sort_keys=True))
