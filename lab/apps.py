"""Isolated lab fixtures, the client certificate authorizer and the operator dashboard."""

import hashlib
import html
import http.server
import json
import os
import socketserver
import ssl
import sys
from datetime import datetime, timezone

from lab.guest import RUN, TELEMETRY
from lab.model import address, load


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address

    def get_request(self):
        sock, peer = super().get_request()
        sock.settimeout(2)
        return sock, peer

    def process_request_thread(self, sock, peer):
        if self.context:
            try:
                sock = self.context.wrap_socket(sock, server_side=True)
            except (OSError, ssl.SSLError) as error:
                self.event("tls_rejected", peer[0], reason=getattr(error, "reason", None) or type(error).__name__)
                sock.close()
                return
        super().process_request_thread(sock, peer)

    def event(self, event, source, **details):
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        print(json.dumps({"event": event, "service": self.name, "source": source, "time": stamp, **details}, sort_keys=True),
              flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, payload, kind="application/json"):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if not isinstance(payload, bytes):
            payload = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        server = self.server
        if server.kind == "mtls":
            fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            roles = json.loads((server.directory / "roles.json").read_text())
            role = roles.get(fingerprint, "unassigned")
            allow = role in server.service["roles"]
            if role == "observer":
                allow = (server.name == "app" and self.path == "/health") or (
                    server.name == "dashboard" and self.path == "/metrics"
                )
            server.event("identity_allowed" if allow else "identity_denied", self.client_address[0], role=role,
                         resource={"/": "index", "/health": "health", "/metrics": "metrics",
                                   "/api/status": "status"}.get(self.path, "other"))
            if not allow:
                self.reply(403, {"status": "forbidden"})
                return
        if server.name == "dashboard" and self.path in {"/", "/api/status", "/metrics"}:
            snapshot = TELEMETRY / "status.json"
            if not snapshot.exists():
                self.reply(503, {"status": "waiting for telemetry"})
                return
            data = json.loads(snapshot.read_text())
            if self.path == "/":
                self.reply(200, render(data), "text/html; charset=utf-8")
            elif self.path == "/metrics":
                self.reply(200, metrics(data), "text/plain; version=0.0.4; charset=utf-8")
            else:
                self.reply(200, data)
            return
        if self.path not in {"/", "/health"}:
            self.reply(404, {"status": "unknown resource"})
            return
        payload = {"service": server.name, "status": "available"}
        if server.kind in {"egress", "public"}:
            payload["observed_source"] = self.client_address[0]
        self.reply(200, payload)


def table(headers, rows):
    header = "".join(f"<th>{html.escape(str(value))}</th>" for value in headers)
    entries = "\n".join("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{header}</tr></thead><tbody>{entries}</tbody></table>"


def render(data):
    firewall = data["firewall"]
    sensor = data["sensor"]
    segments = table(
        ["Segment", "CIDR", "Link", "RX · bytes", "TX · bytes"],
        [(item["name"], item["network"], "Up" if item["up"] else "Down",
          f'{item["rx_bytes"]:,}', f'{item["tx_bytes"]:,}') for item in data["segments"]],
    )
    availability = table(
        ["Service probe", "Status", "Latency · ms"],
        [(name, "Up" if item["up"] else "Down", item["latency_ms"]) for name, item in data["health"].items()],
    )
    vpn = table(
        ["Peer", "Authorization", "Handshake", "RX · bytes", "TX · bytes"],
        [(name.replace("_", " "), "Allowed" if item["authorized"] else "Revoked",
          "Recent" if item["handshake_recent"] else "Idle", item["rx_bytes"], item["tx_bytes"])
         for name, item in data["vpn"].items()],
    )
    alerts = table(
        ["Signature", "Source", "Destination"],
        [(item["signature"], item["source"], item["destination"]) for item in sensor["alerts"][-6:]],
    )
    cards = "".join(
        f'<div class="metric"><span>{html.escape(label)}</span><strong>{value:,}</strong></div>'
        for label, value in (
            ("Mirrored packets", sensor["packets"]), ("Mirrored bytes", sensor["bytes"]),
            ("Firewall allowed · new", firewall["allowed_new_packets"]), ("Firewall dropped", firewall["dropped_packets"]),
            ("Observed TCP flows", sensor["tcp_flows"]), ("DNS queries", sensor["dns_queries"]),
        )
    )
    state = "Compliant" if data["compliant"] else "Drift detected"
    infra = data["infrastructure"]
    infra_rows = table(
        ["Signal", "Sample"],
        [("Uptime", f'{infra["uptime_seconds"]} s'), ("Memory available",
         f'{infra["memory_available_mib"]} / {infra["memory_total_mib"]} MiB'), ("1-minute load", infra["load_one_minute"])],
    )
    recent = "".join(f"<li>{html.escape(event)}</li>" for event in data["firewall_events"][-8:])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Security Lab | Operations</title>
<style>
:root{{color-scheme:dark;font:14px system-ui,sans-serif;background:#0d131b;color:#dfebf6}}
body{{max-width:1260px;margin:auto;padding:30px 35px 50px}}
header{{display:flex;gap:16px;align-items:end;justify-content:space-between;margin-bottom:22px}}
h1,h2{{margin:0}} h1{{font-size:31px;font-weight:720}} h2{{font-size:17px;margin-bottom:10px}}
header p{{margin:6px 0 0;color:#9ab0c6}} .state{{border:1px solid #3e796b;color:#97e9cf;border-radius:5px;padding:8px 12px;white-space:nowrap}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(153px,1fr));gap:10px;margin-bottom:13px}}
.metric,section{{background:#151f2b;border:1px solid #26384a;border-radius:7px;padding:15px}}
.metric span{{display:block;color:#9ab0c6;margin-bottom:6px}}.metric strong{{font-size:24px;font-variant-numeric:tabular-nums}}
.grid{{display:grid;grid-template-columns:1.17fr 1fr;gap:13px;align-items:start}} .stack{{display:grid;gap:13px}}
table{{width:100%;border-collapse:collapse;text-align:left;font-variant-numeric:tabular-nums}}
td,th{{padding:7px 6px;border-bottom:1px solid #253649}}th{{font-size:12px;color:#9ab0c6;font-weight:600}}
tr:last-child td{{border:0}} ul{{padding:0 0 0 18px;font:11px ui-monospace,monospace;line-height:1.6;overflow-wrap:anywhere}}
@media(max-width:830px){{body{{padding:16px}}.grid{{grid-template-columns:1fr}}header{{align-items:start;flex-wrap:wrap}}}}
</style></head><body>
<header><div><h1>Network Security Lab</h1><p>Operations · {html.escape(data["sampled_at"])}</p></div>
<div class="state">Policy {state}</div></header>
<div class="metrics">{cards}</div>
<main class="grid"><div class="stack"><section><h2>Network segments</h2>{segments}</section>
<section><h2>Service availability</h2>{availability}</section>
<section><h2>Infrastructure health</h2>{infra_rows}</section></div>
<div class="stack"><section><h2>WireGuard peers</h2>{vpn}</section>
<section><h2>Security alerts</h2>{alerts}</section>
<section><h2>Recent firewall decisions</h2><ul>{recent}</ul></section></div></main></body></html>
"""


def metrics(data):
    rows = [
        ("ztlab_mirrored_packets_total", None, data["sensor"]["packets"]),
        ("ztlab_mirrored_bytes_total", None, data["sensor"]["bytes"]),
        ("ztlab_dns_queries_total", None, data["sensor"]["dns_queries"]),
        ("ztlab_sensor_alerts_total", None, data["sensor"]["alert_count"]),
        ("ztlab_firewall_new_allowed_packets_total", None, data["firewall"]["allowed_new_packets"]),
        ("ztlab_firewall_dropped_packets_total", None, data["firewall"]["dropped_packets"]),
        ("ztlab_policy_compliant", None, int(data["compliant"])),
    ]
    for name, peer in data["vpn"].items():
        rows.append(("ztlab_vpn_peer_recent_handshake", f'peer="{name}"', int(peer["handshake_recent"])))
    for name, probe in data["health"].items():
        rows.append(("ztlab_availability", f'service="{name}"', int(probe["up"])))
        rows.append(("ztlab_probe_duration_seconds", f'service="{name}"', probe["latency_ms"] / 1000))
    for segment in data["segments"]:
        label = 'segment="' + segment["id"] + '"'
        rows.extend([
            ("ztlab_segment_link_up", label, int(segment["up"])),
            ("ztlab_segment_rx_bytes_total", label, segment["rx_bytes"]),
            ("ztlab_segment_tx_bytes_total", label, segment["tx_bytes"]),
        ])
    return "".join(f"{name}{'{' + labels + '}' if labels else ''} {value}\n" for name, labels, value in rows)


def serve(name, user):
    policy = load()
    service = policy["services"][name]
    directory = RUN / "services" / name
    os.setgroups([])
    os.setgid(user)
    os.setuid(user)
    context = None
    if service["kind"] in {"public", "mtls"}:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(directory / "server.pem", directory / "server.key")
        if service["kind"] == "mtls":
            context.load_verify_locations(directory / "clients.pem")
            context.verify_flags |= ssl.VERIFY_X509_STRICT
            context.verify_mode = ssl.CERT_REQUIRED
    with Server((address(policy, service["node"]), service["port"]), Handler) as server:
        server.context = context
        server.name = name
        server.kind = service["kind"]
        server.service = service
        server.directory = directory
        (directory / "ready").write_text("ready\n", encoding="ascii")
        server.serve_forever()


if __name__ == "__main__":
    serve(sys.argv[1], int(sys.argv[2]))
