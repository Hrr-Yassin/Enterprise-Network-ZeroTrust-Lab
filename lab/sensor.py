"""Small passive sensor for lab-only traffic when full IDS engines are unavailable."""

import ipaddress
import socket
import struct
import time
from collections import deque
from datetime import datetime, timezone

from lab.guest import TELEMETRY, write_json
from lab.probe import query_name

CANARY = "ids-check.lab.test"
SIGNATURE = "LAB-DNS-CANARY"


def observe(packet):
    if len(packet) < 34 or packet[12:14] != b"\x08\x00":
        return None
    ip = packet[14:]
    header = (ip[0] & 0x0F) * 4
    if header < 20 or len(ip) < header + 8 or int.from_bytes(ip[6:8]) & 0x3FFF:
        return None
    protocol = ip[9]
    if protocol not in {6, 17}:
        return None
    source = str(ipaddress.ip_address(ip[12:16]))
    destination = str(ipaddress.ip_address(ip[16:20]))
    sport, dport = struct.unpack_from("!HH", ip, header)
    is_syn = protocol == 6 and len(ip) >= header + 20 and ip[header + 13] & 0x12 == 0x02
    name = None
    if protocol == 17 and dport == 53:
        dns = ip[header + 8:]
        if len(dns) >= 12 and not dns[2] & 0x80:
            try:
                name = query_name(dns)[0]
            except ValueError:
                pass
    return source, destination, sport, dport, protocol, is_syn, name


def main():
    output = TELEMETRY / "sensor.json"
    data = {"packets": 0, "bytes": 0, "tcp_flows": 0, "dns_queries": 0, "alert_count": 0}
    alerts = deque(maxlen=20)
    dns_events = deque(maxlen=30)
    flow_events = deque(maxlen=40)
    flows = set()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sensor:
        sensor.bind(("mon0", 0))
        sensor.settimeout(0.1)
        refresh = 0
        while True:
            try:
                packet = sensor.recv(65535)
                data["packets"] += 1
                data["bytes"] += len(packet)
                event = observe(packet)
                if event:
                    source, destination, sport, dport, protocol, is_syn, name = event
                    key = (source, destination, sport, dport, protocol)
                    if is_syn and key not in flows:
                        if len(flows) >= 8192:
                            flows.clear()
                        flows.add(key)
                        data["tcp_flows"] += 1
                        flow_events.append({"source": source, "destination": destination,
                                            "source_port": sport, "destination_port": dport})
                    if name:
                        data["dns_queries"] += 1
                        if name.endswith(".lab.test"):
                            dns_events.append({"name": name, "source": source, "destination": destination})
                        if name == CANARY:
                            data["alert_count"] += 1
                            alerts.append({"signature": SIGNATURE, "source": source, "destination": destination,
                                           "time": datetime.now(timezone.utc).isoformat(timespec="seconds")})
            except TimeoutError:
                pass
            if time.monotonic() >= refresh:
                write_json(output, {**data, "alerts": list(alerts), "dns_sample": list(dns_events),
                                    "tcp_sample": list(flow_events)})
                refresh = time.monotonic() + 0.25


if __name__ == "__main__":
    main()
