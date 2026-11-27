"""Validate the policy model and compile a transaction for the lab firewall."""

import ipaddress
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "config/lab.json"
ID = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
IFNAME = re.compile(r"[a-z][a-z0-9-]{0,14}\Z")
INTERNAL = ipaddress.ip_network("10.77.0.0/16")
TEST_WAN = ipaddress.ip_network("192.0.2.0/24")
IDENTITIES = {"employee", "remote_user", "operator", "observer", "unassigned"}
DENY_COUNTERS = ("deny_input", "deny_forward", "deny_output", "drop_invalid", "drop_spoof")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path=POLICY):
    policy = json.loads(path.read_text(encoding="utf-8"))
    validate(policy)
    return policy


def address(policy, node):
    if node == "edge":
        return policy["segments"]["wan"]["gateway"]
    return policy["nodes"][node]["ip"]


def endpoint(policy, rule, allowed):
    service = policy["services"][rule["service"]]
    host = address(policy, service["node"])
    if allowed and rule.get("nat") == "dnat":
        host = address(policy, "edge")
    return rule.get("address", host), rule.get("port", service["port"])


def validate(policy):
    segments = policy["segments"]
    nodes = policy["nodes"]
    services = policy["services"]
    peers = policy["peers"]
    require(set(segments) == {"wan", "dmz", "staff", "app", "vault", "identity", "admin", "sensor", "guest", "vpn"},
            "The topology must contain the declared lab segments")
    for label in (*segments, *nodes, *services):
        require(ID.fullmatch(label), f"Invalid policy name {label!r}")
    occupied = []
    used_interfaces = set()
    used_ips = set()
    for name, segment in segments.items():
        network = ipaddress.ip_network(segment["network"])
        boundary = TEST_WAN if name == "wan" else INTERNAL
        require(network.version == 4 and network.subnet_of(boundary), f"{name} is outside the lab address space")
        require(all(not network.overlaps(other) for other in occupied), f"Overlapping segment {name}")
        occupied.append(network)
        gateway = ipaddress.ip_address(segment["gateway"])
        require(gateway in network and gateway not in {network.network_address, network.broadcast_address},
                f"Invalid gateway for {name}")
        interface = segment["interface"]
        require(IFNAME.fullmatch(interface) and interface not in used_interfaces, f"Invalid or repeated interface {interface}")
        require(interface not in {"lo", "tap0", "mon0", "eth0", "br-wan"}, f"Reserved interface {interface}")
        used_interfaces.add(interface)
        used_ips.add(gateway)
    require(segments["vpn"]["interface"] == "wg0", "The lab WireGuard interface must be wg0")
    for name, node in nodes.items():
        require(name != "edge" and node["segment"] in segments, f"Invalid node {name}")
        network = ipaddress.ip_network(segments[node["segment"]]["network"])
        ip = ipaddress.ip_address(node["ip"])
        require(ip in network and ip not in {*used_ips, network.network_address, network.broadcast_address},
                f"Invalid or repeated node address for {name}")
        used_ips.add(ip)
    for name in segments.keys() - {"wan", "vpn"}:
        require(sum(node["segment"] == name for node in nodes.values()) == 1, f"{name} requires exactly one endpoint")
    require(set(peers) == {name for name, node in nodes.items() if node["segment"] == "vpn"}, "VPN endpoints must match peers")
    for name, peer in peers.items():
        require(nodes[peer["transport"]]["segment"] == "wan" and peer["service"] in services and
                peer["identity"] in IDENTITIES, f"Invalid VPN peer {name}")
    require(len({peer["transport"] for peer in peers.values()}) == len(peers), "VPN transport endpoints must be unique")
    for name, service in services.items():
        require(type(service["port"]) is int and 0 < service["port"] <= 65535, f"Invalid port for {name}")
        require(service["kind"] in {"dns", "wireguard", "mtls", "public", "egress"}, f"Invalid service kind for {name}")
        if service["node"] == "edge":
            require(service["kind"] == "wireguard", f"Unexpected edge listener {name}")
        else:
            require(service["node"] in nodes, f"Invalid node for {name}")
        if service["kind"] in {"public", "mtls"}:
            require(re.fullmatch(r"[a-z][a-z0-9-]*\.lab\.test", service["host"]), f"Invalid lab name for {name}")
        if service["kind"] == "mtls":
            roles = set(service["roles"])
            require(roles and roles <= IDENTITIES - {"unassigned", "observer"}, f"Invalid authorized roles for {name}")
    used_ids = set(DENY_COUNTERS) | {"established", "wireguard_reply"}
    flows = set()
    for rule in policy["permits"]:
        validate_rule(rule, nodes, services, used_ids)
        source = nodes[rule["from"]]["segment"]
        service = services[rule["service"]]
        destination = nodes[service["node"]]["segment"] if service["node"] != "edge" else "wan"
        protocols = rule["protocols"]
        require(bool(protocols) and set(protocols) <= {"tcp", "udp"} and len(set(protocols)) == len(protocols),
                f"Invalid protocols in {rule['id']}")
        require((service["kind"] == "dns" and set(protocols) == {"tcp", "udp"}) or
                (service["kind"] == "wireguard" and protocols == ["udp"]) or
                (service["kind"] not in {"dns", "wireguard"} and protocols == ["tcp"]), f"Protocol does not match {rule['id']}")
        nat = rule.get("nat")
        require(nat in {None, "dnat", "snat"}, f"Invalid NAT in {rule['id']}")
        if nat == "dnat":
            require(source == "wan" and destination == "dmz" and service["kind"] == "public", "DNAT must publish a DMZ service")
        if nat == "snat":
            require(source not in {"wan", "vpn"} and destination == "wan" and service["kind"] == "egress", "SNAT must target the simulator")
        if service["kind"] == "mtls":
            role = rule.get("identity")
            require(role in service["roles"] or
                    (role == "observer" and rule["from"] == "monitor" and rule.get("path") == "/health"),
                    f"Missing authorized identity for {rule['id']}")
        for protocol in protocols:
            host, port = endpoint(policy, rule, True)
            flow = (rule["from"], host, port, protocol)
            require(flow not in flows, f"Repeated permit in {rule['id']}")
            flows.add(flow)
    for rule in policy["denials"]:
        validate_rule(rule, nodes, services, used_ids)
        host, port = endpoint(policy, rule, False)
        boundary = ipaddress.ip_address(host)
        require(any(boundary in network and boundary not in {network.network_address, network.broadcast_address} for network in occupied),
                f"Destination outside the lab or reserved in {rule['id']}")
        require(type(port) is int and 0 < port <= 65535 and rule["protocol"] in {"tcp", "udp"}, f"Invalid denial probe {rule['id']}")
        require((rule["from"], host, port, rule["protocol"]) not in flows, f"Denial overlaps a permit in {rule['id']}")


def validate_rule(rule, nodes, services, used_ids):
    name = rule["id"]
    require(ID.fullmatch(name) and name not in used_ids, f"Invalid or repeated rule name {name!r}")
    used_ids.add(name)
    require(rule["from"] in nodes and rule["service"] in services, f"Undefined endpoint in {name}")


def nft_set(values):
    return values[0] if len(values) == 1 else "{ " + ", ".join(sorted(values)) + " }"


def verdict_chain(name, verdict, event):
    return [
        f"  chain p_{name} {{",
        f"    counter name {name}",
        f'    limit rate 25/second burst 20 packets log prefix "ZTLAB {event} {name} "',
        f"    {verdict}",
        "  }",
    ]


def firewall(policy, disabled=()):
    segments, nodes, services = (policy[key] for key in ("segments", "nodes", "services"))
    rules = [rule for rule in policy["permits"] if rule["id"] not in disabled]
    wan, edge = segments["wan"]["interface"], address(policy, "edge")
    lines = ["# Generated by lab/model.py. Load only in the dedicated edge namespace.",
             "flush ruleset", "table inet ztlab_filter {"]
    for name in [*(rule["id"] for rule in rules), "established", "wireguard_reply", *DENY_COUNTERS]:
        lines.append(f"  counter {name} {{ }}")
    for rule in rules:
        lines.extend(verdict_chain(rule["id"], "accept", "ALLOW"))
    for name in DENY_COUNTERS:
        lines.extend(verdict_chain(name, "drop", "DROP"))
    lines.append("  chain source_validation {")
    for name, segment in segments.items():
        ips = [node["ip"] for node in nodes.values() if node["segment"] == name]
        lines.append(f'    iifname "{segment["interface"]}" ip saddr != {nft_set(ips)} jump p_drop_spoof')
    lines.append("  }")
    for chain in ("input", "forward", "output"):
        lines.extend([
            f"  chain {chain} {{",
            f"    type filter hook {chain} priority filter; policy drop;",
        ])
        if chain in {"input", "output"}:
            selector = "iifname" if chain == "input" else "oifname"
            lines.append(f'    {selector} "lo" accept')
        if chain != "output":
            lines.append("    jump source_validation")
        lines.extend([
            "    ct state invalid jump p_drop_invalid",
            "    ct state established,related counter name established accept",
        ])
        if chain == "output":
            ips = [address(policy, peer["transport"]) for peer in policy["peers"].values()]
            port = services["vpn"]["port"]
            lines.append(f'    oifname "{wan}" ip saddr {edge} ip daddr {nft_set(ips)} '
                         f'udp sport {port} counter name wireguard_reply accept')
        else:
            for rule in rules:
                source = nodes[rule["from"]]
                service = services[rule["service"]]
                target = service["node"]
                if (target == "edge") != (chain == "input"):
                    continue
                incoming = segments[source["segment"]]["interface"]
                outgoing = "" if chain == "input" else f' oifname "{segments[nodes[target]["segment"]]["interface"]}"'
                translated = " ct status dnat" if rule.get("nat") == "dnat" else ""
                for protocol in rule["protocols"]:
                    lines.append(f'    iifname "{incoming}"{outgoing} ip saddr {source["ip"]} '
                                 f'ip daddr {address(policy, target)} {protocol} dport {service["port"]}'
                                 f'{translated} ct state new jump p_{rule["id"]}')
        lines.extend([f"    jump p_deny_{chain}", "  }"])
    lines.extend(["}", "table ip ztlab_nat {"])
    for chain, kind in (("prerouting", "dnat"), ("postrouting", "snat")):
        priority = "dstnat" if kind == "dnat" else "srcnat"
        lines.extend([f"  chain {chain} {{", f"    type nat hook {chain} priority {priority}; policy accept;"])
        for rule in rules:
            if rule.get("nat") != kind:
                continue
            source = nodes[rule["from"]]
            service = services[rule["service"]]
            host, port = address(policy, service["node"]), service["port"]
            if kind == "dnat":
                lines.append(f'    iifname "{wan}" ip saddr {source["ip"]} ip daddr {edge} tcp dport {port} dnat to {host}')
            if kind == "snat":
                lines.append(f'    oifname "{wan}" ip saddr {source["ip"]} ip daddr {host} tcp dport {port} snat to {edge}')
        lines.append("  }")
    return "\n".join([*lines, "}", ""])


def matrix(policy):
    lines = [
        "# Authorized communication matrix",
        "",
        "Source of truth is [config/lab.json](../config/lab.json). The edge drops other new flows and permits stateful replies.",
        "",
        "| Policy row | Source | Destination as seen by client | Transport | Decision | Constraint |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for mode, key in (("Allow", "permits"), ("Drop", "denials")):
        for rule in policy[key]:
            host, port = endpoint(policy, rule, mode == "Allow")
            protocols = ", ".join(rule["protocols"] if mode == "Allow" else [rule["protocol"]])
            constraints = [part for part in (rule.get("nat", "").upper(), rule.get("identity"), rule.get("path")) if part]
            lines.append(f"| {rule['id']} | {rule['from']} | {rule['service']} at {host}:{port} | {protocols} "
                         f"| {mode} | {', '.join(constraints) or '—'} |")
    return "\n".join([*lines, ""])
