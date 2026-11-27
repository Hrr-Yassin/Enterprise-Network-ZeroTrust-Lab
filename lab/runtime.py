"""Build the isolated L2/L3 topology, bring up policy and run the guest entry points."""

import base64
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
from pathlib import Path

from lab.guest import RUN, SECRETS, TELEMETRY, guard, run
from lab.model import DENY_COUNTERS, address, firewall, load


class Lab:
    def __init__(self):
        guard()
        self.policy = load()
        self.nodes = self.policy["nodes"]
        self.segments = self.policy["segments"]
        self.services = self.policy["services"]
        self.peers = self.policy["peers"]
        self.peer_keys = {}
        self.peer_observations = {}
        self.baseline = None

    def namespace(self, node):
        return self.peers[node]["transport"] if node in self.peers else node

    def edge(self, *args, **kwargs):
        return run(*args, namespace="edge", **kwargs)

    def setup(self):
        for path, mode in ((SECRETS, 0o700), (TELEMETRY, 0o755)):
            path.mkdir(mode=mode)
        for name in ("veth", "bridge", "nf_conntrack", "nf_tables", "nft_ct", "nft_log", "nft_limit", "nft_nat",
                     "nft_chain_nat", "nf_log_syslog", "wireguard", "sch_ingress", "cls_matchall", "act_mirred"):
            run("modprobe", name)
        run("sysctl", "-w", "net.netfilter.nf_log_all_netns=1")
        parent_links = json.loads(run("ip", "-j", "link", "show"))
        if {link["ifname"] for link in parent_links} != {"lo"}:
            raise RuntimeError("Detached guest isolation check failed")
        names = [name for name in self.nodes if name not in self.peers]
        for name in ["edge", *names]:
            run("ip", "netns", "add", name)
            run("ip", "link", "set", "lo", "up", namespace=name)
            run("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1",
                namespace=name)
            run("sysctl", "-w", "net.ipv4.ip_unprivileged_port_start=0", namespace=name)
        run("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1")
        run("ip", "link", "add", "br-wan", "type", "bridge")
        run("ip", "link", "set", "br-wan", "up")
        self.wan_port("edge", self.segments["wan"]["interface"], 0)
        for index, name in enumerate(names, 1):
            node = self.nodes[name]
            zone = node["segment"]
            segment = self.segments[zone]
            interface = segment["interface"]
            if zone == "wan":
                self.wan_port(name, "eth0", index)
            else:
                self.pair("edge", interface, name, "eth0")
                self.configure("edge", interface, segment["gateway"], segment)
            self.configure(name, "eth0", node["ip"], segment)
            run("ip", "route", "replace", "default", "via", segment["gateway"], namespace=name)
        self.configure("edge", self.segments["wan"]["interface"], address(self.policy, "edge"), self.segments["wan"])
        self.make_wireguard()
        self.apply(firewall(self.policy))
        self.baseline = self.fingerprint()
        self.edge("sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.send_redirects=0",
                  "net.ipv4.conf.default.send_redirects=0",
                  *(f"net.ipv4.conf.{segment['interface']}.send_redirects=0" for segment in self.segments.values()))
        (RUN / "firewall.baseline").write_text(self.baseline + "\n", encoding="ascii")
        self.pair("edge", "tap0", "monitor", "mon0")
        for segment in self.segments.values():
            interface = segment["interface"]
            self.edge("tc", "qdisc", "add", "dev", interface, "clsact")
            self.edge("tc", "filter", "add", "dev", interface, "ingress", "matchall",
                      "action", "mirred", "egress", "mirror", "dev", "tap0")

    def pair(self, left, left_if, right, right_if):
        run("ip", "link", "add", "dev", left_if, "netns", left, "type", "veth",
            "peer", "name", right_if, "netns", right)
        for namespace, interface in ((left, left_if), (right, right_if)):
            run("ip", "link", "set", interface, "up", namespace=namespace)

    def wan_port(self, namespace, interface, index):
        port = f"wan{index}"
        run("ip", "link", "add", "dev", port, "type", "veth", "peer", "name", interface, "netns", namespace)
        run("ip", "link", "set", port, "master", "br-wan")
        run("ip", "link", "set", port, "up")
        run("ip", "link", "set", interface, "up", namespace=namespace)

    @staticmethod
    def configure(namespace, interface, ip, segment):
        prefix = ipaddress.ip_network(segment["network"]).prefixlen
        run("ip", "addr", "add", f"{ip}/{prefix}", "dev", interface, namespace=namespace)

    @staticmethod
    def wg_key(name):
        key = SECRETS / f"{name}.wg"
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(run("wg", "genkey"))
        return key, run("wg", "pubkey", data=key.read_text()).strip()

    def make_wireguard(self):
        segment = self.segments["vpn"]
        port = self.services["vpn"]["port"]
        private_key, public_key = self.wg_key("edge")
        self.edge_public = public_key
        self.edge("ip", "link", "add", "wg0", "type", "wireguard")
        self.configure("edge", "wg0", segment["gateway"], segment)
        self.edge("wg", "set", "wg0", "listen-port", port, "private-key", private_key)
        for name in self.peers:
            namespace = self.namespace(name)
            key, self.peer_keys[name] = self.wg_key(name)
            self.authorize_peer(name)
            run("ip", "link", "add", "wg0", "type", "wireguard", namespace=namespace)
            self.configure(namespace, "wg0", self.nodes[name]["ip"], segment)
            run("wg", "set", "wg0", "private-key", key, namespace=namespace)
            self.configure_remote_peer(name)
            run("ip", "link", "set", "wg0", "mtu", "1420", "up", namespace=namespace)
            run("ip", "route", "add", "10.77.0.0/16", "dev", "wg0", namespace=namespace)
        self.edge("ip", "link", "set", "wg0", "mtu", "1420", "up")

    def configure_remote_peer(self, name, reset=False):
        namespace = self.namespace(name)
        if reset:
            run("wg", "set", "wg0", "peer", self.edge_public, "remove", namespace=namespace)
        gateway, port = address(self.policy, "edge"), self.services["vpn"]["port"]
        run("wg", "set", "wg0", "peer", self.edge_public, "endpoint", f"{gateway}:{port}",
            "allowed-ips", "10.77.0.0/16", namespace=namespace)

    def authorize_peer(self, name):
        self.edge("wg", "set", "wg0", "peer", self.peer_keys[name], "allowed-ips", f"{self.nodes[name]['ip']}/32")

    def revoke_peer(self, name):
        self.edge("wg", "set", "wg0", "peer", self.peer_keys[name], "remove")

    def peer_status(self):
        stamps = {key: int(stamp) for key, stamp in
                  (row.split() for row in self.edge("wg", "show", "wg0", "latest-handshakes").splitlines())}
        transfers = {key: (int(rx), int(tx)) for key, rx, tx in
                     (row.split() for row in self.edge("wg", "show", "wg0", "transfer").splitlines())}
        result = {}
        for name, key in self.peer_keys.items():
            stamp = stamps.get(key, 0)
            rx, tx = transfers.get(key, (0, 0))
            authorized = key in stamps
            result[name] = {"authorized": authorized, "handshake_recent": bool(stamp and time.time() - stamp < 180),
                            "last_handshake_utc_epoch": stamp, "rx_bytes": rx, "tx_bytes": tx}
            observation = (authorized, stamp)
            if self.peer_observations.get(name) != observation:
                with (TELEMETRY / "vpn-events.jsonl").open("a", encoding="utf-8") as log:
                    event = {"peer": name, "authorized": authorized, "handshake_utc_epoch": stamp,
                             "observed_utc_epoch": int(time.time())}
                    log.write(json.dumps(event, sort_keys=True) + "\n")
                self.peer_observations[name] = observation
        return result

    def apply(self, text, check_only=False):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=RUN, prefix="candidate-", suffix=".nft") as candidate:
            candidate.write(text)
            candidate.flush()
            self.edge("nft", "-c", "-f", candidate.name)
            if not check_only:
                self.edge("nft", "-f", candidate.name)

    def backup(self):
        return "flush ruleset\n" + self.edge("nft", "-s", "list", "ruleset")

    def fingerprint(self):
        live = json.loads(self.edge("nft", "-s", "-j", "list", "ruleset"))["nftables"]
        for entry in live:
            for fields in entry.values():
                for name in ("handle", "packets", "bytes"):
                    fields.pop(name, None)
        return hashlib.sha256(json.dumps(live[1:], sort_keys=True).encode()).hexdigest()

    def counters(self):
        raw = json.loads(self.edge("nft", "-j", "list", "counters", "inet", "ztlab_filter"))["nftables"]
        return {item["counter"]["name"]: item["counter"]["packets"] for item in raw if "counter" in item}

    def firewall_metrics(self):
        counters = self.counters()
        allowed = sum(counters.get(rule["id"], 0) for rule in self.policy["permits"])
        return {"allowed_new_packets": allowed, "dropped_packets": sum(counters.get(name, 0) for name in DENY_COUNTERS),
                "stateful_reply_packets": counters.get("established", 0), "counters": counters}

    def segment_status(self):
        links = {entry["ifname"]: entry for entry in json.loads(self.edge("ip", "-j", "-s", "link", "show"))}
        return [
            {"id": name, "name": segment["name"], "network": segment["network"],
             "up": "LOWER_UP" in links[segment["interface"]]["flags"],
             "rx_bytes": links[segment["interface"]]["stats64"]["rx"]["bytes"],
             "tx_bytes": links[segment["interface"]]["stats64"]["tx"]["bytes"]}
            for name, segment in self.segments.items()
        ]

    def firewall_events(self):
        events = []
        for line in run("dmesg").splitlines():
            if "ZTLAB ALLOW " not in line and "ZTLAB DROP " not in line:
                continue
            prefix, marker = line.split("ZTLAB ", 1)
            fields = marker.split()
            include = ("IN=", "OUT=", "SRC=", "DST=", "PROTO=", "SPT=", "DPT=")
            stamp = re.search(r"\[\s*(\d+\.\d+)\]", prefix)
            time_field = [f"UPTIME={stamp[1]}"] if stamp else []
            events.append(" ".join([*fields[:2], *time_field, *(field for field in fields[2:] if field.startswith(include))]))
        return events[-400:]


def emit(name, payload):
    print(f"ZTLAB FILE {name} {base64.b64encode(payload).decode('ascii')}", flush=True)


def run_main():
    lab = Lab()
    mode = next(word.split("=", 1)[1] for word in Path("/proc/cmdline").read_text().split()
                if word.startswith("ztlab.mode="))
    lab.setup()
    print(f"ZTLAB NETWORK READY {len(lab.segments)} segments, {len(lab.policy['permits'])} permit rows", flush=True)
    if mode == "network":
        status = lab.segment_status()
        if not all(segment["up"] for segment in status):
            raise RuntimeError("One or more lab networks did not come up")
        emit("network.json", json.dumps({"segments": status, "firewall_sha256": lab.baseline}).encode())
        return
    from lab.verify import verify, verify_identity, live
    if mode in {"verify", "verify-addons"}:
        verify(lab, addons_only=(mode == "verify-addons"))
    elif mode == "identity":
        verify_identity(lab)
    else:
        live(lab)


if __name__ == "__main__":
    run_main()
