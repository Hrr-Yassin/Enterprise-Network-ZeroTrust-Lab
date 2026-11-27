"""Stage trusted offline IDS binaries and verify live traffic on the guest mirror."""

import json
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from lab.guest import TELEMETRY, guard, run, source_namespace, write_json
from lab.model import ROOT
from lab.sensor import CANARY

ENGINES = ("suricata", "zeek")
PREFIX = Path("/opt/ztlab/ids")
CONFIG = ROOT / "monitoring"
CAPTURE_DEVICE = "mon0"
CAPTURE_NAMESPACE = "monitor"
CANARY_SID = 9900101
INLINE_SID = 9900102
QUEUE = 81
EVIDENCE = "ids-observations.json"


def _bundle_file(source, relative):
    path = source / relative
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError(f"Missing IDS bundle file: {relative}") from error
    if not resolved.is_relative_to(source) or not resolved.is_file():
        raise ValueError(f"IDS bundle path must resolve to a regular file inside the bundle: {relative}")
    return resolved


def _bundle_directory(source, relative):
    directory = source / relative
    if directory.is_symlink() or not directory.is_dir() or not directory.resolve().is_relative_to(source):
        raise ValueError(f"IDS bundle directory must be a real directory inside the bundle: {relative}")
    return directory


def validate_bundle(source):
    """Return the regular files that belong to the offline IDS payload."""
    source = Path(source).resolve()
    if not source.is_dir():
        raise ValueError("Select a readable IDS bundle directory")

    files = {}
    for name in ENGINES:
        relative = Path("bin") / name
        executable = _bundle_file(source, relative)
        with executable.open("rb") as handle:
            header = handle.read(20)
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00" or not os.access(executable, os.X_OK):
            raise ValueError(f"IDS bundle {relative} must be an executable Linux x86-64 ELF file")
        files[relative] = executable

    for name in ("conn", "dns"):
        _bundle_file(source, Path("share/zeek/base/protocols") / name / "__load__.zeek")
    _bundle_directory(source, "share/zeek/policy")
    for name in ("share/zeek", "lib", "lib64"):
        tree = source / name
        if name != "share/zeek" and not tree.exists() and not tree.is_symlink():
            continue
        _bundle_directory(source, name)
        for path in sorted(tree.rglob("*")):
            relative = path.relative_to(source)
            if path.is_dir():
                if path.is_symlink():
                    raise ValueError(f"IDS bundle directory symlinks are unsupported: {relative}")
                continue
            files[relative] = _bundle_file(source, relative)
    return files


def stage_bundle(root, source):
    """Copy only the selected runtime payload into a fresh initramfs staging tree."""
    from lab.build import copy
    from lab.observability import library_paths

    files = validate_bundle(source)
    preferred = {path.name: original for path, original in files.items()
                 if len(path.parts) == 2 and path.parts[0] in {"lib", "lib64"}}
    for guest_path, original in library_paths([files[Path("bin") / name] for name in ENGINES], preferred).items():
        if Path(guest_path).name not in preferred:
            copy(original, root, guest_path)
    target = root / PREFIX.relative_to("/")
    for relative, resolved in files.items():
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(resolved, destination)
        destination.chmod(0o755 if relative.parts[0] == "bin" else 0o644)
    (target / ".ready").write_text("1\n", encoding="ascii")


def enabled():
    return (PREFIX / ".ready").is_file()


@dataclass
class CaptureEngine:
    name: str
    process: subprocess.Popen
    output: Path
    version: str


def _environment():
    zeek_scripts = PREFIX / "share/zeek"
    script_dirs = (zeek_scripts, zeek_scripts / "policy", zeek_scripts / "site",
                   zeek_scripts / "builtin-plugins")
    lib_dirs = (PREFIX / "lib64", PREFIX / "lib")
    return {
        **os.environ,
        "LD_LIBRARY_PATH": ":".join(map(str, lib_dirs)),
        "ZEEKPATH": ":".join(map(str, script_dirs)),
        "ZEEK_PLUGIN_PATH": ":".join(str(path / "zeek/plugins") for path in lib_dirs),
    }


def _command(name, *args):
    return ("ip", "netns", "exec", CAPTURE_NAMESPACE, str(PREFIX / "bin" / name), *map(str, args))


def _read_version(name, output):
    option = "-V" if name == "suricata" else "--version"
    try:
        result = subprocess.run(_command(name, option), capture_output=True, text=True, timeout=25,
                                env=_environment())
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{name} version probe timed out in the detached guest") from error
    (output / "version.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    pattern = rf"\b{name}\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.-]+)?)\b"
    match = re.search(pattern, result.stdout + result.stderr, flags=re.IGNORECASE)
    if result.returncode or not match:
        raise RuntimeError(f"Unable to verify the {name} version in the guest. Read {output / 'version.log'} from the live guest.")
    return match.group(1)


def _require_running(engines):
    for engine in engines:
        code = engine.process.poll()
        if code is not None:
            raise RuntimeError(f"{engine.name} exited with status {code}. Read {engine.output / 'engine.log'} from the live guest.")


def _packet_socket_inodes():
    with source_namespace(CAPTURE_NAMESPACE):
        interface = socket.if_nametoindex(CAPTURE_DEVICE)
        header, *rows = Path("/proc/net/packet").read_text().splitlines()
    columns = header.split()
    index, inode = columns.index("Iface"), columns.index("Inode")
    return {fields[inode] for row in rows if (fields := row.split()) and int(fields[index]) == interface}


def _process_socket_inodes(process):
    found = set()
    for descriptor in (Path("/proc") / str(process.pid) / "fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            found.add(match.group(1))
    return found


def start_engines():
    """Open both passive captures and wait for their sockets to bind to mon0."""
    guard()
    if not enabled():
        raise RuntimeError("The detached guest was built without an IDS bundle")
    link, = json.loads(run("ip", "-j", "address", "show", "dev", CAPTURE_DEVICE,
                           namespace=CAPTURE_NAMESPACE))
    if link.get("addr_info"):
        raise RuntimeError("The IDS capture port must have no address")
    engines = []
    try:
        for name in ENGINES:
            output = TELEMETRY / "ids" / name
            output.mkdir(mode=0o700, parents=True, exist_ok=True)
            version = _read_version(name, output)
            if name == "suricata":
                options = (f"--af-packet={CAPTURE_DEVICE}", "-c", CONFIG / "suricata.yaml",
                           "-S", CONFIG / "local.rules", "-k", "none", "-l", output)
            else:
                options = ("-C", "-i", CAPTURE_DEVICE, CONFIG / "isolated.zeek")
            with (output / "engine.log").open("ab") as log:
                process = subprocess.Popen(_command(name, *options), cwd=output, stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=log, env=_environment())
            engines.append(CaptureEngine(name, process, output, version))

        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            _require_running(engines)
            attached = _packet_socket_inodes()
            try:
                if all(attached & _process_socket_inodes(engine.process) for engine in engines):
                    _require_running(engines)
                    return engines
            except FileNotFoundError:
                _require_running(engines)
            time.sleep(0.2)
        raise RuntimeError(f"Both engine capture sockets must bind to {CAPTURE_NAMESPACE}/{CAPTURE_DEVICE}")
    except BaseException:
        stop_engines(engines)
        raise


def stop_engines(engines):
    """Reap the configured guest process handles, including on acceptance failure."""
    for engine in engines:
        if engine.process.poll() is None:
            engine.process.terminate()
    for engine in engines:
        try:
            engine.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            engine.process.kill()
            engine.process.wait()


def _records(path):
    try:
        with path.open("rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            stream.seek(max(0, size - 1_000_000))
            if size > 1_000_000:
                stream.readline()
            for line in stream:
                if not line.endswith(b"\n"):
                    break
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, ValueError):
                    continue
                if isinstance(record, dict):
                    yield record
    except FileNotFoundError:
        return


def _zeek_flow(record, source, resolver):
    return (
        record.get("id.orig_h") == source and record.get("id.resp_h") == resolver and
        record.get("id.resp_p") == 53 and record.get("proto") == "udp"
    )


def _suricata_alert(path, source, resolver):
    for row in _records(path):
        alert = row.get("alert")
        if (row.get("event_type") == "alert" and isinstance(alert, dict) and alert.get("signature_id") == CANARY_SID
                and row.get("src_ip") == source and row.get("dest_ip") == resolver
                and row.get("dest_port") == 53 and str(row.get("proto", "")).lower() == "udp"):
            return row
    return None


def _zeek_correlation(output, source, resolver):
    queries = {
        row["uid"] for row in _records(output / "dns.log") if row.get("uid") and
        _zeek_flow(row, source, resolver) and str(row.get("query", "")).rstrip(".").lower() == CANARY
        and row.get("rcode") == 0
    }
    return any(row.get("uid") in queries and _zeek_flow(row, source, resolver)
               for row in _records(output / "conn.log"))


def check(engines, source_ip, resolver_ip, pulse):
    """Verify independently observed alerts and correlated DNS and connection records."""
    guard()
    active = {engine.name: engine for engine in engines}
    suricata = active["suricata"]
    zeek = active["zeek"]
    deadline = time.monotonic() + 35
    next_pulse = time.monotonic() + 6
    while True:
        _require_running(engines)
        alert = _suricata_alert(suricata.output / "eve.json", source_ip, resolver_ip)
        correlation = _zeek_correlation(zeek.output, source_ip, resolver_ip)
        if alert and correlation:
            break
        if not correlation and time.monotonic() >= next_pulse:
            # A fresh fixture packet advances Zeek's live network time past the idle timer.
            pulse()
            next_pulse = time.monotonic() + 6
        if time.monotonic() >= deadline:
            missing = []
            if not alert:
                missing.append("Suricata canary signature")
            if not correlation:
                missing.append("correlated Zeek DNS and connection records")
            raise AssertionError("Live mirror evidence missing " + " and ".join(missing))
        time.sleep(0.25)

    _require_running(engines)
    write_json(TELEMETRY / EVIDENCE, {
        "capture": {"mode": "passive", "namespace": CAPTURE_NAMESPACE, "interface": CAPTURE_DEVICE, "addressed": False},
        "fixture": {"source": source_ip, "resolver": resolver_ip, "port": 53, "transport": "udp", "query": CANARY},
        "suricata": {"version": suricata.version, "signature_id": CANARY_SID, "event_type": "alert"},
        "zeek": {"version": zeek.version, "dns_rcode": 0, "connection_uid_matched": True},
    })
    return f"Suricata {suricata.version} matched SID {CANARY_SID}. Zeek {zeek.version} correlated the DNS and UDP connection records."


def telemetry():
    path = TELEMETRY / "ids"
    return {
        "suricata_alerts": sum(row.get("event_type") == "alert" for row in _records(path / "suricata/eve.json")),
        "zeek_dns": sum(1 for _ in _records(path / "zeek/dns.log")),
        "zeek_connections": sum(1 for _ in _records(path / "zeek/conn.log")),
    }


def verify_inline(lab, query):
    """Activate Suricata on one isolated DNS path and remove the queue afterward."""
    guard()
    output = TELEMETRY / "ids-inline"
    output.mkdir(mode=0o700)
    run("modprobe", "nfnetlink_queue")
    run("modprobe", "nft_queue")
    source, resolver = (lab.policy["nodes"][name]["ip"] for name in ("employee", "resolver"))
    answer = lab.policy["nodes"]["api"]["ip"]
    before = lab.fingerprint()
    queue = f"""table inet ztlab_inline {{
  chain canary {{
    type filter hook forward priority 10; policy accept;
    ip saddr {source} ip daddr {resolver} udp dport 53 queue num {QUEUE}
  }}
}}
"""
    active = False
    worker = None
    try:
        with (output / "engine.log").open("wb") as log, source_namespace("edge"):
            worker = subprocess.Popen(
                [PREFIX / "bin/suricata", "-q", str(QUEUE), "--runmode", "workers",
                 "-c", CONFIG / "suricata.yaml", "-S", CONFIG / "inline.rules", "-l", output],
                cwd=output, env=_environment(), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            )
        deadline = time.monotonic() + 25
        with source_namespace("edge"):
            while time.monotonic() < deadline:
                if worker.poll() is not None:
                    raise RuntimeError(f"Suricata inline exited with status {worker.returncode}")
                if any(line.split()[0] == str(QUEUE) for line in
                       Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines() if line.strip()):
                    break
                time.sleep(0.15)
            else:
                raise RuntimeError("Suricata did not subscribe to the guest NFQUEUE")
        run("nft", "-f", "-", namespace="edge", data=queue)
        active = True
        permitted = query("app.lab.test").get("answers") == [answer]
        blocked = query(CANARY).get("result") == "timeout"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            event = next((record.get("alert") for record in _records(output / "eve.json")
                          if record.get("event_type") == "alert" and record.get("src_ip") == source
                          and record.get("dest_ip") == resolver
                          and record.get("alert", {}).get("signature_id") == INLINE_SID), None)
            if event and event.get("action") == "blocked":
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Suricata did not log a blocked verdict for the synthetic inline canary")
    finally:
        try:
            if active:
                run("nft", "delete", "table", "inet", "ztlab_inline", namespace="edge")
        finally:
            if worker is not None and worker.poll() is None:
                worker.terminate()
                try:
                    worker.wait(5)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.wait()
    if not permitted or not blocked or query(CANARY).get("answers") != [answer] or lab.fingerprint() != before:
        raise AssertionError("Inline exercise did not pass normal DNS, drop the canary, and restore the firewall")
    write_json(TELEMETRY / "ips-observations.json", {
        "engine": "Suricata", "capture": "edge NFQUEUE", "queue": QUEUE,
        "source": source, "resolver": resolver, "canary": CANARY, "signature_id": INLINE_SID,
        "normal_dns_passed": True, "canary_timed_out": True, "suricata_verdict": "blocked",
        "canary_recovered": True, "firewall_fingerprint_restored": True,
    })
    return "Suricata allowed ordinary DNS and blocked the synthetic canary inline. Removed the queue and verified recovery."
