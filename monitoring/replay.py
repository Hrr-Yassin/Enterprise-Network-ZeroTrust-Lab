"""Check the locally installed optional IDS engines against the fixed synthetic capture."""

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONITORING = ROOT / "monitoring"
EVIDENCE = ROOT / "evidence"
CANARY = "ids-check.lab.test"


def events(path):
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]


def replay(engine, capture, output):
    executable = shutil.which(engine)
    if executable is None:
        return {"status": "missing"}
    output.mkdir()
    if engine == "suricata":
        args = [executable, "-c", MONITORING / "suricata.yaml", "-S", MONITORING / "local.rules",
                "-k", "none", "-r", capture, "-l", output]
    else:
        args = [executable, "-C", "-r", capture, MONITORING / "isolated.zeek"]
    try:
        process = subprocess.run(args, cwd=output, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"status": "timed_out"}
    (output / "engine.log").write_bytes(process.stdout + process.stderr)
    if process.returncode:
        return {"status": "error", "exit": process.returncode}
    if engine == "suricata":
        matched = any(row.get("event_type") == "alert" and row.get("alert", {}).get("signature_id") == 9900101
                      for row in events(output / "eve.json"))
    else:
        matched = any(row.get("query") == CANARY for row in events(output / "dns.log"))
    return {"status": "passed" if matched else "canary_missing"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=("all", "suricata", "zeek"), nargs="?", default="all")
    args = parser.parse_args()
    capture = EVIDENCE / "synthetic-dns.pcap"
    manifest = json.loads((EVIDENCE / "manifest.json").read_text())
    if hashlib.sha256(capture.read_bytes()).hexdigest() != manifest["artifact_sha256"][capture.name]:
        parser.error("The fixed synthetic capture differs from its verification manifest")
    started = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = ROOT / ".work" / "engine-replay" / started
    output.mkdir(parents=True, mode=0o700)
    names = ("suricata", "zeek") if args.engine == "all" else (args.engine,)
    result = {name: replay(name, capture, output / name) for name in names}
    report = json.dumps(result, indent=2) + "\n"
    (output / "results.json").write_text(report, encoding="utf-8")
    print(report, end="")
    return int(any(item["status"] != "passed" for item in result.values()))


if __name__ == "__main__":
    raise SystemExit(main())
