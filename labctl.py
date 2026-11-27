#!/usr/bin/env python3
"""Host entry point. All network creation and traffic run inside a NIC-free guest."""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from lab import build
from lab.model import ROOT, firewall, load, matrix

WORK = ROOT / ".work"
FILES = {
    "network.json", "checks.json", "telemetry.json", "firewall-events.log", "identity-events.jsonl",
    "synthetic-dns.pcap", "packet-summary.txt", "dashboard.html", "dashboard.png", "firewall-backup.nft", "vpn-events.jsonl",
}
RECORD = re.compile(r"ZTLAB FILE ([a-z0-9.-]+) ([A-Za-z0-9+/=]+)\Z")
RUN_ID = re.compile(r"\d{8}T\d{12}Z\Z")


def guest_command(args, image, mode):
    accelerator = args.accelerator
    if accelerator == "auto":
        accelerator = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    memory = 1536 if args.browser else 640
    command = [
        build.executable("qemu-system-x86_64"), "-no-user-config", "-machine", f"pc,accel={accelerator}",
        "-smp", "2", "-m", f"{memory}M", "-display", "none", "-nodefaults", "-nic", "none",
        "-serial", "stdio", "-monitor", "none", "-no-reboot",
        "-kernel", args.kernel, "-initrd", image, "-append",
        f"console=ttyS0,115200 quiet loglevel=3 rdinit=/init panic=1 ztlab.mode={mode}",
    ]
    return command, accelerator, memory


def extract(serial, output):
    files = {}
    for line in serial.splitlines():
        match = RECORD.fullmatch(line)
        if match and match[1] in FILES:
            name = match[1]
            if name in files:
                raise RuntimeError(f"Guest emitted {name} more than once")
            data = base64.b64decode(match[2], validate=True)
            if len(data) > 4_000_000:
                raise RuntimeError(f"Oversize evidence artifact {name}")
            (output / name).write_bytes(data)
            files[name] = hashlib.sha256(data).hexdigest()
    return files


def record_run(args, image, mode):
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = WORK / "runs" / run_id
    output.mkdir(mode=0o700, parents=True)
    serial_path = output / "serial.log"
    print(f"Running the isolated {mode} guest. Private run log: {serial_path.relative_to(ROOT)}", flush=True)
    command, accelerator, memory = guest_command(args, image, mode)
    started = time.monotonic()
    peak = 0
    timed_out = False
    with serial_path.open("wb") as log, subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT
    ) as process:
        while process.poll() is None:
            try:
                status = Path(f"/proc/{process.pid}/status").read_text(encoding="ascii")
                match = re.search(r"^VmHWM:\s+(\d+)", status, re.MULTILINE)
                if match:
                    peak = max(peak, int(match[1]))
            except OSError:
                pass
            if time.monotonic() - started > args.timeout:
                timed_out = True
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                break
            time.sleep(0.2)
        status = process.returncode
    serial = serial_path.read_text(encoding="utf-8", errors="replace")
    files = extract(serial, output)
    with image.open("rb") as archive:
        image_hash = hashlib.file_digest(archive, "sha256").hexdigest()
    manifest = {
        "run": run_id, "mode": mode, "accelerator": accelerator, "guest_memory_mib": memory,
        "vcpus": 2, "elapsed_seconds": round(time.monotonic() - started, 2),
        "peak_host_qemu_rss_kib": peak or None, "initramfs_bytes": image.stat().st_size,
        "initramfs_sha256": image_hash,
        "kernel_release": args.kernel.name.removeprefix("vmlinuz-"), "host_network_attachment": False,
        "policy_sha256": hashlib.sha256((ROOT / "config/lab.json").read_bytes()).hexdigest(),
        "artifact_sha256": files, "qemu_exit": status, "timed_out": timed_out,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for line in serial.splitlines():
        if line.startswith("ZTLAB ") and not line.startswith("ZTLAB FILE "):
            print(line)
    print(f"Run artifacts: {output.relative_to(ROOT)}")
    if status or timed_out or (mode == "network" and "network.json" not in files):
        return 1
    if mode == "verify":
        if "checks.json" not in files:
            return 1
        report = json.loads((output / "checks.json").read_text(encoding="utf-8"))
        return int(not report["checks"] or any(not check["passed"] for check in report["checks"]))
    return 0


def report_run(run_id, export):
    directory = WORK / "runs"
    if run_id:
        if not RUN_ID.fullmatch(run_id):
            raise ValueError("Enter a complete UTC run ID from .work/runs")
        source = directory / run_id
    else:
        source = next((path for path in sorted(directory.glob("*"), reverse=True) if (path / "checks.json").is_file()), None)
    if source is None or not (source / "checks.json").is_file():
        raise RuntimeError("No completed acceptance evidence found")
    manifest = json.loads((source / "manifest.json").read_text())
    run_report = json.loads((source / "checks.json").read_text())
    passed = sum(item["passed"] for item in run_report["checks"])
    summary = [
        "# Acceptance results", "",
        f"Run {manifest['run']} passed {passed} of {len(run_report['checks'])} checks.",
        f"The suite tested {run_report['tested_permits']} allowed protocol paths and "
        f"{run_report['tested_denials']} denied paths against the communication matrix.", "",
        "| Check | Result | Observation |", "| --- | --- | --- |",
    ]
    for item in run_report["checks"]:
        observation = str(item["result"]).replace("|", "\\|").replace("\n", " ")
        summary.append(f"| {item['id']} | {'Pass' if item['passed'] else 'Fail'} | {observation} |")
    rendered = "\n".join([*summary, ""])
    if export:
        target = ROOT / "evidence"
        target.mkdir(exist_ok=True)
        for name, digest in manifest["artifact_sha256"].items():
            if name not in FILES or hashlib.sha256((source / name).read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"Artifact integrity check failed for {name}")
        for name in [*manifest["artifact_sha256"], "manifest.json"]:
            shutil.copyfile(source / name, target / name)
        (target / "results.md").write_text(rendered, encoding="utf-8")
        print(f"Exported allowlisted artifacts for {manifest['run']} to evidence/")
    else:
        print(rendered, end="")
    return int(passed != len(run_report["checks"]))


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "build", "network", "verify", "live", "report"))
    parser.add_argument("--kernel", type=Path, default=Path(f"/boot/vmlinuz-{platform.release()}"))
    parser.add_argument("--accelerator", choices=("auto", "kvm", "tcg"), default="auto")
    parser.add_argument("--browser", action="store_true", help="Pack local Chromium Headless Shell for screenshot evidence")
    parser.add_argument("--chromium", type=Path, help="Select an existing chrome-headless-shell executable")
    parser.add_argument("--timeout", type=int, default=260, help="Guest verification deadline in seconds")
    parser.add_argument("--reuse-image", action="store_true", help="Use the previously built image for this profile")
    parser.add_argument("--run-id", help="Select the source run for report")
    parser.add_argument("--export-evidence", action="store_true", help="Copy the allowlisted run evidence into evidence/")
    return parser.parse_args()


def main():
    args = arguments()
    if args.chromium:
        args.browser = True
    if args.action == "report":
        return report_run(args.run_id, args.export_evidence)
    policy = load()
    if args.action == "plan":
        if (ROOT / "docs/communication-matrix.md").exists() and (
            ROOT / "docs/communication-matrix.md"
        ).read_text(encoding="utf-8") != matrix(policy):
            raise RuntimeError("The committed communication matrix differs from the policy model")
        if (ROOT / "config/edge.nft").exists() and (ROOT / "config/edge.nft").read_text(encoding="utf-8") != firewall(policy):
            raise RuntimeError("The committed edge rules differ from the policy model")
        print(f"Validated {len(policy['segments'])} segments, {len(policy['permits'])} permits "
              f"and {len(policy['denials'])} denial cases")
        print(firewall(policy), end="")
        return 0
    image_dir = WORK / ("browser" if args.browser else "base")
    image = image_dir / "lab.cpio.gz"
    if not args.reuse_image:
        browser = build.browser_source(args.chromium) if args.browser else None
        image = build.build(image_dir, args.kernel, browser)
    elif not image.is_file():
        raise RuntimeError("No previously built image for this profile")
    if args.action == "build":
        print(f"{image.relative_to(ROOT)} ({image.stat().st_size:,} bytes)")
        return 0
    if args.action == "live":
        command, _, _ = guest_command(args, image, "live")
        return subprocess.call(command)
    return record_run(args, image, args.action)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Lab error: {error}", file=sys.stderr)
        sys.exit(1)
