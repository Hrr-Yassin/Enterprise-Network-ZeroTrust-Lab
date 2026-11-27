"""Operations that may run only inside the lab's detached guest."""

import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path

RUN = Path("/run/ztlab")
SECRETS = RUN / "secrets"
TELEMETRY = RUN / "telemetry"
PYTHON = "/usr/bin/python3"


def guard():
    command_line = Path("/proc/cmdline").read_text().split()
    if not (os.geteuid() == 0 and (RUN / "guest").is_file() and
            set(command_line) & {"ztlab.mode=network", "ztlab.mode=verify", "ztlab.mode=live"}):
        raise RuntimeError("The deployment and acceptance suite require the booted, NIC-free lab guest")


@contextmanager
def source_namespace(name):
    guard()
    with Path("/proc/self/ns/net").open("rb") as original, (Path("/run/netns") / name).open("rb") as source:
        os.setns(source.fileno(), os.CLONE_NEWNET)
        try:
            yield
        finally:
            os.setns(original.fileno(), os.CLONE_NEWNET)


def command(*args, namespace=None, check=True, data=None, timeout=12):
    args = [str(arg) for arg in args]
    if namespace:
        args = ["ip", "-n", namespace, *args[1:]] if args[0] == "ip" else ["ip", "netns", "exec", namespace, *args]
    result = subprocess.run(args, text=True, capture_output=True, input=data, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[:6]} exited {result.returncode}: {result.stderr.strip()[:900]}")
    return result


def run(*args, **kwargs):
    return command(*args, **kwargs).stdout


def write_json(path, payload):
    staging = path.with_suffix(".tmp")
    staging.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    staging.replace(path)


def start(namespace, *args, stdout=None, stderr=None):
    args = ["ip", "netns", "exec", namespace, *(str(arg) for arg in args)]
    return subprocess.Popen(args, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL)
