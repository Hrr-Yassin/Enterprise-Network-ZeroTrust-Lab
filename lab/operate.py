"""Inspect or change only the dedicated edge firewall from the guest console."""

import argparse
import hashlib
import os
import re

from lab.guest import RUN, guard
from lab.model import firewall
from lab.runtime import Lab


def main():
    guard()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "backup", "validate", "apply", "restore"))
    parser.add_argument("name", nargs="?", help="Name of a backup or candidate staged under the guest backup directory")
    args = parser.parse_args()
    lab = Lab()
    expected = (RUN / "firewall.baseline").read_text().strip()
    if args.action == "status":
        observed = lab.fingerprint()
        print(f"Expected {expected}\nObserved {observed}")
        return int(expected != observed)
    directory = RUN / "firewall-backups"
    directory.mkdir(exist_ok=True, mode=0o700)
    path = None
    if args.name:
        if not re.fullmatch("[a-z][a-z0-9-]{0,32}", args.name):
            parser.error("Use a short lowercase snapshot name")
        path = directory / f"{args.name}.nft"
    if args.action == "backup":
        if not path:
            parser.error("Provide a new backup name")
        snapshot = lab.backup().encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(snapshot)
        print(f"Saved {path} SHA256 {hashlib.sha256(snapshot).hexdigest()}")
        return 0
    if args.action == "restore" and not path:
        parser.error("Provide the snapshot name to restore")
    if args.action in {"apply", "restore"} and path is None:
        parser.error("Stage a named candidate, then validate it before applying")
    if path and not path.is_file():
        parser.error(f"No readable candidate named {args.name}")
    candidate = path.read_text(encoding="utf-8") if path else firewall(lab.policy)
    if args.action == "validate":
        lab.apply(candidate, check_only=True)
        print("Candidate passed kernel validation")
    else:
        lab.apply(candidate)
        print(f"Applied candidate. Edge policy SHA256 {lab.fingerprint()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
