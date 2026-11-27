#!/usr/bin/env python3
"""Run the lab's localhost playbook with system Ansible or a local wheelhouse."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTOMATION = ROOT / "automation"


def wheel_paths(directory):
    if not directory.is_dir():
        raise ValueError("The supplied Ansible wheelhouse is not a readable directory")
    wheels = sorted(path.resolve() for path in directory.glob("*.whl") if path.is_file())
    if not any(path.name.startswith("ansible_core-") for path in wheels):
        raise ValueError("The wheelhouse must include an ansible-core wheel and its dependency wheels")
    return wheels


def playbook_binary(work, wheels):
    if wheels is None:
        executable = shutil.which("ansible-playbook")
        if not executable:
            raise ValueError("Provide --wheelhouse with local ansible-core and dependency wheels")
        return executable
    environment = work / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    pip = [environment / "bin/python", "-m", "pip", "--isolated", "--disable-pip-version-check"]
    pip_env = {**os.environ, "PIP_CONFIG_FILE": os.devnull}
    # Install explicit wheel paths only. Pip does not resolve requirements or use package indexes.
    subprocess.run([*pip, "install", "--no-index", "--no-deps", "--only-binary=:all:", *wheels], check=True, env=pip_env)
    subprocess.run([*pip, "check"], check=True, env=pip_env)
    return environment / "bin/ansible-playbook"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, help="Directory with a compatible ansible-core dependency closure")
    parser.add_argument("--check", action="store_true", help="Validate the policy and bundle layouts only")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--ids-bundle", type=Path)
    parser.add_argument("--observability-bundle", type=Path)
    parser.add_argument("--accelerator", choices=("auto", "kvm", "tcg"), default="auto")
    args = parser.parse_args()
    wheels = wheel_paths(args.wheelhouse) if args.wheelhouse else None
    work = ROOT / ".work" / "ansible"
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=work, prefix="playbook-") as directory:
        sandbox = Path(directory)
        executable = playbook_binary(sandbox, wheels)
        local_temp, remote_temp = sandbox / "local-tmp", sandbox / "remote-tmp"
        for path in (local_temp, remote_temp):
            path.mkdir(mode=0o700)
        variables = {
            "lab_browser": args.browser, "lab_accelerator": args.accelerator,
            "lab_ids_bundle": str(args.ids_bundle.resolve()) if args.ids_bundle else "",
            "lab_observability_bundle": str(args.observability_bundle.resolve()) if args.observability_bundle else "",
        }
        command = [executable, "-i", "localhost,", AUTOMATION / "site.yml", "--extra-vars", json.dumps(variables)]
        if args.check:
            command.append("--check")
        env = {key: value for key, value in os.environ.items() if not key.startswith("ANSIBLE_")}
        env.update(ANSIBLE_CONFIG=str(AUTOMATION / "ansible.cfg"), ANSIBLE_HOME=str(sandbox),
                   ANSIBLE_LOCAL_TEMP=str(local_temp), ANSIBLE_REMOTE_TEMP=str(remote_temp))
        return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Lab automation error: {error}", file=sys.stderr)
        sys.exit(1)
