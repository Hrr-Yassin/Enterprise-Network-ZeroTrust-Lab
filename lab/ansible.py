"""Install local Ansible wheels and run an idempotent role inside the guest."""

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from zipfile import ZipFile

from lab.guest import PYTHON, RUN, TELEMETRY, guard, write_json
from lab.model import ROOT

PREFIX = Path("/opt/ztlab-ansible")
STATE = RUN / "ansible"


def validate_bundle(source):
    directory = Path(source).resolve(strict=True)
    wheels = sorted(directory.glob("*.whl"))
    if len([path for path in wheels if path.name.startswith("ansible_core-")]) != 1:
        raise ValueError("The guest wheelhouse requires one ansible-core wheel plus its compatible dependencies")
    if any(path.is_symlink() or not path.is_file() for path in wheels):
        raise ValueError("The guest Ansible wheelhouse accepts regular local wheel files")
    return wheels


def stage_bundle(staging, source):
    import encodings.cp437

    target = staging / PREFIX.relative_to("/")
    target.mkdir(parents=True)
    digests = {}
    for wheel in validate_bundle(source):
        with wheel.open("rb") as stream:
            digests[wheel.name] = hashlib.file_digest(stream, "sha256").hexdigest()
        shutil.copyfile(wheel, target / wheel.name)
    write_json(target / "wheels.json", digests)
    shutil.copyfile(ROOT / "automation/guest.yml", target / "guest.yml")
    shutil.copyfile(ROOT / "automation/ansible.cfg", target / "ansible.cfg")
    locale = Path("/usr/lib/locale/C.utf8")
    if not locale.is_dir():
        raise RuntimeError("The local Fedora C.utf8 locale is required for the guest Ansible CLI")
    shutil.copytree(locale, staging / locale.relative_to("/"))
    # Fedora can ship this codec solely as bytecode. Ansible's zip modules need it.
    codec = Path(encodings.cp437.__file__)
    shutil.copyfile(codec, staging / codec.relative_to("/"))


def enabled():
    return (PREFIX / "wheels.json").is_file()


def unpack_wheels(packages, digests):
    for name, digest in digests.items():
        path = PREFIX / name
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise RuntimeError(f"Guest Ansible wheel checksum mismatch: {name}")
        with ZipFile(path, metadata_encoding="utf-8") as wheel:
            for entry in wheel.infolist():
                relative = Path(entry.filename)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"Wheel contains a path outside the guest site-packages: {name}")
                if not entry.is_dir():
                    if relative.parts[0].endswith(".data"):
                        if relative.parts[1] not in {"platlib", "purelib"}:
                            continue
                        relative = Path(*relative.parts[2:])
                    target = packages / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with wheel.open(entry) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)


def playbook(environment, name, options):
    command = [PYTHON, "-m", "ansible.cli.playbook", "-i", "localhost,", str(PREFIX / "guest.yml"), *options]
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=50)
    output = result.stdout + result.stderr
    (STATE / f"{name}.log").write_text(output, encoding="utf-8")
    recap = re.search(r"^localhost\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)", output, re.M)
    if result.returncode or not recap:
        match = re.search(r"FAILED! => (\{[^\n]+\})", output)
        detail = json.loads(match[1]).get("module_stderr", "") if match else ""
        raise RuntimeError(f"Inside-guest Ansible {name} exited {result.returncode}. {(detail or output).strip()[-460:]}")
    ok, changed, unreachable, failed = map(int, recap.groups())
    if ok != 2 or unreachable or failed:
        raise RuntimeError(f"Inside-guest Ansible {name} did not finish both tasks")
    return {"ok": ok, "changed": changed, "unreachable": unreachable, "failed": failed}


def verify(lab):
    guard()
    STATE.mkdir(mode=0o700)
    packages = STATE / "site-packages"
    digests = json.loads((PREFIX / "wheels.json").read_text(encoding="ascii"))
    unpack_wheels(packages, digests)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ANSIBLE_")}
    environment.update(
        ANSIBLE_CONFIG=str(PREFIX / "ansible.cfg"), ANSIBLE_HOME=str(STATE),
        ANSIBLE_LOCAL_TEMP=str(STATE / "local-tmp"), ANSIBLE_REMOTE_TEMP=str(STATE / "remote-tmp"),
        ANSIBLE_NOCOLOR="1", PYTHONPATH=f"{packages}:/ztlab", LC_ALL="C.utf8",
    )
    try:
        version = subprocess.check_output(
            [PYTHON, "-c", "from ansible.release import __version__; print(__version__)"],
            env=environment, text=True, timeout=15,
        ).strip()
        preview = playbook(environment, "check", ["--check"])
        record = STATE / "compliance.txt"
        if record.exists():
            raise RuntimeError("Guest Ansible check mode wrote the compliance record")
        apply = playbook(environment, "apply", [])
        repeat = playbook(environment, "repeat", [])
    except subprocess.SubprocessError as error:
        raise RuntimeError(f"Guest Ansible execution failed: {type(error).__name__}") from error
    expected = f"Expected {lab.baseline}\nObserved {lab.baseline}\n"
    if (record.read_text() != expected or (record.stat().st_mode & 0o777) != 0o600
            or apply["changed"] != 1 or repeat["changed"] != 0):
        raise RuntimeError("Guest Ansible did not record the current policy idempotently")
    write_json(TELEMETRY / "ansible-observations.json", {
        "ansible_core_version": version, "wheel_sha256": digests, "check": preview, "apply": apply, "repeat": repeat,
        "guest_firewall_sha256": lab.baseline, "compliance_record_mode": "0600", "check_wrote_record": False,
    })
    return f"Ansible Core {version} checked and recorded the live guest policy and repeated with zero changes"
