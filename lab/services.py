"""Provision short-lived service and client identities and start isolated fixtures."""

import hashlib
import json
import os
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time

from lab.guest import PYTHON, RUN, SECRETS, TELEMETRY, run, start
from lab.model import IDENTITIES, address


def certificate_authority(name, passwordless_root):
    cert = passwordless_root / f"{name}.pem"
    key = passwordless_root / f"{name}.key"
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
        "-sha256", "-days", "3", "-subj", f"/CN=Zero Trust Lab {name} CA",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
        "-keyout", key, "-out", cert)
    key.chmod(0o600)


def issue(name, authority, usage, output, hostname=None):
    cert, key = output
    scratch = SECRETS / "mint"
    scratch.mkdir(exist_ok=True, mode=0o700)
    csr, extensions = scratch / "request.csr", scratch / "extensions.cnf"
    lines = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature", f"extendedKeyUsage={usage}",
             "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid,issuer"]
    if hostname:
        lines.append(f"subjectAltName=DNS:{hostname}")
    extensions.write_text("\n".join(lines) + "\n", encoding="ascii")
    run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
        "-subj", f"/CN={name}", "-keyout", key, "-out", csr)
    run("openssl", "x509", "-req", "-sha256", "-in", csr, "-CA", SECRETS / f"{authority}.pem",
        "-CAkey", SECRETS / f"{authority}.key", "-set_serial", "0x" + secrets.token_hex(16), "-days", "2",
        "-extfile", extensions, "-out", cert)
    key.chmod(0o600)


class Fixtures:
    def __init__(self, lab):
        self.lab = lab
        self.processes = {}
        self.roles = {}
        self.users = {}

    def provision(self):
        (RUN / "services").mkdir()
        (TELEMETRY / "events").mkdir()
        for authority in ("services", "clients", "untrusted"):
            certificate_authority(authority, SECRETS)
        for role in sorted(IDENTITIES | {"foreign"}):
            client_cert, client_key = (SECRETS / f"{role}.{suffix}" for suffix in ("pem", "key"))
            issue(role, "untrusted" if role == "foreign" else "clients", "clientAuth", (client_cert, client_key))
            if role not in {"unassigned", "foreign"}:
                self.roles[hashlib.sha256(ssl.PEM_cert_to_DER_cert(client_cert.read_text())).hexdigest()] = role
        for index, (name, service) in enumerate(self.lab.services.items(), 12000):
            if service["kind"] not in {"public", "mtls", "egress"}:
                continue
            self.users[name] = index
            directory = RUN / "services" / name
            directory.mkdir(mode=0o750)
            os.chown(directory, 0, index)
            if service["kind"] in {"public", "mtls"}:
                issue(name, "services", "serverAuth", (directory / "server.pem", directory / "server.key"), service["host"])
            if service["kind"] == "mtls":
                shutil.copyfile(SECRETS / "clients.pem", directory / "clients.pem")
                self.write_roles(name, self.roles)
            for item in directory.iterdir():
                os.chown(item, 0, index)
                item.chmod(0o440)
            ready = directory / "ready"
            ready.touch(mode=0o600)
            os.chown(ready, index, index)
        for authority in ("services", "clients", "untrusted"):
            (SECRETS / f"{authority}.key").unlink()
        shutil.rmtree(SECRETS / "mint")
        for name in self.users:
            self.restart(name)
        self.restart("dns")

    def write_roles(self, service, roles):
        target = RUN / "services" / service / "roles.json"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent, delete_on_close=False) as stage:
            stage.write(json.dumps(roles, sort_keys=True) + "\n")
            stage.flush()
            os.fchown(stage.fileno(), 0, self.users[service])
            os.fchmod(stage.fileno(), 0o440)
            os.replace(stage.name, target)

    def role_status(self, service, role, active):
        directory = RUN / "services" / service
        current = json.loads((directory / "roles.json").read_text())
        if active:
            current.update((digest, label) for digest, label in self.roles.items() if label == role)
        else:
            current = {digest: label for digest, label in current.items() if label != role}
        self.write_roles(service, current)

    def restart(self, name):
        self.stop(name)
        service = self.lab.services[name]
        log_path = TELEMETRY / "events" / f"{name}.log"
        with log_path.open("ab") as log:
            if name == "dns":
                host = address(self.lab.policy, service["node"])
                flags = [
                    "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--no-resolv", "--no-hosts",
                    "--bind-interfaces", f"--listen-address={host}", "--local=/lab.test/", "--domain-needed",
                    "--bogus-priv", "--user=nobody", "--group=nobody", "--log-queries=extra", "--log-facility=-",
                ]
                for application in self.lab.services.values():
                    if "host" in application:
                        ip = address(self.lab.policy, application["node"])
                        flags.append(f"--host-record={application['host']},{ip}")
                flags.append(f"--host-record=ids-check.lab.test,{address(self.lab.policy, 'api')}")
                process = start(service["node"], *flags, stdout=log, stderr=log)
                ready = None
            else:
                ready = RUN / "services" / name / "ready"
                ready.write_text("", encoding="ascii")
                process = start(service["node"], PYTHON, "-m", "lab.apps", name, self.users[name], stdout=log, stderr=log)
            self.processes[name] = process
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited during startup: {log_path.read_text()[-500:]}")
            if ready is None or ready.read_text(encoding="ascii").strip() == "ready":
                return
            time.sleep(0.05)
        raise RuntimeError(f"{name} did not become ready: {log_path.read_text()[-500:]}")

    def stop(self, name):
        process = self.processes.pop(name, None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def events(self):
        events = []
        for name in self.users:
            for line in (TELEMETRY / "events" / f"{name}.log").read_text().splitlines():
                if line.startswith('{"event": '):
                    events.append(json.loads(line))
        return events[-100:]
