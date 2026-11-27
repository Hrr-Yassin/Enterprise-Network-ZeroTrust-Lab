"""Stage local release files and run metrics services on the guest monitor loopback."""

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from string import Template
from urllib.parse import urlencode

from lab.guest import RUN, SECRETS, TELEMETRY, guard, source_namespace, write_json
from lab.model import ROOT, address, load

INSTALL = Path("/opt/ztlab-observability")
STATE = RUN / "observability"
MONITORING = ROOT / "monitoring"
BINARIES = ("prometheus/prometheus", "prometheus/promtool", "grafana/bin/grafana")
LOADER = "/lib64/ld-linux-x86-64.so.2"
PROMETHEUS_UID = 13001
GRAFANA_UID = 13002
PROMETHEUS_PORT = 9090
GRAFANA_PORT = 3000
OPERATOR = "operator"
DATASOURCE = "ztlab-prom"
DASHBOARD = "ztlab-observability"
JOB = "isolated-ztlab"


@dataclass(frozen=True)
class ReleaseBundle:
    directory: Path
    files: tuple[Path, ...]
    dependencies: dict[str, Path]


def bundle_path(directory, name, kind, optional=False):
    path = directory
    for part in Path(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"Symlinks are unsupported in observability bundles: {name}")
    if optional and not path.exists():
        return None
    if kind == "file" and path.is_file() or kind == "directory" and path.is_dir():
        return path
    raise ValueError(f"Observability bundle is missing its {kind}: {name}")


def asset_files(directory, name, optional=False):
    assets = bundle_path(directory, name, "directory", optional=optional)
    if assets is None:
        return []
    files = []
    for path in sorted(assets.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            files.append(path)
        elif not stat.S_ISDIR(mode):
            raise ValueError(f"Unsupported release asset type: {path.relative_to(directory)}")
    return files


def elf_dependencies(path):
    with path.open("rb") as stream:
        header = stream.read(20)
    if header[:7] != b"\x7fELF\x02\x01\x01" or header[18:20] != b"\x3e\x00":
        raise ValueError(f"Observability requires a Linux x86-64 ELF binary: {path.name}")
    try:
        metadata = subprocess.run(("readelf", "-l", "-d", "-W", path), check=True, timeout=10,
                                  text=True, capture_output=True, env={**os.environ, "LC_ALL": "C"}).stdout
    except FileNotFoundError:
        raise RuntimeError("Observability bundle validation requires readelf (binutils)") from None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError(f"Unreadable ELF metadata for {path.name}") from None
    interpreter = re.search(r"\[Requesting program interpreter: ([^\]]+)\]", metadata)
    if interpreter and interpreter[1] != LOADER:
        raise ValueError(f"Unsupported ELF interpreter for {path.name}: {interpreter[1]}")
    return bool(interpreter), re.findall(r"\(NEEDED\).+\[([A-Za-z0-9_.+-]+)\]", metadata)


def library_paths(binaries):
    libraries = {}
    pending = list(binaries)
    known = None
    while pending:
        interpreter, requires = elf_dependencies(pending.pop())
        if interpreter:
            if not Path(LOADER).is_file():
                raise RuntimeError(f"Missing compatible local ELF interpreter: {LOADER}")
            libraries[LOADER] = Path(LOADER)
        if requires and known is None:
            cache = subprocess.run(("ldconfig", "-p"), check=True, timeout=10, text=True, capture_output=True).stdout
            known = {}
            for name, location in re.findall(r"^\s*(\S+) \([^)]*x86-64[^)]*\) => (\S+)", cache, re.MULTILINE):
                if "/glibc-hwcaps/" not in location:
                    known.setdefault(name, Path(location))
        for name in requires:
            target = f"/lib64/{name}"
            if target not in libraries:
                library = known.get(name)
                if library is None or not library.is_file():
                    raise RuntimeError(f"Missing compatible local library for observability release: {name}")
                libraries[target] = library
                pending.append(library)
    return libraries


def validate_bundle(source):
    """Inspect release layout and ELF metadata without executing the supplied files."""
    directory = source.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("The observability bundle must be a directory of extracted releases")
    binaries = [bundle_path(directory, name, "file") for name in BINARIES]
    if any(not os.access(path, os.X_OK) for path in binaries):
        raise ValueError("Observability release binaries must have their executable mode set")
    defaults = bundle_path(directory, "grafana/conf/defaults.ini", "file")
    if not defaults.stat().st_size:
        raise ValueError("Grafana conf/defaults.ini is empty")
    bundle_path(directory, "grafana/public/build", "directory")
    assets = asset_files(directory, "grafana/public")
    if not any(path.suffix == ".js" and Path("build") in path.relative_to(directory / "grafana/public").parents
               for path in assets):
        raise ValueError("Grafana public/build does not contain release JavaScript")
    assets.extend(asset_files(directory, "grafana/plugins-bundled", optional=True))
    dependencies = library_paths(binaries)
    return ReleaseBundle(directory, (*binaries, defaults, *assets), dependencies)


def stage_bundle(staging, source):
    bundle = validate_bundle(source)
    destination = staging / INSTALL.relative_to("/")
    for original in bundle.files:
        target = destination / original.relative_to(bundle.directory)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        target.chmod(0o755 if original.stat().st_mode & 0o111 else 0o644)
    for guest_path, original in bundle.dependencies.items():
        target = staging / guest_path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(original, target)
            target.chmod(0o755)
    hashes = {}
    for name in BINARIES:
        with (destination / name).open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    write_json(destination / "manifest.json", hashes)
    with (staging / "etc/passwd").open("a", encoding="utf-8") as users, \
         (staging / "etc/group").open("a", encoding="utf-8") as groups:
        for name, uid in (("prometheus", PROMETHEUS_UID), ("grafana", GRAFANA_UID)):
            users.write(f"lab-{name}:x:{uid}:{uid}:{name}:{STATE / name}:/bin/sh\n")
            groups.write(f"lab-{name}:x:{uid}:\n")


def enabled():
    return (INSTALL / "manifest.json").is_file()


def private_dir(path, uid):
    path.mkdir(mode=0o700)
    os.chown(path, uid, uid)


def write_config(path, data, mode=0o644, group=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(data)
        stream.flush()
        os.fchown(stream.fileno(), 0, group)
        os.fchmod(stream.fileno(), mode)


def configure():
    policy = load()
    monitor = policy["services"]["dashboard"]
    if monitor["node"] != "monitor" or monitor["kind"] != "mtls":
        raise RuntimeError("Prometheus requires the mTLS metrics endpoint in the monitor namespace")
    target = address(policy, monitor["node"]) + f":{monitor['port']}"
    STATE.mkdir(mode=0o755)
    for name in ("services.pem", "observer.pem", "observer.key"):
        write_config(STATE / name, (SECRETS / name).read_text(), mode=0o440, group=PROMETHEUS_UID)
    config = Template((MONITORING / "prometheus.yml").read_text())
    write_config(STATE / "prometheus.yml", config.substitute(monitor_name=monitor["host"], monitor_target=target))
    shutil.copyfile(MONITORING / "alerts.yml", STATE / "alerts.yml")
    private_dir(STATE / "prometheus", PROMETHEUS_UID)
    grafana = STATE / "grafana"
    grafana.mkdir(mode=0o755)
    for name in ("data", "logs", "plugins"):
        private_dir(grafana / name, GRAFANA_UID)
    provisioning = grafana / "provisioning"
    for kind, source in (("datasources", "grafana-datasource.yml"), ("dashboards", "grafana-dashboard.yml")):
        directory = provisioning / kind
        directory.mkdir(parents=True)
        shutil.copyfile(MONITORING / source, directory / "ztlab.yml")
    dashboards = grafana / "dashboards"
    dashboards.mkdir()
    shutil.copyfile(MONITORING / "grafana.json", dashboards / "ztlab.json")
    password = secrets.token_urlsafe(36)
    write_config(STATE / "grafana-operator-password", password + "\n", mode=0o600)
    config = Template((MONITORING / "grafana.ini").read_text())
    write_config(grafana / "grafana.ini", config.substitute(password=password), mode=0o440, group=GRAFANA_UID)
    return target


def http(port, path, password=None):
    headers = {}
    if password is not None:
        token = base64.b64encode(f"{OPERATOR}:{password}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=3)) as connection:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(2_000_000)


def get_json(port, path, password=None):
    code, body = http(port, path, password)
    if code != 200:
        raise RuntimeError(f"Loopback API {path} returned HTTP {code}")
    return json.loads(body)


def await_http(processes, port, path, timeout=75):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for name, process in processes.items():
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited during startup with status {process.returncode}. See its private guest log")
        try:
            if http(port, path)[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(1)
    raise RuntimeError(f"Loopback service on port {port} did not become ready")


def stop(processes):
    for process in processes.values():
        if process.poll() is None:
            process.terminate()
    for process in processes.values():
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def private_log(name):
    fd = os.open(STATE / f"{name}.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def start_service(name, argv, uid, cwd):
    with private_log(name) as log:
        return subprocess.Popen(argv, cwd=cwd, user=uid, group=uid, extra_groups=[],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)


def launch():
    """Validate the configuration and start real services as guest-only unprivileged users."""
    guard()
    if not enabled():
        raise RuntimeError("The guest image contains no observability release bundle")
    target = configure()
    processes = {}
    with source_namespace("monitor"):
        try:
            with private_log("promtool") as log:
                result = subprocess.run((INSTALL / "prometheus/promtool", "check", "config",
                                         STATE / "prometheus.yml"), user=PROMETHEUS_UID, group=PROMETHEUS_UID,
                                        extra_groups=[], stdout=log, stderr=subprocess.STDOUT, timeout=40)
            if result.returncode:
                raise RuntimeError("promtool rejected the staged config. See its private guest log")
            processes["prometheus"] = start_service(
                "prometheus", (INSTALL / "prometheus/prometheus",
                               f"--config.file={STATE / 'prometheus.yml'}",
                               f"--storage.tsdb.path={STATE / 'prometheus'}",
                               "--storage.tsdb.retention.time=6h", "--storage.tsdb.retention.size=64MB",
                               f"--web.listen-address=127.0.0.1:{PROMETHEUS_PORT}"),
                PROMETHEUS_UID, STATE / "prometheus",
            )
            grafana = INSTALL / "grafana"
            processes["grafana"] = start_service(
                "grafana", (grafana / "bin/grafana", "server", f"--homepath={grafana}",
                            f"--config={STATE / 'grafana/grafana.ini'}"),
                GRAFANA_UID, grafana,
            )
            await_http(processes, PROMETHEUS_PORT, "/-/ready")
            await_http(processes, GRAFANA_PORT, "/api/health")
        except subprocess.TimeoutExpired:
            stop(processes)
            raise RuntimeError("promtool configuration check timed out") from None
        except BaseException:
            stop(processes)
            raise
    return processes, target


def checked_api(port, path, password=None):
    response = get_json(port, path, password)
    if not isinstance(response, dict):
        raise RuntimeError(f"Unexpected response from {path}")
    return response


def prometheus_data(path, port=PROMETHEUS_PORT, password=None):
    response = checked_api(port, path, password)
    if response.get("status") != "success" or not isinstance(response.get("data"), dict):
        raise RuntimeError(f"Prometheus failed to return successful data for {path}")
    return response["data"]


def scrape_target(target):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        targets = prometheus_data("/api/v1/targets").get("activeTargets", [])
        for item in targets:
            if item.get("labels", {}).get("job") == JOB and item.get("scrapeUrl") == f"https://{target}/metrics":
                if item.get("health") == "up" and item.get("lastError") == "":
                    return
        time.sleep(1)
    raise RuntimeError("Prometheus did not record a healthy mTLS scrape of the monitor metrics endpoint")


def evaluated_rules():
    expected = {"LabServiceUnavailable", "LabFirewallPolicyDrift", "LabIDSCanarySeen"}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        rule_data = prometheus_data("/api/v1/rules")
        rules = {rule.get("name"): rule.get("health") for group in rule_data.get("groups", [])
                 if group.get("name") == "ztlab" for rule in group.get("rules", [])}
        if set(rules) == expected and all(health == "ok" for health in rules.values()):
            return sorted(rules)
        if "err" in rules.values():
            break
        time.sleep(1)
    raise RuntimeError("Prometheus did not load and evaluate all observability alert rules")


def measure():
    password = (STATE / "grafana-operator-password").read_text().strip()
    query = "/api/v1/query?" + urlencode({"query": "ztlab_policy_compliant"})
    dashboard_path = f"/api/dashboards/uid/{DASHBOARD}"
    if http(GRAFANA_PORT, dashboard_path)[0] not in {401, 403}:
        raise RuntimeError("The Grafana dashboard API accepted unauthenticated access")
    datasource = checked_api(GRAFANA_PORT, f"/api/datasources/uid/{DATASOURCE}", password)
    if (datasource.get("type"), datasource.get("access"), datasource.get("url")) != (
        "prometheus", "proxy", f"http://127.0.0.1:{PROMETHEUS_PORT}"
    ):
        raise RuntimeError("Grafana did not provision the in-guest Prometheus data source")
    dashboard = checked_api(GRAFANA_PORT, dashboard_path, password).get("dashboard", {})
    expected = json.loads((MONITORING / "grafana.json").read_text())
    if dashboard.get("uid") != DASHBOARD or [panel.get("id") for panel in dashboard.get("panels", [])] != [
        panel["id"] for panel in expected["panels"]
    ]:
        raise RuntimeError("Grafana did not provision the expected dashboard panels")
    direct = prometheus_data(query).get("result", [])
    proxied = prometheus_data(f"/api/datasources/proxy/uid/{DATASOURCE}{query}", GRAFANA_PORT, password).get("result", [])
    for result in (direct, proxied):
        if len(result) != 1 or result[0].get("metric", {}).get("job") != JOB or result[0].get("value", [None])[-1] != "1":
            raise RuntimeError("Prometheus compliance metric was missing or unhealthy")
    rules = evaluated_rules()
    grafana_health = checked_api(GRAFANA_PORT, "/api/health")
    prometheus_build = prometheus_data("/api/v1/status/buildinfo")
    if grafana_health.get("database") != "ok" or not grafana_health.get("version") or not prometheus_build.get("version"):
        raise RuntimeError("Observability service health responses did not identify the two engines")
    return {
        "prometheus": {"version": prometheus_build["version"], "scrape_job": JOB, "mtls_target_health": "up",
                       "evaluated_alert_rules": rules, "compliance_sample": 1},
        "grafana": {"version": grafana_health["version"], "dashboard_uid": DASHBOARD, "panel_count": len(dashboard["panels"]),
                    "datasource_uid": DATASOURCE, "proxied_compliance_sample": 1, "unauthenticated_dashboard_rejected": True},
    }


def verify():
    processes, target = launch()
    try:
        with source_namespace("monitor"):
            scrape_target(target)
            evidence = measure()
        evidence["release_sha256"] = json.loads((INSTALL / "manifest.json").read_text())
        write_json(TELEMETRY / "observability.json", evidence)
        return "Prometheus scraped the mTLS metrics endpoint and Grafana served its provisioned dashboard and a live query"
    except http.client.HTTPException as error:
        raise RuntimeError(f"Observability loopback request failed: {type(error).__name__}") from error
    finally:
        stop(processes)


if __name__ == "__main__":
    with source_namespace("monitor"):
        print(json.dumps(measure(), indent=2, sort_keys=True))
