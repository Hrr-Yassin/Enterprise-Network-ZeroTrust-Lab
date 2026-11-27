"""Render and inspect both monitoring dashboards in headed in-guest Chromium."""

import base64
import fcntl
import json
import os
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path
from urllib.parse import urlsplit

from lab.guest import PYTHON, RUN, TELEMETRY, guard, source_namespace, write_json

PREFIX = Path("/opt/ztlab-display")
CHROME = PREFIX / "chromium/chrome"
XVFB = PREFIX / "Xvfb"
DISPLAY = ":88"
WIDTH, HEIGHT = 1600, 1280
BROWSER_UID = 13000
CHROMIUM_FILES = ("chrome", "chrome_crashpad_handler", "chrome_100_percent.pak", "chrome_200_percent.pak",
                  "resources.pak", "icudtl.dat", "v8_context_snapshot.bin")
GRAFANA_URL = "http://127.0.0.1:3000/d/ztlab-observability/enterprise-network-zero-trust?from=now-5m&to=now"


def validate_bundle(source):
    source = Path(source).resolve(strict=True)
    server = (source / "usr/bin/Xvfb").resolve(strict=True)
    if not server.is_relative_to(source) or not stat.S_ISREG(server.stat().st_mode) or not os.access(server, os.X_OK):
        raise ValueError("Provide the extracted signed Xvfb RPM with usr/bin/Xvfb")
    cached = sorted((Path.home() / ".cache/ms-playwright").glob("chromium-*/chrome-linux64/chrome"), reverse=True)
    browser = next((path.parent for path in cached if all((path.parent / name).is_file() for name in CHROMIUM_FILES)), None)
    if browser is None:
        raise ValueError("The visible profile requires a locally cached full Playwright Chromium release")
    return server, browser


def stage_bundle(root, source):
    from lab.build import browser_system_assets, copy, executable, libraries

    server, browser = validate_bundle(source)
    copy(server, root, str(XVFB))
    libraries(server, root)
    xkbcomp = executable("xkbcomp")
    copy(xkbcomp, root, "/usr/bin/xkbcomp")
    libraries(xkbcomp, root)
    shutil.copytree("/usr/share/X11/xkb", root / "usr/share/X11/xkb")
    for name in (*CHROMIUM_FILES, "libEGL.so", "libGLESv2.so", "libvk_swiftshader.so", "libvulkan.so.1",
                 "vk_swiftshader_icd.json"):
        if (browser / name).is_file():
            copy(browser / name, root, str(CHROME.parent / name))
    if (browser / "locales").is_dir():
        for locale in (browser / "locales").glob("en-US*"):
            if locale.is_file():
                copy(locale, root, str(CHROME.parent / "locales" / locale.name))
    libraries(browser / "chrome", root)
    libraries(browser / "chrome_crashpad_handler", root)
    browser_system_assets(root)


def enabled():
    return CHROME.is_file() and XVFB.is_file()


def xauthority(home):
    fields = (b"", DISPLAY[1:].encode(), b"MIT-MAGIC-COOKIE-1", os.urandom(16))
    file = home / "Xauthority"
    file.write_bytes(struct.pack("!H", 65535) + b"".join(struct.pack("!H", len(item)) + item for item in fields))
    os.chmod(file, 0o600)
    os.chown(file, BROWSER_UID, BROWSER_UID)
    return file


def stop_process(process):
    if process is not None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


class DevTools:
    def __init__(self, process, request, response):
        self.process = process
        self.request = request
        self.response = response
        self.pending = b""
        self.sequence = 0
        self.grafana_responses = 0

    def call(self, method, params=None, session=None):
        self.sequence += 1
        message = {"id": self.sequence, "method": method}
        if params is not None:
            message["params"] = params
        if session is not None:
            message["sessionId"] = session
        self.request.write(json.dumps(message).encode() + b"\0")
        self.request.flush()
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if b"\0" not in self.pending:
                readable, _, _ = select.select([self.response], [], [], max(0, deadline - time.monotonic()))
                if not readable:
                    break
                chunk = os.read(self.response, 65536)
                if not chunk or self.process.poll() is not None:
                    raise RuntimeError("Headed Chromium exited during live dashboard validation")
                self.pending += chunk
                continue
            event, self.pending = self.pending.split(b"\0", 1)
            packet = json.loads(event)
            if packet.get("id") == self.sequence:
                if "error" in packet:
                    raise RuntimeError(f"Chromium DevTools rejected {method}: {packet['error']['code']}")
                return packet.get("result", {})
            if packet.get("method") == "Network.responseReceived":
                answer = packet["params"]["response"]
                url = urlsplit(answer["url"])
                if (url.netloc == "127.0.0.1:3000" and url.path.startswith("/api/ds/query")
                        and answer["status"] == 200):
                    self.grafana_responses += 1
        raise RuntimeError(f"Chromium did not respond to {method}")

    def navigate(self, session, url, labels, live_metric=False):
        nav = self.call("Page.navigate", {"url": url}, session)
        if nav.get("errorText"):
            raise RuntimeError(f"Chromium dashboard navigation failed: {nav['errorText']}")
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            dom = self.call(
                "Runtime.evaluate", {"expression": "document.body?.innerText || ''", "returnByValue": True}, session,
            ).get("result", {}).get("value", "")
            if all(label in dom for label in labels) and (not live_metric or self.grafana_responses):
                return
            time.sleep(0.5)
        raise RuntimeError("Headed Chromium did not render the expected dashboard panels and live data")


def start_chromium(home, authority, log):
    pipes = [*os.pipe(), *os.pipe()]
    chrome_in, control_out, control_in, chrome_out = pipes
    child_in = fcntl.fcntl(chrome_in, fcntl.F_DUPFD_CLOEXEC, 10)
    child_out = fcntl.fcntl(chrome_out, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(chrome_in)
    os.close(chrome_out)
    argv = [
        PYTHON, "-m", "lab.visible_browser", str(child_in), str(child_out),
        "--remote-debugging-pipe", "--ozone-platform=x11", "--disable-gpu", "--no-sandbox", "--no-proxy-server",
        "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
        "--disable-sync", "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--disable-extensions",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--disable-breakpad",
        "--disable-dev-shm-usage", "--test-type",
        "--lang=en-US", "--window-position=0,0", f"--window-size={WIDTH},{HEIGHT}", f"--user-data-dir={home / 'profile'}",
        "about:blank",
    ]
    env = {**os.environ, "DISPLAY": DISPLAY, "XAUTHORITY": str(authority), "XDG_RUNTIME_DIR": str(home),
           "XDG_CONFIG_HOME": str(home), "XDG_CACHE_HOME": str(home)}
    try:
        with source_namespace("monitor"):
            process = subprocess.Popen(argv, env=env, user=BROWSER_UID, group=BROWSER_UID, extra_groups=[],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
                                       pass_fds=(child_in, child_out))
    except BaseException:
        os.close(control_in)
        os.close(control_out)
        raise
    finally:
        os.close(child_in)
        os.close(child_out)
    return DevTools(process, os.fdopen(control_out, "wb"), control_in)


def save_frame(framebuffer, target):
    """Capture the complete X11 screen, including the Chromium window chrome."""
    data = framebuffer.read_bytes()
    header = struct.unpack_from("!25I", data)
    width, height = header[4:6]
    channel_masks = (0xFF0000, 0xFF00, 0xFF)
    if ((header[1], header[2], header[3], width, height) != (7, 2, 24, WIDTH, HEIGHT)
            or header[7] != 0 or header[11] != 32 or tuple(header[14:17]) != channel_masks):
        raise RuntimeError("Xvfb did not expose the expected 24-bit Chromium framebuffer")
    offset, stride = header[0] + header[19] * 12, header[12]
    if len(data) < offset + stride * height or stride < width * 4:
        raise RuntimeError("Xvfb framebuffer is incomplete")
    pixel_data = bytearray()
    for y in range(height):
        pos = offset + y * stride
        row = data[pos:pos + width * 4]
        rgb = bytearray(width * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = row[2::4], row[1::4], row[0::4]
        pixel_data.extend(b"\0")
        pixel_data.extend(rgb)

    def chunk(kind, value):
        return struct.pack("!I", len(value)) + kind + value + struct.pack("!I", zlib.crc32(kind + value))

    target.write_bytes(b"\x89PNG\r\n\x1a\n"
                       + chunk(b"IHDR", struct.pack("!2IBBBBB", width, height, 8, 2, 0, 0, 0))
                       + chunk(b"IDAT", zlib.compress(pixel_data, 5)) + chunk(b"IEND", b""))


def verify(operator_html, password):
    guard()
    home = RUN / "visible-chromium"
    home.mkdir(mode=0o700)
    os.chown(home, BROWSER_UID, BROWSER_UID)
    socket_dir = Path("/tmp/.X11-unix")
    socket_dir.mkdir(mode=0o1777, exist_ok=True)
    socket_dir.chmod(0o1777)
    authority = xauthority(home)
    source = home / "operator-dashboard.html"
    source.write_text(operator_html, encoding="utf-8")
    xserver = protocol = None
    try:
        with (home / "xserver.log").open("wb") as log, source_namespace("monitor"):
            xserver = subprocess.Popen(
                [XVFB, DISPLAY, "-screen", "0", f"{WIDTH}x{HEIGHT}x24", "-nolisten", "tcp", "-extension", "GLX",
                 "-auth", authority, "-fbdir", home, "-noreset"],
                user=BROWSER_UID, group=BROWSER_UID, extra_groups=[], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True,
            )
        framebuffer = home / "Xvfb_screen0"
        deadline = time.monotonic() + 14
        while not (framebuffer.is_file() and (socket_dir / "X88").is_socket()):
            if xserver.poll() is not None or time.monotonic() >= deadline:
                detail = (home / "xserver.log").read_text(errors="replace")[-600:].strip()
                raise RuntimeError(f"Xvfb did not start the visible guest display. {detail}")
            time.sleep(0.2)
        with (home / "chromium.log").open("wb") as log:
            protocol = start_chromium(home, authority, log)
            product = protocol.call("Browser.getVersion")["product"]
            targets = protocol.call("Target.getTargets")["targetInfos"]
            tab = next(item["targetId"] for item in targets if item["type"] == "page")
            session = protocol.call("Target.attachToTarget", {"targetId": tab, "flatten": True})["sessionId"]
            protocol.call("Page.enable", session=session)
            protocol.call("Network.enable", session=session)
            token = base64.b64encode(f"operator:{password}".encode()).decode("ascii")
            protocol.call("Network.setExtraHTTPHeaders", {"headers": {"Authorization": f"Basic {token}"}}, session)
            protocol.navigate(session, GRAFANA_URL, ("Enterprise Network Zero Trust", "Segment links",
                                                     "Policy compliance", "Availability"), live_metric=True)
            time.sleep(1)
            save_frame(framebuffer, TELEMETRY / "grafana.png")
            query_count = protocol.grafana_responses
            protocol.call("Network.setExtraHTTPHeaders", {"headers": {}}, session)
            protocol.navigate(session, source.as_uri(), ("Network Security Lab", "Network segments", "Security alerts"))
            time.sleep(0.8)
            save_frame(framebuffer, TELEMETRY / "dashboard-visible.png")
            write_json(TELEMETRY / "browser-observations.json", {
                "browser": product, "mode": "headed X11", "display": "Xvfb with no TCP listener",
                "dimensions": [WIDTH, HEIGHT], "grafana_live_query_responses": query_count,
                "grafana_path": urlsplit(GRAFANA_URL).path, "operator_view": "authorized in-guest HTTPS response",
            })
    finally:
        if protocol is not None:
            stop_process(protocol.process)
            protocol.request.close()
            os.close(protocol.response)
        stop_process(xserver)
    return "Headed Chromium rendered the live Grafana dashboard and authenticated operator dashboard on the guest display"


if __name__ == "__main__":
    os.dup2(int(sys.argv[1]), 3, inheritable=True)
    os.dup2(int(sys.argv[2]), 4, inheritable=True)
    os.close(int(sys.argv[1]))
    os.close(int(sys.argv[2]))
    os.execv(CHROME, [str(CHROME), *sys.argv[3:]])
