"""Render the sanitized live HTTPS response in the installed Chromium engine."""

import os
import struct
import subprocess

from lab.guest import RUN, TELEMETRY

BROWSER = "/opt/browser/chrome-headless-shell"


def screenshot():
    source = TELEMETRY / "dashboard.html"
    if not source.is_file():
        raise RuntimeError("No verified dashboard HTML was available for Chromium")
    home = RUN / "browser"
    home.mkdir(mode=0o700, exist_ok=True)
    browser_user = 13000
    os.chown(home, browser_user, browser_user)
    destination = home / "dashboard.png"
    command = [
        BROWSER, "--headless", "--single-process", "--no-sandbox", "--disable-gpu",
        "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
        "--disable-component-update", "--disable-sync", "--disable-domain-reliability",
        "--disable-client-side-phishing-detection", "--no-proxy-server", "--no-zygote",
        "--host-resolver-rules=MAP * ~NOTFOUND", "--disable-breakpad", "--disable-dev-shm-usage",
        "--lang=en-US", "--run-all-compositor-stages-before-draw",
        f"--user-data-dir={home / 'profile'}", "--window-size=1440,1120",
        f"--screenshot={destination}", source.as_uri(),
    ]
    try:
        process = subprocess.run(
            command, user=browser_user, group=browser_user, extra_groups=[], timeout=135, text=True,
            capture_output=True, env={**os.environ, "XDG_RUNTIME_DIR": str(home), "XDG_CONFIG_HOME": str(home),
                                      "XDG_CACHE_HOME": str(home)},
        )
    except subprocess.TimeoutExpired as error:
        details = (error.stderr or b"").decode(errors="replace")[-550:]
        raise RuntimeError(f"Chromium screenshot timed out. {details}") from None
    if process.returncode or not destination.is_file():
        raise RuntimeError(f"Chromium exited {process.returncode}: {process.stderr[-500:]}")
    data = destination.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or struct.unpack_from("!II", data, 16) != (1440, 1120):
        raise RuntimeError("Chromium did not produce the expected dashboard image")
    (TELEMETRY / "dashboard.png").write_bytes(data)
    return "Chromium rendered a 1440 × 1120 PNG from the dashboard HTML fetched through authorized guest HTTPS"
