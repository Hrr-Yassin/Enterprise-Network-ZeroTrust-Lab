"""Build the disposable Fedora-kernel guest using trusted local packages."""

import compileall
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

from lab.model import ROOT

MODULES = (
    "veth", "bridge", "nf_conntrack", "nf_tables", "nft_ct", "nft_log", "nft_limit", "nft_nat",
    "nft_chain_nat", "nf_log_syslog", "wireguard", "sch_ingress", "cls_matchall", "act_mirred",
)
TOOLS = ("busybox", "ip", "tc", "nft", "modprobe", "openssl", "wg", "dnsmasq", "tcpdump")
LIBRARY = re.compile(r"(?:^|\s)(/[^\s]+)\s+\(")


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def executable(name):
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"Missing local prerequisite: {name}")
    return Path(path).resolve()


def copy(source, root, destination=None):
    target = root / (destination or str(source)).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copy2(source, target)
    return target


def libraries(source, root):
    result = subprocess.run(("ldd", source), capture_output=True, text=True)
    if result.returncode and "not a dynamic executable" not in result.stderr + result.stdout:
        raise RuntimeError(f"Unable to resolve dependencies of {source.name}: {result.stderr.strip()}")
    if "not found" in result.stdout:
        raise RuntimeError(f"Missing an installed dependency of {source.name}")
    for line in result.stdout.splitlines():
        match = LIBRARY.search(line)
        if match:
            copy(Path(match[1]), root)


def install_executable(name, root):
    source = executable(name)
    copy(source, root, f"/bin/{name}")
    libraries(source, root)


def python_runtime(root):
    source = Path(sys.executable).resolve()
    copy(source, root, "/usr/bin/python3")
    libraries(source, root)
    stdlib = Path(sysconfig.get_path("stdlib"))
    shutil.copytree(
        stdlib,
        root / stdlib.relative_to("/"),
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "site-packages", "test", "tests",
                                     "ensurepip", "idlelib", "tkinter", "config-*"),
    )
    for extension in (stdlib / "lib-dynload").glob("*.so"):
        libraries(extension, root)
    compileall.compile_dir(root / stdlib.relative_to("/"), quiet=1, stripdir=root, prependdir="/")


def kernel_modules(root, version):
    source = Path("/usr/lib/modules") / version
    destination = root / "lib/modules" / version
    destination.mkdir(parents=True)
    requested = set()
    for name in MODULES:
        installed = run("modinfo", "--set-version", version, "--filename", name).strip()
        if installed.startswith("/"):
            requested.add(Path(installed))
        for line in run("modprobe", "--ignore-install", "--set-version", version, "--show-depends", name).splitlines():
            if line.startswith("insmod "):
                requested.add(Path(line.split()[1]))
    for item in sorted(requested):
        copy(item, root, "/lib/modules/" + str(item).split("/modules/", 1)[1])
    for item in source.glob("modules.builtin*"):
        if not item.name.endswith(".bin"):
            shutil.copy2(item, destination)
    run("depmod", "--basedir", str(root), "-a", version)


def browser_source(explicit):
    if explicit is not None:
        if not explicit.is_file() or explicit.name != "chrome-headless-shell":
            raise RuntimeError("Provide the local chrome-headless-shell executable")
        return explicit.resolve()
    if shutil.which("chrome-headless-shell"):
        return executable("chrome-headless-shell")
    cached = sorted((Path.home() / ".cache/ms-playwright").glob(
        "chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"
    ))
    if not cached:
        raise RuntimeError("The browser profile requires a local Chromium Headless Shell installation")
    return cached[-1]


def browser_runtime(root, source):
    browser_dir = source.parent
    for name in ("chrome-headless-shell", "icudtl.dat", "headless_command_resources.pak", "headless_lib_data.pak",
                 "headless_lib_strings.pak", "v8_context_snapshot.bin"):
        copy(browser_dir / name, root, f"/opt/browser/{name}")
    for name in ("libEGL.so", "libGLESv2.so", "libvk_swiftshader.so", "libvulkan.so.1", "vk_swiftshader_icd.json"):
        if (browser_dir / name).is_file():
            copy(browser_dir / name, root, f"/opt/browser/{name}")
    if (browser_dir / "locales").is_dir():
        shutil.copytree(browser_dir / "locales", root / "opt/browser/locales",
                        ignore=lambda _path, names: [name for name in names if not name.startswith("en-US")])
    libraries(source, root)
    for name in ("libnssckbi.so", "libfreeblpriv3.so", "libsoftokn3.so", "libnsssysinit.so"):
        lib = Path("/usr/lib64") / name
        if lib.is_file():
            copy(lib, root, f"/lib64/{name}")
    fonts = list(Path("/usr/share/fonts").glob("**/DejaVuSans.ttf"))
    if not fonts:
        fonts = list(Path("/usr/share/fonts").glob("**/LiberationSans-Regular.ttf"))
    if fonts:
        copy(fonts[0], root, "/usr/share/fonts/lab-sans.ttf")
    (root / "etc/fonts").mkdir(parents=True)
    (root / "etc/fonts/fonts.conf").write_text(
        '<?xml version="1.0"?>\n<fontconfig><dir>/usr/share/fonts</dir>'
        '<cachedir>/tmp/fontconfig</cachedir></fontconfig>\n', encoding="utf-8"
    )


def guest_files(root):
    for name in ("dev", "proc", "sys", "run", "tmp", "sbin", "etc/ssl", "var", "ztlab/lab", "ztlab/config", "ztlab/monitoring"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "var/run").symlink_to("/run")
    for tool in ("sh", "mount", "mkdir", "poweroff", "sleep", "dmesg", "cat", "setsid", "cttyhack", "sysctl", "umount"):
        (root / "bin" / tool).symlink_to("busybox")
    (root / "sbin/modprobe").symlink_to("/bin/modprobe")
    (root / "etc/resolv.conf").write_text("", encoding="utf-8")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n", encoding="utf-8")
    (root / "etc/ssl/openssl.cnf").write_text("[req]\ndistinguished_name = dn\n[dn]\n", encoding="utf-8")
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n"
                                    "lab-browser:x:13000:13000:Chromium:/run/ztlab/browser:/bin/sh\n", encoding="utf-8")
    (root / "etc/group").write_text("root:x:0:\nnobody:x:65534:\nlab-browser:x:13000:\n", encoding="utf-8")
    copy(ROOT / "lab/boot.sh", root, "/init").chmod(0o755)
    for source in sorted((ROOT / "lab").glob("*.py")):
        if source.name != "build.py":
            copy(source, root, f"/ztlab/lab/{source.name}")
    copy(ROOT / "config/lab.json", root, "/ztlab/config/lab.json")
    for source in sorted((ROOT / "monitoring").iterdir()):
        if source.is_file():
            copy(source, root, f"/ztlab/monitoring/{source.name}")


def pack(root, target):
    paths = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
    with target.open("wb") as output, subprocess.Popen(
        ("cpio", "-o", "-0", "--quiet", "--format=newc", "--owner=0:0"),
        cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    ) as archive:
        with subprocess.Popen(("gzip", "-2"), stdin=archive.stdout, stdout=output) as compressor:
            archive.stdout.close()
            archive.stdin.write(("\0".join(paths) + "\0").encode())
            archive.stdin.close()
            if archive.wait() or compressor.wait():
                raise RuntimeError("Could not package the guest initramfs")


def build(output, kernel, browser=None, ids_bundle=None, observability_bundle=None):
    if not kernel.is_file() or not kernel.name.startswith("vmlinuz-"):
        raise RuntimeError("Specify a readable local Fedora /boot/vmlinuz-<release> with matching installed modules")
    version = kernel.name.removeprefix("vmlinuz-")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="build-", dir=output) as directory:
        staging = Path(directory) / "root"
        staging.mkdir()
        for tool in TOOLS:
            install_executable(tool, staging)
        python_runtime(staging)
        kernel_modules(staging, version)
        guest_files(staging)
        if browser is not None:
            browser_runtime(staging, browser)
        if ids_bundle is not None:
            from lab.ids import stage_bundle

            stage_bundle(staging, ids_bundle)
        if observability_bundle is not None:
            from lab.observability import stage_bundle

            stage_bundle(staging, observability_bundle)
        archive = Path(directory) / "lab.cpio.gz"
        pack(staging, archive)
        destination = output / "lab.cpio.gz"
        os.replace(archive, destination)
    return destination
