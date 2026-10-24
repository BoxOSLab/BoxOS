#!/usr/bin/env python3
"""Boot a checksum-verified upstream Alpine image with the vendored BoxKernel."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
import urllib.request

project = pathlib.Path(__file__).resolve().parent.parent
catalog = json.load(urllib.request.urlopen("https://raw.githubusercontent.com/BoxOSLab/BoxRootfs/main/latest.json", timeout=30))
parser = argparse.ArgumentParser()
parser.add_argument("--cache-dir", type=pathlib.Path)
parser.add_argument("--distro", choices=["alpine", "debian", "ubuntu"], default="alpine")
parser.add_argument("--all", action="store_true", help="Also test Debian and Ubuntu")
options = parser.parse_args()
images = [image for image in catalog["images"] if image["arch"] == "amd64" and (options.all or image["distro"] == options.distro)]
subprocess.run(["cargo", "build", "--locked", "--manifest-path", str(project / "vendor/boxkernel/Cargo.toml")], check=True)
kernel = project / "vendor/boxkernel/target/debug/proot"
for image in images:
    with tempfile.TemporaryDirectory(prefix="boxos-smoke-") as folder:
        root = pathlib.Path(folder) / "rootfs"
        root.mkdir()
        cached = options.cache_dir / image["filename"] if options.cache_dir else None
        if cached and cached.exists():
            data = cached.read_bytes()
        else:
            data = urllib.request.urlopen(image["url"], timeout=60).read()
            if cached:
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_bytes(data)
        assert len(data) == image["size"]
        assert hashlib.sha256(data).hexdigest() == image["sha256"]
        archive = pathlib.Path(folder) / "rootfs.tar.xz"
        archive.write_bytes(data)
        with tarfile.open(archive) as stream:
            stream.extractall(root, filter="tar")
        args = [str(kernel), "--kill-on-exit", "-0", "-l", "-L", "-H", "--sysvipc", "-p", "-r", str(root),
                "-b", "/dev", "-b", "/proc", "-b", "/sys", "-w", "/root", "/bin/sh", "-lc",
                "set -eu; test \"$(id -u)\" = 0; printf boxos > /root/probe; test \"$(cat /root/probe)\" = boxos; "
                "mkdir /root/work; ln /root/probe /root/work/hardlink; test \"$(cat /root/work/hardlink)\" = boxos; "
                "sh -c 'echo child-process-ok'; " +
                ("/sbin/apk --version; " if image["distro"] == "alpine" else
                 "if command -v apt >/dev/null; then apt --version; else dpkg --version; echo 'Image capability: dpkg only (apt omitted upstream)'; fi; ") +
                "uname -m; echo BOXOS_SMOKE_OK"]
        result = subprocess.run(args, text=True, capture_output=True, timeout=60)
        print(result.stdout, flush=True)
        print(result.stderr, flush=True)
        result.check_returncode()
        assert "BOXOS_SMOKE_OK" in result.stdout
        print(f"Verified upstream {image['filename']} and launched Linux with the app's runtime flags.")
