#!/usr/bin/env python3
"""Build a relocatable reviewer .app. Never installs, registers, or modifies Keychain."""
import argparse
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess


def build(binary_dir, destination, architecture, identity=None, ad_hoc=False, version="0.3.0"):
    release_version = version.split("-", 1)[0].split("+", 1)[0]
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", release_version):
        raise ValueError("version must begin with a numeric release version")
    if identity == "":
        raise ValueError("distributed signing requires a nonempty identity")
    if architecture not in ("arm64", "x86_64"):
        raise ValueError("unsupported macOS architecture")
    if destination.exists():
        raise ValueError("destination already exists; choose a fresh output path")
    if destination.suffix != ".app":
        raise ValueError("destination must end in .app")
    for binary in ("opaque-approver", "opaque-approve-helper"):
        source = binary_dir / binary
        if not source.is_file() or source.is_symlink() or not os.access(source, os.X_OK):
            raise ValueError(f"missing executable regular binary: {binary}")
    root = Path(__file__).resolve().parent.parent
    macos = destination / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    for binary in ("opaque-approver", "opaque-approve-helper"):
        shutil.copy2(binary_dir / binary, macos / binary)
    plist = plistlib.loads((root / "packaging/reviewer/Info.plist").read_bytes())
    plist["CFBundleShortVersionString"] = release_version
    (destination / "Contents/Info.plist").write_bytes(plistlib.dumps(plist))
    subprocess.run(["xcrun", "swiftc", "-swift-version", "5", "-O", "-target", f"{architecture}-apple-macosx12.0", "-framework", "AppKit", str(root / "packaging/reviewer/OpaqueReviewer.swift"), "-o", str(macos / "OpaqueReviewer")], check=True)
    if identity or ad_hoc:
        signer = identity or "-"
        for item in [*(macos / name for name in ("opaque-approver", "opaque-approve-helper", "OpaqueReviewer")), destination]:
            command = ["codesign", "--force", "--options", "runtime", "--sign", signer]
            if identity:
                command.append("--timestamp")
            subprocess.run([*command, str(item)], check=True)
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(destination)], check=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--architecture", choices=["arm64", "x86_64"], default=platform.machine())
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sign-identity")
    group.add_argument("--ad-hoc", action="store_true", help="local integrity only; not trusted distribution")
    parser.add_argument("--version", default="0.3.0")
    args = parser.parse_args()
    result = build(args.binary_dir.resolve(), args.output.absolute(), args.architecture, args.sign_identity, args.ad_hoc, args.version)
    print(result)
    print("Built only; no installation or URL registration performed.")


if __name__ == "__main__":
    main()
