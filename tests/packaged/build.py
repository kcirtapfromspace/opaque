#!/usr/bin/env python3
"""Package already compiled native tools for installed-runtime acceptance.

Copies payloads into a fresh output, adds the macOS app with ad-hoc local signing,
and uses the production release manifest format. Never publishes or installs.
"""
import argparse
import importlib.util
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_artifacts", ROOT / "scripts/release_artifacts.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    payload = args.output / "payload"
    payload.mkdir()
    for name in RELEASE.BINS:
        source = args.binary_dir / name
        if not source.is_file() or source.is_symlink():
            parser.error("all eight regular compiled tool files are required")
        shutil.copy2(source, payload / name)
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if platform.system() == "Darwin":
        subprocess.run(["python3", str(ROOT / "scripts/package-reviewer-macos.py"),
                        "--binary-dir", str(payload), "--output", str(payload / RELEASE.APP),
                        "--ad-hoc", "--version", version], check=True, timeout=120)
    revision = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    host = subprocess.check_output(["rustc", "-vV"], text=True)
    target = next(line.split(": ", 1)[1] for line in host.splitlines() if line.startswith("host: "))
    manifest = RELEASE.create_manifest(ROOT, payload, target, version, revision, allow_dirty=args.allow_dirty)
    with tarfile.open(args.output / "candidate.tar.gz", "w:gz") as archive:
        for name in [*manifest["files"], RELEASE.MANIFEST]:
            archive.add(payload / name, arcname=name, recursive=False)
    print(f"Packaged native build candidate for {target} at {revision}; no distribution signature claimed")


if __name__ == "__main__":
    main()
