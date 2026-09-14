#!/usr/bin/env python3
"""Run every declared parser fuzz target with bounded, reproducible inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib

import synthesized_suite as suite

TOOLCHAIN = "nightly-2026-09-13"
FUZZ_VERSION = "0.13.2"


def completed_runs(output: bytes) -> int:
    matches = re.findall(rb"^#([0-9]+)\s+DONE\b", output, re.MULTILINE)
    return int(matches[-1]) if matches else 0


def fuzz_environment() -> dict[str, str]:
    env = suite.environment()
    env.update(RUSTUP_TOOLCHAIN=TOOLCHAIN, CARGO_INCREMENTAL="0")
    return env


def verify_dependency_versions(root: Path) -> None:
    production = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    campaign = tomllib.loads((root / "fuzz/Cargo.lock").read_text())["package"]
    identities: dict[str, set[tuple[str, str | None, str | None]]] = {}
    def identity(package):
        return package["version"], package.get("source"), package.get("checksum")
    for package in production:
        identities.setdefault(package["name"], set()).add(identity(package))
    for package in campaign:
        if package["name"] in identities and identity(package) not in identities[package["name"]]:
            raise ValueError("fuzz dependency identity differs from the product lock")


def targets(root: Path) -> list[str]:
    manifest = tomllib.loads((root / "fuzz/Cargo.toml").read_text())
    names = [entry["name"] for entry in manifest["bin"]]
    if not names or len(set(names)) != len(names):
        raise ValueError("missing or duplicate fuzz targets")
    for entry in manifest["bin"]:
        name = entry["name"]
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            raise ValueError("invalid fuzz target name")
        if entry["path"] != f"fuzz_targets/{name}.rs":
            raise ValueError("fuzz target path differs from its declared name")
        if not (root / "fuzz" / entry["path"]).is_file():
            raise ValueError("missing fuzz implementation")
        seeds = list((root / "fuzz/corpus" / name).iterdir())
        if not seeds or any(not p.is_file() or p.is_symlink() for p in seeds):
            raise ValueError("each target needs reviewed regular seed files")
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cargo-fuzz", default="cargo-fuzz")
    parser.add_argument("--runs", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=424242)
    args = parser.parse_args()
    if args.runs < 1 or args.seed < 1:
        parser.error("runs and seed must be positive")
    root = args.source_root.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    env = fuzz_environment()
    report = {"schema": "opaque.parser-fuzz-smoke.v1", "status": "failed",
              "toolchain": TOOLCHAIN, "cargo_fuzz": FUZZ_VERSION, "seed": args.seed,
              "requested_runs_per_target": args.runs, "sanitizer": "address", "targets": [],
              "commands": []}
    interrupted = False
    def run(stage, command, timeout):
        result = suite.invoke(command, cwd=root, env=env, timeout=timeout)
        (output / f"{stage}.log").write_bytes(result.output)
        # Only fixed cleanup classifications enter the public summary. Command
        # output and arbitrary exception payloads stay in the private logs.
        reason = result.reason if result.reason in (None, "timeout", "output_limit", "leaked_process_group") else "execution_interrupted"
        report["commands"].append({"stage": stage, "exit_code": result.returncode,
                                   "reason": reason, "cleanup_forced": result.cleanup_forced,
                                   "log_sha256": hashlib.sha256(result.output).hexdigest()})
        return result
    try:
        report["source_before"] = suite.source_snapshot(root)
        names = targets(root)
        verify_dependency_versions(root)
        version_result = run("version", [args.cargo_fuzz, "--version"], 30)
        suite.command_ok(version_result)
        version = version_result.output.decode().strip()
        if version != f"cargo-fuzz {FUZZ_VERSION}":
            raise ValueError("cargo-fuzz version differs from pin")
        lock = root / "fuzz/Cargo.lock"
        lock_hash = hashlib.sha256(lock.read_bytes()).hexdigest()
        report["lock_sha256"] = lock_hash
        suite.command_ok(run("fetch", ["cargo", "fetch", "--locked", "--manifest-path", str(root / "fuzz/Cargo.toml")], 300))
        # cargo-fuzz has no --locked option. Offline execution plus a before/after
        # lock digest prevents silently resolving a different dependency graph.
        env["CARGO_NET_OFFLINE"] = "true"
        for name in names:
            corpus = output / "corpus" / name
            shutil.copytree(root / "fuzz/corpus" / name, corpus)
            artifacts = output / "artifacts" / name
            artifacts.mkdir(parents=True)
            command = [args.cargo_fuzz, "fuzz", "run", "--fuzz-dir", str(root / "fuzz"),
                       "--target-dir", str(args.target_dir.resolve()), "--no-cfg-fuzzing", "--sanitizer", "address", "--codegen-units", "16",
                       name, str(corpus), "--", f"-runs={args.runs}", f"-seed={args.seed}",
                       "-max_len=131074", "-timeout=5", "-rss_limit_mb=2048",
                       f"-artifact_prefix={artifacts}/"]
            started = time.monotonic()
            result = run(name, command, 1800)
            raw = result.output
            runs = completed_runs(raw)
            unchanged = hashlib.sha256(lock.read_bytes()).hexdigest() == lock_hash
            passed = result.reason is None and not result.cleanup_forced and result.returncode == 0 and runs >= args.runs and unchanged
            report["targets"].append({"target": name, "status": "passed" if passed else "failed",
                                      "exit_code": result.returncode, "completed_runs": runs,
                                      "reason": report["commands"][-1]["reason"], "cleanup_forced": result.cleanup_forced,
                                      "seconds": round(time.monotonic() - started, 3), "lock_unchanged": unchanged,
                                      "log_sha256": hashlib.sha256(raw).hexdigest()})
            print(f"{name}: {'passed' if passed else 'failed'} ({runs} executions)", flush=True)
            if not passed:
                break
        if len(report["targets"]) == len(names) and all(row["status"] == "passed" for row in report["targets"]):
            report["status"] = "passed"
    except KeyboardInterrupt:
        interrupted = True
        report["status"] = "failed"
        report["failure"] = "fuzz_interrupted"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, suite.Invalid):
        report["failure"] = "fuzz_setup_or_execution_failed"
    finally:
        try:
            report["source_after"] = suite.source_snapshot(root)
        except KeyboardInterrupt:
            interrupted = True
            report["status"] = "failed"
            report["failure"] = "fuzz_interrupted"
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, suite.Invalid):
            report["status"] = "failed"
            report["failure"] = "fuzz_source_snapshot_failed"
        else:
            if report.get("source_before") != report["source_after"]:
                report["status"] = "failed"
                report["failure"] = "source_changed_during_fuzz_execution"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 130 if interrupted else 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        # Unwind the shared invocation helper so its separately owned compiler
        # or fuzzer process group is retired when CI terminates the runner.
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Parser fuzz runner interrupted; no successful qualification produced.", file=sys.stderr)
        raise SystemExit(130)
