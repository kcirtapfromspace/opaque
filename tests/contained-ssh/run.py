#!/usr/bin/env python3
"""Run the declared contained profile inside one owned disposable systemd host.

Never publish service ports, inherit credentials, or prune Docker resources.
Runtime logs and synthesized reports are private local output, not site assets.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
LABEL = "org.opaque.contained-run"


def command(args, *, timeout=30, check=True, log=None):
    if log is None:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    else:
        with log.open("ab") as stream:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("contained command failed: " + Path(args[0]).name)
    return result


def git(*args):
    return command(["git", "-C", str(ROOT), *args]).stdout.decode().strip()


def output_path(path):
    path = path.expanduser().absolute()
    if path.exists() or path.is_symlink():
        raise ValueError("output must be a new directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve()
    path = parent / path.name
    if path.is_relative_to(ROOT):
        raise ValueError("runtime output must be outside the source checkout")
    path.mkdir(mode=0o700)
    return path


def mount(path, destination=None, *, readonly=True):
    if "," in str(path) or "," in str(destination or path):
        raise ValueError("Docker mount path cannot contain commas")
    return ["--mount", "type=bind,src=" + str(path) + ",dst=" + str(destination or path)
            + (",readonly" if readonly else "")]


def cleanup_container(container, run_id, output):
    metadata = command(["docker", "inspect", container], check=False)
    if metadata.returncode:
        # A disconnected daemon is not proof of removal. Confirm absence
        # through a successful inventory before reporting cleanup complete.
        inventory = command(["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}} {{.Names}}"], check=False)
        if inventory.returncode or any(container in line.split() for line in inventory.stdout.decode().splitlines()):
            return "failed"
        return "already_absent"
    actual = json.loads(metadata.stdout)[0]
    if (actual.get("Config", {}).get("Labels") or {}).get(LABEL) != run_id:
        return "ownership_mismatch"
    command(["docker", "logs", container], check=False, log=output / "systemd.log")
    removed = command(["docker", "rm", "--force", container], check=False)
    return "removed_owned_container" if removed.returncode == 0 else "failed"


def handoff_artifacts(container):
    command(["docker", "exec", container, "chown", "--recursive", "--no-dereference",
             f"{os.getuid()}:{os.getgid()}", "/evidence"])


def model_assets():
    spec = importlib.util.spec_from_file_location("opaque_model_assets", ROOT / "tests/real-model/assets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--registry-cache", help="optional existing Docker volume for Cargo registry cache")
    parser.add_argument("--target-cache", help="optional existing Docker volume; no concurrent builds may use it")
    parser.add_argument("--image", default="opaque-contained-ssh:local")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--coverage", action="store_true",
                        help="collect pinned-nightly production coverage including the contained cases")
    modes.add_argument("--real-model", action="store_true",
                       help="run the actual pinned CPU model with scripted signed approval")
    parser.add_argument("--model-file", type=Path,
                        help="existing pinned GGUF; otherwise download the immutable public asset")
    parser.add_argument("--model-image", default="opaque-contained-real-model:local")
    parser.add_argument("--acceptance", action="append", choices=("packaged", "browser", "model", "service"), default=[],
                        help="with --coverage, run existing acceptance using the same instrumented objects")
    parser.add_argument("--coverage-acceptance-only", action="store_true", help="partial development collection; not a full qualification")
    parser.add_argument("--coverage-allow-dirty", action="store_true", help="explicit local instrumented candidate only")
    args = parser.parse_args()
    wants_model = args.real_model or (args.coverage and "model" in args.acceptance)
    if args.model_file and not wants_model:
        parser.error("--model-file requires --real-model or explicit model coverage acceptance")
    if (args.acceptance or args.coverage_acceptance_only or args.coverage_allow_dirty) and not args.coverage:
        parser.error("coverage acceptance options require --coverage")
    if len(args.acceptance) != len(set(args.acceptance)):
        parser.error("each acceptance may be selected once")
    if args.coverage_acceptance_only and not args.acceptance:
        parser.error("--coverage-acceptance-only requires explicit acceptance selection")
    os.umask(0o077)
    for cache in (args.registry_cache, args.target_cache):
        if cache and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", cache):
            raise ValueError("invalid cache volume name")
        if cache:
            command(["docker", "volume", "inspect", cache])
    output = output_path(args.output)
    artifacts = output / "container"
    # Mount this child directly: fixture UIDs may traverse it inside the
    # container, while the host's outer 0700 output keeps artifacts private.
    artifacts.mkdir(mode=0o711)
    artifacts.chmod(0o711)  # Restore traversal bits removed by the private umask.
    run_id = str(uuid.uuid4())
    name = "opaque-contained-" + run_id
    record = {"schema": "opaque.contained-run.v1", "run_id": run_id,
              "status": "failed", "mode": "coverage" if args.coverage else "real-model" if args.real_model else "acceptance",
              "started_unix": time.time(), "cleanup": "not_started",
              "network_scope": "one disposable host; literal loopback services; no inter-host isolation claim",
              "approval_scope": "production protocol with explicit synthetic test signer; no native human claim"}
    # Signal handlers unwind into owned-container cleanup. A forced SIGKILL
    # remains the caller/CI runner's responsibility, as with other processes.
    def interrupt(_signal, _frame):
        raise KeyboardInterrupt
    old_handlers = {number: signal.signal(number, interrupt) for number in (signal.SIGTERM, signal.SIGINT)}
    container = None
    model = None
    assets = None
    try:
        if wants_model:
            assets = model_assets()
            model = assets.obtain_model(args.model_file, output)
            record["model_host_before"] = assets.verify_model(model)
        command(["docker", "build", "--tag", args.image, str(Path(__file__).parent)],
                timeout=900, log=output / "image-build.log")
        selected_image = args.image
        if wants_model:
            command(["docker", "build", "--build-arg", "CONTAINED_IMAGE=" + args.image,
                     "--tag", args.model_image, str(ROOT / "tests/real-model")],
                    timeout=1800, log=output / "model-image-build.log")
            selected_image = args.model_image
        if "service" in args.acceptance:
            service_image = selected_image + "-service"
            command(["docker", "build", "--build-arg", "CONTAINED_IMAGE=" + selected_image,
                     "--tag", service_image, str(ROOT / "tests/service")],
                    timeout=300, log=output / "service-image-build.log")
            selected_image = service_image
        image = json.loads(command(["docker", "image", "inspect", selected_image]).stdout)[0]
        record["image"] = {"id": image["Id"], "architecture": image["Architecture"], "os": image["Os"]}
        common = Path(git("rev-parse", "--git-common-dir"))
        if not common.is_absolute():
            common = (ROOT / common).resolve()
        argv = ["docker", "run", "--detach", "--name", name, "--label", LABEL + "=" + run_id,
                "--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,mode=1777"]
        argv += mount(ROOT)
        if not common.is_relative_to(ROOT):
            argv += mount(common)
        argv += mount(artifacts, "/evidence", readonly=False)
        if model is not None:
            argv += mount(model, "/models/model.gguf")
        for cache, destination in ((args.registry_cache, "/usr/local/cargo/registry"), (args.target_cache, "/target")):
            if cache:
                argv += ["--mount", f"type=volume,src={cache},dst={destination}"]
        argv += [selected_image]
        # An uncertain Docker response still leaves this exact, labeled name
        # eligible for cleanup; never infer ownership from a prefix alone.
        container = name
        container = command(argv).stdout.decode().strip()
        record["container_id"] = container
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = command(["docker", "exec", container, "cat", "/proc/1/comm"], check=False)
            if state.returncode == 0 and state.stdout.strip() == b"systemd":
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("contained systemd startup deadline")
        if args.coverage:
            command(["docker", "exec", container, "rustup", "toolchain", "install",
                     "nightly-2026-09-13", "--profile", "minimal", "--component", "llvm-tools-preview"],
                    timeout=900, log=output / "coverage-tools.log")
            command(["docker", "exec", container, "cargo", "+1.95.0", "install", "cargo-llvm-cov",
                     "--version", "0.9.1", "--locked", "--root", "/coverage-tools"],
                    timeout=900, log=output / "coverage-tools.log")
            arguments = ["scripts/collect_critical_coverage.py", "--contained", "--source-root", str(ROOT),
                         "--target-dir", "/target", "--reuse-target-dir", "--output", "/evidence/coverage",
                         "--collector", "/coverage-tools/bin/cargo-llvm-cov"]
            for purpose in args.acceptance:
                arguments += ["--acceptance", purpose]
            if args.coverage_acceptance_only:
                arguments.append("--acceptance-only")
            if args.coverage_allow_dirty:
                arguments.append("--acceptance-allow-dirty")
            report_path = artifacts / "coverage/collection.json"
            expected = "acceptance_only_collected" if args.coverage_acceptance_only else "collected"
        elif args.real_model:
            arguments = ["tests/real-model/service.py", "--source-root", str(ROOT),
                         "--target-dir", "/target", "--output", "/evidence/model",
                         "--suite-output", "/evidence/suite"]
            report_path = artifacts / "suite/report.json"
            expected = "passed"
        else:
            arguments = ["scripts/synthesized_suite.py", "--profile", "contained",
                         "--target-dir", "/target", "--output", "/evidence/suite"]
            report_path = artifacts / "suite/report.json"
            expected = "passed"
        suite = command(["docker", "exec", "--workdir", str(ROOT), container, "python3", "-B", *arguments],
                        timeout=3600, check=False, log=output / "suite.log")
        record["suite_exit_code"] = suite.returncode
        # Linux bind mounts preserve container-root ownership. Transfer only
        # this run's private artifact mount before the host caller reads its
        # mode-0600 report; the source and cache mounts remain untouched.
        handoff_artifacts(container)
        if report_path.exists():
            raw = report_path.read_bytes()
            report = json.loads(raw)
            record["suite_report_sha256"] = hashlib.sha256(raw).hexdigest()
            record["source"] = report.get("source_after")
            record["counts"] = report.get("counts")
            if args.coverage:
                record["coverage_gate"] = report.get("coverage_gate")
                record["measured"] = report.get("measured")
            if suite.returncode == 0 and report.get("status") == expected:
                record["status"] = expected
        if args.real_model:
            service_path = artifacts / "model-service.json"
            if not service_path.is_file():
                record["status"] = "failed"
            else:
                model_service = json.loads(service_path.read_text())
                record["model_service"] = model_service
                if model_service.get("status") != "passed" or model_service.get("cleanup") != "stopped_and_reaped":
                    record["status"] = "failed"
    finally:
        if container is not None:
            try:
                record["cleanup"] = cleanup_container(container, run_id, output)
            except (OSError, RuntimeError, ValueError, KeyError, IndexError, TypeError, subprocess.TimeoutExpired) as error:
                record["cleanup"] = "failed"
                record["cleanup_error"] = type(error).__name__
            if record["cleanup"] not in ("already_absent", "removed_owned_container"):
                record["status"] = "failed"
        if model is not None:
            try:
                record["model_host_after"] = assets.verify_model(model)
                if record.get("model_host_before") != record["model_host_after"]:
                    record["status"] = "failed"
            except (OSError, ValueError) as error:
                record["status"] = "failed"
                record["model_host_check_failure"] = type(error).__name__
        record["finished_unix"] = time.time()
        (output / "run.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        for number, handler in old_handlers.items():
            signal.signal(number, handler)
    print(json.dumps({"status": record["status"], "cleanup": record["cleanup"], "output": str(output)}))
    # Successful collection does not mean the per-crate coverage policy passed.
    # Enforce tiers and the native-target ratchet with check_coverage_policy.py.
    return 0 if record["status"] in ("passed", "collected", "acceptance_only_collected") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("Contained acceptance failed; inspect the private output directory.", file=sys.stderr)
        raise SystemExit(1)
