#!/usr/bin/env python3
"""Own one actual pinned CPU model server for the declared model acceptance test.

Run only in the disposable contained host. The service summary contains hashes
and counters; full server logs and test outputs stay in private runtime files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

from assets import LLAMA_COMMIT, MODEL_COMMIT, MODEL_SHA256, TEMPLATE_SHA256, digest, verify_model

ALIAS = "opaque-smollm2-135m"
MODEL = Path("/models/model.gguf")
SERVER = Path("/opt/opaque-model/llama-server")
MAX_REPLY = 256 * 1024


def get(base, path, *, as_json=True):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base.rstrip("/") + path, timeout=2) as response:
        if response.status != 200:
            raise ValueError("model metadata status is not successful")
        raw = response.read(MAX_REPLY + 1)
    if len(raw) > MAX_REPLY:
        raise ValueError("model metadata exceeds its byte limit")
    return json.loads(raw) if as_json else raw.decode("utf-8", errors="strict")


def generation_count(metrics):
    values = []
    for line in metrics.splitlines():
        if line.startswith("llamacpp:tokens_predicted_total"):
            match = re.fullmatch(r"llamacpp:tokens_predicted_total ([0-9]+)", line)
            if match is None:
                raise ValueError("unrecognized model generation counter")
            values.append(int(match[1]))
    if len(values) != 1:
        raise ValueError("missing or duplicate generation counter")
    return values[0]


def profile_from_metadata(base, props, models, service_uid):
    if not isinstance(props, dict) or not isinstance(models, dict):
        raise ValueError("model metadata must be objects")
    build = props.get("build_info")
    if not isinstance(build, str) or not re.fullmatch(r"b[0-9]+-" + LLAMA_COMMIT[:9], build):
        raise ValueError("server metadata has the wrong source revision")
    template = props.get("chat_template")
    if not isinstance(template, str) or hashlib.sha256(template.encode()).hexdigest() != TEMPLATE_SHA256:
        raise ValueError("server template differs from the pinned model")
    settings = props.get("default_generation_settings")
    if (props.get("model_path") != str(MODEL) or type(props.get("total_slots")) is not int
            or props["total_slots"] != 1 or not isinstance(settings, dict)
            or type(settings.get("n_ctx")) is not int or settings["n_ctx"] != 1024):
        raise ValueError("model server context or artifact path differs")
    entries = models.get("data")
    if (not isinstance(entries, list) or len(entries) != 1
            or not isinstance(entries[0], dict) or entries[0].get("id") != ALIAS):
        raise ValueError("model alias inventory differs")
    return {"profile_id": "contained-pinned-model", "api_url": base, "model_id": ALIAS,
            "model_path": str(MODEL), "model_artifact_sha256": MODEL_SHA256,
            "chat_template_sha256": TEMPLATE_SHA256, "server_build": build,
            "service_uid": service_uid, "source_id": "opaque-public-receipts-v1",
            "allow_loopback_http": True}


def stop_owned(process):
    # start_new_session binds this process group to the exact owned child.
    # Reaping alone is insufficient if a descendant outlives the group leader.
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return "stopped_and_reaped"
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return "stopped_and_reaped"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return "stopped_and_reaped"
        time.sleep(0.01)
    return "process_group_remains"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--suite-output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--coverage-input", type=Path,
                        help="explicit collector-built model test; stable default acceptance remains unchanged")
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    report = {"schema": "opaque.actual-model-service.v1", "status": "failed",
              "model_revision": MODEL_COMMIT, "server_source_revision": LLAMA_COMMIT,
              "approval_scope": "actual signed protocol with scripted test review; no native human claim",
              "source_scope": "fixed synthetic public receipt prompts; not live GitHub data or a quality benchmark",
              "execution": {"backend": "cpu", "threads": 2, "context_tokens": 1024,
                            "parallel_slots": 1, "gpu_layers": 0},
              "cleanup": "not_started"}
    server = None
    suite = None
    previous_handlers = {}
    def interrupt(_signal, _frame):
        raise KeyboardInterrupt
    for number in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[number] = signal.signal(number, interrupt)
    try:
        coverage = None
        if args.coverage_input is not None:
            sys.path.insert(0, str(args.source_root / "scripts"))
            import acceptance_coverage
            coverage = acceptance_coverage.load(args.coverage_input, root=args.source_root, purpose="model")
        if Path("/opt/opaque-model/source-commit").read_text().strip() != LLAMA_COMMIT:
            raise ValueError("server image has the wrong source pin")
        report["model_before"] = verify_model(MODEL)
        report["server_before"] = digest(SERVER)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        base = f"http://127.0.0.1:{port}/"
        home = args.output / "server-home"
        home.mkdir(mode=0o700)
        argv = [str(SERVER), "--model", str(MODEL), "--host", "127.0.0.1", "--port", str(port),
                "--parallel", "1", "--ctx-size", "1024", "--threads", "2", "--n-gpu-layers", "0",
                "--alias", ALIAS, "--metrics"]
        with (args.output / "server.log").open("xb") as log:
            server = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=True, env={"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                                                                   "HOME": str(home), "LANG": "C.UTF-8"})
        report["server_pid"] = server.pid
        deadline = time.monotonic() + 60
        while True:
            if server.poll() is not None:
                raise RuntimeError("model server exited before readiness")
            try:
                if get(base, "/health") == {"status": "ok"}:
                    break
            except (OSError, ValueError, urllib.error.URLError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("model server readiness deadline")
            time.sleep(0.1)
        if Path(f"/proc/{server.pid}/exe").resolve() != SERVER:
            raise ValueError("observed server executable differs")
        report["server_start_ticks"] = int(Path(f"/proc/{server.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19])
        profile = profile_from_metadata(base, get(base, "/props"), get(base, "/v1/models"), str(uuid.uuid4()))
        report["server_build"] = profile["server_build"]
        report["service_uid"] = profile["service_uid"]
        report["chat_template_sha256"] = profile["chat_template_sha256"]
        profile_path = args.output / "profile.json"
        profile_path.write_text(json.dumps(profile, sort_keys=True) + "\n")
        report["profile_file_sha256"] = digest(profile_path)["sha256"]
        report["tokens_before"] = generation_count(get(base, "/metrics", as_json=False))
        if report["tokens_before"] != 0:
            raise ValueError("generation occurred before the approval suite")
        env = {"PATH": "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/root",
               "CARGO_HOME": "/usr/local/cargo", "RUSTUP_HOME": "/usr/local/rustup",
               "RUSTUP_TOOLCHAIN": "1.95.0"}
        suite_arguments = [sys.executable, "-B", str(args.source_root / "scripts/synthesized_suite.py"),
                           "--profile", "model", "--target-dir", str(args.target_dir),
                           "--model-profile", str(profile_path), "--output", str(args.suite_output)]
        if coverage:
            env["RUSTUP_TOOLCHAIN"] = coverage["toolchain"]
            suite_arguments += ["--coverage-input", str(args.coverage_input)]
        with (args.output / "acceptance.log").open("xb") as log:
            suite = subprocess.Popen(suite_arguments,
                                     cwd=args.source_root, env=env, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        report["suite_exit_code"] = suite.wait(timeout=2400)
        report["tokens_after"] = generation_count(get(base, "/metrics", as_json=False))
        if server.poll() is not None or report["tokens_after"] <= 0:
            raise ValueError("model server did not retain observed generation evidence")
        acceptance = json.loads((args.suite_output / "report.json").read_text())
        report["counts"] = acceptance.get("counts")
        if report["suite_exit_code"] == 0 and acceptance.get("status") == "passed":
            if coverage:
                report["coverage"] = {"input_sha256": acceptance_coverage.digest(args.coverage_input),
                                      "qualification": coverage["qualification"],
                                      "profiles": acceptance_coverage.profiles(coverage, roles={"test", "daemon", "peer"})}
            report["status"] = "passed"
    except (KeyboardInterrupt, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["failure_kind"] = type(error).__name__
    finally:
        for process, key in ((suite, "suite_cleanup"), (server, "cleanup")):
            if process is None:
                continue
            try:
                report[key] = stop_owned(process)
            except (OSError, subprocess.TimeoutExpired) as error:
                report[key] = "failed"
                report[key + "_failure"] = type(error).__name__
            if report[key] != "stopped_and_reaped":
                report["status"] = "failed"
        try:
            report["model_after"] = verify_model(MODEL)
            report["server_after"] = digest(SERVER)
            if report.get("model_before") != report["model_after"] or report.get("server_before") != report["server_after"]:
                report["status"] = "failed"
                report["artifact_identity_changed"] = True
        except (OSError, ValueError) as error:
            report["status"] = "failed"
            report["artifact_check_failure"] = type(error).__name__
        (args.output.parent / "model-service.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    print(json.dumps({"status": report["status"], "cleanup": report["cleanup"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
