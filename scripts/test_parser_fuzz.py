import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import unittest
from unittest import mock

import run_parser_fuzz as fuzz


class ParserFuzzTests(unittest.TestCase):
    def test_only_a_completed_libfuzzer_run_satisfies_the_execution_guard(self):
        self.assertEqual(fuzz.completed_runs(b"#12 INITED cov: 30\n"), 0)
        self.assertEqual(fuzz.completed_runs(b"Done 2000 runs\n"), 0)
        self.assertEqual(fuzz.completed_runs(b"#2000 DONE cov: 20\n"), 2000)
        self.assertEqual(fuzz.completed_runs(b"#20 DONE cov: 2\n#50 DONE cov: 4\n"), 50)

    def test_every_declared_fuzz_target_requires_implementation_and_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzz/fuzz_targets").mkdir(parents=True)
            (root / "fuzz/corpus/sample").mkdir(parents=True)
            (root / "fuzz/Cargo.toml").write_text('[[bin]]\nname="sample"\npath="fuzz_targets/sample.rs"\n')
            with self.assertRaises(ValueError):
                fuzz.targets(root)
            (root / "fuzz/fuzz_targets/sample.rs").write_text("fn main() {}")
            with self.assertRaises(ValueError):
                fuzz.targets(root)
            (root / "fuzz/corpus/sample/valid").write_bytes(b"fixture")
            self.assertEqual(fuzz.targets(root), ["sample"])
            (root / "fuzz/corpus/sample/link").symlink_to("valid")
            with self.assertRaises(ValueError):
                fuzz.targets(root)

    def test_shared_parser_dependencies_must_use_product_locked_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzz").mkdir()
            good = '[[package]]\nname="parser"\nversion="1.0.0"\n'
            (root / "Cargo.lock").write_text(good)
            (root / "fuzz/Cargo.lock").write_text(good)
            fuzz.verify_dependency_versions(root)
            (root / "fuzz/Cargo.lock").write_text(good.replace("1.0.0", "1.0.1"))
            with self.assertRaises(ValueError):
                fuzz.verify_dependency_versions(root)

    def test_matching_versions_cannot_replace_product_dependency_sources_or_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzz").mkdir()
            good = ('[[package]]\nname="parser"\nversion="1.0.0"\n'
                    'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                    'checksum="reviewed-checksum"\n')
            (root / "Cargo.lock").write_text(good)
            for changed in [good.replace("reviewed-checksum", "different-checksum"),
                            good.replace("registry+https://github.com/rust-lang/crates.io-index", "git+https://example.invalid/parser"),
                            good.replace('checksum="reviewed-checksum"\n', '')]:
                (root / "fuzz/Cargo.lock").write_text(changed)
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    fuzz.verify_dependency_versions(root)

    def test_campaign_environment_cannot_inherit_instrumentation_or_sanitizer_overrides(self):
        forbidden = {name: "unreviewed-override" for name in (
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "LLVM_PROFILE_FILE", "ASAN_OPTIONS", "LSAN_OPTIONS",
            "UBSAN_OPTIONS", "MSAN_OPTIONS", "TSAN_OPTIONS", "CARGO_BUILD_TARGET",
            "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "AWS_SECRET_ACCESS_KEY",
        )}
        with mock.patch.dict(os.environ, forbidden | {"RUSTUP_TOOLCHAIN": "unreviewed", "CARGO_INCREMENTAL": "1"}):
            env = fuzz.fuzz_environment()
        self.assertFalse(set(forbidden) & set(env))
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], fuzz.TOOLCHAIN)
        self.assertEqual(env["CARGO_INCREMENTAL"], "0")

    def run_campaign(self, target_result, *, fetch_result=None, snapshot_results=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzz/fuzz_targets").mkdir(parents=True)
            (root / "fuzz/corpus/sample").mkdir(parents=True)
            (root / "fuzz/Cargo.toml").write_text('[[bin]]\nname="sample"\npath="fuzz_targets/sample.rs"\n')
            (root / "fuzz/fuzz_targets/sample.rs").write_text("fn main() {}")
            (root / "fuzz/corpus/sample/seed").write_bytes(b"fixture")
            lock = '[[package]]\nname="parser"\nversion="1.0.0"\n'
            (root / "Cargo.lock").write_text(lock)
            (root / "fuzz/Cargo.lock").write_text(lock)
            calls = []
            def invoke(argv, **kwargs):
                calls.append((argv, kwargs | {"env": dict(kwargs["env"])}))
                if argv[-1] == "--version":
                    return fuzz.suite.CommandResult(0, f"cargo-fuzz {fuzz.FUZZ_VERSION}\n".encode())
                if argv[1] == "fetch":
                    return fetch_result or fuzz.suite.CommandResult(0, b"")
                return target_result
            output = root / "output"
            argv = ["run_parser_fuzz.py", "--source-root", str(root), "--output", str(output),
                    "--target-dir", str(root / "target")]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(fuzz.suite, "source_snapshot", return_value={"revision": "a" * 40, "dirty": False}, side_effect=snapshot_results), \
                    mock.patch.object(fuzz.suite, "invoke", side_effect=invoke), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = fuzz.main()
            return code, json.loads((output / "report.json").read_text()), calls

    def test_version_fetch_and_fuzz_use_owned_group_execution_and_explicit_address_sanitizer(self):
        code, report, calls = self.run_campaign(fuzz.suite.CommandResult(0, b"#2000 DONE cov: 20\n"))
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "passed")
        self.assertEqual([row["stage"] for row in report["commands"]], ["version", "fetch", "sample"])
        self.assertEqual([kwargs["timeout"] for _, kwargs in calls], [30, 300, 1800])
        self.assertIn("--locked", calls[1][0])
        command, options = calls[2]
        self.assertEqual(command[command.index("--sanitizer") + 1], "address")
        self.assertIn("--no-cfg-fuzzing", command)
        self.assertEqual(options["env"]["CARGO_NET_OFFLINE"], "true")
        self.assertNotIn("CARGO_NET_OFFLINE", calls[0][1]["env"])
        self.assertTrue(all(row["reason"] is None and not row["cleanup_forced"] for row in report["commands"]))

    def test_done_output_cannot_qualify_timeout_leak_or_failed_execution(self):
        output = b"#2000 DONE cov: 20\n"
        for result in [fuzz.suite.CommandResult(0, output, "timeout", True),
                       fuzz.suite.CommandResult(0, output, "output_limit", True),
                       fuzz.suite.CommandResult(0, output, "leaked_process_group", True),
                       fuzz.suite.CommandResult(1, output),
                       fuzz.suite.CommandResult(0, output, "private-untrusted-payload")]:
            with self.subTest(reason=result.reason, code=result.returncode):
                code, report, _ = self.run_campaign(result)
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["targets"][0]["status"], "failed")
                self.assertNotIn("private-untrusted-payload", json.dumps(report))

    def test_failed_dependency_fetch_never_starts_the_fuzzer(self):
        code, report, calls = self.run_campaign(
            fuzz.suite.CommandResult(0, b"#2000 DONE cov: 20\n"),
            fetch_result=fuzz.suite.CommandResult(0, b"", "timeout", True))
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(report["targets"], [])
        self.assertEqual(report["commands"][-1]["reason"], "timeout")

    def test_interruption_after_completed_runs_cannot_publish_a_passing_report(self):
        code, report, _ = self.run_campaign(
            fuzz.suite.CommandResult(0, b"#2000 DONE cov: 20\n"),
            snapshot_results=[{"revision": "a" * 40, "dirty": False}, KeyboardInterrupt()])
        self.assertEqual(code, 130)
        self.assertEqual(report["targets"][0]["status"], "passed")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failure"], "fuzz_interrupted")

    @unittest.skipUnless(os.name == "posix", "owned process groups require POSIX")
    def test_actual_entrypoint_sigterm_retires_the_owned_tool_and_descendant(self):
        # The tool is deliberately a process fixture: this tests interruption
        # cleanup of the real runner entrypoint, not parser fuzz acceptance.
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, tools, output = parent / "source", parent / "tools", parent / "output"
            (root / "fuzz/fuzz_targets").mkdir(parents=True)
            (root / "fuzz/corpus/sample").mkdir(parents=True)
            tools.mkdir()
            (root / "fuzz/Cargo.toml").write_text('[[bin]]\nname="sample"\npath="fuzz_targets/sample.rs"\n')
            (root / "fuzz/fuzz_targets/sample.rs").write_text("fn main() {}")
            (root / "fuzz/corpus/sample/seed").write_bytes(b"fixture")
            lock = '[[package]]\nname="parser"\nversion="1.0.0"\n'
            (root / "Cargo.lock").write_text(lock)
            (root / "fuzz/Cargo.lock").write_text(lock)
            for argv in [["init"], ["add", "."], ["-c", "user.name=Fuzz runner fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-m", "fixture"]]:
                subprocess.run(["git", *argv], cwd=root, capture_output=True, check=True, timeout=10)
            marker = output / "ready.json"
            tool = tools / "cargo-fuzz"
            tool.write_text(f'''#!{sys.executable}
import json, os, signal, subprocess, sys, time
from pathlib import Path
if sys.argv[1:] == ["--version"]:
    print("cargo-fuzz {fuzz.FUZZ_VERSION}")
    raise SystemExit(0)
marker = Path({str(marker)!r})
temporary = marker.with_suffix(".tmp")
temporary.write_text(json.dumps({{"tool": os.getpid(), "child": None}}))
temporary.replace(marker)
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
def stop(_number, _frame):
    child.wait(timeout=3)
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
temporary.write_text(json.dumps({{"tool": os.getpid(), "child": child.pid}}))
temporary.replace(marker)
time.sleep(60)
''')
            tool.chmod(0o700)
            cargo = tools / "cargo"
            cargo.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
            cargo.chmod(0o700)
            env = fuzz.suite.environment()
            env["PATH"] = str(tools) + os.pathsep + env["PATH"]
            with tempfile.TemporaryFile() as log:
                process = subprocess.Popen(
                    [sys.executable, "-B", str(Path(fuzz.__file__).resolve()), "--source-root", str(root),
                     "--output", str(output), "--target-dir", str(parent / "target"), "--cargo-fuzz", str(tool)],
                    env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    deadline = time.monotonic() + 10
                    ready = None
                    while time.monotonic() < deadline and process.poll() is None:
                        if marker.exists():
                            ready = json.loads(marker.read_text())
                            if ready["child"] is not None:
                                break
                        time.sleep(0.02)
                    self.assertIsNotNone(ready)
                    self.assertIsNotNone(ready["child"])
                    process.send_signal(signal.SIGTERM)
                    self.assertEqual(process.wait(timeout=5), 130)
                    report = json.loads((output / "report.json").read_text())
                    self.assertEqual(report["status"], "failed")
                    self.assertEqual(report["failure"], "fuzz_interrupted")
                    for pid in [ready["tool"], ready["child"]]:
                        with self.assertRaises(ProcessLookupError):
                            os.kill(pid, 0)
                finally:
                    # If the entrypoint regresses, its fake tool remains alive
                    # in its own group. Fence cleanup to this unique tool path.
                    if marker.exists():
                        pid = json.loads(marker.read_text())["tool"]
                        try:
                            command = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True, stderr=subprocess.DEVNULL)
                            if str(tool) in command and os.getpgid(pid) == pid:
                                os.killpg(pid, signal.SIGKILL)
                        except (ProcessLookupError, subprocess.CalledProcessError):
                            pass
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
