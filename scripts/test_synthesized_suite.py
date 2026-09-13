"""Runner regressions use fake compiler output, never native approval or providers."""
import copy
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import synthesized_suite as suite


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="opaque-runner-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.binary = self.target / "test-fixture"
        self.binary.write_bytes(b"synthetic executable fixture")
        self.manifest = {
            "schema": suite.SCHEMA, "scope": "Synthetic runner regression only",
            "profiles": list(suite.SOFTWARE),
            "targets": [{"id": "fixture", "package": "fixture", "kind": "test", "name": "fixture",
                         "features": [], "platforms": ["linux", "darwin"], "root": False,
                         "tools": [], "build_timeout_seconds": 10}],
            "tests": [{"id": key, "target": "fixture", "name": "fixture::" + key,
                       "timeout_seconds": 1, "include_ignored": False} for key in ("first", "second")],
            "requirements": [
                {"id": "first-contract", "profile": "protocol", "status": "implemented",
                 "tests": ["first", "second"], "description": "Both test results are required"},
                {"id": "shared-contract", "profile": "protocol", "status": "implemented",
                 "tests": ["first"], "description": "Shared test executes once"},
                *[{"id": p + "-missing", "profile": p, "status": "missing", "tests": [],
                   "description": "Not implemented"} for p in ("contained", "model", "packaged")],
                {"id": "vendor", "profile": "external", "status": "external", "tests": [],
                 "description": "Live account qualification is separate"}],
        }
        self.calls = []
        self.list_output = b"fixture::first: test\nfixture::second: test\n\n2 tests, 0 benchmarks\n"
        self.overrides = {}
        self.snapshot_value = {"revision": "a" * 40, "tree_sha256": "b" * 64, "dirty": False}

    def fake(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == "rustc":
            return suite.CommandResult(0, ("release: 1.95.0\nhost: x86_64-unknown-linux-gnu\ncommit-hash: " + "a"*40 + "\n").encode())
        if argv[0] == "cargo":
            event = {"reason": "compiler-artifact", "profile": {"test": True},
                     "target": {"kind": ["test"], "name": "fixture"}, "executable": str(self.binary)}
            return suite.CommandResult(0, json.dumps(event).encode())
        if "--list" in argv:
            return suite.CommandResult(0, self.list_output)
        name = argv[argv.index("--exact") + 1]
        return self.overrides.get(name, suite.CommandResult(
            0, f"running 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n".encode()))

    def run_report(self, profile="protocol", snapshot=None):
        with patch.object(suite.shutil, "which", return_value="/fixture/tool"):
            return suite.run_suite(self.manifest, self.root, profile, self.target,
                                   executor=self.fake, snapshot=snapshot or (lambda _: self.snapshot_value.copy()))

    def test_selected_requirements_and_unique_execution_counts_are_distinct(self):
        report = self.run_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"]["unique_tests_passed"], 2)
        self.assertEqual(report["counts"]["scenario_executions"], 2)
        self.assertEqual(report["counts"]["selected_requirements_passed"], 2)
        self.assertEqual(len([a for a in self.calls if "--exact" in a]), 2)
        self.assertIsNone(report["coverage"]["line_percent"])
        self.assertEqual(report["coverage"]["overall_product"], "not_measured")
        self.assertEqual(report["requirements"][-1]["status"], "not_selected_external")

    def test_all_profile_fails_with_explicit_unimplemented_requirements(self):
        report = self.run_report("all")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(sum(r["status"] == "missing" for r in report["requirements"]), 3)
        self.assertEqual(report["counts"]["unique_tests_passed"], 2)

    def test_missing_test_blocks_target_before_any_execution(self):
        self.list_output = b"fixture::first: test\n\n1 test, 0 benchmarks\n"
        report = self.run_report()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(any("--exact" in argv for argv in self.calls))
        self.assertTrue(all(t["reason"] == "required_test_missing" for t in report["tests"]))

    def test_vacuous_skipped_and_partial_named_results_fail(self):
        outputs = [
            b"running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;\n",
            b"test fixture::first ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out;\n",
            b"test fixture::first ... ok\n",
            b"test fixture::different ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;\n",
            b"test fixture::first ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n",
        ]
        for output in outputs:
            with self.subTest(output=output):
                self.overrides["fixture::first"] = suite.CommandResult(0, output)
                self.assertEqual(self.run_report()["status"], "failed")

    def test_explicit_ignored_selection_must_still_really_pass(self):
        self.manifest["tests"][0]["include_ignored"] = True
        self.assertEqual(self.run_report()["status"], "passed")
        selected = next(a for a in self.calls if "--exact" in a)
        self.assertIn("--include-ignored", selected)
        self.overrides["fixture::first"] = suite.CommandResult(
            0, b"test fixture::first ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;\n")
        self.assertEqual(self.run_report()["status"], "failed")

    def test_prerequisite_failure_cannot_green_skip(self):
        self.manifest["targets"][0]["root"] = True
        with patch.object(suite.os, "geteuid", return_value=501):
            report = self.run_report()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["counts"]["scenario_executions"], 0)
        self.assertTrue(all(t["reason"] == "root_required" for t in report["tests"]))
        self.assertFalse(any(a[0] != "rustc" for a in self.calls))

    def test_source_change_prevents_requirement_qualification(self):
        snapshots = iter([self.snapshot_value, self.snapshot_value | {"dirty": True}])
        report = self.run_report(snapshot=lambda _: next(snapshots))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["counts"]["selected_requirements_passed"], 0)
        self.assertIn("source_changed_during_run", report["gates"])

    def test_required_ptrace_cannot_be_silently_substituted(self):
        self.manifest["targets"][0]["requires_sys_ptrace"] = True
        with patch.object(suite, "has_sys_ptrace", return_value=False):
            report = self.run_report()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(any(a[0] != "rustc" for a in self.calls))
        self.assertTrue(all(t["reason"] == "sys_ptrace_required" for t in report["tests"]))

    def test_missing_initial_source_produces_failure_report(self):
        def unavailable(_):
            raise suite.Invalid("unavailable")
        report = self.run_report(snapshot=unavailable)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["counts"]["scenario_executions"], 0)
        self.assertFalse(any(a[0] != "rustc" for a in self.calls))

    def test_failure_reports_hide_subprocess_output_and_fail_junit(self):
        sentinel = b"PRIVATE_CREDENTIAL_SENTINEL"
        self.overrides["fixture::first"] = suite.CommandResult(1, sentinel)
        report = self.run_report()
        output = self.root / "reports"
        suite.write_reports(report, output)
        self.assertNotIn(sentinel, (output / "report.json").read_bytes())
        self.assertNotIn(sentinel, (output / "junit.xml").read_bytes())
        xml = ET.fromstring((output / "junit.xml").read_bytes())
        self.assertEqual(xml.attrib["failures"], "1")
        self.assertEqual(xml.attrib["skipped"], "0")
        with self.assertRaises(suite.Invalid):
            suite.write_reports(report, output)

    def test_timeout_is_failure_even_if_captured_output_claims_pass(self):
        passed = self.fake(["binary", "--exact", "fixture::first"])
        self.overrides["fixture::first"] = suite.CommandResult(0, passed.output, "timeout", True)
        self.assertEqual(self.run_report()["status"], "failed")

    def test_duplicate_tests_and_vacuous_requirements_are_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed["tests"][1]["name"] = changed["tests"][0]["name"]
        with self.assertRaises(suite.Invalid):
            suite.validate_manifest(changed)
        changed = copy.deepcopy(self.manifest)
        changed["requirements"][0]["tests"] = []
        with self.assertRaises(suite.Invalid):
            suite.validate_manifest(changed)

    def test_inventory_rejects_partial_or_duplicate_names(self):
        for value in (b"", b"x: test\n2 tests, 0 benchmarks\n",
                      b"x: test\nx: test\n2 tests, 0 benchmarks\n"):
            with self.assertRaises(suite.Invalid):
                suite.inventory(value)

    def test_default_libtest_inventory_is_requested_instead_of_terse(self):
        self.run_report()
        argv = next(a for a in self.calls if "--list" in a)
        self.assertEqual(argv, [str(self.binary), "--list"])
        # Real --format terse lacks a footer and cannot prove completeness.
        with self.assertRaises(suite.Invalid):
            suite.inventory(b"bounded_task_store_matches_reference_state_graph: test\n")
        self.assertEqual(
            suite.inventory(b"bounded_task_store_matches_reference_state_graph: test\n\n1 test, 0 benchmarks\n"),
            {"bounded_task_store_matches_reference_state_graph"})

    def test_model_proof_requires_exact_finite_bounds_and_no_extra_fields(self):
        proof = dict(schema_version=1, fixed_cases=8, abstract_states=79, abstract_edges=1343,
                     allowed_edges=345, denied_edges=998, fresh_database_sequences=1351,
                     persisted_transition_checks=8848, max_witness_depth=6, declared_depth_bound=8,
                     slots=1, request_identities=2, logical_instants=2, wall_clock_sleeps=0, provider_calls=0)
        marker = lambda p: b"TASK_MODEL_COVERAGE " + json.dumps(p).encode() + b"\n"
        self.assertEqual(suite.model_proof(marker(proof))["observed"], proof)
        for changed in (proof | {"abstract_edges": 1342}, proof | {"private_value": "sentinel"},
                        proof | {"slots": True}):
            with self.assertRaises(suite.Invalid):
                suite.model_proof(marker(changed))
        with self.assertRaises(suite.Invalid):
            suite.model_proof(marker(proof) * 2)
        duplicate = marker(proof).replace(b'{"schema_version": 1,', b'{"schema_version": 0, "schema_version": 1,')
        with self.assertRaises(suite.Invalid):
            suite.model_proof(duplicate)

    def test_changed_artifact_cannot_keep_a_passing_result(self):
        def changed(argv, **kwargs):
            result = self.fake(argv, **kwargs)
            if "--exact" in argv:
                self.binary.write_bytes(b"substituted executable")
            return result
        with patch.object(suite.shutil, "which", return_value="/fixture/tool"):
            report = suite.run_suite(self.manifest, self.root, "protocol", self.target,
                                     executor=changed, snapshot=lambda _: self.snapshot_value)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["tests"][0]["reason"], "test_artifact_changed")
        self.assertEqual(report["counts"]["scenario_executions"], 1)
        self.assertEqual(len([call for call in self.calls if "--exact" in call]), 1)

    def test_target_alias_cannot_inflate_unique_compiled_test_counts(self):
        changed = copy.deepcopy(self.manifest)
        changed["targets"].append(changed["targets"][0] | {"id": "alias"})
        changed["tests"].append(changed["tests"][0] | {"id": "aliased-first", "target": "alias"})
        changed["requirements"][0]["tests"].append("aliased-first")
        with self.assertRaisesRegex(suite.Invalid, "duplicate_compilation_target"):
            suite.validate_manifest(changed)

    def test_empty_benchmarked_or_multiple_inventory_summaries_fail(self):
        for output in (b"0 tests, 0 benchmarks\n", b"x: test\n1 test, 1 benchmark\n",
                       b"x: test\n1 test, 0 benchmarks\n1 test, 0 benchmarks\n"):
            with self.assertRaises(suite.Invalid):
                suite.inventory(output)

    def test_execution_environment_removes_ambient_credentials(self):
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "sentinel", "OPAQUE_SESSION_TOKEN": "sentinel"}):
            env = suite.environment(execution_home="/isolated-home")
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("OPAQUE_SESSION_TOKEN", env)
        self.assertEqual(env["HOME"], "/isolated-home")
        self.assertTrue(env["CARGO_HOME"])
        self.assertTrue(env["RUSTUP_HOME"])

    def test_source_git_trust_is_limited_to_the_explicit_checkout(self):
        self.assertEqual(suite.git_command(self.root, "rev-parse", "HEAD"),
                         ["git", "-c", "safe.directory=" + str(self.root.resolve()), "rev-parse", "HEAD"])
        invocations = []
        def fake_git(argv, **kwargs):
            invocations.append(argv)
            value = b"a" * 40 + b"\n" if "rev-parse" in argv else b""
            return suite.CommandResult(0, value)
        suite.source_snapshot(self.root, executor=fake_git)
        self.assertEqual(len(invocations), 3)
        self.assertTrue(all(argv[1:3] == ["-c", "safe.directory=" + str(self.root.resolve())]
                            for argv in invocations))
        self.assertFalse(any("safe.directory=*" in argv for argv in invocations))

    def test_real_timeout_terminates_the_owned_process_group(self):
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); print(p.pid,flush=True); time.sleep(30)"
        result = suite.invoke([sys.executable, "-B", "-c", code], cwd=self.root,
                              env=suite.environment(), timeout=0.2)
        self.assertEqual(result.reason, "timeout")
        self.assertTrue(result.cleanup_forced)
        child = int(result.output.strip())
        def alive():
            try:
                os.kill(child, 0)
                stat = Path(f"/proc/{child}/stat")
                return not (stat.exists() and stat.read_text().split()[2] == "Z")
            except ProcessLookupError:
                return False
        deadline = time.monotonic() + 2
        while alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(alive())


if __name__ == "__main__":
    unittest.main()
