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

    def model_requirement(self):
        requirement = next(r for r in self.manifest["requirements"] if r["profile"] == "model")
        requirement.update(status="implemented", tests=["first"])

    def test_real_model_input_is_explicit_and_only_selected_model_cases_receive_it(self):
        self.model_requirement()
        model = self.root / "model-profile.json"
        model.write_text('{"synthetic_runner_profile":true}')
        environments = {}
        def fake(argv, **kwargs):
            if "--exact" in argv:
                environments[argv[argv.index("--exact") + 1]] = kwargs["env"].copy()
            return self.fake(argv, **kwargs)
        with patch.object(suite.shutil, "which", return_value="/fixture/tool"), patch.dict(os.environ, {"OPAQUE_TEST_REAL_MODEL_PROFILE": "ambient-value"}):
            report = suite.run_suite(self.manifest, self.root, "all", self.target, executor=fake,
                                     snapshot=lambda _: self.snapshot_value, model_profile=model)
        self.assertEqual(report["counts"]["unique_tests_passed"], 2)
        self.assertEqual(environments["fixture::first"]["OPAQUE_TEST_REAL_MODEL_PROFILE"], str(model))
        self.assertNotIn("OPAQUE_TEST_REAL_MODEL_PROFILE", environments["fixture::second"])
        self.assertEqual(report["model_profile_sha256"], suite.digest(model.read_bytes()))
        with self.assertRaisesRegex(suite.Invalid, "model_input_without_selected_model_test"):
            suite.run_suite(self.manifest, self.root, "protocol", self.target, model_profile=model)

    def test_missing_real_model_input_cannot_use_ambient_profile_or_execute(self):
        self.model_requirement()
        with patch.dict(os.environ, {"OPAQUE_TEST_REAL_MODEL_PROFILE": "ambient-value"}):
            report = self.run_report("model")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["tests"][0]["reason"], "required_real_model_profile_missing")
        self.assertEqual(report["counts"]["scenario_executions"], 0)
        self.assertFalse(any("--exact" in call for call in self.calls))

    def test_real_model_profile_mutation_cannot_keep_a_passing_result(self):
        self.model_requirement()
        model = self.root / "model-profile.json"
        model.write_text("original synthetic profile")
        def changed(argv, **kwargs):
            result = self.fake(argv, **kwargs)
            if "--exact" in argv:
                model.write_text("changed synthetic profile")
            return result
        with patch.object(suite.shutil, "which", return_value="/fixture/tool"):
            report = suite.run_suite(self.manifest, self.root, "model", self.target,
                                     executor=changed, snapshot=lambda _: self.snapshot_value, model_profile=model)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["tests"][0]["reason"], "model_profile_changed")
        self.assertEqual(report["counts"]["unique_tests_passed"], 0)

    def packaged_fixture(self):
        self.manifest["requirements"] = [r for r in self.manifest["requirements"] if r["profile"] != "packaged"]
        for system in ("linux", "darwin"):
            self.manifest["requirements"].append({"id": "packaged-" + system, "profile": "packaged", "status": "implemented",
                "tests": [], "runner": "installed-artifacts", "platforms": [system], "description": "Installed native fixture"})
        self.snapshot_value["release_tree_sha256"] = "c" * 64
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.3.0"\n')
        self.archive = self.root / "candidate.tar.gz"
        self.archive.write_bytes(b"synthetic runner archive; not a real installed binary")
        self.packaged_target = "aarch64-apple-darwin" if sys.platform == "darwin" else "x86_64-unknown-linux-gnu"
        platform_check = "installed_macos_relocated_signed_app_runtime" if sys.platform == "darwin" else "installed_linux_distinct_uid_and_spoofed_home_denial"
        self.packaged_result = {"schema": "opaque.packaged-acceptance.v1", "status": "passed", "version": "0.3.0",
            "target": self.packaged_target, "source_revision": self.snapshot_value["revision"],
            "source_tree_sha256": self.snapshot_value["release_tree_sha256"], "archive_sha256": suite.digest(self.archive.read_bytes()),
            "candidate_qualification": "build_candidate", "transport": "controlled_local_archive_via_real_installer",
            "published_signature_verified": False, "native_human_approval": False, "service_registration": False,
            "cases": [*suite.PACKAGED_CHECKS, platform_check], "native_capability": "capability_unavailable_fail_closed"}

    def packaged_fake(self, argv, **kwargs):
        if argv[0] == "rustc":
            self.calls.append(argv)
            return suite.CommandResult(0, ("release: 1.95.0\nhost: " + self.packaged_target + "\ncommit-hash: " + "a"*40 + "\n").encode())
        if str(self.root / "tests/packaged/run.py") in argv:
            self.calls.append(argv)
            Path(argv[argv.index("--output") + 1]).write_text(json.dumps(self.packaged_result))
            return suite.CommandResult(0, b"synthetic runner output, not installed qualification")
        return self.fake(argv, **kwargs)

    def packaged_run(self, **kwargs):
        return suite.run_suite(self.manifest, self.root, "packaged", self.target,
                               executor=kwargs.pop("executor", self.packaged_fake),
                               snapshot=lambda _: self.snapshot_value, **kwargs)

    def test_packaged_native_runner_is_one_command_and_never_inflates_rust_counts(self):
        self.packaged_fixture()
        report = self.packaged_run(packaged_archive=self.archive)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"]["unique_tests_passed"], 0)
        self.assertEqual(report["counts"]["scenario_executions"], 0)
        self.assertEqual(report["counts"]["command_scenario_executions"], 1)
        self.assertEqual(report["counts"]["selected_requirements_passed"], 1)
        self.assertEqual(sum(r["status"] == "not_selected_platform" for r in report["requirements"]), 1)
        self.assertFalse(any(call[0] == "cargo" for call in self.calls))
        output = self.root / "packaged-reports"
        suite.write_reports(report, output)
        xml = ET.fromstring((output / "junit.xml").read_bytes())
        self.assertEqual(xml.attrib["tests"], "1")
        self.assertEqual(xml.attrib["failures"], "0")

    def test_packaged_missing_explicit_archive_cannot_use_ambient_input(self):
        self.packaged_fixture()
        with patch.dict(os.environ, {"OPAQUE_PACKAGED_ARCHIVE": str(self.archive)}):
            report = self.packaged_run()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["commands"][0]["reason"], "required_packaged_archive_missing")
        self.assertEqual(report["counts"]["command_scenario_executions"], 0)

    def test_packaged_registration_rejects_unknown_runners_and_vacuous_other_requirements(self):
        self.packaged_fixture()
        suite.validate_manifest(self.manifest)
        for mutation in ({"runner": "arbitrary-command"}, {"runner": None}, {"platforms": []},
                         {"platforms": ["darwin", "linux"]}, {"profile": "protocol"}, {"tests": ["first"]}):
            changed = copy.deepcopy(self.manifest)
            changed["requirements"][-1].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(suite.Invalid):
                suite.validate_manifest(changed)
        changed = copy.deepcopy(self.manifest)
        del changed["requirements"][-1]["runner"]
        with self.assertRaisesRegex(suite.Invalid, "vacuous_requirement"):
            suite.validate_manifest(changed)

    def test_packaged_reports_reject_missing_checks_identity_mutations_and_external_claims(self):
        self.packaged_fixture()
        for mutation in ({"cases": []}, {"cases": self.packaged_result["cases"][:-1]},
                         {"cases": self.packaged_result["cases"] + [self.packaged_result["cases"][0]]},
                         {"source_revision": "b" * 40}, {"source_tree_sha256": "d" * 64},
                         {"target": "foreign-target"}, {"archive_sha256": "e" * 64},
                         {"native_human_approval": True}, {"native_human_approval": 0},
                         {"private_credential": "PRIVATE_CREDENTIAL_SENTINEL"}):
            with self.subTest(mutation=mutation), self.assertRaises(suite.Invalid):
                suite.packaged_report(self.packaged_result | mutation, source=self.snapshot_value,
                                      target=self.packaged_target, version="0.3.0", archive_sha256=suite.digest(self.archive.read_bytes()))

    def test_changed_packaged_archive_cannot_keep_a_passing_result(self):
        self.packaged_fixture()
        def changed(argv, **kwargs):
            result = self.packaged_fake(argv, **kwargs)
            if "--archive" in argv:
                self.archive.write_bytes(b"replaced archive")
            return result
        report = self.packaged_run(packaged_archive=self.archive, executor=changed)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["commands"][0]["reason"], "packaged_archive_changed")
        self.assertEqual(report["counts"]["command_scenarios_passed"], 0)

    def test_missing_native_requirement_cannot_green_skip_an_entire_profile(self):
        self.packaged_fixture()
        self.manifest["requirements"] = [r for r in self.manifest["requirements"] if r.get("platforms") != [sys.platform]]
        report = self.packaged_run()
        self.assertEqual(report["status"], "failed")
        self.assertIn("no_requirements_for_platform", report["gates"])

    def test_packaged_local_candidate_requires_explicit_dirty_allowance(self):
        self.packaged_fixture()
        self.packaged_result["candidate_qualification"] = "local_candidate"
        report = self.packaged_run(packaged_archive=self.archive)
        self.assertEqual(report["commands"][0]["reason"], "packaged_dirty_candidate_not_allowed")
        self.assertEqual(self.packaged_run(packaged_archive=self.archive, packaged_allow_dirty=True)["status"], "passed")

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

    def test_source_snapshot_archive_digest_includes_exact_files_links_and_missing_entries(self):
        (self.root / "source.rs").write_bytes(b"exact source bytes")
        (self.root / "alias").symlink_to("source.rs")
        def fake_git(argv, **kwargs):
            if "rev-parse" in argv:
                return suite.CommandResult(0, b"a" * 40 + b"\n")
            if "ls-files" in argv:
                return suite.CommandResult(0, b"source.rs\0missing\0alias\0")
            return suite.CommandResult(0, b"?? source.rs\0")
        snapshot = suite.source_snapshot(self.root, executor=fake_git)
        expected = suite.hashlib.sha256()
        expected.update(b"alias\0symlink\0source.rs")
        expected.update(b"missing\0absent\0")
        expected.update(b"source.rs\0file\0" + suite.hashlib.sha256(b"exact source bytes").digest())
        self.assertEqual(snapshot["release_tree_sha256"], expected.hexdigest())

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
