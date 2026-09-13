"""Collection contracts: dropped child counters and incomplete scope must fail."""
import copy
import json
import os
import signal
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import collect_critical_coverage as collector
import synthesized_suite as suite


class CollectionContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.target = self.root / "target"
        self.target.mkdir()
        self.binary = self.target / "test-binary"
        self.binary.write_bytes(b"fixture mapping object")

    def event(self, **changes):
        event = {"reason": "compiler-artifact", "profile": {"test": True},
                 "target": {"kind": ["test"], "name": "fixture"},
                 "executable": str(self.binary)}
        event.update(changes)
        return json.dumps(event).encode()

    def profile(self, role, body=b"nonempty fixture profile"):
        path = self.root / f"{role}-100-500-.profraw"
        path.write_bytes(body)
        return path

    def test_linux_requires_existing_split_uid_tests_and_macos_reports_its_own_scope(self):
        linux = collector.selected_cases("linux")
        macos = collector.selected_cases("darwin")
        self.assertEqual(set(linux) - set(macos), {"synthesized_review_e2e"})
        self.assertEqual(len(linux["synthesized_review_e2e"]), 4)
        self.assertEqual(sum(map(len, linux.values())), 25)
        self.assertEqual(sum(map(len, macos.values())), 21)
        for cases in (linux, macos):
            self.assertTrue(any("requester_reviewer_and_device_revocation" in name
                                for name in cases["opaqued"]))
        with self.assertRaisesRegex(suite.Invalid, "unsupported_native_platform"):
            collector.selected_cases("win32")

    def test_contained_selection_adds_declared_ssh_and_inference_cases_without_dropping_existing_jobs(self):
        baseline = collector.selected_cases("linux")
        contained = collector.selected_cases("linux", True)
        self.assertEqual({key: contained[key] for key in baseline}, baseline)
        self.assertEqual(contained[collector.CONTAINED_TARGET], collector.CONTAINED_CASES)
        self.assertEqual(sum(map(len, contained.values())), 28)
        self.assertEqual(collector.role_requirements(collector.CONTAINED_TARGET, collector.CONTAINED_CASES[0]),
                         {"test", "daemon", "peer"})
        with self.assertRaisesRegex(suite.Invalid, "contained_profile_requires_linux"):
            collector.selected_cases("darwin", True)

    def test_contained_collection_refuses_unmarked_host_wrong_account_and_missing_tools(self):
        marker = self.root / "marker"
        pid1 = self.root / "pid1"
        marker.write_text("opaque-contained-ssh-v1\n")
        pid1.write_text("systemd\n")
        with patch.object(collector.os, "geteuid", return_value=0), \
             patch.object(suite, "has_sys_ptrace", return_value=True), \
             patch.object(collector.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=7382)), \
             patch.object(collector.shutil, "which", return_value="/fixture/tool"):
            self.assertTrue(collector.contained_prerequisites("linux", marker=marker, pid1=pid1)["systemd_pid1"])
            marker.write_text("unmarked-host\n")
            with self.assertRaisesRegex(suite.Invalid, "marked_systemd_host"):
                collector.contained_prerequisites("linux", marker=marker, pid1=pid1)
            marker.write_text("opaque-contained-ssh-v1\n")
            with patch.object(collector.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=0)):
                with self.assertRaisesRegex(suite.Invalid, "requires_host_account"):
                    collector.contained_prerequisites("linux", marker=marker, pid1=pid1)
            with patch.object(collector.shutil, "which", return_value=None):
                with self.assertRaisesRegex(suite.Invalid, "missing_tool_vault"):
                    collector.contained_prerequisites("linux", marker=marker, pid1=pid1)

    def test_every_declared_exact_name_is_checked_before_any_baseline_execution(self):
        expected = {"opaqued": ("actual::test", "renamed::test")}
        with self.assertRaisesRegex(suite.Invalid, "required_named_test_not_found:opaqued:renamed::test"):
            collector.validate_case_inventory(expected, {"opaqued": {"actual::test"}})
        self.assertEqual(collector.validate_case_inventory(expected, {"opaqued": set(expected["opaqued"])})
                         ["opaqued"]["compiled_tests"], 2)
        run = collector.Collector(self.root, self.root, self.target, "cargo-llvm-cov")
        with patch.object(run, "execute") as execute:
            with self.assertRaisesRegex(suite.Invalid, "declared_inventory_not_validated"):
                run.collect()
            execute.assert_not_called()
        for bad in ({}, {"opaqued": ()}, {"opaqued": ("repeated", "repeated")}):
            with self.assertRaises(suite.Invalid):
                collector.validate_case_inventory(bad, {"opaqued": {"repeated"}})

    def test_platform_specific_continuous_mode_preserves_all_darwin_sections(self):
        linux = collector.instrumentation_flags("linux", 4096)
        self.assertIn("-Cllvm-args=-runtime-counter-relocation", linux)
        for size, alignment in ((4096, "1000"), (16384, "4000")):
            macos = collector.instrumentation_flags("darwin", size)
            for section in ("cnts", "data", "bits"):
                self.assertIn(f"-Clink-arg=-Wl,-sectalign,__DATA,__llvm_prf_{section},{alignment}", macos)
            self.assertFalse(any("runtime-counter-relocation" in flag for flag in macos))
        with self.assertRaisesRegex(suite.Invalid, "invalid_native_page_size"):
            collector.instrumentation_flags("darwin", 1234)

    def test_show_env_is_parsed_without_shell_evaluation_and_missing_flags_fail(self):
        flags = collector.instrumentation_flags("linux", 4096)
        encoded = "\x1f".join(collector.BASE_FLAGS)
        raw = ("__CARGO_LLVM_COV_RUSTC_WRAPPER=1\nCARGO_LLVM_COV=1\n"
               "RUSTC_WRAPPER='/fixture/path with spaces/cargo-llvm-cov'\n"
               f"__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS='{encoded}'\n").encode()
        result = collector.parse_environment(raw, flags)
        self.assertEqual(result["RUSTC_WRAPPER"], "/fixture/path with spaces/cargo-llvm-cov")
        self.assertEqual(result["__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS"].split("\x1f"), flags)
        for invalid in (raw + b"RUSTC_WRAPPER=duplicate\n", raw.replace(b"instrument-coverage", b"opt-level=3"),
                        raw + b"exit 0\n"):
            with self.assertRaises(suite.Invalid):
                collector.parse_environment(invalid, flags)

    def test_compiler_inventory_rejects_missing_ambiguous_and_foreign_objects(self):
        selected = collector.artifacts(self.event(), self.target)
        self.assertEqual(selected, {("fixture", "test", True): self.binary})
        foreign = self.root / "ordinary-uninstrumented-daemon"
        foreign.write_bytes(b"wrong directory")
        for event in (b"{}", self.event(executable=str(foreign)),
                      self.event(target={"kind": ["test", "bin"], "name": "fixture"})):
            with self.assertRaises(suite.Invalid):
                collector.artifacts(event, self.target)
        other = self.target / "second"
        other.write_bytes(b"different object")
        with self.assertRaisesRegex(suite.Invalid, "duplicate_compiler_target"):
            collector.artifacts(self.event() + b"\n" + self.event(executable=str(other)), self.target)

    def test_runtime_package_names_follow_exact_artifact_manifests_and_never_parent_environment(self):
        manifests = []
        for package in ("opaque-core", "opaqued"):
            directory = self.root / package
            directory.mkdir()
            manifest = directory / "Cargo.toml"
            manifest.write_text(f'[package]\nname = "{package}"\n')
            manifests.append(manifest)
        raw = self.event(manifest_path=str(manifests[0]))
        with patch.dict(os.environ, {"CARGO_PKG_NAME": "unrelated-parent-package"}):
            self.assertEqual(collector.artifact_packages(raw, {self.binary}, self.root),
                             {self.binary: "opaque-core"})
        for invalid in (self.event(), raw + b"\n" + self.event(manifest_path=str(manifests[1]))):
            with self.assertRaises(suite.Invalid):
                collector.artifact_packages(invalid, {self.binary}, self.root)

    def test_symlink_cannot_substitute_for_instrumented_object(self):
        link = self.target / "symlink"
        link.symlink_to(self.binary)
        with self.assertRaisesRegex(suite.Invalid, "invalid_compiler_artifact"):
            collector.artifacts(self.event(executable=str(link)), self.target)

    def test_test_process_profile_alone_never_qualifies_daemon_collection(self):
        self.profile("test")
        for target in ("task_api_e2e", "resource_authority_e2e", "mcp_gateway_e2e", "synthesized_review_e2e"):
            with self.assertRaisesRegex(suite.Invalid, "missing_required_child_profiles"):
                collector.profile_inventory(self.root, target)

    def test_actual_adapter_scenarios_require_adapter_profiles_but_direct_rpc_does_not(self):
        self.profile("test")
        self.profile("daemon")
        cases = collector.CASES["mcp_gateway_e2e"]
        for name in (cases[0], cases[5]):
            with self.assertRaisesRegex(suite.Invalid, "missing_required_child_profiles"):
                collector.profile_inventory(self.root, "mcp_gateway_e2e", name)
        profiles, _ = collector.profile_inventory(self.root, "mcp_gateway_e2e", cases[3])
        self.assertEqual({item["role"] for item in profiles}, {"test", "daemon"})
        self.profile("adapter")
        self.assertEqual(len(collector.profile_inventory(self.root, "mcp_gateway_e2e", cases[0])[0]), 3)

    def test_split_uid_caller_profiles_require_retained_mapping_objects(self):
        for role in ("test", "daemon", "peer"):
            self.profile(role)
        with self.assertRaisesRegex(suite.Invalid, "missing_instrumented_peer_object"):
            collector.profile_inventory(self.root, "synthesized_review_e2e")
        peer = self.root / "peer-binary-fixture"
        peer.write_bytes(b"retained caller mapping")
        profiles, objects = collector.profile_inventory(self.root, "synthesized_review_e2e")
        self.assertEqual(objects, [peer])
        self.assertEqual(len(profiles), 3)
        self.assertTrue(all(len(item["sha256"]) == 64 for item in profiles))

    def test_empty_unknown_and_symlink_profiles_fail_before_merge(self):
        for role, contents, reason in (("test", b"", "empty_or_invalid_execution_profile"),
                                      ("unexpected", b"data", "unknown_execution_profile_role")):
            path = self.profile(role, contents)
            with self.assertRaisesRegex(suite.Invalid, reason):
                collector.profile_inventory(self.root, "opaque_core")
            path.unlink()
        link = self.root / "test-1-2-.profraw"
        link.symlink_to(self.binary)
        with self.assertRaisesRegex(suite.Invalid, "empty_or_invalid_execution_profile"):
            collector.profile_inventory(self.root, "opaque_core")

    def test_suite_results_reject_zero_duplicate_missing_or_new_ignored_tests(self):
        valid = b"test fixture ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
        self.assertEqual(collector.suite_pass(valid, {"fixture"}), {"passed": 1, "ignored": []})
        for raw, names in ((b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;", set()),
                           (valid, {"fixture", "absent"}),
                           (b"test fixture ... ok\n" + valid, {"fixture"}),
                           (valid.replace(b"... ok", b"... ignored").replace(b"1 passed", b"0 passed").replace(b"0 ignored", b"1 ignored"), {"fixture"})):
            with self.assertRaises(suite.Invalid):
                collector.suite_pass(raw, names)

    def test_existing_ignored_live_and_benchmark_are_reported_exactly(self):
        names = {"passing", *collector.ALLOWED_IGNORED}
        raw = "test passing ... ok\n" + "".join(f"test {name} ... ignored, explicit prerequisite\n"
                                                for name in sorted(collector.ALLOWED_IGNORED))
        raw += "test result: ok. 1 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out;\n"
        self.assertEqual(collector.suite_pass(raw.encode(), names),
                         {"passed": 1, "ignored": sorted(collector.ALLOWED_IGNORED)})

    def test_report_scope_cannot_grow_to_other_packages_or_drop_required_handlers(self):
        sources = [{"path": name} for name in collector.REQUIRED_FILES]
        files = [{"filename": str(self.root / name)} for name in collector.REQUIRED_FILES]
        report = {"data": [{"files": files}]}
        self.assertEqual(collector.validate_report_scope(report, sources, self.root), [])
        invalid = copy.deepcopy(report)
        invalid["data"][0]["files"].append({"filename": str(self.root / "crates/opaqued/src/main.rs")})
        with self.assertRaisesRegex(suite.Invalid, "undeclared_or_duplicate_report_source"):
            collector.validate_report_scope(invalid, sources, self.root)
        report["data"][0]["files"].pop()
        with self.assertRaisesRegex(suite.Invalid, "required_source_missing_from_collection"):
            collector.validate_report_scope(report, sources, self.root)

    def test_fresh_output_refuses_stale_or_existing_directory(self):
        with self.assertRaises(FileExistsError):
            collector.fresh_directory(self.root)
        fresh = collector.fresh_directory(self.root / "fresh", 0o1777)
        self.assertEqual(fresh.stat().st_mode & 0o7777, 0o1777)

    def test_interrupted_collection_records_failure_and_never_leaves_collecting_status(self):
        source = self.root / "checkout"
        source.mkdir()
        output = self.root / "aborted"
        with patch.object(collector.Collector, "setup", side_effect=KeyboardInterrupt):
            status = collector.main(["--source-root", str(source), "--output", str(output),
                                     "--target-dir", str(self.root / "new-target")])
        report = json.loads((output / "collection.json").read_text())
        self.assertEqual(status, 130)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failures"], ["interrupted"])

    def test_sigterm_uses_failure_cleanup_path_and_restores_the_callers_handler(self):
        source = self.root / "checkout"
        source.mkdir()
        output = self.root / "terminated"
        original = signal.getsignal(signal.SIGTERM)
        def terminate():
            os.kill(os.getpid(), signal.SIGTERM)
        with patch.object(collector.Collector, "setup", side_effect=terminate):
            status = collector.main(["--source-root", str(source), "--output", str(output),
                                     "--target-dir", str(self.root / "new-target")])
        self.assertEqual(status, 130)
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)
        self.assertEqual(json.loads((output / "collection.json").read_text())["status"], "failed")

    def test_real_command_failure_and_timeout_never_pass_collection(self):
        run = collector.Collector(self.root, self.root, self.target, "cargo-llvm-cov")
        with self.assertRaisesRegex(suite.Invalid, "command_failed_fixture"):
            run.command("fixture", [sys.executable, "-c", "raise SystemExit(17)"], timeout=2)
        with self.assertRaisesRegex(suite.Invalid, "command_timeout|process_group_cleanup_denied"):
            run.command("deadline", [sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.1)
        for path in self.root.glob("command-*.log"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
