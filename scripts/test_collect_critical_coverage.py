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

    def workspace(self, extra=()):
        names = sorted({path.split("/")[1] for path in collector.REQUIRED_FILES})
        packages = []
        for name, kind in [*((name, "lib") for name in names), *extra]:
            directory = self.root / ("components" if name.startswith("new-") else "crates") / name
            directory.mkdir(parents=True, exist_ok=True)
            manifest = directory / "Cargo.toml"
            manifest.write_text(f'[package]\nname = "{name}"\n')
            source = directory / "src" / ("main.rs" if kind == "bin" else "lib.rs")
            source.parent.mkdir(exist_ok=True)
            source.write_text("fn production() {}\n")
            packages.append({"id": "workspace:" + name, "name": name, "manifest_path": str(manifest),
                             "features": {"acceptance": []}, "targets": [{"name": name.replace("-", "_") if kind == "lib" else name,
                             "kind": [kind], "src_path": str(source), "test": True, "required-features": ["acceptance"]}]})
        for name in collector.REQUIRED_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fn production_guard() {}\n")
        metadata = {"workspace_root": str(self.root), "workspace_members": [p["id"] for p in packages],
                    "workspace_default_members": [packages[0]["id"]], "packages": packages}
        return metadata, collector.workspace_inventory(metadata, self.root)

    def workspace_run(self, workspace):
        run = collector.Collector(self.root, self.root, self.target, "cargo-llvm-cov")
        run.workspace = workspace
        run.result["coverage_packages"] = [p["name"] for p in workspace]
        run.result["source_inventory"] = collector.source_inventory(self.root, workspace)
        return run

    def test_linux_requires_existing_split_uid_tests_and_macos_reports_its_own_scope(self):
        linux = collector.selected_cases("linux")
        macos = collector.selected_cases("darwin")
        self.assertEqual(set(linux) - set(macos), {"synthesized_review_e2e"})
        self.assertEqual(len(linux["synthesized_review_e2e"]), 4)
        self.assertEqual(sum(map(len, linux.values())), 28)
        self.assertEqual(sum(map(len, macos.values())), 23)
        for cases in (linux, macos):
            self.assertIn("ssh_planning_without_tenant_is_denied_before_provider_io",
                          cases["task_api_e2e"])
            self.assertTrue(any("requester_reviewer_and_device_revocation" in name
                                for name in cases["opaqued"]))
        with self.assertRaisesRegex(suite.Invalid, "unsupported_native_platform"):
            collector.selected_cases("win32")

    def test_contained_selection_adds_declared_ssh_and_inference_cases_without_dropping_existing_jobs(self):
        baseline = collector.selected_cases("linux")
        contained = collector.selected_cases("linux", True)
        self.assertEqual({key: contained[key] for key in baseline}, baseline)
        self.assertEqual(contained[collector.CONTAINED_TARGET], collector.CONTAINED_CASES)
        self.assertEqual(sum(map(len, contained.values())), 36)
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

    def test_debug_symbol_settings_preserve_coverage_flags_for_cargo_and_bare_peers(self):
        with patch.dict(os.environ, {"CARGO_PROFILE_DEV_DEBUG": "2", "CARGO_PROFILE_TEST_DEBUG": "2"}):
            run = collector.Collector(self.root, self.root, self.target, "cargo-llvm-cov")
        self.assertEqual(run.env["CARGO_PROFILE_DEV_DEBUG"], "0")
        self.assertEqual(run.env["CARGO_PROFILE_TEST_DEBUG"], "0")
        settings = run.result["debug_symbol_settings"]
        self.assertEqual(settings["cargo_profile_environment"],
                         {"CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0"})
        self.assertEqual(settings["rustc_flag"], "-Cdebuginfo=0")
        for platform in ("linux", "darwin"):
            flags = collector.instrumentation_flags(platform, 4096)
            self.assertEqual(flags[:len(collector.BASE_FLAGS)], list(collector.BASE_FLAGS))
            self.assertIn("-Zcoverage-options=branch", flags)
            self.assertIn("-Cdebuginfo=0", flags)
            self.assertFalse(any("strip" in flag or "opt-level" in flag for flag in flags))
            raw = ("__CARGO_LLVM_COV_RUSTC_WRAPPER=1\nCARGO_LLVM_COV=1\n"
                   "RUSTC_WRAPPER=/fixture/cargo-llvm-cov\n"
                   "__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS='"
                   + "\x1f".join(collector.BASE_FLAGS) + "'\n").encode()
            parsed = collector.parse_environment(raw, flags)
            self.assertEqual(parsed["__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS"].split("\x1f"), flags)

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
        for target in ("task_api_e2e", "resource_authority_e2e", "mcp_gateway_e2e"):
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
        case = collector.CASES["synthesized_review_e2e"][0]
        for role in ("test", "daemon", "peer"):
            self.profile(role)
        with self.assertRaisesRegex(suite.Invalid, "missing_instrumented_peer_object"):
            collector.profile_inventory(self.root, "synthesized_review_e2e", case)
        peer = self.root / "peer-binary-fixture"
        peer.write_bytes(b"retained caller mapping")
        profiles, objects = collector.profile_inventory(self.root, "synthesized_review_e2e", case)
        self.assertEqual(objects, [peer])
        self.assertEqual(len(profiles), 3)
        self.assertTrue(all(len(item["sha256"]) == 64 for item in profiles))

    def test_ordinary_oidc_baselines_do_not_claim_ignored_daemon_peer_ceremonies(self):
        self.profile("test")
        targets = {"synthesized_review_e2e": collector.CASES["synthesized_review_e2e"],
                   collector.CONTAINED_TARGET: (*collector.CONTAINED_CASES,
                       "contained_real_model_completions_require_signed_review_and_survive_restart")}
        for target, cases in targets.items():
            profiles, objects = collector.profile_inventory(self.root, target)
            self.assertEqual({entry["role"] for entry in profiles}, {"test"})
            self.assertEqual(objects, [])
            for case in cases:
                with self.subTest(target=target, case=case), self.assertRaisesRegex(suite.Invalid, "missing_required_child_profiles"):
                    collector.profile_inventory(self.root, target, case)
        self.profile("daemon")
        self.profile("peer")
        for target, cases in targets.items():
            with self.assertRaisesRegex(suite.Invalid, "missing_instrumented_peer_object"):
                collector.profile_inventory(self.root, target, cases[0])
        (self.root / "peer-binary-fixture").write_bytes(b"retained caller mapping")
        for target, cases in targets.items():
            for case in cases:
                profiles, objects = collector.profile_inventory(self.root, target, case)
                self.assertEqual({entry["role"] for entry in profiles}, {"test", "daemon", "peer"})
                self.assertEqual(len(objects), 1)

    def test_workspace_rpc_requires_actual_peer_profile_and_mapping_on_each_platform(self):
        name = "task_rpc_rechecks_changed_workspace_after_source_read_without_publishing"
        for native_platform in ("linux", "darwin"):
            self.assertIn(name, collector.selected_cases(native_platform)["task_api_e2e"])
        self.profile("test")
        self.profile("daemon")
        peer = self.root / "peer-binary-fixture"
        peer.write_bytes(b"retained caller mapping")
        with self.assertRaisesRegex(suite.Invalid, "missing_required_child_profiles"):
            collector.profile_inventory(self.root, "task_api_e2e", name)
        self.profile("peer")
        peer.unlink()
        with self.assertRaisesRegex(suite.Invalid, "missing_instrumented_peer_object"):
            collector.profile_inventory(self.root, "task_api_e2e", name)
        peer.symlink_to(self.binary)
        with self.assertRaisesRegex(suite.Invalid, "invalid_instrumented_peer_object"):
            collector.profile_inventory(self.root, "task_api_e2e", name)
        peer.unlink()
        peer.write_bytes(b"")
        with self.assertRaisesRegex(suite.Invalid, "invalid_instrumented_peer_object"):
            collector.profile_inventory(self.root, "task_api_e2e", name)
        peer.write_bytes(b"retained caller mapping")
        profiles, objects = collector.profile_inventory(self.root, "task_api_e2e", name)
        self.assertEqual({entry["role"] for entry in profiles}, {"test", "daemon", "peer"})
        self.assertEqual(objects, [peer])

    def test_metadata_discovers_every_member_and_nonstandard_bin_only_package(self):
        metadata, workspace = self.workspace((("new-cli", "bin"), ("new-library", "lib")))
        inventory = collector.source_inventory(self.root, workspace)
        self.assertEqual({item["package"] for item in inventory}, {p["name"] for p in metadata["packages"]})
        self.assertGreater(len(workspace), len(metadata["workspace_default_members"]))
        self.assertIn("components/new-cli/src/main.rs", {item["path"] for item in inventory})
        self.assertTrue(all(len(item["sha256"]) == 64 for item in inventory))
        missing = copy.deepcopy(metadata)
        missing["packages"].pop()
        with self.assertRaisesRegex(suite.Invalid, "missing_or_duplicate_workspace_package"):
            collector.workspace_inventory(missing, self.root)
        unknown_feature = copy.deepcopy(metadata)
        unknown_feature["packages"][0]["targets"][0]["required-features"] = ["not-declared"]
        with self.assertRaisesRegex(suite.Invalid, "undeclared_required_target_features"):
            collector.workspace_inventory(unknown_feature, self.root)
        for package in workspace:
            source = self.root / package["targets"][0]["source"]
            directory = source.parent
            directory.rename(directory.with_name("missing-src"))
            try:
                with self.assertRaisesRegex(suite.Invalid, "empty_declared_source_package|workspace_runtime_entrypoint_missing_from_scope"):
                    collector.source_inventory(self.root, workspace)
            finally:
                directory.with_name("missing-src").rename(directory)

    def test_workspace_build_requires_all_libraries_bins_and_exact_package_identities(self):
        metadata, workspace = self.workspace((("new-cli", "bin"),))
        events = {}
        for package in metadata["packages"]:
            target = package["targets"][0]
            binary = self.target / (package["name"] + "-test")
            binary.write_bytes(b"compiled mapping fixture")
            events[package["name"]] = self.event(executable=str(binary), package_id=package["id"],
                manifest_path=package["manifest_path"], target={"name": target["name"], "kind": target["kind"]})
        normal_event = json.loads(events["new-cli"])
        normal_event["profile"]["test"] = False
        normal = json.dumps(normal_event).encode()
        for package in metadata["packages"]:
            run = self.workspace_run(workspace)
            raw = b"\n".join(event for name, event in events.items() if name != package["name"])
            with self.subTest(missing=package["name"]), patch.object(run, "command", side_effect=[normal, raw]) as command:
                with self.assertRaisesRegex(suite.Invalid, "missing_workspace_test_artifacts"):
                    run.build()
                for call in command.call_args_list:
                    self.assertIn("--workspace", call.args[1])
                    self.assertIn("--all-features", call.args[1])
                    self.assertNotIn("-p", call.args[1])
        wrong = json.loads(events["new-cli"])
        wrong["manifest_path"] = metadata["packages"][0]["manifest_path"]
        with self.assertRaisesRegex(suite.Invalid, "artifact_workspace_package_mismatch"):
            collector.artifact_packages(json.dumps(wrong).encode(), {Path(wrong["executable"])}, self.root, workspace)
        run = self.workspace_run(workspace)
        with patch.object(run, "command", side_effect=[normal, b"\n".join(events.values())]):
            run.build()
        self.assertEqual(set(run.baseline), collector.expected_artifacts(workspace, tests=True))
        with self.assertRaisesRegex(suite.Invalid, "missing_workspace_binary_artifacts"):
            collector.validate_workspace_artifacts(workspace, {}, tests=False)

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

    def test_target_names_are_qualified_by_workspace_package_before_collision_checks(self):
        other = self.target / "other-package-test"
        other.write_bytes(b"second mapping fixture")
        first = self.event(package_id="workspace:first")
        second = self.event(package_id="workspace:second", executable=str(other))
        selected = collector.artifacts(first + b"\n" + second, self.target, qualified=True)
        self.assertEqual(set(selected), {("workspace:first", "fixture", "test", True),
                                         ("workspace:second", "fixture", "test", True)})
        with self.assertRaisesRegex(suite.Invalid, "missing_compiler_package_id"):
            collector.artifacts(self.event(), self.target, qualified=True)

    def test_new_ignored_tests_require_reviewed_package_target_and_prerequisite(self):
        accepted = collector.reviewed_ignored_tests("opaqued", "opaqued", {collector.DAEMON_ROOT_CASE})
        self.assertIn("irreversible", accepted[collector.DAEMON_ROOT_CASE])
        for package, target, names in (("opaqued", "opaqued", {"silently_disabled_guard"}),
                                       ("other-package", "opaqued", {collector.DAEMON_ROOT_CASE}),
                                       ("opaqued", "other-target", {collector.DAEMON_ROOT_CASE})):
            with self.assertRaisesRegex(suite.Invalid, "unreviewed_ignored_workspace_tests"):
                collector.reviewed_ignored_tests(package, target, names)
        live = collector.reviewed_ignored_tests("opaque-providers", "opaque_providers", {"onepassword::op_cli::tests::live_read_field"})
        self.assertIn("separate explicit opt-in", next(iter(live.values())))

    def test_zero_test_target_preserves_mapping_inventory_without_a_vacuous_pass(self):
        zero = collector.ZERO_COUNTER_DIAGNOSTIC + b"\n0 tests, 0 benchmarks\n"
        self.assertEqual(collector.test_inventory(zero), set())
        with self.assertRaises(suite.Invalid):
            suite.inventory(zero)
        summary = collector.ZERO_COUNTER_DIAGNOSTIC + b"\nrunning 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
        with self.assertRaisesRegex(suite.Invalid, "vacuous_or_incomplete_suite_result"):
            collector.suite_pass(summary, set())
        run = collector.Collector(self.root, self.root, self.target, "cargo-llvm-cov")
        (self.root / "profiles").mkdir()
        run.package_by_binary[self.binary] = "opaque-approver"
        run.test_inventories[self.binary] = (set(), set())
        run.objects = {self.binary}
        with patch.object(run, "command", side_effect=[zero, summary]):
            run.execute("opaque-approver", self.binary)
        entry = run.result["executions"][0]
        self.assertEqual(entry["passed"], 0)
        self.assertEqual(entry["qualification"], "no_tests_executed")
        self.assertEqual(entry["counter_diagnostics"], ["no_continuous_counters_in_zero_test_harness"])
        self.assertEqual(entry["profiles"], [])
        self.assertIn(self.binary, run.objects)

    def test_only_exact_zero_counter_diagnostic_is_allowed_with_observed_zero_tests(self):
        self.assertEqual(collector.test_inventory(b"\n0 tests, 0 benchmarks\n"), set())
        diagnostic = collector.ZERO_COUNTER_DIAGNOSTIC + b"\n"
        for raw in (diagnostic + b"fixture: test\n1 test, 0 benchmarks\n",
                    b"LLVM Profile Error: failed to write counters\n0 tests, 0 benchmarks\n",
                    diagnostic * 2 + b"0 tests, 0 benchmarks\n",
                    diagnostic + b"unexpected output\n0 tests, 0 benchmarks\n"):
            with self.subTest(raw=raw), self.assertRaisesRegex(suite.Invalid, "unexpected_llvm_profile_error"):
                collector.test_inventory(raw)
        with self.assertRaisesRegex(suite.Invalid, "unexpected_llvm_profile_error"):
            collector.counter_diagnostics(diagnostic, zero_tests=False)
        with self.assertRaisesRegex(suite.Invalid, "unexpected_llvm_profile_error"):
            collector.counter_diagnostics(b"LLVM Profile Error: failed to write counters\n", zero_tests=True)

    def test_named_collection_captures_diagnostics_and_preserves_exact_result_guards(self):
        name = "split_daemon_custody_and_signature_bound_approver"
        listing = f"{name}: test\n\n1 test, 0 benchmarks\n".encode()
        result = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
        captured = f"test {name} ... ok\n".encode() + result
        interleaved = f"test {name} ... audit tail:\nfixture diagnostic\nok\n".encode() + result
        with self.assertRaisesRegex(suite.Invalid, "missing_or_nonpassing_named_result"):
            suite.named_pass(interleaved, name)
        run = collector.Collector(self.root, self.root, self.target, "cargo-llvm-cov")
        (self.root / "profiles").mkdir()
        run.package_by_binary[self.binary] = "opaqued"
        run.test_inventories[self.binary] = ({name}, {name})
        run.objects = {self.binary}
        def command(label, argv, env, timeout):
            if "--list" in argv:
                return listing
            self.assertIn("--exact", argv)
            self.assertIn(name, argv)
            self.assertIn("--include-ignored", argv)
            self.assertNotIn("--nocapture", argv)
            profiles = Path(env["OPAQUE_COVERAGE_PROFILE_DIR"])
            for role, pid in (("test", 100), ("daemon", 200)):
                (profiles / f"{role}-{pid}-500-.profraw").write_bytes(b"fixture profile")
            run.last_command_pid = 100
            return captured
        with patch.object(run, "command", side_effect=command):
            run.execute("trust_domain_e2e", self.binary, name)
        entry = run.result["executions"][0]
        self.assertEqual(entry["passed_test_names"], [name])
        self.assertEqual(entry["passed"], 1)
        self.assertEqual(entry["additional_profile_process_ids"], [200])

    def test_ignored_only_target_reports_reason_without_child_profile_or_ignored_execution(self):
        name = collector.CONTAINED_CASES[0]
        listing = f"{name}: test\n\n1 test, 0 benchmarks\n".encode()
        summary = (f"test {name} ... ignored, requires marked systemd fixture\n"
                   "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;\n").encode()
        run = collector.Collector(self.root, self.root, self.target, "cargo-llvm-cov")
        (self.root / "profiles").mkdir()
        run.package_by_binary[self.binary] = "opaqued"
        run.test_inventories[self.binary] = ({name}, {name})
        run.objects = {self.binary}
        run.result["skipped_tests"] = [{"package": "opaqued", "target": collector.CONTAINED_TARGET,
                                        "test": name, "executed_by_explicit_profile": False}]
        with patch.object(run, "command", side_effect=[listing, summary]) as command:
            run.execute(collector.CONTAINED_TARGET, self.binary)
        self.assertFalse(any("--include-ignored" in call.args[1] for call in command.call_args_list))
        self.assertEqual(run.result["executions"][0]["qualification"], "no_tests_executed")
        self.assertEqual(run.result["skipped_tests"][0]["reason"], "requires marked systemd fixture")
        self.assertFalse(run.result["skipped_tests"][0]["executed_by_explicit_profile"])

    def test_inherited_child_profiles_preserve_distinct_process_identity_without_forged_roles(self):
        self.profile("test")
        (self.root / "test-200-500-.profraw").write_bytes(b"inherited child profile")
        profiles, _ = collector.profile_inventory(self.root, "other-target")
        self.assertEqual({p["process_id"] for p in profiles}, {100, 200})
        self.assertEqual({p["role"] for p in profiles}, {"test"})
        with self.assertRaisesRegex(suite.Invalid, "missing_required_child_profiles"):
            collector.profile_inventory(self.root, "trust_domain_e2e")

    def test_unique_test_counts_never_include_repeated_invocations_or_other_package_aliases(self):
        baseline = {"package": "first-package", "target": "shared", "kind": "lib", "passed": 2,
                    "passed_test_names": ["first", "second"], "qualification": "passed"}
        repeated = {**baseline, "passed": 1, "passed_test_names": ["first"]}
        foreign = {**repeated, "package": "second-package"}
        binary = {**repeated, "kind": "bin"}
        zero = {**baseline, "passed": 0, "passed_test_names": [], "qualification": "no_tests_executed"}
        counts = collector.test_execution_counts([baseline, repeated, foreign, binary, zero],
            [{"compiled_tests": 5, "non_ignored_tests": 4}], [{"executed_by_explicit_profile": False}])
        self.assertEqual(counts["unique_passed_tests"], 4)
        self.assertEqual(counts["passed_test_invocations"], 5)
        self.assertEqual(counts["repeated_pass_invocations"], 1)
        self.assertEqual(counts["zero_test_process_invocations"], 1)
        self.assertEqual(counts["ignored_tests_not_executed"], 1)

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
        raw += f"test result: ok. 1 passed; 0 failed; {len(collector.ALLOWED_IGNORED)} ignored; 0 measured; 0 filtered out;\n"
        self.assertEqual(collector.suite_pass(raw.encode(), names),
                         {"passed": 1, "ignored": sorted(collector.ALLOWED_IGNORED)})

    def coverage_report(self, original_complete):
        self.coverage_workspace = self.workspace()[1]
        files = []
        for name in collector.REQUIRED_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("pub fn production_guard() {}\n")
            original = name in collector.ORIGINAL_REQUIRED_FILES
            count = 10 if original else 1000
            covered = count if original == original_complete else count - 1
            summary = {metric: {"count": count, "covered": covered}
                       for metric in ("lines", "branches")}
            files.append({"filename": str(path), "summary": summary})
        totals = {metric: {key: sum(item["summary"][metric][key] for item in files)
                          for key in ("count", "covered")}
                  for metric in ("lines", "branches")}
        return {"type": "llvm.coverage.json.export", "data": [{"files": files, "totals": totals}]}

    def test_original_scope_export_uses_its_own_counts_and_literal_gate(self):
        for complete in (True, False):
            with self.subTest(original_complete=complete):
                report = self.coverage_report(complete)
                unchanged = copy.deepcopy(report)
                raw = json.dumps(report).encode()
                run = self.workspace_run(self.coverage_workspace)
                run.result["target"] = "fixture-native-target"
                run.llvm_cov, run.llvm_profdata = "fixture-cov", "fixture-profdata"
                def command(label, argv, **options):
                    if label == "merge-critical":
                        Path(argv[-1]).write_bytes(b"merged fixture profile")
                        return b""
                    self.assertEqual(label, "export-critical")
                    options["export"].write_bytes(raw)
                    return raw
                with patch.object(run, "command", side_effect=command):
                    result = run.export("critical", {self.binary}, [{"path": "fixture.profraw"}])
                expanded = json.loads((self.root / "coverage-summary.json").read_text())
                original = json.loads((self.root / "original-scope-summary.json").read_text())
                self.assertEqual(result["coverage_gate"], "failed")
                self.assertEqual(expanded["coverage_packages"], [p["name"] for p in self.coverage_workspace])
                self.assertEqual(original["coverage_packages"], list(collector.ORIGINAL_PACKAGES))
                self.assertEqual(original["required_source_files"], sorted(collector.ORIGINAL_REQUIRED_FILES))
                self.assertEqual(original["status"], "passed" if complete else "failed")
                self.assertEqual(original["thresholds"], {"lines": 100.0, "branches": 100.0})
                self.assertEqual(original["input_sha256"], expanded["input_sha256"])
                self.assertEqual(original["target"], "fixture-native-target")
                for metric in ("lines", "branches"):
                    self.assertEqual(original["measured"][metric]["count"], 60)
                    self.assertEqual(original["measured"][metric]["covered"], 60 if complete else 54)
                    self.assertEqual(original["measured"][metric]["percent"], 100.0 if complete else 90.0)
                    self.assertEqual(expanded["measured"][metric]["count"], 3060)
                self.assertEqual(report, unchanged)

    def test_expanded_export_cannot_hide_invalid_totals_by_rebuilding_the_subset(self):
        report = self.coverage_report(True)
        report["data"][0]["totals"]["lines"]["covered"] -= 1
        raw = json.dumps(report).encode()
        run = self.workspace_run(self.coverage_workspace)
        run.result["target"] = "fixture-native-target"
        run.llvm_cov, run.llvm_profdata = "fixture-cov", "fixture-profdata"
        with patch.object(run, "command", return_value=raw):
            with self.assertRaisesRegex(collector.gate.CoverageError, "merged totals disagree"):
                run.export("critical", {self.binary}, [{"path": "fixture.profraw"}])
        self.assertFalse((self.root / "original-scope-summary.json").exists())

    def test_workspace_export_cannot_omit_a_new_package_even_when_other_packages_are_complete(self):
        report = self.coverage_report(True)
        _, workspace = self.workspace((("new-public-api", "lib"),))
        run = self.workspace_run(workspace)
        run.result["target"] = "fixture-native-target"
        run.llvm_cov, run.llvm_profdata = "fixture-cov", "fixture-profdata"
        rows = collector.workspace_package_coverage(report, run.result["source_inventory"], workspace, self.root)
        missing = next(row for row in rows if row["package"] == "new-public-api")
        self.assertEqual(missing["status"], "unqualified_zero_native_mapping")
        self.assertEqual(missing["measured"]["lines"]["count"], 0)
        with patch.object(run, "command", return_value=json.dumps(report).encode()):
            with self.assertRaisesRegex(suite.Invalid, "eligible_workspace_package_missing_native_mapping:new-public-api"):
                run.export("critical", {self.binary}, [{"path": "fixture.profraw"}])
        self.assertEqual(run.result["workspace_package_coverage"], rows)
        self.assertFalse((self.root / "coverage-summary.json").exists())

    def test_metadata_preserves_feature_eligibility_and_explicit_nonruntime_targets(self):
        metadata, _ = self.workspace((("new-runtime", "bin"),))
        target = copy.deepcopy(metadata["packages"][-1]["targets"][0])
        target.update(name="not-runtime", kind=["example"], test=False)
        metadata["packages"][-1]["targets"].append(target)
        workspace = collector.workspace_inventory(metadata, self.root)
        package = next(p for p in workspace if p["name"] == "new-runtime")
        self.assertEqual(package["features"], ["acceptance"])
        self.assertEqual(package["targets"][0]["required_features"], ["acceptance"])
        self.assertFalse(package["targets"][1]["eligible"])
        self.assertNotIn(("new-runtime", "not-runtime", "example", True), collector.expected_artifacts(workspace, tests=True))

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
