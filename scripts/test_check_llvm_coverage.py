import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "check_llvm_coverage", Path(__file__).with_name("check_llvm_coverage.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class MeasuredCoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        (self.root / "state.rs").write_text("pub fn state() {}\n")
        (self.root / "approval.rs").write_text("pub fn approve() {}\n")
        summary = {"lines": {"count": 10, "covered": 10, "percent": 100},
                   "branches": {"count": 4, "covered": 4, "percent": 100}}
        self.report = {"type": "llvm.coverage.json.export", "data": [{
            "files": [{"filename": str(self.root / "state.rs"), "summary": summary}],
            "totals": copy.deepcopy(summary)}]}

    def check(self, report=None, **options):
        return GATE.evaluate(self.report if report is None else report, source_root=self.root,
                             required_files=options.pop("required_files", ["state.rs"]), **options)

    def test_complete_measured_source_and_branch_counts_pass(self):
        result = self.check(require_branches=True)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["measured"]["branches"]["percent"], 100)

    def test_rounded_or_forged_percent_does_not_hide_uncovered_lines(self):
        for source in (self.report["data"][0]["files"][0]["summary"],
                       self.report["data"][0]["totals"]):
            source["lines"] = {"count": 10001, "covered": 10000, "percent": 100}
        result = self.check()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"], ["line_coverage_below_target"])

    def test_omitted_required_source_cannot_pass_a_filtered_report(self):
        result = self.check(required_files=["state.rs", "approval.rs"])
        self.assertEqual(result["missing_required_source_files"], ["approval.rs"])
        self.assertEqual(result["status"], "failed")

    def test_one_missing_line_or_branch_fails_even_when_float_rounds_to_one_hundred(self):
        for metric, failure in (("lines", "line_coverage_below_target"),
                                ("branches", "branch_coverage_below_target")):
            report = copy.deepcopy(self.report)
            for summary in (report["data"][0]["files"][0]["summary"],
                            report["data"][0]["totals"]):
                summary[metric] = {"count": 10**18, "covered": 10**18 - 1, "percent": 100}
            result = self.check(report, require_branches=True)
            self.assertEqual(result["measured"][metric]["percent"], 100.0)
            self.assertIn(failure, result["failures"])
            self.assertEqual(result["status"], "failed")

    def test_absent_branch_instrumentation_is_unmeasured_not_one_hundred_percent(self):
        for source in (self.report["data"][0]["files"][0]["summary"],
                       self.report["data"][0]["totals"]):
            source["branches"] = {"count": 0, "covered": 0, "percent": 100}
        self.assertIsNone(self.check()["measured"]["branches"]["percent"])
        self.assertIn("branch_coverage_not_measured", self.check(require_branches=True)["failures"])

    def test_zero_line_report_and_zero_line_required_file_fail(self):
        for source in (self.report["data"][0]["files"][0]["summary"],
                       self.report["data"][0]["totals"]):
            source["lines"] = {"count": 0, "covered": 0, "percent": 100}
        result = self.check()
        self.assertIn("no_instrumented_lines", result["failures"])
        self.assertIn("required_source_has_no_instrumented_lines", result["failures"])

    def test_duplicate_foreign_and_missing_sources_are_invalid(self):
        variants = []
        duplicate = copy.deepcopy(self.report)
        duplicate["data"][0]["files"] *= 2
        variants.append(duplicate)
        for name in ("../foreign.rs", "missing.rs"):
            changed = copy.deepcopy(self.report)
            changed["data"][0]["files"][0]["filename"] = name
            variants.append(changed)
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(GATE.CoverageError):
                self.check(variant)

    def test_inconsistent_totals_malformed_counts_and_empty_data_fail(self):
        for count in (-1, True, 9, "10", float("nan")):
            changed = copy.deepcopy(self.report)
            changed["data"][0]["totals"]["lines"]["count"] = count
            with self.subTest(count=count), self.assertRaises(GATE.CoverageError):
                self.check(changed)
        for change in ({}, [], {"type": "test_results", "data": []},
                       {"type": "llvm.coverage.json.export", "data": []}):
            with self.assertRaises(GATE.CoverageError):
                self.check(change)

    def test_missing_declared_scope_and_nonfinite_thresholds_fail(self):
        for options in ({"required_files": []}, {"required_files": ["missing.rs"]},
                        {"minimum_lines": float("nan")}, {"minimum_branches": float("inf")},
                        {"minimum_lines": -1}, {"minimum_lines": 101}):
            with self.subTest(options=options), self.assertRaises(GATE.CoverageError):
                self.check(**options)

    def test_cli_writes_failed_report_and_returns_nonzero(self):
        report, output = self.root / "coverage.json", self.root / "gate.json"
        report.write_text(json.dumps(self.report))
        result = GATE.main(["--report", str(report), "--source-root", str(self.root),
                            "--require-file", "state.rs", "--require-file", "approval.rs",
                            "--output", str(output)])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.read_text())["status"], "failed")

    def workspace(self):
        packages = []
        for name, kind, filename in (("library", "lib", "lib.rs"), ("excluded-cli", "bin", "main.rs")):
            directory = self.root / name
            (directory / "src").mkdir(parents=True)
            (directory / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n')
            source = directory / "src" / filename
            source.write_text("pub fn run() {}\n")
            packages.append({"id": name, "name": name, "manifest_path": str(directory / "Cargo.toml"),
                             "targets": [{"kind": [kind], "src_path": str(source)}]})
        return {"workspace_members": [item["id"] for item in packages],
                "workspace_default_members": ["library"], "packages": packages}

    def workspace_report(self, metadata):
        report = copy.deepcopy(self.report)
        summary = report["data"][0]["totals"]
        report["data"][0]["files"] = [
            {"filename": package["targets"][0]["src_path"], "summary": copy.deepcopy(summary)}
            for package in metadata["packages"]]
        for metric in ("lines", "branches"):
            for key in ("count", "covered"):
                summary[metric][key] *= len(metadata["packages"])
        return report

    def test_default_excluded_binary_package_cannot_disappear_from_full_workspace_gate(self):
        metadata = self.workspace()
        report = self.workspace_report(metadata)
        complete = self.check(report, required_files=[], workspace_metadata=metadata)
        self.assertEqual(complete["status"], "passed")
        self.assertEqual([item["package"] for item in complete["workspace_packages"]], ["excluded-cli", "library"])
        report["data"][0]["files"].pop()
        report["data"][0]["totals"] = copy.deepcopy(report["data"][0]["files"][0]["summary"])
        omitted = self.check(report, required_files=[], workspace_metadata=metadata)
        self.assertEqual(omitted["measured"]["lines"]["percent"], 100)
        self.assertEqual(omitted["unmeasured_workspace_packages"], ["excluded-cli"])
        self.assertEqual(omitted["status"], "failed")

    def test_zero_mapping_and_test_sources_cannot_qualify_a_workspace_package(self):
        metadata = self.workspace()
        for mode in ("zero", "test"):
            report = self.workspace_report(metadata)
            item = report["data"][0]["files"][1]
            if mode == "zero":
                for metric in ("lines", "branches"):
                    for key in ("count", "covered"):
                        item["summary"][metric][key] = 0
                        report["data"][0]["totals"][metric][key] //= 2
            else:
                test = self.root / "excluded-cli" / "tests" / "cli.rs"
                test.parent.mkdir()
                test.write_text("#[test] fn test() {}\n")
                item["filename"] = str(test)
            result = self.check(report, required_files=[], workspace_metadata=metadata)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["unmeasured_workspace_packages"], ["excluded-cli"])

    def test_shared_module_requires_mapping_and_preserves_all_exact_package_owners(self):
        metadata = self.workspace()
        shared = self.root / "assets" / "brand.rs"
        shared.parent.mkdir()
        shared.write_text("pub fn get(value: [u8; 4]) -> [u8; 4] { value }")
        for package in metadata["packages"]:
            Path(package["targets"][0]["src_path"]).write_text(
                '#[path="../../assets/brand.rs"] mod shared; pub fn run() { shared::get(); }')
        report = self.workspace_report(metadata)
        missing = self.check(report, required_files=[], workspace_metadata=metadata)
        self.assertEqual(missing["missing_required_source_files"], ["assets/brand.rs"])
        self.assertEqual(missing["status"], "failed")
        summary = copy.deepcopy(report["data"][0]["files"][0]["summary"])
        report["data"][0]["files"].append({"filename": str(shared), "summary": summary})
        for metric in ("lines", "branches"):
            for key in ("count", "covered"):
                report["data"][0]["totals"][metric][key] += summary[metric][key]
        complete = self.check(report, required_files=[], workspace_metadata=metadata)
        self.assertEqual(complete["status"], "passed")
        self.assertEqual(complete["measured"]["lines"]["count"], 30)
        self.assertEqual(complete["sources_without_unique_workspace_owner"], [])
        self.assertTrue(all(row["shared_sources"] == ["assets/brand.rs"] for row in complete["workspace_packages"]))
        # Exact source edges confer no ownership of neighboring assets.
        unrelated = shared.with_name("unrelated.rs")
        unrelated.write_text("pub fn unrelated() {}")
        report["data"][0]["files"][-1]["filename"] = str(unrelated)
        result = self.check(report, required_files=[], workspace_metadata=metadata)
        self.assertIn("assets/unrelated.rs", result["sources_without_unique_workspace_owner"])
        self.assertEqual(result["status"], "failed")

    def test_shared_native_cfg_is_declared_without_qualifying_compiled_out_code(self):
        metadata = self.workspace()
        shared = self.root / "assets" / "native.rs"
        shared.parent.mkdir()
        shared.write_text("pub fn native() {}")
        Path(metadata["packages"][0]["targets"][0]["src_path"]).write_text(
            '#[cfg(target_os="linux")] #[path="../../assets/native.rs"] mod native; pub fn run() {}')
        scope = GATE.workspace_scope(metadata, self.root)
        package = next(item for item in scope if item["package"] == "library")
        self.assertEqual(package["shared_sources"], ["assets/native.rs"])
        self.assertEqual(package["required_shared_sources"], [])
        result = self.check(self.workspace_report(metadata), required_files=[], workspace_metadata=metadata)
        self.assertEqual(result["measured"]["lines"]["count"], 20)
        self.assertNotIn("assets/native.rs", result["required_source_files"])

    def test_invalid_or_missing_workspace_members_fail_closed(self):
        metadata = self.workspace()
        variants = [None, {}, {**metadata, "workspace_members": []},
                    {**metadata, "workspace_members": ["library", "library"]},
                    {**metadata, "workspace_members": ["missing"]},
                    {**metadata, "packages": metadata["packages"] * 2}]
        foreign = copy.deepcopy(metadata)
        foreign["packages"][1]["manifest_path"] = str(self.root.parent / "Cargo.toml")
        variants.append(foreign)
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(GATE.CoverageError):
                GATE.workspace_scope(variant, self.root)

    def test_workspace_cli_discovers_metadata_independently_of_report(self):
        metadata = self.workspace()
        report, output = self.root / "coverage.json", self.root / "gate.json"
        report.write_text(json.dumps(self.workspace_report(metadata)))
        with patch.object(GATE.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(metadata).encode()
            status = GATE.main(["--report", str(report), "--source-root", str(self.root),
                                "--require-workspace", "--output", str(output)])
            self.assertIn("--all-features", run.call_args.args[0])
            self.assertIn("--no-deps", run.call_args.args[0])
        self.assertEqual(status, 0)
        self.assertEqual(len(json.loads(output.read_text())["workspace_packages"]), 2)

    def test_null_metadata_cannot_turn_off_requested_workspace_requirement(self):
        report, output = self.root / "coverage.json", self.root / "gate.json"
        report.write_text(json.dumps(self.report))
        with patch.object(GATE.subprocess, "run") as run:
            run.return_value.stdout = b"null"
            status = GATE.main(["--report", str(report), "--source-root", str(self.root),
                                "--require-workspace", "--require-file", "state.rs",
                                "--output", str(output)])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.read_text())["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
