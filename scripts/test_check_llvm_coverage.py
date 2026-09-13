import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
