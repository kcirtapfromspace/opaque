#!/usr/bin/env python3
"""Gate measured LLVM source coverage; never infer it from passing tests.

Input is a freshly generated cargo-llvm-cov JSON export. Required source files
protect against an accidentally narrowed report. This validates the report's
shape and counts, not its authenticity or completeness for unlisted platforms.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import sys


class CoverageError(ValueError):
    pass


def _count(value):
    if type(value) is not int or value < 0:
        raise CoverageError("coverage counts must be nonnegative integers")
    return value


def _metric(value):
    if not isinstance(value, dict):
        raise CoverageError("missing coverage metric")
    count, covered = _count(value.get("count")), _count(value.get("covered"))
    if covered > count:
        raise CoverageError("covered count exceeds instrumented count")
    # Recompute percentages from integers; never trust a rounded percentage
    # supplied by a tool or accept NaN as satisfying the threshold.
    return {"count": count, "covered": covered,
            "percent": float(Fraction(covered * 100, count)) if count else None}


def _below(metric, minimum):
    # The display float can round 99.999... to 100. Gate on exact rational
    # counts, so even a single uncovered line always fails a 100% target.
    target = Fraction(str(minimum))
    return metric["covered"] * 100 * target.denominator < metric["count"] * target.numerator


def _relative(filename, source_root):
    if not isinstance(filename, str) or any(ord(char) < 32 for char in filename):
        raise CoverageError("invalid source filename")
    path = Path(filename)
    if not path.is_absolute():
        path = source_root / path
    try:
        relative = path.resolve().relative_to(source_root)
    except ValueError as error:
        raise CoverageError("report contains source outside the configured root") from error
    if relative == Path("."):
        raise CoverageError("invalid source filename")
    return relative.as_posix()


def evaluate(report, *, source_root, required_files, minimum_lines=100.0,
             require_branches=False, minimum_branches=100.0):
    for minimum in (minimum_lines, minimum_branches):
        if isinstance(minimum, bool) or not math.isfinite(minimum) or not 0 <= minimum <= 100:
            raise CoverageError("coverage threshold must be finite and between 0 and 100")
    source_root = Path(source_root).resolve(strict=True)
    required = {_relative(name, source_root) for name in required_files}
    if not required:
        raise CoverageError("at least one required source file must be declared")
    if any(not (source_root / name).is_file() for name in required):
        raise CoverageError("a required source file does not exist")
    if not isinstance(report, dict) or report.get("type") != "llvm.coverage.json.export":
        raise CoverageError("expected LLVM coverage JSON export")
    data = report.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise CoverageError("expected exactly one merged coverage dataset")
    files = data[0].get("files")
    if not isinstance(files, list) or not files:
        raise CoverageError("coverage report contains no source files")
    measured = {}
    for item in files:
        if not isinstance(item, dict):
            raise CoverageError("invalid coverage source entry")
        name = _relative(item.get("filename"), source_root)
        if name in measured:
            raise CoverageError("duplicate source file would inflate coverage")
        if not (source_root / name).is_file():
            raise CoverageError("reported source file is missing")
        summary = item.get("summary")
        if not isinstance(summary, dict):
            raise CoverageError("missing source summary")
        measured[name] = {metric: _metric(summary.get(metric))
                          for metric in ("lines", "branches")}
    missing = sorted(required - measured.keys())
    totals = {}
    for metric in ("lines", "branches"):
        totals[metric] = _metric({key: sum(item[metric][key] for item in measured.values())
                                 for key in ("count", "covered")})
    declared_totals = data[0].get("totals")
    if not isinstance(declared_totals, dict):
        raise CoverageError("missing merged totals")
    for metric in totals:
        declared = _metric(declared_totals.get(metric))
        if any(declared[key] != totals[metric][key] for key in ("count", "covered")):
            raise CoverageError("merged totals disagree with source file counts")
    failures = []
    if missing:
        failures.append("required_source_missing_from_report")
    if not totals["lines"]["count"]:
        failures.append("no_instrumented_lines")
    elif _below(totals["lines"], minimum_lines):
        failures.append("line_coverage_below_target")
    unmeasured_required = sorted(name for name in required & measured.keys()
                                 if not measured[name]["lines"]["count"])
    if unmeasured_required:
        failures.append("required_source_has_no_instrumented_lines")
    if require_branches:
        if not totals["branches"]["count"]:
            failures.append("branch_coverage_not_measured")
        elif _below(totals["branches"], minimum_branches):
            failures.append("branch_coverage_below_target")
    return {
        "schema": "opaque.measured-code-coverage.v1",
        "status": "failed" if failures else "passed",
        "scope": "instrumented files in this report; not whole-product or state-space coverage",
        "threshold_comparison": "exact integer ratios; displayed percentages may be rounded",
        "required_source_files": sorted(required),
        "reported_source_files": len(measured),
        "missing_required_source_files": missing,
        "unmeasured_required_source_files": unmeasured_required,
        "thresholds": {"lines": minimum_lines,
                       "branches": minimum_branches if require_branches else None},
        "measured": totals,
        "failures": failures,
        "uncovered_files": [{"path": name, **metrics}
                            for name, metrics in sorted(measured.items())
                            if metrics["lines"]["covered"] < metrics["lines"]["count"]
                            or (require_branches and metrics["branches"]["covered"]
                                < metrics["branches"]["count"])],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--require-file", action="append", required=True)
    parser.add_argument("--minimum-lines", type=float, default=100.0)
    parser.add_argument("--require-branches", action="store_true")
    parser.add_argument("--minimum-branches", type=float, default=100.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        raw = args.report.read_bytes()
        result = evaluate(json.loads(raw), source_root=args.source_root,
                          required_files=args.require_file, minimum_lines=args.minimum_lines,
                          require_branches=args.require_branches,
                          minimum_branches=args.minimum_branches)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        status = 0 if result["status"] == "passed" else 1
    except (CoverageError, OSError, ValueError, TypeError):
        result = {"schema": "opaque.measured-code-coverage.v1", "status": "invalid",
                  "failures": ["invalid_or_unreadable_coverage_input"]}
        status = 2
    serialized = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(serialized)
    else:
        sys.stdout.write(serialized)
    return status


if __name__ == "__main__":
    sys.exit(main())
