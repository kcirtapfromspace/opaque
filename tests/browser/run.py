#!/usr/bin/env python3
"""Run the existing Chromium tests with explicit, collector-built native objects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import acceptance_coverage as coverage
import synthesized_suite as suite

FILES = ("package.json", "package-lock.json", "dashboard.test.mjs", "processes.mjs", "processes.test.mjs")
EXPECTED = {"cleanup removes an actual orphaned group and preserves the failure",
            "owner authentication, lock and reload clear private state in Chromium",
            "keyboard tabs and mobile layout work against the real dashboard",
            "live daemon inventory becomes unavailable after process loss without synthetic fallback"}


def passing_tests(raw):
    text = raw.decode()
    names = re.findall(r"^ok [0-9]+ - (.+)$", text, re.MULTILINE)
    coverage.require(len(names) == len(EXPECTED) and set(names) == EXPECTED
                     and re.findall(r"^# tests ([0-9]+)$", text, re.MULTILINE) == ["4"]
                     and re.findall(r"^# pass ([0-9]+)$", text, re.MULTILINE) == ["4"]
                     and re.findall(r"^# fail ([0-9]+)$", text, re.MULTILINE) == ["0"]
                     and all(re.findall(r"^# " + label + r" ([0-9]+)$", text, re.MULTILINE) == ["0"]
                             for label in ("cancelled", "skipped", "todo"))
                     and not re.search(r"^not ok |# (?:SKIP|TODO)", text, re.MULTILINE), "browser_exact_tests_did_not_pass")
    return sorted(names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage-input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--browser-cache", type=Path, help="explicit existing Playwright engine cache; otherwise download the pinned engine")
    args = parser.parse_args()
    initial = suite.source_snapshot(ROOT)
    value = coverage.load(args.coverage_input, root=ROOT, purpose="browser", source=initial)
    args.output.mkdir(mode=0o700)
    runtime, home = args.output / "runtime", args.output / "home"
    runtime.mkdir(); home.mkdir(mode=0o700)
    for name in FILES:
        shutil.copyfile(Path(__file__).parent / name, runtime / name)
    binary_dirs = {str(Path(row["path"]).parent) for row in value["objects"].values()}
    coverage.require(len(binary_dirs) == 1, "browser_runtime_binaries_must_share_build_directory")
    events = args.output / "processes.jsonl"
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "LANG": "C.UTF-8",
           "OPAQUE_BROWSER_BINARY_DIR": next(iter(binary_dirs)),
           "OPAQUE_BROWSER_COVERAGE_PROFILE_DIR": value["profile_dir"],
           "OPAQUE_BROWSER_COVERAGE_EVENTS": str(events)}
    if args.browser_cache:
        coverage.require(args.browser_cache.is_dir() and not args.browser_cache.is_symlink(), "browser_cache_unavailable")
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(args.browser_cache.resolve())
    def run(name, argv, timeout):
        result = suite.invoke(argv, cwd=runtime, env=env, timeout=timeout)
        (args.output / (name + ".log")).write_bytes(result.output)
        suite.command_ok(result)
        return result.output
    run("dependencies", ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], 180)
    if not args.browser_cache:
        run("chromium-install", ["node", "node_modules/playwright/cli.js", "install", "chromium"], 300)
    raw = run("chromium-tests", ["node", "--test", "--test-reporter=tap", "--test-concurrency=1",
                                 "processes.test.mjs", "dashboard.test.mjs"], 300)
    names = passing_tests(raw)
    observed = [json.loads(line) for line in events.read_text().splitlines()]
    coverage.require(len(observed) == 4 and len({row["pid"] for row in observed}) == 4
                     and [row["name"] for row in observed].count("opaque-web") == 3
                     and [row["name"] for row in observed].count("opaqued") == 1, "browser_process_inventory_incomplete")
    for row in observed:
        expected = value["objects"].get(row["name"])
        coverage.require(expected is not None and row["binary"] == expected["path"]
                         and row["sha256"] == expected["sha256"] and not row["forced_cleanup"]
                         and (row["exit_code"] == 0 or row["signal"] == "SIGINT"), "browser_runtime_identity_or_exit_changed")
    profiles = coverage.profiles(value, roles={"web", "daemon"}, process_ids={row["pid"] for row in observed})
    final = suite.source_snapshot(ROOT)
    coverage.require(initial == final, "browser_source_changed")
    report = {"schema": "opaque.browser-coverage-acceptance.v1", "status": "passed", "source_before": initial,
              "source_after": final, "platform": sys.platform, "target": value["target"],
              "input_sha256": coverage.digest(args.coverage_input), "qualification": value["qualification"],
              "tests": names, "processes": observed, "profiles": profiles,
              "test_output_sha256": hashlib.sha256(raw).hexdigest(),
              "scope": "Actual Chromium against instrumented Rust services; browser engine and JavaScript coverage are not Rust workspace percentages"}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "passed", "tests": len(names), "native_processes": len(observed)}))


if __name__ == "__main__":
    main()
