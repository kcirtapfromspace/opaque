#!/usr/bin/env python3
"""Verify that release binaries carry an embedded cargo-auditable dependency
manifest, the same data a downstream user extracts with `cargo audit bin`.

This is a provenance-presence gate, not a vulnerability gate. `cargo-deny`
already blocks known-vulnerable dependencies from Cargo.lock earlier and
cheaper, before an hour of cross-compiling and (on macOS) notarizing. A
freshly disclosed advisory in some dependency must not fail a release build
here merely because this step happens to call the same RustSec database as
that check; only a binary with no embedded dependency data at all should.
`cargo audit bin` reports both kinds of finding through the same nonzero
exit code, so this script tells them apart by parsing its JSON report:
a report that parses at all means the manifest was found and extracted,
whatever it says about advisories; a report that does not parse means
extraction failed, which is the one condition this gate exists to catch.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

import release_artifacts as release


def check_binary(path):
    """Return (ok, message) for one release binary."""
    if not path.is_file():
        return False, f"{path.name}: no such file at {path}"
    try:
        result = subprocess.run(
            ["cargo", "audit", "bin", "--json", str(path)],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        return False, f"{path.name}: `cargo audit` is not installed (cargo install cargo-audit)"
    except subprocess.TimeoutExpired:
        return False, f"{path.name}: `cargo audit bin` timed out"
    try:
        report = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        detail = (result.stderr or result.stdout or "no output").strip()
        return False, (f"{path.name}: no embedded dependency manifest found "
                        f"-- was it built with `cargo auditable build`? ({detail})")
    vulnerabilities = report.get("vulnerabilities") or {}
    if vulnerabilities.get("found"):
        count = vulnerabilities.get("count", "some")
        return True, (f"{path.name}: embedded dependency manifest present "
                       f"({count} known advisory match(es); tracked separately by cargo-deny, not this gate)")
    return True, f"{path.name}: embedded dependency manifest present"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--bin", action="append", dest="bins", default=None,
                         help="binary name to check (repeatable); default is every release binary")
    args = parser.parse_args()
    bins = args.bins or list(release.BINS)
    results = [(name, *check_binary(args.binary_dir / name)) for name in bins]
    failed = [(name, message) for name, ok, message in results if not ok]
    for name, ok, message in results:
        print(message, file=sys.stdout if ok else sys.stderr)
    if failed:
        parser.exit(1, f"verify-auditable-binary: {len(failed)} of {len(results)} binaries are missing embedded dependency data\n")
    print(json.dumps({"checked": [name for name, _, _ in results]}, sort_keys=True))


if __name__ == "__main__":
    main()
