#!/usr/bin/env python3
"""Rewrite the Homebrew formula's download URLs and checksums for a release.

Called by scripts/update-tap.sh, which has already downloaded every asset and
verified it against the checksum published beside it.

The version is deliberately *not* declared in the formula: Homebrew scans it
out of the URL, and declaring it as well fails `brew audit --strict`. So the
version lives in the URLs, and this rewrites it there along with the sha256
line under each one.
"""

import pathlib
import re
import sys

ASSET = re.compile(r"opaque-(\d+\.\d+\.\d+)-([a-z0-9_]+-[a-z0-9-]+)\.tar\.gz")
SHA_LINE = re.compile(r'^\s*sha256 "')


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: rewrite_formula.py <version> <sums-file> <formula>", file=sys.stderr)
        return 2
    version, sums_path, formula_path = argv[1], argv[2], argv[3]

    sums = dict(
        line.split()
        for line in pathlib.Path(sums_path).read_text().splitlines()
        if line.strip()
    )

    formula = pathlib.Path(formula_path)
    out: list[str] = []
    pending: str | None = None
    urls = shas = 0

    for line in formula.read_text().splitlines(keepends=True):
        match = ASSET.search(line)
        if match:
            target = match.group(2)
            if target not in sums:
                print(f"rewrite_formula: formula names an unknown target {target}", file=sys.stderr)
                return 1
            line = re.sub(r"/download/v\d+\.\d+\.\d+/", f"/download/v{version}/", line)
            line = re.sub(r"opaque-\d+\.\d+\.\d+-", f"opaque-{version}-", line)
            pending = target
            urls += 1
        elif pending and SHA_LINE.match(line):
            line = re.sub(r'"[^"]*"', f'"{sums[pending]}"', line, count=1)
            shas += 1
            pending = None
        out.append(line)

    if urls != len(sums) or shas != len(sums):
        print(
            f"rewrite_formula: rewrote {urls} urls and {shas} checksums, "
            f"expected {len(sums)} of each",
            file=sys.stderr,
        )
        return 1

    formula.write_text("".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
