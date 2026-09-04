#!/usr/bin/env bash
# Prepare a release: bump the workspace version and close out the changelog.
#
# The version is not a judgement call — git-cliff derives it from the
# conventional-commit types that have merged since the last tag, so what the
# merged PRs said they were is what decides the bump.
#
#   scripts/release-prep.sh            # version from the merged commits
#   scripts/release-prep.sh 0.3.0      # or state it explicitly
#
# Writes: Cargo.toml (workspace version), Cargo.lock, CHANGELOG.md.
# Commits nothing — the caller decides, which is what makes this safe to run
# locally and in CI alike.

set -euo pipefail

cd "$(dirname "$0")/.."

die() { printf 'release-prep: %s\n' "$1" >&2; exit 1; }

current=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$current" ] || die "no [workspace.package] version in Cargo.toml"

if [ $# -ge 1 ]; then
  next="${1#v}"
else
  command -v git-cliff >/dev/null || die "git-cliff not found (or pass a version explicitly)"
  # --bumped-version prints the NEXT version; it prints the current tag when
  # nothing warrants a release.
  next=$(git-cliff --bumped-version 2>/dev/null | tail -1)
  next="${next#v}"
fi

case "$next" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "computed version '$next' is not semver" ;;
esac

if [ "$next" = "$current" ]; then
  printf 'release-prep: already at %s — nothing to release\n' "$current" >&2
  echo "version=$current"
  echo "changed=false"
  exit 0
fi

# 1. The version, in the one place it lives.
python3 - "$next" <<'PY'
import pathlib, re, sys
nxt = sys.argv[1]
p = pathlib.Path("Cargo.toml")
s = p.read_text()
s2, n = re.subn(r'(?m)^version = "[^"]+"$', f'version = "{nxt}"', s, count=1)
if n != 1:
    raise SystemExit("release-prep: could not rewrite the workspace version")
p.write_text(s2)
PY

# 2. Cargo.lock records member versions too; --offline keeps this deterministic
#    and stops a release prep from quietly bumping dependencies.
cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null

# 3. Close out the changelog. The entries are written by hand and are worth
#    more than a list of commit subjects, so this only stamps the release: the
#    curated [Unreleased] section becomes [x.y.z] with today's date, and a
#    fresh [Unreleased] takes its place.
python3 - "$next" <<'PY'
import datetime, pathlib, re, sys
nxt = sys.argv[1]
p = pathlib.Path("CHANGELOG.md")
s = p.read_text()
if f"## [{nxt}]" in s:
    raise SystemExit(f"release-prep: CHANGELOG already has a {nxt} section")
today = datetime.date.today().isoformat()
# `\s*` here would be greedy across the newline and swallow the blank line
# that separates the heading from its entries.
new, n = re.subn(
    r"(?m)^## \[Unreleased\][ \t]*$",
    f"## [Unreleased]\n\n## [{nxt}] - {today}",
    s,
    count=1,
)
if n != 1:
    raise SystemExit("release-prep: no '## [Unreleased]' heading in CHANGELOG.md")
p.write_text(new)
PY

# 4. The Homebrew formula pins the version it downloads, so it drifts silently
#    if left out of the bump.
if [ -f homebrew/opaque.rb ]; then
  python3 - "$next" <<'PY'
import pathlib, re, sys
nxt = sys.argv[1]
p = pathlib.Path("homebrew/opaque.rb")
s = p.read_text()
s2, n = re.subn(r'(?m)^(  version ")[^"]+(")$', rf'\g<1>{nxt}\g<2>', s, count=1)
if n == 1:
    p.write_text(s2)
else:
    print("release-prep: warning: no version line in homebrew/opaque.rb", file=sys.stderr)
if "PLACEHOLDER" in s2:
    print(
        "release-prep: warning: homebrew/opaque.rb still has PLACEHOLDER checksums — "
        "`brew install` cannot work until they are filled from the release assets",
        file=sys.stderr,
    )
PY
fi

printf 'release-prep: %s -> %s\n' "$current" "$next" >&2
echo "version=$next"
echo "changed=true"
