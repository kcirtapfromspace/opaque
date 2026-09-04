#!/usr/bin/env bash
# Point the Homebrew formula at a published release.
#
# A formula may only name artifacts that exist, so this runs *after* a release
# is published — never as part of preparing one. It downloads every asset,
# checks each against the .sha256 published beside it, and writes the version
# and checksums into homebrew/opaque.rb.
#
#   scripts/update-tap.sh              # the latest release
#   scripts/update-tap.sh v0.2.0       # a specific one
#   scripts/update-tap.sh v0.2.0 --push
#
# --push also syncs the formula into the tap repository, which is what
# `brew install kcirtapfromspace/tap/opaque` actually reads.

set -euo pipefail

cd "$(dirname "$0")/.."

TAP_REPO="${OPAQUE_TAP_REPO:-kcirtapfromspace/homebrew-tap}"
FORMULA="homebrew/opaque.rb"
TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-gnu
)

die() { printf 'update-tap: %s\n' "$1" >&2; exit 1; }

command -v gh >/dev/null || die "gh is required"
[ -f "$FORMULA" ] || die "$FORMULA not found"

tag=""
push=false
for arg in "$@"; do
  case "$arg" in
    --push) push=true ;;
    -*) die "unknown flag: $arg" ;;
    *) tag="$arg" ;;
  esac
done

if [ -z "$tag" ]; then
  tag=$(gh release view --json tagName --jq .tagName) || die "no published release"
fi
version="${tag#v}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

printf 'update-tap: %s\n' "$tag" >&2

for target in "${TARGETS[@]}"; do
  asset="opaque-${version}-${target}.tar.gz"
  gh release download "$tag" --pattern "$asset" --pattern "$asset.sha256" \
    --dir "$work" --clobber >/dev/null 2>&1 \
    || die "release $tag has no $asset (did the build for $target fail?)"

  actual=$(shasum -a 256 "$work/$asset" | awk '{print $1}')

  # The checksum published beside the asset is an independent statement about
  # the same bytes; if they disagree, something is wrong upstream and a formula
  # is the last place that should paper over it.
  if [ -f "$work/$asset.sha256" ]; then
    published=$(awk '{print $1}' "$work/$asset.sha256")
    [ "$actual" = "$published" ] \
      || die "checksum mismatch for $asset (downloaded $actual, published $published)"
  else
    printf 'update-tap: warning: no published .sha256 beside %s\n' "$asset" >&2
  fi

  printf '  %s  %s\n' "$actual" "$target" >&2
  printf '%s %s\n' "$target" "$actual" >> "$work/sums"
done

python3 scripts/rewrite_formula.py "$version" "$work/sums" "$FORMULA"

if grep -q PLACEHOLDER "$FORMULA"; then
  die "formula still contains PLACEHOLDER values"
fi

printf 'update-tap: %s now points at %s\n' "$FORMULA" "$tag" >&2

if [ "$push" = true ]; then
  clone="$work/tap"
  gh repo clone "$TAP_REPO" "$clone" -- --quiet \
    || die "cannot clone $TAP_REPO (create it first: gh repo create $TAP_REPO --public)"
  mkdir -p "$clone/Formula"
  cp "$FORMULA" "$clone/Formula/opaque.rb"
  git -C "$clone" add Formula/opaque.rb
  if git -C "$clone" diff --cached --quiet; then
    printf 'update-tap: tap already at %s\n' "$tag" >&2
  else
    git -C "$clone" commit -q -m "opaque $version"
    git -C "$clone" push -q
    printf 'update-tap: pushed %s to %s\n' "$tag" "$TAP_REPO" >&2
  fi
fi
