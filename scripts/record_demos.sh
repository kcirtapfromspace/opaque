#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing dependency: $1" >&2
    exit 1
  fi
}

need_cmd asciinema
need_cmd agg

mkdir -p assets/demos

echo "==> Building release binaries"
cargo build --release >/dev/null

record() {
  local name="$1"
  local script="$2"
  local cast="assets/demos/${name}.cast"
  local gif="assets/demos/${name}.gif"

  echo "==> Recording ${cast}"
  rm -f "$cast" "$gif"
  asciinema rec -q -c "bash \"$script\"" "$cast"

  echo "==> Rendering ${gif}"
  agg --quiet --theme github-light --idle-time-limit 1.5 "$cast" "$gif"
}

record "quickstart" "scripts/demo_quickstart.sh"
record "sandbox-exec" "scripts/demo_sandbox_exec.sh"

echo "==> Done"

