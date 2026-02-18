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
  local cols="${3:-80}"
  local rows="${4:-24}"
  local cast="assets/demos/${name}.cast"
  local gif="assets/demos/${name}.gif"

  echo "==> Recording ${cast}"
  rm -f "$cast" "$gif"
  asciinema rec -q --cols "$cols" --rows "$rows" -c "bash \"$script\"" "$cast"

  echo "==> Rendering ${gif}"
  agg --quiet --theme github-light --idle-time-limit 2.0 --speed 0.8 "$cast" "$gif"
}

record "quickstart" "scripts/demo_quickstart.sh" 132 28
record "sandbox-exec" "scripts/demo_sandbox_exec.sh" 100 28
record "security-audit-detail-leak" "scripts/demo_security_audit_detail_leak.sh" 120 28
record "security-sandbox-secret-leak" "scripts/demo_security_sandbox_secret_leak.sh" 110 28
record "security-onepassword-read-field" "scripts/demo_security_onepassword_read_field.sh" 110 28

echo "==> Done"
