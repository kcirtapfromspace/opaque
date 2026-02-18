#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT/target/release"

if [[ ! -x "$BIN_DIR/opaque" || ! -x "$BIN_DIR/opaqued" ]]; then
  echo "error: release binaries not found; run: cargo build --release" >&2
  exit 1
fi

export PATH="$BIN_DIR:$PATH"
export TERM="${TERM:-xterm-256color}"

run() {
  echo "\$ $*"
  "$@"
  echo
  sleep 0.6
}

DEMO_DIR="$(mktemp -d /private/tmp/opaque-demo-security-sandbox-leak.XXXXXX)"
OPAQUED_PID=""

cleanup() {
  if [[ -n "${OPAQUED_PID:-}" ]]; then
    kill "$OPAQUED_PID" >/dev/null 2>&1 || true
    wait "$OPAQUED_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DEMO_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Use a throwaway state directory so we do not touch ~/.opaque or any real secrets.
export HOME="$DEMO_DIR/home"
export XDG_RUNTIME_DIR="$DEMO_DIR/xdg"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$DEMO_DIR/logs" "$DEMO_DIR/project"
chmod 700 "$HOME" "$XDG_RUNTIME_DIR" >/dev/null 2>&1 || true

# Dummy value used as a "secret". This demo intentionally shows it leaking via
# captured stdout. Do NOT replace with a real secret.
export OPAQUE_DEMO_VALUE_SRC="demo_value_123456"

run opaque init

cat >"$HOME/.opaque/config.toml" <<'TOML'
# Demo-only policy.
#
# This rule *attempts* to restrict secret names to ALLOWED_* (see secret_names),
# but the current implementation does not reliably populate secret_ref_names for
# convenience wrappers (including exec -> sandbox.exec). As a result, the
# secret_names constraint is bypassable and should not be relied on for safety.
[[rules]]
name = "demo-allow-sandbox-exec-with-secret-patterns"
operation_pattern = "sandbox.exec"
allow = true
client_types = ["agent"]

[rules.client]

[rules.secret_names]
patterns = ["ALLOWED_*"]

[rules.approval]
require = "never"
factors = []
TOML

run opaque policy check

cat >"$HOME/.opaque/profiles/demo.toml" <<TOML
[profile]
name = "demo"
description = "Security demo profile (dummy secret)"
project_dir = "$DEMO_DIR/project"
extra_read_paths = []

[network]
allow = []

[secrets]
DEMO_VALUE = "env:OPAQUE_DEMO_VALUE_SRC"

[env]
RUST_LOG = "info"

[limits]
timeout_secs = 60
max_output_bytes = 1048576
TOML

echo "\$ opaqued  # (started in background)"
RUST_LOG=info opaqued >"$DEMO_DIR/logs/opaqued.log" 2>&1 &
OPAQUED_PID="$!"
sleep 0.4

SOCK="$XDG_RUNTIME_DIR/opaque/opaqued.sock"
TOKEN="$XDG_RUNTIME_DIR/opaque/daemon.token"
for _ in $(seq 1 200); do
  if [[ -S "$SOCK" && -f "$TOKEN" ]]; then
    break
  fi
  sleep 0.05
done

echo "\$ opaque exec --profile demo -- sh -lc 'echo \"$DEMO_VALUE\"'"
opaque exec --profile demo -- sh -lc 'echo "$DEMO_VALUE"'
echo
sleep 0.6

run opaque audit tail --limit 12

