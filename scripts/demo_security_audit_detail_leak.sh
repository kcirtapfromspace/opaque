#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT/target/release"

if [[ ! -x "$BIN_DIR/opaque" || ! -x "$BIN_DIR/opaqued" ]]; then
  echo "error: release binaries not found; run: cargo build --release" >&2
  exit 1
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "error: sqlite3 is required for this demo" >&2
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

DEMO_DIR="$(mktemp -d /private/tmp/opaque-demo-security-audit-detail.XXXXXX)"
OPAQUED_PID=""

cleanup() {
  if [[ -n "${OPAQUED_PID:-}" ]]; then
    kill "$OPAQUED_PID" >/dev/null 2>&1 || true
    wait "$OPAQUED_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DEMO_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Throwaway HOME/XDG dirs so we do not touch ~/.opaque.
export HOME="$DEMO_DIR/home"
export XDG_RUNTIME_DIR="$DEMO_DIR/xdg"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$DEMO_DIR/logs" "$DEMO_DIR/project"
chmod 700 "$HOME" "$XDG_RUNTIME_DIR" >/dev/null 2>&1 || true

run opaque init

cat >"$HOME/.opaque/config.toml" <<'TOML'
# Demo-only policy: allow sandbox.exec without approvals.
[[rules]]
name = "demo-allow-sandbox-exec"
operation_pattern = "sandbox.exec"
allow = true
client_types = ["agent"]

[rules.client]

[rules.approval]
require = "never"
factors = []
TOML

run opaque policy check

cat >"$HOME/.opaque/profiles/demo.toml" <<TOML
[profile]
name = "demo"
description = "Audit demo profile (no secrets)"
project_dir = "$DEMO_DIR/project"
extra_read_paths = []

[network]
allow = []

[secrets]

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

# Dummy "secret-like" string that must never be used with real values.
#
# It is passed as part of the argv (sh -lc <string>) and gets persisted in the
# audit DB in the SandboxCreated detail.
echo "\$ opaque exec --profile demo -- sh -lc 'echo password=dummy_value_123456 >/dev/null'"
opaque exec --profile demo -- sh -lc 'echo password=dummy_value_123456 >/dev/null'
echo
sleep 0.6

DB="$HOME/.opaque/audit.db"
echo "\$ sqlite3 \"$DB\" \"select kind, detail from audit_events where kind='sandbox.created' order by ts_utc_ms desc limit 1;\""
sqlite3 "$DB" "select kind, detail from audit_events where kind='sandbox.created' order by ts_utc_ms desc limit 1;"
echo
sleep 0.6

