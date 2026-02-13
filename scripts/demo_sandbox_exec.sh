#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT/target/release"

if [[ ! -x "$BIN_DIR/opaque" || ! -x "$BIN_DIR/opaqued" ]]; then
  echo "error: release binaries not found; run: cargo build --release" >&2
  exit 1
fi

export PATH="$BIN_DIR:$PATH"

run() {
  echo "\$ $*"
  "$@"
  echo
}

DEMO_DIR="$(mktemp -d /private/tmp/opaque-demo-sandbox-exec.XXXXXX)"
OPAQUED_PID=""

cleanup() {
  if [[ -n "${OPAQUED_PID:-}" ]]; then
    kill "$OPAQUED_PID" >/dev/null 2>&1 || true
    wait "$OPAQUED_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DEMO_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

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
description = "Demo profile (no secrets)"
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

SOCK="$XDG_RUNTIME_DIR/opaque/opaqued.sock"
TOKEN="$XDG_RUNTIME_DIR/opaque/daemon.token"
for _ in $(seq 1 200); do
  if [[ -S "$SOCK" && -f "$TOKEN" ]]; then
    break
  fi
  sleep 0.05
done

echo "\$ opaque exec --profile demo -- sh -lc 'echo \"hello from sandbox\"; echo \"stderr line\" 1>&2'"
opaque exec --profile demo -- sh -lc 'echo "hello from sandbox"; echo "stderr line" 1>&2'
echo
