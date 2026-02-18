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

DEMO_DIR="$(mktemp -d /private/tmp/opaque-demo-security-1password.XXXXXX)"
OPAQUED_PID=""
MOCK_PID=""

cleanup() {
  if [[ -n "${OPAQUED_PID:-}" ]]; then
    kill "$OPAQUED_PID" >/dev/null 2>&1 || true
    wait "$OPAQUED_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${MOCK_PID:-}" ]]; then
    kill "$MOCK_PID" >/dev/null 2>&1 || true
    wait "$MOCK_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DEMO_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Throwaway HOME/XDG dirs so no real ~/.opaque state or secrets are touched.
export HOME="$DEMO_DIR/home"
export XDG_RUNTIME_DIR="$DEMO_DIR/xdg"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$DEMO_DIR/logs"
chmod 700 "$HOME" "$XDG_RUNTIME_DIR" >/dev/null 2>&1 || true

run opaque init

cat >"$HOME/.opaque/config.toml" <<'TOML'
# Demo-only policy: allow 1Password browsing + read_field without approvals.
#
# This demo intentionally shows plaintext output using a MOCK 1Password Connect
# server and a dummy field value. Do NOT use real secrets in this flow.
[[rules]]
name = "demo-allow-onepassword"
operation_pattern = "onepassword.*"
allow = true
client_types = ["agent"]

[rules.client]

[rules.approval]
require = "never"
factors = []
TOML

run opaque policy check

# Start a local mock 1Password Connect server and point opaqued at it.
mkdir -p "$DEMO_DIR/tmp"
PORT_FILE="$DEMO_DIR/tmp/mock_1p_port"

echo "\$ python3 scripts/mock_1password_connect.py  # (started in background)"
python3 "$ROOT/scripts/mock_1password_connect.py" --port 0 --port-file "$PORT_FILE" >"$DEMO_DIR/logs/mock-1p.log" 2>&1 &
MOCK_PID="$!"

for _ in $(seq 1 200); do
  if [[ -f "$PORT_FILE" ]]; then
    break
  fi
  sleep 0.05
done
PORT="$(cat "$PORT_FILE")"

export OPAQUE_DEMO_1P_TOKEN="demo_token_value"
export OPAQUE_1PASSWORD_TOKEN_REF="env:OPAQUE_DEMO_1P_TOKEN"
export OPAQUE_1PASSWORD_CONNECT_URL="http://127.0.0.1:${PORT}"

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

run opaque 1p list-vaults
run opaque 1p list-items --vault DemoVault

echo "\$ opaque 1p read-field --vault DemoVault --item DemoItem --field password"
opaque 1p read-field --vault DemoVault --item DemoItem --field password
echo
sleep 0.6

