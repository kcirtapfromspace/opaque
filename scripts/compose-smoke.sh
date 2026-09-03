#!/usr/bin/env bash
# End-to-end smoke test of the container trust-domain split (deploy/docker):
# daemon and agent in separate containers sharing ONLY the socket volume.
#
# Proves, against the real compose stack:
#   1. bootstrap seals the config under the daemon account
#   2. the daemon starts with trust_domain.enforce and verified custody
#   3. the agent container reaches the daemon through the socket (ping/version)
#   4. the custody volume has NO PATH inside the agent container
#   5. the socket surface carries split permissions (0750 dir / 0660 sock)
#   6. a client running AS the daemon account is refused (peer-uid inversion)
#
# Requires Docker. Builds Linux binaries via the same pinned container and
# cargo volumes as scripts/linux-harness.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/deploy/docker/compose.yaml" --project-name opaque-smoke)
IMAGE="rust:1.95.0-slim-bookworm" # keep in sync with rust-toolchain.toml
BIN_DIR="$REPO_ROOT/deploy/docker/bin"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mSMOKE FAILED: %s\033[0m\n' "$*" >&2; exit 1; }

step "building linux binaries (pinned container, shared cargo volumes)"
docker run --rm \
    -v "$REPO_ROOT:/work" \
    -v opaque-linux-target:/ctarget \
    -v opaque-linux-cargo-registry:/usr/local/cargo/registry \
    -v opaque-linux-rustup:/usr/local/rustup \
    -e CARGO_TARGET_DIR=/ctarget \
    -w /work "$IMAGE" \
    cargo build -p opaqued -p opaque

mkdir -p "$BIN_DIR"
docker run --rm \
    -v opaque-linux-target:/ctarget \
    -v "$BIN_DIR:/out" \
    debian:bookworm-slim \
    sh -c 'cp /ctarget/debug/opaqued /ctarget/debug/opaque /out/ && chmod 0755 /out/opaqued /out/opaque'
cp "$REPO_ROOT/deploy/docker/bootstrap.sh" "$BIN_DIR/bootstrap.sh"

step "clean slate"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

step "bootstrap (seed + seal config as the daemon account)"
"${COMPOSE[@]}" run --rm init | tee /tmp/opaque-smoke-init.out
grep -q "bootstrap: config sealed" /tmp/opaque-smoke-init.out \
    || fail "bootstrap did not seal the config"

step "start daemon"
"${COMPOSE[@]}" up -d opaqued

step "wait for socket"
"${COMPOSE[@]}" run --rm --entrypoint /bin/sh agent -c \
    'for i in $(seq 1 60); do [ -S /run/opaque/opaqued.sock ] && exit 0; sleep 0.5; done; exit 1' \
    || { "${COMPOSE[@]}" logs opaqued; fail "daemon socket never appeared"; }

step "assert: daemon custody verified + enforced (daemon logs)"
"${COMPOSE[@]}" logs opaqued | tee /tmp/opaque-smoke-daemon.log >/dev/null
grep -q "custody verified" /tmp/opaque-smoke-daemon.log \
    || fail "daemon did not report verified custody"
grep -q "listening on /run/opaque/opaqued.sock" /tmp/opaque-smoke-daemon.log \
    || fail "daemon did not bind the configured split socket"
grep -q "socket surface opened to group" /tmp/opaque-smoke-daemon.log \
    || fail "daemon did not open the socket surface to the client group"

step "assert: agent can ping the daemon across the split"
"${COMPOSE[@]}" run --rm agent ping || fail "agent ping failed"
"${COMPOSE[@]}" run --rm agent version || fail "agent version failed"

step "assert: custody paths do not exist inside the agent container"
"${COMPOSE[@]}" run --rm --entrypoint /bin/sh agent -c \
    '[ ! -e /var/lib/opaque ] && [ ! -e /etc/opaque ]' \
    || fail "agent container can see custody paths"

step "assert: socket surface permissions are the split shape"
"${COMPOSE[@]}" run --rm --entrypoint /bin/sh agent -c '
    set -e
    dirperm=$(stat -c "%a %u %g" /run/opaque)
    sockperm=$(stat -c "%a %u %g" /run/opaque/opaqued.sock)
    tokperm=$(stat -c "%a %u %g" /run/opaque/daemon.token)
    echo "dir=$dirperm sock=$sockperm token=$tokperm"
    [ "$dirperm" = "750 7381 7999" ]
    [ "$sockperm" = "660 7381 7999" ]
    [ "$tokperm" = "640 7381 7999" ]
' || fail "socket surface permissions are not the split shape"

step "assert: a client running AS the daemon account is refused"
if "${COMPOSE[@]}" exec -T opaqued /opt/opaque/opaque ping >/dev/null 2>&1; then
    fail "daemon-uid client was accepted — the peer-uid inversion is not enforced"
fi
echo "refused as expected"

step "teardown"
"${COMPOSE[@]}" down -v

printf '\n\033[32mSMOKE PASSED: container trust-domain split verified\033[0m\n'
