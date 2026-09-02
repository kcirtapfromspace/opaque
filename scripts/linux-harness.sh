#!/usr/bin/env bash
# Linux verification harness for the trust-domain hardening work.
#
# The isolation guarantees this repo is growing (separate-uid custody, Landlock,
# seccomp, container split) are Linux-only and cannot be verified on a macOS dev
# box directly. This script gives every environment the same entry points:
#
#   on Linux  — runs natively (this is what CI calls)
#   on macOS  — re-runs itself inside a pinned rust container via Docker
#
# Subcommands:
#   probe            kernel capability probe (landlock + seccomp); nonzero if missing
#   gate             cargo fmt --check + clippy -D warnings + full workspace tests
#   test [args...]   arbitrary `cargo test` args, e.g. `test -p opaqued --test x`
#   isolation        multi-uid isolation suite (needs root; added by stage S1+)
#   shell            interactive shell in the container (macOS only)
#   all              probe + gate  (default)
#
# The container pins the same toolchain as rust-toolchain.toml. Named volumes
# hold the target dir and cargo registry so repeat runs are incremental.

set -euo pipefail

IMAGE="rust:1.95.0-slim-bookworm" # keep in sync with rust-toolchain.toml
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMD="${1:-all}"
[ "$#" -gt 0 ] && shift

in_docker() {
    # Re-invoke this script inside the pinned Linux container.
    local tty_flags=()
    [ -t 0 ] && tty_flags=(-it)
    docker run --rm "${tty_flags[@]}" \
        -v "$REPO_ROOT:/work" \
        -v opaque-linux-target:/ctarget \
        -v opaque-linux-cargo-registry:/usr/local/cargo/registry \
        -e CARGO_TARGET_DIR=/ctarget \
        -w /work \
        "$IMAGE" \
        bash "scripts/linux-harness.sh" "$@"
}

if [ "$(uname -s)" != "Linux" ]; then
    case "$CMD" in
        shell) in_docker shell ;;
        *) in_docker "$CMD" "$@" ;;
    esac
    exit $?
fi

# ---- everything below runs on Linux (native CI runner or inside the container)

probe() {
    local bin="${TMPDIR:-/tmp}/opaque-linux-probe"
    cc -O1 -o "$bin" "$REPO_ROOT/scripts/linux-probe.c"
    echo "kernel: $(uname -r) ($(uname -m))"
    "$bin"
}

gate() {
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
}

isolation() {
    # Multi-uid custody/ownership tests: the daemon principal must own the
    # custody files and the agent principal must be unable to read or write
    # them. Requires root (creates throwaway uids). Stages S1+ populate this.
    if [ "$(id -u)" -ne 0 ]; then
        echo "isolation suite needs root (it creates throwaway uids)" >&2
        exit 1
    fi
    echo "isolation: no suites registered yet (stage S1 adds the first)" >&2
    exit 1
}

case "$CMD" in
    probe) probe ;;
    gate) gate ;;
    test) cargo test "$@" ;;
    isolation) isolation ;;
    all)
        probe
        gate
        ;;
    shell) exec bash ;;
    *)
        echo "unknown subcommand: $CMD (probe|gate|test|isolation|shell|all)" >&2
        exit 2
        ;;
esac
