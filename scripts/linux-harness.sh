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
        -v opaque-linux-rustup:/usr/local/rustup \
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
    # them. Requires root (chown + seteuid across throwaway uids). In the
    # container we already are root; on a CI runner, re-run cargo under sudo
    # with the toolchain env carried across.
    local prefix=()
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            prefix=(sudo -E env "PATH=$PATH" "HOME=$HOME"
                "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}"
                "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}")
        else
            echo "isolation suite needs root (it creates throwaway uids)" >&2
            exit 1
        fi
    fi

    # Each invocation greps for its own non-vacuous pass: a renamed/filtered-out
    # test must fail the harness, never silently pass (repo convention).
    run_exact() {
        local pkg="$1" target_flag="$2" test_path="$3"
        "${prefix[@]}" cargo test -p "$pkg" $target_flag "$test_path" \
            -- --ignored --exact 2>&1 | tee /tmp/isolation-run.out
        grep -q "test result: ok. 1 passed" /tmp/isolation-run.out || {
            echo "isolation: $test_path did not actually run+pass" >&2
            exit 1
        }
    }

    run_exact opaque-core --lib trust_domain::tests::root_multi_uid_custody_matrix \
        || exit 1
    run_exact opaqued "--bin opaqued" trust_domain::tests::root_enforce_blocks_foreign_custody_then_privileges_drop \
        || exit 1
    echo "isolation suite: all suites ran as root and passed"
}

e2e_split() {
    # Full split e2e: real daemon as a dedicated uid, custody probes at the
    # agent uid, signature-bound approval through the real approval server.
    # Same root requirement and anti-vacuous grep guards as `isolation`.
    local prefix=()
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            prefix=(sudo -E env "PATH=$PATH" "HOME=$HOME"
                "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}"
                "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}")
        else
            echo "e2e-split needs root (it stages two principals)" >&2
            exit 1
        fi
    fi

    run_one() {
        "${prefix[@]}" cargo test -p opaqued --test trust_domain_e2e "$1" \
            -- --ignored --exact --test-threads=1 2>&1 | tee /tmp/e2e-split.out
        grep -q "test result: ok. 1 passed" /tmp/e2e-split.out || {
            echo "e2e-split: $1 did not actually run+pass" >&2
            exit 1
        }
    }
    run_one split_daemon_refuses_stolen_custody || exit 1
    run_one split_daemon_custody_and_signature_bound_approver || exit 1
    echo "e2e-split: split daemon verified end to end as root"
}

case "$CMD" in
    probe) probe ;;
    gate) gate ;;
    test) cargo test "$@" ;;
    isolation) isolation ;;
    e2e-split) e2e_split ;;
    all)
        probe
        gate
        ;;
    shell) exec bash ;;
    *)
        echo "unknown subcommand: $CMD (probe|gate|test|isolation|e2e-split|shell|all)" >&2
        exit 2
        ;;
esac
