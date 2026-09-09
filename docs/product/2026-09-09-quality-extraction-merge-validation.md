# Quality remediation and crate extraction merge

Private engineering record, 2026-09-09. This local merge integrates `main` at `2adcff3` (the seven-crate daemon extraction and showcase rename) into `codex/quality-remediation` at `0dab7ef`. Neither history is discarded. This record must remain excluded from visitor HTML, assets, search, sitemaps, and previews.

## Source and command locations

| Previous location | Merged location |
| --- | --- |
| `crates/opaque-metrics/`, package/binary `opaque-metrics` | `crates/opaque-showcase/`, package/binary `opaque-showcase` |
| Daemon `sandbox/` | `crates/opaque-sandbox/src/` |
| Daemon `task_api.rs`, `task_store.rs`, `ssh.rs`, `inference/` | `crates/opaque-bounded-work/src/` |
| Daemon provider modules | `crates/opaque-providers/src/` |
| Daemon federation, export, attestation modules | `crates/opaque-federation-runtime/src/` |
| Daemon approval, factor, FIDO2, pairing, push modules | `crates/opaque-approval/src/` |
| Daemon tenant module | `crates/opaque-tenant/src/tenant.rs` |
| Daemon resolver and secret types | `crates/opaque-core/src/resolver.rs`, `secret.rs` |

Native review and authentication remain in the shared `opaque-native-approval` crate. `opaque-approval` re-exports it, and the workstation approver depends on it directly, preserving one implementation without a source-path import or dependency cycle. The sandbox manifest carries the common `libc` dependency required by process custody and Tokio's test utilities for the moved lifecycle regressions.

The extracted GitHub RPC helper also delegates truncation to the shared Unicode-safe implementation. A regression covers a multibyte character crossing its byte limit. Catalog fixtures use public provider constructors across the new crate boundary. Formatting fixes bring inherited extraction files into compliance with the workspace gate.

The relocated showcase audit writer is preserved, including bounded admission, durable acknowledgments, sticky failure, and lock custody. Its metrics/provider and server changes match the remediation versions. The existing module declaration and crate-relative imports connect it to the renamed package.

CI uses the new showcase Node-test path and explicitly enables every provider feature for workspace tests and Clippy. Python discovery remains under `scripts` and `deploy/hosted-demo`. Daemon wrapper, federation, provider, and Linux isolation selectors still point to their existing tests. Publication workflow guards and public release archive membership remain unchanged.

The local metrics harness builds and launches `opaque-showcase`. Hosted-demo image inputs, runtime default binary path, and operational instructions use that name. Existing `OPAQUE_METRICS_*` environment names, cookies, and MCP tool names remain protocol-compatible. Building or deploying a replacement image is a separate step; no running demo was changed by these edits.

Current commands for the relocated checks:

```sh
node --test deploy/cloudflare-demo/tests/*.test.mjs deploy/cloudflare-docs-privacy/tests/*.test.mjs crates/opaque-showcase/tests/*.test.cjs crates/opaque-web/tests/*.test.cjs
cargo test --release --locked -p opaque-bounded-work --lib task_pagination_scales -- --ignored --nocapture
cargo test --locked -p opaque-bounded-work --lib ssh::tests::live_vault_host_execution -- --ignored --exact
cargo build --locked --release -p opaque-showcase
```

The SSH command requires the disposable private Vault/host fixture; use `scripts/ssh_vault_dogfood.py` to construct it. The extraction does not turn an ignored integration test into a standalone test without those services. Historical reviews retain their original evidence locations and pre-merge results; those are not assertions about this merged tree.

## Validation

Checks executed after the path adaptations on this macOS checkout:

| Check | Outcome |
| --- | --- |
| `cargo test --locked --workspace --all-features --quiet` | 1,957 passed; zero failures; seven intentional ignores. Includes the extracted libraries, daemon integration suites, and documentation contracts. |
| `cargo clippy --locked --workspace --all-features --all-targets -- -D warnings` | Passed. |
| `cargo fmt --all -- --check` and staged/unstaged `git diff --check` | Passed. |
| Node 26.8.1, all four worker/browser suites using the showcase path above | 167 passed, no failures or skips. |
| Python 3.12.11, pinned requirements, `scripts` discovery | 140 run: 138 passed and two Linux-only skips. The installed FIDO2 library checks executed. |
| Python 3.12.11, pinned requirements, `deploy/hosted-demo` discovery | 70 passed, no skips. |
| Pinned strict MkDocs build plus generated-site privacy inspection | Passed: 43 marked private source fixtures excluded, including this record. HTML, asset bytes, search, and sitemap inspected. |
| Python AST parsing, CI YAML parsing, required feature flags and nonempty Node globs | Passed. |
| Relocated showcase audit writer, metrics, metrics regressions, and server | Byte-identical to their `0dab7ef` implementations; existing module/import wiring verified. |
| Linux harness source selectors | Core/daemon trust-domain and daemon split tests remain present. Kernel probes and zero-tests guards are preserved. No moved sandbox selector exists in this harness. |

Reproduce the Python and artifact checks without installing into the system interpreter:

```sh
uv run --no-project --python 3.12.11 --with-requirements scripts/requirements-test.txt python -B -m unittest discover -s scripts -p 'test_*.py'
uv run --no-project --python 3.12.11 --with-requirements scripts/requirements-test.txt python -B -m unittest discover -s deploy/hosted-demo -p 'test_*.py'
uv run --no-project --python 3.12.11 --with-requirements scripts/requirements-test.txt python -B scripts/check_site_privacy.py --build
```

The integration pass verified that the merged lockfile keeps the exact external package names, versions, and sources from local `main`; only workspace package membership/dependency edges changed. A separate source review confirmed that the extracted task and federation paths retain audit barriers, durable reservation/finalization, live authority checks, cancellation guards, and export continuity. The seven Rust ignores are the two explicit load diagnostics, three authenticated desktop-provider cases, the private SSH/Vault fixture, and an interactive browser fixture.

The validated merge retains both `0dab7ef` and `2adcff3` in its ancestry and is prepared for a fast-forward of local `main`. No remote CI, push, release, deployment, compiled-WASM Node extension, or Linux enforcement run is claimed by the checks above. Running cluster workloads were not changed.
