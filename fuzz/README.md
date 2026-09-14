# Exercise production parsers with generated inputs

Run the same parsers used by the CLI and MCP transport, with AddressSanitizer,
shrinking and a fixed seed. No daemon, provider credentials or network service
is used by the targets. Installing tools and fetching locked dependencies needs
registry access; target execution uses Cargo offline mode.

```sh
rustup toolchain install nightly-2026-09-13 --component rust-src
cargo install cargo-fuzz --version 0.13.2 --locked
python3 -B scripts/run_parser_fuzz.py \
  --output /tmp/opaque-parser-smoke \
  --target-dir /tmp/opaque-parser-build
```

The output directory must be new. The runner discovers every target declared in
`fuzz/Cargo.toml`, copies reviewed synthetic seeds to its output directory, and
requires each target to finish at least 2,000 executions. It fails on crashes,
timeouts, absent seeds, zero executions, dependency versions differing from the product lock, dependency-lock changes or source
changes. CI runs this independently of the workspace coverage gate. The fuzz
workspace is executable test tooling; every product crate remains measured by
the parent workspace policy.

| Target | Actual production entry point | Additional assertions |
|---|---|---|
| `policy_document` | CLI TOML policy document and semantic checks | JSON roundtrip preserves validation results and ordered policy digest |
| `mcp_request` | Stdio JSON-RPC envelope parser and recoverable line decoder | Envelope ID/version validity, roundtrip, invalid-version rejection and recovery after malformed lines |
| `daemon_response` | Broker response decoder | Exact request correlation, exclusive result/error, null preservation, missing/wrong-ID rejection |
| `task_manifest` | Typed manifest decoding, validation and canonicalization | Digest stability, canonicalization idempotence, invalid expiry/title rejection |

Inputs are capped at the protocol frame boundary (128 KiB, with two framing
bytes for MCP). Each input has a five-second timeout; the process has a 2 GiB
RSS limit. The runner uses `--no-cfg-fuzzing` so production checks are not
compiled out for the campaign. It retains source identity, lock hash, completed
execution counts and log hashes in `report.json`. Generated corpora, failure
inputs and logs stay in the chosen output directory; review and minimize a
reproducer before adding a synthetic regression fixture to the repository.

Increase the bounded campaign size or change the seed deliberately:

```sh
python3 -B scripts/run_parser_fuzz.py \
  --output /tmp/opaque-parser-campaign \
  --target-dir /tmp/opaque-parser-build --runs 1000000 --seed 1729
```

To reproduce one retained failing input, use the pinned toolchain and the same
production configuration:

```sh
cargo +nightly-2026-09-13 fuzz run --no-cfg-fuzzing \
  mcp_request /tmp/opaque-parser-campaign/artifacts/mcp_request/crash-INPUT_HASH
```

A smoke pass proves the listed execution completed; it is not exhaustive input
coverage. Rejected input paths principally check robustness, while accepted
inputs exercise the listed semantic assertions. Fuzz executions are not counted
as separate Rust tests, and do not qualify provider integrations or physical
approval. Policy decision properties run separately with
`cargo test --locked -p opaque-core --test policy_properties`. They cover
ordered decisions, approval obligations and UID narrowing, not every matcher.
Use `PROPTEST_RNG_SEED=424242` to replay a campaign; keep minimized failure seeds
when they reveal an actual production regression.

The [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
and [Proptest configuration guide](https://proptest-rs.github.io/proptest/proptest/tutorial/config.html)
describe the underlying runners and shrinking behavior.
