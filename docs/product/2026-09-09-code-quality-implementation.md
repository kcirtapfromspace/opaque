# Code quality remediation and validation

Private engineering record, 2026-09-09. Implements the findings in [the review and gap plan](2026-09-09-code-quality-gap-plan.md), against base commit `e49b49e17aab4f1e73d42c8d6cce7b15de0bd711`. This record must remain excluded from public artifacts. The remediation was committed locally as `0dab7ef`; the checks below describe that pre-extraction tree. The subsequent merge of the local crate extraction and its separate validation are recorded in [the merge record](2026-09-09-quality-extraction-merge-validation.md). No deployment, remote branch, repository setting, or running cluster was modified.

## Implemented changes

| Finding | Result | Regression evidence |
| --- | --- | --- |
| F1: retention integrity | Verify before maintenance in an atomic transaction; authenticate the pruned prefix, sequence high-watermark, and row-ID boundary; preserve surviving hashes. Existing corruption stops startup. Legacy unchained schema migration is an explicit atomic baseline. | Retained corruption, missing tail, altered boundary, clock regression, rollback, full pruning/restart, and export cursor continuity. |
| F2: audit durability | Publish the in-memory hash only after commit. Flush returns storage, timeout, closed, or backpressure errors; losses stay visible. Duplicate IDs fail instead of silently acknowledging different content. Close owns and drains its channel and threads. | Failure injection at row/head/commit boundaries; recovery, dropped/synthetic events, fanout, concurrent verify/write/retention, close races. |
| F3: unsafe retries | Retry only connection establishment. Once delivery starts, failure produces an uncertain outcome without replay. CLI and MCP share strict response-envelope validation. | Disposable Unix servers observe one dispatch after a lost response; startup retries, deadlines, mismatched IDs, malformed envelopes, and legitimate null results. |
| F4: connection exhaustion | Five-second whole-frame handshake deadline and bounded writes; shutdown-aware reads; owned permit/accounting guard. | Silent/partial prefix/partial body, valid handshake, shutdown, saturation, abort/panic, stalled writes. |
| F5: protocol panics | Validate MCP object/schema inputs; use one Unicode-safe truncator; count sandbox output without retained plaintext copies. | Every Unicode scalar and byte boundary; actual MCP process malformed-input corpus followed by a successful ping; multibyte output. |
| F6: protocol stalls | Up to eight in-flight MCP calls, responsive control messages, bounded local blocking work, cancellation, and operation-aware deadlines. | Stalled broker, capacity, ping/list, cancellation, malformed UTF-8, oversized frame recovery, and no false success. |
| F7: receipt pagination | Owner-indexed keyset query fetches at most 101 rows and decodes at most 100, with a 96 KiB page budget. Expiry refresh touches only returned records. | Corrupt unvisited history cannot break the first page; owner/cursor/insert/expiry cases and 1,000/100,000-record scalability harness. |
| F8: repeated compilation | Share immutable secret patterns and URL/path regexes; compile operation schemas at registration and MCP schemas once. Invalid built-ins fail visibly. | Existing redaction/schema corpus, shared validator identity checks, and a dedicated release benchmark. |
| F9: dashboard evidence race | Single-flight refresh with coalesced follow-up, filter-generation rejection, retained concurrent evidence, independent stream cursor, and failure retention. | Reordered refresh, changed filters, burst coalescing, stream/snapshot ordering, and failure tests using the shipped script. |
| F10: slow catch-up | Drain full 100-event pages immediately; sleep at the tail; index sequences for range reads; move SQLite page queries to blocking workers; cancel buffered delivery; batch rendering per frame. | Actual SSE resume/cancellation regression, real-schema query-plan assertion, and explicit large-backlog load harness. |
| F11: blocking metrics durability | Dedicated bounded audit writer (32 queued records, five-second acknowledgment), sticky storage failure, retained state custody during canceled writes, separate eight-slot provider admission. Organization transitions run on blocking workers; async state contention fails closed. | Slow/failing storage, overload, timer responsiveness, cancellation/custody, provider concurrency, and gateway authorization/disclosure tests. |
| F12: capability drift | Live inventory derives from the selected daemon's registry, installed handlers, task ledger, and trusted task profiles; shared MCP routing metadata; enabled/disabled/fixture-only status and explicit execution paths. Demo data is explicitly synthetic and disconnected requests fail. | Registry inventory contract across all eight task/profile configuration combinations, adapter route agreement, selected/disconnected/malformed daemon responses, and UI availability labels. |

The daemon now also waits for durable audit evidence before registered operation dispatch and successful disclosure, before returning a successful control approval, and around each bounded task effect. These waits use a bounded blocking-worker admission limit, with permits held until the underlying wait finishes even after cancellation. Task receipts retain their independent durable reservation/finalization contract. If audit persistence fails after a provider effect, no successful payload is returned and later effects stop; the existing receipt remains the reconciliation path. Denials and diagnostics remain asynchronous because they cannot grant an effect.

Sandbox lifecycle review additionally found that the direct execution timeout reset on output and that collector waits could retain sender clones after completion. The collector now terminates on the completion frame and drops promptly on execution error; execution uses an absolute deadline and explicit child/reader custody. Native platform validation remains necessary for the platform-specific isolation guarantees.

## Continuing quality gates

- **G1:** CI now runs the existing Python and JavaScript suites, installs the pinned FIDO2 test dependency, rejects skipped/vacuous required Python suites on Linux, and runs native macOS Rust tests on pull requests. Existing Linux trust-domain enforcement probes remain in place.
- **G2:** A nonpublishing private-repository CI job builds a disposable docs source with private sentinels, then checks generated HTML routes, all asset bytes, compressed content, search data, and sitemaps. Its adversarial fixtures must fail for leaked content and unreviewed routes. Publication guards are preserved.
- **G3:** Added exhaustive Unicode property coverage, real protocol corpus tests, transaction and transport fault injection, scheduling regressions, and reproducible release/scalability harnesses. These targeted checks run production boundaries. They are not a claim of exhaustive fuzzing or production capacity certification.
- **G4:** Extracted native approval into `opaque-native-approval`, removed the approver's source-path import, made task API dependencies explicit, and isolated connection, durability, and process-custody helpers. Sanitized responses have private fields and validated task-receipt construction; a compile-fail contract prevents post-sanitization mutation. Large entrypoints can be decomposed further as specific behavior is changed and characterized.

## Performance evidence

Host: Apple M1 Ultra, arm64, macOS 26.6.2, Rust 1.95.0. `cargo bench --locked -p opaque-core --bench validation` runs seven timed samples after warmup under the workspace optimized release profile. Numbers below are local diagnostics, not production SLOs; concurrent build activity and allocator/runtime variance can affect timings.

| Case | Median nanoseconds per call |
| --- | ---: |
| Empty target validation | 10 |
| Small target validation | 267 |
| Audit target summary | 1,397 |
| Secret-reference metadata validation | 345 |
| Cached schema validation | 151 |
| Compile and validate the same schema | 3,918 |

The same release harness initially measured target summaries at 346,719 ns after secret-pattern caching. That exposed remaining per-call URL-regex compilation. Caching those exact patterns reduced the measured median to 1,397 ns. This is a comparison between two local implementations in this change, not a claimed whole-application speedup or comparison against an unmeasured release build of the original commit.

Receipt and SSE load tests have explicit ignored entrypoints so routine correctness checks do not acquire machine-speed-dependent latency budgets. After the crate extraction, run the receipt harness with `cargo test --release --locked -p opaque-bounded-work --lib task_pagination_scales -- --ignored --nocapture`. It reports history size, returned rows/bytes, and page latency; bounded work is enforced separately by the ordinary regression.

The release receipt run returned 100 rows and 97,201 serialized bytes for both histories: the first page took 1.379 ms with 1,000 stored receipts and 1.120 ms with 100,000. These are single observations, not latency percentiles. The ordinary regression verifies that corrupt unvisited history is not decoded; existing authority-transition tests continue to cover concurrent claim/reservation/revocation.

The explicit SSE harness is `cargo test --release --locked -p opaque-web --bin opaque-web audit_backlog_load_baseline -- --ignored --nocapture`. It checks every delivered sequence while a concurrent producer adds 2,000 more events to a 20,000-event backlog, then checks cancellation. The fixture uses the same sequence index as production; a separate test opens the actual audit sink's schema and checks the production streaming query uses an indexed range without a temporary sort.

The final release SSE run drained the initial 20,000-event backlog in 58 ms and delivered all 22,000 events in 2,085 ms, including a producer averaging 955.0 events/second. It verified exact sequence continuity, a page buffer of at most 100, and cancellation under 250 ms. These synthetic rows are small; the total duration includes waiting for the two-second producer. This is neither a saturated throughput figure nor a production workload claim.

## Release evidence and limits

Local checks passed:

| Check | Result |
| --- | --- |
| `cargo test --locked --workspace --quiet` | 1,942 passed; seven intentional ignores. |
| `cargo test --locked -p opaque-core -p opaque-web --quiet` after the final sequence-index change | 471 passed, including the new real-schema query-plan regression; one explicit load-test ignore. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed on the final source. |
| `cargo fmt --all -- --check` and `git diff --check` | Passed. |
| Python 3.12.11 with `scripts/requirements-test.txt`, scripts and hosted-demo suites | 208 passed; two Linux-only skips on macOS. All FIDO2-library tests executed. |
| All four Node worker/browser suites | 167 passed. |
| Pinned strict MkDocs generated-site check | Passed; 42 marked private source fixtures excluded from HTML, assets, search, and sitemaps. |
| Explicit release receipt/SSE load checks | Passed; measurements above. |
| Synthetic audit-report concurrency fixtures | 100 repeated iterations of two tests across four concurrent processes passed. |

The default Rust ignores comprise the two separately executed load diagnostics, three authenticated 1Password desktop cases, one private disposable SSH/Vault service case, and the interactive browser fixture. Linux-only root enforcement probes are compiled/run on the Linux CI path rather than this macOS host. An earlier audit test assumed a paused writer could not consume a queued item; its nondeterministic assertion was replaced with a deterministic no-consumer fixture plus the real-writer durability integration test.

Remote CI has been configured but has not run for this unpushed work. Repository branch-protection settings have not been changed, so making the new jobs mandatory for merging is an administrator/release configuration step. Linux-only enforcement must pass on its Linux runner; native human authentication, physical FIDO2 devices, live provider side effects, release installation, and production soak measurements are separate release evidence and were not simulated as successful here.

iOS remains a visibly deferred prototype. Unsigned AWS transport remains limited to explicit loopback fixtures. Neither is promoted to a supported production capability by these fixes. The work closes concrete reviewed defects and adds repeatable checks; it does not establish a subjective equivalence with another project's overall engineering quality.
