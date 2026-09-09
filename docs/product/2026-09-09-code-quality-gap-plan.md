# Code quality review and gap plan

Private engineering assessment, 2026-09-09. Reviewed checkout: e49b49e17aab4f1e73d42c8d6cce7b15de0bd711. This document belongs under docs/product and must remain excluded from public site artifacts.

This is the historical review of that checkout. Subsequent fixes and validation are recorded in [Code quality remediation and validation](2026-09-09-code-quality-implementation.md).

The codebase contains substantial working engineering, but its quality is uneven. The most consequential gaps are recovery after partial failure, durable audit correctness, transport lifecycle bounds, and enforcement of existing tests. Those gaps matter more than stylistic cleanup for a broker whose value depends on trustworthy authorization and evidence. Four findings below merit P1 treatment before relying on the affected paths in broader production use.

“Lazy coding” is not an observable author trait. Observable shortcut patterns here include treating a failed write as committed, retrying across a side-effect boundary, adding pagination only after loading everything, maintaining copied capability metadata, and testing a copy of an implementation instead of its public boundary. These are concrete targets for improvement.

This was a broad, risk-directed review, not an exhaustive certification of roughly 140,000 tracked lines across the examined source languages, scripts, tests, and HTML. Three parallel reviews covered daemon/core, metrics/web/mobile, and adapters/CI/scripts. The primary review checked the findings, examined validation and sanitization costs, and researched the requested reference projects. Production code was not changed; no services, deployments, or remote repositories were modified.

## What the Ghostty reference means in practice

The useful standard is a set of engineering habits with observable outcomes:

- **Understand the system affected by a change.** Ghostty explicitly expects contributors to explain their changes and interactions with the wider system. Apply that here through a short account of invariants, failure paths, and validation for each substantive change. [Ghostty contributing guide](https://github.com/ghostty-org/ghostty/blob/main/CONTRIBUTING.md).
- **Exercise recovery, not just successful execution.** Hashimoto describes injecting failures at named points and checking cleanup and resulting state. For Opaque, the equivalents are failed SQLite commits, lost acknowledgments, interrupted subprocesses, revoked authorization, and disconnected clients. [Testing error recovery](https://mitchellh.com/writing/tripwire).
- **Diagnose performance with a reproducer.** The Ghostty memory-leak investigation connected a specific workload, resource ownership, measurement, and regression coverage. Apply that process to receipt history, audit backlogs, request validation, and slow storage. [Ghostty memory-leak investigation](https://mitchellh.com/writing/ghostty-memory-leak-fix).
- **Complete small, usable slices.** Hashimoto also advocates early demos and intentionally incomplete intermediate components. A prototype is legitimate when its boundaries are explicit; each supported Opaque feature needs a working path from request through authorization, execution, and truthful evidence. [Building large technical projects](https://mitchellh.com/writing/building-large-technical-projects).
- **Verify the actual platform and artifact.** Ghostty documents native input matrices, memory tools, distribution checks, and VM integration tests. Opaque needs platform-specific approval/isolation checks and verification of the artifact it actually deploys. [Ghostty development guide](https://github.com/ghostty-org/ghostty/blob/main/HACKING.md).

These are adaptations to Opaque's Rust broker and applications, not a claim that a language change, framework rewrite, or larger test count establishes equivalence with Ghostty. Ghostty's own documented defects and manual testing limitations also show why the target must be a repeatable engineering process.

## Findings, ordered by consequence

P1 means a reachable integrity or availability defect to close first. P2 means a concrete robustness, scalability, completeness, or verification gap. “Reproduced” distinguishes executed probes from source-traced findings; an unmeasured performance consequence is identified as such.

### F1 — P1: Retention can authenticate corrupted audit history

**Evidence:** crates/opaque-core/src/audit.rs:1410-1412 runs retention and then backfill_chain; :1090-1137 recomputes surviving hashes. The daemon opens that sink at crates/opaqued/src/main.rs:1490 and verifies only afterward at :1503. Periodic retention repeats the same behavior at audit.rs:1679-1691.

**Failure:** when at least one record expires, existing corruption in a retained record can be signed again using the legitimate chain key. The later integrity check reports success. This undermines tamper evidence even without an attacker obtaining the key; accidental corruption can also be absorbed.

**Reproduced:** write one legitimately aged event and one recent event; modify the recent detail through SQLite without updating its hash. Verification fails before reopening and succeeds after reopening with retention enabled. The modified detail survives.

**Close the gap:** verify existing evidence before destructive maintenance. Preserve an authenticated boundary for the pruned prefix rather than silently signing retained contents again. Make pruning and boundary updates atomic. Treat legacy migration as a separately specified trust transition. An invalid existing chain must not be “repaired” implicitly.

**Acceptance:** valid pruning succeeds; corruption in a retained row and tail deletion remain detectable when old rows are also eligible for removal; interruption at every maintenance step leaves either the previous valid state or the new valid state. Replace the current retention test's reliance on modifying an already-signed timestamp with legitimately aged fixture events.

### F2 — P1: Failed audit transactions corrupt subsequent writes and obscure durability failure

**Evidence:** audit.rs:1840 changes the in-memory last_hash before the head update and commit at :1847-1850 succeed. The writer increments its committed counter and clears the batch even on insertion failure at :1661-1672. AuditSink::flush returns no result at :725 and :1898.

**Failure:** SQLite rollback restores the database but not the in-memory chain head. The next successful write chains from a nonexistent record. Callers cannot distinguish successful durability from a failed batch settling or a flush timeout.

**Reproduced:** an isolated SQLite trigger rejected a chain_head update after row insertion. Flush returned while the failed event was absent. After removing the trigger, the next event was written, but chain verification reported a break at record 2, sequence 2.

**Close the gap:** calculate a transaction-local candidate head and publish it only after commit. Track accepted, committed, and failed outcomes separately. Return an explicit durability result and expose writer health. Define which authorization/receipt events require a durable acknowledgment before proceeding; keep best-effort telemetry distinct. Retry failed persistence only with explicit event deduplication and bounded policy.

**Acceptance:** injected row-insert, head-update, commit, storage-full, and writer-termination failures produce explicit errors; recovery does not poison the chain; no success acknowledgment represents missing durable evidence.

### F3 — P1: CLI retries can duplicate already-dispatched commands

**Evidence:** crates/opaque/src/main.rs:3693-3709 retries the whole call_once on connection errors, exempting only task_run. The exec command uses method exec at :2778; opaqued creates a new execution UUID for every such request at crates/opaqued/src/main.rs:6328.

**Failure:** a reset after a side effect but before its response can cause another execution. The loop permits four attempts. A connection failure does not establish that the original command did nothing. Source-traced; this review did not reproduce an actual duplicate side effect.

**Close the gap:** distinguish connection establishment from request dispatch. Retry safely before dispatch; after a non-idempotent dispatch, return an explicit uncertain outcome or reconcile a stable durable request identifier. Use an explicit read-only retry classification. Provider idempotency, where available, should be part of the operation contract. A broker alone cannot promise exactly-once remote effects across every crash boundary.

**Acceptance:** a disposable server that reads a command, records the simulated effect, and resets before replying receives no second unsafe execution; reads still recover from pre-dispatch connection failures; task_run keeps its existing uncertainty behavior.

### F4 — P1: Incomplete handshakes can occupy every connection slot indefinitely

**Evidence:** opaqued/src/main.rs:3191 waits for the first frame without a timeout or shutdown branch. The 30-second timeout starts only at :3250. The daemon has 64 permits (:2119), acquired before handling the connection (:2153).

**Failure:** a local peer admitted by the socket/peer boundary can open 64 connections and send no complete handshake. Legitimate connections are then rejected indefinitely. A daemon token is not needed to occupy these slots. This is a local reachability issue, not an assertion of public-network exposure.

**Close the gap:** bound the entire handshake, including a partial length prefix or partial body, and observe shutdown while waiting. Use owned guards for all connection accounting and bounded response writes.

**Acceptance:** silent and partial-frame clients expire; saturation recovers automatically; shutdown promptly releases all permits; valid slow handshakes within the documented budget continue to work. Source-traced; no running daemon was saturated during review.

### F5 — P2: Protocol boundary handling can panic on valid JSON or Unicode

**Evidence:** opaque-mcp/src/main.rs:155 accepts any JSON arguments value; tools.rs:208-214 mutates a string key on its clone. Arguments containing an array can panic. main.rs:178 slices an unknown tool name at an arbitrary byte boundary. A name of 63 ASCII characters followed by é crosses byte 64 and panics. The existing test at :754 exercises a copied ASCII slicing expression rather than the handler.

**Related locations:** opaqued/src/main.rs:2200 truncates client strings the same way. sandbox/mod.rs:198 and :208 truncate UTF-8 output, and :222 ignores a collector join failure. The captured strings are not returned, so retaining them is unnecessary for the output counts.

**Close the gap:** validate object and schema requirements before parameter construction; use one tested byte-budget truncator that respects character boundaries. Count sandbox output without unnecessary plaintext copies and propagate collector failures. Unexpected request failures must not break unrelated requests or connection accounting.

**Acceptance:** actual stdio/IPC tests send arrays, scalars, null, missing fields, and multibyte text across every limit, then successfully ping afterward. Add mixed-Unicode subprocess output cases. The panic paths are source-traced, not a full binary reproduction in this review.

### F6 — P2: A stalled daemon response blocks the entire MCP reader

**Evidence:** opaque-mcp/src/daemon_client.rs:104 waits without a response deadline; opaque-mcp/src/main.rs:489 awaits the call inside the serial stdin loop. CLI response reading at opaque/src/main.rs:3768 also has no deadline.

**Failure:** one accepted connection that never replies prevents later MCP ping, listing, and cancellation messages from being processed. A connect timeout does not bound the request lifecycle.

**Close the gap:** define operation-aware deadlines, keep the protocol reader responsive with bounded request concurrency, and connect cancellation to owned resources. Combine timeout reporting with F3's uncertainty semantics; a timeout must not become authorization to replay a side effect.

**Acceptance:** a fake daemon that accepts but never replies reaches a defined terminal outcome; ping and cancellation remain responsive during long operations; queues, task counts, and outstanding responses stay bounded.

### F7 — P2: Receipt pagination performs full-history work for every page

**Evidence:** opaqued/src/task_store.rs:389 calls list, which selects, decodes, validates, and potentially updates every owner receipt within an immediate transaction (:359-375). Only afterward does list_page seek its cursor and apply the 96 KiB response limit.

**Consequence:** each page consumes O(total history) CPU and memory under the shared connection mutex. Traversing many bounded pages approaches quadratic work as history grows, competing with claims and revocations. Wire size is bounded; database work is not. This follows from the query and loop structure; production latency was not measured.

**Close the gap:** resolve owner-scoped cursors to stable database ordering keys and fetch bounded keyset pages with an appropriate index. Stop decoding at the row/byte budget. Move bulk expiry maintenance out of listing while preserving expiry checks in authority-changing operations.

**Acceptance:** compare 1,000 and 100,000 receipts; instrument rows decoded, bytes retained, and lock duration per page. Work must scale with the page, not the entire owner history. Test cursor ownership, inserts between pages, expired records, and concurrent revoke/claim operations.

### F8 — P2: Fixed validation machinery is rebuilt on request paths

**Evidence:** opaque-core/src/validate.rs:130 and :178 compile all secret patterns for each validation call; audit.rs:408 does so for each target summary, even empty input. operation.rs:156 compiles a JSON Schema validator per validation, called by enclave.rs:850. task_api.rs:46 creates another sanitizer per request. Other modules already use cached patterns, showing an existing local approach.

**Consequence:** repeated compilation and allocation add avoidable fixed CPU work before meaningful request processing. A diagnostic dev-mode probe confirmed material work even on empty input; it is not a release throughput measurement.

**Close the gap:** share immutable compiled patterns, fail startup or tests on invalid built-in patterns, and compile immutable operation schemas when building the registry. Preserve input/output behavior and error semantics. The current filter_map at sanitize.rs:178 silently discards a pattern that fails compilation; do not let that become a missing security rule.

**Acceptance:** instrument compilation counts so steady-state requests compile no fixed patterns or schemas. Compare release-mode validation/enclave benchmarks before and after on a fixed machine with representative sizes; retain all redaction and schema rejection cases. Choose further optimizations from profiles.

### F9 — P2: Concurrent audit refreshes can replace newer visible evidence with older results

**Evidence:** opaque-web/static/index.html:1434-1436 launches a full audit request for each streamed event when full-text search is active. Responses overwrite state at :1372-1380 without a generation or ordering check.

**Reproduced:** run two refreshes using the shipped dashboard script in a Node VM. Resolve the newer result containing sequence 102, then the older result containing 101. The visible event becomes 101 while the resume cursor remains 102. Event 102 disappears from the visible snapshot and will not be replayed by that resume cursor. The persisted database is not changed by this UI bug.

**Close the gap:** coalesce refreshes, bind responses to the filter generation, and preserve evidence newer than an installed snapshot. Separate a stream's consumption cursor from a snapshot's completeness watermark.

**Acceptance:** deterministic reordered-response, filter-change, refresh-failure, and reconnect tests. A 100-event burst must create bounded refresh work rather than 100 concurrent requests.

### F10 — P2: Audit catch-up sleeps even while known backlog remains

**Evidence:** opaque-web/src/sse.rs:56-60 sleeps 500 ms before each query; :94 caps the query at 100 events.

**Consequence:** catch-up has a theoretical ceiling of 200 events/second before processing overhead. A 20,000-event backlog takes at least 100 seconds; arrivals above that rate cannot be drained. The browser also rebuilds up to 200 rows for each event at static/index.html:1272-1312. These bounds are derived from code, not a live load test.

**Close the gap:** immediately drain full pages and sleep only at the current tail, with cancellation and downstream backpressure preserved. Batch rendering per animation frame. Consider a shared bounded producer only if measurements justify its added complexity.

**Acceptance:** replay 20,000 events while a synthetic producer exceeds the old ceiling; verify sequence completeness, bounded memory and request counts, recovery to the tail when capacity permits, and responsive cancellation. Record measured latency on the benchmark host.

### F11 — P2: Metrics audit durability blocks async request workers

**Evidence:** opaque-metrics/src/server.rs:456-466 takes a shared standard mutex and calls file sync_data directly from request handling. The chat semaphore at :2091 does not bound external MCP provider queries at :1964-1987 and :2553-2591.

**Consequence:** slow storage blocks the executor worker doing the write; other workers can block waiting for the same mutex. Unrelated endpoints and timers can be delayed. The blocking mechanism is statically established; production impact remains unmeasured.

**Close the gap:** use a bounded writer outside async workers with asynchronous durability acknowledgments and explicit failure/saturation behavior. Preserve durable authorization before source access and durable observation before disclosure. Bound external source work separately; putting nested chat-to-MCP work behind the same fully occupied semaphore can deadlock.

**Acceptance:** inject slow and failed storage while saturating source queries. Verify unrelated endpoint/timer responsiveness, bounded queues, cancellation, and refusal to disclose results when required evidence is not durable.

### F12 — P2: Live capability metadata is copied and already incomplete

**Evidence:** opaque-web/src/routes/operations.rs:4-129 returns the same 15 hardcoded operations in live and demo modes. It does not query the selected daemon or derive data from the operation registry; registry additions at opaqued/src/main.rs:1295 and elsewhere cannot update this list.

**Failure:** users receive stale descriptions of the connected system. Registered, enabled, policy-permitted, and MCP-exposed are also different states; a copied catalog cannot reliably express them. Registration alone must not present a mock-only provider as available.

**Close the gap:** expose an authenticated read-only capability view based on authoritative registry and handler availability metadata. Keep demo metadata explicitly synthetic and disconnected state explicit. Derive shared descriptions/schema where practical without merging the adapters' different authorization boundaries.

**Acceptance:** contract tests compare the view with the configured daemon and adapter exposure rules, including disabled providers, restricted operations, disconnected mode, and newly registered capabilities.

## Cross-cutting gaps that let these defects persist

**G1 — Existing verification is not enforced across the repository.** .github/workflows/ci.yml runs Rust checks on Ubuntu. The Python script/controller and Node worker/browser suites are absent. Native macOS code is compiled out of those jobs; tag-time release builds do not replace pre-merge tests, and release jobs are guarded off in this private repository. Add required private-repository jobs for the existing suites and a native macOS build/test job. Exercise Linux-only cases on Linux and install the pinned FIDO2 test dependency where those tests are required. A missing dependency should not turn required verification into a green skip.

**G2 — Generated-site privacy has no required build gate here.** Entire jobs in deploy-site.yml:46 and pages.yml:24 are skipped for the private repository. The current generated artifact passed the review's exclusion check; no current leak was demonstrated. Retain publication guards and introduce an independent build/privacy job that inspects generated HTML, search, sitemap, and assets. Use private sentinel content and route/content checks so omitting navigation alone cannot satisfy the gate.

**G3 — There is no dedicated performance or generative testing harness.** The inspected tree and manifests contain no dedicated benchmark, fuzz, or property-test targets/dependencies. Existing example tests are valuable, but F2, F5, F7, and F9 show the missing dimensions: partial failures, arbitrary inputs, growth, and scheduling. Add small targeted harnesses for those dimensions; do not target a coverage percentage or add tests that merely restate code.

**G4 — Large modules and weak boundaries raise change cost.** The daemon main file has about 9,300 lines and the CLI main file about 9,000, including tests; their final large test sections begin at lines 6535 and 7261 respectively. Size alone is not a bug. More concrete coupling includes opaque-approver/src/main.rs:16 importing daemon approval source through a path attribute, and task_api.rs:2 depending on its parent through a wildcard import. Extract transport lifecycle, command dispatch, and native approval into explicit modules or a small shared crate only as the affected behavior gains characterization tests.

SanitizedResponse's public payload/error fields at opaque-core/src/sanitize.rs:37-43 also allow mutation after sanitization; task_api.rs:77 relies on that escape hatch for validated receipts. This weakens the advertised type-level invariant, although this review did not demonstrate a secret leak through it. Provide typed constructors/accessors for validated public receipts and make post-sanitization state immutable.

The unused explicit SqliteAuditSink::close at audit.rs:1855-1864 joins while channel senders remain alive, despite a comment describing a timeout. Remove the unused API or implement an owned shutdown protocol and a bounded shutdown test. Treat comment/behavior contradictions as review findings, not explanatory documentation.

## Partial implementations and strengths to preserve

**iOS is a deferred prototype.** README.md:217-222 explicitly defers iOS approvals. Network, key, discovery, pairing, persistence, and approval methods contain TODOs or fatalError calls. Keep the prototype visibly unsupported and out of supported feature/release claims. If prioritized later, finish one real-device pair → fetch → review → authenticate/sign → server verification → revoke flow before extending the UI. Do not spend the core reliability budget polishing a nonfunctional mobile shell.

**AWS production transport is explicitly unsupported.** opaqued/src/main.rs:1735-1759 quarantines unsigned AWS transport to explicitly enabled loopback mocks and logs the missing signed production implementation. This is an honest capability boundary, not proof of working AWS integration. Preserve the default denial; real signing and provider integration require a separate completion gate.

**Fixtures are not automatically stubs to remove.** Metrics fixture modes are explicit, and the examined implementation checks identity, scope, response sizes, freshness, evidence, revocation, and uncertainty. Task reservation/recovery, bounded provider responses, native workstation custody, and workspace subprocess controls are substantive. Linux CI probes Landlock/seccomp before enforcement tests, and several integration jobs guard against vacuous zero-test passes. Build on those patterns.

## Execution plan

Use the sequence below as work packages, not a calendar promise. Owner labels are proposed responsibilities, not assignments to named people. Each package should become a small reviewable change or series of changes with its own failing regression, implementation, and recorded validation.

| Order | Owner | Work package | Depends on | Completion evidence |
| --- | --- | --- | --- | --- |
| 0 | Quality/release | Wire current Python/Node suites and nonpublishing docs privacy verification into CI; establish native macOS checks. Record supported, prototype, and disabled capabilities. | None | Required checks run on this private repository; an intentionally failing test/private sentinel fails the correct job; platform skips are explicit. |
| 1A | Core/storage | Fix F1 retention trust and atomicity. Specify migration and corruption handling. | None | Valid retention and tamper/interruption regressions pass; corruption is never silently authenticated. |
| 1B | Core/storage | Fix F2 transaction-local state and explicit durability acknowledgments; resolve audit shutdown ownership. | Coordinate with 1A | Failure injection at every write boundary; post-failure chain remains truthful; no false durable success. |
| 1C | Runtime/CLI | Fix F3 retry boundaries and F4 handshake deadlines; define stable request IDs and uncertain outcomes. | None | Simulated lost acknowledgments cannot replay unsafe work; incomplete handshakes release capacity and obey shutdown. |
| 2A | Adapters | Fix F5/F6 protocol validation, Unicode boundaries, response deadlines, and bounded MCP concurrency. | 1C transport semantics | Real protocol corpus tests and stalled-server tests; ping/cancel stays responsive. |
| 2B | Core/storage | Replace F7 in-memory pagination with bounded database pages. | Storage behavior tests | Bounded rows/bytes per page at 100,000 receipts; ownership and concurrent authority transitions remain correct. |
| 2C | Web | Fix F9 snapshot/stream ordering, then F10 backlog draining and render batching. | None | Reordered-response reproducer passes; burst/reconnect load has no evidence loss or unbounded fanout. |
| 2D | Metrics | Fix F11 storage isolation and provider admission. | Durability contract from 1B | Slow/failing storage and overload preserve authorization/evidence ordering and runtime responsiveness. |
| 3A | Core/performance | Fix F8 compilation lifetime; establish reproducible release benchmarks. | Baseline harness | No fixed validator compilation per request; same correctness corpus; measured time/allocation comparison. |
| 3B | Adapters/core | Fix F12 capability drift and tighten sanitization/native-approval module boundaries. | Supported capability map; characterization tests | Authoritative catalog contract; post-sanitization mutation rejected by the API; supported adapters remain compatible. |
| 4 | Quality plus subsystem owners | Add focused property/fuzz, restart, fault, platform, and soak coverage; verify packaged artifacts and finalize operator contracts. | Relevant packages above | Reproducible clean-checkout verification and recorded platform/artifact evidence; all P1 findings closed. |

**Parallelism:** 0, storage work, runtime work, and the dashboard race can start independently. Avoid simultaneous edits to the same audit implementation. Assign one reviewer with responsibility for audit/authority invariants across 1A, 1B, and metrics durability. Refactor large entrypoints incrementally while these seams are being tested; a wholesale rewrite would make behavioral review harder.

**First merge set:** required existing tests, the retained-corruption regression/fix, the rollback/flush regression/fix, and the post-dispatch retry/incomplete-handshake fixes. These directly improve confidence in the system's central promise.

## Definition of done for supported code

1. **State and evidence:** authorization, dispatch, durable observation, and uncertainty have explicit states. No success is synthesized from an ignored error. Every P1 has a regression that fails on the reviewed commit and passes with its correction.
2. **Recovery:** specify and exercise disconnect, deadline, restart, cancellation, storage failure, revocation, and duplicate-delivery behavior wherever relevant. Failed operations leave a defined state and owned resources are released.
3. **Bounds:** request bodies, output capture, response frames, queues, concurrent work, history pages, and wait times have enforced limits. Saturation has an observable outcome. Measure rows decoded, queue depth, lock duration, and event lag rather than inferring bounds from response size.
4. **Testing:** every supported language/platform surface has required appropriate checks. Boundary tests call production handlers/protocols; fixtures cannot silently stand in for real authentication or supported provider behavior. Fuzz arbitrary JSON/Unicode and use model-based tests for task and audit transitions where they add value.
5. **Performance:** keep fixed host/workload release baselines for validation, receipt paging, audit catch-up, and slow-storage contention. Record latency distributions, memory, allocations where useful, and variance. Set numeric regression budgets after the baseline is stable; this review did not measure production SLOs. Enforce deterministic resource bounds immediately.
6. **Maintainability:** one authoritative source for capability and operation metadata, explicit retry/deadline semantics, immutable validated outputs, and narrow modules with clear ownership. Comments explain a verified invariant or reason, not behavior the implementation lacks.
7. **Delivery:** verify installation/package behavior and the generated public site artifact. Publish no internal review, dogfood evidence, credentials, or raw session artifacts. Keep supported, disabled, and prototype features distinguishable in code and documentation.

## Validation performed and limits

The following existing suites were run locally on macOS without changing repository source:

~~~sh
python3 -B -m unittest discover -s scripts -p 'test_*.py'
# 132 run: 125 passed, 7 skipped.
# Skips: five missing FIDO2-library checks, two Linux-only checks.

python3 -B -m unittest discover -s deploy/hosted-demo -p 'test_*.py'
# 70 passed.

node --test deploy/cloudflare-demo/tests/*.test.mjs deploy/cloudflare-docs-privacy/tests/*.test.mjs crates/opaque-metrics/tests/*.test.cjs crates/opaque-web/tests/*.test.cjs
# 162 passed.

mkdocs build --strict --site-dir /tmp/opaque-quality-review-site
# Passed with locally installed MkDocs; 74 files before this report was added.
~~~

Generated paths, search entries, and sitemap routes were checked for product, dogfood, release-dogfood, and tenant-boundaries exclusions. After adding this report, a second strict build to /tmp/opaque-quality-review-final-site still produced 74 files: zero private paths, private search entries, or private sitemap routes. A byte-level scan of every generated file also found none of this report's title, filename, or reviewed-commit marker. This is a local result, not proof that CI enforces it, and the docs environment was not recreated from the pinned requirements for this review.

Separate disposable probes reproduced F1/F2 through opaque-core's actual public API and F9 using the shipped JavaScript. The Rust probe used a separate temporary manifest with the workspace's dependency declarations, resolved independently rather than reusing the repository Cargo.lock. Treat the results as reproduced source-level defects, with locked in-repository regressions still required. Probe source, generated binaries, disposable databases/keys, and raw outputs remain outside the repository.

A six-case, 100-iteration validation microprobe took roughly 1.19-1.74 seconds per case in unoptimized dev mode, including empty inputs. This corroborates repeated compilation but is not a production latency or optimization-speedup claim. The performance work package requires release-mode baselines.

The complete Rust workspace suite, live provider effects, native human authentication, Linux isolation, and production load were not rerun in this review. Source-traced findings above should receive the listed executable regression tests before their fixes are considered complete. The review and plan are complete; implementation work remains.
