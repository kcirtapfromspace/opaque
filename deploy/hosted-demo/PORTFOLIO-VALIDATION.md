# Expanded portfolio analytics validation

**Private validation record, 4 September 2026 (America/Denver). Deployed and
publicly qualified with both approved models; both leases cleaned up.**
This increment adds richer synthetic analytics to the completed
[organization checkpoint](ORGANIZATION-VALIDATION.md). That record retains its
own runtime, Worker, public role-flow and generation-16 cleanup evidence. None
of the results below replaces that historical proof.

Source, Python, JavaScript and final Rust checks have passed. After two failed
packaged rounds, the strict-schema planner passed ten actual Rust/model calls
for each model. Both final packaged runtimes then completed thirteen checks,
including allowed analytics, role restrictions and sharing withdrawal. The
analytics image is deployed, and a normal public Gemma session completed three
analytics questions, a customer-scope denial, engineer visibility checks and
cleanup. Public Qwen completed a six-bucket trend, a timed-support processing
breakdown, a raw-record denial and verified cleanup. The final packaged
source-counter files were not recovered; the limitation and completed narrower
repeat are recorded below, separately from the recovered public counters.

This ledger and its evidence references belong in the
[private dogfood workspace](../../docs/product/2026-09-04-private-workspace.md).

## Qualified scope

The source creates **7,205 seconds** of seeded synthetic history and retains
**7,260 seconds** while generating new events. Events contain timestamp, channel,
region, product, review/mismatch flags and processing duration. They contain no
borrower identifiers, credit scores or real lending decisions.

| Component | Fixed contract |
| --- | --- |
| Measures | `application_count`, `manual_review_count`, `identity_mismatch_count`, `manual_review_rate_percent`, `identity_mismatch_rate_percent`, `mean_processing_seconds`. One to four unique measures per query. |
| Views | Summary; trend with six equal buckets; breakdown by one dimension; comparison of the current and immediately preceding equal period. |
| Windows | 60, 300, 900, 1,800 or 3,600 seconds. Comparisons require both complete periods. |
| Channels | `web`, `mobile`, `partner`. |
| Regions | `northeast`, `southeast`, `midwest`, `west`. |
| Products | `personal_loan`, `auto_loan`, `credit_card`. |
| Filters | At most one exact configured value per dimension. No tenant, source URL, SQL, raw fields, arbitrary expression or credential argument. |
| Source boundary | One configured tenant and private source credential; exact `POST /v1/portfolio/query` route and bounded body. |
| MCP boundary | `opaque_portfolio_query`, `portfolio:read` and a separate scope for each requested measure. Source and evidence are rebound to the verified tenant and configured source. |
| Answers | Numeric results, comparisons and summaries are computed from validated source evidence. The portfolio snapshot path does not send numeric evidence to the model for restatement. |

The final generator uses a 65/25/10 channel mix for web/mobile/partner. Recent
mobile applications have more seeded mismatch flags; recent partner applications
have longer processing durations. Uneven volume creates a useful distinction
between the channel with the largest number of manual reviews and the channel
with the highest review rate. The deterministic scenario test verifies that
distinction for its fixture; public values are not fixed promises. These are
designed correlations, not causal findings about real customers.

Counts are zero for an empty group; rates and mean duration are null. Relative
change is null when the prior value is zero. Rate deltas use percentage points,
while the relative-change field uses percent. Trend and comparison intervals use
`(start, end]`, with no shared-boundary double counting. Results whose required
history or source freshness is unavailable are rejected.

The existing organization restrictions remain: engineer activity permission
does not grant portfolio reads; support needs its exact-customer case; role
generations are checked before and after source access and at evidence delivery;
question text is concealed unless separately shared. Live watches retain their
own scope and narrow metric contract. A richer filtered/grouped historical query
must not be silently converted into a legacy watch.

## Recorded automated checks

| Check | Recorded result |
| --- | --- |
| Source | **9 tests passed**, including the final channel mix. Known-event arithmetic, filters, scope rejection, unavailable history and seeded scenarios are covered. |
| Hosted Python | Final rerun: **54 tests passed** in **24.075 seconds**, including the final channel mix. Log: `/private/tmp/opaque-portfolio-deployment/python-final.log`. The earlier 54-test run took 25.535 seconds. |
| JavaScript | **112 tests passed**. Log: `/private/tmp/opaque-portfolio-deployment/javascript-final.log`. |
| Final Rust | **72 tests passed** (40 library, 32 gateway), with all-target Clippy and warnings denied. The earlier 67-test result predates the strict-schema planner. |
| Actual Rust planner/model corpus | **10/10 exact-query passes for Gemma and 10/10 for Qwen**; seven questions plus repeats per model. This corpus exercises planning only, without source queries. Evidence: `evidence/constrained/final-summary.json`. |
| Final packaged real-model qualification | **13/13 checks for each model**, including nine allowed questions and four denials, plus the role/sharing controls and quiescent-health assertions described below. |
| Final packaged source-counter evidence | Not recovered for the thirteen-check runs. A separate narrow repeat passed for each model: one allowed query, then four denials; source count remained **1 → 1** across the denials. |
| Public analytics rollout | Immutable analytics runtime deployed; controller ready; both model Pod admission checks passed. |
| Public Gemma | Three allowed analytics questions, Cedar denial, concealed engineer question text and no metric entitlement; final source count three; cleanup generation 20. |
| Public Qwen | Six-bucket trend, timed-support processing breakdown and raw-record denial; final source count two; cleanup generation 22. The end-demo click was repeated before cleanup was observed. |

An earlier public-browser attempt was blocked by the operator's locked Mac.
After the Mac was unlocked, the operator completed normal public Turnstile
admission. The public observations below are separate from local qualification.

Review-driven source cases cover exact window/bucket/comparison edges and a
future event, all-empty comparisons, a zero previous value, excess measures with
no accepted query, and the longest one-hour comparison after live generation and
retention pruning. The bounded Rust review corrected two integration issues:
selected counts and corresponding rates must agree with the sample denominator,
and application counts must match exactly rather than within floating-point
tolerance. A separate correction lets portfolio-only chat grants operate without
requiring the legacy metric-read scope. Those corrections passed the earlier
Rust checkpoint and are retained in the final 72-test result.

## First packaged round: partial success, then rejection

Evidence is under
`/private/tmp/opaque-portfolio-deployment/evidence/first-packaged-attempt/`.

| Model | Completed observations | Failure that stopped the round |
| --- | --- | --- |
| Gemma | Channel review-rate breakdown in 5.49 seconds: Mobile 29.71%. Review-count breakdown in 4.32 seconds: Web 1,124 reviews. | The requested mobile mismatch comparison emitted an incomplete/unsupported-model-response error and no portfolio result. Saved source evidence recorded two aggregate queries, matching the two completed questions. |
| Qwen | Channel review-rate breakdown in 13.10 seconds: Mobile 27.67%. | The next count question failed the time/filter/group/count-versus-rate intent guard. No portfolio result was delivered for it. Saved source evidence recorded one aggregate query. |

A preceding Gemma model-forwarding attempt also returned a model-rejected error;
it is preserved as `gemma4-e2b-first-forward-failure.sse`. No automatic retry was
reported by the gateway. It is not counted as a successful analytics question.

The direct saved Gemma comparison response explains the initial failure: it
returned prose claiming that comparison would require separate calls and ended
with `finish_reason: length` at 192 completion tokens. The actual source contract
supports both periods in one comparison query. A diagnostic instruction change
then produced the correct comparison plan, but this single success was not
sufficient qualification: the next packaged round still exposed regressions.

## Second packaged round: improvement without a complete pass

Evidence is under
`/private/tmp/opaque-portfolio-deployment/evidence/second-packaged-attempt/`.

| Model | Completed observations | Failure that stopped the round |
| --- | --- | --- |
| Gemma | No accepted portfolio result in this round's saved validation sequence. | The first channel-rate question failed query-scope validation. A diagnostic response combined `view: comparison` with `dimension: channel`, which is invalid: a dimension is permitted only for breakdown. |
| Qwen | Rate breakdown in 13.71 seconds: Mobile 31.13%; count breakdown in 8.40 seconds: Web 1,070 reviews; mobile mismatch comparison in 9.22 seconds: 19.44% versus 3.54%, with a source-computed +15.89 percentage-point change. | “Compare processing time by channel over the last 15 minutes” failed the intent-preservation guard. The saved source counter remained three, matching the three completed questions. |

The displayed comparison values are rounded; the delta comes from unrounded
source values, so subtracting the two displayed percentages can differ in the
last decimal. The per-question timings describe these few local requests, not
benchmark results or a service SLO. The presence of several correct answers does
not turn either partial round into a passed model qualification.

The saved files include per-question SSE, partial `*-report.json` records,
source counters and validation tracebacks. They show an error followed by the
normal completion event for rejected plans, not a fabricated numeric result.

## Strict-plan correction and completed local qualification

The new path derives bounded semantic constraints from recognized question
fields, periods, measures and grouping. It asks the model for one JSON object
containing `name: opaque_portfolio_query` and the constrained arguments, using
the model server's strict JSON-schema response format. It does not rely solely
on a native tool handler whose generic arguments dictionary failed to enforce
the desired shape in these attempts.

Returned JSON is still parsed into the strict typed plan and independently
checked against the token's scopes, query contract and original constraints.
Unexpected fields, extra calls, truncated/prose responses and changed query
meaning are rejected. The gateway does not fill in a missing field or issue a
broader substitute after rejection. The source computes the numeric answer only
after authorization.

This is a constrained question interface, not an arbitrary natural-language SQL
engine. Server-derived semantics are part of the implementation; the model is
not granted authority to redefine the customer, source, scope or requested
period.

The final actual Rust/model corpus passed ten exact-query checks for each model,
covering seven questions plus repeats. It used the `portfolio_plan` JSON-schema
envelope, a 192-token output bound and a 45-second model deadline. Gemma calls
took 7.97–10.64 seconds and Qwen calls took 7.30–21.20 seconds in this small run.
These observations are not a general model benchmark. The authoritative summary
is `evidence/constrained/final-summary.json`; earlier partial diagnostic files
remain historical failures and must not be mistaken for that final result.

## Final packaged runs: both models passed

The packaged Gemma and Qwen sequences each completed all thirteen reported chat
checks. Their seven initial analyst questions exercised rate versus count
breakdowns, a filtered adjacent-period comparison, mean processing time by
channel, a six-bucket trend, a region breakdown and a query with both product
and region filters. Each run then verified an engineer denial, an explicitly
shared analyst comparison, a support query, and denials for Cedar, borrower
records and unavailable 24-hour history.

The surrounding control assertions verified that initial question sharing was
off, the engineer saw no earlier question text, opt-in exposed exactly the new
shared question, and withdrawing sharing concealed all retained question text.
Both final health responses were ready with `active_requests: 0`,
`model_requests_in_flight: 0` and `model_execution_uncertain: false`. The runtime
reported the expected selected model alias and actual model name in each run.

| Packaged model | Final recorded result | Allowed-question durations |
| --- | --- | --- |
| `gemma4-e2b` | 13 checks passed; nine allowed questions, four denials. | 7.93–10.47 seconds. |
| `qwen35-4b` | 13 checks passed; nine allowed questions, four denials. | 6.08–12.66 seconds. |

The reports are `evidence/gemma4-e2b-report.json` and
`evidence/qwen35-4b-report.json`; corresponding per-question SSE, final-health
and engineer-purged responses are saved beside them. The top-level
`gemma-validation.log` and `qwen-validation.log` both end with `passed: true`
and `checks: 13`. These files are under
`/private/tmp/opaque-portfolio-deployment/`.

**Source-counter limitation:** copying the final source counter and audit files
with `docker cp` did not find their tmpfs-backed paths. The owned containers were
then removed before those files could be collected through `docker exec`.
Consequently this record does not claim an observed final source count of nine,
or prove zero additional source calls from the final packaged report alone.
The earlier rounds' recovered counters remain valid only for those earlier
rounds. The separate repeat below recovered the counter directly without
retroactively supplying missing evidence for these thirteen-check runs.

## Separate source-boundary repeat: both models passed

Fresh Gemma and Qwen fixtures each completed one allowed channel review-rate
query, followed by four denials: Cedar's application counts, borrower names/SSNs,
an unsupported 24-hour trend, and the otherwise allowed question after switching
to the engineer persona. For **each** model, the captured accepted source-query
count was **one before the denials and one after all four**. Both finished with
quiescent health. This is direct counter evidence that those four checks added
no accepted source query in these separate runs.

The operator read the tmpfs-backed files with `docker exec` and preserved source
counters and audit files before cleanup. Evidence is under
`/private/tmp/opaque-portfolio-deployment/boundary/`: `gemma.log`, `qwen.log`,
and each model's `*-before-denials-source.json`, `*-after-denials-source.json`,
`*-audit.jsonl`, report, health response and SSE under `evidence/`. Both logs end
with `passed: true`, `source_queries_before_denials: 1`,
`source_queries_after_denials: 1` and `denied_queries: 4`.

These are five-question counter runs, distinct from the completed thirteen-check
product flows and the planning-only ten-case corpora. No combined final source
total is inferred across their different fixtures.

## Analytics cutover

The deployed runtime is
`192.168.25.201:5050/opaque-hosted-demo@sha256:898b2aeb391dd24ae905303401b81aaf2187f68e9f2c9eaa5a511397d8dbc9d7`.
The ValidatingAdmissionPolicy reached observed generation **7**, with no type
checking warnings. Generated positive Pod server dry-runs passed for both
approved model profiles. The controller rolled out to **1/1** ready after the
slot was drained; retained generation **18** was preserved. Worker deployment
`24a17900-9200-43da-8705-42ac329859fe` enabled admission for the new runtime.

The customer-facing Pages guide was subsequently published as `e9a777d2`, and
returned `200` with the six-measure visitor guide. The final documentation guard
Worker is `d2c132f8-7d96-495d-b27b-c632104a2703`, extending the earlier guard to
ten route patterns across `opaque.info` and `www.opaque.info`. Eight
representative private-route checks returned `404` with `no-store`; the operator
also verified public search and sitemap contained no internal content. Public
availability of the visitor experience does not make this validation record or
its operator evidence public.

## Public Gemma: completed flow and cleanup

Normal Turnstile and public admission created lease
`104c9659d4ae439bbc38340352122f01`, using Gemma on the new analytics image.
The browser delivered the following scoped answers and evidence:

| Question | Observed result |
| --- | --- |
| Highest manual-review rate by channel over 15 minutes | Mobile, **29.97%**. |
| Most manual reviews by channel over 15 minutes | Web, **1,080** reviews. This differs from the highest-rate channel. |
| Mobile identity-mismatch rate, latest 15 minutes versus preceding 15 minutes | **18.85% versus 4.19%**, a **+14.66 percentage-point** change computed from the source values. |
| Cedar application counts by channel | Customer-scope denial, with no returned portfolio result. |

The final captured source counter was **three** after the three allowed
questions and the Cedar denial. The UI's engineer persona showed no customer
metric entitlement, and expanding activity retained “Question text concealed”
for the unshared question. These observations do not claim every role or denial
case was re-exercised publicly in this particular lease.

The operator selected **End this demo** and verified cleanup. Retained state is
schema **2**, generation **20**, `lease_id: null`,
`cleaned_lease_id: 104c9659d4ae439bbc38340352122f01` and
`model_id: gemma4-e2b`; the slot had no remaining Pods, Services or Secrets.

Evidence is under `/private/tmp/opaque-portfolio-deployment/evidence/public/`:
`gemma-breakdown.txt`, `gemma-count.txt`, `gemma-comparison.txt`,
`gemma-denied.txt`, `gemma-engineer-expanded.txt`, `gemma-final-source.json`,
`gemma-final-audit.jsonl` and `gemma-cleanup-state.json`. The saved
`site-boundary-final.json` also records successful visitor pages and search,
with the private document routes returning `404`.

## Public Qwen: completed flow and cleanup

Normal public bot protection and admission created Qwen lease
`bfe0cf7956ea41b39dd1abcc348c97d7`. A 30-minute application-volume trend returned
six consecutive five-minute buckets: **3,304; 3,914; 2,954; 3,692; 3,656; 2,961**
applications. The evidence displayed each interval and its sample count.

A temporary support case, bounded to the assigned customer and at most
**300 seconds**, permitted a 15-minute processing-time breakdown: **Web 1.18
seconds, Mobile 1.31 seconds, Partner 3.14 seconds**. A subsequent request for
borrower names and SSNs was rejected with `raw_records_denied`. The recovered
source counter was **two** after these two allowed questions and one denial,
with no extra accepted source query for that denial.

The first visible **End this demo** click did not produce an observed transition
out of the ready state. There is no captured error establishing why. A repeated
visible click was followed by verified cleanup; this record does not claim
one-click completion. Final retained state is schema **2**, generation **22**,
`lease_id: null`, `cleaned_lease_id: bfe0cf7956ea41b39dd1abcc348c97d7` and
`model_id: qwen35-4b`. The operator verified no remaining slot Pods, Services or
Secrets.

Evidence is under `/private/tmp/opaque-portfolio-deployment/evidence/public/`:
`qwen-trend.txt`, `qwen-support.txt`, `qwen-support.png`, `qwen-denied.txt`,
`qwen-final-source.json`, `qwen-final-audit.jsonl` and
`qwen-cleanup-state.json`. The final eight public documentation-boundary checks
are preserved in `privacy-routes-final.json`.

Both public model flows are complete within this stated sample. Local tests and
packaged runs cover additional cases; the public sessions do not substitute for
that broader evidence or establish reliability beyond the observed requests.

The [question/evaluation matrix](../../docs/product/2026-09-04-portfolio-analytics.md)
describes expected query meanings. Operator files under `/private/tmp` are not a
durable evidence archive. This record reproduces no session cookies, bearer
tokens, source credentials, private keys or environment-file contents.

This remains a disposable synthetic customer source with shared trusted model
services. It does not demonstrate production SSO, a real credit warehouse,
cross-customer source access, lending decisions, FCRA compliance, confidential
inference, hardware attestation or microVM/network isolation.
