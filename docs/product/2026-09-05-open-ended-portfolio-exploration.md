# Open-ended portfolio questions

Private implementation and qualification record · September 5, 2026.

The demo needs to interpret unfamiliar questions about its data and return a
useful, correct answer. Valid JSON, an authorized query, and accurate numbers
are necessary but insufficient: the selected measure, window, filters and
comparison must answer the question the visitor actually asked.

## Implemented path

The live chat planner receives the authenticated session's aggregate catalog
and proposes one to four distinct queries, a clarification, or an unsupported
request. The prior keyword parser remains only in the explicitly deterministic
fixture/legacy path. It does not choose queries for the new live exploration
path. Model proposals cannot select a customer, endpoint, credential, scope,
grant or arbitrary SQL.

All proposed queries are validated before the first read. Every read then goes
through the existing MCP authorization and source validation. Session authority
and persona generation are checked again before each disclosure and after model
selection. Findings describe the source snapshot's recorded time; a slow model
does not turn that historical observation into a claim of current freshness.

The visible analysis plan is rendered from validated query fields, rather than
the model's free-form interpretation. The query schema makes grouping required
for breakdowns and impossible for other views, matching runtime validation.
Explicit supported durations and literal catalog filters constrain both the
generation schema and post-validation. The model still chooses relevant
measures, views and comparisons. A mismatched proposal is rejected; the server
does not silently rewrite it or send a substitute query. Unqualified “flagged”
requests ask which measure the visitor means. Requests for joint manual-review
and identity-mismatch counts are declined because marginal aggregates cannot
establish their intersection.

The service constructs facts from validated source calculations. The model
selects existing fact IDs for relevance. It cannot manufacture final answer
numbers or prose. Each selected fact retains its source receipt, measure units,
window, filters and sample counts. Breakdown facts retain every segment's value,
including ties and missing values, so named interior groups remain available.
Tables appear as partial evidence while the
selection is pending. If selection fails, the service explicitly labels its
computed-observation fallback; qualification does not count that fallback as a
successful model answer.

The data remains synthetic loan-application aggregates: application, manual
review and identity mismatch counts; review and mismatch percentages; and mean
processing time in seconds. Views are summary, six-bucket trend, single-dimension
breakdown, and adjacent-period comparison. Exact windows are 1, 5, 15, 30 and
60 minutes. Channel, region and product equality filters combine with AND.
Borrower records, scores, outcomes, forecasts, unsupported historical periods
and causal explanations are unavailable. This increment does not connect a new
enterprise dataset or add general conversational memory. A completed
clarification retains the original question and the user's clarification under
the current browser identity, with a visible New question reset. The next
request contains only labeled user text, bounded to the existing 2,000-byte
limit. Success, error, revocation and identity changes clear that context.

## Qualification method

`crates/opaque-metrics/examples/portfolio_exploration_eval.rs` calls the actual
configured model through `ChatModel`. Its checks include broad exploration,
synonyms, counts versus percentages, combined filters, a requested window,
ambiguous terminology, causal limits, unavailable data and exact fact selection.
It records semantic failures separately from protocol validity. These inputs
are synthetic; this harness alone proves neither source access nor human consent.

`scripts/portfolio_exploration_dogfood.py` starts the actual packaged runtime on
unused loopback ports 8081–8084, completes its synthetic IdP/PKCE sessions, and
sends questions through the authenticated chat route to a live model. It checks
actual source reads, completed SSE answers, source receipts, selection mode,
and held-out query/answer semantics. Custom `--question` runs check protocol
only and explicitly record semantic qualification as unavailable. The script
stops only the runtime it created. The harness does not change cluster workloads.

Both tools keep reports in explicitly private temporary storage. Do not commit
raw events, runtime credentials, signing keys, session cookies or model bodies.

Example commands, using an already available model's task-owned port forward:

```sh
CARGO_TARGET_DIR=/Users/thinkstudio/opaque/target CARGO_INCREMENTAL=0 \
  cargo build -p opaque-metrics --example portfolio_exploration_eval --bin opaque-metrics

/Users/thinkstudio/opaque/target/debug/examples/portfolio_exploration_eval \
  --base-url http://127.0.0.1:19682/ --model Qwen3.5-4B-Q4_K_M.gguf \
  --output /private/tmp/NEW-private-model-evaluation.json

python3 scripts/portfolio_exploration_dogfood.py \
  --binary /Users/thinkstudio/opaque/target/debug/opaque-metrics \
  --model-base-url http://127.0.0.1:19682/ --model-profile qwen35-4b
```

## Results and release decision

Initial live evaluations rejected both available profiles as ready without
further work. The first Gemma run passed only 7/16 semantic checks after auditing
two overly permissive assertions; a longer few-shot prompt passed 6/16. The
initial Qwen run passed 12/16: six of ten live planning checks, three of three
fact selections, and three early runtime denials. Qwen still invented filters
for ambiguous wording and rejected supported compound-filter questions.

Those failures are preserved as failures. They are not source authorization
failures, but they prevent claiming reliable open-ended understanding.

The compact Qwen prompt improved the planner/selector harness to 13/16. Raw
diagnostics showed that two rejected proposals combined a grouping dimension
with a non-breakdown view; the schema now prevents that invalid combination.
With that correction, the actual authenticated runtime passed 4/5 core cases
and 3/6 fresh holdouts. The failures included an overview selecting only
application counts, a dropped partner filter, a wrong five-minute window and
an unsupported joint-event question answered with separate marginal counts.
The overview passed a focused runtime regression after the relevance prompt was
changed to request evidence across distinct measures and views.

A separate three-case experiment asked the same model to review its own plans.
It failed all three cases and was rejected; no extra review call was added to
the application. Request-specific window and explicit-filter constraints are
now enforced before source access instead.

With these constraints, the final D3 runtime passed **5/5 core cases** against
the existing Qwen3.5 4B service: open-ended overview, review volume versus rate,
channel workload, processing-time change, and unavailable history. All four
supported answers used model-selected source facts; they took 15.64–26.89
seconds. The historical request caused zero source reads. The additional six
cases passed **5/6**: partner counts, five-minute regional minimum, joint-event
denial, combined mobile/credit-card filters and forecast denial. The named
regional pair failed because the model invented a Northeast filter for a
Southeast/Midwest question. D4 corrects the general constraint gap: explicitly
named categories now restrict optional filters even when several categories
prevent resolving one mandatory filter. Unfiltered breakdowns remain possible.
The complete regression and independently authored cases then exercised D4.

D4's complete model regression passed **15/16**, with a time-movement question
rejected on duplicate category breakdowns. Six independently authored runtime
questions then scored **5/6** after correcting the harness to recognize the
existing explicit applicant-action policy denial (the original 4/6 report is
preserved). The real failure returned region and channel mismatch-rate facts
for a question about movement over fifteen minutes. Those numbers were grounded
but did not answer the question. Source correctness alone is not a semantic pass.

Three alternatives were rejected without changing production code: removing
the broad example passed 0/5 candidate questions; enabling reasoning exceeded
the 45-second model request limit on its first question; adding positive trend
guidance passed only 1/5. These failed records remain available privately.

The next contract revision therefore constrains explicitly requested temporal
analysis to trend or adjacent-period comparison, in both schema generation and
post-validation. It preserves model selection of measures and ordinary broad
questions. Examples are restricted to those same allowed views. Local tests
cover literal temporal variants, named/defined uses of “Trend”, quoted questions
and clarification continuations. Explicit mixed temporal/category-view requests
are declined with guidance to ask separately; both views remain available.
This is a bounded literal constraint, not a claim of complete natural-language
understanding. This revision passed all six independently authored runtime
cases, including the previously incorrect temporal answer, in 11.81–22.65
seconds for supported questions. The earlier six-case suite still caught one
incomplete named comparison: a region breakdown filtered to Southeast omitted
the requested Midwest participant.

The final comparison contract prevents a breakdown of multiple explicitly named
participants from filtering that grouping dimension to one participant. Other
dimension filters remain available. Separate queries must cover the requested
participants with the same window, view, other filters and at least one common
measure. Incomplete or incomparable plans fail before source access. D7 passed
**6/6 comparison/filter holdouts** and **6/6 independently authored cases**.
Its core report scored **3/5**: the overview contained one exact duplicate among
four otherwise valid queries and was rejected before any source read. The other
failure was a rubric mismatch: the volume-versus-rate answer selected all three
necessary measures from aligned six-bucket trends, but the rubric required
adjacent-period comparisons. Independent review confirmed the same population,
window, snapshot time, bucket boundaries and sample counts, with no causal
overclaim. The original report remains unchanged.

The final robustness revision removes only semantically identical redundant
queries after validating the original proposal's cardinality and every query.
It preserves the first query's parameters and still applies temporal, named
category and authorization constraints before any read. It does not repair
invalid operands or substitute a different query. The temporal rubric accepts
a complete coherent set of selected trends or comparisons, while rejecting
mixed axes, mismatched windows, restricted cohorts and missing selected
measures. The final revision passed **17/17 actual authenticated runtime
cases**: 5/5 core, 6/6 comparison/filter holdouts and 6/6 independently authored
questions. Every supported answer used model-selected source facts; unavailable
history, joint-event counts, forecasts and applicant actions produced no source
reads. Supported answers took 15.08–46.15 seconds. All three runs used the same
Mac executable, SHA-256
`1e23c7bd9ee3eb5a8f81320b155ddba1f3d96b22ed66e4225915ff367628b6aa`,
and each isolated runner confirmed that its own runtime stopped afterward.
These finite passing cases demonstrate the tested behavior; they do not
establish perfect understanding of arbitrary questions or unrestricted data.

During the preceding run, the model container was OOM-killed after its first
answer. Its pinned server defaults to an 8192 MiB optional cross-request prompt
cache despite a 5500 MiB container limit. After confirming no active demo
workspaces or inference requests, the deployment was updated only to append
`--cache-ram 0`; the checked-in manifest matches. Model weights, image, GPU,
context size, inference concurrency and memory limit are unchanged. The rollout
became ready with zero restarts. The core rerun observed a 5,419,601,920-byte peak
and zero cgroup OOM events. This model-service repair is separate from a web
application rollout.

Local verification passed 63 metrics library tests, 52 gateway tests, 43 browser
UI tests and 35 offline semantic-harness tests. Metrics Clippy passed for all
targets with warnings denied; workspace formatting and diff checks passed.
The hosted-demo suites also passed 87 Worker/browser tests and 56 controller and
runtime tests.
No public application rollout or production IdP/hardware ceremony is
established by these local checks.

## Release artifacts

The runtime artifact is bound to source commit `5157feb`. Its Linux ARM64
executable is 24,417,392 bytes, stripped, mode 0755, with SHA-256
`5bf46dd2719edb8b59b1697863aeb4160204b38b8d89d6e9e0fad788891e45ab`.
The pinned offline Rust build and cached packaging completed without pulling a
new image or changing the base packages. The 58-file input manifest remained
unchanged across packaging. Inspection of the actual image found exactly the
six allowlisted application files, with no internal documentation, extra source
or credential environment. Startup passed as UID 7383 with a read-only root
filesystem and no network.

The image was published only to the private registry as
`192.168.25.201:5050/opaque-hosted-demo@sha256:d179e9b52ac3ccbccad7d5478bf91756f388c8008d7d67bd2c97573ee9dcedb0`;
the registry readback matched the archive's crane publication digest. The
separate Docker image/index identifier is not used as the deployment digest.

The actual Worker public-assets directory contains only `index.html`, SHA-256
`0fd7681289cd71e43baaa9a93aa6b4267e34cb90ad7f7e930e3e9e0decf67247`.
Its generated bundle and asset inspection exclude private documentation and
operator records. No main-site or documentation-site deployment is involved.
Admissions were paused with Worker version
`c110e7d6-eceb-4b6c-bceb-12931ed67aec`. The queue had no work actions; the
retained slot had generation 26 and no lease or runtime resources. A remaining
alarm was the terminal-record history expiry, beyond every active queue/lease
deadline. The slot ConfigMap was never rewritten. Resource-version-guarded
patches changed only the admission image expression and controller/runtime
image. Controller readiness and admission type checking passed. Both enabled
model profiles passed server-side Pod dry runs; the old image, wrong model URL,
wrong model name and test-origin environment were rejected for both profiles.

Worker version `ed3c35fb-a61a-47c8-9251-49196349e605` reopened admissions with
Qwen as the default. Unauthenticated workspace/internal access returned 401;
foreign-origin joins and validly shaped joins with invalid bot proof returned
403. Both private qualification-document URLs returned 404. The runbook probes
now include the required model alias so they actually reach bot verification.

A normal browser admission reached the digest-pinned ARM64 runtime with Qwen.
The following public-route checks passed, with complete source receipts and
model-selected facts rather than the fallback:

- A new overview wording, “Give me an overview of the application portfolio,
  including anything worth investigating,” selected adjacent-period and channel
  evidence across application volume, review rate, mismatch rate and processing
  time.
- The fifteen-minute mismatch movement question returned six equal time
  intervals for the requested percentage.
- The one-minute Southeast/Midwest comparison retained both requested regions.
- Borrower names and SSNs were explicitly denied without an evidence table.
- Switching to Product engineer removed the analyst conversation, metric
  entitlement and task receipt; only permitted activity metadata remained.

The browser test session was ended normally. Its exact Pod, Service and Secret
were removed; retained slot generation advanced to 28 with a null lease and the
matching cleanup tombstone. The Qwen model remained ready with zero restarts.

During final cleanup, the separate **Add WASM approval window** task superseded
the public Worker and paused new admissions for its approval rollout. This task
did not overwrite that concurrent deployment or re-enable its admissions. The
open-ended changes and Qwen configuration must be carried into that combined
release; the passing evidence above is for this tested exploration runtime,
not a claim that the other task's older runtime already contains these changes.
Release coordination was sent directly to the active approval task.
