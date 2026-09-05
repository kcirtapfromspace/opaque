# Credit portfolio demo validation

Record date: **2026-09-04 (America/Denver)**. This record covers the Harborlight
Credit Union increment. Harborlight is fictional and all application events are
synthetic. The previous [operational-metrics validation](VALIDATION.md) remains a
historical record. The credit and model-choice evidence is recorded separately
below; an older successful stream is not proof of a later release.
The subsequent organization/support increment has its own
[validation record](ORGANIZATION-VALIDATION.md).

## Completed local checks

The coordinating implementation agents reported these completed checks. They
were run against the local changes, not inferred from the existing deployment.

| Check | Completed evidence |
| --- | --- |
| Python | **36 tests passed**, covering the hosted demo's source, runtime, controller, fixed model profiles and migration checks. |
| JavaScript | **94 tests passed**: 35 browser UI tests and 59 queue/HTTP/Worker tests, including the persistent action-error correction. |
| Rust | **44 tests passed** for `opaque-metrics`. |
| Rust lint | Clippy passed for all `opaque-metrics` targets with warnings denied. |
| Credit profile | The configured profile admits only application rate, manual review rate and identity mismatch rate. It refuses a source, admission or requested OAuth scope that adds another metric. |
| Explicit forbidden chat requests | Score, borrower/PII, foreign lender, credentials and write requests were denied with **zero model and source requests** in the focused tests. |
| Direct MCP boundary | Forbidden average credit score and added authority fields were rejected independently of the natural-language preflight. |
| Evidence handling | Scoped reads produced the policy/evidence events; foreign or malformed source results did not produce successful source-evidence claims. Streaming still required its separate scope. |
| Existing experience | The operational-metrics session contract remained unchanged in the regression checks. |

Generic model failures emit an error and completion event, without fabricating a
policy verdict or a no-source-access proof. The policy UI checks customer,
policy and tool binding before displaying reported decisions. A configured
portfolio-monitoring purpose is descriptive profile context, not a verified
OAuth purpose claim or a semantic guarantee about how an answer is used.

## Packaged runtime and model observations

The actual packaged runtime completed its local OAuth flow and exposed the
credit profile. Requests for average credit score, raw borrower records and
another lender were rejected early. No `source-evidence.json` file was created
by those three requests. This is a local runtime observation; the focused tests
above separately count the absence of model and source calls.

The first allowed question sent to the real Gemma service **did not produce a
valid allowed answer**. The proposed tool arguments omitted the required
`window_secs` and selected `watch_secs: 0`. Strict validation rejected the
malformed call. This shows that an allowed business question does not bypass
the tool schema; it does not establish a working credit stream or successful
model explanation. The planner prompt was then corrected and the packaged
runtime was tested again.

The final packaged-runtime retest **passed with the real Gemma service**. It
selected `manual_review_rate_percent`, `window_secs: 60` and `watch_secs: 10`.
The answer included five result snapshots, the source recorded exactly five
aggregate queries, and the model's final explanation reported **20.27 percent**.
That value describes this synthetic observation, not a fixed or promised result.
The three forbidden questions preceded this stream and had created no source
evidence file.

Private request captures for the successful planning and explanation calls
recorded 401 prompt / 37 completion tokens and 354 prompt / 14 completion tokens,
respectively. Those captures contained no `Authorization` field, source-key
environment-variable name or JWT-shaped string. This is a bounded inspection of
those payloads, not proof that credentials can never appear anywhere in the
system. No captured question, token or credential value is reproduced here.

After the retest, runtime health reported ready, zero active requests, zero model
requests and `uncertain: false`. The local runtime and debug proxy were stopped.
The failed first attempt remains part of this record; the successful retest does
not retroactively change it.

## Credit deployment and public checks

| Item | Recorded identity or observation |
| --- | --- |
| First deployed credit runtime image | `192.168.25.201:5050/opaque-hosted-demo@sha256:bf713fdd21a073c7e33e1457583f7172bbf22c8b6ab025a16fbc6cc116a257b2` |
| Worker for the first credit admission | `070db8d2-03f8-44b9-a7e0-dfdf8f856360` |
| Rollout baseline | Admission paused and prior work drained with retained generation 6 before the controller rollout. |
| Admission policy | Generation 3, observed generation 3, with no reported type-check warnings. |
| Server dry-run | The final image's positive Pod passed after an initial cache-propagation rejection; the previous image was denied. No Pod creation is implied by these dry-runs. |
| Service readiness | Controller and tunnel each reported 1/1 available; admission was reenabled. |
| Real public admission | A normal browser flow using real Turnstile admitted lease `d797c4efe3b34cb0a763b47537c2be0c`, generation 7. |
| Tenant | `demo-d797c4efe3b34cb0a763b47537c2be0c` |
| Public presentation | Credit UI, manual-review watch and three forbidden-request checks verified. |

The public question “Watch my manual review rate live” completed with five
source queries. Its displayed manual-review aggregate was approximately
20.3666% over a 60-second window with 491 samples; Gemma's final answer reported
20.37 percent. The browser retained 26 tool events and reported allowed source
policy evidence. The source's recorded `last_as_of` was **1788575598**.

The same browser then requested raw borrower data, another customer's portfolio
and average credit score. It displayed `raw_records_denied`,
`customer_scope_denied` and `metric_scope_denied`, respectively. Each showed
“No source access at this denied check”; `source.aggregate_queries` remained
**5** after all three. Thus those denied requests added no aggregate source
queries. These observations do not prove that arbitrary hostile phrasing can
be recognized by the early text check; server tool and token validation remain
the boundary.

DOM evidence is retained under
`/private/tmp/opaque-credit-deployment/evidence/`: `allowed.txt`,
`raw-denied.txt`, `customer-denied.txt` and `score-denied.txt`. These temporary
paths are local operator records, not a durable evidence archive. The public
values are observations, not constants or promised results.

A subsequent combined allowed query returned correct source evidence:
**696 apps/min** and **5.3161% identity mismatch**. Gemma's prose incorrectly
described the application rate using **req/s**. The numeric source evidence and
UI units were correct; the model explanation was not. Source query count reached
six: five watch queries and this one combined query. The correction provides the
explanation model with the actual per-metric units and removes the irrelevant
global unit map. The failure remains part of this record despite the subsequent
successful retests.

At **20:36 MDT**, the operator ended this first credit demo through the normal
browser control. Immediately before cancellation, retained state showed
`chat_inflight: false` and `execution_stopped: true`. Cleanup was verified with
no lease Pods, Services or Secrets remaining in the slot and retained generation
**8**, with `cleaned_lease_id: d797c4efe3b34cb0a763b47537c2be0c`. The control state
was retained. This establishes cleanup of the first credit lease, not a new
visitor handoff or a live revocation-during-stream test.

Admissions were paused under Worker `f542dcbd-8011-46dc-8921-97d929393cfc` while
the unit correction was prepared. A local real-Gemma retest then correctly
explained **169 apps/min**, **3.55% identity mismatch** and a 60-second window.
The source/result/evidence contract did not change. Unit-only runtime image
`192.168.25.201:5050/opaque-hosted-demo@sha256:75932d2aacd7fc6e662a91c4f46f41d29e2264b594a8b370a17b3e4ccbb4aad3`
was deployed with admission policy generation 4, no reported warnings, a passing
positive Pod server dry-run and controller availability 1/1. Worker
`070db8d2-03f8-44b9-a7e0-dfdf8f856360` was restored with admissions open. That
intermediate deployment preceded the model-choice release below.

## Model profiles and packaged qualification

The fixed catalog binds `gemma4-e2b`, `qwen35-4b` or `qwen3-14b` to an exact
configured backend URL and model name. Only the first two are enabled for new
public leases. Every lease action and controller state record retains the
selected alias; authenticated health must match it before readiness or clearing
execution uncertainty. This is configured routing, not attestation of model
weights. The migration assigns historical queue version-2 tickets and unbound
controller schema-1 state explicitly to Gemma, independently of the new default.
New-format missing bindings fail closed. The global model concurrency limit
remains one. [OPERATIONS.md](OPERATIONS.md#fixed-model-selection-and-rollout)
documents the cutover and backward-incompatible state rollback constraint.

The operator verified the Qwen3.5-4B Q4_K_M artifact's **2,740,937,888 bytes** and
SHA-256 `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4`.
The dedicated `opaque-models/llama-server-qwen35` service reached 1/1 readiness
on Jetson 1 using build **b1-fc6545d**, a 2,048-token context, one parallel
sequence and text-only execution. It reported **4,205,751,296 parameters**. Its
image is
`192.168.25.201:5050/llamacpp-jetson@sha256:d69eef7f2933b3d689f21c893767f05dbdf7bab345c83cbb88e93360a6678bf7`.
The old Qwen3-14B head was stalled with RPC not listening; it was backed up at
`/private/tmp/opaque-credit-deployment/llamacpp-head-before-model-update.yaml`
and only that head was scaled to zero to release the GPU. RPC workers 2/3 and
Gemma were unchanged. The new server uses a bounded 8 GiB PVC mounted read-only,
non-root execution and no host mount. The old head must not be restarted while
the new service holds the same GPU.

The new packaged Qwen runtime passed three early denials before any
`source-evidence.json` file existed. The combined application/identity request
returned two results in one source query, with correct prose of **150.00
apps/min** and **6.67% identity mismatch**, in **14.25 seconds**. The prose omitted
the window; validated evidence retained **60 seconds**. A manual-review watch
returned five results and an answer of **20.47%** over 60 seconds in **19.23
seconds**. Final source query count was **6**. These are particular synthetic
observations, not promised values or a benchmark sample.

The four Qwen model requests logged **10.45–10.80 generated tokens per second**
for these calls. Observed cgroup memory was **3,837,538,304 bytes**, with a peak of
**4,239,224,832 bytes** (approximately 3.948 GiB); host `MemAvailable` was
**1,002,324 KiB** afterward. These readings do not guarantee headroom for another
workload. Runtime health matched `qwen35-4b`, its exact model name and the explicit
local test URL, with zero requests, zero model requests and `uncertain: false`.
The local runtime was stopped. Evidence is under
`/private/tmp/opaque-credit-deployment/evidence/`: `qwen-local-0.sse`,
`qwen-local-1.sse` and `qwen-server-first-tests.log`.

The new Gemma catalog runtime separately completed a combined request in
**8.93 seconds**, correctly explaining **48 apps/min**, **0% identity mismatch**
and a 60-second window. It was confirmed quiescent and stopped. Different source
observations and a few requests do not establish a controlled model comparison.

## Model-choice deployment and public checks

| Item | Recorded identity or observation |
| --- | --- |
| Deployed model-choice runtime image | `192.168.25.201:5050/opaque-hosted-demo@sha256:325f36141dea8228d31de0c2ad96ed01652a0dc57668b8456b61f1ff7e8c1247` |
| Model-choice rollout Worker | `9b66c4fa-d104-49b6-9b37-381e6d87df21`; used for the public model checks below. |
| Final enabled Worker | `6f230d13-5e6a-43eb-b7b6-4b76d1424dce`; persistent landing-page action errors, Gemma and Qwen enabled, Gemma default. Runtime image unchanged. |
| Compatible paused Worker | `def2e00d-4cca-4577-a2ab-10414747141e`; understands queue version 3. |
| Migration baseline | Drained generation 8 / controller schema 1, with no outstanding actions before migration. |
| Admission policy | Generation 5, observed generation 5, no reported type-check warnings. |
| Server dry-runs | Two positive Pods, Gemma and Qwen, passed. Five negative Pods were denied: mismatched profile, foreign destination, test override, missing profile and duplicate profile. |
| Public model selection | Normal real Turnstile admission selected Qwen and reached a ready, correctly labeled workspace. |
| First public Qwen lease | `7a297744e4a14306adf1bc371ea439b1`, generation 9, controller schema 2, immutable `model_id: qwen35-4b`. |

The public Qwen watch returned five snapshots containing application and manual
review metrics, for ten individual metric results. Application rates were
651, 670, 687, 702 and **694 apps/min**. Corresponding manual-review percentages
were approximately 20.7373, 20.4478, 20.3785, 20.0855 and **20.0288%**. Qwen's
answer reported **694.00 apps/min** and **20.03%**; the evidence retained the
60-second window. The source recorded five aggregate queries, 718 generated
synthetic events and `last_as_of: 1788577010`.

The three forbidden questions then displayed `raw_records_denied`,
`customer_scope_denied` and `metric_scope_denied`. The source query count stayed
**5** after all three. This confirms these denied checks did not add source
queries under the selected Qwen lease. Before cancellation, controller state
retained `qwen35-4b`, `chat_inflight: false` and `execution_stopped: true`.
The normal End control was clicked at **20:58:31 MDT**. At approximately
**20:58:40 MDT**, the slot had no lease Pods, Services or Secrets. Retained
controller schema 2 held generation **10**,
`cleaned_lease_id: 7a297744e4a14306adf1bc371ea439b1` and `model_id: qwen35-4b`.

Public evidence is retained under `/private/tmp/opaque-model-deployment/evidence/`:
`qwen-public-watch.txt`, the three `qwen-*-denied.txt` records,
`qwen-public-source.json` and `qwen-public-before-cleanup.json`. These are local
operator records, not a durable evidence archive.

A fresh normal Turnstile flow selected the Gemma default at **21:00:44 MDT**,
admitting lease `8f354371ea704cd5ac7d0fb20dfd07b7`, generation **11**, controller
schema 2 and `model_id: gemma4-e2b`. The ready workspace displayed Gemma 4 E2B
and the actual Gemma GGUF name. At **21:01:38 MDT**, the question “What are my
application rate and identity mismatch rate?” completed with **627.00 apps/min**,
**4.63% identity mismatch** and a 60-second window. The source recorded 627
synthetic events and exactly **one aggregate query** for the two authorized
metrics; raw records, borrower data and lending decisions remained false in the
source description. Initial coverage was 56 seconds, so evidence correctly
reported `window_partial: true`; the UI discloses that new sources can have
partial initial windows. These are observations, not fixed example outputs.

Evidence under `/private/tmp/opaque-model-deployment/evidence/` includes
`gemma-public-answer.txt`, `gemma-public-source.json` and
`gemma-public-before-cleanup.json`. Before cancellation, the controller reported
`chat_inflight: false` and `execution_stopped: true`. At **21:07 MDT**, cleanup
was verified with no lease Pods, Services or Secrets in slot 0. Retained state
held controller schema 2, generation **12**, `lease_id: null`,
`cleaned_lease_id: 8f354371ea704cd5ac7d0fb20dfd07b7` and
`model_id: gemma4-e2b`. The operator saved `gemma-public-cleanup.json` alongside
the other evidence.
An earlier join at 20:59 failed without creating a lease; the reason is not
established by this record. A five-second UI refresh hid that action error.
The landing-page correction now keeps failed action errors visible through
polling and provides an explicit retry. It passed the updated UI tests and was
deployed as final Worker `6f230d13-5e6a-43eb-b7b6-4b76d1424dce`. Admissions remain
enabled with the two-model catalog and Gemma default. No cause is inferred for
the earlier failed join, and the fix is not a claim that joins cannot fail.

Final public configuration and the landing asset returned HTTP 200. Configuration
reported `available: true`, exactly the Gemma and Qwen aliases, and Gemma as the
default. The served asset contained the persistent-error behavior. A final
browser check displayed both selector options and the terminal cleanup state;
the operator saved `final-public-config.json` and `final-public-selector.txt`.
Controller, tunnel, Qwen and Gemma each reported 1/1 readiness; the old Qwen3-14B
head remained 0/0, and RPC workers 2/3 each remained 1/1. The checked-in Qwen
Deployment now requests one replica for this qualified configuration; initial
installs must stage at zero until download and GPU allocation are complete.

## Release status and remaining checks

The final documentation build passed strict MkDocs validation and was published
to Cloudflare Pages as `a9d78ea9.opaque-3pv.pages.dev`. The production homepage,
hosted-demo guide and model-catalog page each returned HTTP 200 with the current
content after publication.

| Item | Status |
| --- | --- |
| Final credit runtime image and digest | Model-choice image `325f3614…` deployed with the unit correction; exact digest above. |
| Corrected planner with the packaged runtime | Passed the real-model retest above. |
| Live allowed credit stream | Original Gemma manual-review watch, new Qwen application/manual-review watch and fresh Gemma application/identity answer passed. The fresh Gemma answer used the correct units and window. |
| Live forbidden credit requests | Passed under the original Gemma and new Qwen leases: score, raw borrower and foreign-customer denials with each lease's source count unchanged at five. |
| Public credit rollout | Model choices live: Gemma default and Qwen3.5 4B. Both selections, readiness and answers passed. Landing-page action-error correction passed tests and is deployed in the final Worker above. |
| Credit-session cancellation and cleanup | Original Gemma cleanup passed at 20:36 MDT / generation 8; Qwen around 20:58:40 MDT / generation 10; fresh Gemma at 21:07 MDT / generation 12. Lease resources absent and bindings retained. |
| Independent two-visitor queue handoff | Still not demonstrated live by this record. |
| Revocation during a public credit stream | Not demonstrated live; local auth/revocation tests are separate evidence. |

The rollout started from a reported empty slot with retained generation **6**;
the first credit lease was generation **7** and its verified cleanup is retained
at generation **8**. Qwen then used generation **9** and was cleaned at
generation **10**; the fresh Gemma lease used generation **11** and was cleaned
at generation **12**. This record
does not infer the cause of earlier generation changes or claim an independent
infrastructure inspection.
Retained control state must not be reset to make a release check pass.

The [public hosted guide](../../docs/hosted-demo.md) now describes the verified
live credit flow while retaining these remaining checks. No source credential,
access token, browser cookie or private signing key belongs in this record.

## Scope

These results concern synthetic aggregate authorization and presentation. They
do not establish real customer SSO, production credit-data entitlement, FCRA
compliance, a network-isolation boundary, a microVM, a TEE, confidential inference
or tenant-isolated GPU memory. The model remains a shared trusted processor.
Follow [OPERATIONS.md](OPERATIONS.md) for pause, drain and recovery; uncertain
execution or cleanup must retain its capacity fence.
