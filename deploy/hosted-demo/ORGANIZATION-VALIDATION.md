# Organization and support demo validation

Record date: **2026-09-04 (America/Denver)**. This record covers the fictional
Northstar Financial Systems organization, Harborlight Credit Union customer,
engineer activity and temporary support increment. Earlier
[credit/model validation](CREDIT-VALIDATION.md) and
[operational validation](VALIDATION.md) remain historical records.

**Current status:** local tests and the corrected packaged Docker/Gemma run
passed. The organization release is deployed after a drained cutover. A normal
public browser session verified analyst access, the engineer boundary, future
sharing and a support read, then expired and released its slot resources. A
second public session passed Cedar denial without a source query and removal of
previously shared text. Ending that session removed its slot resources and
retained the completed generation in durable controller state.

## Implementation under test

The fixture uses three distinct OAuth subjects and fixed clients, each with a
real PKCE exchange. The engineer has only `organization:activity:read`; analyst
and support have their separately admitted metric permissions. Support has no
stream scope and needs a case bound to its subject, token, exact customer,
authorization generation and a deadline no later than 300 seconds or token
expiry. Hosted tokens are capped by the lease deadline. Cedar Community Bank
is a directory-only entry with no connected source or data entitlement.

The runtime keeps three private gateway cookies and chooses the target cookie
only for the corresponding role activation. It changes the selected identity
only after a complete successful response. Ambiguous transport, malformed or
truncated response, and complete 3xx/5xx responses disable readiness; known 4xx
rejection preserves the prior actor. Requests waiting for the identity lock
recheck readiness and expiry before dispatch. Controls neither reserve model
work nor clear existing execution uncertainty.

Activity is projected from actual requests inside this lease. Question text is
hidden by default. Only the analyst can enable future sharing, and disabling it
purges stored text. The bounded feed contains at most 100 records, with a
900-second retention ceiling; the hosted lease ends sooner. The feed excludes
numeric source results, model answer text and credentials. A role change advances
the generation used by direct MCP, nested chat MCP and streamed delivery.

## Completed local evidence

| Check | Recorded result |
| --- | --- |
| Hosted Python suite | **49 tests passed** in 22.313 seconds after the real HTTP completion regression was added. Log: `/private/tmp/opaque-organization-python-tests.log`. |
| Rust suite | Provider reported **53 tests passed**, including nine organization cases, and repeated the final suite successfully after formatting. |
| Rust lint | All-target Clippy passed with warnings denied. |
| JavaScript | **106 tests passed**: 62 queue/HTTP/Worker and 44 UI tests. Log: `/private/tmp/opaque-organization-deployment/javascript-final.log`. |
| Packaged build | Offline Linux/ARM64 Cargo build and stripped runtime binary passed; final Docker image identity is recorded below. |
| Identity boundary | Distinct subject/client login binding, engineer raw-bearer and spoofed-header denial before source/model I/O, and production configuration refusing the role simulator. |
| Support | Exact assigned customer, bounded case expiry, no stream scope, and missing/incorrect case denial. A case reason does not add token permissions. |
| Generation and disclosure | Queued SSE results and delayed nested MCP calls fail after analyst→engineer→analyst; a role change during model planning prevents source access and a second model call. |
| Sharing | Future capture only, default concealment, recognized sensitive/denied question concealment, and body-time projection after withdrawal. These tests do not prove universal PII detection. |
| Evidence accuracy | A successful source read remains recorded even when a later watch step fails. Generic failure does not establish no source access. |
| Runtime/controller controls | Fixed paths/methods/generation/expiry; no private cookie or credential forwarding; busy/uncertain controls rejected; metadata/control replies do not release model fences or emit completion trailers. |
| Control ceiling | The shared control limit cannot be reset by switching personas. At the ceiling, stored shared text is cleared; rejected controls do not append new audit entries. |

The independent bounded review identified and verified corrections for retained
source-access evidence, nested MCP generation propagation, readiness after a
waiting identity lock, and an authorization check immediately after an awaited
status event before explanation-model dispatch. No remaining material finding
was reported in that slice. This is not a whole-repository security assessment.

## Packaged runtime failure and correction

The first organization image failed closed during role activation: the Rust
gateway accepted the transition, but Python 3.11's `read1` left a fully consumed
Content-Length JSON response marked open. The runtime returned 503 and withheld
readiness instead of assuming a consistent selected identity. That failed local
image was not used for the public organization release.

The corrected path performs a final empty `response.read(1)` before checking
closed framing and remaining length. A new test uses a real stdlib HTTP/1.1
loopback server and `HTTPConnection`, beyond the existing response double.
Complete JSON now activates the intended identity; truncation still fails
closed without switching the selected cookie. The full 49-test suite passed
after this correction.

## Corrected Docker run with real Gemma

The operator completed the following sequence using the packaged Python 3.11
runtime and the real configured Gemma service:

1. Three distinct PKCE logins completed; the analyst asked an application-rate
   question with sharing off and received an answer in **5.78 seconds**.
2. The engineer's same question was denied in **0.03 seconds**, without result
   events. The earlier analyst question remained concealed.
3. The analyst enabled sharing and asked an identity-mismatch question, which
   completed in **5.74 seconds**. The engineer saw only this shared question.
4. Support received a case for the exact assigned customer, bounded to at most
   300 seconds, and could not change sharing (403). Its non-streaming
   manual-review question completed in **5.69 seconds**.
5. A named Cedar question was denied in **0.03 seconds**. Returning to the analyst
   and disabling sharing purged all stored text visible to the engineer.

The final source evidence recorded exactly **three aggregate queries** after
the three allowed and two denied questions. The activity feed contained **eight
records**. Runtime health was ready with zero active requests, zero model
requests and no execution uncertainty; the local container was stopped.
The timings describe these few requests, not a model benchmark or service SLO.

Source evidence and local audit records are retained under
`/private/tmp/opaque-organization-deployment/evidence`. These temporary operator
paths are not a durable evidence archive. No cookies, bearer tokens, private
keys or source credential values are reproduced here.

## Deployment and public checks

| Item | Status or identity |
| --- | --- |
| Final runtime image | `192.168.25.201:5050/opaque-hosted-demo@sha256:f55b4cea579771465eadd69065ad4d6d38f9bb7c698f6118681631fa9f01289c` |
| Paused cutover Worker | `f54cee7f-45e8-43d5-b3f8-c22c4bf40b76`. Drained baseline was empty with retained controller schema 2, generation 12. |
| Initial enabled Worker | `80a86a84-8f2c-4765-aefa-3dab8427206d`, including the organization routes. |
| Current Worker | `7c2ae49d-f2bb-443f-832c-54856a09c7e7`, with consistent model and deadline decoration on control responses. Runtime image unchanged. |
| Published guide | Strict MkDocs build passed; Pages deployment `8b1f1c35.opaque-3pv.pages.dev`. Public hosted guide and organization note returned 200 with the final role-flow and cleanup evidence. |
| Server dry-runs and policy | Controller and admission policy passed; positive Gemma and Qwen runtime Pods passed. Admission policy observed generation 6 with no type-check warnings. |
| Service readiness | Controller on the final runtime image 1/1; tunnel, Gemma and Qwen each 1/1. Existing RPC workers on nodes 2 and 3 remain 1/1; the 14B head remains at zero replicas. |
| Public release | Normal Turnstile admission selected Gemma and prepared lease `798decb7edba46a8a395ad0f2080e7dd`, controller generation 13. Edge deadline: `2026-09-05T04:02:05.725Z` (22:02:05 MDT). Gemma and Qwen remain the choices, with Gemma default. |
| Public roles and sharing | Analyst application query returned **704 apps/min** with **one source query**. Engineer had zero metric-tool entitlement; the earlier unshared question was concealed. The saved engineer view showed the later shared identity-mismatch question. In the second session, the engineer saw a newly shared application question, then lost access to its text after the analyst disabled sharing. |
| Public support | Case `c29dac6c-0867-4ad0-94a9-5867eadf30f3` named Harborlight and was capped to the edge deadline `2026-09-05T04:02:05.725Z`. A real support answer reported **19.1964%** manual review, **672 samples**, **60 seconds**. |
| Public support expiry/revocation | The case deadline was bounded by the lease. Separate case expiry/revocation during active work remains local-test evidence; no public active-work revocation proof is claimed. |
| First lease cleanup | Lease `798decb7edba46a8a395ad0f2080e7dd` expired naturally before Cedar/purge checks. Kubernetes readback confirmed no Pods, Services or Secrets in slot 0. |
| Final lease cleanup | Public **End this demo** completed for `f1016d624870457cb8afb99452dcfc0e`. Slot 0 had no Pods, Services or Secrets; retained state was schema 2, generation 16, `lease_id: null`, the matching `cleaned_lease_id` and `model_id: gemma4-e2b`. |
| Final public check | Landing and public configuration returned 200; admissions were available and the two approved models were listed. Public capacity counts were absent from both HTML and configuration. |

The public organization panel displayed Northstar Financial Systems, the three
demo personas, Harborlight as the assigned customer and Cedar as directory-only,
with question sharing off. During role controls, session responses exposed the
gateway's raw deadline and omitted the selected-model label. The actual lease
authority was unchanged. The Worker correction applies the same edge deadline
and model decoration to every session-bearing control response and clamps the
displayed support-case deadline in activity. The HTTP assertions were extended;
all 106 JavaScript tests still passed. The correction is deployed in the current
Worker recorded above. A closed browser-automation tab had to be reopened before
the support flow; this was not an application failure and required no image
change.

Public DOM evidence includes `public-analyst-unshared.txt`,
`public-engineer-hidden.txt`, `public-analyst-shared.txt`,
`public-engineer-shared.txt` and `public-support-allowed.txt` under the same
operator evidence directory. The first session's natural expiry prevented the
remaining checks from completing within that lease, so they were performed in a
new normally admitted session.

### Second public session

Lease `f1016d624870457cb8afb99452dcfc0e` completed the remaining flow:

1. The analyst enabled future sharing and asked an application-rate question.
   The engineer could inspect that question and tool metadata while retaining
   no metric entitlement (`public-second-engineer-shared.txt`).
2. Support case `d09c155b-054b-4961-a5d4-6e87e5b8ad77` named Harborlight, used the
   reason “Investigate reported application metrics” and lasted at most 300
   seconds. A question about Cedar's application rate returned
   `customer_scope_denied`, zero tool calls and no source access at that check.
   The source's aggregate-query count remained **one before and after** the
   denial, recorded in `public-second-source-before-denial.json` and
   `public-second-source-after-denial.json`.
3. The analyst selected **Stop sharing & clear stored text**. The engineer
   expanded both chat records: all question text was concealed, and the earlier
   shared application question was absent (`public-engineer-purged.txt`). The
   activity view retained three metadata records, including the denial.

Final audit and source records were saved. The audit retained distinct subjects,
persona authorization generations 2 (engineer), 3 (support), 4 (analyst) and
5 (engineer), the 300-second support limit, `customer_scope_denied` and sharing
disabled. These persona generations are separate from the controller's lease
generation. Public **End this demo** completed, and slot readback confirmed no
Pods, Services or Secrets. `public-final-cleanup-state.json` records controller
schema 2, generation 16, no current lease and the matching cleaned lease ID.
The operator removed the local runtime archive and environment file and left
no local test container running.

The [organization product note](../../docs/product/2026-09-04-organization-consumers.md)
distinguishes implemented controls from production work. The public
[hosted guide](../../docs/hosted-demo.md) must retain that distinction until the
public checks are recorded.

## Limits

This is a self-selected simulator using disposable identities and synthetic
source data. Three real token exchanges do not prove real staff employment,
production customer membership, customer-approved support access or an OAuth
token-exchange service. The organization is scoped to this disposable lease;
the directory does not demonstrate multiple connected customer sources.

The hosted runtime rejects role/sharing changes while chat or model work is
active or uncertain. Gateway epoch tests are not live proof of immediate role
revocation during an active hosted model request. Consent withdrawal cannot
erase content already delivered to a recipient. Prompt hashes are not
anonymization, and sanitization does not guarantee removal of personal data.

No production organization directory, central warehouse, raw credit data,
borrowing/underwriting decision, FCRA compliance, TEE, microVM, confidential
inference, GPU-memory isolation or verified cross-network isolation is claimed.
Shared model services remain trusted processors. Follow
[OPERATIONS.md](OPERATIONS.md) for pause, drain and compatible rollback; retain
all lease generations and uncertainty fences.
