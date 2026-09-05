# PRD: unified bounded work and the one-read demo

**September 5, 2026 · implementation requested · private workspace**

This PRD turns the [unified product strategy](2026-09-05-unified-product-strategy.md)
into the next concrete implementation slice. The user explicitly requested
strategy, implementation and a demo update; implementation proceeds alongside
this document. Checkboxes below are completion criteria, not claims that the
work is already tested or deployed. The [roadmap](roadmap.md)
records milestone evidence.

Current validation: **32 metrics unit + 42 gateway HTTP tests, 87 JavaScript
checks and 56 hosted Python tests passed** on September 5, with metrics Clippy
and locked workspace compilation. The public deployment completed normal
admission, keyboard confirmation, one source read, denied replay, a permitted
Gemma portfolio question, raw-record denial, persona revocation and cleanup.
See the [private validation record](../../deploy/hosted-demo/BOUNDED-WORK-VALIDATION.md)
for exact images, source counters, public-output checks and remaining limits.
The final guide clarification about receipt expiry and non-retractable results
is published at Pages deployment `ca3fe4da.opaque-3pv.pages.dev` and the production
domain; 18 HTTP checks and the 74-file generated-output privacy scan passed.
Failure/unknown/concurrency cases use automated fixtures; no production identity,
native human signature or real host is claimed by this demo.

## 1. Overview

Opaque already has broker task grants, application authorization and a bounded
Vault/OpenSSH executor. Visitors currently see a synthetic-data chat experience
without directly approving one exact piece of work and observing its consumption.
Add that missing experience through a narrow, fixture-only demo task coordinator.

The fixed task reads **manual review rate over a 60-second window** for the
workspace's assigned fictional customer. The visitor reviews the exact task,
approves **one read**, executes it, then sees its observed result and a denied
replay. The task survives application restart in its current private state store;
an ambiguous dispatched read remains consumed.

This is actual enforcement over synthetic source data. The coordinator's
approval is a visitor action under a disposable demo identity. It is not a
production IdP, native human authentication ceremony, signed broker task grant
or Vault/SSH action.

## 2. Goals

- Make the request → review → authorize → execute → result workflow usable in
  the existing demo without changing model choice or existing chat behavior.
- Bind one exact source read to server-owned customer, identity, operation,
  manifest identity/digest, allowance and expiry.
- Persist consumption and deny replay under concurrent requests and restart.
- Recheck current authorization before dispatch and before disclosing evidence.
- Display the difference between visitor approval, source-observed evidence,
  denied work and an unknown dispatched outcome.
- Refresh public copy and visitor guidance while excluding private documents,
  configuration, operator records and raw artifacts from all public output.

## 3. User stories

### US-001: prepare one exact task

**Description:** As a visitor, I want a task with exact limits so that I can
understand what one approval permits.

**Acceptance criteria:**

- [x] Task creation is available only in explicit fixture/demo mode; the
  production broker-authority path cannot fall back to this coordinator.
- [x] The server fixes the operation to the existing aggregate source read of
  `manual_review_rate_percent` over 60 seconds and the authorized fictional
  customer, available to the current analyst identity only.
- [x] The server supplies a unique task identity, canonical manifest digest,
  identity binding, one-read allowance and expiry no more than five minutes
  from creation and no later than current token/workspace authority.
- [x] The client cannot substitute metric, tenant, source endpoint, command,
  principal, budget or deadline through extra/untrusted fields.
- [x] Planning performs no source read or model disclosure.
- [x] Relevant Rust tests and lint checks pass.

### US-002: review and approve the prepared scope

**Description:** As a visitor, I want to review the actual prepared task before
approving it so that the permission I give matches the eventual source read.

**Acceptance criteria:**

- [x] Before approval, the UI displays customer, operation, metric, window,
  allowance, deadline and a clear synthetic-data/demo-identity label.
- [x] Approval binds the server task identity and exact manifest digest;
  changed, expired, revoked or other-identity tasks cannot be approved.
- [x] The approval action is protected by the same session/origin rules as
  other browser mutations, with no state-changing GET.
- [x] UI labels the act as visitor approval, with no native biometric,
  verified-employee or cryptographic-approval claim.
- [x] Pending, rejected, disconnected and unavailable states are visible and
  do not show a success state or silently permit execution.
- [x] Verify in browser, including keyboard operation and narrow viewport.

### US-003: execute once and preserve uncertainty

**Description:** As a visitor, I want the service to consume the approved read
once so that retrying or opening another page cannot create more authority.

**Acceptance criteria:**

- [x] Execution requires the current analyst identity, customer, role authority,
  expiry and exact task/manifest binding; engineer and support are denied.
- [x] SQLite atomically reserves the read before provider dispatch; concurrent
  requests yield at most one dispatch for that task.
- [x] Duplicate execution never dispatches a second source request.
- [x] A persisted reserved task recovered after restart cannot become unused.
- [x] A failure after dispatch may have started produces an unknown/consumed
  outcome; it is never automatically refunded into executable authority.
- [x] A source response is validated for exact query/customer/window and
  freshness before it can become successful task evidence.
- [x] Targeted tests count actual fixture source calls for concurrency,
  duplicate execution and source failures; ledger tests deny reuse after recovery.

### US-004: stop future work and withhold stale authority

**Description:** As a visitor, I want revocation and current permissions to
matter while the task exists so that the approved scope is not a lasting bypass.

**Acceptance criteria:**

- [x] Revoke persists before acknowledging success; a revoked task cannot
  later execute or reopen through delayed approval/replay.
- [x] Execution checks current authority before dispatch and again before
  evidence disclosure. Removed/changed identity or customer authority denies.
- [x] Identity change or revocation during a blocked fixture source request
  suppresses evidence; task expiry also suppresses held receipt delivery.
- [x] The UI identifies revoked work and prevents another run.
- [x] Publish the final visitor-guide clarification that expiry closes receipt
  access and revocation cannot retract evidence already received; the production
  domain and Pages deployment were verified after connectivity recovered.
- [x] Cross-identity/cross-workspace task lookup, approval, execution and
  revocation are denied without exposing another visitor's task data.
- [x] HTTP tests exercise revocation, identity changes and delayed receipt
  delivery through real gateway routes.

### US-005: explain the result with accurate provenance

**Description:** As a visitor, I want a receipt that distinguishes approved
scope from observed activity so that I can see what the service substantiates.

**Acceptance criteria:**

- [x] The result shows manifest/task identity, approved allowance and expiry,
  consumption state, terminal outcome and operation-specific source evidence.
- [x] Success exposes bounded validated metric evidence with units, window
  and source timestamps; source unavailability is distinct from numeric zero.
- [x] Receipt provenance names the demo coordinator and synthetic source.
  No signature verification, production broker or real-host execution is implied.
- [x] A denied replay is visible and reports no additional source dispatch
  only when instrumentation or the exercised execution path establishes it.
- [x] Missing results, interrupted transport and unknown dispatch do not
  become a verified denial or successful completed read in the UI.
- [x] Verify the successful flow, replay and revoked state in the browser; exercise
  disconnected and unknown states with automated UI tests.

### US-006: refresh the demo and preserve its working paths

**Description:** As a visitor, I want the demo entry and workspace to explain
one coherent product without losing the existing portfolio exploration.

**Acceptance criteria:**

- [x] Landing and workspace copy explain bounded work and introduce the one-read
  task alongside the existing synthetic portfolio chat, with a separate one-read
  task allowance and existing chat question limit.
- [x] Available-model selection, bot check, queue, ready/expiry states, role
  exploration, sharing controls, live watch and cleanup keep their regression
  coverage; normal public admission, roles, Gemma chat and cleanup also pass.
- [x] Visitor documentation describes the actual new flow and its approval,
  data and receipt limitations without private implementation details.
- [x] Vault SSH is described only as a separately validated pattern if shown;
  visitors are not offered a fake real-host action.
- [x] Browser validation covers entry, one allowed read, one denied replay and
  an existing permitted portfolio question on the built application.

### US-007: publish only the visitor experience

**Description:** As the operator, I want a verified public build and narrow
deployment so that the refreshed demo does not expose private work or interrupt
unrelated running workloads.

**Acceptance criteria:**

- [x] Relevant application/Rust and hosted-runtime checks pass for changed
  code; record actual commands, environment and results privately.
- [x] Inspect generated public routes, assets, search and sitemaps. Exclude
  `docs/product/`, `tasks/`, dogfood guides, deployment evidence and raw state.
- [x] Public output contains no internal host references, credentials, keys,
  private repository configuration or copied raw session artifacts.
- [x] Inventory retained runtimes and target only demo resources during
  deployment; preserve unrelated workloads and in-progress local work.
- [x] Verify the deployed entry and workspace match the built revision and
  exercise the task behavior; a local pass alone does not mean deployed.
- [x] Record remaining native-review, real source/IdP and real-host gates
  separately from this demo's completion.

## 4. Functional requirements

1. **FR-1:** Define a single typed fixed-read manifest and reject unrecognized
   authority-affecting fields. Browser text is not a policy input.
2. **FR-2:** Store task identity, canonical digest, caller/customer binding,
   approved limit/deadline, state and bounded result in a private SQLite store.
3. **FR-3:** Keep planning, approval, execution, lookup and revoke distinct;
   every protected request revalidates current caller authority.
4. **FR-4:** Reserve atomically before dispatch and consume permanently after a
   possibly dispatched effect. A read-only operation still consumes its slot.
5. **FR-5:** Bind approval to the prepared manifest, not a free-form chat answer.
6. **FR-6:** Check expiry and revocation at execution/disclosure boundaries.
7. **FR-7:** Derive visible task state and receipt from authoritative server
   records; the frontend cannot award success or refill a counter.
8. **FR-8:** The fixture-only coordinator must fail closed outside its intended
   deployment mode and must not bypass the existing production broker endpoint.
9. **FR-9:** Preserve existing source authorization, metric validation, output
   bounds and session cleanup. Do not forward user tokens to source/model APIs.
10. **FR-10:** State publicly that this flow uses synthetic application data and
    visitor approval under demo identities; retain production/operator evidence
    only inside the private workspace.

## 5. Non-goals

- Deploying a new production IdP, choosing a real private application dataset
  without its tenant contract, or claiming those connections are complete.
- Replacing the broker's task ledger, approval verifier, Vault CA custody or
  exact host controls with the demo coordinator.
- AWX, arbitrary shell access, arbitrary metrics/SQL, arbitrary destinations,
  automatic scope expansion, generic provider discovery or a new token protocol.
- Adding DPoP, SPIRE, AuthZEN, offline capabilities, hardware attestation or a
  second CA provider merely to align the demo with research vocabulary.
- Claiming customer adoption, regulatory compliance, confidential inference,
  independent signature verification or globally exactly-once external effects.

## 6. Design considerations

Reuse the current stack and typography. Show one sequence with clear verbs:
**Review**, **Approve one read**, **Run**, **Inspect receipt**. Keep exact scope
visible through the sequence. Use semantic buttons, keyboard focus, readable
contrast and an inline result area that does not move controls unexpectedly.

Use distinct text for **not approved**, **approved**, **reserved/consumed**,
**observed**, **denied**, **expired**, **revoked** and **unknown**. Actual internal
enum names may differ; do not hide uncertainty behind a green completion badge.
No fake testimonials, run statistics or evidence are added.

## 7. Technical considerations

Keep the implementation additive in the existing Rust metrics gateway and
hosted runtime. Reuse its verified access object, organization authorization,
source adapter and mutation protections. Avoid duplicating token validation.
The SQLite transition is an execution guard, not an optimization; persistence,
concurrency and crash recovery are part of the tested contract.

The actual broker resource authority and SSH contracts remain the production
architecture foundation. A later production task API should reuse that broker
and its canonical task types, not promote this fixture-only endpoint by removing
a mode flag. Cross-process enforcement and trust boundaries need their own
integration and deployment evidence.

## 8. Success metrics

Technical completion requires one observed source read for a successful task,
zero additional reads on duplicate execution, no budget recovery after restart,
denial or withheld evidence when authority changes, and accurate receipt labels.
Report the exact tested cases rather than claiming universal security.

Product validation requires a visitor to identify the permitted customer,
operation, allowance and expiry, then explain the observed versus denied result.
This is a proposed usability check, not a measured result. Customer value still
requires repeated useful work at independent organizations.

## 9. Open decisions after this slice

- Which actual application owner can supply a semantically correct read-only
  aggregate API and two independently authorized test tenants?
- Which production IdP/resource-token contract and registered client will be
  provisioned, including signing-key rotation and exact membership mapping?
- Which native human reviewer and selected real host will close those separate
  deployment gates?

These decisions do not block implementing and validating the explicitly scoped
synthetic demo. Their absence must remain visible in the product roadmap.
