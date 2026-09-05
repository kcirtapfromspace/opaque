# PRD: bounded agent work, first GitHub manifest workflow

**Historical PRD · September 4, 2026; reconciled September 5.** The bounded task
implementation and fixture validation now exist. The original unchecked
acceptance criteria below are retained as design history, not a current delivery
checklist or evidence that the implementation is absent. Use the
[private milestone roadmap](../docs/product/roadmap.md) for active work and gates.

## Current reconciliation

| Story group | Implemented and recorded evidence | Still needs distinct evidence |
| --- | --- | --- |
| US-001–003: dashboard, workspace and AWS quarantine | Authenticated dashboard/MCP flows, task workspace checks and loopback-only mock AWS restrictions are implemented. Later workspace security fixes and regressions are recorded. | Current-revision verification belongs to M0; do not treat the early assessment's observed defects as current failures without reproducing them. |
| US-004–005: pinned source and immutable grant | Fixed manifests bind repository IDs, Vault KV v2 versions, expiry and canonical approval scope. | Real source permissions and protected downstream-consumer evidence were not established by fixture preflight. |
| US-006: trusted review | Native full-manifest review and paired-workstation signing are implemented; enrollment, TLS pinning and test signing were exercised. | M1 requires a completed human ceremony and its receipt; automatic test signatures never count as human consent. |
| US-007–009: durable authority and outcomes | Fixed allowances, concurrency/replay prevention, restart recovery, revocation checks and permanently consumed unknown outcomes passed fixtures. | Real provider effectiveness remains M2; fresh authority is required for another mutating attempt. |
| US-010: task and evidence | CLI/MCP/dashboard task views, approval provenance and receipts exist; release tasks add read-only workflow reconciliation. | Observe human interpretation of scope and uncertainty in M1 and a real workflow receipt in M2. |
| US-011 and commercial gates | No completed customer adoption/pilot evidence is recorded. | Repeated useful customer work and consented measurement; demos and synthetic traffic do not count. |

Evidence: [bounded-work implementation](../docs/product/2026-09-04-dogfood-readiness.md),
[separate-broker release](../docs/product/2026-09-04-remote-release-readiness.md),
[workspace security review](../docs/product/2026-09-04-release-security-review.md).
This is reconciliation by implemented contract, not a claim that every
subcriterion in each story has been independently verified. Historical public
repository examples are not destinations for the current private dogfood work.

Companion: [product strategy](/Users/thinkstudio/opaque/docs/product/2026-09-04-product-strategy.md). This PRD is additive; it does not overwrite the existing attestor proposal. Scope assumes discovery confirms repeated demand for the workflow. The user has not yet supplied customer or staffing evidence.

## 1. Problem and outcome

An agent can currently ask Opaque to publish a secret without receiving its plaintext. A batch is still a sequence of separately approved operations, and the user lacks a coherent view of the approved batch, progress, limits, and partial outcome.

Let an owner approve one exact manifest and permit an agent to carry out its entries under a durable grant. The grant belongs to the owner and task, independently of agent session lifetime. It cannot be widened or replenished by changing sessions, delegates, request IDs, or clients.

**Reference scenario:** publish `DATABASE_URL`, `API_KEY`, and `DEPLOY_TOKEN` to GitHub repositories `acme/api` and `acme/worker`. These are illustrative names and references, not real credentials. There are six fixed action slots; each permits one mutating dispatch to its exact repository/secret pair using the approved source version or custody-held snapshot. Expiry is 30 minutes. Deletes, other repositories, organization-wide writes, and additional secrets are excluded.

**Outcome wording:** “GitHub accepted six approved secret writes.” It must not imply successful deployment, downstream use, secret correctness, or permanent confidentiality.

**First-spike decision:** use Vault KV v2 and explicit immutable version reads; defer custody-persisted value snapshots and other source backends. Bind Vault instance/namespace, mount, path, field, and version. The official [KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2) supports version-specific reads; Opaque's current typed resolver contract needs new implementation. Unavailable/deleted versions fail closed, never fall back to latest. If discovery does not yield suitable customers, reconsider this choice before the build rather than require vault migration.

**Week-one feasibility gate:** demonstrate a complete trusted review plus authenticator ceremony in the chosen split-domain deployment. Existing FIDO2 assertion verification alone is insufficient. Also verify a pinned source read and a destination contract. Do not start the main ledger implementation while those boundaries are unresolved.

## 2. Goals and users

- A developer can request the batch through the existing CLI/MCP integration.
- A resource owner can understand and approve its exact scope in one trusted review.
- Parallel workers can finish the task without acquiring additional authority.
- The operator can distinguish accepted, unattempted, denied, and unknown outcomes and recover deliberately.
- A platform lead can evaluate whether the process reduces interruptions and allows useful work previously withheld.

Initial buyer, workflow frequency, and price are hypotheses. Installation may be assisted during the pilot. A production pilot requires a separately controlled broker and protected downstream consumers; disposable test values are appropriate until those conditions are established.

## 3. Domain model and state

| Object | Required meaning |
| --- | --- |
| Task | Human-readable objective plus stable owner/organization identity. The objective explains the job; typed constraints enforce it. |
| Grant revision | Broker-issued identifier, owner, authorized caller/delegation context, fixed action slots, source snapshot/version IDs, expiry, approval obligation, and exact policy reference. Canonically encoded and immutable once approved. |
| Action slot | Stable broker-issued slot ID; provider/repository identity, secret name, operation, approved source, and maximum one initial mutating dispatch. |
| Approval | Verified factor evidence bound to grant revision, canonical digest, nonce, expiry, and decision. The trusted reviewer sees the same meaning as the encoded grant. |
| Attempt | Unique admitted dispatch and durable state. Caller request IDs are deduplication inputs, not new authority. |
| Receipt | Versioned record linking grant, approval, admission, provider response/evidence, and final or unresolved state. |

Grant states: `draft → awaiting_approval → active → exhausted/expired/revoked/closed`. A scope change creates a new revision requiring the original approval policy; it does not mutate the approved revision in place. Prior usage remains charged to the task. A closed grant can contain unknown action outcomes and must retain that qualification.

Action states: `unattempted → reserved → dispatched → accepted | rejected | unknown`. A separate denial event records requests refused before reservation. Persist the reservation before dispatch. A crash after reservation is conservatively recoverable as uncertain unless the implementation can prove the request never left the broker.

V1 uses a deliberately conservative limit: **six maximum mutating dispatches, one per approved slot, with no automatic mutation retries**. The six slots are not a claim of atomic changes across two repositories. If preflight proves nothing was sent, a reservation can be released according to an audited local transition. Rejected and uncertain dispatched attempts do not silently create replacement capacity. Recovery requiring another provider call needs an explicit owner-approved additional attempt. Read-only reconciliation has separate rate limits and no power to write.

## 4. User stories and acceptance criteria

### US-001: Restore dashboard data loading
As an operator, I can see real connection status and data without being shown simulated success after an error.

- [ ] Ordinary UI API calls authenticate through the intended same-origin mechanism; streaming authentication has an explicit supported design.
- [ ] Browser flow loads status, policy, operations, and audit through the real route/middleware stack.
- [ ] Unauthorized, unavailable, and demo states are distinct; demo is an explicit user choice.
- [ ] Focused route checks and existing relevant tests pass; no new lint/type errors in touched code.
- [ ] Verify in browser, including authentication failure and unavailable daemon states.

### US-002: Preserve workspace context on the selected agent path
As a developer, I can use the recommended preset without bypassing its workspace restriction.

- [ ] One supported CLI/MCP path propagates trustworthy workspace evidence required by the selected policy.
- [ ] The existing restricted preset accepts its permitted test workspace and rejects an outside or missing workspace.
- [ ] Tests exercise the real wrapper → daemon → policy path, not only a hand-constructed request.
- [ ] Existing relevant tests pass; no new lint/type errors in touched code.

### US-003: Quarantine unsupported AWS resolution
As an operator, I cannot unknowingly send production credentials through a mock-only client.

- [ ] Unsupported AWS access fails closed at top-level operations and every composite/reference resolver entry point.
- [ ] A GitHub operation carrying an `aws:` reference cannot reach the mock client outside an explicitly isolated test configuration.
- [ ] Public readiness/capability output does not advertise unsupported AWS paths as ready.
- [ ] Focused regression and existing relevant tests pass; no new lint/type errors in touched code.

### US-004: Preflight the source and destination
As a requester, I can see whether the exact planned batch is executable and what protection it has.

- [ ] A real, non-disclosing check confirms configured source access and the named GitHub resource identity; mere environment-variable presence is insufficient.
- [ ] Bind stable provider/repository IDs plus readable names; a mismatch or unsupported target is refused.
- [ ] Each Vault KV v2 source uses an explicit version with instance/namespace, mount, path, and field bound before approval. Verify returned version; missing/deleted versions fail without fallback.
- [ ] Resolver/cache keys include all source identity and version fields. Changing the current/latest value cannot change an already approved slot.
- [ ] No plaintext or public hash of a low-entropy secret enters grant metadata, UI, agent output, or logs. V1 does not persist local value snapshots.
- [ ] Show overwrite/create intent when the provider supplies adequate evidence; otherwise mark the uncertainty explicitly.
- [ ] Report downstream consumer protection as verified, operator-attested, or unknown. Never imply branch protection alone proves secret confidentiality.
- [ ] Focused provider-contract tests and relevant existing checks pass; no new lint/type errors. Verify in browser.

### US-005: Store a canonical, immutable grant
As an owner, my approval applies to one unambiguous set of changes.

- [ ] Broker creates canonical, versioned grant and fixed slot IDs from the validated manifest; reject duplicate/conflicting slot entries.
- [ ] Add an explicit multi-destination manifest schema and new typed batch/grant operation path. The current single-repository manifest is not silently reinterpreted.
- [ ] Changing a target, operation, source snapshot, limit, expiry, or delegate changes the grant revision and invalidates pending approval.
- [ ] Agent session creation and arbitrary request IDs cannot issue, amend, or replenish grants.
- [ ] Equivalent field ordering yields the same canonical meaning; malformed or ambiguous data is rejected.
- [ ] Unit/storage tests and relevant existing checks pass; no new lint/type errors.

### US-006: Review and approve exact scope
As a resource owner, I can approve the specific manifest on a surface outside the agent's control.

- [ ] Trusted review displays all six repository/secret pairs, source labels/versions, dispatch ceiling, expiry, and excluded actions.
- [ ] Verified factor evidence is bound to the same canonical grant digest and decision; a changed grant cannot reuse approval.
- [ ] Pilot ships one complete trusted review/factor path; unfinished iOS UI is not treated as a working factor.
- [ ] A dashboard click alone does not constitute out-of-band intent when the agent controls that surface.
- [ ] Grant authorization is an explicit opt-in mode for this operation/workflow. Preserve existing `Always` approval behavior unless an operator deliberately enables the new bounded mode; never silently weaken registry floors or upgraded policies.
- [ ] Approval replay, expiry, scope substitution, and baseline-policy tests pass; no new lint/type errors. Verify in browser on the selected trusted UI.

### US-007: Reserve authority atomically
As an owner, all workers share the allowance I approved.

- [ ] A transaction verifies current grant validity and reserves the unspent slot before any mutation is dispatched.
- [ ] Concurrent requests for a slot produce at most one admitted initial dispatch.
- [ ] A 100-worker test against the six-slot grant dispatches no more than six writes; changing session, worker, or request key does not reset capacity.
- [ ] Persisted state survives restart; missing/corrupt grant state fails closed rather than initializing a fresh allowance.
- [ ] A second broker instance cannot create an independent copy of the allowance. V1 supports one authoritative writer; unsupported multi-writer configurations refuse startup or dispatch.
- [ ] Concurrency/crash tests and relevant existing checks pass; no new lint/type errors.

### US-008: Execute with truthful retry semantics
As an operator, losing a response does not cause an unapproved duplicate write or a false success report.

- [ ] Recheck mutable target identity and required preconditions immediately before dispatch; use the approved source version/snapshot.
- [ ] Repeating the same slot request returns its stored state or receipt without issuing another mutation, regardless of client request-key changes.
- [ ] Automatic transport/adapter mutation retries are disabled for V1 or explicitly included in the approved dispatch contract; no hidden retries exceed the ceiling.
- [ ] Timeout/disconnect after possible dispatch yields `unknown` with the slot still consumed/reserved.
- [ ] Mock-provider tests inject pre-dispatch failure, post-effect response loss, crash/restart, and partial batch completion.
- [ ] UI, logs, and CLI do not call HTTP acceptance deployment success; relevant tests pass with no new lint/type errors. Verify in browser.

### US-009: Stop, revoke, and request expanded scope
As an owner, I can prevent further admissions and see exactly what cannot be undone.

- [ ] Revocation and admission share an ordered durable boundary; no new admission occurs after committed revocation.
- [ ] Display previously dispatched/in-flight actions separately. Revocation does not claim to cancel provider effects already accepted or in progress.
- [ ] Out-of-scope requests are denied before provider dispatch with a concrete reason and a proposed scope difference.
- [ ] Only a trusted owner/policy can approve a revised grant or recovery attempt; old consumption is not reset.
- [ ] Unknown outcomes cannot be cleared merely by closing a task.
- [ ] Race/replay tests and relevant checks pass; no new lint/type errors. Verify in browser.

### US-010: Show the task and evidence
As an operator, I can understand the work without reading event JSON.

- [ ] Task view shows approval state, six slots, accepted/unattempted/unknown states, meaningful activity, remaining/reserved capacity, and required decisions.
- [ ] A receipt identifies grant revision, policy identity, approver evidence, each admitted attempt, and available GitHub response metadata.
- [ ] Receipt distinguishes broker-recorded evidence, provider API acceptance, and any independently verified state. It does not expose secret values.
- [ ] Existing HMAC audit verification remains intact. Public verification, if offered, uses an explicit asymmetric evidence-signing design and trust root; never disclose the HMAC secret as a verifier key.
- [ ] Export and reopen a representative accepted/partial/unknown receipt; verify its declared checks and alteration detection.
- [ ] Relevant tests pass with no new lint/type errors. Verify in browser with keyboard navigation and narrow layouts.

### US-011: Measure pilot outcomes without collecting credentials
As the product team, we can decide whether the workflow earns adoption.

- [ ] Record task start/first value/completion, stated evidence level, interventions, scope amendments, and setup assistance with agreed customer data handling.
- [ ] Do not collect secrets, unrestricted tool arguments, or full provider response bodies as product analytics.
- [ ] Report per-organization repeat use and task outcomes, including unknowns and failures, against its observed incumbent baseline.
- [ ] A pilot report can distinguish completed useful work from demos and denied calls.
- [ ] Relevant checks pass; no new lint/type errors. Verify any analytics UI in browser.

## 5. Functional requirements

- **FR-1:** The broker is the authoritative issuer and state owner for grants; the agent can only propose work and invoke an authorized slot.
- **FR-2:** Approval binds exact canonical scope, and the executor consumes that same scope without reinterpreting a mutable plan file.
- **FR-3:** Authorization combines current policy, trusted principal/delegation, grant validity, fixed slot constraints, and remaining capacity.
- **FR-4:** Reservation is durable and atomic across supported workers. Child attribution never creates a separate spend allowance.
- **FR-5:** Source material cannot change between approved snapshot/version and execution unnoticed.
- **FR-6:** A dispatch has a durable identity and state. Client retries cannot cause additional dispatches by inventing new keys.
- **FR-7:** Unknown outcomes remain explicit and retain their charge until a documented recovery decision; additional writes require additional authority.
- **FR-8:** Revocation blocks new admissions with an explicit in-flight limitation.
- **FR-9:** Review, progress, and receipt surfaces show the same resource/action semantics and evidence levels.
- **FR-10:** Legacy operation/policy behavior remains unchanged outside explicit grant-mode configuration.
- **FR-11:** Neither grant metadata nor telemetry contains credential plaintext or secret-derived public fingerprints.
- **FR-12:** Production assurance is conditional on broker custody and downstream consumer control; the interface states the actual integration boundary.

## 6. Non-goals

No arbitrary shell execution under a six-call allowance; no universal deployment guarantee; no bulk deletion; no general CA or token-format expansion; no mobile rebuild; no public transparency network; no automatic compensation across GitHub repositories; no universal exactly-once promise; no inference that an agent's natural-language objective is honest; no isolation between sibling agents merely because they have different labels.

Remote OAuth/EMA, a general attestor registry, and additional providers are separate increments when required by a validated deployment. V1 can use one supported client and one custody architecture, but must not advertise broader interoperability.

## 7. Technical approach and dependencies

Reuse the existing operation registry, daemon secret resolution, factor verification, policy evaluation, GitHub adapter, and audit events. Add a small grant/state module and storage migration beside them. Do not overload the in-memory lease cache into a persistence protocol without specifying crash behavior.

Treat the existing registry's per-operation approval floor as a deliberate compatibility boundary. A task grant is a new authorization path with explicit configuration and a documented threat model, not a shortcut that marks every call preapproved.

Use one authoritative transactional ledger in V1. Atomic counters local to separate daemons do not enforce an organization-wide budget. Defer distributed consumption until there is a concrete consistency or partitioned-budget design.

Integrate meaningful tests at the wrapper/daemon/provider boundary. Pure policy and tool-schema tests cannot detect absent workspace context, broken browser authentication, or effect-after-timeout behavior. Run the repository's pinned toolchain and required checks; report remaining baseline failures accurately rather than copying the older PRD's unpinned-toolchain assumption.

## 8. Success and release gates

Technical release gate: the six-slot scenario, fan-out, session reset, altered source/target, approval replay, restart, duplicate request, timeout-after-effect, and revocation race all satisfy the stated contract. A clean install reaches one truthful useful outcome using the selected provider and trust deployment. CI checks appropriate to changed components pass; selected end-to-end and browser flows are verified.

Commercial gate: three independent teams repeat the workflow over at least two weeks and two agree to paid continuation; candidate pilot targets include 80% completion without expansion and 50% fewer interventions than their own baseline. Treat these as provisional thresholds, not statistical proof of PMF. If the task is too infrequent, validate a recurring action for the same buyer before extending the platform.

Only organically needed customer work counts toward adoption gates. Exclude demos, disposable test values used solely for authorization experiments, synthetic replay/concurrency batches, and activity generated by the vendor to increase usage.

## 9. Decisions to resolve through discovery and the first spike

1. Which repeated task and buyer will commit a test resource and a paid pilot?
2. Does the first cohort actually use Vault KV v2, and does its retention policy preserve approved versions long enough? If not, revise the single-source choice before implementation.
3. Which trusted approval surface/factor can the first customers operate without unacceptable setup burden?
4. What evidence can GitHub expose for destination protections and post-timeout reconciliation? What must remain explicitly unknown?
5. Which client reliably propagates the required workspace and principal information?
6. Does a receipt need a customer-verifiable signature in the first pilot, or is a verified internal chain plus export sufficient?

These questions affect implementation choices; they do not justify adding unrelated integrations. The first milestone is one complete, demonstrably bounded customer workflow.
