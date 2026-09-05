# Opaque milestone roadmap

**Current execution plan · September 5, 2026 · private dogfood workspace**

This is the current checklist for architecture, validation and demonstrations.
Dated product notes and PRDs retain their original evidence and proposals;
their old “next steps” and unchecked criteria do not establish today's priority
or implementation status. Update this file when a gate changes and link the
evidence supporting that change.

The current product direction is [one product for bounded agent work](2026-09-05-unified-product-strategy.md):
request, review exact limits, authorize, execute and inspect the evidence. The
immediate implementation adds a persisted, visitor-approved one-read task to
the synthetic public demo. Its coordinator is explicitly a demo authority path,
not a signed production broker grant. The
[implementation PRD](prd-unified-bounded-work.md) defines this slice.

In parallel, finish the human-approved, single-use staging artifact smoke check
through a separately controlled broker, followed by a truthful receipt and
denied replay. Real application data/enterprise identity and a selected real
host remain separate deployment gates. The implemented attestor and Vault SSH
fixtures extend the tested boundary without completing those gates.

## Evidence rules

- **Built** means implementation exists. **Validated** names the exercised
  contract and environment. **Demonstrated** requires an observed user flow.
  None alone establishes production readiness or customer adoption.
- Automatic fixture signatures remain `insecure_test`. A paired-workstation
  signature establishes an enrolled review application's decision; it does not
  remotely attest a biometric sensor. Record native human review separately.
- Record revision/build identity, commands, results and limitations. Keep a
  sanitized durable summary here; raw logs, private keys, credentials and
  browser/session state stay in ignored or temporary storage.
- A historical pass is historical evidence. Missing temporary files do not
  invalidate a recorded result, but cannot serve as a fresh run.

## Baseline: what already exists

| Mechanism | Built | Validated | Demonstrated / remaining gap |
| --- | --- | --- | --- |
| Broker custody, separate identity, sandbox, OIDC and signed delegation | Yes | Real-daemon/fixture checks; split broker/workload UIDs | Foundation in use; no isolation between co-resident sibling agents or protection from a trusted host administrator. [Foundation](../../CHANGELOG.md), [release evidence](2026-09-04-remote-release-readiness.md). |
| Signed policy, rollback protection, audit export and signed posture | Yes | Federation/identity daemon checks and verifier-gated key release | Software posture and enrolled keys; no hardware measurement. [Federation contract](../federation.md). |
| Durable bounded task grants | Yes | Secret, release and inference fixtures: fixed allowances, replay, expiry/revocation, restart, permanently consumed unknowns | Human consent and real provider effectiveness are distinct gates; this is not generic counted approval leases. [Task evidence](2026-09-04-dogfood-readiness.md). |
| Paired workstation review and one staging workflow dispatch | Yes | Enrollment, pinned TLS, signed test review, separate custody and read-only reconciliation | Host setup passed historically; completed native human review and real GitHub dispatch remain M1–M2. [Release evidence](2026-09-04-remote-release-readiness.md). |
| Tenant inference and HTTP OAuth/MCP aggregate gateway | Yes; broker-owned resource authority added | Two-tenant fixtures; real daemon/gateway current role, membership, disclosure and durable revocation checks | Synthetic-source chat observed with a real model; production IdP/source remain M3. [Inference](2026-09-04-tenant-inference-readiness.md), [gateway](2026-09-04-scoped-metrics-chat.md), [authority](2026-09-05-broker-resource-authority.md). |
| Hosted GPU demo, organization/support roles and demo lifecycle controller | Yes; deployed | Final packaged Gemma/Qwen qualification: 13/13 checks each; separate narrow denial-counter repeats | Public allowed queries, role/customer denials and cleanup observed September 4. Synthetic data and demo-specific controller; no general tenant operator or GPU isolation proof. [Portfolio ledger](../../deploy/hosted-demo/PORTFOLIO-VALIDATION.md), [organization ledger](../../deploy/hosted-demo/ORGANIZATION-VALIDATION.md). |
| Runtime attestor registry, selectors, native codesign identity, generic counted leases and full EMA | Partial: canonical workload identity and listener-bound peercred attestor | Real-daemon observed identity, caller-claim denials and verifying audit chain | Policy selectors/floors, lease migration, registry, codesign and EMA remain. [September 5 progress](2026-09-05-attestor-ssh-progress.md). |
| Bounded SSH certificates and host operation | Schema-4 broker operation, Vault signing, signed host control/receipts and fixed-health guard | 47 real Vault/OpenSSH checks including the Rust executor; 26 Linux guard/control tests; core/CLI/enclave suites | Native human approval and real host integration remain. [Vault integration](2026-09-05-vault-ssh-integration.md), [contract](../../examples/bounded-ssh/README.md). |

The portfolio ledger records missing source counters for the full packaged runs
and a separate successful narrow repeat. Do not widen that repeat into evidence
for unrecovered counters. Public model qualification does not need rebuilding
merely because an earlier note called GPU inference future work.

## Current milestone queue

| Milestone | Status | Next concrete work | Completion evidence |
| --- | --- | --- | --- |
| **M0 — Unify product and refresh the demo** | Demo and visitor guide deployed and verified September 5 | Continue M1–M4; Actions remain disabled | Actual allowed read, denied replay, concurrency/restart/expiry/revocation checks; browser/deployment verification; private material excluded; existing workloads preserved |
| **M1 — Human signed review across the broker boundary** | In progress: fresh native fixture preparation | Verify host reviewer, enroll with pinned TLS, prepare one disposable task and open full native review | Real human decision, `paired_workstation` receipt, one fixture dispatch, denied replay and read-only reconciliation |
| **M2 — One real private staging artifact smoke check** | Preflight in progress; no live dispatch claimed | Resolve private target, reviewed workflow/protections, immutable artifact and credential references | Native-approved GitHub dispatch; exact run correlation; fixed smoke command succeeds; replay causes no second dispatch |
| **M3 — Real source, production identity and unified authorization** | Broker-owned resource authority implemented and exercised with real daemon/gateway fixtures; production selection open | Configure a suitable tenant-aware application source and IdP resource/client contract | Two actual test tenants; permitted read/disclosure; source-level foreign-tenant denial; membership removal, expiry and rotation checks |
| **M4 — Attestor, counted leases, EMA and bounded SSH** | First attestor slice plus broker/Vault SSH operation implemented | Finish policy/lease integration; demonstrate native approval and provision a selected real host | Compatibility, concurrency, real identity/provisioning and host-operation evidence; certificate issuance alone is insufficient |

The demo, preparation and read-only preflight can run concurrently. Complete M1 before
using its native path for M2. M2 closes the first external-effect milestone;
synthetic gateway or demo-controller evidence cannot complete M3/M4. Codex owns
implementation and reproducible checks. The operator supplies the actual human
decision and any missing protected destination, IdP or source configuration.

### M0: unified product, demo and validation

- [x] Consolidate current product direction and define a narrow implementation
  PRD without treating a new credential format or provider catalogue as the
  product. [Strategy](2026-09-05-unified-product-strategy.md),
  [PRD](prd-unified-bounded-work.md).
- [x] Implement the fixture-only one-read demo task: server-issued exact
  `manual_review_rate_percent`/60-second manifest, analyst visitor approval, at most five-minute
  expiry capped by current authority, atomic durable reservation, revoke and
  no refund after ambiguous dispatch.
- [x] Exercise exact caller/customer/digest binding, concurrent/repeated
  execution, restart, expiry and authority changes at source/disclosure
  boundaries. Count actual synthetic source effects.
- [x] Update the entry, workspace and visitor guidance with review → approve
  one read → run → receipt. Keep the existing portfolio, role and lifecycle
  paths usable; verify in a browser.
- [x] Label visitor approval, synthetic evidence and demo-coordinator custody;
  no production identity, signed broker approval or real-host action claims.
- [x] Deploy and verify the built public demo after generated-output inspection;
  retain the new revision and observed results privately.

- [x] Create one roadmap and reconcile both historical PRDs and four readiness
  notes without rewriting old evidence.
- [x] Record fresh workspace/Rust, dashboard/JavaScript and hosted Python checks
  for the current revision; run other fixtures where relevant.
- [x] Build and inspect generated documentation for private routes, search,
  sitemaps and assets, including this roadmap.
- [x] Inventory retained fixture/container state before changes; preserve
  unrelated workloads and distinguish stale task IDs/paths from current commands.
- [x] Establish current private repository visibility and Actions availability.
  The September 4 record reports Actions disabled; local tests are not fresh CI.

Completing M0 does not complete M1's native human ceremony, M2's private provider
effect, M3's actual source/identity provisioning or M4's real-host operation. A
demo task has its own durable coordinator; it is not the production broker task
ledger and does not establish federation between the two.

September 5 coordinator evidence: **32 metrics unit + 42 HTTP tests, 87 JavaScript
and 56 hosted Python tests passed**. Metrics Clippy and the locked workspace
check passed. The new runtime and public Worker are deployed; a normal public
session completed the task, denied replay with exactly one source read, answered
a permitted Gemma portfolio question, denied raw records and cleared task evidence
across persona changes. Cleanup retained generation 24 with no slot resources.
The generated 74-file site and public private-route/search/sitemap checks passed.
GitHub confirms the repository is private and Actions remain disabled; these are
local and public-flow checks, not CI. See the
[complete validation record](../../deploy/hosted-demo/BOUNDED-WORK-VALIDATION.md).

The final visitor-guide clarification about receipt expiry and non-retractable
results is published at Pages deployment `ca3fe4da.opaque-3pv.pages.dev` and the
production domain. The retry passed 18 HTTP checks, including private-route
exclusion, after a strict 74-file rebuild and generated-output privacy scan.

### M1: native human review

- [ ] Start a fresh native fixture with separate broker/workload identities,
  protected workstation state and operator-pinned enrollment. Verify the actual
  host reviewer/helper binaries.
- [ ] Prepare a current task; show the full repository, workflow, artifact,
  destination, allowance, expiry and unknown-outcome meaning.
- [ ] The human completes review and the native ceremony. Record understanding
  of scope, review time, mistakes and interventions.
- [ ] Verify `paired_workstation` receipt provenance, observe the fixture result,
  repeat execution and reconcile without a second dispatch.
- [ ] Retain a sanitized evidence summary. Key enrollment, a displayed window or
  automatic signature does not close this gate.

Runbook: [release dogfood](../release-dogfood.md). Disposable providers test the
human and broker boundary here; M2 tests the real external provider.

### M2: private artifact smoke check

- [ ] Verify `kcirtapfromspace/opaque-dogfood` is private and use its observed
  numeric IDs. Old public repository examples are historical templates, not
  current dogfood destinations.
- [ ] Prepare the manual workflow, `staging` environment and branch/workflow
  protections. Record Actions availability and concrete missing prerequisites.
- [ ] Select an immutable reviewed artifact and a private distribution path
  accessible to the smoke workflow. Verify its fixed binary command and commit
  identity; no internal image or fixture becomes public.
- [ ] Resolve narrow broker credential references and any runner-side artifact
  access. Keep credential values outside manifests, receipts and Git.
- [ ] Review the final private-target contract and bind exact workflow bytes,
  branch/observed commit, artifact digest and environment in trusted broker state.
- [ ] Complete native approval, dispatch once, reconcile the exact run, verify
  its fixed artifact smoke check and demonstrate denied replay.

The [staging template](../../examples/staging-release/README.md) originally used
a public product target/image. Private target and artifact-access adaptation are
part of M2, not grounds to publish internal work. Workflow success proves the
fixed smoke check. Service rollout, rollout rollback and application-health
claims require a separate contract and evidence.

### M3: application data and enterprise identity

- [ ] Choose one read-only aggregate adapter, owning application and two test
  tenants; establish source authorization and custody before private data access.
- [ ] Configure production IdP, exact issuer/resource/client bindings and key
  lifecycle; deny wrong issuer/audience/tenant and ID-token substitution.
- [x] Implement and fixture-validate gateway/broker admission and revocation,
  including changes during active work. Data reads and model disclosure stay
  separately bounded. [Broker authority](2026-09-05-broker-resource-authority.md).
- [ ] Demonstrate permitted reads/disclosure and source/gateway denials,
  membership removal, expiry, credential rotation and stale evidence. Record
  actual source effects and model disclosure separately.

The aggregate adapter, OAuth boundary and hosted lifecycle exist. Connect and
validate a real deployment; present OAuth support does not establish full EMA.
The [production connection preflight](2026-09-05-production-connection-preflight.md)
records why the current Quant and Dex candidates are not yet a provisioned
tenant-aware source/resource-token combination.

### M4: remaining architecture and SSH

September 5 implementation and fresh checks are recorded in
[attestor/SSH progress](2026-09-05-attestor-ssh-progress.md). This advances M4a
and exercises M4e's host controls without completing their production gates.
The [Vault integration](2026-09-05-vault-ssh-integration.md) adds broker approval,
exact task binding, signed host authority and authenticated receipts. AWX is not
part of this design; fixture authorization does not count as native human review.

| Gate | Build and validate | Required evidence |
| --- | --- | --- |
| **M4a — Attestor seam** | Canonical selectors/strength, listener-selected attestor, legacy policy/lease compatibility, peercred adapter | Policy golden corpus; no caller-selected attestor/strength; explicit unavailable-identity failure; real-daemon checks |
| **M4b — Counted leases** | Atomic per-lease allowance and claimed instance attribution without a new principal | Concurrent consumption, expiry and compatibility; labels never authorize; task-grant budgets remain distinct |
| **M4c — Native macOS identity** | Populate code-signing identity through the platform construction path | Signed helper connects to real daemon; assertion at production boundary; explicit prerequisite/skip if signing identity unavailable |
| **M4d — EMA provisioning** | Reconcile existing HTTP gateway with intended MCP resource-server deployment; complete provisioned-client flow | Configured issuer/audience checks; enterprise provisioning, attributed principal and verified audit trail; no duplicate disconnected authorization layer |
| **M4e — Bounded SSH operation** | Select one necessary host task, define CA/certificate/key custody, implement restricted access | Exact principals/destinations, short expiry, host-enforced command/session controls, foreign host/principal/command denial, replay/revocation/expiry and effect receipts |

The historical attestor and bounded-task PRDs are not present in this checkout;
use the current gate definitions and linked implementation evidence, and
reconcile transport and compatibility decisions before coding each slice. SSH
certificate expiry bounds new authentication, not necessarily an established
session. Define termination and command enforcement before claiming bounded
execution from a signed-SSH demo.

## Separate deferred gates

- **Isolation and hardware:** a general tenant operator, more runtime attestors,
  microVM/vsock validation and hardware measurement/key release each require a
  distinct threat boundary and live evidence. Container custody, demo cleanup
  and software posture do not complete these gates.
- **External transparency:** signed checkpoints and witnessed Merkle proofs
  remain demand-led work for a named relying party. Signed exports/local audit
  integrity do not establish public completeness or prove external effects.
- **Adoption:** repeated useful customer work, setup burden and recovery remain
  unmeasured. Demos and synthetic suites do not satisfy historical pilot targets.

## Publication boundary

This roadmap, product notes, dogfood guides, deployment records and operator
evidence remain private. Do not add them to public navigation or assets. Inspect
generated output as well as configuration before publication. Only visitor
documentation and the customer-facing demo are eligible for public deployment.
See [private workspace boundary](2026-09-04-private-workspace.md).
