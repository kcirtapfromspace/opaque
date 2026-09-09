# Opaque milestone roadmap

**Current execution plan · September 5, 2026 · private dogfood workspace**

This is the current checklist for architecture, validation and demonstrations.
Dated product notes and PRDs retain their original evidence and proposals;
their old “next steps” and unchecked criteria do not establish today's priority
or implementation status. Update this file when a gate changes and link the
evidence supporting that change.

The current product direction is [one product for bounded agent work](2026-09-05-unified-product-strategy.md):
request, review exact limits, authorize, execute and inspect the evidence. The
persisted, visitor-approved one-read task is deployed in the synthetic public
demo. Its coordinator is explicitly a demo authority path,
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
| Durable bounded task grants | Yes | Secret, release and inference fixtures: fixed allowances, replay, expiry/revocation, restart, permanently consumed unknowns | Human consent and real provider effectiveness are distinct gates; this is not generic counted approval leases. [Task evidence](2026-09-04-dogfood-readiness.md), [PRD reconciliation](../../tasks/prd-bounded-agent-work.md). |
| Paired workstation review and one staging workflow dispatch | Yes | Enrollment, pinned TLS, separate custody, completed native human review and read-only reconciliation | M1 demonstrated: one human-approved fixture dispatch, denied replay and persisted receipt after restart. Real GitHub dispatch remains M2. [Native proof](2026-09-05-native-review-proof.md), [release evidence](2026-09-04-remote-release-readiness.md). |
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
| **M1 — Human signed review across the broker boundary** | Demonstrated September 5 with actual human native review and one fixture dispatch | Proceed to M2; retain the bounded native-review regressions and readiness probe | `paired_workstation` receipt, one observed fixture dispatch, denied replay before/after restart, MCP/dashboard reconciliation. [Proof](2026-09-05-native-review-proof.md) |
| **M2 — One real private staging artifact smoke check** | Guarded workflow/live broker recipe prepared; amd64 artifact locally validated, unpublished; live prerequisites unmet and Actions disabled | Configure independent review and effective private protections, install workflow, publish a matching private artifact and provision live broker custody | Native-approved GitHub dispatch; exact run correlation; fixed smoke command succeeds; replay causes no second dispatch. [Local proof and live limits](2026-09-05-native-review-proof.md) |
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
- [x] Record workspace/Rust, dashboard/JavaScript and hosted Python checks
  for the delivered revisions, with other fixtures where relevant. Consolidation
  validation is a separate checkpoint from those historical runs.
- [x] Build and inspect generated documentation for private routes, search,
  sitemaps and assets, including this roadmap.
- [x] Inventory retained fixture/container state before changes; preserve
  unrelated workloads and distinguish stale task IDs/paths from current commands.
- [x] Establish current private repository visibility and Actions availability.
  Actions remain disabled at the September 5 consolidation check. Inherited
  public-publication workflows have repository/visibility guards; local tests
  do not establish fresh GitHub CI.

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
The deployment checkpoint confirmed private repository visibility and disabled
Actions; these are local and public-flow checks, not CI. See the
[complete validation record](../../deploy/hosted-demo/BOUNDED-WORK-VALIDATION.md).

Keep the broader September 5 checkpoints separate: the earlier
[milestone-readiness record](2026-09-05-milestone-validation.md) reports **1,726
Rust tests** and its scoped Python/JavaScript checks. The later `f8a2858` merge
[handoff](2026-09-05-idp-oauth-handoff.md) reports **1,769 Rust tests passed,
four ignored live-provider checks, 123 JavaScript tests, 56 hosted Python tests
and 43 Python contract tests (41 passed, two Linux-only skips on macOS)**, plus
locked workspace/all-target Clippy, formatting and documentation checks. These
are historical results for their recorded revisions; do not add their counts
together or present them as fresh consolidation validation.

The [fresh consolidation checkpoint](2026-09-05-worktree-consolidation.md)
integrates both private lines of work in the sole registered checkout and records
the merged revision's validation separately. Preserved runtime state and the
read-only staging prerequisite snapshot are documented there.

The final visitor-guide clarification about receipt expiry and non-retractable
results is published at Pages deployment `ca3fe4da.opaque-3pv.pages.dev` and the
production domain. The retry passed 18 HTTP checks, including private-route
exclusion, after a strict 74-file rebuild and generated-output privacy scan.

### M1: native human review

- [x] Exercise separate broker/workload custody, protected workstation state
  and operator-pinned enrollment with the actual host reviewer/helper.
- [x] Verify the native review window is usable, prepare a fresh fixture and
  recheck its host reviewer/helper binaries before the next human attempt.
- [x] Prepare a current task; show the full repository, workflow, artifact,
  destination, allowance, expiry and unknown-outcome meaning.
- [x] The human completes review and the native ceremony. Record observed
  timing and interventions; subjective comprehension was not surveyed.
- [x] Verify `paired_workstation` receipt provenance, observe the fixture result,
  repeat execution and reconcile without a second dispatch.
- [x] Retain a sanitized evidence summary. Key enrollment, a displayed window or
  automatic signature does not close this gate.

Runbook: [release dogfood](../release-dogfood.md). Disposable providers test the
human and broker boundary here; M2 tests the real external provider.

The first authorized native attempt completed custody and enrollment, then
returned `task review timed out` at the 90-second deadline with **zero
dispatches**. No completed human decision or successful native receipt is
recorded. The runner's fail-fast/error-evidence fix is retained; a displayed
window or automatic fixture signature would not close this gate. See the
[sanitized attempt record](2026-09-05-milestone-validation.md).

The subsequent [native walkthrough](2026-09-05-native-review-proof.md) completed
in 10.14 seconds with an actual human decision and native authentication. Exactly
one fixture dispatch was observed; replay before/after restart, persisted receipt,
MCP and dashboard reconciliation passed. The earlier timeout remains historical
evidence with an unconfirmed cause. No real GitHub effect is implied by this M1
completion.

### M2: private artifact smoke check

- [x] Verify private `kcirtapfromspace/opaque-dogfood` and bind observed repository
  ID `1357845081` in the prepared contract. Recheck destination identity before
  dispatch; historical public examples are not current dogfood destinations.
- [x] Prepare the private manual workflow and GET-only preflight, including
  private artifact access and exact workflow-byte checks. Retain inherited
  public-publication guards before any Actions enablement.
- [x] Build and inspect one committed-source amd64 artifact locally, then run
  its fixed smoke command without network/credentials. This does not establish
  private registry publication or workflow pull access. [Artifact evidence](2026-09-05-native-review-proof.md).
- [ ] Install/verify the manual workflow, `staging` environment and effective
  branch/workflow protections. Record Actions availability and missing prerequisites.
- [ ] Select an immutable reviewed artifact and a private distribution path
  accessible to the smoke workflow. Verify its fixed binary command and commit
  identity; no internal image or fixture becomes public.
- [ ] Resolve narrow broker credential references and any runner-side artifact
  access. Keep credential values outside manifests, receipts and Git.
- [ ] Review the final private-target contract and bind exact workflow bytes,
  branch/observed commit, artifact digest and environment in trusted broker state.
- [ ] Complete native approval, dispatch once, reconcile the exact run, verify
  its fixed artifact smoke check and demonstrate denied replay.

The [staging template](../../examples/staging-release/README.md) now targets the
private repository and same-name private GHCR package, with a fixed
`/usr/local/bin/opaque --version` smoke command. The artifact digest remains an
unresolved sentinel. The September 5 08:03 UTC
[read-only preflight](2026-09-05-milestone-validation.md) observed unprotected
`main` and absent/inaccessible workflow, environment, protection and package
metadata. The [fresh September 5 consolidation preflight](2026-09-05-worktree-consolidation.md) again passed private
repository identity and observed unprotected `main`, disabled Actions and an
unresolved artifact digest; workflow, environment and package evidence remains
unavailable or blocked. It reports **5 passed, 9 blocked and 2 operator-required
checks**. No live dispatch or effective artifact access is claimed. Workflow
success would prove the fixed smoke check; service rollout, rollback and
application-health claims require separate contracts and evidence.

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

| Gate | Remaining build and validation | Required evidence |
| --- | --- | --- |
| **M4a — Attestor seam** | Canonical identity and listener-selected peercred attestation are built; finish policy selectors/strength floors, lease fingerprints, compatibility and the multi-listener registry | Policy golden corpus; no caller-selected attestor/strength; explicit unavailable-identity failure; real-daemon checks |
| **M4b — Counted leases** | Atomic per-lease allowance and claimed instance attribution without a new principal | Concurrent consumption, expiry and compatibility; labels never authorize; task-grant budgets remain distinct |
| **M4c — Native macOS identity** | Populate code-signing identity through the platform construction path | Signed helper connects to real daemon; assertion at production boundary; explicit prerequisite/skip if signing identity unavailable |
| **M4d — EMA provisioning** | Broker-owned gateway authority is integrated; provision the actual IdP/client and compatible resource access-token contract, then complete the client flow | Configured issuer/audience checks; enterprise provisioning, attributed principal and verified audit trail; no duplicate disconnected authorization layer |
| **M4e — Bounded SSH operation** | The Vault-signed fixed-health operation is built and fixture validated; select and provision a real host, establish production key custody and complete native review | Exact principals/destinations, short expiry, host-enforced command/session controls, foreign host/principal/command denial, replay/revocation/expiry and effect receipts on that host |

The historical [attestor PRD](../../tasks/prd-attestor-seam.md) and
[bounded-task PRD](../../tasks/prd-bounded-agent-work.md) retain their original
acceptance criteria with current reconciliation notes. Use these gate definitions
and linked implementation evidence to choose each slice. SSH certificate expiry
bounds new authentication; the implemented fixed-health host guard separately
enforces session duration, expiry and revocation. Validate those controls on the
selected real host before claiming its bounded operation is demonstrated.

## Since September 5

Infrastructure/quality work in parallel; no M0–M4 gate changed.

- **Code quality remediation.** Seven P1 gaps found (partial-failure
  recovery, durable audit correctness, transport lifecycle bounds, test
  enforcement), fixed and merged with the seven-crate `opaqued` split.
  [Review](2026-09-09-code-quality-gap-plan.md),
  [remediation](2026-09-09-code-quality-implementation.md),
  [merge validation](2026-09-09-quality-extraction-merge-validation.md),
  [deployment](2026-09-09-quality-runtime-deployment.md).
- **Cloudflare usage safeguards.** September 5–6 demo pause was Durable
  Object storage-quota exhaustion from continuous front-end polling; fixed
  by reducing polling/write frequency.
  [Investigation](2026-09-09-cloudflare-worker-usage.md),
  [rollout](2026-09-09-cloudflare-usage-safeguards.md).
- **Demo pilot contact capture.** Optional contact-request flow added to
  the public demo to start recruiting pilot teams; not evidence of demand.
  [Plan](2026-09-09-demo-pilot-recruitment.md),
  [deployment](2026-09-09-pilot-contact-deployment.md).
- **Visitor documentation redeployed** at the post-merge commit; private
  routes/search/sitemap exclusions reverified.
  [Deployment](2026-09-09-visitor-docs-deployment.md).

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
