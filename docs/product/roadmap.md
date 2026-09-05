# Opaque milestone roadmap

**Current execution plan · September 5, 2026 · private dogfood workspace**

This is the current checklist for architecture, validation and demonstrations.
Dated product notes and PRDs retain their original evidence and proposals;
their old “next steps” and unchecked criteria do not establish today's priority
or implementation status. Update this file when a gate changes and link the
evidence supporting that change.

The immediate outcome is a human-approved, single-use staging artifact smoke
check through a separately controlled broker, followed by a truthful receipt and
denied replay. Real application data and enterprise identity follow; the
attestor and bounded SSH work then extend the proven authorization boundary.

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
| Paired workstation review and one staging workflow dispatch | Yes | Enrollment, pinned TLS, signed test review, separate custody and read-only reconciliation | Host setup passed historically; completed native human review and real GitHub dispatch remain M1–M2. [Release evidence](2026-09-04-remote-release-readiness.md). |
| Tenant inference and HTTP OAuth/MCP aggregate gateway | Yes | Two-tenant fixtures; token, scope, disclosure and revocation denials | Synthetic-source chat observed with a real model; production IdP/source and broker integration remain M3. [Inference](2026-09-04-tenant-inference-readiness.md), [gateway](2026-09-04-scoped-metrics-chat.md). |
| Hosted GPU demo, organization/support roles and demo lifecycle controller | Yes; deployed | Final packaged Gemma/Qwen qualification: 13/13 checks each; separate narrow denial-counter repeats | Public allowed queries, role/customer denials and cleanup observed September 4. Synthetic data and demo-specific controller; no general tenant operator or GPU isolation proof. [Portfolio ledger](../../deploy/hosted-demo/PORTFOLIO-VALIDATION.md), [organization ledger](../../deploy/hosted-demo/ORGANIZATION-VALIDATION.md). |
| Runtime attestor registry, selectors, native codesign identity, generic counted leases and full EMA | No complete implementation | Existing identity/task/gateway tests do not establish these proposed contracts | M4 proposal reconciled against current source. [Attestor PRD](../../tasks/prd-attestor-seam.md). |
| Bounded SSH certificates and host operation | No | None recorded | M4 acceptance target; signing a key alone does not constrain commands or terminate sessions. |

The portfolio ledger records missing source counters for the full packaged runs
and a separate successful narrow repeat. Do not widen that repeat into evidence
for unrecovered counters. Public model qualification does not need rebuilding
merely because an earlier note called GPU inference future work.

## Current milestone queue

| Milestone | Status | Next concrete work | Completion evidence |
| --- | --- | --- | --- |
| **M0 — Reconcile and refresh** | Local gates passed | Preserve the fresh [validation record](2026-09-05-milestone-validation.md); Actions remains disabled | 1,726 Rust tests, Clippy/fmt, 54 hosted Python, 86 JS, 20 milestone tests, signed fixture and generated-site checks passed |
| **M1 — Human signed review across the broker boundary** | Native walkthrough implemented; first human attempt timed out | Resolve the operator's window observation and rerun `--native-check`; first attempt dispatched nothing | Real human decision, `paired_workstation` receipt, one fixture dispatch, denied replay and read-only reconciliation |
| **M2 — One real private staging artifact smoke check** | Private template/preflight ready; live prerequisites unmet | Actions disabled; main unprotected; workflow/environment/package absent or inaccessible; artifact digest unresolved | Native-approved GitHub dispatch; exact run correlation; fixed smoke command succeeds; replay causes no second dispatch |
| **M3 — Real source, production identity and unified authorization** | Queued; integration selection open | Name one application aggregate source and production IdP; align admission/revocation with broker | Two actual test tenants; permitted read/disclosure; source-level foreign-tenant denial; membership removal, expiry and rotation checks |
| **M4 — Attestor, counted leases, EMA and bounded SSH** | Queued | Implement the attestor proposal in reviewable slices, then a specific host operation | Compatibility, concurrency, real identity/provisioning and host-operation evidence; certificate issuance alone is insufficient |

Preparation and read-only preflight can run concurrently. Complete M1 before
using its native path for M2. M2 closes the first external-effect milestone;
synthetic gateway or demo-controller evidence cannot complete M3/M4. Codex owns
implementation and reproducible checks. The operator supplies the actual human
decision and any missing protected destination, IdP or source configuration.

### M0: documentation and validation

- [x] Create one roadmap and reconcile both historical PRDs and four readiness
  notes without rewriting old evidence.
- [x] Record fresh workspace/Rust, dashboard/JavaScript and hosted Python checks
  for the current revision; run other fixtures where relevant.
- [x] Build and inspect generated documentation for private routes, search,
  sitemaps and assets, including this roadmap.
- [x] Inventory retained fixture/container state before changes; preserve
  unrelated workloads and distinguish stale task IDs/paths from current commands.
- [x] Establish current private repository visibility and Actions availability.
  The current GET-only check confirms private visibility and disabled Actions;
  local tests are not fresh CI. Inherited public publication workflows now have
  repository/visibility guards; these local changes must land before enablement.

### M1: native human review

- [x] Start a fresh native fixture with separate broker/workload identities,
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

- [x] Verify `kcirtapfromspace/opaque-dogfood` is private and use its observed
  numeric IDs. Old public repository examples are historical templates, not
  current dogfood destinations.
- [ ] Prepare the manual workflow, `staging` environment and branch/workflow
  protections. Record Actions availability and concrete missing prerequisites.
  The private workflow and GET-only preflight are implemented; external
  installation and effective protections remain open. See the
  [current validation record](2026-09-05-milestone-validation.md).
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
- [ ] Unify gateway/broker admission and revocation, including changes during
  active work. Keep data reads and model disclosure separately bounded.
- [ ] Demonstrate permitted reads/disclosure and source/gateway denials,
  membership removal, expiry, credential rotation and stale evidence. Record
  actual source effects and model disclosure separately.

The aggregate adapter, OAuth boundary and hosted lifecycle exist. Connect and
validate a real deployment; present OAuth support does not establish full EMA.

### M4: remaining architecture and SSH

| Gate | Build and validate | Required evidence |
| --- | --- | --- |
| **M4a — Attestor seam** | Canonical selectors/strength, listener-selected attestor, legacy policy/lease compatibility, peercred adapter | Policy golden corpus; no caller-selected attestor/strength; explicit unavailable-identity failure; real-daemon checks |
| **M4b — Counted leases** | Atomic per-lease allowance and claimed instance attribution without a new principal | Concurrent consumption, expiry and compatibility; labels never authorize; task-grant budgets remain distinct |
| **M4c — Native macOS identity** | Populate code-signing identity through the platform construction path | Signed helper connects to real daemon; assertion at production boundary; explicit prerequisite/skip if signing identity unavailable |
| **M4d — EMA provisioning** | Reconcile existing HTTP gateway with intended MCP resource-server deployment; complete provisioned-client flow | Configured issuer/audience checks; enterprise provisioning, attributed principal and verified audit trail; no duplicate disconnected authorization layer |
| **M4e — Bounded SSH operation** | Select one necessary host task, define CA/certificate/key custody, implement restricted access | Exact principals/destinations, short expiry, host-enforced command/session controls, foreign host/principal/command denial, replay/revocation/expiry and effect receipts |

The [attestor PRD](../../tasks/prd-attestor-seam.md) supplies story details;
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
