# PRD: Attestor Seam, Fan-Out Authority, and EMA Interop

**Status:** Historical proposal · September 4, 2026; reconciled September 5.
**Current execution plan:** [private milestone roadmap](../docs/product/roadmap.md).
The original story checkboxes below are design acceptance criteria, not today's
delivery checklist or a current schedule. This track is queued as M4 after the
native-review, private staging-smoke and real-source integration milestones.
macOS enterprise positioning remains a separate decision.

## Current reconciliation

| Original phase | Current state | Remaining work |
| --- | --- | --- |
| A — Attestor seam | Proposed. `ClientMatch` still uses fixed Unix/code-signing fields; no complete selector/attestor registry is present. | M4a: canonical identity, listener-bound attestation and migration compatibility. |
| B — Fan-out authority | Durable task grants now share fixed allowances across callers; the generic in-memory approval lease still has TTL/one-time fields and no counted budget. | M4b: generic counted leases and safe claimed attribution. Task-grant validation does not complete US-006/007. |
| C — Reference attestors | Production `build_client_identity` still assigns `codesign_team_id: None`. Existing peer credentials are not behind the proposed attestor trait. | M4a/M4c: peercred adapter and native signed-helper construction-path evidence. |
| D — EMA | Separate `opaque-metrics` HTTP MCP gateway now implements configured issuer/audience validation, protected-resource metadata and scoped OAuth access. It does not complete enterprise provisioning or unify broker authority. | M3/M4d: reconcile transport ownership with the implemented gateway, then demonstrate the complete provisioned-client flow. Do not build a second disconnected gateway merely to tick an original story. |

Evidence: [bounded work](../docs/product/2026-09-04-dogfood-readiness.md),
[scoped gateway](../docs/product/2026-09-04-scoped-metrics-chat.md), and current
[`ClientMatch`](../crates/opaque-core/src/policy.rs),
[`LeaseEntry`](../crates/opaqued/src/enclave.rs),
[`build_client_identity`](../crates/opaqued/src/main.rs). Line numbers, market
context and future-tense claims in the original proposal below describe its
draft snapshot; revalidate them when implementing a story.

---

## 1. Introduction / Overview

Opaque identifies a calling workload by Unix process attributes read off a local socket: `uid`, `gid`, `pid`, `exe_path`, `exe_sha256`, `codesign_team_id`. That model described the world accurately when one agent was one process on one host.

It no longer describes the field. As of late 2026:

- **Agents fan out.** Claude Code's Dynamic Workflows orchestrate tens to hundreds of parallel subagents in a single session; Agent Teams run parallel teammates with independent context windows. Every one of them presents Opaque with the *same* client identity.
- **Agents run everywhere.** The sandbox layer (E2B, Modal, Daytona, Fly Machines, ArcBox) is contested and consolidating. Betting the identity model on any one runtime is a commercial error as much as an architectural one.
- **Agents are provisioned by the enterprise.** The June 2026 Enterprise-Managed Authorization (EMA) extension to MCP makes the enterprise IdP the authoritative provisioner of MCP server access, and treats MCP servers as OAuth 2.1 resource servers.

Four consequences, all live in the current codebase:

1. **Fan-out lease pooling.** `LeaseKey` deliberately excludes `pid` and hashes only stable process fields (`enclave.rs:254`). Under a 100-way fan-out, an approval lease granted to one subagent is immediately reusable by the other 99, for free, with no draw-down.
2. **No extension point.** `ClientMatch` (`policy.rs:25`) is a fixed four-field struct. A container image digest, a k8s ServiceAccount, or a VM attestation has nowhere to go, so every new runtime target is a daemon fork rather than a plugin.
3. **A dead policy field.** `codesign_team_id` is documented as a match field. Both construction sites in `build_client_identity` (`main.rs:2298`, `:2307`) hardcode `None`, and `peer.rs` never populates it. It cannot match on any request. The unit test at `main.rs:5707` passes only because it builds the identity by hand.
4. **Unreachable by enterprise provisioning.** `opaque-mcp` is not an OAuth 2.1 resource server, so an EMA-provisioned deployment routes around it.

This increment introduces the attestor seam, ports and implements two reference attestors, fixes fan-out lease pooling, and makes `opaque-mcp` speakable in an EMA flow.

---

## 2. Goals

- **G-1.** Caller identity becomes a *selector set* plus an *attestation strength*, uniform across every substrate.
- **G-2.** Adding a runtime target costs one attestor implementation and one policy binding — zero changes to `policy.rs`, `enclave.rs`, or `main.rs`.
- **G-3.** No approval lease is ever silently shared across parallel subagents; concurrent reuse draws down a bounded budget.
- **G-4.** Every existing policy file matches byte-identically after upgrade. No deployment changes meaning silently.
- **G-5.** `codesign_team_id` becomes a real, populated, matchable field, verified through the production construction path.
- **G-6.** `opaque-mcp` is reachable in an EMA-provisioned enterprise flow.

---

## 3. User Stories

### Phase A — The seam

#### US-001: Selector and WorkloadIdentity types
**Description:** As a maintainer, I need a substrate-neutral representation of "who is calling" so that identity stops being a fixed Unix struct.

**Acceptance Criteria:**
- [ ] `Selector` type is a namespaced key/value pair rendering as `<source>:<key>:<value>` (e.g. `peercred:uid:501`)
- [ ] `WorkloadIdentity { selectors: BTreeSet<Selector>, strength: AttestationStrength, source: AttestorId }`
- [ ] Selector set is canonically ordered so two identical sets always hash identically
- [ ] `ClientIdentity` is retained unchanged; no behavior change in this story
- [ ] Unit tests cover canonical ordering and round-trip serde
- [ ] `cargo test -p opaque-core` passes; no new clippy or fmt findings in touched files

#### US-002: AttestationStrength and the policy floor
**Description:** As an operator, I need to require a minimum attestation strength on a rule so a weakly-attested caller cannot inherit a principal meant for a strongly-attested one.

**Acceptance Criteria:**
- [ ] `AttestationStrength` enum: `None < Weak < Medium < Strong`, with `Ord` derived in that order
- [ ] `ClientMatch` gains `min_attestation: Option<AttestationStrength>`
- [ ] A rule with `min_attestation` set does not match when the achieved strength is lower
- [ ] Absent `min_attestation` on a rule is recorded in the audit event, so permissive rules are visible
- [ ] Serde round-trips; unknown strength strings are a config parse error, not a silent default
- [ ] Test: `Strong` request matches a `min_attestation = "medium"` rule; `Weak` does not
- [ ] `cargo test` passes; no new clippy or fmt findings in touched files

#### US-003: WorkloadAttestor trait and transport-keyed registry
**Description:** As a maintainer, I need attestors to be pluggable and selected by the transport the daemon accepted the connection on, never by anything the caller claims.

**Acceptance Criteria:**
- [ ] `trait WorkloadAttestor { fn id(&self) -> AttestorId; fn attest(&self, conn: &ConnectionContext) -> Result<WorkloadIdentity, AttestError>; }`
- [ ] Registry maps *listener* → attestor at daemon start; the mapping is not reachable from request content
- [ ] A request carrying a self-declared substrate, attestor id, or strength field is rejected with an audited error
- [ ] `attest` returning `Err` produces `strength: None` with an empty selector set — never a partial identity
- [ ] Test: a request whose payload claims `attestor: k8s` on a peercred listener is refused
- [ ] `cargo test` passes; no new clippy or fmt findings in touched files

#### US-004: ClientMatch desugars to peercred selectors
**Description:** As an operator upgrading Opaque, I need my existing policy file to match exactly as it did before, so upgrading never changes what is allowed.

**Acceptance Criteria:**
- [ ] `uid`, `exe_path`, `exe_sha256`, `codesign_team_id` are retained and desugar to `peercred:*` / `codesign:*` selectors
- [ ] `ClientMatch` gains `selectors: Option<Vec<String>>` as an additive field
- [ ] Glob semantics on `exe_path` are preserved exactly, including the existing pattern behavior
- [ ] Golden test: every policy fixture in the repo produces an identical match/no-match verdict against a fixed identity corpus, pre- and post-change
- [ ] A policy setting both legacy fields and `selectors` is an AND, and this is documented
- [ ] `cargo test` passes; no new clippy or fmt findings in touched files

#### US-005: LeaseKey derives from selectors; zero-selector is a refusal
**Description:** As a security reviewer, I need an unattested caller to be refused by name rather than silently matching on whichever fields happened to be present.

**Acceptance Criteria:**
- [ ] `LeaseKey::client_fingerprint` is computed from the canonical selector set plus strength, not the five Unix fields
- [ ] A `WorkloadIdentity` with zero selectors and `strength: None` never produces a usable lease
- [ ] Requests with `strength: None` are refused with a distinct `attestation_unavailable` error, audited
- [ ] The existing `delegation: Option<(sub, jti)>` binding is retained unchanged
- [ ] Test: two callers with identical zero-selector identities do not share a lease — they are both refused
- [ ] `cargo test -p opaqued` passes; no new clippy or fmt findings in touched files

### Phase B — Fan-out authority

#### US-006: Counted leases
**Description:** As an operator, I need an approval to authorize a bounded amount of work so that a hundred-way fan-out cannot spend one approval a hundred times for free.

**Acceptance Criteria:**
- [ ] `LeaseEntry` gains `budget: Option<u32>` and `spent: u32`
- [ ] A lease expires at whichever of `ttl` or `budget` is reached first
- [ ] `budget` is configurable per rule alongside the existing `lease_ttl`
- [ ] Draw-down is atomic under concurrent access — N concurrent reuses consume exactly N units
- [ ] `budget: None` preserves today's unlimited-within-TTL behavior, so existing configs are unchanged
- [ ] Test: a lease with `budget = 5` refuses the 6th identical operation at `t+0`
- [ ] Test: 100 concurrent tasks against a `budget = 100` lease consume exactly 100 and the 101st is refused
- [ ] `cargo test -p opaqued` passes; no new clippy or fmt findings in touched files

#### US-007: Claimed agent-instance id, recorded but never trusted
**Description:** As an auditor, I need to know which subagent in a fan-out performed an operation, while it stays clear that this attribution is claimed rather than proven.

**Acceptance Criteria:**
- [ ] Requests may carry an optional `agent_instance` string supplied by the harness
- [ ] The value is recorded in the audit record and explicitly flagged as unattested
- [ ] `agent_instance` participates in `LeaseKey` as defense in depth, partitioning leases between subagents
- [ ] `agent_instance` is **never** usable in a policy match, and a config attempting it is a parse error
- [ ] Documentation states plainly that co-resident subagents are one principal by construction and cannot be securely separated
- [ ] Test: a policy file referencing `agent_instance` in a match fails to parse with a clear message
- [ ] `cargo test` passes; no new clippy or fmt findings in touched files

### Phase C — Reference attestors

#### US-008: Peercred attestor behind the trait
**Description:** As a maintainer, I need the existing behavior reimplemented as the first attestor so the seam is proven faithful before anything new is built on it.

**Acceptance Criteria:**
- [ ] `PeercredAttestor` emits `peercred:uid`, `peercred:gid`, `peercred:exe_path`, `peercred:exe_sha256`
- [ ] Reports `strength: Weak` when the caller shares the daemon's uid, `Medium` when the uid differs
- [ ] The uid comparison is against the daemon's *effective* uid, resolved at startup
- [ ] Golden test from US-004 still passes with the attestor in the path
- [ ] The existing `identity_e2e.rs` suite passes unmodified against a real daemon
- [ ] `cargo test` passes; no new clippy or fmt findings in touched files

#### US-009: macOS codesign attestor
**Description:** As an operator on macOS, I need `codesign_team_id` to actually be populated so the policy field the documentation advertises can match.

**Acceptance Criteria:**
- [ ] Attestor resolves the peer pid to a code object and extracts the signing Team ID via the platform code-signing APIs
- [ ] Emits `codesign:team`, and `codesign:notarized` when that status is determinable
- [ ] Reports `strength: Medium`; an unsigned or ad-hoc-signed caller yields no codesign selector and does not silently pass
- [ ] `build_client_identity` populates `codesign_team_id` from the attestor result on macOS
- [ ] Linux builds are unaffected and continue to compile and pass
- [ ] Documentation and README claims about `codesign_team_id` become true, or are corrected where they overstate
- [ ] `cargo test` passes on both platforms; no new clippy or fmt findings in touched files

#### US-010: Non-vacuous attestation test
**Description:** As a reviewer, I need the codesign test to exercise the real construction path so this class of bug cannot recur.

**Acceptance Criteria:**
- [ ] Test builds a signed helper binary, runs it, and connects to a real daemon socket
- [ ] Assertion is made on the identity produced by `build_client_identity`, not one constructed in the test
- [ ] Test fails if `codesign_team_id` is `None` when the caller is signed
- [ ] Test is skipped with an explicit logged reason when no signing identity is available, never silently passed
- [ ] The test is registered on a path CI actually runs (guard against the Phase-1 vacuous-pass failure mode)
- [ ] `cargo test` passes

### Phase D — EMA interop

#### US-011: opaque-mcp as an OAuth 2.1 resource server
**Description:** As an enterprise administrator, I need Opaque's MCP server to participate in standard authorization so my IdP can provision access to it.

**Acceptance Criteria:**
- [ ] Serves protected-resource metadata at the well-known endpoint
- [ ] Unauthorized requests return `401` with a `WWW-Authenticate` header naming the authorization server
- [ ] Bearer tokens are validated for signature, `exp`, and audience binding to this resource
- [ ] A token whose audience is a different resource is rejected
- [ ] Rejections are audited with the reason
- [ ] `cargo test -p opaque-mcp` passes; no new clippy or fmt findings in touched files

#### US-012: Issuer validation
**Description:** As a security reviewer, I need issuer validation so the authorization-server mix-up class of attack is closed.

**Acceptance Criteria:**
- [ ] The issuer is validated against the expected authorization server for the resource
- [ ] A token from an unexpected but otherwise well-formed issuer is rejected
- [ ] Issuer configuration is explicit; there is no discovery path that accepts an issuer the operator did not configure
- [ ] Test covers the mix-up case with two distinct test issuers
- [ ] `cargo test` passes; no new clippy or fmt findings in touched files

#### US-013: EMA provisioning acceptance test
**Description:** As a maintainer, I need one end-to-end test proving an EMA-provisioned client can reach Opaque, so the interop claim is verified rather than asserted.

**Acceptance Criteria:**
- [ ] Test spawns a real `opaque-mcp` and a mock IdP (reuse the wiremock pattern from `identity_e2e.rs`)
- [ ] An EMA-provisioned client completes authorization and invokes one tool successfully
- [ ] The resulting principal appears in the audit chain with its identity attributed
- [ ] Chain verification passes after the flow
- [ ] Test is serialized against other daemon-spawning tests, matching the existing module-mutex pattern

---

## 4. Functional Requirements

**Identity and attestation**

- **FR-1.** The system must represent caller identity as a canonically ordered set of namespaced selectors plus an attestation strength.
- **FR-2.** The system must select an attestor based on the listener that accepted the connection, and must never accept a substrate, attestor id, or strength asserted by the caller.
- **FR-3.** The system must treat a failed or absent attestation as `strength: None` with zero selectors, and must refuse such requests with a distinct audited error rather than falling back to a partial identity.
- **FR-4.** The system must allow a policy rule to declare a minimum attestation strength and must fail closed when the achieved strength is lower.
- **FR-5.** The system must record, for every request, which attestor produced the identity and what strength it achieved.

**Backward compatibility**

- **FR-6.** The system must retain `uid`, `exe_path`, `exe_sha256` and `codesign_team_id` as policy fields, desugaring them to equivalent selectors.
- **FR-7.** Every existing policy file must produce identical match verdicts before and after this change, verified by golden test.
- **FR-8.** When a rule specifies both legacy fields and explicit selectors, all must match.

**Leases and fan-out**

- **FR-9.** The system must derive the lease fingerprint from the selector set and strength, not from Unix process fields.
- **FR-10.** The system must support an operation budget on a lease, expiring the lease at whichever of TTL or budget is reached first.
- **FR-11.** Budget draw-down must be atomic under concurrency; N concurrent reuses must consume exactly N units.
- **FR-12.** A lease with no configured budget must behave exactly as today, bounded only by TTL.
- **FR-13.** The system must accept an optional harness-supplied agent instance identifier, record it in the audit trail marked as unattested, and partition leases on it.
- **FR-14.** The system must reject any policy configuration that attempts to match on the agent instance identifier.

**macOS**

- **FR-15.** On macOS, the system must populate the code-signature Team ID from the operating system for the calling process, and must emit no codesign selector when the caller is unsigned or ad-hoc signed.
- **FR-16.** The codesign attestation test must exercise the production identity-construction path and must fail loudly rather than skip silently when its preconditions are unmet.

**MCP / EMA**

- **FR-17.** `opaque-mcp` must serve protected-resource metadata and return `401` with `WWW-Authenticate` for unauthorized requests.
- **FR-18.** `opaque-mcp` must validate bearer token signature, expiry, and audience binding to itself, rejecting tokens issued for another resource.
- **FR-19.** `opaque-mcp` must validate the token issuer against explicit operator configuration, with no path that trusts an unconfigured issuer.
- **FR-20.** All authorization rejections must be written to the audit chain with a reason.

---

## 5. Non-Goals (Out of Scope)

- **Device management, AI-tool discovery, or endpoint telemetry.** That is the MDM layer's job. Positioning relative to it is deferred by decision; this increment builds the macOS attestor purely as the bug fix it already is, which preserves the option either way at no extra cost.
- **Replacing `SandboxExecutor`.** Ring 2 confinement of provider helpers is a separate concern at a different layer and is untouched here.
- **ArcBox, Docker, or Kubernetes attestors.** They become additive once the seam exists. The microVM attestor additionally remains gated on an unrun vsock spike.
- **Consent freshness, cumulative budgets across an envelope, and re-presence step-up.** These belong to the denomination track and run in parallel; only per-lease budgets are in scope here, because fan-out forces them.
- **Attesting individual subagents as separate principals.** Co-resident subagents are one principal by construction. The claimed instance id is attribution and defense in depth, never a security boundary — and the documentation must say so.
- **New cryptography.** Every mechanism here composes primitives already in the tree.
- **Capability declarations in agent plan files.** Deferred until the harness story settles; the loop-shaped design that motivated it no longer reflects how agents run.

---

## 6. Technical Considerations

**Migration safety is the main risk.** Policy matching is the most security-critical surface in the codebase, and a silent change in match semantics would alter what every deployment permits. The mitigation is the golden corpus in US-004, and the precedent is the audit chain's presence-versioned canon — append only when non-empty, so existing artifacts verify byte-identically with no backfill. Apply the same discipline.

**Lint baseline.** `cargo fmt --check` and `cargo clippy -- -D warnings` already fail on `main` (unpinned toolchain; roughly 49 fmt and 49 clippy findings in files this work does not touch). Acceptance criteria are therefore written as *no new findings in touched files*. Pinning the toolchain and clearing the baseline remains a separate maintenance commit and is not a dependency of this work.

**Integration points.**
- `opaque-core/src/peer.rs` — becomes the peercred attestor's internals rather than the universal identity source.
- `opaque-core/src/policy.rs:25` — `ClientMatch` gains selectors and `min_attestation`. `IdentityMatch` is already substrate-neutral and is not touched.
- `opaqued/src/enclave.rs:254,329` — `LeaseKey` fingerprint source and `LeaseEntry` budget.
- `opaqued/src/main.rs:2287` — `build_client_identity` becomes attestor dispatch.
- `opaque-mcp` — gains the resource-server surface.
- Phase 2's `opqa1` verify-before-trust attestation seam is where strong remote attestors will eventually plug in; this increment should not foreclose that shape.

**Testing patterns to reuse.** `identity_e2e.rs` already spawns a real `opaqued` plus a wiremock IdP over the real socket, serialized by a module mutex. Both the EMA acceptance test and the macOS attestation test should follow that pattern. Note the Phase-1 lesson: a named test needs the `tests::` path or CI passes vacuously.

**macOS specifics.** Team ID extraction needs the platform code-signing APIs against the peer pid obtained from `LOCAL_PEERPID`. There is a genuine TOCTOU consideration — the pid may be recycled between the peer-credential read and the code-object query — and the attestor should document how it handles that, even if the mitigation is simply reporting reduced strength.

---

## 7. Success Metrics

- **SM-1.** Adding a new substrate requires exactly one new attestor file plus a policy binding, with zero diffs to `policy.rs`, `enclave.rs`, or `main.rs`. Verified by implementing the peercred attestor second, after the trait exists.
- **SM-2.** 100% of existing policy fixtures produce identical verdicts pre- and post-change.
- **SM-3.** A 100-way concurrent fan-out against a budgeted lease consumes exactly 100 budget units, and the 101st operation is refused.
- **SM-4.** `codesign_team_id` matches a real signed binary through the production construction path on macOS.
- **SM-5.** Zero requests reach policy evaluation with an unattested identity that is not explicitly refused.
- **SM-6.** An EMA-provisioned client completes an end-to-end tool invocation against `opaque-mcp` with the principal attributed in a verifying audit chain.

---

## 8. Open Questions

1. **Does any current harness expose a stable subagent instance identifier?** US-007 assumes the harness can supply one. If none exists, the story degrades to recording nothing and the fan-out defense rests entirely on counted leases (US-006). Verify before starting Phase B.
2. **What is the right default for `min_attestation` on a fresh install?** Failing closed is correct for new deployments but would break upgrades if applied retroactively. Proposal: absent on upgrade, `Medium` in the setup wizard for new installs — needs a decision.
3. **Does EMA require dynamic client registration support**, or is static configuration sufficient for the deployments Opaque targets? Affects US-011 scope.
4. **How should strength be reported for the shared-uid peercred case** once the daemon runs under a service account in some deployments and not others? US-008 proposes deriving it from the actual uid comparison rather than a static value; confirm that is acceptable to policy authors.
5. **The ArcBox vsock spike is still unrun.** It does not block this increment, but it does gate whether the microVM attestor is the next one built or is deprioritized behind Kubernetes.
6. **Endpoint-management posture** (integrate beneath an MDM AI-governance layer versus build standalone) is deferred by decision. Revisit once the seam exists and the macOS attestor is real — the decision is cheaper to make with working code than without.

---

## 9. Why this ordering

The three problems this increment solves are not speculative and do not depend on any prediction about where agent architectures go next:

- Fan-out lease pooling is a **live defect** under orchestration patterns that shipped this year.
- The dead `codesign_team_id` field is a **live documentation lie**.
- EMA is a **published specification** that determines whether enterprise deployments can reach Opaque at all.

The seam is worth building because it makes all three cheap to fix at once, and makes the fourth through ninth substrates additive rather than invasive. Nothing here requires believing a particular forecast about context windows, sandbox winners, or harness design — which is the property a foundation should have.
