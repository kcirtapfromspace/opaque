# Security remediation plan — 2026-09-09

Private implementation preparation. Exclude from public routes, search, sitemaps, previews and assets.

Baseline: `e49b49e17aab4f1e73d42c8d6cce7b15de0bd711`, private `kcirtapfromspace/opaque-dogfood`. Inputs: [security review](2026-09-09-security-review.md) and [threat model](opaque-threat-model.md). The user requested preparation to resolve the findings. This document defines the changes, sequencing, compatibility decisions and closure evidence; **all four findings remain open and no runtime fixes are implemented yet**.

## Scope and delivery order

Use the review's synthetic public demo plus planned production broker scope, with trusted host administrators, policy owners and broker/approver custody. These are working planning assumptions, not assertions about live systems. The four code fixes are ready to implement without additional deployment context. Production acceptance has separate evidence requirements below.

| Batch | Finding / threats | Deliverable | Status | Dependency |
| --- | --- | --- | --- | --- |
| R1 | SR-001 P1 / TM-001 | One server-derived action for generic policy, approval, audit and provider execution | Prepared; open | First release priority; operation inventory and compatibility tests |
| R2 | SR-002 P2 / TM-002 | Credential-free dashboard shell and explicit owner-token unlock | Prepared; open | Independent of R1 |
| R3 | SR-003 P3 / TM-003 | Final lease validation for every protected demo response | Prepared; open | Edge fix independent; inner proxy checks use same response contract |
| R4 | SR-004 P3 / TM-006 | Bounded MCP error with same-process protocol continuity | Prepared; open | Independent small patch |
| H1–H5 | Residual TM-005–TM-009 work | Availability, provenance, publication and platform follow-ups | Scoped; unverified or design work | Follow confirmed defects; do not count as newly proven exploits |
| D1–D3 | TM-004/TM-007/TM-009 | Actual production source, custody and cluster/model acceptance | Evidence required | Before expanding to confidential production use |

Keep R1, R2, R3 and R4 as separately reviewable changes. R2–R4 can be developed alongside R1 because their files are independent. If R1 lands incrementally, unconverted generic operations must fail closed; do not release an intermediate build that silently retains a bypassing path. Integrate the completed batches before broad validation. No new user-facing Codex tasks, remote tickets, publication or live changes are created by this preparation.

## R1 — Canonical generic broker actions

**Invariant:** The operation that policy evaluates, the human reviews, the lease/hash binds, the audit records and the handler executes is one immutable, server-derived action.

**Selected implementation:** Introduce a daemon-owned typed action representation, suggested location `crates/opaqued/src/action.rs`, with exhaustive operation preparation and provider-specific parsing beside the handlers. Preparation validates parameters, permitted scope combinations, defaults and destination fields without resolving credentials or calling a provider. It yields the canonical target, effective secret reference names, action hash payload and review fields. Handlers consume that prepared action, not a second parse of the original JSON.

At `crates/opaqued/src/enclave.rs::execute`, perform registry/handler lookup and action preparation before policy, approval, lease lookup, credential resolution or dispatch. Move canonical request-target auditing after preparation; earlier rejection events contain a fixed reason, request ID and verified client, never raw parameter content. Keep policy matching semantics and project the prepared action into its existing request interface. No production default handler may fall back to forwarding raw parameters.

Treat wire `target` as an optional consistency assertion during migration:

- Missing required operation parameters fail closed.
- Omitted redundant target fields are filled from the complete server-derived action before policy evaluation.
- Every supplied target key/value must agree with the canonical action; unknown, contradictory or malformed targets fail. Do not silently convert a malformed target into an empty map.
- Canonical defaults and effective credential-reference selectors are resolved once. Secret bytes never become target/review/audit fields.
- Validate the actual execution values. Trimming or sanitizing only a copied policy target would preserve the original defect.

**Coverage requirement:** Preparation found 28 generic registrations. The adjacent provider families below are implementation coverage, not additional independently reproduced findings.

| Family | Required action coverage / compatibility detail |
| --- | --- |
| GitHub set Actions, Codespaces, Dependabot and organization secrets | Repository/environment/user/org scope, secret name, visibility, selected repository audience and effective value/token references. Show audience breadth in approval. |
| GitHub list/delete | Include actual scope and environment in the canonical target; current registered keys omit them. Reject irrelevant competing repo/org/environment fields. |
| GitLab variables | Project, key, environment scope and effective protected/masked/raw/type options. |
| 1Password and Bitwarden | Explicit targetless listing versus vault/project selection and exact item/field/secret IDs. Preserve Reveal denial. |
| AWS | Exact role/secret/parameter/path/name and effective mode/options; explicitly targetless account/list operations; keep secret values confidential and existing safety floors. |
| Sandbox execution | Exact argv plus shared human command rendering and a nonsecret profile snapshot/digest. Derive declared references from that snapshot; do not reread a different profile after approval. Avoid blanket 256-character limits that truncate legitimate argv. |
| Sandbox execve hooks | Typed executable/argv/cwd/environment-key/sandbox inputs and approval responses. Pending approval authority comes from server state. Preserve this distinct hook contract. |
| `test.noop` | Explicit harmless contract or test-only registration; no unrestricted target passthrough. |

Eight bounded-task operation names are registered separately in `crates/opaqued/src/enclave/task.rs`: `github.publish_manifest`, `github.release_manifest`, `github.dispatch_staging_workflow`, `github.observe_staging_workflow`, `inference.fixed_manifest`, `inference.fixed_completion`, `ssh.health_manifest`, `ssh.service_health`. Keep them unavailable through generic execution; reject before generic approval. Their typed task route retains current owner/tenant/delegation/profile checks, durable reservation, one dispatch and charged unknown outcomes. The task PublishSecret path shares a policy operation with generic GitHub publication but serializes a different typed request: new generic schemas must not accidentally reject or reroute it.

**Files:** `crates/opaqued/src/{main,enclave}.rs`, proposed `action.rs`, provider modules under `github/`, `gitlab/`, `onepassword/`, `bitwarden/`, `aws/`, and sandbox handler modules. Change `crates/opaque-core/src/operation.rs` only if required for explicit contract metadata. Preserve task ledger formats and manifest digests.

**Acceptance evidence:**

1. A registry-coverage test requires each generic operation to have an explicit preparer and each task-only operation to reject generic dispatch. Parser cases cover missing/unknown fields, optional defaults, scope transitions, target contradictions and correct canonical projections.
2. Local mock-provider integration verifies raw/wrapper equivalence and denial before approval, credential resolution and provider requests. A positive control reaches precisely the canonical allowed destination. Use disposable synthetic configuration and local mocks only.
3. Enclave tests compare the policy request, approval fields/hash, first-use lease key, typed handler action and audit target. Changing a security-relevant destination/audience/argv field cannot reuse the prior authorization.
4. Existing task, identity, provider and reservation/unknown-outcome regressions still pass. Scope additions do not silently narrow old broad policy rules; inventory and document policies that need new explicit restrictions.

Extend `crates/opaqued/tests/provider_e2e.rs` and enclave/provider tests. `.github/workflows/ci.yml` currently asserts exactly **2 passed** for provider E2E; update that non-vacuous guard when adding tests. Prefer checking required test identities and a successful suite over a stale hardcoded count. Generic approval/cache changes must invalidate old generic leases during upgrade, while durable task/audit state remains intact.

**Closure:** A wrapper-only or GitHub-only repair does not close R1. Every enabled generic path must use prepared authority or be explicitly unavailable. Record which legitimate client requests/policies change and test those migrations.

## R2 — Explicit dashboard unlock

**Selected design:** Serve the same static credential-free HTML to all callers. The owner reads the existing 0600 `web.token` file and enters it into a password field. Keep the bearer only in page memory and Authorization headers. Keep the current loopback bind, Host/Origin validation, mandatory API bearer checks, no-store and frame/referrer protections.

This first fix introduces no cookie/session endpoint or new bootstrap token store. `--open` and startup output retain a credential-free URL and private token-file path; never include token values in URLs, command arguments, HTML, logs, browser storage or error messages. Preserve bind-before-token-file-write so a failed second launch cannot overwrite the active process's token file.

The browser starts locked and performs no protected requests, polling, SSE or reconciliation until an authenticated status check succeeds. An authenticated disconnected-daemon status still permits inspection of persisted policy/audit. Add **Lock dashboard**, which clears the page's token, private DOM/state/caches, audit cursor and timers and aborts requests/SSE. It is a local lock, not server-side revocation of a copied bearer. Full reload/new tab requires entry; server restart rotates the token. No idle TTL or globally revocable browser session is claimed.

Use an authentication generation and cancellation registry. After awaited headers, JSON parsing and stream reads, callbacks must match the current generation before updating the page. Lock, 401, credential replacement and page lifecycle restoration must not allow old responses to repopulate private data or restart polling. Never replay a reconciliation POST during unlock/reconnect. Explicit local `--demo` uses the same unlock rule and keeps its synthetic labels and daemon independence.

**Files:** `crates/opaque-web/src/{main,security}.rs`, `routes/mod.rs`, `static/index.html`, `tests/dashboard.test.cjs`, `docs/web-dashboard.md`. Remove token injection helpers and the existing positive test that expects a bearer in anonymous HTML. Preserve the daemon proxy's authority rules.

**Acceptance evidence:**

1. Real-router tests show identical credential-free HTML before/after authentication; missing/wrong/query-only credentials cannot access status, policy, audit/SSE, sessions, tasks/detail, operations or reconciliation. Correct owner-file bearer clients still work.
2. Frontend tests use the shipped script: zero protected calls while locked; one initialization after successful unlock; input cleared; no browser/URL credential persistence; complete lock/401 reset; stale JSON/chunks suppressed across auth generations; no mutation replay.
3. Fixture browser checks cover keyboard entry/lock, full reload, back-forward cache, restart, two tabs, transient network/SSE recovery and explicit demo. A distinct-UID Linux fixture verifies private-file denial plus locked HTML/API denial; label that check unexecuted if the validation environment cannot provide it.

**Compatibility:** Existing header-authenticated scripts continue working. Automatic browser bootstrap becomes explicit owner entry. Browser automation must enter a synthetic fixture token. Same-account processes, root, extensions and an owner who shares the token remain outside the capability-possession boundary.

## R3 — Final authority check for every protected demo response

**Invariant:** After bounded collection, parsing and transformations, the scheduler still authorizes the original visitor lease, tenant, generation and model immediately before protected bytes are released. Both original and current expiries are enforced. Scheduler denial or unavailability withholds the response.

Add a shared release-time check in `deploy/cloudflare-demo/src/http.mjs`, using the chat path's stronger binding comparison. Apply it to task/approval results, session/activity/persona/sharing JSON, protected workspace HTML and protected upstream error bodies. Preserve the independent task receipt deadline. Public landing/callback assets retain their separate public contract. Do not leave a raw generic error-body pass-through.

Use bounded readers that count actual bytes without trusting Content-Length, enforce the existing request deadline and clean up readers on all exits. Proposed initial caps preserve existing runtime limits: **32 KiB task/approval, 64 KiB control, 256 KiB session/activity/HTML/generic responses**. The current workspace HTML is about 157 KiB; test the largest legitimate activity fixture before tightening. Bound transformed output too, validate expected response shape/type, and handle deliberately empty statuses explicitly.

Add compatible final local deadline/readiness/identity checks to `deploy/hosted-demo/controller.py` and `runtime.py` for non-chat output. These are defense in depth: controller slot locks/local state cannot substitute for scheduler-authoritative cancellation. Preserve persona-lock ordering and accepted identity transitions; do not deadlock cleanup while a request holds its slot lock.

**Effect semantics:** Each upstream action is submitted once. Denied/failed disclosure does not undo an accepted sharing/persona change, retry a mutation, refund a consumed slot, fabricate a receipt or release an uncertain model fence. Preserve chat background draining and trusted completion evidence.

**Acceptance evidence:**

1. Worker HTTP fixtures delay headers and body independently for every protected response family. Expiry at the exact deadline, cancellation, lease/generation replacement, tenant/model drift and scheduler failure yield no protected payload and exactly one upstream dispatch.
2. Test boundary/oversized bodies without Content-Length, truncated framing, invalid UTF-8/JSON/shape/content type, timeout and abort. Valid response metadata/security headers and allowed statuses remain compatible.
3. Controller/runtime tests verify local expiry/readiness/cookie/generation changes and one dispatch; task reservations, ambiguous results, persona serialization and model-drain completion retain their meanings.

**Files/tests:** `deploy/cloudflare-demo/src/http.mjs`, `tests/http.test.mjs`; `deploy/hosted-demo/{controller,runtime}.py`, `test_controller.py`, `test_runtime.py`. No queue schema or persistent-state migration is planned. Prepare the edge fix first; inner-layer changes may follow under the same limits without waiting to close the public edge gap.

## R4 — MCP diagnostic cannot panic

Replace the unknown-tool name interpolation in `crates/opaque-mcp/src/main.rs` with the fixed diagnostic `unknown tool`. Preserve `INVALID_PARAMS` and request ID. Existing exact catalog membership is sufficient; no new syntax policy, dependency or panic-catching mechanism is needed.

Replace the test that duplicates the faulty string slice with calls to the real handler. Cover empty/long/Unicode names, multibyte characters around the former boundary, and missing/non-string names. Add `crates/opaque-mcp/tests/stdio.rs` using the actual binary with a nonexistent temporary daemon socket: initialization, invalid calls, ping and tools/list all occur in the same child. Assert correct IDs/errors, continued valid responses, bounded test lifetime and normal EOF exit. No daemon or provider is needed.

**Closure:** Handler tests and same-process transport tests pass, error text stays bounded and no panic occurs. Only the diagnostic wording changes; supported operations and protocol codes remain stable.

## Residual hardening and production gates

These items preserve coverage of the threat model beyond the four confirmed defects. An observation remains unverified until its acceptance evidence exists.

| ID / threats | Follow-up action | Completion evidence / scope limit |
| --- | --- | --- |
| H1 / TM-006 | Bound broker first-frame wait and pre-auth gateway/runtime work; reserve login capacity before issuer egress | Synthetic local tests prove permits/capacity are released after timeout and valid clients recover. Choose limits from legitimate lifecycle needs. No claim of measured current live DoS. |
| H2 / TM-005 | Specify whether generic sensitive dispatch must recheck policy/delegation after approval | Write the exact revocation contract and test changes before dispatch. Existing request-start semantics are documented; avoid silently changing them or claiming task-grade revocation now. Keep bounded task semantics unchanged. |
| H3 / TM-008 | Pin privileged CI actions, use locked builds, address the yanked transitive dependency, and test installer provenance with exact signer/workflow/ref and complete certificate/bundle material | All intended artifacts verify; missing/untrusted/tampered material fails according to an explicit installer policy. Test older-release compatibility before changing defaults. Re-run advisory/license/source checks; do not infer a vulnerability from yanking alone. |
| H4 / TM-008 | Add a generated-public-output privacy gate; preserve repository/visibility/ID guards and remove enabled public push paths from the private checkout | Tests inspect actual route files, search, sitemap and assets. Verify every push destination is private at push time. No private Actions enablement or public export is implied. Local alternate remote configuration remains unchanged during preparation. |
| H5 / TM-009 | Constrain command-bearing lifecycle/probe fields and runtime connection work in the fixed pod contract | Allowed/denied manifests verified against the actual admission API in a disposable environment; local tests alone do not prove live enforcement. Preserve legitimate reviewed probes. |
| D1 / TM-004 | Establish production issuer/resource-token and two independent tenant/source bindings | Exact issuer/audience/client/subject, source ownership, credentials and permitted model disclosure demonstrated with synthetic fixtures first, then approved scoped sources. OIDC discovery alone is insufficient. |
| D2 / TM-005/TM-007 | Validate actual broker/approver/host custody and platform enforcement | Separate-UID Linux, Landlock/seccomp capability probes, signed workstation flow, fixed SSH host/CA and durable restart/revocation evidence. No credit for TODO iOS transport or inferred biometric attestation. |
| D3 / TM-009 | Establish CNI enforcement, authenticated model access, encrypted sensitive internal hops and immutable processor identity | Direct unauthorized paths denied in the deployed network; model usage reconciles to intended authority; no confidential inputs until evidence exists. Preserve running workloads while preparing changes. |

No cryptographic or rate-limit parameter should be chosen solely to make a test pass. Installer and workflow follow-ups should use the official references already cited in the review and recheck the actual tool versions during implementation.

## Validation and closure workflow

For each implementation batch, add the negative regression at the relevant boundary and a positive legitimate control, then verify the fix. Tests must exercise the real handler/dispatcher where practical; no test should merely repeat the implementation. Use synthetic local fixtures, bounded subprocesses and sanitized summaries. Preserve existing local work and keep generated binaries/raw artifacts in ignored or temporary storage.

| Change | Relevant validation commands |
| --- | --- |
| R1 | `cargo test --locked -p opaque-core -p opaqued`; explicit `cargo test --locked -p opaqued --test provider_e2e`; relevant task/identity/resource suites with nonzero counts |
| R2 | `cargo test --locked -p opaque-web`; `node --test crates/opaque-web/tests/dashboard.test.cjs`; fixture browser and separate-UID checks as described |
| R3 | `node --test deploy/cloudflare-demo/tests/*.test.mjs deploy/cloudflare-docs-privacy/tests/*.test.mjs`; `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/hosted-demo -p 'test_*.py'`; affected gateway regressions |
| R4 | `cargo test --locked -p opaque-mcp`, including the new binary stdio test |
| Integrated Rust changes | `cargo fmt --all -- --check`; `cargo clippy --locked --workspace --all-targets -- -D warnings`; `cargo test --locked --workspace`; `cargo deny --locked check` |
| Public documentation/UI assets | Strict MkDocs build into temporary output, then actual output scan for private paths, report text, search/sitemap entries and copied assets |

Commands above are **planned validation**, not newly executed test results. The prior review's 250 passing tests and one ignored test remain historical evidence. Run relevant Linux capability/isolation suites when custody/sandbox contracts change; record platform-skipped tests explicitly. If private Actions remain disabled, local checks are evidence of local execution only. Do not enable release or publication workflows just to obtain a green run.

Use these states per finding: **open → implemented locally → independently reviewed → validated artifact → deployed and verified**. Record the implementation commit, exact tests/results, residual limitations and deployment identity at each transition. Code review closure and live rollout completion are distinct. Keep historical discovery evidence; append resolution evidence rather than rewriting the past. The current state of SR-001 through SR-004 is **open**.

## Release and rollback preparation

Build reviewed immutable artifacts after tests pass and inspect the diff for credentials/private publication material. Verify the destination repository/registry visibility before pushing. Public visitor docs may describe changed behavior, but this plan, the review and threat model remain private. New local branches should use the `codex/` prefix and preserve the current uncommitted reports.

Before any actual rollout, obtain fresh deployed image/configuration identities and active lease/queue state. Prepare exact patches against those current versions. The existing approval-specific rollout renderer must not be blindly reused for security rollout: it also rewrites OAuth settings, which are unrelated to these fixes. Prepare narrowly scoped image/policy changes without reapplying bootstrap state, resetting generations or deleting workloads.

Drain or preserve current sessions using the existing service lifecycle; retain broker/task/audit custody and uncertain execution accounting. Deploy the independently compatible edge response fix before relying on inner-proxy updates. Verify safe synthetic browser/task behavior, auth failures, final expiry/cancellation checks and private-route exclusion against the actual artifact. A rollback must preserve ledgers and restrict affected operations/admission if necessary; do not restore a known unsafe path as the only recovery strategy. Deployment is a later concrete action, not part of this preparation.

## Preparation result

- Source and test locations, implementation decisions, compatibility changes and closure criteria are defined for all four confirmed findings.
- Every TM-001 through TM-009 scenario maps to a fix, retained invariant, hardening item or deployment gate.
- No source fixes, new security probes, runtime test runs, credential reads, live operations, branch changes, commits or pushes occurred in this preparation. Only private assessment/planning documents changed.
- Preparation checks passed: local report links/whitespace and finding/threat coverage; strict MkDocs build; generated 74-file route, search, sitemap and asset inspection with no checked private paths or report markers. This validates document containment, not the unimplemented fixes.
