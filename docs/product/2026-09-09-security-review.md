# Security review — 2026-09-09

Private assessment. Exclude from public routes, search, sitemaps, previews and assets.

Assessed checkout: `e49b49e17aab4f1e73d42c8d6cce7b15de0bd711` (detached HEAD, initially clean), private `kcirtapfromspace/opaque-dogfood`. Source assessment and disposable local tests only. No product fixes, live service tests, cluster operations, credential inspection, commits, pushes or publication were performed. The companion [threat model](opaque-threat-model.md) supplies the working remediation baseline; the [remediation plan](2026-09-09-security-remediation-plan.md) tracks proposed changes and closure criteria. All four findings remain open.

## 1. Security posture summary

- **One P1, one P2 and two P3 defects were confirmed.** The highest risk is a raw broker request that passes destination policy using one target but executes against another destination in its parameters.
- The local dashboard exposes its API credential through unauthenticated HTML. Loopback and browser-origin checks do not establish an OS-user identity boundary.
- Several demo JSON responses lack the final lease check already present for task responses and chat streams. Impact is limited to an already-admitted session's late response; no cross-tenant access was demonstrated.
- Bounded task execution, resource-token validation and source/model disclosure have substantial explicit controls. Those controls must not be assumed to cover the older generic execution path or every outer proxy route.
- Existing local suites passed: **250 tests, one ignored**, plus the targeted reproductions below. The advisory scan passed with a yanked dependency warning. These results do not establish live deployment security or exhaustive coverage.
- The generated 74-file documentation site contained none of the checked private routes, search entries or internal content markers. Current source guards prevent the inherited public publication jobs from running in this private repository.

## 2. Threat model assumptions

Risk ratings use the recorded public synthetic demo plus prospective production broker use. Agents and visitors are untrusted. Broker/approver accounts, host administrators, sealed policy, source ownership and deployment operators are trusted. A different local OS user is not assumed to own the dashboard's private files. Host-root or broker-account compromise is outside the demonstrated isolation guarantee.

Assets include provider credentials and destination integrity; private policy, task, session and audit data; approval signing keys; tenant/resource authority; source evidence and model disclosure; durable consumption records; visitor input and support reasons; cluster capacity; private repository material and release artifacts. Synthetic datasets do **not** guarantee that visitor-entered text is synthetic.

The principal boundaries are agent IPC → broker authorization → provider; trusted approver → signed decision → broker; browser/local HTTP client → dashboard → owner-custody data; visitor → Worker scheduler → controller/runtime → gateway/source/model; and private source → build/release/public site. The detailed system model and residual scenarios are in the companion draft.

Ratings are conditional on deployment, not assertions that this checkout matches every live image. Local daemon DoS is excluded by `SECURITY.md`'s vulnerability reporting policy; relevant availability observations are retained below as assessment limitations rather than headline findings.

## 3. Findings

### SR-001 — P1: raw execution can authorize one destination and use another

**Evidence:** `crates/opaqued/src/main.rs:5472-5515` independently accepts client-controlled `target` and nested operation `params`, then sends both to the enclave at `5550-5566`. `crates/opaqued/src/enclave.rs:830-893` checks allowed target keys, parameter schema and derived secret references, but does not derive the target from those parameters. `crates/opaque-core/src/policy.rs:493` matches `request.target`. `crates/opaqued/src/github/mod.rs:350-398` derives the actual repository, environment and secret name from `params`. The human description iterates the target at `enclave.rs:1312-1366`.

**Preconditions and abuse path:** An admitted agent can call the generic `execute` RPC for an enabled GitHub operation. Its policy permits a specific target, and the broker's provider credential has authority beyond that target. The caller supplies the permitted target alongside different, valid destination parameters. Policy evaluates the permitted target; the handler acts on the parameter destination. Approval still occurs when required, but its target text can describe the decoy destination. Hashing the parameters preserves their bytes; it does not make the displayed destination truthful.

**Impact:** Repository/environment/secret-name policy restrictions and meaningful destination approval can be bypassed within the provider credential's actual rights. Secret publication to an unintended repository can place a broker-held value into another workflow's custody. The local experiment established the unintended write, not retrieval of a real secret. This is not an unauthenticated Internet attack, a provider-rights escalation, or a demonstrated bypass of the typed bounded-task implementation.

**Validation:** A disposable source copy with a temporary integration probe used the real daemon, validator, enclave and GitHub handler against a loopback mock provider with synthetic credentials. The convenience wrapper was denied for the out-of-policy destination. A raw request claiming the allowed repository/name was accepted, and the mock observed the write to the other repository/name. The subreview reported its dedicated test passing. No real provider was contacted; no raw credential-bearing artifacts are included here. Source inspection independently establishes the inconsistent fields and sinks.

**Recommended fix:** Parse each operation into one typed, canonical action. Derive every policy target, approval field, audit target and provider argument from that action before authorization. Reject contradictory legacy target fields and cover all generic operations, including organization, environment, scope and secret name. Until corrected, restrict generic execution of affected provider operations to a safe server-derived path; narrowing provider credentials is a secondary containment measure.

**Verification and detection:** Add real-dispatch mock tests for mismatched and omitted repository, environment, organization, scope and secret-name fields. Each must fail before credential resolution/provider calls and approval issuance. Verify wrappers and raw requests canonicalize identically. Audit the canonical destination and a fixed mismatch reason without secret values.

### SR-002 — P2: dashboard bootstrap exposes the bearer protecting private operator data

**Evidence:** `crates/opaque-web/src/main.rs:66` binds a loopback TCP listener. `security.rs:41-50` accepts a matching Host with no Origin; `security.rs:74-76` exempts non-API routes from bearer checks. `routes/mod.rs:32-34` embeds the live bearer into unauthenticated GET `/`. `routes/policy.rs:19-35` and `routes/audit.rs:45-56` read selected private files, while `daemon_client.rs:118-138` forwards requests using the dashboard process's identity.

**Preconditions and abuse path:** Another local unprivileged account or isolated process can reach the same loopback listener while the operator runs the dashboard. It obtains the bearer from HTML and accesses the APIs despite lacking permission to read the 0600 token/config/audit files. A non-browser client supplies Host and can omit Origin. Browser cross-origin protections remain useful against external websites.

**Impact:** Disclosure of dashboard-visible policy, audit, session, task and receipt information, and access to its reconciliation endpoint within the dashboard principal's existing authority. No arbitrary provider write or human approval was demonstrated. The issue is cross-user confidentiality and delegated identity, not a claim of isolation from a process that already owns the dashboard account.

**Validation:** An isolated dashboard used a 0700 temporary directory and 0600 synthetic configuration. Unauthenticated HTML returned the bearer; an API request without it returned 401; the HTML-derived bearer returned the fixture policy with 200. Foreign Host returned 403. The test did not change OS UID: cross-UID reachability is an inference from ordinary loopback TCP and the absent client identity check, not a claimed multi-UID experiment.

**Recommended fix:** Serve a bootstrap page without reusable credentials. Require a separately delivered owner capability or explicit entry of the private token before authorizing the browser. One option is a short-lived, single-use capability delivered by the launching OS process, consumed into a private session. Preserve Host/Origin and no-store protections, and document which local accounts can access the listener.

**Verification and detection:** Test that a distinct UID cannot obtain a credential or read policy, audit/SSE, tasks or reconciliation through an ordinary GET. Test expiry and replay of bootstrap capabilities and the authorized browser flow. Record static authentication failures without bearer values.

### SR-003 — P3: demo session and activity JSON can arrive after lease revocation

**Evidence:** `deploy/cloudflare-demo/src/http.mjs:158-164` authorizes before awaiting the controller. The branch at `179-189` reads and returns session/activity/control JSON without checking the scheduler again. Task output at `169-177` and chat output at `253-263` have final checks. Generic forwarding at `deploy/hosted-demo/controller.py:626-646` and `runtime.py:479-500` does not supply the missing authoritative cancellation check.

**Preconditions and abuse path:** A visitor starts a request with a valid lease. Expiry or cancellation occurs while upstream headers/body are pending. The Worker returns the late JSON although the scheduler would now deny that lease.

**Impact:** The lease's final disclosure boundary is inconsistent. Activity may contain explicitly shared visitor question text (`crates/opaque-metrics/src/organization.rs:370-392,468-473`), hashes, identity/query metadata and results; session responses include support metadata. The response belongs to an already-admitted session. No new post-expiry request, cross-tenant read, credential disclosure or approval bypass was shown. **Low severity for the current bounded synthetic demo; reassess as medium before using this proxy for confidential tenant data.**

**Validation:** Six isolated cases used the real Worker handler and queue with a mock upstream: expiry and cancellation during each of session, activity and sharing requests. All returned a sentinel JSON payload with 200, performed only the initial authorization, and subsequently failed queue authorization. No deployed endpoint was used.

**Recommended fix:** Bound and collect protected responses, then reauthorize immediately before release and compare the original lease/generation with current authority. Apply the rule consistently to other protected HTML/generic output. Keep mutation outcomes distinct: withholding a late sharing response does not undo an accepted sharing change and must not trigger redispatch.

**Verification and detection:** Delay headers and body independently; cancel, expire or replace the lease during each wait; assert no protected bytes are released and no action is retried. Emit a fixed disclosure-denied reason and nonsecret correlation ID.

### SR-004 — P3: a Unicode unknown-tool name terminates the MCP process

**Evidence:** `crates/opaque-mcp/src/main.rs:172-179` truncates unknown tool names by byte index 64. This can split a valid UTF-8 character. The main dispatcher awaits the handler at `481-489`.

**Preconditions and impact:** A malformed or model-generated `tools/call` supplies a valid Unicode name crossing that byte boundary. The MCP stdio process panics and closes its session instead of returning `INVALID_PARAMS`. No daemon access or privilege gain is needed or obtained.

**Validation:** A disposable MCP process with a nonexistent daemon socket received a boundary-crossing unknown name. It exited 101 with a character-boundary panic and no JSON-RPC response. No live daemon was contacted.

**Recommended fix and verification:** Use character-safe truncation or a bounded generic error, and validate supported tool-name syntax. Test multibyte inputs on either side of the truncation boundary, followed by a successful ping on the same process.

## 4. Probing questions and open context

The user was asked whether risk should be calibrated for the public synthetic demo plus planned production broker use, and whether trusted host/broker-custody assumptions apply. Their subsequent direction to prepare remediation is being used to proceed under that working baseline. No additional live deployment facts were supplied. Code findings stand; deployment likelihood remains conditional.

No extra permission is required to read this report or review fixes. A production acceptance decision additionally needs the actual data owners, provider-token scope, externally reachable listeners, CNI/model isolation and deployed image/config identity. Those were not inferred from historical rollout notes.

## 5. Prioritized recommendations

1. Correct SR-001 before relying on generic provider destination policy for production secrets. Canonicalize once and use the same action for authorization, review and execution.
2. Correct SR-002 before using the live dashboard where untrusted processes or other OS users can reach its listener.
3. Close the demo's late-response gap and retain its synthetic-data restriction until actual confidential-source and model isolation are demonstrated.
4. Fix the MCP Unicode panic and keep the targeted negative cases alongside existing authorization and lifecycle regressions.
5. Extend security gates to cover raw IPC versus wrappers, complete response delivery, local-user dashboard access and generated public output. Track the residual items below without representing them as confirmed exploits.

## Residual risks and controls checked

- **Task and SSH controls:** Task owner/tenant/delegation checks, exact manifest/profile bindings, approval followed by current-policy checks, durable reservation before dispatch, charged unknown outcomes, Vault certificate checks and signed fixed-command host admission were inspected. Prior September 4/5 Git-workspace and SSH ordering/outcome fixes are present; their old findings were not copied as open defects. This assessment does not rerun the complete Linux isolation, real Vault/OpenSSH or cluster suites.
- **Legacy revocation semantics:** `enclave.rs:744-747` explicitly allows requests already evaluated to finish under the old policy. The generic path resolves identity/evaluates policy before approval, unlike the bounded-task rechecks. This is a documented contract difference and a production design decision, not a separately counted newly discovered bypass. Consider stronger checks before sensitive dispatch when immediate revocation is required.
- **Connection availability:** The daemon acquires one of 64 connection permits before the first frame (`main.rs:2119,2152-2170,3191`). The 30-second idle timeout starts after handshake (`3250-3252`). Withholding the first frame appears able to retain permits; saturation was not tested. Metrics login performs issuer metadata requests before its pending-login cap (`opaque-metrics/src/server.rs:1458-1504`). Bound pre-authentication work and reserve capacity before egress for exposed deployments.
- **Metrics/source/model controls:** Production mode requires broker authority; tokens bind exact tenant, issuer, resource, client, scope and current membership. Typed source queries and validated responses constrain tenant/query/freshness; model output does not create authorization. Source/model/OAuth transports restrict redirects/proxies/retries and bound responses. Queued gateway disclosures recheck current authority. Local gateway tests exercise these controls, but provider ownership and deployment custody remain dependencies.
- **Human approval:** The Rust workstation client pins an exact TLS certificate, bounds responses, maintains private key/token files and revalidates/refetches the full review after user interaction. The demo binds OAuth/passkey approval to a task manifest. A valid enrolled signature does not independently prove a biometric ceremony. The iOS network client remains a TODO scaffold (`ios/Opaque/Sources/Network/ApprovalClient.swift`); it was not credited as a functioning production approval transport.
- **Cluster limitations:** `deploy/hosted-demo/OPERATIONS.md:307-315` records unverified network-policy enforcement, routable model services, plaintext internal hops, other model clients and mutable/shared model custody. These are known deployment assumptions, not newly demonstrated live exploits. Runtime connection limits and admission restrictions on lifecycle/probe commands merit further checks before claiming containment of hostile cluster peers or a compromised controller.
- **Supply chain:** `cargo deny --locked check advisories` passed under the checked configuration, including its existing `RUSTSEC-2025-0119` exception. It warned about yanked `spin 0.9.8` through `flume`/`mdns-sd`; no vulnerability is inferred solely from yanking. CI uses several mutable action tags. Pin privileged actions to reviewed commits as recommended by [GitHub](https://docs.github.com/en/actions/reference/security/secure-use).
- **Installer provenance:** `install.sh:223-257` makes cosign optional, skips verification if signature download fails, and supplies only a detached signature, while release CI emits a separate certificate (`.github/workflows/release.yml:141-145`). Use a tested certificate/bundle verification flow with exact workflow/ref identity and an explicit trust policy. [Sigstore's verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/) describes the necessary verification material. No live release signature was tested; this is hardening/compatibility work, not a demonstrated artifact compromise.
- **Private/public containment:** MkDocs excludes `product/**` and the private guides. The generated output was inspected, not only navigation. Public release/site jobs require the public repository and visibility; the staging workflow requires the private repository ID and visibility. Local `public-opaque` still has an enabled public push URL, unlike `upstream`; remove/disable that accidental-publication path in a separately scoped configuration change. No push was attempted and current remote repository visibility was not queried.

## Validation record and limitations

| Check | Result |
| --- | --- |
| `cargo test -p opaque-web --offline -- --test-threads=2` | 34 passed |
| `cargo test -p opaque-metrics --offline --test gateway -- --test-threads=2` | 53 passed; 1 ignored |
| `node --test deploy/cloudflare-demo/tests/*.test.mjs deploy/cloudflare-docs-privacy/tests/*.test.mjs` | 93 passed; includes 3 privacy Worker tests also run separately |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/hosted-demo -p 'test_*.py'` | 70 passed |
| Dedicated broker mock-provider regression in disposable source | Subreview reported reproduction passed; scoped wrapper denied, inconsistent raw request dispatched |
| Isolated dashboard and MCP probes | Both defects reproduced; no real daemon/config/credentials used |
| Delayed demo JSON probes | 6 expiry/cancellation cases reproduced |
| `cargo deny --locked check advisories` | Passed with existing advisory exception; yanked dependency warning |
| `mkdocs build --strict --site-dir /tmp/opaque-security-site-2026-09-09` | Passed; generated 74 files |
| Generated site inspection | No excluded private paths/search locations; no selected internal content markers |

The 250-test total counts the existing suites once and excludes the dedicated reproduction cases. Passing suites did not catch the new cases. No full workspace test run, broad fuzzing, live penetration test, actual multi-UID experiment, real human ceremony or live-network containment validation was performed. Two follow-up subreview runs were stopped by automatic security review for “possible cybersecurity risk”; previously completed findings and local results were retained, and no blocked experiment was retried. Temporary evidence and binaries remain outside tracked report content.
