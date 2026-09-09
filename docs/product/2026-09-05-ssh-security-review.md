# SSH trust-boundary security review — 2026-09-05

Internal operator evidence; exclude from public routes, search, sitemaps and assets. Read-only review using the adversarial-security-review skill. Scope: broker SSH execution and approval, task API/ledger integration, host signed control and fixed-command guard. This is a bounded implementation review, not a penetration test or a claim of hardware attestation.

## 1. Security posture summary

- No path was found for an untrusted caller to replace the approved host, CA, principal, source IP, command, delegated subject, broker tenant, or executable identity under the stated trusted-custody assumptions.
- Approval precedes certificate issuance and host admission. One durable reservation is consumed before provider dispatch; interruption and ambiguous execution do not create another allowance.
- The broker verifies Vault certificates against a pinned CA and exact critical options. The host independently verifies signed broker admission and enforces one fixed executable, an unprivileged UID, short duration, revocation and output-release checks.
- Signed host evidence is bound to the complete action and expiry. Success additionally requires exact health JSON, complete output/hash/length consistency, a successful SSH process and current broker authorization.
- Two P2 state/evidence issues were found and fixed during this review: reordered revoke/grant admission, and ambiguous Vault signing results classified as rejection. Both fixes were inspected and their targeted regression tests passed; no unresolved finding remains in this bounded scope.

## 2. Threat model assumptions and attack surface

**Assets:** Vault signer credential, ephemeral SSH private key, broker grant signing key, host receipt signing key, fixed host read authority, tenant/principal separation, durable single-use allowance and audit evidence.

**Attacker:** untrusted authenticated agent can call planning/run/revoke/read APIs, supply arbitrary manifests/tool arguments, disconnect or cancel operations and replay artifacts it observes. A network adversary can delay or interrupt traffic but cannot forge TLS or Ed25519 signatures. The agent cannot read broker custody or change sealed profiles, identities, policy, signing keys, the trusted host root configuration, or the fixed probe executable. The SSH account has no arbitrary code-execution path; its UID is the local guard trust boundary.

**Boundaries and sinks:** MCP/CLI → authenticated broker IPC → task owner and current delegation → exact policy/approval → durable reservation → Vault signing API → signed host-control API → pinned OpenSSH host/certificate → root-owned Unix guard → unprivileged fixed health probe. Sensitive sinks are certificate issuance, host-ledger admission, fixed process execution and evidence disclosure. The CA cannot approve broker work; the host receipt signer cannot mint SSH certificates.

**Invariants:** every effect must match the reviewed immutable action; revocation must never create a fresh allowance; expiry is exclusive; shell/PTY/forwarding/subsystems and caller-selected commands are unavailable; ambiguous effects stay charged; evidence cannot migrate between tenant, broker, grant, principal, profile or task action.

## 3. Findings

### Resolved P2 — Revoke-before-grant ordering could leave late host authority

**Discovery evidence:** `examples/bounded-ssh/broker_control.py`, `BrokerControl.apply` (pre-fix lines 209–233): revocation required an existing matching `broker_authority` row, while a later grant inserted its row. `crates/opaqued/src/ssh.rs`, `HostGrantCleanup::drop`, intentionally sends a revoke when cancellation interrupts an in-flight grant.

**Abuse path:** cancel or revoke an owned task while its signed grant request is delayed. Cleanup/revoke arrives first, is rejected because no grant exists, and the earlier grant subsequently commits. A disposable reproduction using the repository's existing test helpers produced `revoke-before-grant: rejected` followed by `delayed-grant status: granted`.

**Impact:** host closure is not monotonic under request reordering. In the current broker path, further SSH dispatch is withheld and the retained private key is dropped, so this review did not demonstrate an unauthorized health read. Remaining unused admission persists until expiry; the condition matters if this control protocol or credential lifecycle is reused.

**Recommended fix:** persist a revocation tombstone bound to the exact action and expiry even when its grant has not arrived. A later grant with that ID must fail. Reject mismatched action/expiry revocations without modifying existing authority.

**Resolution and verification:** `BrokerControl.apply` now atomically inserts an already-revoked grant and exact authority row when revocation precedes admission. Later grants collide with the immutable UUID. Inspected the changed code and ran `python3 -m unittest discover -s scripts -p 'test_ssh_broker_control.py' -v`: all 11 tests passed. New tests cover revoke-before-grant across restart, altered tombstone authority/expiry, and revocation overtaking an already-verified in-flight grant. They assert no probe spawn and unchanged authority. Host acknowledgement remains distinct from local revocation.

### Resolved P2 — Lost Vault signing responses were represented as rejection

**Discovery evidence:** `crates/opaqued/src/ssh.rs`, `vault_certificate` and `execute_ssh_action`: before the fix, every certificate error was mapped to `Rejected/source_unavailable`, including transport failure after the Vault signing request was dispatched.

**Abuse path:** the signing service accepts and signs, but its response is lost, reset, malformed or times out. The broker cannot prove whether issuance occurred, yet stores a deterministic rejection rather than an unknown signer outcome.

**Impact:** inaccurate durable evidence about an irreversible signer effect. Existing permanent reservation and absence of subsequent host/SSH dispatch prevent allowance reuse or a demonstrated host execution bypass. The issue is outcome integrity, not a demonstrated disclosure of the ephemeral private key.

**Recommended fix:** distinguish local/pre-dispatch validation and explicit provider rejection from ambiguous post-dispatch failures. Record an unknown outcome after transport or unusable-success-response uncertainty; retain the consumed slot and perform no automatic issuance retry.

**Resolution and verification:** `SignFailure` now distinguishes `Rejected` and `Unknown`; local/preflight failures and explicit 4xx rejection remain rejected, while dispatched transport, 5xx, unusable response and certificate-validation uncertainty become unknown. `execute_ssh_action` preserves this distinction. Ran `cargo test -p opaqued lost_signer_response_is_unknown_and_never_contacts_host_control --bin opaqued`: passed. Its signer accepts the request then truncates a promised HTTP 200 response; the result is unknown and no host-control request occurs. Existing task reservation/finalization remains unchanged, so uncertainty cannot refund the slot.

## 4. Probing questions

None block implementation review. Real deployment acceptance still needs the operator-selected host, Vault role/CA, production identity and custody configuration; fixture results do not supply those facts.

## 5. Prioritized recommendations and residual limits

1. Retain the new regression tests for both resolved findings, including reordered transport, restart, authority mismatch and ambiguous signer responses.
2. Preserve the complete reviewed profile digest plus exact subject/delegation/workload comparison at both preflight and execution. Keep provider endpoints and signer references derived from trusted configuration.
3. Keep host revocation and deadline enforcement independent of broker availability. Cancellation cleanup is best effort; network loss or runtime shutdown can prevent an acknowledgement and cannot undo a health read already accepted by the source.
4. Preserve permanent task/host reservations across restart. Retain authenticated broker ledger/audit custody: the persisted receipt includes decoded evidence and a signed-envelope digest, not an independently re-verifiable copy of the complete host signature envelope. Historical independent host-signature verification requires separately retained original signed payloads in private operator storage. Such retention is not implemented by this change; do not commit raw logs or session artifacts.
5. Treat deployment custody and the fixed command as security dependencies. Same-UID broker compromise, host-root compromise, altered probe binaries, CA compromise, time rollback and service-manager behavior are outside the demonstrated isolation guarantee. The probe's Linux parent-death signal protects the fixed executable; arbitrary replacement commands or platforms would require separate lifecycle validation.

### Controls checked and existing coverage inspected

- `task_api::require_tenant_identity`, current delegation resolution, task owner binding and `enclave::task_decision` reject principal, session, workload and profile drift.
- `execute_task` rechecks policy generation/context after approval and before reservation/dispatch. `RunGuard` seals interrupted tasks; `TaskStore::finalize_slot` binds receipt action, request ID and reserved slot and prevents second finalization.
- `ssh_key` 0.6.7 `Certificate::validate_at` was inspected locally: it verifies CA fingerprint/signature and exclusive validity. Broker code additionally checks user certificate type, exact ephemeral public key/key ID/principal/options and no extensions.
- Prior review corrections are present: fixed `HostKeyAlias` for port-independent host pinning, no process-group signal after a successfully reaped broker SSH child, execution-time full profile comparison, cancellation cleanup and strict successful-receipt expiry.
- Host tests inspected cover unsigned/tampered/cross-profile admission, nonce and grant replay, immutable allowance after restart, active revocation, source-time expiry, output suppression, process-group termination, fixed-probe parent death, busy-ledger cancellation and peer/command restrictions. The new regression evidence executed during this review is recorded in the resolved findings above. Additional real Vault/OpenSSH and broader suite results are tracked by the implementation agents.
