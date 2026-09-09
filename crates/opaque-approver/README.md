# Trusted workstation approvals

`opaque-approver` reviews and approves whole Opaque tasks from a workstation separate from the broker and the agent. The broker retains provider credentials. The workstation retains a dedicated Ed25519 private key and a broker-specific bearer token. The agent receives neither.

An enrolled workstation signature proves possession of that key. The broker trusts the enrolled workstation application to display the complete review and require native authentication; the protocol does **not** remotely attest that a biometric sensor was used. Run this application in a trusted account or workstation whose files, executables, session, and environment the agent cannot modify. A separate directory under an agent-controlled account is not this boundary.

## Build

```sh
cargo build -p opaque-approver -p opaque-approve-helper
```

Keep `opaque-approve-helper` beside `opaque-approver`, or install the helper in its supported system location. macOS uses a complete scrollable review followed by LocalAuthentication. Linux requires the existing desktop review helper and polkit setup. Missing native UI or authentication fails closed. These commands do not install services or alter OS accounts.

## Enroll using trusted operator channels

On the trusted workstation, initialize an explicit custody directory whose parent already exists:

```sh
opaque-approver init --state-dir /trusted/operator/opaque-approver --name "Release workstation"
```

The command creates a private `0700` directory and separate `0600` key/state files, refuses to overwrite credentials, and prints JSON containing `public_key_hex` and `key_fingerprint`. Share only the public enrollment information with the broker operator. Never copy `workstation.key` or the enrolled `workstation.json` into the agent or broker environment.

The broker operator adds the public key to trusted daemon configuration:

```toml
[[workstation_approvers]]
name = "Release workstation"
public_key_hex = "<public_key_hex from init>"
# Optional existing human principal for audit and distinct-approver checks:
# principal_id = "<human principal ID>"

[approval]
server_bind = "0.0.0.0:7381"
timeout_secs = 120
```

Expose this listener only to the intended workstation network or a trusted tunnel. Keep agent IPC separate. In the applicable task policy's approval configuration, select `factors = ["paired_workstation"]`; task approval permits exactly one full-review factor. Enrollment alone does not alter policy.

Obtain the broker ID and SHA-256 fingerprint of its TLS certificate through the operator's trusted channel. Do not discover or accept them from an unverified first connection. Then enroll:

```sh
opaque-approver enroll \
  --state-dir /trusted/operator/opaque-approver \
  --broker https://broker.example:7381 \
  --broker-id '<operator-verified broker ID>' \
  --tls-fingerprint '<operator-verified certificate SHA256>'
```

Enrollment requires both the trusted broker allowlist and a signed, expiring, single-use proof of key possession over the pinned TLS connection. The bearer token is saved privately and never printed. The client refuses to rebind an existing identity to another broker or TLS pin. Use separate custody for another broker.

Removing the public key from trusted configuration disables its saved credentials at the next broker startup. Revoking its paired device disables pending and future use immediately, persists across restarts, and cannot be undone by leaving the key in configuration. Rotate to a new key to replace a revoked workstation.

## Review a task

After an agent starts a planned task, list pending rounds:

```sh
opaque-approver list --state-dir /trusted/operator/opaque-approver
opaque-approver review --state-dir /trusted/operator/opaque-approver --approval-id '<approval UUID>'
```

The application retrieves every byte of the broker-generated manifest review, verifies its hash, broker identity, round, and deadline, then displays it through the native review helper. After approval and native authentication it re-fetches the same round and signs the exact decision. A changed, cancelled, expired, or consumed round cannot authorize execution. Rejecting the review sends a signed rejection. There is no noninteractive approval option.

## Wire protocol for isolated fixtures

Production serde types and signing functions live in `opaque_core::workstation`. All routes require TLS pinning. Only an allowlisted public key can obtain an enrollment challenge:

| Route | Request | Response |
| --- | --- | --- |
| `POST /workstation/enrollment/challenge` | `{public_key_hex}` | `EnrollmentChallenge` |
| `POST /workstation/enrollment/complete` | `{public_key_hex, nonce, signature}` | `{device_id, server_id, token}` |
| `GET /workstation/approvals/pending` | Auth headers | `{approvals: [WorkstationChallenge]}` |
| `GET /workstation/approvals/{approval_id}` | Auth headers | `{challenge, review_text}` |
| `POST /workstation/approvals/{approval_id}/respond` | `{device_id, decision, signature}` | Empty HTTP 200 |

Authenticated routes require both `Authorization: Bearer <token>` and `X-Opaque-Device: <device_id>`. Legacy mobile credentials cannot access this capability. `decision` is `approve` or `reject`; signatures are 64-byte Ed25519 signatures encoded as 128 hexadecimal characters.

`WorkstationChallenge` fields are `schema_version` (1), `broker_id`, `approval_id`, `request_id`, `operation`, `content_hash`, `nonce`, `created_at`, and `expires_at`. Times are Unix seconds; the nonce is 32 random bytes encoded as hex. `content_hash` is SHA-256 of the exact UTF-8 `review_text`. Supported operations are `github.publish_manifest`, `github.release_manifest`, `inference.fixed_manifest`, and `agent_session_start`. Agent session creation uses a paired workstation only when the trusted daemon sets `[approval] session_factor = "paired_workstation"`; its default is native approval. Pairing and role management retain native approval. Expiry is exclusive and the maximum challenge lifetime is 300 seconds.

To build the signed message, prefix **each** field with its byte length encoded as a four-byte little-endian integer, concatenate, then SHA-256 the result. Sign the resulting 32 bytes with ordinary Ed25519 (not Ed25519ph). Decision fields, in order:

1. UTF-8 `opaque.workstation-decision.v1`
2. `broker_id`
3. `approval_id`
4. `request_id`
5. `operation`
6. `content_hash`
7. `nonce`
8. `created_at`, encoded as eight-byte signed little-endian
9. `expires_at`, encoded as eight-byte signed little-endian
10. UTF-8 `approve` or `reject`

Enrollment uses the same field encoding with domain `opaque.workstation-enrollment.v1`, then `broker_id`, `public_key_hex`, `nonce`, `created_at`, and `expires_at`.

Automated fixtures must use isolated disposable signing keys and configure broker `workstation_test_mode = true`. This exercises the real signature verification path while marking receipts `insecure_test`. It is not evidence of human review. The production CLI has no fixture signing or authentication bypass.
