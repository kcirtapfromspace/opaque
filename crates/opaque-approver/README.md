# Trusted workstation approvals

`opaque-approver` reviews and approves whole Opaque tasks from a workstation separate from the broker and the agent. The broker retains provider credentials. The workstation retains a dedicated Ed25519 private key and a broker-specific bearer token. The agent receives neither.

An enrolled workstation signature proves possession of that key. The broker trusts the enrolled workstation application to display the complete review and require native authentication; the protocol does **not** remotely attest that a biometric sensor was used. Run this application in a trusted account or workstation whose files, executables, session, and environment the agent cannot modify. A separate directory under an agent-controlled account is not this boundary.

## Install the macOS reviewer

The macOS release archive includes `Opaque Reviewer.app`, `opaque-approver`, and
`opaque-approve-helper`. The release workflow signs the nested binaries and app,
notarizes them, and staples the app ticket. A built unsigned or ad-hoc-signed app
is a local development artifact, not evidence that trusted distribution succeeded.

Move the released app to Applications in the trusted reviewer's account and open
it normally. This associates `opaque-approval://` references with the app. Keep
the agent in a separate account or device that cannot alter the app or custody.
The application uses its bundled binaries; it never evaluates a shell command
from a URL or downloads a helper.

1. Choose a private parent folder in that trusted account and select **Create
   workstation key**. The app creates a new `opaque-workstation` folder and
   displays only public enrollment information. Existing keys are never replaced.
2. Give the public key to the broker operator for the allowlist described below.
3. Enter the HTTPS origin, broker ID and certificate SHA-256 supplied through the
   operator's authenticated channel. Select **Enroll pinned broker**. A notice
   cannot supply or replace those settings. Selecting a different existing custody
   folder is explicit; separate brokers require separate enrollment custody.
4. Open an opaque notice. The app queues at most 16 distinct references and
   retrieves context from the enrolled broker. Choose **Review complete task**
   to start native review. Opening a notice alone cannot approve or authenticate.
5. Read every action and limit, then use native authentication. The app displays
   the remaining deadline; expired or changed rounds require fresh review.

Only one app instance and one review per custody can run at a time. Repeated
references select the existing queue entry; the most recent 128 completed notices
are suppressed for the application session. Broker consumption remains the
persistent replay defense across app restarts. Queued references and displayed
context are memory-only; the locally selected custody path is an account preference.
The app does not poll Slack or an untrusted URL. Unknown broker and stale notices
fail closed. Dismissal is local and does not send a rejection.

A decision report says **decision accepted** or **acknowledgment unknown**. Neither
means the operation succeeded. If the response was lost, the CLI tries one
read-only receipt lookup for that exact decision; it never resends the POST or
agent operation. The app also offers **Look up decision receipt**. Missing receipts
remain unknown. Verify actual effects through the broker's operation evidence.

Uninstall by removing the app; this intentionally retains reviewer custody.
Revoke the paired device at the broker before deliberately deleting an enrollment.
Replacing the app does not re-enroll, change a pin, or revive a revoked device.

## Build and inspect locally

```sh
cargo build -p opaque-approver -p opaque-approve-helper
python3 scripts/package-reviewer-macos.py --binary-dir target/debug \
  --output /tmp/opaque-reviewer-build/Opaque\ Reviewer.app --ad-hoc
/tmp/opaque-reviewer-build/Opaque\ Reviewer.app/Contents/MacOS/OpaqueReviewer --self-test
```

Use a fresh output path. The packaging command does not install the app, register
URLs, open native UI, or modify Keychain. `--ad-hoc` verifies local bundle
integrity only. Distributed releases require a Developer ID signing identity and
notarization credentials; their availability is an operator prerequisite.
The launcher's `--self-test` is inert: strict link parsing, duplicate/capacity
checks, no account state, subprocesses or decisions. It does not qualify native
visibility, accessibility or a human installation journey.

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

`WorkstationChallenge` fields are `schema_version` (1 for legacy ceremonies, 2 for current-authority remote tasks), optional `authority`, `broker_id`, `approval_id`, `request_id`, `operation`, `content_hash`, `nonce`, `created_at`, and `expires_at`. Times are Unix seconds; the nonce is 32 random bytes encoded as hex. `content_hash` is SHA-256 of the exact UTF-8 `review_text`. Supported operations are `github.publish_manifest`, `github.release_manifest`, `inference.fixed_manifest`, `agent_session_start`, `identity.provisioning.bind_start`, and `identity.provisioning.mandate_start`. Remote MCP invocation is not supported by this protocol. Agent session creation uses a paired workstation only when the trusted daemon sets `[approval] session_factor = "paired_workstation"`; its default is native approval. Pairing and role management retain native approval. Expiry is exclusive and the maximum challenge lifetime is 300 seconds.

To build the signed message, prefix **each** field with its byte length encoded as a four-byte little-endian integer, concatenate, then SHA-256 the result. Sign the resulting 32 bytes with ordinary Ed25519 (not Ed25519ph). Legacy v1 decision fields, in order:

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

Version 2 uses the following field sequence: UTF-8
`opaque.workstation-decision.v2`, `schema_version` as four-byte unsigned
little-endian, `broker_id`, `approval_id`, `request_id`, `operation`,
`content_hash`, `nonce`, eight-byte signed little-endian `created_at` and
`expires_at`, compact UTF-8 JSON for `authority`, then `approve` or `reject`.
Every field still has its four-byte little-endian byte-length prefix before the
combined SHA-256 and Ed25519 signature.

The authority JSON uses the exact declared struct order, without whitespace:
`binding`, `principal_id`, `public_key_hex`, `required_role`, `authority_epoch`.
Binding order is `tenant`, `task_id`, `manifest_digest`, `request_hash`,
`policy_digest`, `requester`; tenant order is `schema_version`, `tenant_id`, `broker_id` (`schema_version` is 1).
Strings use Serde JSON escaping and UUIDs use their serialized string form.
Use the public Rust structs and `workstation_decision_bytes` rather than signing
an independently reformatted JSON object. Unknown fields, mismatched schema/
authority combinations and altered authority are rejected.

`GET /workstation/receipts/{approval_id}` returns `SignedWorkstationReceipt` with
`schema_version`, `review`, `response` and `accepted_at`. Verification authenticates
the human decision and reviewed bytes using the enrolled reviewer key. It does
not authenticate a hardware sensor, make `accepted_at` part of that signature,
or establish a separately signed producer checkpoint or an execution result.
Current reviewer/device eligibility is still required for receipt access.

Enrollment uses the same field encoding with domain `opaque.workstation-enrollment.v1`, then `broker_id`, `public_key_hex`, `nonce`, `created_at`, and `expires_at`.

Automated fixtures must use isolated disposable signing keys and configure broker `workstation_test_mode = true`. This exercises the real signature verification path while marking receipts `insecure_test`. It is not evidence of human review. The production CLI has no fixture signing or authentication bypass.
