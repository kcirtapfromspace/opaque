# Trusted workstation approvals

`opaque-approver` reviews and approves whole Opaque tasks from a workstation separate from the broker and the agent. The broker retains provider credentials. The workstation retains a dedicated Ed25519 private key and a broker-specific bearer token. The agent receives neither.

An enrolled workstation signature proves possession of that key. The broker trusts the enrolled workstation application to display the complete review and require native authentication; the protocol does **not** remotely attest that a biometric sensor was used. Run this application in a trusted account or workstation whose files, executables, session, and environment the agent cannot modify. A separate directory under an agent-controlled account is not this boundary.

## Install the macOS reviewer

This revision adds `Opaque Reviewer.app`, `opaque-approver`, and
`opaque-approve-helper` to future macOS release archives. Existing published tags
may predate these additions; check the selected archive's contents. The release
workflow signs the nested binaries and app, notarizes them, and staples the app
ticket. These workflow changes do not establish that a signed release has shipped.
A built unsigned or ad-hoc-signed app is a local development artifact.

Use the archive for your Mac's architecture: `aarch64-apple-darwin` for Apple
silicon or `x86_64-apple-darwin` for Intel. The launcher targets macOS 12 or later;
an actual installation and native approval still need qualification on the target
OS and architecture. Building the app locally requires macOS and Xcode Command
Line Tools with Swift. Linux has the standalone CLI and native helper, with no
macOS app or URL-handler installer; Windows is not supported by this reviewer.

The shell installer installs command-line binaries only. For the GUI, extract a
verified release archive containing the app, move it to Applications in the
trusted reviewer's account, and open it normally. macOS can then register its
`opaque-approval://` handler; verify that a reference opens the intended app if
another application has registered the same scheme. Keep
the agent in a separate account or device that cannot alter the app or custody.
The application uses its bundled binaries; it never evaluates a shell command
from a URL or downloads a helper.

The updated Homebrew formula preserves an included macOS app at
`$(brew --prefix opaque)/Opaque Reviewer.app`; it does not open the app or register
the URL handler. Both installers tolerate older archives that omit the new CLI
binaries, so installation success alone does not establish reviewer availability.
The formula currently pins v0.2.0; its release URL and checksums must be updated to
a future archive containing the reviewer before that formula delivers the app.

1. Choose a private parent folder in that trusted account and select **Create
   workstation key**. The app creates a new `opaque-workstation` folder and
   displays only public enrollment information. Use a workstation name of 1–64
   printable ASCII characters. Existing keys are never replaced.
2. Give the public key to the broker operator for the allowlist and current
   remote-task reviewer configuration described below. Wait for that setup before
   enrolling; the app does not configure the broker or grant a human role.
3. Enter the HTTPS origin, broker ID and certificate SHA-256 supplied through the
   operator's authenticated channel. Select **Enroll pinned broker**. A notice
   cannot supply or replace those settings. Selecting a different existing custody
   folder is explicit; separate brokers require separate enrollment custody.
4. Open an opaque notice. The app queues at most 16 distinct references and
   retrieves context from the enrolled broker. Choose **Review complete task**
   to start native review. Opening a notice alone cannot approve or authenticate.
5. Read every action and limit, then use native authentication to approve. Review
   is limited to 90 seconds and authentication to 60 seconds, each also bounded by
   the challenge's remaining lifetime. The app displays the challenge deadline;
   expired or changed rounds require fresh review. Rejecting the native review
   submits a signed rejection without an approval authentication step.

Only one app instance and one review per custody can run at a time. Repeated
references are ignored while already queued; the most recent 128 dismissed notices
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
"Accepted" means the broker acknowledged the signed decision, which may be either
approve or reject. Retained decision receipts are available for current-authority
v2 remote tasks; legacy v1 ceremonies do not provide the same receipt recovery.

Uninstall by removing the app; this intentionally retains reviewer custody.
Revoke the paired device at the broker before deliberately deleting an enrollment.
Replacing the app does not re-enroll, change a pin, or revive a revoked device.

## Build and inspect locally

Run from the repository root. This example respects `CARGO_TARGET_DIR`, creates a
fresh temporary output, and removes the generated bundle on exit:

```sh
(
  set -eu
  cargo build --locked -p opaque-approver -p opaque-approve-helper
  reviewer_target_dir="${CARGO_TARGET_DIR:-target}"
  reviewer_build_dir="$(mktemp -d "${TMPDIR:-/tmp}/opaque-reviewer.XXXXXX")"
  trap 'rm -rf "$reviewer_build_dir"' EXIT
  python3 scripts/package-reviewer-macos.py --binary-dir "$reviewer_target_dir/debug" \
    --output "$reviewer_build_dir/Opaque Reviewer.app" --ad-hoc
  "$reviewer_build_dir/Opaque Reviewer.app/Contents/MacOS/OpaqueReviewer" --self-test
  "$reviewer_build_dir/Opaque Reviewer.app/Contents/MacOS/opaque-approver" --help
  codesign --verify --deep --strict "$reviewer_build_dir/Opaque Reviewer.app"
)
```

Use a fresh output path. The packaging command does not install the app, register
URLs, open native UI, or modify Keychain. `--ad-hoc` verifies local bundle
integrity only. Distributed releases require a Developer ID signing identity and
notarization credentials. Their availability is unverified here and is needed for
an actual distributed artifact; local packaging can proceed without them.
The launcher's `--self-test` is inert: strict link parsing, duplicate/capacity and
post-enrollment inspection retry checks, no account state, subprocesses or decisions. It does not qualify native
visibility, accessibility or a human installation journey.

## Build

```sh
cargo build --locked -p opaque-approver -p opaque-approve-helper
```

Keep `opaque-approve-helper` beside `opaque-approver`, or install the helper in its supported system location. macOS uses a complete scrollable review followed by LocalAuthentication. Linux requires the existing desktop review helper and polkit setup. Missing native UI or authentication fails closed. These commands do not install services or alter OS accounts.

The following CLI examples assume `opaque-approver` is on the trusted operator's
`PATH`. After a source build, use `"${CARGO_TARGET_DIR:-target}/debug/opaque-approver"`
in its place. The app's bundled CLI is at
`/Applications/Opaque Reviewer.app/Contents/MacOS/opaque-approver`; quote this path.

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
# Required for current-authority v2 remote tasks:
principal_id = "<existing enabled human principal ID>"

[approval]
server_bind = "0.0.0.0:7381"
timeout_secs = 120

[remote_approvals]
reviewer_public_key_hex = "<same public_key_hex from init>"
required_role = "operator"
# notice_token_file is optional; leave it absent for CLI-only review.
```

Expose this listener only to the intended workstation network or a trusted tunnel. Keep agent IPC separate. In the applicable task policy's approval configuration, select `factors = ["paired_workstation"]`; task approval permits exactly one full-review factor. Enrollment alone does not alter policy.

This is an addition to an already provisioned broker, not a complete daemon
configuration. Current v2 remote tasks require native approval backend, enabled
bounded tasks (`enable_task_grants = true`), sealed configuration
(`require_seal = true`), enforced isolated custody, an isolated tenant binding,
and `identity.required = true`. The mapped human must remain enabled and admitted
with the configured role. Follow the [deployment guide](../../docs/deployment.md)
and [identity guide](../../docs/identity.md) for those prerequisites. A policy
requiring a distinct approver still requires a different human from the requester;
an agent or a second key for the same human does not satisfy that requirement.

Apply broker configuration through the trusted sealing/startup process before
enrollment. Existing workstation keys cannot be remapped to a different
`principal_id`; use a new key and revoke the old device for a changed mapping.
Legacy v1 ceremonies can omit `[remote_approvals]` and the principal mapping, but
that does not enable current-authority remote-task review or its retained receipts.

Obtain the broker ID and SHA-256 fingerprint of its TLS certificate through the operator's trusted channel. Do not discover or accept them from an unverified first connection. Then enroll:

```sh
opaque-approver enroll \
  --state-dir /trusted/operator/opaque-approver \
  --broker https://broker.example:7381 \
  --broker-id '<operator-verified broker ID>' \
  --tls-fingerprint '<operator-verified certificate SHA256>'
```

Enrollment requires both the trusted broker allowlist and a signed, expiring, single-use proof of key possession over the pinned TLS connection. The bearer token is saved privately and never printed. The client refuses to rebind an existing identity to another broker or TLS pin. Use separate custody for another broker.

Use the full 64-character hex certificate SHA-256, not the shortened fingerprint
shown in the daemon's startup log. The broker ID is its `opq-...` pairing identity,
not a tenant ID or hostname. There is currently no dedicated read-only CLI export
for this enrollment handoff; the operator must supply these values through trusted
provisioning. The reviewer cannot fill that gap by trusting a notice or network
discovery response.

Removing the public key from trusted configuration disables its saved credentials at the next broker startup. Revoking its paired device disables pending and future use immediately, persists across restarts, and cannot be undone by leaving the key in configuration. Rotate to a new key to replace a revoked workstation.
On the broker, the trusted operator can use `opaque device ls` to identify the
workstation and `opaque device revoke '<device-id>'` to close its admission.

## Review a task

Planning a task alone creates no review round. After the authorized caller starts
`opaque task run '<task-id>'`, list the pending round on the reviewer workstation:

```sh
opaque-approver list --state-dir /trusted/operator/opaque-approver
opaque-approver review --state-dir /trusted/operator/opaque-approver --approval-id '<approval UUID>'
```

For an opaque notice, read context without native UI using
`opaque-approver inspect --state-dir /trusted/operator/opaque-approver --notice '<opaque-approval://review/broker-id/approval-UUID>'`.
The `open` command takes the same flags and starts full native review. For
read-only recovery, use
`opaque-approver receipt --state-dir /trusted/operator/opaque-approver --approval-id '<approval UUID>'`.
Receipt access can fail after device revocation or lost reviewer eligibility;
unavailable evidence never establishes that an operation did or did not execute.

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
| `GET /workstation/receipts/{approval_id}` | Auth headers | `SignedWorkstationReceipt` (v2 remote tasks) |

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
