# Remote reviews and independent notification adapters

Opaque core owns the review challenge, current reviewer eligibility, signed
decision and final authorization check. A separately enrolled workstation fetches
the full review over pinned TLS and signs the exact challenge. The broker verifies
that signature and retains the decision before acknowledging it. Notification
adapters cannot approve work or replace the native review ceremony.

A host can use the public `opaque-approval` runtime without an enterprise service.
`RemoteApprovals` accepts host-owned reviewer resolution and authority guards;
the host keeps revocation checks held through the irreversible ledger transition.
The same configured device, principal, required role, authority epoch and exact
requester must remain eligible when a decision is accepted and used.

## Configuring the optional notice feed

```toml
[remote_approvals]
reviewer_public_key_hex = "<independently enrolled workstation Ed25519 public key>"
required_role = "operator"
notice_token_file = "/absolute/broker-custody/notice.token"
```

The optional token is a dedicated read credential, not a paired-device token.
Its file must be an owned mode-0600 regular file directly inside the same custody
directory as the remote decision ledger. Use 32–128 random URL-safe characters,
with no whitespace, and distribute it only to the intended adapter through
private custody. The broker hashes the credential at startup; credential rotation
requires an intentional restart, which cancels unfinished approval rounds.
Omitting the token disables the feed while preserving trusted workstation review.
Legacy `slack` configuration is rejected, so a migration cannot silently leave
notification delivery enabled inside the broker.

`GET /notifications/pending` on the existing HTTPS approval server requires the
single `Authorization: Bearer <notice-token>` header. Browser-origin requests are
rejected. The response has `Cache-Control: no-store` and this v1 shape:

```json
{
  "schema_version": 1,
  "broker_id": "opq-example",
  "notices": [
    {
      "approval_id": "00000000-0000-4000-8000-000000000001",
      "broker_id": "opq-example",
      "expires_at": 2000000000
    }
  ]
}
```

The response contains at most the 64 live workstation rounds and filters each
against current reviewer eligibility and expiry. It contains no review text,
requester, task details, signing keys or transport credentials. Polling does not
consume a round or write delivery status. A notice token cannot fetch workstation
review documents or submit decisions. Public wire structs are
`remote::notices::{ApprovalNotice, PendingNoticeFeed}`.

## Implementing an adapter

Pin the broker's certificate and identity through a trusted channel before
sending credentials. Disable redirects and ambient proxies, bound requests and
responses, validate the feed version and broker ID, and never derive endpoints
or credentials from notice contents. Use `opaque_core::workstation::notice_link`
to create the opaque reference; only the enrolled approver resolves it against
its own pinned broker configuration.

An adapter owns its delivery deduplication, retry budget and transport credentials
separately from broker state. Recheck that a notice is still pending immediately
before delivery. Cancellation can race a message already in transit; the message
still carries no authority, and the workstation/broker check the current review.
A delivery failure or unknown outcome must never become an approval or retry of
an agent operation. Snapshot or transport availability is not proof of approval.

Core retains the existing decision ledger schema for historical signed receipts.
Old notification columns remain inert for compatibility; new rounds do not store
transport attempts there. Restart cancels unfinished rounds and cannot resume
work from either historical receipts or notification state.

Current remote task approval uses one configured reviewer. It does not authorize
MCP invocations, provide approval quorum or imply a completed production pilot.
