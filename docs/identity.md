# Identity (Phase 1)

Phase 1 introduces a **real principal model** on top of the Phase 0 enclave: who a
request is *for* (a verified human or a declared service), who *acts* (the agent
workload), and who *approved* it, all recorded in the tamper-evident audit chain.

The core reframe: nothing a local client process claims about itself is trusted,
because agents drive the same `opaque` CLI a human does. Identity is established
where an agent cannot follow:

- **Human identity**: proven at the IdP in a browser (OIDC). The daemon owns the
  entire flow; the CLI only displays a URL.
- **Presence**: proven by the out-of-band approval act (Phase 0), now attributed
  to a principal.
- **Delegation**: a daemon-signed token binding an agent (`act`) to the principal
  it works on behalf of (`sub`), with the effective permission being the
  *intersection* of what the agent session and the delegating principal may do.

## Principals

| Kind | Established by | Id prefix | Notes |
|---|---|---|---|
| Human | OIDC login (verified `iss` + `sub`) | `hum_` | Roles assigned by admins; first human bootstraps as admin+approver+operator |
| Agent | Workload identity (tool name) | `agt_` | Never authority-bearing on its own |
| Service | Daemon config (`[[identity.service_principals]]`) | `svc_` | For autonomous (no-human) operation, opted into by policy |

### Roles

Roles attach to principals, not client types (client classification stays
audit-only, never a security gate):

- `admin`: manage identity (assign roles, register service principals)
- `approver`: may confirm out-of-band approvals
- `operator`: may run operations (the default working role)
- `auditor`: read-only access to audit and configuration

Roles are resolved from the identity store **at request time**, never embedded in
tokens: revoking a role or disabling a principal takes effect immediately.

## Access modes

| Mode | Subject (`sub`) | Approval | Use |
|---|---|---|---|
| `delegated` | Authenticated human | Required (out-of-band) | Normal agent work on behalf of a person |
| `autonomous` | Config-declared service principal | Per policy | CI / unattended pipelines |
| `break_glass` | Authenticated human | Required, from a **distinct** approver | Emergency step-up (fails closed until a distinct-approver factor, a paired device, is available) |

## Configuration

```toml
[identity]
issuer = "https://your-org.okta.com"      # any OIDC-discoverable IdP (Okta, Entra, Google)
client_id = "opaque-cli"
# audience = "opaque-cli"                  # defaults to client_id
# redirect_port = 8721                     # fixed loopback port if your IdP requires exact redirect URIs
# session_ttl_secs = 43200                 # human login session lifetime (default 12h)
# allowed_email_domains = ["example.com"]  # fail-closed email domain allowlist
# required = false                         # when true: agent operations REQUIRE a valid delegation

[[identity.service_principals]]
name = "ci"
roles = ["operator"]
```

Register the IdP application as a **native/public client** with loopback redirect
URIs (RFC 8252). The daemon binds the loopback listener and performs the code
exchange itself with PKCE. The authorization code never passes through the CLI,
so an agent driving the CLI cannot complete a login.

## Managed identity lifecycle

A provider-neutral adapter can submit membership observations through the public
[lifecycle contract](https://github.com/kcirtapfromspace/opaque/blob/main/crates/opaque-core/src/identity_lifecycle.rs). The broker
owns admission, role mapping, authority epochs and revocation. An adapter never
opens its identity database or submits roles directly.

Enable managed lifecycle only with sealed configuration, enforced tenant custody,
a tenant binding, `identity.required = true`, and explicit
`identity.allowed_subjects`. Add these settings to the reviewed configuration:

```toml
[lifecycle]
socket_path = "/run/opaque/identity-lifecycle.sock"
allowed_adapter_uids = [7383]
socket_gid = 7999
token_file = "/var/lib/opaque/.opaque/identity-lifecycle.token"

[lifecycle.group_roles]
reviewers = ["approver", "operator"]
```

The example assumes broker UID 7381 and a separately isolated adapter UID 7383.
Preprovision the socket parent as broker-owned, group 7999, mode 0750; grant the
adapter only traversal and socket access. Every ancestor must be broker/root
controlled without untrusted writes; root-owned sticky temporary directories are
permitted. The socket is broker-owned mode 0660. Store a separate random
32–128-character URL-safe credential without whitespace in owner-only
`identity-lifecycle.token` directly inside broker custody. Give the adapter its
own private copy of only that credential. Keep task, approval, provider and
lifecycle credentials distinct. Same-UID processes share a trust boundary.

The wire format is one big-endian `u32` length followed by one JSON
`LifecycleRequest`, then one similarly framed `LifecycleResponse`. The public
`identity_lifecycle::deliver(socket, broker_uid, credential, batch)` client checks
path custody, socket ownership and the connected OS peer UID **before sending any
credential or mutation bytes**. The broker separately checks the adapter peer UID
against `allowed_adapter_uids` and authenticates the dedicated credential. There
is no TCP or HTTP fallback. Frames are bounded, connections have a 10-second
deadline, and at most 32 requests are handled concurrently.

Each version-1 batch carries the exact tenant/broker binding, configured issuer,
strictly sequential source revision starting at one, and at most 4,096 subject
updates within 2 MiB. Each subject must be explicitly admitted and may carry at
most 128 group identifiers. Core maps those identifiers through the sealed role
mapping. Unprovisioned humans cannot bootstrap admin or log in under managed
mode. Deleted subjects remain tombstoned; terminal `suspend` batches revoke human
authority and cannot be remotely cleared.

A successful receipt binds tenant, issuer, revision and the SHA-256 digest of the
serialized batch. Adapters must verify all those values before acknowledging a
source update, retain pending deliveries durably, and retry the exact batch after
an uncertain result. Only exact replay of the most recent committed revision is
acknowledged again. Updating authority and final task dispatch share the identity
writer lock; removal/regrant does not restore old sessions, delegations or
reviewer authority. A receipt cannot recall an already completed external effect.

The broker holds a lifetime endpoint writer lock. On restart it retires only an
owned stale socket after observing connection refusal; active sockets and
unrelated files remain untouched. Managed state cannot be silently disabled by
removing its configuration. Legacy `[scim]` configuration and persisted legacy
managed identity state fail closed with an explicit offline-migration requirement.
No automatic migration, authority reset, remote transport or retention pruning is
provided by this contract.

## Commands

```console
$ opaque login          # opens the IdP in your browser; daemon completes the flow
$ opaque whoami         # process identity + logged-in principal, roles, session expiry
$ opaque logout         # revoke your human session(s)
$ opaque identity ls            # principals and roles (admin/auditor)
$ opaque identity roles <id> <roles…>   # assign roles (admin)
$ opaque identity delegations   # active delegation sessions
```

## Delegation tokens

`opaque agent run` (with `[identity]` configured) mints a **delegation token**
instead of an opaque session token: `opqd1.<claims>.<sig>` (Ed25519 over
domain-separated, RFC 8693-shaped claims):

```json
{ "jti": "…", "sub": "hum_…", "act": "agt_…", "mode": "delegated", "iat": …, "exp": … }
```

- Minting still requires a **fresh out-of-band approval** (an agent cannot mint
  its own session) and, in delegated mode, an unexpired human login session.
- The daemon validates signature + expiry + store state on **every** request and
  attaches the verified `PrincipalContext` to the operation. The human session
  expiring or the delegation being revoked kills in-flight agent access.
- Approval bindings (`content_hash`) include `sub`/`act`/`mode`/`jti`, so
  approvals and first-use leases for two principals at the same uid are never
  interchangeable.

## Policy integration

Rules gain an `[identity]` block. Any identity constraint **fails closed** when
the request carries no verified principal:

```toml
[[rules]]
name = "agents-for-operators-only"
operation_pattern = "github.*"
client_types = ["agent"]

[rules.identity]
require_principal = true
roles = ["operator"]            # the DELEGATOR must hold ALL listed roles
access_modes = ["delegated"]
# principal = "dev@example.com" # pin to one principal (id or label)
```

The `roles` constraint applies to the **delegating principal** (`sub`). This is
how *effective permission = agent ∩ human* is enforced.

## Audit

- Every operation record's `client_json` now carries the principal context
  (`sub`, `act`, mode, delegation id, role snapshot).
- Approvals record **who approved** (`approver_json`): the approving principal,
  label, and source. Sources today: `local_bio_session` (presence proven,
  name session-bound), `polkit_account` (polkit-authenticated account),
  `paired_device` and `fido2` (SIGNATURE-BOUND: the daemon verified the
  approver's cryptographic response to its own challenge before recording).
- Login, logout, role changes, and delegation issue/revoke are audited events;
  every startup records a `trust_domain.posture` event, so "was the split
  enforced at the time?" is answerable from the log.
- All new fields are covered by the HMAC hash chain; pre-Phase-1 databases keep
  verifying unchanged (`opaque audit verify`).

## Threat-model honesty

- **Same-uid caveat, now MODE-DEPENDENT:** while the daemon shares the agent's
  uid (session mode), integrity here is tamper-*evident*, not tamper-*proof*:
  an adversary holding the uid can read keys and rewrite state. Under the
  trust-domain split (`[trust_domain] enforce = true`; see
  docs/deployment.md), the custody files are unreadable and unwritable at the
  agent's uid and startup fails closed on any violation: the same guarantees
  become tamper-*prevention*, verified end to end by the Linux e2e suite
  (`scripts/linux-harness.sh e2e-split`).
- **Approver attribution** depends on the factor: `local_bio_session` proves
  presence with a session-bound name; `paired_device`/`fido2` approvers are
  cryptographically verified: an Ed25519 or P-256 signature over the
  daemon-issued, decision-bound challenge, checked against the pairing or
  credential store before the approval settles.
- The loopback redirect follows RFC 8252: `state` binds the callback to the
  attempt, PKCE binds the code to the daemon, and the ID token's `nonce`, `iss`,
  `aud`, signature, and expiry are all verified against the IdP's JWKS.

## Delegation in bounded work

A delegation token is exactly what an agent session presents when planning
a [bounded-work task](bounded-work.md) on a human's behalf: `task plan*`
still requires a fresh out-of-band approval to mint the session, and every
subsequent `task run`/`show`/`reconcile` call carries the same verified
`PrincipalContext` described above, so a human logging out or a delegation
being revoked kills in-flight task access exactly like any other operation.
