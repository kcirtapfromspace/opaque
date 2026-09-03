# Identity (Phase 1)

Phase 1 introduces a **real principal model** on top of the Phase 0 enclave: who a
request is *for* (a verified human or a declared service), who *acts* (the agent
workload), and who *approved* it — all recorded in the tamper-evident audit chain.

The core reframe: nothing a local client process claims about itself is trusted,
because agents drive the same `opaque` CLI a human does. Identity is established
where an agent cannot follow:

- **Human identity** — proven at the IdP in a browser (OIDC). The daemon owns the
  entire flow; the CLI only displays a URL.
- **Presence** — proven by the out-of-band approval act (Phase 0), now attributed
  to a principal.
- **Delegation** — a daemon-signed token binding an agent (`act`) to the principal
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

- `admin` — manage identity: assign roles, register service principals
- `approver` — may confirm out-of-band approvals
- `operator` — may run operations (the default working role)
- `auditor` — read-only access to audit and configuration

Roles are resolved from the identity store **at request time**, never embedded in
tokens — revoking a role or disabling a principal takes effect immediately.

## Access modes

| Mode | Subject (`sub`) | Approval | Use |
|---|---|---|---|
| `delegated` | Authenticated human | Required (out-of-band) | Normal agent work on behalf of a person |
| `autonomous` | Config-declared service principal | Per policy | CI / unattended pipelines |
| `break_glass` | Authenticated human | Required, from a **distinct** approver | Emergency step-up (fails closed until a distinct-approver factor — a paired device — is available) |

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
exchange itself with PKCE — the authorization code never passes through the CLI,
so an agent driving the CLI cannot complete a login.

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
instead of an opaque session token: `opqd1.<claims>.<sig>` — Ed25519 over
domain-separated, RFC 8693-shaped claims:

```json
{ "jti": "…", "sub": "hum_…", "act": "agt_…", "mode": "delegated", "iat": …, "exp": … }
```

- Minting still requires a **fresh out-of-band approval** (an agent cannot mint
  its own session) and — in delegated mode — an unexpired human login session.
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

The `roles` constraint applies to the **delegating principal** (`sub`) — this is
how *effective permission = agent ∩ human* is enforced.

## Audit

- Every operation record's `client_json` now carries the principal context
  (`sub`, `act`, mode, delegation id, role snapshot).
- Approvals record **who approved** (`approver_json`): the approving principal,
  label, and source. Sources today: `local_bio_session` (presence proven,
  name session-bound), `polkit_account` (polkit-authenticated account),
  `paired_device` and `fido2` (SIGNATURE-BOUND — the daemon verified the
  approver's cryptographic response to its own challenge before recording).
- Login, logout, role changes, and delegation issue/revoke are audited events;
  every startup records a `trust_domain.posture` event, so "was the split
  enforced at the time?" is answerable from the log.
- All new fields are covered by the HMAC hash chain; pre-Phase-1 databases keep
  verifying unchanged (`opaque audit verify`).

## Threat-model honesty

- **Same-uid caveat, now MODE-DEPENDENT:** while the daemon shares the agent's
  uid (session mode), integrity here is tamper-*evident*, not tamper-*proof* —
  an adversary holding the uid can read keys and rewrite state. Under the
  trust-domain split (`[trust_domain] enforce = true` — see
  docs/deployment.md), the custody files are unreadable and unwritable at the
  agent's uid and startup fails closed on any violation: the same guarantees
  become tamper-*prevention*, verified end to end by the Linux e2e suite
  (`scripts/linux-harness.sh e2e-split`).
- **Approver attribution** depends on the factor: `local_bio_session` proves
  presence with a session-bound name; `paired_device`/`fido2` approvers are
  cryptographically verified — an Ed25519 or P-256 signature over the
  daemon-issued, decision-bound challenge, checked against the pairing or
  credential store before the approval settles.
- The loopback redirect follows RFC 8252: `state` binds the callback to the
  attempt, PKCE binds the code to the daemon, and the ID token's `nonce`, `iss`,
  `aud`, signature, and expiry are all verified against the IdP's JWKS.
