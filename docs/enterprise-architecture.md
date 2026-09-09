# Opaque Enterprise Architecture

This document describes the technical architecture of Opaque and outlines a
tiered deployment model from individual developer use to enterprise-scale
rollouts.

## System Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────┐
│  AI Coding Tool (Claude Code, Codex, etc.)              │
│                                                         │
│  Communicates via MCP (stdio) or CLI (Unix socket)      │
└──────────────┬──────────────────────────┬───────────────┘
               │ MCP/stdio               │ Unix socket
               ▼                         ▼
┌──────────────────────┐   ┌──────────────────────────────┐
│  opaque-mcp          │──▶│  opaqued (composition root)  │
│  (MCP protocol       │   │  crates/opaqued/              │
│   adapter, Safe ops  │   │                              │
│   only)              │   │  Dispatch + enclave.rs:      │
│  crates/opaque-mcp/  │   │  Policy ─▶ Approval           │
└──────────────────────┘   │    ▼          ▼               │
                           │  Execute ─▶ Sanitize          │
┌──────────────────────┐   │    ▼                          │
│  opaque (CLI)        │──▶│  Audit                        │
│                      │   └──────────────┬───────────────┘
│  crates/opaque/      │                  │ calls into
└──────────────────────┘   ┌──────────────┴───────────────┐
                           ▼              ▼               ▼
                  ┌────────────────┐┌──────────────┐┌────────────────┐
                  │opaque-providers││opaque-approval││opaque-sandbox  │
                  │ GitHub/GitLab/ ││ pairing/FIDO2/││ Landlock/       │
                  │ 1Password/     ││ factor        ││ seccomp/        │
                  │ Bitwarden/     ││ registry/     ││ Seatbelt        │
                  │ Vault/AWS      ││ approval-srv  ││                 │
                  └────────────────┘└──────────────┘└────────────────┘
                  ┌────────────────┐┌──────────────────────────────┐
                  │opaque-bounded- ││opaque-tenant /                 │
                  │work            ││opaque-federation-runtime       │
                  │ task ledger/   ││ tenant custody + IdP           │
                  │ SSH/inference  ││ provisioning; signed bundles,  │
                  │                ││ SIEM export, attestation       │
                  └────────────────┘└──────────────────────────────┘
                           │ all built on
                           ▼
                  ┌────────────────────────────┐
                  │  opaque-core                │
                  │  policy/operation/sanitize/ │
                  │  audit/peer/seal/proto/     │
                  │  socket/identity/bundle/    │
                  │  tenant/task/trust_domain   │
                  └──────────────┬──────────────┘
                                 │
                  ┌──────────────┼──────────────┐
                  ▼              ▼               ▼
            ┌──────────┐  ┌───────────┐  ┌────────────┐
            │ Keychain │  │ Provider  │  │ SQLite     │
            │ (secret  │  │ APIs      │  │ Audit Log  │
            │  refs)   │  │           │  │ (HMAC      │
            │          │  │           │  │  chained)  │
            └──────────┘  └───────────┘  └────────────┘
```

`opaqued` is a composition root, not a monolith: it wires together the
crates below, dispatches RPC, and owns `enclave.rs` — the enforcement funnel
every request passes through — plus identity/agent-session/provisioning
glue. Providers, approval, sandboxing, and bounded-work/tenant/federation
logic each live in their own crate; see [architecture](architecture.md) for
the full crate table.

### Core Library (`crates/opaque-core/`)

The shared library used by every binary. Selected modules:

| Module            | Purpose                                                         |
|-------------------|------------------------------------------------------------------|
| `policy.rs`       | Deny-by-default allowlist engine with glob matching, client/identity/team matching |
| `operation.rs`    | Operation registry, safety classification, request envelope, `content_hash()` (binds approvals to operation + target + secret refs + params + client + principal) |
| `sanitize.rs`     | Typestate-enforced response sanitization (an unsanitized response is a compile error) |
| `audit.rs`        | Structured audit events, HMAC hash-chain sink, central detail redaction |
| `peer.rs`         | Unix peer credential extraction (SO_PEERCRED / getpeereid) |
| `seal.rs`         | Keyed config integrity seal (`opqs1:` HMAC) |
| `trust_domain.rs` | Custody-set verification for the trust-domain split (see [Deployment](deployment.md)) |
| `identity.rs`     | Principals (Human/Agent/Service), roles, `opqd1` delegation tokens (see [Identity](identity.md)) |
| `bundle.rs`       | Signed policy bundles, `opqb1` format (see [Federation](federation.md)) |
| `attest.rs`       | Signed posture attestation reports |
| `tenant.rs`       | Tenant binding/custody (provenance, not an isolation boundary by itself) |
| `task.rs`, `ssh.rs`, `release.rs`, `inference.rs` | Immutable manifest/action types for bounded work (see [Bounded agent work](bounded-work.md)) |
| `proto.rs`        | IPC framing protocol (length-delimited codec) |
| `socket.rs`       | Socket path resolution, symlink/ownership checks |
| `profile.rs`      | Execution profile loading and secret ref validation |
| `validate.rs`     | Input validation (operation params against JSON schemas) |
| `rate_limit.rs`   | Per-client/per-operation/global sliding-window rate limiting |
| `resolver.rs`     | Provider-agnostic secret resolvers (`env:`, `keychain:`, `profile:`) plus the resolver trait family |

> **Provider feature flags, honestly.** `opaque-providers` gates GCP,
> Azure, Doppler, and Infisical behind Cargo features so an embedder
> depending on the crate directly can build without them. `opaqued`'s own
> `Cargo.toml` re-enables all four, so the shipped daemon still compiles
> every provider in — the feature boundary is at the crate level, not (yet)
> in what ships.

### Safety Classification

Every registered operation carries a safety class:

| Class             | Meaning                                    | Agent Access |
|-------------------|--------------------------------------------|--------------|
| `Safe`            | Uses secrets internally, never returns them| Allowed      |
| `SensitiveOutput` | May return credential-adjacent data        | Restricted   |
| `Reveal`          | Returns plaintext secret values            | Never (hard-blocked for every client) |

`sandbox.exec` is `SensitiveOutput` and returns only `stdout_length`/
`stderr_length`, never output content; anything that would return a
plaintext secret (e.g. `onepassword.read_field`) is `Reveal` and
hard-blocked for every client. The MCP server exposes `Safe` operations
plus a small set of `SensitiveOutput` ones with output withheld (sandbox
exec, task tools) — see [MCP integration](mcp-integration.md) for the exact
list. The enclave enforces safety-class restrictions independently either
way, as defense-in-depth.

### IPC Protocol

All communication between clients (CLI, MCP server) and the daemon uses
Unix domain sockets with length-delimited framing:

1. Client connects to the daemon's Unix socket (`$XDG_RUNTIME_DIR/opaque/opaqued.sock`
   or `~/.opaque/run/opaqued.sock`; a distinct system socket under trust-domain
   split deployments)
2. Client sends a handshake frame with a daemon token (prevents cross-user
   socket hijacking)
3. Request/response pairs use `LengthDelimitedCodec` with a 128 KB max
   frame size
4. Frames carry JSON-encoded `Request` and `Response` envelopes
5. The daemon enforces a bounded connection semaphore, per-connection rate
   limiting, and an idle timeout — none of these are unbounded

## Deployment Tiers

### Tier 1: Individual Developer

**Scope:** Single machine, single user.

- Build from source: `cargo build --release`
- Initialize: `opaque init --preset github-secrets`
- Run daemon manually or as a service: `opaque service install`
- Config stored in `~/.opaque/config.toml`
- Audit log at `~/.opaque/audit.db`
- Secrets resolved from macOS Keychain or Linux `secret-tool`

**Trust model:** The developer trusts themselves. Policy prevents AI agents
from accessing operations beyond what is explicitly allowed. Biometric
approval confirms intent for sensitive operations.

### Tier 2: Team / Shared Configuration

**Scope:** Multiple developers sharing a common policy.

- Distribute a `config.toml` through version control or config management
- Use `opaque setup --seal` to lock the policy with a keyed HMAC seal
- Daemon refuses to start if the config has been tampered with
- Team members use the same policy presets for consistency
- Bitwarden or 1Password team vaults provide shared secret references

**Trust model:** The team agrees on a policy. The config seal ensures that
local modifications are detected. Each developer still runs their own daemon.

### Tier 3: Organization / Centralized Policy

**Scope:** Hundreds of developers with centrally managed policy.

Shipped today:

- Central, signed policy bundles (`opqb1`) distributed to every daemon and
  verified before use, with anti-rollback and live hot-swap — see
  [Federation](federation.md)
- Org/team policy namespaces resolved daemon-side from the applied bundle
- Audit-chain export to SIEM (spool / webhook / TLS syslog), independently
  verifiable via `sequence_number` + `record_hash`
- Continuous software posture attestation (`opaque attest`) and a
  verify-before-trust key-release seam for KMS/SPIRE integration
- Real principal identity: daemon-owned OIDC login, roles resolved live,
  on-behalf-of delegation tokens, break-glass with a distinct-approver
  requirement — see [Identity](identity.md)
- FIDO2 / WebAuthn and paired-device approval factors, verified
  cryptographically (Ed25519/P-256) against a daemon-issued challenge

Not yet shipped:

- **Hardware-rooted attestation** — today's posture attestation is
  software-only, not a hardware measurement of the running binary. The
  KMS/SPIRE key-release seam is where that plugs in later.
- **Production IdP/resource-token wiring for `Inference` tasks** — the
  tenant/gateway machinery is implemented and fixture-tested; connecting a
  real IdP and data source is still a deployment-specific step (see below
  and [bounded work](bounded-work.md)).
- A dedicated bundle-serving control-plane server (bundles ship by URL/file
  today).

### Tenant and IdP wiring for application-evidence

`Inference` tasks enforce tenant binding, source-snapshot hash, and
per-task approval out of the box; they don't provision your IdP or connect
a live data source — that's an operator step. Today's mechanism:
`identity.required = true` plus an `identity.allowed_subjects` allowlist
scoped to your issuer.

## Security Properties

### What the Daemon Guarantees

1. **No bypass paths.** Every operation goes through `enclave.rs`. The type
   system prevents constructing a response without sanitization.

2. **Secret isolation.** Plaintext values exist only in `SecretValue` buffers
   that are zeroized on drop and optionally mlocked. They never appear in
   audit logs, error messages, or client responses — audit `detail` text is
   redacted centrally in the sink as a last line of defense.

3. **Client authentication.** Unix peer credentials are verified for every
   connection, and executable path/hash can be pinned in policy rules. A
   macOS Team-ID field exists on `ClientIdentity` but nothing populates it
   from a real code-signature check yet — `codesign_team_id` policy rules
   can't match today.

4. **Tamper detection.** The config seal catches unauthorized policy changes
   before the daemon processes any requests. Under
   [trust-domain enforcement](deployment.md), the same guarantee upgrades
   from tamper-*evidence* to tamper-*prevention*: the agent's uid cannot
   read or write the custody files that back the seal, the audit chain, or
   delegation signing key.

5. **Audit completeness.** Every request, policy decision, approval event,
   and operation outcome is logged with timestamps and correlation IDs, and
   chained by HMAC so tampering, reordering, or truncation is detectable
   (`opaque audit verify`).

### What the Daemon Does Not Guarantee

- **Network-level encryption** between daemon and provider APIs relies on
  TLS. The daemon requires HTTPS by default for provider base URLs (HTTP is
  permitted only for localhost).

- **Host compromise.** If the host OS is compromised, all bets are off.
  Opaque assumes a trusted local environment, unless trust-domain
  enforcement puts the daemon under a separate service account/container
  from the agent.

- **Provider-side security.** Opaque cannot prevent the provider (GitHub,
  1Password, etc.) from being compromised independently.

## Open work

Hardware attestation, IdP/tenant-source wiring, the inert `codesign_team_id`
field, and the provider feature-gate gap above are the open items — see
[deferred roadmap](roadmap-deferred.md) for the rest.
