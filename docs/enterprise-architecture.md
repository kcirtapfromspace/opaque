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
│  opaque-mcp          │──▶│  opaqued (daemon)             │
│  (MCP protocol       │   │                              │
│   adapter, Safe ops  │   │  ┌─────────────────────────┐ │
│   only)              │   │  │ Enclave                  │ │
│                      │   │  │ (enclave.rs)             │ │
│  crates/opaque-mcp/  │   │  │                          │ │
└──────────────────────┘   │  │  Policy ─▶ Approval      │ │
                           │  │    ▼          ▼          │ │
┌──────────────────────┐   │  │  Execute ─▶ Sanitize     │ │
│  opaque (CLI)        │──▶│  │    ▼                     │ │
│                      │   │  │  Audit                   │ │
│  crates/opaque/      │   │  └─────────────────────────┘ │
└──────────────────────┘   │                              │
                           │  Provider handlers:          │
                           │  ├── github/    (client.rs,  │
                           │  │              crypto.rs)   │
                           │  ├── gitlab/    (client.rs)  │
                           │  ├── onepassword/ (client.rs,│
                           │  │                op_cli.rs) │
                           │  ├── bitwarden/ (client.rs)  │
                           │  ├── vault/     (client.rs)  │
                           │  └── sandbox/   (macos.rs,   │
                           │                  linux.rs)   │
                           │                              │
                           │  crates/opaqued/             │
                           └──────────────────────────────┘
                                       │
                           ┌───────────┼───────────┐
                           ▼           ▼           ▼
                     ┌──────────┐ ┌─────────┐ ┌────────┐
                     │ Keychain │ │ Provider│ │ SQLite │
                     │ (secret  │ │ APIs    │ │ Audit  │
                     │  refs)   │ │         │ │ Log    │
                     └──────────┘ └─────────┘ └────────┘
```

### Core Library (`crates/opaque-core/`)

The shared library used by all binaries:

| Module         | Purpose                                                    |
|----------------|------------------------------------------------------------|
| `policy.rs`    | Deny-by-default allowlist engine with glob matching        |
| `operation.rs` | Operation registry, safety classification, request envelope|
| `sanitize.rs`  | Typestate-enforced response sanitization                   |
| `audit.rs`     | Structured audit events with correlation IDs (SQLite sink) |
| `peer.rs`      | Unix peer credential extraction (SO_PEERCRED / getpeereid) |
| `seal.rs`      | Config integrity seal (SHA-256 in OS keychain)             |
| `proto.rs`     | IPC framing protocol (length-delimited codec)              |
| `socket.rs`    | Socket path resolution and safety validation               |
| `profile.rs`   | Execution profile loading and secret ref validation        |
| `validate.rs`  | Input validation (operation params against JSON schemas)   |

### Daemon (`crates/opaqued/`)

The trusted process that holds secrets and enforces policy:

| Module          | Purpose                                                   |
|-----------------|-----------------------------------------------------------|
| `enclave.rs`    | Central enforcement funnel — all requests flow through it |
| `approval.rs`   | Native OS approval prompts (macOS Touch ID, Linux polkit) |
| `github/`       | GitHub API client, NaCl encryption, operation handler     |
| `gitlab/`       | GitLab CI/CD variable API client and handler              |
| `onepassword/`  | 1Password Connect API + CLI integration                   |
| `bitwarden/`    | Bitwarden Secrets Manager API client and handler          |
| `vault/`        | HashiCorp Vault KV client with lease-aware caching        |
| `sandbox/`      | Sandboxed command execution (macOS sandbox-exec, Linux)   |
| `secret.rs`     | `SecretValue` wrapper with zeroize-on-drop and mlock      |

### Safety Classification

Every registered operation carries a safety class:

| Class             | Meaning                                    | Agent Access |
|-------------------|--------------------------------------------|--------------|
| `Safe`            | Uses secrets internally, never returns them| Allowed      |
| `SensitiveOutput` | May return credential-adjacent data        | Restricted   |
| `Reveal`          | Returns plaintext secret values            | Never        |

The MCP server hard-codes a list of `Safe` operations only. The enclave
enforces safety-class restrictions independently, providing defense-in-depth.

### IPC Protocol

All communication between clients (CLI, MCP server) and the daemon uses
Unix domain sockets with length-delimited framing:

1. Client connects to `~/.opaque/opaqued.sock`
2. Client sends a handshake frame with a daemon token (prevents cross-user
   socket hijacking)
3. Request/response pairs use `LengthDelimitedCodec` with a 128 KB max
   frame size
4. Frames carry JSON-encoded `Request` and `Response` envelopes

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
- Use `opaque setup --seal` to lock the policy with a SHA-256 seal
- Daemon refuses to start if the config has been tampered with
- Team members use the same policy presets for consistency
- Bitwarden or 1Password team vaults provide shared secret references

**Trust model:** The team agrees on a policy. The config seal ensures that
local modifications are detected. Each developer still runs their own daemon.

### Tier 3: Organization / Centralized Policy (Roadmap)

**Scope:** Hundreds of developers with centrally managed policy.

Planned capabilities:

- Central policy server distributing signed policy bundles
- Audit log forwarding to a central SIEM
- Per-team policy namespaces
- Hardware-bound attestation for daemon identity
- FIDO2 / WebAuthn approval factors

## Security Properties

### What the Daemon Guarantees

1. **No bypass paths.** Every operation goes through `enclave.rs`. The type
   system prevents constructing a response without sanitization.

2. **Secret isolation.** Plaintext values exist only in `SecretValue` buffers
   that are zeroized on drop and optionally mlocked. They never appear in
   audit logs, error messages, or client responses.

3. **Client authentication.** Unix peer credentials are verified for every
   connection. Executable identity (path, hash, Team ID) enables fine-grained
   policy rules.

4. **Tamper detection.** The config seal catches unauthorized policy changes
   before the daemon processes any requests.

5. **Audit completeness.** Every request, policy decision, approval event,
   and operation outcome is logged with timestamps and correlation IDs.

### What the Daemon Does Not Guarantee

- **Network-level encryption** between daemon and provider APIs relies on
  TLS. The daemon validates URL schemes (HTTPS required, HTTP only for
  localhost).

- **Host compromise.** If the host OS is compromised, all bets are off.
  Opaque assumes a trusted local environment.

- **Provider-side security.** Opaque cannot prevent the provider (GitHub,
  1Password, etc.) from being compromised independently.

## Roadmap

### Phase 1 (Current)

- macOS and Linux support
- GitHub, GitLab, 1Password, Bitwarden, Vault providers
- MCP server for Claude Code
- Policy presets and config seal
- Structured audit logging
- Agent session wrapping

### Phase 2 (Near-term)

- Cross-compiled release binaries (macOS x86_64/aarch64, Linux x86_64/aarch64)
- Release CI with checksums and GitHub Releases
- Vault dynamic secrets with full lease lifecycle
- Additional policy presets

### Phase 3 (Future)

- Central policy distribution
- Audit log forwarding
- iOS / FaceID mobile approvals
- FIDO2 / WebAuthn approval factors
