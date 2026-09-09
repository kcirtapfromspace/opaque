# Architecture

Opaque lets a team give an agent a bounded piece of work, keep control while
it runs, and inspect the evidence after. Every capability — secrets,
identity, policy, certificates, receipts — serves one progression:

**Policy → Approval → Execute → Sanitize → Audit**, and for multi-step work,
**plan → review → approve → run → inspect** (see [bounded work](bounded-work.md)).

LLMs get **operations**, never plaintext secret values. Nothing a local
client process claims about itself is trusted, since an agent can drive the
same `opaque` CLI a human does.

## 1. Design goals

- No plaintext secret disclosure to LLM context: not in prompts, tool
  output, or logs.
- Presence, not classification: authority comes from an out-of-band approval
  act, not from guessing whether a process is "the human" or "the agent."
- Custody, not just correctness: once [trust-domain enforcement](deployment.md)
  is on, the daemon's keys, database, and config belong to an identity the
  agent's uid cannot touch.
- Tamper-evidence over the whole record: every audit event HMAC-chains;
  federated fleets export that chain to a SIEM in independently verifiable form.
- Bounded, inspectable work: a multi-step task is a pinned manifest approved
  once, each action charging one slot, with a receipt — not an open-ended
  credential handed to the agent.

## 2. Threat model

An agent with arbitrary commands and unconstrained egress can exfiltrate
anything it can read. Opaque doesn't claim otherwise. What it does claim:

1. **Accidental disclosure is prevented by construction.** No operation
   returns a plaintext secret to a CLI/MCP/web client (`REVEAL` doesn't
   exist); typestate in `opaque-core` makes an unsanitized response a
   compile error, not a runtime check someone can forget.
2. **A malicious agent runtime is resisted, not just an honest one.** The
   daemon executes secret-using operations itself. Client classification
   (human vs. agent) is audit-only, never a security gate — an agent can
   present the same executable path and peer credentials a human's terminal
   does. Sandboxed exec (Landlock/seccomp on Linux, Seatbelt on macOS)
   bounds an agent-driven command when exec mode is used at all.
3. **A compromised daemon-uid process is bounded by trust-domain
   separation**, not by this codebase alone — see [deployment](deployment.md).

## 3. Crates

`opaqued`'s original ~65k-line monolith is now a ~23k-line composition root
over focused crates. Each crate owns one concern; `opaqued` wires them
together and runs the RPC dispatch loop.

| Crate | Owns |
|---|---|
| `opaque-core` | Shared types: policy engine, operation/audit/proto, task manifests, tenant bindings, sealing, socket hygiene |
| `opaqued` | Composition root: enclave, RPC dispatch, identity store, provisioning API, agent sessions |
| `opaque-providers` | GitHub, GitLab, 1Password, Bitwarden, Vault, AWS. GCP/Azure/Doppler/Infisical are Cargo features `opaqued` enables by default, so all ten still ship in the daemon binary today |
| `opaque-approval` | Device pairing, FIDO2, factor registry, native prompting, approval-server relay |
| `opaque-native-approval` | Native review/auth shared by the daemon and the workstation approver |
| `opaque-approve-helper` | Linux polkit review helper |
| `opaque-approver` | Trusted paired-workstation full-manifest approver — a separate binary for a separate machine (`crates/opaque-approver/README.md`) |
| `opaque-sandbox` | Landlock/seccomp/Seatbelt isolation, execve hooks, composite secret-resolver dispatch |
| `opaque-bounded-work` | The [task](bounded-work.md) ledger, SSH certificate execution, inference brokering |
| `opaque-tenant` | Tenant custody boundary, delegated IdP provisioning types |
| `opaque-federation-runtime` | [Federation](federation.md): signed policy bundles, SIEM export, posture attestation |
| `opaque-mcp` | MCP server for Claude Code and other MCP clients |
| `opaque-web` | Read-only local dashboard |
| `opaque` | CLI client |
| `opaque-showcase` | Demo/sales collateral (chat + metrics gateway). Excluded from `default-members`, so it never compiles into a plain build or release binary |

```mermaid
flowchart LR
  Agent["LLM tool (Codex / Claude Code)"] -->|requests operation| MCP["opaque-mcp"]
  CLI["opaque (CLI)"] --> D
  MCP --> D["opaqued"]
  Web["opaque-web (read-only)"] -->|IPC + SQLite| D
  Human["Human"] -->|out-of-band approval| Approval["opaque-approval /<br/>opaque-approver"]
  Approval --> D

  D --> Providers["opaque-providers<br/>GitHub / GitLab / 1Password /<br/>Bitwarden / Vault / AWS"]
  D --> Sandbox["opaque-sandbox<br/>exec (optional)"]
  D --> BoundedWork["opaque-bounded-work<br/>task ledger / SSH / inference"]
  D --> Tenant["opaque-tenant"]
  D --> Federation["opaque-federation-runtime"]
```

## 4. Trust boundaries

- **Trusted:** `opaqued`, the approval factor(s) and pairing/workstation
  keys, configured provider credentials, the audit chain's HMAC key.
- **Same-uid, tamper-evident not tamper-proof, until trust-domain
  enforcement is on:** by default the daemon's DB and config live at the
  agent's own uid, so a compromised agent account can read the HMAC key or
  rewrite the DB. `opaque audit verify` and startup verification detect
  this; they don't prevent it. A dedicated service account or separate
  container turns it into a hard guarantee — see [deployment](deployment.md).
- **Untrusted:** the LLM and its tool runtime, arbitrary agent-run commands,
  dependencies pulled in at run time.

## 5. Identity and policy

Client identity is derived, never self-declared: Unix socket peer
credentials (uid/gid/pid) plus executable path and SHA-256. (macOS Team-ID
matching exists in policy but nothing populates it from a real code-signature
check yet — treat it as inert.) Client type classification is **audit-only**
— it never gates a decision, since an agent drives the same CLI a human does.

Real authority comes from [identity](identity.md): a verified human (OIDC
login, daemon-owned), an agent workload, or a config-declared service
principal, with roles resolved live at request time — never embedded in a
token, so revocation is immediate. Delegated access is the intersection of
what the agent session and the delegating human may do.

Policy rules match `client_id` × `operation` × `target`:

```toml
[[rules]]
name = "mcp-github-only"
client_id = "opaque-mcp"
operation_pattern = "github.*"
target_pattern = "org/acme-*"
allow = true
```

See [policy](policy.md) for the full rule and preset reference.

## 6. Approval

Approval is required on first use of a (client, operation, target) tuple, on
policy-flagged high-risk actions, and after lease expiry. The factor
registry is pluggable and challenge-bound:

- **Local biometric** — macOS Touch ID; Linux polkit with a pre-auth intent
  dialog (`zenity`/`kdialog`) shown before the OS prompt.
- **Paired second device** — Ed25519, decision-bound signatures.
- **FIDO2** — hardware keys and passkeys, verified daemon-side.
- **Paired workstation** — a separate machine reviews the entire task
  manifest and signs a decision; see [bounded work](bounded-work.md) and
  `crates/opaque-approver/README.md`.

No interactive session or configured factor reachable (headless, no
display, no paired device) fails closed — never an unapproved fallback. See
[deployment](deployment.md) for platform session-detection requirements.

## 7. Sandboxed execution

`opaque exec` is the compatibility path for humans running existing dev
tools with secrets injected as env vars — not a hard guarantee if the agent
picks the command. `opaque-sandbox` applies Landlock + seccomp (Linux) or
Seatbelt (macOS) to every exec child; typestate sanitization and
secret-pattern scrubbing apply regardless of sandbox mode.

Agent-safe operations are preferred over exec: the daemon performs the
privileged call itself (`github.set_actions_secret`, `task_run`, …) and
returns a sanitized result, so the secret never enters the agent's process.

## 8. Bounded agent work

Beyond a single operation, Opaque hands the agent a **task**: an immutable
manifest approved once as a whole, each action charging one slot exactly
once. Three operation families today: repository/release work,
application-evidence reads, host operations over signed SSH certs. See
[bounded work](bounded-work.md) for the manifest, CLI, lifecycle, and what's
production-ready versus fixture-validated.

## 9. Federation

One org signature carries policy to a fleet (`opqb1` bundles, verified
before parsing, anti-rollback from custody). Each daemon exports its audit
chain to a SIEM in independently verifiable form, and can produce signed
posture attestations and require verified posture before releasing key
material. See [federation](federation.md).

## 10. Audit

Every operation — approval requested/granted/denied and by which factor,
executed and its target/status, provider fetches (metadata only, never
values) — is an append-only, HMAC-chained SQLite row. `opaque audit verify`
detects edits, reordering, deletion, or tail truncation; the daemon
re-verifies at startup and raises a CRITICAL alert on break. SIEM export
(spool, webhook, TLS syslog) carries each record's sequence number and hash,
so the exported stream verifies independently against the source database.

## 11. Providers

GitHub Actions/Codespaces secrets, GitLab CI variables, 1Password, Bitwarden
Secrets Manager, HashiCorp Vault, AWS Secrets Manager. GCP, Azure, Doppler,
and Infisical are feature-gated in `opaque-providers`, but `opaqued` enables
all four anyway — so today's shipped binary compiles in all ten regardless.

## 12. Platforms

| Platform | Architecture | Status |
|---|---|---|
| macOS | Apple Silicon (aarch64), Intel (x86_64) | Fully supported |
| Linux | x86_64, aarch64 | Fully supported |

macOS runs the daemon as a LaunchAgent in a GUI session (never a
LaunchDaemon — native approval prompts require it); Linux runs it as a
systemd user service in a graphical session with a polkit auth agent. See
[deployment](deployment.md).

## Deferred

iOS second-device approvals (FaceID) and a general-purpose interactive
tenant runtime remain out of scope for now — see the
[deferred roadmap](roadmap-deferred.md).
