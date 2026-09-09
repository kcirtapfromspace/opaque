---
template: home.html
hide:
  - navigation
  - toc
---

# Opaque

**Secrets stay secret. Agents stay powerful.**
**Approve the work. Keep authority bounded.**

For platform and security teams — ten developers and up — whose teams
already use AI coding agents, and who today either withhold sensitive
access or supervise every action. Opaque lets you give an agent a bounded
piece of work — publish a secret, dispatch a release, run a fixed host
check, read scoped data — approve exactly what it's allowed to do, and
inspect the evidence after. LLMs get operations, never plaintext values.
Every operation passes through Policy → Approval → Execute → Sanitize →
Audit; multi-step work adds plan → review → approve → run → inspect.

Not a secrets manager, not an agent framework — the authorization and
evidence layer between the two you already have. Security owns policy and
custody; developers and agents finish the work.

- **Bounded agent work** — a pinned task manifest approved once as a whole;
  each action charges exactly one slot and leaves a receipt.
- **Trust-domain enforcement** — run the daemon under a dedicated service
  account or separate container that exclusively owns every key, database,
  and config; startup fails closed on any custody violation.
- **Signature-bound approvals** — local biometric (Touch ID, polkit), paired
  second device (Ed25519), FIDO2 hardware keys and passkeys, and a
  trusted-workstation full-manifest reviewer for tasks, all verified
  daemon-side.
- **Tamper-evident audit** — an HMAC hash chain in SQLite, verified with
  `opaque audit verify`.
- **Sandboxed execution** — bubblewrap, Landlock, and seccomp applied to exec
  children; typestate-enforced response sanitization.
- **Identity substrate** — OIDC human login (PKCE, daemon-owned), Ed25519
  delegation tokens, live role resolution, segregation of duties.
- **Federation** — one org signature carries policy to a whole fleet, with
  anti-rollback enforcement; the audit chain exports to your SIEM in a form it
  can verify; daemons prove their posture before receiving key material.
- **Providers** — GitHub Actions secrets, GitLab CI variables, 1Password,
  Bitwarden Secrets Manager, HashiCorp Vault, AWS Secrets Manager.

Install: `brew install kcirtapfromspace/tap/opaque`, the shell installer, or
`cargo install`. Licensed BUSL-1.1. New here? Start with the
[tutorial](tutorial.md). Then: [getting started](getting-started.md), the
[policy engine](policy.md), [bounded agent work](bounded-work.md),
[MCP integration](mcp-integration.md), [identity](identity.md),
[deployment](deployment.md), [federation](federation.md), and
[architecture](architecture.md).
