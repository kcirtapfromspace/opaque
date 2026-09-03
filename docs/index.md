---
template: home.html
hide:
  - navigation
  - toc
---

# Opaque

**Secrets stay secret. Agents stay powerful.**

A local, approval-gated secrets broker for AI coding agents. LLMs get
operations, never plaintext values. Every operation passes through
Policy → Approval → Execute → Sanitize → Audit.

- **Trust-domain enforcement** — run the daemon under a dedicated service
  account or separate container that exclusively owns every key, database,
  and config; startup fails closed on any custody violation.
- **Signature-bound approvals** — local biometric (Touch ID, polkit), paired
  second device (Ed25519), FIDO2 hardware keys and passkeys, verified
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
[policy engine](policy.md), [MCP integration](mcp-integration.md),
[identity](identity.md), [deployment](deployment.md),
[federation](federation.md), and [architecture](architecture.md).
