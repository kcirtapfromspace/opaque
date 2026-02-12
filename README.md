# AgentPass (WIP)

Approval-gated secrets broker for AI coding tools (Claude Code, Codex, etc).

## Problem
AI coding agents often need API keys, tokens, and passwords to run tests, call SaaS APIs, or push CI/CD configuration. If you paste secrets into prompts or let the agent print them, you risk disclosure and long-lived credential leakage.

## Goal
Provide a local "secrets broker" that:

- Requires proof-of-life + explicit approval before a new secret is used (FIDO2/security key, local biometrics, or second-device FaceID/TouchID).
- Integrates with secret sources (1Password, HashiCorp Vault, etc).
- Brokers secrets into:
  - local environments (process execution) and
  - SaaS providers (GitHub/GitLab secret stores),
  without exposing plaintext secrets to the LLM.

## Docs
- Architecture: `docs/architecture.md`
- LLM harness: `docs/llm-harness.md`
- Mobile approvals: `docs/mobile-approvals.md`
- Storage model: `docs/storage.md`
- Audit & analytics: `docs/audit-analytics.md`
