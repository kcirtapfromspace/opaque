# Opaque (WIP)

Local approval-gated secrets broker for AI coding tools (Codex, Claude Code, etc) that must not disclose plaintext secrets to LLM context.

## What v1 Includes

- Enclave enforcement funnel: policy -> approval -> execute -> sanitize -> audit
- Client identity from Unix peer creds (`uid/gid/pid`) + executable identity (path/hash, optional macOS Team ID)
- Deny-by-default policy engine with allowlist rules
- Modern terminal UI for the CLI (spinners, structured output, audit tables)
- Operation-bound native OS approvals:
  - macOS LocalAuthentication
  - Linux polkit (+ intent dialog)
- Typestate-enforced response sanitization + secret-pattern scrubbing
- Structured audit events (SQLite) with correlation IDs
- First provider: GitHub secrets sync (Actions repo/env, Codespaces user/repo, Dependabot, org)

## Deferred (Not In v1)

See `docs/roadmap-deferred.md`. Notably:

- MCP server exposure (v2)
- 1Password / HashiCorp Vault connectors (v2)
- iOS approvals / FaceID (v3)
- FIDO2 / WebAuthn approvals (v3)

## Quickstart (From Source)

```bash
cargo build --release

./target/release/opaque init

# Edit ~/.opaque/config.toml to add an allow rule (deny-all is the default).
./target/release/opaque policy check

./target/release/opaqued
```

In another terminal:

```bash
./target/release/opaque ping
./target/release/opaque execute test.noop
./target/release/opaque audit tail --limit 10
```

More details: `docs/getting-started.md`

## Demos

### Enclave Quickstart (Init, Policy, Daemon, Execute, Audit)

![quickstart demo](assets/demos/quickstart.gif)

### Sandboxed Exec (No stdout/stderr Returned)

![sandbox exec demo](assets/demos/sandbox-exec.gif)

## Docs

- Docs index: `docs/README.md`
- Getting started: `docs/getting-started.md`
- Demos: `docs/demos.md`
- Policy: `docs/policy.md`
- Operations: `docs/operations.md`
- LLM harness: `docs/llm-harness.md`
- Deployment: `docs/deployment.md`
- Security assessment: `docs/security-assessment.md`
- Deferred roadmap: `docs/roadmap-deferred.md`
