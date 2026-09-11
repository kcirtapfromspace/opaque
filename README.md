# Opaque

![CI](https://github.com/kcirtapfromspace/opaque/actions/workflows/ci.yml/badge.svg)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange.svg)](LICENSE)
![Release](https://img.shields.io/github/v/release/kcirtapfromspace/opaque)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue)

### Secrets stay ███████. Agents stay powerful.

### Approve the work. Keep authority bounded.

Opaque lets a team give an AI coding agent (Codex, Claude Code, etc) a
**bounded piece of work**: publish a secret, dispatch a release, run a
fixed host check, read scoped application data. You approve exactly what it
may do and inspect the evidence after. LLMs get **operations**, never
plaintext secret values.

## What It Does

Every operation passes through:

**Policy -> Approval -> Execute -> Sanitize -> Audit**

Multi-step work adds **plan -> review -> approve -> run -> inspect**. See
[bounded agent work](docs/bounded-work.md).

New here? The [15-minute tutorial](docs/tutorial.md) takes you from install to a
secret your agent moved but never saw, with verifiable broker audit records.

## Who It's For

Platform and security teams whose developers already use AI coding
agents. Today those teams either keep sensitive access away from the agent
or watch its every move. Start on one laptop; one signed policy governs a
fleet.

- **Security and platform leads** own policy and custody: what agents may
  touch, which operations need a human, and an evidence trail an auditor
  or SIEM can verify.
- **Developers** hand the agent real work, approve the exact scope once,
  and read the receipt.
- **The agent** (Claude Code, Codex, any MCP client) finishes the task with
  credentialed operations while provider credentials remain in broker custody.
  Allowed data results and agent-owned credentials still need their own controls.

Opaque is not another secrets manager or agent framework. It sits in front
of GitHub, GitLab, 1Password, Bitwarden, Vault, and AWS, decides what may
pass, and records observed execution outcomes.

## Features

- Deny-by-default policy engine with allowlist rules
- **Bounded agent work**: a pinned task manifest (publish a secret, dispatch a release, run a fixed SSH host check, read scoped data) approved once as a whole, each action charging exactly one slot, with a receipt (`opaque task plan|run|show|reconcile|revoke`, see `docs/bounded-work.md`)
- **Trust-domain enforcement**: run the daemon as a dedicated service account (or separate container) that exclusively owns every key, database, and config; startup verifies custody and fails closed, turning tamper-evidence into tamper-prevention (`docs/deployment.md`)
- **Signature-bound approvals**: a pluggable factor registry with macOS Touch ID / Linux polkit, a paired second device (Ed25519, decision-bound signatures), FIDO2 hardware keys and passkeys (challenge-bound, verified daemon-side), and a trusted-workstation full-manifest reviewer for tasks; the audit chain records *who* approved, cryptographically
- Identity substrate: daemon-owned OIDC login (PKCE), on-behalf-of delegation tokens, live-resolved roles, segregation of duties
- Authenticated audit records and head (SQLite), plus portable signed checkpoints and independent verification with `opaque-evidence`; see [evidence checkpoints](docs/evidence-checkpoints.md) for coverage, freshness and legacy upgrade requirements
- Signed MCP registry v2 with separate upstream/admitted schemas and bounded integer/status result projection; see [tool qualification](docs/mcp-qualified-tools.md)
- Sandboxed execution: bubblewrap + Landlock + seccomp applied to every exec child; typestate-enforced response sanitization + secret-pattern scrubbing
- Client identity from Unix peer creds + executable identity (path/hash, optional macOS Team ID)
- **Federation**: one org signature carries policy to a whole fleet (`opqb1` bundles, verified before parsing, with anti-rollback and substitution refusal enforced from custody); the audit chain exports to SIEM over spool/webhook/TLS syslog carrying each record's sequence number and hash; daemons produce signed posture attestations and can be required to prove posture before receiving key material (`docs/federation.md`)
- MCP server for Claude Code integration
- Providers: GitHub secrets, GitLab CI variables, 1Password, Bitwarden Secrets Manager, HashiCorp Vault, AWS Secrets Manager
- Policy presets for common workflows; deploy templates for systemd, launchd, docker-compose, and Kubernetes (`deploy/`)

## Install

The reviewer app, MCP registry v2 and `opaque-evidence` are unreleased source
capabilities. Tagged downloads and Homebrew install the published release; they
may not contain these additions. Build this checkout to validate them. Before
upgrading an existing audit store, follow the [explicit legacy transition](docs/evidence-checkpoints.md#authenticated-local-head-and-older-databases).

### macOS (Homebrew)

```sh
brew install kcirtapfromspace/tap/opaque
```

### Linux / macOS (shell script)

```sh
curl -sSfL https://raw.githubusercontent.com/kcirtapfromspace/opaque/main/install.sh | sh
```

### From Source

```sh
cargo install --locked --git https://github.com/kcirtapfromspace/opaque.git opaque opaqued opaque-mcp opaque-approve-helper opaque-approver opaque-web
```

Binaries:

| Binary | Role |
|--------|------|
| `opaqued` | Trusted daemon (enclave, policy, approvals, audit) |
| `opaque` | CLI client |
| `opaque-mcp` | MCP server for Claude Code |
| `opaque-mcp-contract` | Source-built offline registry qualification (`cargo build --locked -p opaque-mcp --bin opaque-mcp-contract`) |
| `opaque-approve-helper` | Native review helper |
| `opaque-approver` | Trusted workstation enrollment and whole-task review (macOS approval) |
| `opaque-evidence` | Offline checkpoint producer and evidence verifier (included in the `opaque` package) |
| `opaque-web` | Local dashboard |

The [macOS reviewer guide](crates/opaque-approver/README.md) covers the separate
app bundle, trusted enrollment and release qualification. The shell installer
installs CLI tools only; a Homebrew release containing the app preserves it at
`$(brew --prefix opaque)/Opaque Reviewer.app` without enrolling a broker.
Source commands targeting Git use its default branch; for an unmerged change,
check out its reviewed commit and run `cargo build --locked` there.

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| macOS | Apple Silicon (aarch64) | Fully supported |
| macOS | Intel (x86_64) | Fully supported |
| Linux | x86_64 | Fully supported |
| Linux | aarch64 | Fully supported |

## Quickstart: Claude Code (MCP)

1. Initialize with a preset:
   ```bash
   opaque init --preset github-secrets
   ```

2. Start the daemon:
   ```bash
   opaqued
   # Or install as a service: opaque service install
   ```

3. Add to your Claude Code MCP config:
   ```json
   {
     "mcpServers": {
       "opaque": {
         "command": "/path/to/opaque-mcp"
       }
     }
   }
   ```

4. Ask Claude Code to sync a secret:
   > "Set the GitHub Actions secret API_KEY for myorg/myrepo using my keychain"

Full MCP docs: [MCP integration](docs/mcp-integration.md)

## Quickstart: Codex / CLI

1. Initialize with a preset:
   ```bash
   opaque init --preset github-secrets
   ```

2. Start the daemon:
   ```bash
   opaqued
   ```

3. Test connectivity:
   ```bash
   opaque ping
   opaque execute test.noop
   ```

Optional: run your agent through Opaque wrapper mode (session-scoped):

```bash
opaque agent run -- codex
```

4. Sync a GitHub secret:
   ```bash
   opaque github set-secret \
     --repo myorg/myrepo \
     --secret-name API_KEY \
     --value-ref keychain:opaque/api-key
   ```

   Sync a GitLab CI variable:
   ```bash
   opaque gitlab set-ci-variable \
     --project mygroup/myproject \
     --key API_KEY \
     --value-ref keychain:opaque/api-key
   ```

5. Build a refs-only manifest from `.env.example` and publish through Opaque:
   ```bash
   opaque github build-manifest \
     --env-file .env.example \
     --value-ref-template 'bitwarden:production/{name}' \
     --out .opaque/env-manifest.json
   ```

   Manually edit `.opaque/env-manifest.json` if any refs need adjustment, then publish:
   ```bash
   opaque github publish-manifest \
     --repo myorg/myrepo \
     --manifest-file .opaque/env-manifest.json
   ```

6. Review the audit log:
   ```bash
   opaque audit tail --limit 10
   opaque audit tail --query github --limit 10
   ```

Full CLI docs: [Getting started](docs/getting-started.md)

## Policy Presets

Get started quickly with built-in presets:

```bash
opaque policy presets                        # list available presets
opaque init --preset safe-demo               # test.noop only (safe to experiment)
opaque init --preset github-secrets          # GitHub secret sync for agents
opaque init --preset gitlab-variables        # GitLab CI variable sync for agents
opaque init --preset sandbox-human           # sandbox exec for humans only
opaque init --preset agent-wrapper-github    # wrapped-agent GitHub sync with session enforcement
```

Or apply a preset to an existing config:

```bash
opaque policy preset github-secrets
```

## Demos

### Enclave Quickstart (Init, Policy, Daemon, Execute, Audit)

![quickstart demo](assets/demos/quickstart.gif)

### Sandboxed Exec (Captured stdout/stderr)

![sandbox exec demo](assets/demos/sandbox-exec.gif)

## Docs

- [Try the portfolio demo](https://demo.opaque.info/): explore synthetic application metrics and scoped analyst, engineer and support views.

- [Docs index](docs/README.md)
- [Tutorial: your first gated operation](docs/tutorial.md)
- [Getting started](docs/getting-started.md)
- [Bounded agent work](docs/bounded-work.md)
- [Identity](docs/identity.md)
- [MCP integration](docs/mcp-integration.md)
- [Qualifying MCP tools](docs/mcp-qualified-tools.md)
- [Trusted reviewer](docs/remote-approvals.md)
- [Evidence checkpoints and audit upgrades](docs/evidence-checkpoints.md)
- [Bitwarden setup](docs/bitwarden.md)
- [Vault setup](docs/vault.md)
- [Federation](docs/federation.md)
- [Policy](docs/policy.md)
- [Operations](docs/operations.md)
- [LLM harness](docs/llm-harness.md)
- [Demos](docs/demos.md)
- [Deployment](docs/deployment.md)
- [Security assessment](docs/security-assessment.md)
- [Deferred roadmap](docs/roadmap-deferred.md)

## Deferred

See [Deferred roadmap](docs/roadmap-deferred.md). Notably:

- iOS second-device approvals / Face ID
- A general-purpose tenant operator and hardware attestation

## License

Business Source License 1.1 (BUSL-1.1). See [LICENSE](LICENSE).

## Building on core

Opaque applications consume public libraries and protocols. See [reusable core](docs/reusable-core.md) and the [independent library consumer](examples/embedded-policy/README.md) for supported integration boundaries. Organization management and deployment automation are separately packaged; local core requires no private component.
