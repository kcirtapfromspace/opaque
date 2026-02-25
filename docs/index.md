---
hide:
  - navigation
---

# Opaque

**Local approval-gated secrets broker for AI coding tools.**

LLMs get **operations** (e.g., "set this GitHub secret"), never plaintext values. Every operation passes through:

**Policy &rarr; Approval &rarr; Execute &rarr; Sanitize &rarr; Audit**

<div class="grid cards" markdown>

- [:material-rocket-launch: **Getting Started**](getting-started.md) -- Install and run your first operation in minutes
- [:material-shield-check: **Policy Engine**](policy.md) -- Deny-by-default rules, presets, and allowlists
- [:material-connection: **MCP Integration**](mcp-integration.md) -- Connect Opaque to Claude Code via MCP
- [:material-sitemap: **Architecture**](architecture.md) -- Design notes and system overview

</div>

---

## Features

- **Deny-by-default policy engine** with allowlist rules
- **Client identity** from Unix peer creds + executable identity (path/hash, optional macOS Team ID)
- **Operation-bound native OS approvals** (macOS Touch ID, Linux polkit)
- **Typestate-enforced response sanitization** + secret-pattern scrubbing
- **Structured audit events** (SQLite) with correlation IDs
- **MCP server** for Claude Code integration
- **Providers**: GitHub secrets, GitLab CI variables, 1Password, Bitwarden Secrets Manager, HashiCorp Vault, AWS Secrets Manager
- **Policy presets** for common workflows

## Install

=== "macOS (Homebrew)"

    ```sh
    brew install kcirtapfromspace/tap/opaque
    ```

=== "Linux / macOS (shell script)"

    ```sh
    curl -sSfL https://raw.githubusercontent.com/kcirtapfromspace/opaque/main/install.sh | sh
    ```

=== "From Source"

    ```sh
    cargo install --git https://github.com/kcirtapfromspace/opaque.git opaque opaqued opaque-mcp
    ```

| Binary | Role |
|--------|------|
| `opaqued` | Trusted daemon (enclave, policy, approvals, audit) |
| `opaque` | CLI client |
| `opaque-mcp` | MCP server for Claude Code |

## Quick Start (Claude Code)

```bash
# 1. Initialize with a preset
opaque init --preset github-secrets

# 2. Start the daemon
opaqued

# 3. Add to your Claude Code MCP config
#    { "mcpServers": { "opaque": { "command": "/path/to/opaque-mcp" } } }

# 4. Ask Claude Code to sync a secret:
#    "Set the GitHub Actions secret API_KEY for myorg/myrepo using my keychain"
```

See the [full getting-started guide](getting-started.md) for CLI and Codex workflows.

## Demos

### Enclave Quickstart

![quickstart demo](https://raw.githubusercontent.com/kcirtapfromspace/opaque/main/assets/demos/quickstart.gif)

### Sandboxed Exec

![sandbox exec demo](https://raw.githubusercontent.com/kcirtapfromspace/opaque/main/assets/demos/sandbox-exec.gif)

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| macOS | Apple Silicon (aarch64) | Fully supported |
| macOS | Intel (x86_64) | Fully supported |
| Linux | x86_64 | Fully supported |
| Linux | aarch64 | Fully supported |

## License

**Business Source License 1.1** (BSL 1.1). Free for individuals, non-commercial use, and organizations with fewer than 10 developers. See [LICENSE](https://github.com/kcirtapfromspace/opaque/blob/main/LICENSE) for details.
