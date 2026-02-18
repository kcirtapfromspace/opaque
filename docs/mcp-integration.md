# MCP Integration

Opaque ships an MCP server (`opaque-mcp`) that exposes Safe operations as tools for Claude Code and other MCP-aware AI assistants.

## Architecture

```
Claude Code  --MCP/stdio-->  opaque-mcp  --Unix socket-->  opaqued (enclave)
```

`opaque-mcp` is a thin protocol adapter. It translates MCP JSON-RPC messages into Opaque IPC requests and forwards them to the daemon over the Unix socket. All policy enforcement, approval gating, and audit logging happen inside `opaqued` — the MCP server has no special privileges.

## Setup

### 1. Build

```bash
cargo build --release
```

Binaries:

- `./target/release/opaqued` (daemon)
- `./target/release/opaque` (CLI)
- `./target/release/opaque-mcp` (MCP server)

### 2. Configure Claude Code

Add to your Claude Code MCP settings (`~/.claude/claude_desktop_config.json` or project-level `.mcp.json`):

```json
{
  "mcpServers": {
    "opaque": {
      "command": "/path/to/opaque-mcp",
      "args": []
    }
  }
}
```

The MCP server communicates over stdio (stdin/stdout) and connects to the daemon via the standard Unix socket path.

### 3. Start the daemon

```bash
opaqued
```

Or use the service manager:

```bash
opaque service install
```

### 4. Verify

In Claude Code, ask: "List my GitHub secrets for owner/repo". If the policy allows `github.list_secrets`, Claude will call the `opaque_github_list_secrets` tool via MCP.

## Available Tools

The MCP server exposes only `SAFE` operations. Operations classified as `SENSITIVE_OUTPUT` or `REVEAL` are never exposed.

### GitHub

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_github_set_actions_secret` | `github.set_actions_secret` | Set a repo or environment Actions secret |
| `opaque_github_set_codespaces_secret` | `github.set_codespaces_secret` | Set a user or repo Codespaces secret |
| `opaque_github_set_dependabot_secret` | `github.set_dependabot_secret` | Set a Dependabot repo secret |
| `opaque_github_set_org_secret` | `github.set_org_secret` | Set an org-level Actions secret |
| `opaque_github_list_secrets` | `github.list_secrets` | List secret names (no values) |
| `opaque_github_delete_secret` | `github.delete_secret` | Delete a secret |

### 1Password

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_onepassword_list_vaults` | `onepassword.list_vaults` | List vault names and descriptions |
| `opaque_onepassword_list_items` | `onepassword.list_items` | List item titles in a vault |

### Bitwarden

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_bitwarden_list_projects` | `bitwarden.list_projects` | List Bitwarden projects |
| `opaque_bitwarden_list_secrets` | `bitwarden.list_secrets` | List secret names in a project |

### Not Exposed

These operations are intentionally excluded from MCP:

- `sandbox.exec` — `SENSITIVE_OUTPUT` (captured stdout/stderr may contain secrets)
- `onepassword.read_field` — `REVEAL` (returns plaintext secret values)
- `bitwarden.read_secret` — `REVEAL` (returns plaintext secret values)
- `test.noop` — test-only, not useful for agents

## Safety Model

1. **Defense in depth**: The MCP tool list is hard-coded in the `opaque-mcp` binary. Even if a client requests an unlisted tool, the MCP server will reject it before it reaches the daemon.

2. **Daemon enforcement**: Every tool call passes through `Enclave::execute()` in `opaqued`. Policy rules, approval requirements, and audit logging all apply regardless of whether the request comes from CLI or MCP.

3. **No secret values in responses**: All MCP tool results are sanitized by the daemon. Secret values are never included in tool responses.

4. **Agent classification**: The MCP server connects as an `agent` client. Policy rules with `client_types = ["human"]` will not match MCP requests.

## Troubleshooting

### "Tool not found"

- Verify `opaque-mcp` is in your MCP config and the path is correct.
- Restart Claude Code after changing MCP config.

### "Connection failed"

- Check that `opaqued` is running: `opaque ping`
- Check the socket path: `ls $(opaque doctor 2>&1 | grep socket)`

### "Policy denied"

- The daemon denied the operation. Check your policy:
  ```bash
  opaque policy show
  opaque policy simulate --operation github.set_actions_secret --client-type agent
  ```
- Ensure your rules include `client_types = ["agent"]` (MCP requests are always classified as agent).

### "Approval required" but no prompt appears

- Approval prompts are shown by `opaqued` on the local machine (macOS Touch ID / Linux polkit). The MCP server cannot show prompts itself.
- Ensure you are at the machine where `opaqued` is running.

### Viewing MCP logs

`opaque-mcp` logs to stderr (stdout is reserved for the MCP transport). To capture logs:

```bash
RUST_LOG=debug opaque-mcp 2>/tmp/opaque-mcp.log
```

Or check the daemon audit log:

```bash
opaque audit tail --limit 20
```
