# MCP Integration

Opaque ships an MCP server (`opaque-mcp`) that exposes Safe operations as tools for Claude Code and other MCP-aware AI assistants.

## Architecture

```
Claude Code  --MCP/stdio-->  opaque-mcp  --Unix socket-->  opaqued (enclave)
```

`opaque-mcp` is a thin protocol adapter. It translates MCP JSON-RPC messages into Opaque IPC requests and forwards them to the daemon over the Unix socket. All policy enforcement, approval gating, and audit logging happen inside `opaqued`; the MCP server has no special privileges.

The adapter validates tool arguments against its published schemas and admits up to eight concurrent tool calls. Ping, tool listing, and cancellation remain responsive while calls wait on the broker. Cancellation stops waiting and closes that call's IPC connection; it does not promise to undo work already dispatched. Broker status and task receipt reads have a 30-second deadline, ordinary operations and sandbox execution five minutes, and bounded task execution 61 minutes. A timeout after dispatch reports an uncertain outcome and never triggers an automatic replay.

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

Signed third-party tool routes are covered in [qualifying one MCP tool](mcp-qualified-tools.md).
That guide explains separate upstream/admitted schemas, offline catalog qualification,
bounded typed result disclosure, current authority checks and the supported transport.

The MCP server exposes `SAFE` operations normally. It also exposes sandbox
execution (`SENSITIVE_OUTPUT`) with its output content withheld from the
model; see [Sandbox](#sandbox) below. Operations classified as `REVEAL`
(they return plaintext secret values) are never exposed.

### Bounded Tasks

An immutable, fully-reviewed manifest (publish a secret, dispatch a
release, run a fixed host check, or run scoped inference), approved once and
executed once. See [bounded agent work](bounded-work.md) for the full
lifecycle.

| Tool | Daemon method | Description |
|------|-----------|-------------|
| `opaque_task_plan_ssh` | `task_plan_ssh` | Plan one fixed SSH host-health check on the tenant's trusted host/command profile |
| `opaque_task_plan_inference` | `task_plan_inference` | Plan three fixed public-source completions in the authenticated tenant |
| `opaque_task_plan` | `task_plan` | Plan a secret-publish or staging-release manifest for review |
| `opaque_task_run` | `task_run` | Request trusted approval and execute a planned task's actions once |
| `opaque_task_get` | `task_get` | Inspect a task's exact scope, approval state, and receipt (maps to `opaque task show` in the CLI) |
| `opaque_task_list` | `task_list` | List a page of tasks owned by the authenticated caller |
| `opaque_task_revoke` | `task_revoke` | Block future provider actions on a task; already-dispatched work may still complete |
| `opaque_task_reconcile` | `task_reconcile` | Re-read correlated provider evidence without re-dispatching |

### GitHub

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_github_set_actions_secret` | `github.set_actions_secret` | Set a repo or environment Actions secret |
| `opaque_github_set_codespaces_secret` | `github.set_codespaces_secret` | Set a user or repo Codespaces secret |
| `opaque_github_set_dependabot_secret` | `github.set_dependabot_secret` | Set a Dependabot repo secret |
| `opaque_github_set_org_secret` | `github.set_org_secret` | Set an org-level Actions secret |
| `opaque_github_list_secrets` | `github.list_secrets` | List secret names (no values) |
| `opaque_github_delete_secret` | `github.delete_secret` | Delete a secret |

### GitLab

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_gitlab_set_ci_variable` | `gitlab.set_ci_variable` | Set a project CI/CD variable (write-only) |

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

### Sandbox

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_sandbox_exec` | `sandbox.exec` | Run a command in the sandbox with profile-scoped secrets injected |
| `opaque_sandbox_list_profiles` | *(client-side)* | List available `~/.opaque/profiles/*.toml` names; reads local files directly, never calls the daemon |

`sandbox.exec` is `SENSITIVE_OUTPUT` and still needs an explicit policy rule
for `agent` clients. It's safe to expose because the model sees only exit
code and stdout/stderr **byte lengths**, never content. The CLI path
(`opaque exec`) differs: it prints raw output to the terminal; treat that
as sensitive, per [LLM harness](llm-harness.md).

### Utility

| Tool | Operation | Description |
|------|-----------|-------------|
| `opaque_secrets_status` | *(client-side)* | List a profile's secret ref names and schemes (never resolves values); reads the profile TOML directly, never calls the daemon |

### Not Exposed

These operations are intentionally excluded from MCP entirely:

- `onepassword.read_field`: `REVEAL` (returns plaintext secret values)
- `bitwarden.read_secret`: `REVEAL` (returns plaintext secret values)
- `test.noop`: test-only, not useful for agents

## Safety Model

1. **Defense in depth**: The MCP tool list is hard-coded in the `opaque-mcp` binary. Even if a client requests an unlisted tool, the MCP server will reject it before it reaches the daemon.

2. **Daemon enforcement**: Every tool call that reaches the daemon passes through `Enclave::execute()` in `opaqued`. Policy, approval, and audit apply regardless of CLI vs. MCP. (`opaque_sandbox_list_profiles` and `opaque_secrets_status` are client-side only; they read local profile files and never reach the daemon.)

3. **No secret values in responses**: MCP tool results are sanitized by the daemon; `REVEAL` operations are never listed. `opaque_sandbox_exec` additionally withholds output content, returning only length metadata.

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
