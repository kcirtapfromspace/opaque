# LLM Harness (v1): Use Secrets Without Disclosure

This doc defines how LLM tools (Codex, Claude Code, etc) should interact with Opaque so they can **use** secrets without ever receiving plaintext secret values.

## The Rule

LLMs get **operations**, not values.

- OK: "set GitHub Actions secret `JWT` for `org/repo` using ref `keychain:opaque/jwt`"
- Not OK: "print the JWT" / "show me the `.env` file" / "return the secret value"

## How The LLM Calls Opaque

### MCP (Preferred for Claude Code)

The recommended path for MCP-aware tools like Claude Code is the `opaque-mcp` server. It exposes Safe operations as MCP tools over stdio, so the LLM calls Opaque tools natively without shell access.

See [MCP integration](mcp-integration.md) for setup.

### CLI Harness (Fallback)

For tools without MCP support (e.g., Codex), the agent runs `opaque ...` CLI commands directly:

- the agent runs `opaque ...` commands
- the daemon (`opaqued`) enforces policy, triggers approvals, executes the operation, sanitizes results, and emits audit events

Both paths go through the same daemon and policy engine. The MCP server is a thin adapter over the same Unix socket IPC.

### Bounded Tasks (Multi-Step Work)

For more than one operation — publish a secret *and* dispatch its release,
or run a fixed host check — plan a single [bounded task](bounded-work.md)
instead of chaining calls: an immutable manifest, approved once, executed
once, with a receipt. MCP (`opaque_task_plan`, `opaque_task_run`, …) and the
CLI (`opaque task plan`, `opaque task run`, …) expose the same lifecycle.

For stronger local isolation, launch the agent via wrapper mode:

- `opaque agent run -- <agent-command ...>`

By default, the agent wrapper starts the child process with a **clean environment** containing only a baseline set of variables (`PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`, `LC_ALL`, `TMPDIR`, `XDG_RUNTIME_DIR`, `COLORTERM`, `SSH_AUTH_SOCK`) plus the `OPAQUE_*` session variables. This prevents secrets like `ANTHROPIC_API_KEY` or `DATABASE_URL` from leaking into the agent process.

To pass additional environment variables selectively:

```bash
opaque agent run --pass-env EDITOR --pass-env VISUAL -- <agent-command ...>
```

To inherit the full parent environment (opt-in):

```bash
opaque agent run --inherit-env -- <agent-command ...>
```

This injects a session token used by Opaque handshakes. If `enforce_agent_sessions = true` is enabled in daemon config, non-session agent calls are rejected.

## Secret Inputs: Refs, Not Values

Operations accept **secret references** (refs), not raw values.

Examples:

- `keychain:opaque/github-pat`
- `env:MY_SECRET` (daemon reads from its own environment, not the agent's)
- `profile:<name>:<key>` (profile indirection; recommended for agent workflows)
- `bitwarden:<secret-id>` or `bitwarden:<project>/<key>` (Bitwarden Secrets Manager)

Opaque should reject raw secret literals for operations that write secrets to providers.

## Profiles: Make Agent Workflows Safer

Instead of giving the agent a pile of refs each run, keep them in a profile:

```toml
[secrets]
GITHUB_TOKEN = "keychain:opaque/github-token"
```

Then the agent can request:

- "run sandbox exec with profile `dev`"

The CLI never sees the resolved secret values *directly*, but secrets can still leak if a sandboxed command prints them (see note under sandbox exec below).

## Approvals

Approvals are operation-bound, triggered as part of execution. An LLM tool
call can request an operation but can't satisfy any factor itself — each
completes on hardware or a channel the agent doesn't control.

Implemented factors (see [Policy](policy.md#approval-configuration)):

- `local_bio`: native OS prompt (macOS LocalAuthentication, Linux polkit)
- `fido2`: hardware security key or passkey (FIDO2/WebAuthn)
- `paired_workstation`: full-manifest review by an enrolled trusted
  workstation — used for bounded task approval
- `ios_faceid`: paired second-device approval (Ed25519). Despite the wire
  name, this ships as desktop-to-desktop pairing, not an iOS app — see
  [mobile approvals](mobile-approvals.md)

## Handling Common Requests Safely

### "Sync my .env to GitHub"

Do not have the agent open a plaintext `.env` containing real values.

Prefer:

- `.env.example` (names only)
- a profile mapping (names -> refs)
- provider-side fetch via refs

Then call:

- `github.set_actions_secret(repo, secret_name, value_ref)` (repo or env Actions secrets)
- `github.set_codespaces_secret(secret_name, value_ref, ...)`
- `github.set_dependabot_secret(repo, secret_name, value_ref)`
- `github.set_org_secret(org, secret_name, value_ref, ...)`

CLI batching workflow (still routes through Opaque per secret):

- `opaque github build-manifest --env-file .env.example --value-ref-template 'bitwarden:production/{name}' --out .opaque/env-manifest.json`
- Review/update `.opaque/env-manifest.json` manually (refs only; no plaintext secrets).
- `opaque github publish-manifest --repo <owner/repo> --manifest-file .opaque/env-manifest.json`
- Use `--dry-run` on `publish-manifest` to preview without publishing.

### "Run tests that need secrets"

Do not paste secrets into prompts or run `printenv` to verify them.

Use:

- `opaque exec --profile <name> -- <command...>` (CLI), or
- the `opaque_sandbox_exec` MCP tool (see [MCP integration](mcp-integration.md#sandbox))

Opaque injects secrets into the sandboxed process environment, but the two
paths differ downstream: the CLI prints raw stdout/stderr, so `opaque exec`
can leak anything a command prints — treat it as `SENSITIVE_OUTPUT` and
avoid commands that echo secrets. The MCP tool withholds output entirely,
returning only exit code and byte lengths.
