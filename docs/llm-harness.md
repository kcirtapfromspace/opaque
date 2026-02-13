# LLM Harness (v1): Use Secrets Without Disclosure

This doc defines how LLM tools (Codex, Claude Code, etc) should interact with Opaque so they can **use** secrets without ever receiving plaintext secret values.

## The Rule

LLMs get **operations**, not values.

- OK: "set GitHub Actions secret `JWT` for `org/repo` using ref `keychain:opaque/jwt`"
- Not OK: "print the JWT" / "show me the `.env` file" / "return the secret value"

## How The LLM Calls Opaque (v1)

v1 uses a CLI harness:

- the agent runs `opaque ...` commands
- the daemon (`opaqued`) enforces policy, triggers approvals, executes the operation, sanitizes results, and emits audit events

MCP server exposure is deferred (v2).

## Secret Inputs: Refs, Not Values

Operations accept **secret references** (refs), not raw values.

Examples:

- `keychain:opaque/github-pat`
- `env:MY_SECRET` (daemon reads from its own environment, not the agent's)
- `profile:<name>:<key>` (profile indirection; recommended for agent workflows)

Opaque should reject raw secret literals for operations that write secrets to providers.

## Profiles: Make Agent Workflows Safer

Instead of giving the agent a pile of refs each run, keep them in a profile:

```toml
[secrets]
GITHUB_TOKEN = "keychain:opaque/github-token"
```

Then the agent can request:

- "run sandbox exec with profile `dev`"

The CLI never sees the resolved secret values.

## Approvals

Approvals are operation-bound and are triggered as part of execution.

v1 implemented factor:

- `local_bio`: native OS prompt (macOS LocalAuthentication, Linux polkit)

Deferred (do not build in v1):

- `ios_faceid` (v3)
- `fido2` / WebAuthn (v3)

## Handling Common Requests Safely

### "Sync my .env to GitHub"

Do not have the agent open a plaintext `.env` containing real values.

Prefer:

- `.env.example` (names only)
- a profile mapping (names -> refs)
- provider-side fetch via refs

Then call:

- `github.set_actions_secret(repo, secret_name, value_ref)`

### "Run tests that need secrets"

Do not paste secrets into prompts or run `printenv` to verify them.

Use:

- `opaque exec --profile <name> -- <command...>`

Opaque can inject secrets into the sandboxed process environment without returning them in command output.

