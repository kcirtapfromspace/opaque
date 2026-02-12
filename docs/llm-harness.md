# LLM Harness: Safe Secret Usage Without Disclosure

This doc defines how LLM tools (Codex, Claude Code, etc) interact with AgentPass to use secrets **without ever receiving plaintext secret values**.

## 1. The Rule: LLMs Get Operations, Not Values

AgentPass exposes a small set of **operations** (see `docs/operations.md`) that can *use* secrets internally.

- LLM tools may request:
  - "set GitHub secret `JWT` from secret ref `vault://...`"
  - "write Kubernetes secret `foo` from secret refs"
  - "call HTTP endpoint with auth ref"
- LLM tools must never request:
  - "print the JWT"
  - "show me the .env contents"
  - any API that returns secret values

## 2. What the LLM Can Provide

Inputs are limited to:

- non-secret metadata: repo name, secret variable names, cluster/namespace names, etc
- **secret references** (refs), not values:
  - `op://...` (1Password item/field reference)
  - `vault://...` (Vault path/key)
  - `profile:<name>:<key>` (recommended for agent workflows)

AgentPass should reject raw values for "secret write" operations.

## 3. Profiles: Make Secret Selection LLM-Friendly

To keep LLM interaction simple and safe, AgentPass should support a "profile" file that maps env var names to secret refs.

Example (conceptual):

```toml
[secrets]
JWT = "vault://kv/myapp/jwt"
DATABASE_URL = "op://Prod DB/uri"
```

Then the LLM only needs to say:

- "set `JWT` in GitHub Actions secrets for `org/repo` using profile `myapp`"

The broker resolves `JWT` -> ref and fetches the value internally.

## 4. Approvals: Proof-of-Life + Step-Up

Operations that use secrets can trigger approval automatically based on policy:

- `local_bio`: native OS popup on desktop (macOS LocalAuthentication, Linux polkit)
- `ios_faceid`: paired iOS device approval (QR pairing + Face ID)

The LLM does not need to orchestrate approvals explicitly. Preferred v1 UX:

1. LLM requests operation.
2. AgentPass triggers approval UI(s).
3. Operation returns success/failure.

If your LLM tool environment has short tool-call timeouts, add an async mode:

- `op.start` returns `request_id`
- `op.status` polls until approved/denied/completed

## 5. Handling “Arbitrary” Requests Safely

### 5.1 “Insert JWT Here”

Do not insert a JWT literal into source code or config files the LLM can read.

Instead, the LLM should:

- change code/config to read from an env var:
  - `JWT` (or `AUTH_TOKEN`)
- then request AgentPass to *deliver* that env var into the target:
  - GitHub Actions secret (repo or environment)
  - GitLab CI variable
  - Kubernetes secret

This keeps the JWT value out of the LLM context and out of the repo.

### 5.2 “Use JWT to Call an API”

Do not run `curl -H "Authorization: Bearer <jwt>" ...` from an agent runtime.

Use an agent-safe operation:

- `http.request_with_auth(auth_ref=..., url=..., method=...)`

AgentPass adds the auth header internally and can enforce:

- domain allowlists
- method allowlists
- response scrubbing

### 5.3 “Sync .env Vars to GitHub”

Avoid having the LLM open a plaintext `.env` that contains real values.

Safer patterns:

- `.env.example` or `.env.manifest` (names only)
- profile mapping (names -> secret refs)
- provider-side fetch (1Password/Vault) using refs

Then sync with operations like:

- `github.set_actions_secret(repo, name, value_ref)`
- `github.set_actions_secret(repo, environment, name, value_ref)`
- `github.set_codespaces_secret(scope, name, value_ref)`

## 6. LLM Prompting Guidance (What To Teach the Agent)

Add these constraints to your agent/system prompt:

- Never ask the user to paste secrets into chat.
- Never read `.env` files that contain real values.
- Use AgentPass operations with secret refs/profiles.
- For any operation that uses secrets, summarize intent for the human:
  - repo/project/cluster
  - secret key names (not values)
  - why it’s needed

## 7. Integration Options

### 7.1 CLI Harness (works everywhere)

- LLM calls `agentpass ...` commands that invoke operations.
- Output is strict JSON without secret values.

### 7.2 MCP Server (best UX for Claude Code)

- Expose AgentPass operations as MCP tools.
- The MCP server must never return secret values.

