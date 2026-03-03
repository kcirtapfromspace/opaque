# Getting Started (Local)

Opaque is a local secrets broker made of:

- `opaqued`: trusted local daemon (enclave, policy, approvals, audit)
- `opaque`: untrusted CLI client
- `opaque-mcp`: MCP server for Claude Code and other MCP-aware tools

Everything flows through `Enclave::execute()` and results are sanitized so plaintext secrets never enter LLM-visible output.

## Build

```bash
cargo build --release
```

Binaries:

- `./target/release/opaqued`
- `./target/release/opaque`
- `./target/release/opaque-mcp`

## Initialize Local State

`opaque init` creates:

- `~/.opaque/config.toml` (policy + daemon config)
- `~/.opaque/profiles/` (exec profiles)
- `~/.opaque/run/` (socket fallback; prefer `XDG_RUNTIME_DIR` on Linux)

```bash
./target/release/opaque init
```

Or initialize with a policy preset:

```bash
./target/release/opaque init --preset safe-demo       # test.noop only
./target/release/opaque init --preset github-secrets   # GitHub secret sync
./target/release/opaque init --preset gitlab-variables # GitLab CI variable sync
./target/release/opaque init --preset sandbox-human    # sandbox for humans only
./target/release/opaque init --preset agent-wrapper-github # wrapped-agent GitHub sync + session tokens
```

List available presets: `opaque policy presets`

## Minimal Policy (Example)

Policy is deny-by-default. Start by allowing only low-risk test operations.

```toml
[[rules]]
name = "allow-test-noop"
operation_pattern = "test.*"
allow = true
client_types = ["human", "agent"]

[rules.client]

[rules.approval]
require = "never"
factors = []
```

Validate:

```bash
./target/release/opaque policy check
```

For the full config format, see [Policy](policy.md) and `examples/policy.toml`.

## Bitwarden Secrets Manager

Opaque can resolve secrets from Bitwarden Secrets Manager using the `bitwarden:` ref scheme.

1. Create a Bitwarden service account and store the access token:
   ```bash
   security add-generic-password -a opaque -s opaque/bitwarden-token -w '<token>'
   ```

2. Use `bitwarden:` refs in profiles or `--value-ref` arguments:
   ```bash
   opaque github set-secret \
     --repo myorg/myrepo \
     --secret-name API_KEY \
     --value-ref bitwarden:production/API_KEY
   ```

See [Bitwarden setup](bitwarden.md) for full setup.

## HashiCorp Vault

Opaque can resolve secrets from Vault using the `vault:` ref scheme:

```text
vault:<path>#<field>
```

Example:

```bash
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name DATABASE_URL \
  --value-ref vault:secret/data/myapp#DATABASE_URL
```

Defaults:

- Vault URL: `http://127.0.0.1:8200` (override with `OPAQUE_VAULT_URL`)
- Vault token ref: `keychain:opaque/vault-token` (override with `OPAQUE_VAULT_TOKEN_REF`)
- Vault lease renew window: `30` seconds (override with `OPAQUE_VAULT_LEASE_RENEW_WINDOW_SECS`, set `0` to disable proactive renewal)
- Audit retention: `audit_retention_days = 90` (runtime purge continuously removes rows older than this window)
- Audit SSE feed: disabled by default; set `OPAQUE_AUDIT_SSE_ADDR=127.0.0.1:8787` to enable (`OPAQUE_AUDIT_SSE_POLL_MS` and `OPAQUE_AUDIT_SSE_BATCH_LIMIT` are optional tuning knobs)

See [Vault setup](vault.md) for details.

## Azure Key Vault

Opaque supports Azure Key Vault operations and `azure:` secret refs.

Ref format:

```text
azure:<vault>/<secret>
azure:<vault>/<secret>/<version>
```

Daemon env configuration (required for Azure operations and resolver auth):

- `OPAQUE_AZURE_VAULT_URL` (used by `opaque azure ...` operations)
- `OPAQUE_AZURE_TENANT_ID`
- `OPAQUE_AZURE_CLIENT_ID`
- `OPAQUE_AZURE_CLIENT_SECRET`

Examples:

```bash
opaque azure list-secrets
opaque azure set-secret --name API_KEY --value-ref keychain:opaque/api-key
```

## GCP Secret Manager

Opaque supports GCP Secret Manager operations and `gcp:` secret refs.

Ref format:

```text
gcp:<project>/<secret>
gcp:<project>/<secret>/<version>
```

Daemon env configuration:

- `OPAQUE_GCP_ACCESS_TOKEN` or `OPAQUE_GCP_SERVICE_ACCOUNT_KEY`
- optional: `OPAQUE_GCP_SM_URL` (default: `https://secretmanager.googleapis.com/v1`)

Examples:

```bash
opaque gcp list-secrets --project my-project
opaque gcp add-secret-version \
  --project my-project \
  --secret-id API_KEY \
  --value-ref keychain:opaque/api-key
```

## MCP Quickstart (Claude Code)

For Claude Code, the MCP server is the recommended integration path:

1. Add to your Claude Code MCP config:
   ```json
   {
     "mcpServers": {
       "opaque": {
         "command": "/path/to/opaque-mcp"
       }
     }
   }
   ```

2. Start `opaqued` (or install it as a service: `opaque service install`)

3. Ask Claude Code to "list my GitHub secrets for owner/repo" — it will call the `opaque_github_list_secrets` tool via MCP.

See [MCP integration](mcp-integration.md) for full setup.

## Run The Daemon

In one terminal:

```bash
./target/release/opaqued
```

In another terminal:

```bash
./target/release/opaque ping
./target/release/opaque version
./target/release/opaque whoami
```

## Agent Wrapper Mode

Run an agent with a session-scoped token managed by Opaque:

```bash
./target/release/opaque agent run -- codex
```

Inspect and revoke active wrapper sessions:

```bash
./target/release/opaque agent list
./target/release/opaque agent end <session-id>
./target/release/opaque agent end --all
```

With stricter daemon enforcement, enable session gating in `~/.opaque/config.toml`:

```toml
enforce_agent_sessions = true
agent_session_ttl_secs = 3600
```

Then wrapped agent clients must present `OPAQUE_SESSION_TOKEN` in the daemon handshake (the wrapper does this automatically).

## Execute Operations

### `test.noop`

```bash
./target/release/opaque execute test.noop
```

### `sandbox.exec` (Profile-Based)

1. Create a profile at `~/.opaque/profiles/dev.toml` (example: `examples/profiles/dev.toml`)
2. Run:

```bash
./target/release/opaque exec --profile dev -- echo "hello from sandbox"
```

`sandbox.exec` captures process output but returns only metadata (`exit_code`, `stdout_length`, `stderr_length`, `truncated`) — raw stdout/stderr is not included in the response. Treat this as sensitive output: avoid commands that print secrets, and do not allow it for agent clients by default.

### GitHub Secrets

The CLI exposes multiple GitHub secret scopes via `opaque github ...`.

```bash
./target/release/opaque github set-secret \
  --repo owner/repo \
  --secret-name MY_TOKEN \
  --value-ref keychain:opaque/my-token
```

OAuth bearer token mode:

```bash
./target/release/opaque github set-secret \
  --repo owner/repo \
  --secret-name MY_TOKEN \
  --value-ref keychain:opaque/my-token \
  --github-auth-mode oauth \
  --github-token-ref keychain:opaque/github-oauth-token
```

Environment-level Actions secret:

```bash
./target/release/opaque github set-secret \
  --repo owner/repo \
  --environment production \
  --secret-name MY_TOKEN \
  --value-ref keychain:opaque/my-token
```

Codespaces (user-level):

```bash
./target/release/opaque github set-codespaces-secret \
  --secret-name DOTFILES_TOKEN \
  --value-ref keychain:opaque/dotfiles-token
```

Codespaces (repo-level):

```bash
./target/release/opaque github set-codespaces-secret \
  --repo owner/repo \
  --secret-name DOTFILES_TOKEN \
  --value-ref keychain:opaque/dotfiles-token
```

Dependabot (repo-level):

```bash
./target/release/opaque github set-dependabot-secret \
  --repo owner/repo \
  --secret-name NPM_TOKEN \
  --value-ref keychain:opaque/npm-token
```

Org-level Actions secret:

```bash
./target/release/opaque github set-org-secret \
  --org myorg \
  --secret-name ORG_DEPLOY_KEY \
  --value-ref keychain:opaque/org-deploy-key
```

These operations are `SAFE`: they never return the secret value or ciphertext.

### GitLab CI Variables

Set a project CI/CD variable:

```bash
./target/release/opaque gitlab set-ci-variable \
  --project group/project \
  --key DATABASE_URL \
  --value-ref keychain:opaque/db-url
```

Use OAuth bearer tokens instead of `PRIVATE-TOKEN` headers:

```bash
./target/release/opaque gitlab set-ci-variable \
  --project group/project \
  --key DATABASE_URL \
  --value-ref keychain:opaque/db-url \
  --gitlab-auth-mode oauth \
  --gitlab-token-ref keychain:opaque/gitlab-oauth-token
```

Optionally set scope/attributes:

```bash
./target/release/opaque gitlab set-ci-variable \
  --project group/project \
  --key DATABASE_URL \
  --value-ref bitwarden:production/DATABASE_URL \
  --environment-scope production \
  --protected \
  --masked
```

This operation is `SAFE`: it writes through to GitLab and never returns the variable value.

Build a refs-only manifest from `.env.example` (names only):

```bash
./target/release/opaque github build-manifest \
  --env-file .env.example \
  --value-ref-template 'bitwarden:production/{name}' \
  --out .opaque/env-manifest.json
```

Manually review/update refs in `.opaque/env-manifest.json`, then publish:

```bash
./target/release/opaque github publish-manifest \
  --repo owner/repo \
  --manifest-file .opaque/env-manifest.json
```

Preview publish only (no API calls):

```bash
./target/release/opaque github publish-manifest \
  --repo owner/repo \
  --manifest-file .opaque/env-manifest.json \
  --dry-run
```

Legacy one-step flow (still supported):

```bash
./target/release/opaque github publish-env \
  --repo owner/repo \
  --env-file .env.example \
  --value-ref-template 'bitwarden:production/{name}'
```

## Audit

The daemon writes a local SQLite audit DB at `~/.opaque/audit.db`.

```bash
./target/release/opaque audit tail --limit 50
./target/release/opaque audit tail --query github --limit 20
```

## Environment Variables

- `OPAQUE_CONFIG`: override daemon/CLI config path (default: `~/.opaque/config.toml`)
- `OPAQUE_SOCK`: override socket path for the CLI only (daemon ignores it)
- `OPAQUE_GITHUB_TOKEN_REF`: override default GitHub token ref used by `github.*` operations (default ref varies by auth mode)
- `OPAQUE_GITHUB_AUTH_MODE`: set GitHub auth mode for `github.*` operations (`pat` default, or `oauth`)
- `OPAQUE_GITHUB_API_URL`: override GitHub API base URL (GitHub Enterprise Server or local testing)
- `OPAQUE_GITLAB_TOKEN_REF`: override default GitLab token ref used by `gitlab.set_ci_variable` (default ref varies by auth mode)
- `OPAQUE_GITLAB_AUTH_MODE`: set GitLab auth mode for `gitlab.set_ci_variable` (`pat` default, or `oauth`)
- `OPAQUE_GITLAB_API_URL`: override GitLab API base URL (GitLab.com / self-managed / local testing)
- `OPAQUE_BITWARDEN_URL`: override Bitwarden API base URL (default: `https://api.bitwarden.com`)

## Next

- [MCP integration (Claude Code)](mcp-integration.md)
- [Bitwarden setup](bitwarden.md)
- [Demo recordings](demos.md)
- [Deployment & OS approval backends](deployment.md)
