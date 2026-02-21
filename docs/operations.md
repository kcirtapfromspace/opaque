# Operations (Contract)

Opaque exposes **operations**, not raw secret values.

v1 transport is local only:

- `opaque` (CLI) -> Unix domain socket -> `opaqued` (daemon)

For MCP-aware tools (Claude Code), `opaque-mcp` provides a stdio-based MCP server that exposes Safe operations as tools. See `docs/mcp-integration.md`.

## Safety Classes

| Class | Meaning | Agent Access |
|------:|---------|--------------|
| `SAFE` | Uses secrets internally and must not return them | Allowed (with policy + approvals) |
| `SENSITIVE_OUTPUT` | Output may contain credential-like data | Denied for agents unless explicitly allowlisted in policy |
| `REVEAL` | Returns plaintext secrets | Never (hard-blocked in v1) |

## Implemented Operations

### `test.noop` (`SAFE`)

No inputs.

Result:

- `{ "status": "ok" }`

### `sandbox.exec` (`SENSITIVE_OUTPUT`)

Runs a command in a platform sandbox using an execution profile.

Inputs (via `opaque exec --profile <name> -- <cmd...>`):

- `profile`: profile name (loads `~/.opaque/profiles/<name>.toml`)
- `command`: command argv array

Result:

- `exit_code`: i32
- `duration_ms`: u64
- `stdout_length`: u64
- `stderr_length`: u64
- `stdout`: string (captured; may be empty)
- `stderr`: string (captured; may be empty)
- `truncated`: bool (true when capture was capped)

Notes:

- The current implementation **returns captured stdout/stderr** (and the CLI prints it). Treat this as `SENSITIVE_OUTPUT`: agent clients should not be allowed by default, and sandboxed commands must not print secret material.

### `github.set_actions_secret` (`SAFE`)

Sets a GitHub Actions secret using GitHub's public-key encryption.

Supports both:

- repo-level Actions secrets
- environment-level Actions secrets

Inputs:

- `repo`: `owner/repo`
- `secret_name`: secret name (ex: `AWS_ACCESS_KEY_ID`)
- `value_ref`: secret reference (ex: `keychain:opaque/my-token`)
- optional: `github_token_ref`: GitHub PAT ref (default: `keychain:opaque/github-pat`)
- optional: `environment`: when set, writes an Actions environment secret instead of a repo secret

Result:

- `status`: `created` | `updated`
- `repo`
- optional: `environment`
- `secret_name`

Notes:

- Never return the secret value or its ciphertext.
- For GitHub Enterprise Server or local testing, `opaqued` honors `OPAQUE_GITHUB_API_URL` as the API base URL.

### `github.set_codespaces_secret` (`SAFE`)

Sets a GitHub Codespaces secret.

Supports both:

- user-level Codespaces secrets
- repo-level Codespaces secrets

Inputs:

- `secret_name`
- `value_ref`
- optional: `repo` (`owner/repo`) (when set, creates a repo-level Codespaces secret)
- optional: `github_token_ref` (default: `keychain:opaque/github-pat`)
- optional: `selected_repository_ids` (user-level only; when omitted, GitHub defaults apply)

Result:

- `status`: `created` | `updated`
- `secret_name`
- optional: `repo` (repo-level)
- optional: `scope`: `"user"` (user-level)

Notes:

- Never return the secret value or its ciphertext.

### `github.set_dependabot_secret` (`SAFE`)

Sets a GitHub Dependabot repository secret.

Inputs:

- `repo`: `owner/repo`
- `secret_name`
- `value_ref`
- optional: `github_token_ref`

Result:

- `status`: `created` | `updated`
- `repo`
- `secret_name`

Notes:

- Never return the secret value or its ciphertext.

### `github.set_org_secret` (`SAFE`)

Sets a GitHub Actions organization secret.

Inputs:

- `org`
- `secret_name`
- `value_ref`
- optional: `github_token_ref`
- optional: `visibility`: `"all" | "private" | "selected"` (default: `"private"`)
- optional: `selected_repository_ids` (when `visibility = "selected"`)

Result:

- `status`: `created` | `updated`
- `org`
- `secret_name`

Notes:

- Never return the secret value or its ciphertext.

### `gitlab.set_ci_variable` (`SAFE`)

Sets a GitLab CI/CD variable for a project.

Inputs:

- `project`: project path or ID (ex: `group/project`)
- `key`: variable key (ex: `DATABASE_URL`)
- `value_ref`: secret reference (ex: `keychain:opaque/db-url`)
- optional: `gitlab_token_ref`: GitLab token ref (default: `keychain:opaque/gitlab-pat`)
- optional: `environment_scope`
- optional: `protected`: boolean
- optional: `masked`: boolean
- optional: `raw`: boolean
- optional: `variable_type`: `"env_var" | "file"` (default: `"env_var"`)

Result:

- `status`: `created` | `updated`
- `project`
- `key`
- optional: `environment_scope`
- optional: `protected`
- optional: `masked`
- optional: `raw`
- optional: `variable_type`

Notes:

- Never returns variable values.
- Supports GitLab self-managed or alternate API hosts via `OPAQUE_GITLAB_API_URL`.

### `onepassword.list_vaults` (`SAFE`)

Lists accessible 1Password vaults (names + descriptions only).

Result:

- `vaults`: array of `{ name, description }`

Notes:

- Safe for agents if your policy allows it; does not return vault IDs or any secret values.

### `onepassword.list_items` (`SAFE`)

Lists item titles in a vault (no field values).

Inputs:

- `vault`: vault name

Result:

- `vault`: vault name
- `items`: array of `{ title, category }`

Notes:

- Safe for agents if your policy allows it; does not return item IDs or any secret values.

### `onepassword.read_field` (`REVEAL`)

Reads a single field value from a 1Password item.

Inputs:

- `vault`: vault name
- `item`: item title
- `field`: field label

Result:

- `vault`
- `item`
- `field`
- `value` (plaintext)

Notes:

- This violates the core v1 rule "LLMs get operations, not values". It should not be enabled for agent workflows. If kept at all, it should be hard-blocked or reserved for interactive human-only flows with explicit friction.

### `bitwarden.list_projects` (`SAFE`)

Lists accessible Bitwarden Secrets Manager projects.

Inputs: none.

Result:

- `projects`: array of `{ name, id }`

Notes:

- Safe for agents if your policy allows it; returns project metadata only.

### `bitwarden.list_secrets` (`SAFE`)

Lists secret names in a Bitwarden project (no values).

Inputs:

- optional: `project`: project name (filters results)

Result:

- `secrets`: array of `{ key, id, project }`

Notes:

- Safe for agents if your policy allows it; does not return secret values.

### `bitwarden.read_secret` (`REVEAL`)

Reads a single secret value from Bitwarden Secrets Manager.

Inputs:

- `id`: secret UUID, or
- `project` + `key`: project name and secret key

Result:

- `key`
- `value` (plaintext)

Notes:

- Hard-blocked in v1. Returns plaintext secrets — should not be enabled for agent workflows. Reserved for interactive human-only flows with explicit friction.

## Deferred Specs (Not Implemented In v1)

These are design placeholders and should not be treated as supported operations in v1:

- `k8s.set_secret`
- `k8s.apply_manifest`
- `aws.call`
- `http.request_with_auth`
