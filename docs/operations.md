# Operations (Contract)

Opaque exposes **operations**, not raw secret values.

v1 transport is local only:

- `opaque` (CLI) -> Unix domain socket -> `opaqued` (daemon)

MCP server exposure is **deferred** (see `docs/roadmap-deferred.md`).

## Safety Classes

| Class | Meaning | Agent Access |
|------:|---------|--------------|
| `SAFE` | Uses secrets internally and must not return them | Allowed (with policy + approvals) |
| `SENSITIVE_OUTPUT` | Output may contain credential-like data | Denied for agents unless explicitly allowlisted in policy |
| `REVEAL` | Returns plaintext secrets | Never (hard-blocked in v1) |

## Implemented Operations (v1)

### `test.noop` (`SAFE`)

No inputs.

Result:

- `{ "status": "ok" }`

### `sandbox.exec` (`SAFE`)

Runs a command in a platform sandbox using an execution profile.

Inputs (via `opaque exec --profile <name> -- <cmd...>`):

- `profile`: profile name (loads `~/.opaque/profiles/<name>.toml`)
- `command`: command argv array

Result:

- `exit_code`: i32
- `duration_ms`: u64
- `stdout_length`: u64
- `stderr_length`: u64

Notes:

- The daemon does **not** return stdout/stderr content (only lengths), to reduce the chance of secret leakage via command output.

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

## Deferred Specs (Not Implemented In v1)

These are design placeholders and should not be treated as supported operations in v1:

- `gitlab.set_ci_variable`
- `k8s.set_secret`
- `k8s.apply_manifest`
- `aws.call`
- `http.request_with_auth`
