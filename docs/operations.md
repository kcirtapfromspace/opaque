# Operations (Draft Contract)

Opaque exposes **operations**, not raw secret values.

Operations are invoked via:

- local CLI (human)
- MCP server (LLM tools)
- internal automation hooks (future)

Unless explicitly noted, operation results must be **sanitized** to avoid leaking secret values into LLM-visible channels.

## Safety Classes

- `SAFE`: uses secrets but cannot return them (ex: "set GitHub secret")
- `SENSITIVE_OUTPUT`: could return token-like material; disabled for LLM clients by default
- `REVEAL`: returns secret values; not exposed to MCP/LLM clients

## GitHub

### `github.set_actions_secret` (SAFE)

Inputs:

- `repo`: `org/repo`
- `name`: secret name (ex: `AWS_ACCESS_KEY_ID`)
- `value_ref`: secret reference (1Password/Vault/etc)
- optional: `environment` (when set, writes an Actions *environment* secret instead of a repo secret)

Result:

- `status`: `ok` | `error`
- `repo`, `name`
- optional: `environment`
- optional: `updated`: bool

Notes:

- Broker fetches repo public key and encrypts secret for GitHub API.
- Never return the secret value or its ciphertext.

### `github.set_codespaces_secret` (SAFE)

Inputs:

- scope: user or repo
- `name`
- `value_ref`

Result:

- `status`, `scope`, `name`

Notes:

- Support both user-level Codespaces secrets and repo-level Codespaces secrets.

## GitLab

### `gitlab.set_ci_variable` (SAFE)

Inputs:

- `project`: id/path
- `key`
- `value_ref`
- `protected`: bool
- `masked`: bool
- `environment_scope`: string

Result:

- `status`, `project`, `key`

Notes:

- Default to `masked=true` and `protected=true` where it makes sense.

## Kubernetes

### `k8s.set_secret` (SAFE)

Inputs:

- `cluster`: logical cluster name
- `namespace`
- `name`
- `type`: secret type (ex: `kubernetes.io/dockerconfigjson`)
- `data_from_refs`: map of `key -> value_ref`

Result:

- `status`, `cluster`, `namespace`, `name`

Notes:

- Disallow providing raw secret values in the request.
- Prefer a broker identity that can `create/update/patch` secrets but not `get/list/watch` secrets.

### `k8s.apply_manifest` (SAFE with policy)

Inputs:

- `cluster`
- `manifest_yaml`

Result:

- `status`, `objects_applied`: list of `kind/name/namespace`

Policy:

- Reject if the manifest contains `kind: Secret`.
- Optionally reject `ConfigMap` keys that look like secrets (heuristic).

## AWS

### `aws.call` (SAFE or SENSITIVE_OUTPUT depending)

Inputs:

- `account`/`role` context (logical)
- `service`: `s3`, `eks`, `ecr`, `sts`, ...
- `action`: operation name
- `params`: structured JSON

Result:

- `status`
- `output`: sanitized JSON

Policy:

- Start with an allowlist (service+action) and resource constraints.
- Mark actions that can return credentials as `SENSITIVE_OUTPUT`.

Examples:

- `ecr:GetAuthorizationToken` is `SENSITIVE_OUTPUT` (token-like)
- `sts:AssumeRole` output credentials are `SENSITIVE_OUTPUT`

## HTTP Proxy

### `http.request_with_auth` (SAFE with strong constraints)

Inputs:

- `method`, `url`
- `headers` (no `Authorization`)
- `body` (size-limited)
- `auth_ref` (secret ref used to set Authorization/header/cookie)

Result:

- `status_code`
- `headers` (filtered)
- `body` (optional; disabled by default unless endpoint allowlisted)

Policy:

- Strict allowlist of domains and methods.
- Body size limits and response scrubbing.
