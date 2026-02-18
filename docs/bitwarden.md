# Bitwarden Secrets Manager

Opaque integrates with [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) for secret storage and retrieval. The integration follows the same pattern as 1Password: browsing operations are `SAFE`, reading secret values is `REVEAL` (hard-blocked in v1).

## Setup

### 1. Create a Bitwarden service account

In the Bitwarden web vault:

1. Go to **Organizations** → your org → **Secrets Manager**
2. Create a **Service Account** with access to the projects you need
3. Copy the service account **access token**

### 2. Store the access token

Store the Bitwarden access token in your macOS Keychain (or another ref-compatible store):

```bash
security add-generic-password -a opaque -s opaque/bitwarden-token -w '<access-token>'
```

### 3. Configure Opaque

Your `config.toml` policy rules control which Bitwarden operations are allowed. See the example rules below or use a preset:

```bash
opaque init --preset github-secrets   # includes test.noop for onboarding
```

## Secret Reference Format

Bitwarden secrets are referenced using the `bitwarden:` scheme:

| Format | Example | Resolution |
|--------|---------|------------|
| `bitwarden:<secret-id>` | `bitwarden:a1b2c3d4-e5f6-7890-abcd-ef1234567890` | Fetch by UUID |
| `bitwarden:<project>/<secret-key>` | `bitwarden:production/DATABASE_URL` | Fetch by project name + secret key |

These refs are used in execution profiles and as `value_ref` arguments to operations like `github.set_actions_secret`.

### Profile example

```toml
# ~/.opaque/profiles/prod.toml
[secrets]
DATABASE_URL = "bitwarden:production/DATABASE_URL"
API_KEY = "bitwarden:production/API_KEY"
GITHUB_TOKEN = "keychain:opaque/github-pat"
```

## Operations

### `bitwarden.list_projects` (`SAFE`)

Lists accessible Bitwarden projects (names only).

- **Approval**: `first_use` (recommended)
- **Result**: `{ "projects": [{ "name": "...", "id": "..." }] }`

### `bitwarden.list_secrets` (`SAFE`)

Lists secret names in a project (no values).

- **Params**: `project` (optional — filter by project name)
- **Approval**: `first_use` (recommended)
- **Result**: `{ "secrets": [{ "key": "...", "id": "...", "project": "..." }] }`

### `bitwarden.read_secret` (`REVEAL`)

Reads a secret value. **Hard-blocked in v1** — this operation returns plaintext and is never allowed for agent clients.

- Human-only interactive use is possible if explicitly enabled in policy with `client_types = ["human"]`.

## Policy Examples

### Allow agents to browse Bitwarden (read-only metadata)

```toml
[[rules]]
name = "allow-bitwarden-list-projects"
operation_pattern = "bitwarden.list_projects"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300

[[rules]]
name = "allow-bitwarden-list-secrets"
operation_pattern = "bitwarden.list_secrets"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300
```

### Use Bitwarden refs with GitHub secrets

```toml
[[rules]]
name = "allow-github-actions-secret"
operation_pattern = "github.set_actions_secret"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]
lease_ttl = 300
```

Then reference Bitwarden secrets in your commands:

```bash
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name DATABASE_URL \
  --value-ref bitwarden:production/DATABASE_URL
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPAQUE_BITWARDEN_URL` | Bitwarden API base URL | `https://api.bitwarden.com` |

The Bitwarden access token is resolved via secret refs (e.g., `keychain:opaque/bitwarden-token`), not environment variables, to avoid credential cycles.

## End-to-End Workflow

1. Store your Bitwarden service account token in the macOS Keychain
2. Initialize Opaque with a policy that allows the operations you need
3. Start `opaqued`
4. Browse your secrets: `opaque execute bitwarden.list_projects`
5. Use Bitwarden refs in GitHub secret sync:
   ```bash
   opaque github set-secret \
     --repo myorg/myrepo \
     --secret-name API_KEY \
     --value-ref bitwarden:production/API_KEY
   ```
6. Review the audit log: `opaque audit tail --limit 10`
