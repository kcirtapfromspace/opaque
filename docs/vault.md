# HashiCorp Vault

Opaque supports Vault-backed secret refs for write-only operations (for example `github.set_actions_secret` and `gitlab.set_ci_variable`).

It does not expose a plaintext `vault.read_*` operation.

## Ref Format

Use:

```text
vault:<path>#<field>
```

Examples:

- `vault:secret/data/myapp#DATABASE_URL` (KV v2 path)
- `vault:secret/myapp#API_KEY` (KV v1 path)

Opaque extracts fields from both KV styles:

- KV v2: `{ "data": { "data": { ... } } }`
- KV v1: `{ "data": { ... } }`

## Auth

Vault auth token ref defaults to:

```text
keychain:opaque/vault-token
```

Override with:

- `OPAQUE_VAULT_TOKEN_REF` (secret ref, ex `env:OPAQUE_VAULT_TOKEN`)

## Vault API URL

Default:

```text
http://127.0.0.1:8200
```

Override with:

- `OPAQUE_VAULT_URL`

URL policy:

- `https://` required for remote hosts
- `http://` allowed only for `localhost` and `127.0.0.1`

## Example

```bash
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name DATABASE_URL \
  --value-ref vault:secret/data/myapp#DATABASE_URL
```

## Current Scope

Shipped in this phase:

- Vault KV field resolution through `vault:` refs
- Dynamic secret engine field resolution (for example `database/creds/...`)
- Lease-aware caching for dynamic refs using Vault `lease_duration`

Still deferred:

- Lease renewal and explicit lease revocation flows
