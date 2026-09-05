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
- `vault:secret/data/myapp?version=7#API_KEY` (one exact KV v2 version)

Opaque extracts fields from both KV styles:

- KV v2: `{ "data": { "data": { ... } } }`
- KV v1: `{ "data": { ... } }`

Bounded publish tasks require a pinned KV v2 ref:

```text
vault:<mount>/data/<path>?version=<positive-integer>#<field>
```

The version is sent as an explicit Vault API query parameter and must match the
returned `data.metadata.version`. Version zero, `latest`, leading zeros,
additional query parameters, and KV v1 paths are rejected. Pinned reads also
require KV v2 deletion metadata: deleted, destroyed, missing, mismatched, or
unavailable versions stop the action. There is no fallback to the latest version
or a field outside the KV v2 data object.

Pinned values are fetched again for each execution and are never cached or saved
as plaintext snapshots. Existing unversioned refs retain their KV v1, KV v2, and
dynamic lease behavior. Dynamic cache identity includes server URL, full token
fingerprint, path, field, and version; it cannot mix sources or token identities.
Vault redirects are not followed.

See the [Vault KV v2 read API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version).

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

## Lease Renewal Window

By default, Opaque proactively renews renewable Vault leases when they are
within 30 seconds of expiry.

Override with:

- `OPAQUE_VAULT_LEASE_RENEW_WINDOW_SECS`
  - integer seconds
  - default `30`
  - set to `0` to disable proactive renewal

## Example

```bash
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name DATABASE_URL \
  --value-ref 'vault:secret/data/myapp?version=7#DATABASE_URL'
```

## Current Scope

Shipped in this phase:

- Vault KV field resolution through `vault:` refs
- Dynamic secret engine field resolution (for example `database/creds/...`)
- Lease-aware caching for dynamic refs using Vault `lease_duration`
- Proactive lease renewal for renewable leases near expiry
- Best-effort revocation of expired cached leases on refresh
