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
fingerprint, path, and version. All fields from one path share one issuance;
credentials from different token identities or servers never share a cache entry.
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

## Dynamic credential snapshots

Vault's [database credentials endpoint](https://developer.hashicorp.com/vault/docs/secrets/databases) issues a new username/password pair on each read. Configure both fields from the same path in one execution profile:

```toml
[secrets]
PGUSER = "vault:database/creds/app-readonly#username"
PGPASSWORD = "vault:database/creds/app-readonly#password"
```

Opaque resolves execution-profile secrets as a batch. It captures the token once and reads each distinct Vault path/version once for that batch, then projects all requested fields from that complete response. Duplicate references and their original order are preserved. Concurrent executions and independent resolver instances share a per-path cache lock, so only one dynamic issuance, renewal or refresh runs for the same server, token, path and version at a time.

Dynamic snapshots remain in broker memory for their lease duration. Renewals update the whole cached credential. Expired snapshots are revoked on a best-effort basis before replacement. Authentication failures, invalid leases and missing leases reported by renewal stop resolution; transient renewal failures may reuse the snapshot only while it remains valid. A lease that expires while other references in the batch are resolving fails the entire batch, allowing the caller to retry the whole execution without mixing credential generations.

Lease expiry is measured from before the network request, including its latency. The cache is bounded to 4,096 distinct active path identities. Static KV snapshots are retained only for the current batch. Pinned KV v2 reads revalidate version availability each batch.

Renewal is triggered by resolution, not a background worker. Opaque does not keep a credential alive throughout an arbitrarily long child process, automatically renew the Vault authentication token, or guarantee a credential remains valid after resolution returns. Configure role TTLs and token lifetimes for the intended operation duration. Revoking a token or lease outside Opaque is observed on the next provider request; locally cached values are not continuously checked.

## Validation

Focused fixture tests cover simultaneous username/password reads, concurrent refresh, token rotation, order-preserving batches, expiry during batch resolution, renewal rejection, KV v2 pinning and sanitized provider errors. Fixtures do not prove that a real database accepts the issued pair.

An ignored live acceptance test issues one credential pair from an explicitly selected disposable PostgreSQL database role, authenticates using `psql` with `SELECT 1`, then revokes the test lease. This creates and removes an ephemeral database credential. Run it only against a role/database provisioned for that purpose. Supply through a secure test environment:

- `OPAQUE_VAULT_LIVE_ACCEPTANCE=1`
- `OPAQUE_VAULT_URL`: test Vault endpoint
- `OPAQUE_VAULT_LIVE_TOKEN_REF=env:NAME_OF_DEDICATED_TEST_TOKEN`
- The referenced token, authorized to read the role and revoke the issued lease
- `OPAQUE_VAULT_LIVE_ROLE_PATH=database/creds/<disposable-role>`
- `OPAQUE_VAULT_LIVE_PSQL_PATH`: absolute path to a trusted `psql` executable
- `OPAQUE_VAULT_LIVE_PGHOST` and `OPAQUE_VAULT_LIVE_PGDATABASE`
- `OPAQUE_VAULT_LIVE_PGPORT` if different from `5432`

```bash
cargo test --locked -p opaque-providers --no-default-features --features vault \
  vault::resolve::snapshot_tests::live_dynamic_fields_share_one_real_lease \
  -- --ignored --exact
```

The test suppresses database output and passes credentials through the child environment. A passing fixture suite is not a recorded live acceptance run.
