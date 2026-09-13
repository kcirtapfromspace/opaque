# Use Azure Key Vault

Opaque can list Key Vault secret, key and certificate metadata, inspect one secret's metadata, and write a secret by reference. An `azure:vault-name/secret-name[/version]` reference supplies plaintext only inside an authorized consumer, never through the generic operation response.

This implementation is available in source builds containing the `azure` provider. It supports public Azure Key Vault and Microsoft Entra client-credentials authentication. Sovereign-cloud endpoints, managed identities, certificate credentials and federated credentials are not currently supported.

## Configure the broker

Use an Entra application identity with access to the intended vault. Grant the identity only the Key Vault data-plane permissions required: secret/key/certificate list permissions for the corresponding lists, secrets/get for metadata inspection or reference resolution, and secrets/set for writes. Entra application registration alone does not grant Key Vault access.

Set these values in the **broker process environment**, keeping actual credentials outside the repository:

```sh
export OPAQUE_AZURE_VAULT_URL=https://your-test-vault.vault.azure.net
export OPAQUE_AZURE_TENANT_ID=your-directory-tenant-id
export OPAQUE_AZURE_CLIENT_ID=your-application-client-id
export OPAQUE_AZURE_CLIENT_SECRET_REF=keychain:opaque/azure-client-secret
```

The keychain entry must contain the application's client secret. `env:NAME` is also supported. Without an explicit reference, the broker uses `env:OPAQUE_AZURE_CLIENT_SECRET`. It does not load Azure CLI sessions or ambient SDK credential chains.

The broker posts to the fixed Entra token endpoint for the configured tenant with `grant_type=client_credentials` and `scope=https://vault.azure.net/.default`. It caches tokens until the expiry margin and refreshes when the resolved client secret changes. Restart the broker after changing environment settings; changes to a keychain credential are picked up during subsequent credential use. [Microsoft's client-credentials protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow).

The configured vault origin and Entra identity are captured in each prepared action before any credential lookup or network request. An `azure:` reference naming another vault is rejected. Changing a caller-supplied parameter cannot change the vault or token endpoint.

## Run a metadata operation

Create an empty parameter object for vault-wide listing:

```sh
cat > azure-list.json <<'JSON'
{}
JSON
opaque execute azure.list_secrets --params-file azure-list.json
```

A matching sealed policy and its native approval requirements still apply. `opaque init --interactive` detects this configuration and can generate metadata-only starter rules. Bind those rules to the intended `azure_vault_url` before authorizing a shared environment.

| Operation | Exact parameters | Returned data |
|---|---|---|
| `azure.list_secrets` | None | Names and enabled flags |
| `azure.list_keys` | None | Names and enabled flags |
| `azure.list_certificates` | None | Names and enabled flags |
| `azure.get_secret` | `name`, optional `version` | Name, enabled flag and `metadata_only: true` |
| `azure.set_secret` | `name`, `value_ref` | Name and write status |

`azure.get_secret` uses Azure's Secret Get endpoint, whose response includes the secret value. The broker discards that value and returns only metadata; the underlying permission is still secrets/get. A list-only identity can use `azure.list_secrets` without this grant. [Azure Secret Get](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01).

Writes accept a UTF-8 value of at most 25 KiB from `env:NAME` or `keychain:service/account`. Add an explicit write policy; onboarding does not grant writes. The provider's echoed value is removed before any operation response. Profile expansion and nested provider `value_ref` inputs are rejected so approval binds the effective source reference. [Azure Secret Set](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret?view=rest-keyvault-secrets-2025-07-01).

For a supported authorized consumer, use `azure:your-test-vault/secret-name` for the latest version or append an exact version. Generic reveal operations remain disabled.

## Verify the real integration

Use an isolated test vault and a harmless existing secret. Execute a metadata list and compare it with Azure's API or portal under an independent operator identity. Explicitly authorize a uniquely named test-secret write only when needed, then verify the resulting version in Azure. Exercise reference resolution through a consumer with a non-secret result rather than logging the secret.

Verify a missing data-plane grant, a reference for a different vault, client-secret rotation, token expiry and a broker policy denial. A broker policy denial should cause no Entra or Key Vault request. Retain the canonical source revision and sanitized provider observations alongside broker receipts. Remove test resources through a separately authorized cleanup action.

Local tests exercise token requests, refresh, pagination, hostile continuations, redirects, invalid identifiers, bounded responses and output redaction. They do not demonstrate the chosen tenant/application/vault permissions. No live Azure account was used for the source validation accompanying this implementation.

## Failure behavior

The client uses Key Vault API version `2025-07-01`. List pagination follows `nextLink` only on the configured vault origin and the same collection path, with the same API version. Foreign origins, unexpected query fields, repeated continuations and oversized responses fail closed. Limits are 25 items per page, 160 pages, 4,000 items and 256 KiB per JSON response; oversized collections return an error, not partial success. [Azure list protocol](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secrets/get-secrets?view=rest-keyvault-secrets-2025-07-01).

Redirects, ambient proxies and automatic retries are disabled. A write transport failure may mean the provider accepted the write; check Azure before intentionally trying again. Errors omit provider bodies, tokens and secret values.
