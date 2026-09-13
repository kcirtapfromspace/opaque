# Use Google Secret Manager

Opaque can list secret names, inspect metadata, create a secret container, and write a new version through Google's Secret Manager REST API. A `gcp:project-number/secret[/version]` reference supplies a value directly to an authorized consumer. The generic operation API never reveals its plaintext.

This implementation is available in source builds containing the `gcp` provider. It uses the global endpoint `https://secretmanager.googleapis.com/v1`; regional Secret Manager endpoints, ADC, metadata-server credentials, workload identity federation and implicit `gcloud` profiles are not currently supported.

## Configure the broker

Enable the Secret Manager API in the intended project and grant the broker identity only the permissions needed for its operations. Listing and metadata inspection need `secretmanager.secrets.list` and `secretmanager.secrets.get`. Container creation needs `secretmanager.secrets.create`; writing versions needs `secretmanager.versions.add`; resolving values needs `secretmanager.versions.access`. These are independent grants. [Google's permissions guide](https://docs.cloud.google.com/secret-manager/docs/view-secret-details).

Choose one credential method in the **broker process environment**:

| Setting | Credential source |
|---|---|
| `OPAQUE_GCP_SERVICE_ACCOUNT_REF=keychain:opaque/gcp-service-account` | A keychain entry containing the complete service-account JSON; `env:NAME` is also supported |
| `OPAQUE_GCP_SERVICE_ACCOUNT_KEY=/absolute/private/service-account.json` | Compatibility path to an owner-readable regular file with no group/other permissions; symlinks are rejected |
| `OPAQUE_GCP_TOKEN_REF=keychain:opaque/gcp-access-token` | An externally supplied access token; `env:NAME` is also supported |
| `OPAQUE_GCP_ACCESS_TOKEN` | Direct access token, when the preceding methods are absent |

The order in the table is the selection priority. Store credentials outside source control. An explicit but invalid higher-priority method fails; it does not silently fall back. `OPAQUE_GCP_SM_URL`, if set, must identify the global endpoint above. Custom HTTP destinations are restricted to compiled unit tests.

Service-account authentication signs an RS256 assertion for `https://oauth2.googleapis.com/token`, requests the `cloud-platform` scope, and caches the resulting token until its refresh margin. A key file cannot redirect the assertion to its own `token_uri`. The cache also changes when the resolved credential changes. Direct tokens must be renewed externally. Restart the broker after changing its environment; keychain updates are read during subsequent credential use. [Google service-account OAuth protocol](https://developers.google.com/identity/protocols/oauth2/service-account).

## Run a metadata operation

Use the project's **numeric project number** in the `project` parameter and every `gcp:` reference. Find it in Google Cloud's project settings; the number below is a synthetic example. This path deliberately rejects project IDs: responses are compared with the exact approved numeric project identity, without an extra project lookup or mutable mapping.

Create a parameter file containing identifiers, not secrets:

```sh
cat > gcp-list.json <<'JSON'
{"project":"123456789012"}
JSON
opaque execute gcp.list_secrets --params-file gcp-list.json
```

The broker must have a matching sealed policy and any required native approval. `opaque init --interactive` can generate metadata-only starter rules after detecting the provider. Scope those rules to the intended project before authorizing a shared environment.

| Operation | Exact parameters | Returned data |
|---|---|---|
| `gcp.list_secrets` | `project` | Secret names |
| `gcp.get_secret` | `project`, `secret_id` | Resource name and creation time |
| `gcp.create_secret` | `project`, `secret_id` | Resource metadata; automatic replication is fixed |
| `gcp.add_secret_version` | `project`, `secret_id`, `value_ref` | Version name and state |

Write `value_ref` accepts `env:NAME` or `keychain:service/account`, with a 64 KiB payload limit. Profile expansion and nested provider references are rejected on this input so the prepared action contains every effective credential reference. Add write policies deliberately; onboarding does not grant them.

To consume an existing secret, use `gcp:123456789012/secret-name/1` as a credential reference in a separately authorized supported consumer. Omit the version for `latest`; configured Google version aliases are also accepted. Returned versions must still identify a positive numeric version. [Google version aliases](https://docs.cloud.google.com/secret-manager/docs/assign-alias-to-secret-version). `gcp.access_secret_version` is not a supported reveal operation.

## Verify the real integration

Use an isolated test project and an existing harmless test secret. First execute `gcp.list_secrets` and `gcp.get_secret`, then compare their identifiers with Google's API or console under an independent operator identity. To qualify writes, explicitly authorize a uniquely named test container, add a harmless value by reference, and verify the new version from Google. Resolve that value only through a consumer that emits a non-secret result; do not print the value in a test transcript.

Also verify a denied project, an identity lacking version-access permission, token expiry/rotation, and a broker policy denial. A policy denial should produce no Google request. Preserve the canonical source revision, broker receipt/request IDs and sanitized provider observations; cleanup of created cloud resources is a separate operator action.

Local protocol tests cover request construction, authentication, pagination, redirect rejection, malformed resource IDs, response limits, CRC32C and output redaction. They do not establish account permissions or a live Google execution. No real Google account was used for the source validation accompanying this implementation.

## Failure behavior

The client follows `nextPageToken` on the fixed list endpoint, returning an error rather than a partial success after repeated tokens, more than 40 pages or 4,000 items. JSON responses are limited to 256 KiB per page and token responses to 16 KiB. Every returned resource must match the requested project number and secret. Returned version IDs must be positive numbers; an exact numeric version request must match exactly. It verifies payload CRC32C when supplied and sends a checksum with writes. [Google list protocol](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/list), [payload integrity fields](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/SecretPayload).

HTTP redirects, ambient proxies and automatic retries are disabled. A transport failure during a write can leave the provider outcome unknown; inspect the provider before deliberately issuing another operation. Error messages omit response bodies, assertions, tokens and values.
