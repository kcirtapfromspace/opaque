# Bitwarden Secrets Manager

Use a Bitwarden Secrets Manager secret in an approved operation without returning its value to the agent:

```bash
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name DATABASE_URL \
  --value-ref bitwarden:production/DATABASE_URL
```

Opaque invokes the official [`bws` CLI](https://bitwarden.com/help/secrets-manager-cli/) for machine-account authentication and secret decryption. Install a trusted official `bws` executable on the broker host before starting `opaqued`. This integration is for Secrets Manager machine accounts, not the separate Password Manager `bw` CLI. A missing executable leaves Bitwarden unavailable; other configured providers can still start.

## Configure the broker

Create a machine account with read access to the required projects and generate an access token in Bitwarden Secrets Manager. Store the token in a base secret store, such as the macOS Keychain item `opaque/bitwarden-token`, using your normal secure credential-entry workflow.

| Variable | Meaning | Default |
|----------|---------|---------|
| `OPAQUE_BITWARDEN_CLI_PATH` | Path to the installed official `bws` executable | Resolve `bws` from broker `PATH` at startup |
| `OPAQUE_BITWARDEN_TOKEN_REF` | Machine access token ref; `keychain:` and `env:` supported | `keychain:opaque/bitwarden-token` |
| `OPAQUE_BITWARDEN_URL` | Secrets Manager API endpoint | `https://api.bitwarden.com` |
| `OPAQUE_BITWARDEN_IDENTITY_URL` | Machine authentication endpoint | Derived for US, EU, or a self-hosted API URL ending in `/api` |

For EU hosting, set `OPAQUE_BITWARDEN_URL=https://api.bitwarden.eu`; the identity endpoint becomes `https://identity.bitwarden.eu`. For self-hosting, `https://secrets.example.com/api` derives `https://secrets.example.com/identity`. Other custom API endpoints require an explicit identity URL. HTTPS is required, including on loopback, to match the official CLI. Endpoint credentials, query strings and fragments are rejected.

Each invocation receives a private temporary configuration with explicit API and identity endpoints and `state_opt_out="true"`. Opaque clears inherited CLI configuration and passes the machine token only through the child's `BWS_ACCESS_TOKEN` environment. The token is absent from command arguments and the configuration file. Shared `bws` profiles, persistent login state and inherited proxy or custom CA environment variables are not used. Custom TLS trust must be installed in the host trust store supported by `bws`.

The broker pins the executable's resolved path and SHA-256 digest. Bitwarden browsing approvals bind that identity and both endpoints. Replacing the executable requires restarting the broker and reviewing the new prepared action. Commands time out after 30 seconds; output exceeding 16 MiB fails with a sanitized error. These bounds also apply to large project listings.

## Secret references

| Reference | Resolution |
|-----------|------------|
| `bitwarden:<secret-uuid>` | Read one non-nil UUID |
| `bitwarden:<project-name>/<secret-key>` | Find an exact project name and exact key, then read its UUID |

Duplicate matching project names or keys are rejected. Use UUID references when names are ambiguous. Secret whitespace is preserved.

Execution profile example:

```toml
[secrets]
DATABASE_URL = "bitwarden:production/DATABASE_URL"
API_KEY = "bitwarden:production/API_KEY"
```

## Browsing and policy

`bitwarden.list_projects` returns `{"projects":[{"name":"production"}]}`. `bitwarden.list_secrets` accepts an optional `project` name and returns `{"secrets":[{"key":"DATABASE_URL"}]}`. Both are `SAFE` metadata operations; IDs, notes and secret values are omitted from their results.

The official `bws secret list` response includes decrypted values. Opaque discards those fields inside the broker, zeroizes the captured response buffer, and returns only keys. Browsing therefore still requires trusting the broker host and installed executable with project contents.

`bitwarden.read_secret` is `REVEAL`: agent clients are always denied. Human use requires an explicit allow rule. Prefer refs in approved operations or execution profiles when plaintext output is unnecessary.

```toml
[[rules]]
name = "browse-bitwarden-projects"
operation_pattern = "bitwarden.list_projects"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300
```

Add a separate rule for `bitwarden.list_secrets` if needed. Provider writes such as `github.set_actions_secret` also require their own policy and approval.

## Validation

The regular tests use an explicitly created fake executable to check command arguments, configuration isolation, output limits, timeout handling, prepared-action binding, metadata sanitization and value transfer through the daemon. They do not prove successful authentication to a live Bitwarden account.

For opt-in live acceptance, install official `bws` and provision a disposable secret with a known SHA-256 digest. Supply these variables through a secure test environment:

- `OPAQUE_BITWARDEN_LIVE_ACCEPTANCE=1`
- `OPAQUE_BITWARDEN_LIVE_TOKEN`: dedicated machine access token
- `OPAQUE_BITWARDEN_LIVE_SECRET_ID`: disposable secret UUID
- `OPAQUE_BITWARDEN_LIVE_VALUE_SHA256`: lowercase SHA-256 of the exact value bytes
- The broker endpoint and executable variables above, if defaults do not apply

```bash
cargo test --locked -p opaque-providers --no-default-features --features bitwarden \
  bitwarden::client::tests::live_machine_authentication_and_secret_decryption \
  -- --ignored --exact
```

This test lists projects and reads the selected secret, verifies the decrypted value by digest, and prints neither the value nor token. It performs no provider writes. A passing fixture suite is not a recorded live acceptance run.
