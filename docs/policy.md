# Policy (v1)

Opaque uses a deny-by-default allowlist policy enforced by the daemon (`opaqued`) inside `Enclave::execute()`.

Rules are evaluated in order; the **first matching rule wins**. If no rule matches, the request is denied.

The policy lives in the daemon config file:

- `OPAQUE_CONFIG` (if set)
- otherwise `~/.opaque/config.toml`

## Client Type (Human vs Agent)

`opaqued` classifies each connecting client as:

- `human`: matches an entry in `known_human_clients`
- `agent`: everything else (default)

This classification is derived from peer credentials + executable identity and is **never** accepted from client-provided params.

## Daemon Config Schema

Top-level fields:

- `known_human_clients` (optional): list of allowlisted human executables
- `rules` (optional): policy rules (deny-all when empty)
- `audit_retention_days` (optional): SQLite retention window (default: 90)

### `known_human_clients`

Each entry matches when **all specified fields match**. Unspecified fields are treated as "any":

- `exe_path`: glob match on executable path
- `exe_sha256`: exact SHA-256 hex digest
- `codesign_team_id`: exact macOS Team ID

Empty entries are rejected by the daemon (would match everything).

Example:

```toml
[[known_human_clients]]
name = "Opaque CLI"
exe_path = "*/target/release/opaque"
```

## Rule Schema

Each `[[rules]]` has:

- `name`: label (used in audit)
- `operation_pattern`: glob (ex: `"github.*"`, `"sandbox.exec"`)
- `allow`: `true` to allow, `false` to explicitly deny
- `client_types`: `["human"]`, `["agent"]`, or both (empty means "all")

Nested tables:

- `[rules.client]`: match on client identity (`uid`, `exe_path`, `exe_sha256`, `codesign_team_id`)
- `[rules.target]`: match on operation target fields (glob patterns)
- `[rules.workspace]`: match on git workspace context (`remote_url_pattern`, `branch_pattern`, `require_clean`)
- `[rules.secret_names]`: constrain referenced secret *names* (not values) via glob patterns
- `[rules.approval]`: operation-bound approval requirements

### Approval Configuration

`[rules.approval]` fields:

- `require`: `always` | `first_use` | `never`
- `factors`: approval factors (any-of). v1 supports `local_bio`
- `lease_ttl`: seconds (optional; for `first_use`)
- `one_time`: bool (optional; defaults to `false`)

Deferred factors exist in types but are out of scope for v1:

- `ios_faceid` (v3)
- `fido2` (v3)

## Example Policy File

This is a minimal, working config that:

1. Allows `github.set_actions_secret` for a repo prefix, with first-use approval + 5 minute lease
2. Allows `sandbox.exec` with approval every time

```toml
audit_retention_days = 90

[[rules]]
name = "allow-agent-github-actions-secrets"
operation_pattern = "github.set_actions_secret"
allow = true
client_types = ["agent"]

[rules.client]

[rules.target]
fields = { repo = "myorg/*" }

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300

[[rules]]
name = "allow-agent-sandbox-exec"
operation_pattern = "sandbox.exec"
allow = true
client_types = ["agent"]

[rules.client]

[rules.approval]
require = "always"
factors = ["local_bio"]
```

For more examples, see `examples/policy.toml`.

Tip: to allow all GitHub secret-setting operations, use an `operation_pattern` like `github.set_*_secret` (or `github.*`) and constrain targets (`repo`, `org`) as needed.
