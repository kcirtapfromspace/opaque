# Plan: Complete GitHub Secret Types (Actions Env, Codespaces, Dependabot, Org)

## Context

v1 shipped `github.set_actions_secret` for repo-level secrets only. The `environment` param is accepted by the CLI but ignored by the handler. The architecture doc says "GitHub scopes: support repo secrets and environment secrets (v1)". The v2 roadmap lists Codespaces secrets as "Small" effort. Since all GitHub secret types use the same NaCl sealed box encryption and nearly identical API patterns, we implement them all in one pass.

## Scope: 5 Features

| # | Feature | Operation | Status |
|---|---------|-----------|--------|
| 1 | Environment Actions secrets | `github.set_actions_secret` (existing, route by `environment` param) | CLI accepts param, handler ignores it |
| 2 | Codespaces secrets (user-level) | `github.set_codespaces_secret` | New |
| 3 | Codespaces secrets (repo-level) | `github.set_codespaces_secret` (same op, `repo` param present) | New |
| 4 | Dependabot secrets | `github.set_dependabot_secret` | New |
| 5 | Org-level Actions secrets | `github.set_org_secret` | New |

## Design Decisions

1. **Separate operations** — Codespaces/Dependabot/Org get their own operation names for distinct approval policies and target keys
2. **One `GitHubHandler`** registered 4 times, dispatches by `request.operation`
3. **`SecretScope` enum** in client.rs generates correct endpoint paths for all 6 API patterns
4. **Shared `set_secret_flow()` helper** — extracts the 7-step core (validate → resolve → audit → get key → encrypt → PUT → audit)
5. **`scope` param on `"github"` method** — defaults to `"repo_actions"` for backward compat

## API Endpoints (all same NaCl sealed box encryption)

| Scope | Public Key | Set Secret |
|-------|-----------|------------|
| Repo Actions | `GET /repos/{o}/{r}/actions/secrets/public-key` | `PUT /repos/{o}/{r}/actions/secrets/{name}` |
| Env Actions | `GET /repos/{o}/{r}/environments/{env}/secrets/public-key` | `PUT /repos/{o}/{r}/environments/{env}/secrets/{name}` |
| Codespaces User | `GET /user/codespaces/secrets/public-key` | `PUT /user/codespaces/secrets/{name}` |
| Codespaces Repo | `GET /repos/{o}/{r}/codespaces/secrets/public-key` | `PUT /repos/{o}/{r}/codespaces/secrets/{name}` |
| Dependabot | `GET /repos/{o}/{r}/dependabot/secrets/public-key` | `PUT /repos/{o}/{r}/dependabot/secrets/{name}` |
| Org Actions | `GET /orgs/{org}/actions/secrets/public-key` | `PUT /orgs/{org}/actions/secrets/{name}` |

Codespaces user + Org PUT payloads include extra fields: `selected_repository_ids` (array), Org also `visibility` ("all"|"private"|"selected").

---

## Implementation Steps

### Step 1: `SecretScope` enum + scoped client methods

**File:** `crates/opaqued/src/github/client.rs`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretScope<'a> {
    RepoActions { owner: &'a str, repo: &'a str },
    EnvActions { owner: &'a str, repo: &'a str, environment: &'a str },
    CodespacesUser,
    CodespacesRepo { owner: &'a str, repo: &'a str },
    Dependabot { owner: &'a str, repo: &'a str },
    OrgActions { org: &'a str },
}

impl SecretScope {
    fn public_key_path(&self) -> String { ... }
    fn set_secret_path(&self, name: &str) -> String { ... }
    pub fn display_target(&self) -> String { ... }  // for error messages, never includes secrets
}
```

Add `get_public_key_scoped()` and `set_secret_scoped()` methods. The set method takes `extra_body: Option<serde_json::Value>` for `selected_repository_ids`/`visibility`.

Keep existing `get_public_key()` / `set_secret()` as wrappers delegating to scoped versions (existing tests stay green).

Tests: path generation for all 6 variants, display_target, scoped method delegation.

### Step 2: Validation helpers

**File:** `crates/opaqued/src/github/mod.rs`

```rust
fn validate_environment_name(name: &str) -> Result<(), String>  // alphanumeric, hyphens, underscores, dots, 1-255
fn validate_org_name(org: &str) -> Result<(), String>           // alphanumeric, hyphens, 1-39 chars
```

Tests: valid/empty/invalid for each.

### Step 3: Refactor handler — extract shared flow + dispatch by operation

**File:** `crates/opaqued/src/github/mod.rs`

Refactor `execute()` to dispatch:
```rust
match request.operation.as_str() {
    "github.set_actions_secret" => self.handle_actions_secret(...)
    "github.set_codespaces_secret" => self.handle_codespaces_secret(...)
    "github.set_dependabot_secret" => self.handle_dependabot_secret(...)
    "github.set_org_secret" => self.handle_org_secret(...)
}
```

Extract shared `set_secret_flow()`:
```rust
async fn set_secret_flow(&self, request_id, scope, secret_name, value_ref,
    github_token_ref, operation_name, audit, extra_body) -> Result<Value, String>
```

**Environment support:** `handle_actions_secret` checks `environment` param → `SecretScope::EnvActions` vs `SecretScope::RepoActions`.

### Step 4: Implement sub-handlers

**File:** `crates/opaqued/src/github/mod.rs`

- `handle_codespaces_secret`: `repo` optional (user vs repo scope), accepts `selected_repository_ids`
- `handle_dependabot_secret`: requires `repo`
- `handle_org_secret`: requires `org` (not `repo`), accepts `visibility` + `selected_repository_ids`

Response shapes vary:
- Repo/Dependabot: `{ status, repo, secret_name }`
- Env: `{ status, repo, environment, secret_name }`
- Codespaces user: `{ status, scope: "user", secret_name }`
- Codespaces repo: `{ status, repo, secret_name }`
- Org: `{ status, org, secret_name }`

Tests: missing param rejected for each, correct scope routing, valid responses.

### Step 5: Register operations + wire handlers

**File:** `crates/opaqued/src/main.rs`

Register 3 new operations:
- `github.set_codespaces_secret` — `secret_name` + `value_ref` required, `repo` optional, `allowed_target_keys: ["repo"]`
- `github.set_dependabot_secret` — `repo` + `secret_name` + `value_ref` required, `allowed_target_keys: ["repo"]`
- `github.set_org_secret` — `org` + `secret_name` + `value_ref` required, `allowed_target_keys: ["org"]`

Wire 4 `GitHubHandler` instances (one per operation name, cheap — just `Arc<AuditSink>` + `reqwest::Client` clone).

### Step 6: Update `"github"` convenience method with `scope` routing

**File:** `crates/opaqued/src/main.rs`

Add `scope` param routing (default: `"repo_actions"`):
- `repo_actions` / `env_actions` → `github.set_actions_secret`
- `codespaces_user` / `codespaces_repo` → `github.set_codespaces_secret`
- `dependabot` → `github.set_dependabot_secret`
- `org_actions` → `github.set_org_secret`

Target map: `org_actions` → `{"org": ...}`, `codespaces_user` → `{}`, others → `{"repo": ...}`.

### Step 7: CLI subcommands

**File:** `crates/opaque/src/main.rs`

Add to `GithubAction` enum:
- `SetCodespacesSecret` — `--repo` (optional), `--secret-name`, `--value-ref`, `--selected-repository-ids`
- `SetDependabotSecret` — `--repo`, `--secret-name`, `--value-ref`
- `SetOrgSecret` — `--org`, `--secret-name`, `--value-ref`, `--visibility` (default "private"), `--selected-repository-ids`

Each sends `method: "github"` with appropriate `scope`.

### Step 8: Final verification

`cargo fmt --all && cargo clippy --workspace && cargo test --workspace`

---

## Files Summary

| File | Action |
|------|--------|
| `crates/opaqued/src/github/client.rs` | Add `SecretScope`, scoped methods, refactor existing as wrappers |
| `crates/opaqued/src/github/mod.rs` | Dispatch by operation, extract shared flow, validation helpers, sub-handlers |
| `crates/opaqued/src/github/crypto.rs` | No changes |
| `crates/opaqued/src/main.rs` | Register 3 new operations, update `"github"` method with scope routing |
| `crates/opaque/src/main.rs` | Add 3 CLI subcommands |

## Existing Code to Reuse

- `encrypt_secret()` — `crates/opaqued/src/github/crypto.rs`
- `validate_repo()`, `validate_secret_name()`, `validate_value_ref()` — `crates/opaqued/src/github/mod.rs`
- `CompositeResolver` — `crates/opaqued/src/sandbox/resolve.rs`
- `ALLOWED_REF_SCHEMES` — `crates/opaque-core/src/profile.rs`
- `GitHubClient` base infrastructure — `crates/opaqued/src/github/client.rs`
- Operation registration pattern — `crates/opaqued/src/main.rs:271-315`
- CLI subcommand pattern — `crates/opaque/src/main.rs:152-175`

## Verification

1. `cargo build --workspace` compiles
2. `cargo test --workspace` — all existing + new tests pass
3. `cargo clippy --workspace` — zero warnings
4. `cargo fmt --check` — clean
5. `SecretScope` generates correct paths for all 6 endpoint variants
6. Environment param routes `github.set_actions_secret` to env endpoint
7. Missing required params rejected for each new operation
8. Unknown scope rejected in `"github"` method
9. Default scope (no field) = `repo_actions` (backward compat)
10. Org operation uses `"org"` target key, not `"repo"`
11. Responses never contain secret values or ciphertext
