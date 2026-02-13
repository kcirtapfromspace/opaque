# Plan: Phase 3 & Phase 4 — GitHub Provider + Memory Safety (US-013, US-014, US-015)

## Context

Phases 1-2 are complete (enclave, policy, audit, daemon hardening, approval UX, sandboxed exec). Phase 3 adds the first real provider integration (`github.set_actions_secret`), proving the full end-to-end pipeline: daemon resolves a secret ref, encrypts it with the repo's public key, and sets it via GitHub API — the CLI never sees the secret value. Phase 4 hardens memory lifetime of secrets.

---

## Phase 3: GitHub Actions Secrets (US-013 + US-014)

### Step 1: Add New Dependencies

**File:** `Cargo.toml` (workspace root)

```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
base64 = "0.22"
crypto_box = "0.9"
```

- `crypto_box` (pure Rust, RustCrypto) for NaCl sealed box encryption — no C/libsodium dependency
- `reqwest` with `rustls-tls` — no OpenSSL dependency
- `base64` for encoding encrypted values

**File:** `crates/opaqued/Cargo.toml` — add `reqwest`, `base64`, `crypto_box` as workspace deps

### Step 2: GitHub Crypto Module

**File:** `crates/opaqued/src/github/crypto.rs` (new)

```rust
pub fn encrypt_secret(plaintext: &[u8], public_key_b64: &str) -> Result<String, CryptoError>
```

Flow:
1. Base64-decode the repository public key (Curve25519)
2. Sealed box encrypt: `crypto_box::aead::seal(plaintext, &public_key)`
3. Base64-encode the ciphertext
4. Return base64 string for the API request

Tests: roundtrip encrypt/decrypt with generated keypair, invalid base64 key rejected, empty plaintext handled

### Step 3: GitHub API Client

**File:** `crates/opaqued/src/github/client.rs` (new)

```rust
pub struct GitHubClient {
    http: reqwest::Client,
    base_url: String,  // "https://api.github.com", overridable for tests
}

impl GitHubClient {
    pub fn new() -> Self;
    pub fn with_base_url(base_url: String) -> Self;  // for mock server tests

    pub async fn get_public_key(&self, token: &str, owner: &str, repo: &str)
        -> Result<PublicKeyResponse, GitHubApiError>;

    pub async fn set_secret(&self, token: &str, owner: &str, repo: &str,
        name: &str, encrypted_value: &str, key_id: &str)
        -> Result<SetSecretResponse, GitHubApiError>;
}
```

GitHub API flow:
- `GET /repos/{owner}/{repo}/actions/secrets/public-key` → `{key_id, key}` (base64 public key)
- `PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}` with `{encrypted_value, key_id}` → 201 Created / 204 No Content

Error types: `GitHubApiError` with variants for network, auth, not_found, rate_limited, server_error. **Never** leak raw API error messages to the client.

Tests: mock HTTP responses for success/failure, auth header presence, sanitized errors

### Step 4: GitHub Handler (OperationHandler)

**File:** `crates/opaqued/src/github/mod.rs` (new)

```rust
pub struct GitHubHandler {
    audit: Arc<dyn AuditSink>,
    client: GitHubClient,
}

impl OperationHandler for GitHubHandler {
    fn execute(&self, request: &OperationRequest) -> Pin<Box<dyn Future<...>>> {
        // 1. Extract params: repo (owner/repo), secret_name, value_ref
        // 2. Optional: github_token_ref (default: "keychain:opaque/github-pat")
        // 3. Optional: environment (for environment secrets vs repo secrets)
        // 4. REJECT raw values — value_ref must start with a known scheme (env:, keychain:, profile:)
        // 5. Resolve value_ref → actual secret via CompositeResolver
        // 6. Resolve GitHub PAT via CompositeResolver (github_token_ref)
        // 7. Emit SecretResolved audit events
        // 8. Call client.get_public_key()
        // 9. encrypt_secret(secret_value, public_key)
        // 10. Call client.set_secret()
        // 11. Return {status, repo, secret_name} — NEVER the value
    }
}
```

Reuses: `CompositeResolver` from `sandbox/resolve.rs` for resolving both the secret value and the GitHub PAT from OS keychain.

Tests: param validation (missing repo/name/ref rejected), raw value rejected, response has no secret data, audit events emitted

### Step 5: Extend Profile Resolution (US-014 completion)

**File:** `crates/opaqued/src/sandbox/resolve.rs`

Add `ProfileResolver` to `CompositeResolver`:

```rust
pub struct ProfileResolver;

impl SecretResolver for ProfileResolver {
    fn resolve(&self, ref_str: &str) -> Result<String, ResolveError> {
        // Parse "profile:<name>:<key>"
        // Load ~/.opaque/profiles/<name>.toml via load_named_profile()
        // Look up <key> in profile.secrets HashMap
        // Resolve the underlying ref (env:, keychain:) via base resolver
        // Cycle prevention: the base resolver excludes ProfileResolver
    }
}
```

Update `CompositeResolver` to dispatch `profile:` prefix → `ProfileResolver`.

Profile infrastructure already exists from Phase 2:
- `ExecProfile` struct + `load_named_profile()` in `opaque-core/src/profile.rs`
- `opaque profile list/show/validate` CLI commands
- `~/.opaque/profiles/<name>.toml` directory structure

The missing piece is the `profile:` ref scheme in the secret resolver.

Tests: `profile:myapp:JWT` resolves through profile, missing profile/key errors, cycle prevention

### Step 6: Register Operation + Wire in Daemon

**File:** `crates/opaqued/src/main.rs`

```rust
// Add mod github;
registry.register(OperationDef {
    name: "github.set_actions_secret".into(),
    safety: OperationSafety::Safe,
    default_approval: ApprovalRequirement::Always,
    default_factors: vec![ApprovalFactor::LocalBio],
    description: "Set a GitHub Actions repository secret".into(),
    params_schema: Some(serde_json::json!({
        "type": "object",
        "required": ["repo", "secret_name", "value_ref"],
        "properties": {
            "repo": {"type": "string"},
            "secret_name": {"type": "string"},
            "value_ref": {"type": "string"},
            "github_token_ref": {"type": "string"},
            "environment": {"type": "string"}
        }
    })),
    allowed_target_keys: vec!["repo".into()],
});

// Wire handler
.handler("github.set_actions_secret", Box::new(github_handler))
```

Add `"github"` method in `handle_request` as convenience wrapper (same pattern as `"exec"`):
- Validates `repo` format (`owner/repo`)
- Validates `secret_name` (alphanumeric + underscores)
- Validates `value_ref` starts with known scheme
- Builds `OperationRequest` with operation `"github.set_actions_secret"`

### Step 7: CLI `github` Subcommand

**File:** `crates/opaque/src/main.rs`

```rust
Github {
    #[command(subcommand)]
    action: GithubAction,
},

enum GithubAction {
    SetSecret {
        #[arg(long)]
        repo: String,          // "owner/repo"
        #[arg(long)]
        secret_name: String,   // "AWS_ACCESS_KEY_ID"
        #[arg(long)]
        value_ref: String,     // "keychain:opaque/aws-key" or "profile:prod:AWS_KEY"
        #[arg(long)]
        github_token_ref: Option<String>,  // default: "keychain:opaque/github-pat"
        #[arg(long)]
        environment: Option<String>,  // for environment secrets
    },
}
```

Sends `{"method": "github", "params": {...}}` to daemon.

---

## Phase 4: Memory Safety Hardening (US-015)

### Step 8: Add `zeroize` Dependency

**File:** `Cargo.toml` (workspace)
```toml
zeroize = { version = "1.8", features = ["derive"] }
```

**File:** `crates/opaqued/Cargo.toml` — add `zeroize = { workspace = true }`

### Step 9: Core Dump Prevention

**File:** `crates/opaqued/src/main.rs`

Add `init_memory_safety()` called early in `run()`, before any secret operations:

```rust
fn init_memory_safety() {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        tracing::info!("core dumps disabled (PR_SET_DUMPABLE=0)");
    }
    #[cfg(target_os = "macos")]
    {
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        tracing::info!("core dumps disabled (RLIMIT_CORE=0)");
    }
}
```

### Step 10: SecretValue Wrapper

**File:** `crates/opaqued/src/secret.rs` (new)

```rust
use zeroize::Zeroizing;

/// A secret value automatically zeroed on drop.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(data: Vec<u8>) -> Self;
    pub fn from_string(s: String) -> Self;
    pub fn as_bytes(&self) -> &[u8];
    pub fn as_str(&self) -> Option<&str>;
    pub fn mlock(&self);  // best-effort, logs warning on failure
}

impl Debug for SecretValue { fn fmt(..) { write!(f, "[REDACTED]") } }
impl Display for SecretValue { fn fmt(..) { write!(f, "[REDACTED]") } }
```

### Step 11: Thread SecretValue Through Resolvers

Update `SecretResolver` trait return type: `Result<String, ResolveError>` → `Result<SecretValue, ResolveError>`

Update all implementations:
- `EnvResolver::resolve` → wrap result in `SecretValue::from_string`
- `KeychainResolver::resolve` → wrap result in `SecretValue::from_string`
- `ProfileResolver::resolve` → wrap
- `resolve_all` → returns `HashMap<String, SecretValue>`
- `SandboxExecutor::build_env` → extract string from SecretValue for env injection
- `GitHubHandler::execute` → use SecretValue, extract bytes for encryption, zeroed on drop

Tests: Debug shows [REDACTED], Display shows [REDACTED], value zeroed on drop, mlock failure doesn't panic

---

## Files Summary

| File | Action | Phase |
|------|--------|-------|
| `Cargo.toml` | Add `reqwest`, `base64`, `crypto_box`, `zeroize` workspace deps | 3+4 |
| `crates/opaqued/Cargo.toml` | Add new deps | 3+4 |
| `crates/opaqued/src/github/mod.rs` | **New**: `GitHubHandler` implementing OperationHandler | 3 |
| `crates/opaqued/src/github/client.rs` | **New**: GitHub REST API client | 3 |
| `crates/opaqued/src/github/crypto.rs` | **New**: NaCl sealed box encryption | 3 |
| `crates/opaqued/src/sandbox/resolve.rs` | Add `ProfileResolver`, extend `CompositeResolver` | 3 |
| `crates/opaqued/src/main.rs` | Register `github.set_actions_secret`, `"github"` method, `init_memory_safety()` | 3+4 |
| `crates/opaque/src/main.rs` | Add `Github` subcommand | 3 |
| `crates/opaqued/src/secret.rs` | **New**: `SecretValue` zeroizing wrapper | 4 |

## Existing Code to Reuse

- `OperationHandler` trait (`enclave.rs:310-327`)
- `CompositeResolver` + `SecretResolver` trait (`sandbox/resolve.rs`)
- `KeychainResolver` (`sandbox/resolve.rs:64-158`) — for GitHub PAT retrieval
- `OperationRegistry::register()` (`operation.rs`)
- `Enclave::execute()` pipeline (`enclave.rs:496-713`)
- `AuditEventKind::SecretResolved` (`audit.rs`) — already exists
- `ExecProfile` + `load_named_profile()` (`profile.rs`) — for profile: refs
- `InputValidator` (`validate.rs`) — validate repo/secret names
- `handle_request` "exec" method pattern (`main.rs:1158-1210`) — copy for "github"
- `InMemoryAuditEmitter` (`audit.rs`) — for tests

## Implementation Order

1. Add workspace deps (reqwest, base64, crypto_box, zeroize)
2. GitHub crypto module (sealed box encryption + tests)
3. GitHub API client (+ mock tests)
4. GitHub handler (OperationHandler impl + tests)
5. Profile resolver extension (+ tests)
6. Register operation + wire in daemon
7. CLI github subcommand
8. SecretValue wrapper + init_memory_safety() (Phase 4)
9. Thread SecretValue through resolvers + handlers
10. Final: cargo test + clippy + fmt

## Verification

1. `cargo build --workspace` — compiles on macOS and Linux
2. `cargo test --workspace` — all existing + new tests pass
3. `cargo clippy --workspace` — zero warnings
4. Unit: crypto roundtrip, API client mock, handler param validation, profile resolver
5. Integration: daemon + CLI with mock GitHub API
6. Verify response never contains secret values or ciphertext
7. Verify SecretValue Debug/Display shows `[REDACTED]`
8. Verify audit trail shows full event chain for github.set_actions_secret
9. Verify core dump prevention is active
