# Storage & Data Model (Broker-First)

Opaque is a **broker**, not a general purpose secret key/value store. The persistent data model should therefore store:

- references, identities, policies, approvals, and audit history
- provider connection metadata (non-secret)
- paired device public keys

and explicitly **must not** store plaintext secret values.

## 1. Storage Layers (Recommended)

### 1.1 In-Memory Only (never persisted)

- plaintext secret material fetched from providers (bytes)
- pending approval requests (nonces, request summaries)
- short-lived approval leases/capabilities (optional to persist; safer to keep in-memory)

If `opaqued` restarts, it is acceptable (and safer) to require re-approval.

### 1.2 OS Credential Store (Keychain / Secret Service)

Use the OS store for **credentials and private keys**:

- GitHub/GitLab credentials (PATs) if you choose to store them locally
- Vault tokens / 1Password service tokens (if stored)
- Opaque server identity private key (used for iOS pairing/transport)
- optional: a database encryption key (see below)

macOS: Keychain
Linux: Secret Service (freedesktop) where available; otherwise a file-backed keystore with strict perms (v1 fallback).

### 1.3 Local Database (SQLite)

Use SQLite for durable **metadata + audit**:

- append-only audit log
- client identities (what binary called, uid/gid, hash)
- paired mobile devices (public keys)
- provider accounts (non-secret config, labels)
- profiles (name -> secret refs mapping)
- operation receipts (optional: last sync status for UX)

Why SQLite:

- single-user local daemon workload fits perfectly
- strong consistency, easy migrations, good tooling
- no external service dependency

For audit analytics and semantic search, see `docs/audit-analytics.md`.

### 1.3.1 Why Not DuckDB or LanceDB As The Primary Store?

- DuckDB:
  - excellent embedded analytics engine (OLAP)
  - not the typical choice as a system-of-record for transactional metadata (policy, devices, approvals, migrations)
  - good fit as a secondary *read-only* analytics layer for large audit exports (Parquet) or ad-hoc queries
- LanceDB:
  - great when you need vector similarity search (embeddings)
  - adds significant dependency surface area and is usually unnecessary for a broker's core metadata/audit needs
  - consider only if you explicitly want semantic search over audit events/policies (and keep it out of the approval/execution path)

### 1.4 Human-Readable Config Files (TOML)

Keep policy and profiles in files when you want them to be reviewable and possibly checked into a repo:

- policy allowlists (clients/ops/targets/factors)
- profile mappings (env var names -> secret refs)

These files can contain sensitive metadata (Vault paths, 1Password item names). They should be protected by file permissions and optionally kept out of repos.

## 2. Encryption at Rest (Practical Options)

Baseline:

- rely on OS full-disk encryption (FileVault/LUKS) + strict directory/file perms (`0700` dirs, `0600` files)

Stronger:

- encrypt selected columns in SQLite (app-level AES-GCM) using a key stored in OS credential store
- avoid SQLCipher until you truly need it (adds build/packaging complexity across macOS+Linux)

Given you are not storing secret values, encryption is mostly about protecting:

- secret references (paths/locators)
- audit trail (targets, repos, clusters)
- device pairing metadata

## 3. Core Types (Conceptual)

### 3.1 Secret reference

The key design choice: store a *ref*, not the value.

```rust
struct SecretRef {
  provider: String,  // "vault", "1password", "aws_sso", ...
  locator: String,   // opaque provider-specific identifier
}
```

Examples:

- `vault://kv/myapp#JWT`
- `op://Prod API/item#field`
- `profile:myapp:JWT` (resolved server-side)

### 3.2 Operation request (what gets approved + audited)

```rust
struct OperationRequest {
  request_id: String,           // random, idempotency key
  client: ClientIdentity,       // observed over UDS peer creds + exe hash
  operation: String,            // "github.set_actions_secret"
  target: serde_json::Value,    // repo/env/cluster/ns/etc
  secret_refs: Vec<SecretRef>,  // refs only
  created_at: i64,
  expires_at: i64,
}
```

### 3.3 Approval decision

```rust
struct ApprovalDecision {
  approved: bool,
  factor: String,               // "local_bio" | "ios_faceid" | ...
  decided_at: i64,
  lease_ttl_secs: u32,          // optional
}
```

## 4. SQLite Schema (Suggested v1)

This is intentionally "metadata + audit", not secret values.

### 4.1 `clients`

- last-seen cache for policy and UX

Fields:

- `id` (pk)
- `uid`, `gid`
- `exe_path`
- `exe_sha256`
- `codesign_team_id` (macOS optional)
- `created_at`, `last_seen_at`

### 4.2 `paired_devices`

- store device public key only (Secure Enclave private key stays on device)

Fields:

- `id` (pk)
- `kind` (`ios`)
- `device_pubkey` (blob/base64)
- `device_name`
- `added_at`
- `revoked_at` nullable

### 4.3 `providers`

Fields:

- `id` (pk)
- `kind` (`vault`, `1password`, ...)
- `label`
- `config_json` (non-secret)
- `created_at`, `updated_at`

### 4.4 `profiles`

Fields:

- `id` (pk)
- `name` (unique)
- `mapping_json` (env var name -> SecretRef string)
- `created_at`, `updated_at`

### 4.5 `audit_events` (append-only)

Fields:

- `id` (pk)
- `ts`
- `client_id`
- `request_id`
- `operation`
- `target_json`
- `secret_ref_names` (optional, avoid storing full locators if you consider them too sensitive)
- `approval_factors_json`
- `outcome` (`ok`/`denied`/`error`)
- `error_code`, `error_message` (sanitized)

You can keep this as the canonical history instead of adding many “state” tables.

## 5. What NOT To Store

- plaintext secrets
- ciphertext that is trivially replayable to reveal secrets in an external system
- raw HTTP request/response bodies from authenticated proxy operations (unless explicitly scrubbed)

If a feature requires caching secret material, treat it as a design smell and revisit (prefer provider-side leases like Vault).
