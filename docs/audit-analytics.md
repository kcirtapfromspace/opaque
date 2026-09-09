# Audit Log, Live Feed, and Analytics

You want three things simultaneously:

1. **Audit**: an append-only tamper-evident-ish record of what happened (requests, approvals, operations).
2. **Live feed**: a real-time stream for UI/monitoring (pending approvals, durations, outcomes).
3. **Analytics + semantic search**: fast queries and “find similar events” without leaking secret material.

This document combines the current audit contract below with proposed analytics architecture. Arrow/Parquet, LanceDB, location fields, and an internal broadcast feed described later are design proposals, not supported runtime capabilities.

## Current durability and retention contract

The daemon records audit events in SQLite with a keyed hash chain. Startup and retention verify existing history before maintenance; corruption stops startup rather than being signed again. Retention removes only an expired insertion-order prefix and authenticates its boundary without changing surviving record hashes. A clock regression can therefore keep an old-timestamp event beyond the retention period until the preceding live events expire. Export cursors remain monotonic even after the table is fully pruned.

Registered operation execution waits for audit durability before dispatch and before returning a successful payload. Bounded task execution also keeps its independent durable reservation and receipt ledger. An audit failure after an external effect cannot undo that effect: the caller receives an uncertain outcome and must inspect its receipt or audit evidence before acting again. Denials and diagnostic events remain asynchronous; they cannot authorize an effect. Persistence failures and queue losses remain visible for the lifetime of the sink; restarting requires investigating the missing evidence and underlying storage fault first.

CLI retries cover connection establishment only. Neither CLI nor MCP automatically replays a dispatched operation after a lost response or deadline. A request ID correlates evidence; it is not a general provider idempotency guarantee.

The chain depends on custody of its key and database. A process that can replace both can forge history. Preserve the database, WAL, and chain key when investigating integrity errors; do not edit rows or remove the key to force startup. Keep backups and exports under the same access controls as audit metadata.

## 1. Storage Strategy (Layered)

### System of record: SQLite (transactional)

- Primary store for:
  - audit events (append-only)
  - device pairings (public keys)
  - client identities (exe hashes, uid/gid)
  - provider metadata (non-secret config)
  - profiles (name -> secret refs)

SQLite gives durability, migrations, constraints, and low operational overhead.

### Analytics store: Arrow/Parquet dataset

- Periodically (or continuously) export/roll up audit events to Parquet files with a stable Arrow schema.
- This enables:
  - DuckDB queries
  - DataFusion queries
  - Python/R/BI tooling

Parquet is an Arrow-friendly, columnar, compressible format for long-term history.

### Semantic index: LanceDB (Arrow-native)

- Build an embeddings index over **sanitized** event text (no secret values, no raw locators).
- Store:
  - `event_id`
  - `ts`
  - `event_text` (sanitized)
  - `embedding` vector

LanceDB is a good fit specifically because it is Arrow-native and optimized for vector search.

## 2. Redaction Policy (Critical)

Audit/feeds become an exfiltration path if they contain sensitive data and are accessible to untrusted agent runtimes.

Rules:

- Never log plaintext secrets.
- Prefer not to log full secret locators (e.g., full Vault paths or 1Password item names) in LLM-visible channels.
- Treat these as sensitive metadata:
  - secret ref locators
  - repository names (sometimes)
  - cluster names/namespaces (sometimes)
  - exact URLs and response bodies from authenticated HTTP proxy ops

Recommended split:

- **Human audit stream**: richer detail (still no values).
- **Agent audit stream**: heavily minimized (operation name + high-level target category + outcome).

Enforce this by separating:

- transport (separate sockets/endpoints) and/or
- authorization (role gating per client identity).

## 3. Event Model

### Event taxonomy (suggested)

- `request.received`
- `policy.denied`
- `approval.required`
- `approval.presented`
- `approval.granted`
- `approval.denied`
- `operation.started`
- `operation.succeeded`
- `operation.failed`
- `provider.fetch.started` / `provider.fetch.finished` (metadata only)

### Correlation IDs

Every operation should carry a correlation chain:

- `request_id`: correlation identifier generated for a request; provider idempotency requires a separate explicit contract
- `approval_id`: approval request id (may be multiple if step-up)
- `event_id`: unique per event

### Minimal event fields (conceptual)

```rust
struct AuditEvent {
  event_id: String,           // uuid
  ts_utc_ms: i64,
  level: String,              // info|warn|error
  kind: String,               // request.received, approval.granted, ...
  request_id: Option<String>,
  approval_id: Option<String>,

  client: ClientSummary,      // observed uid/gid + exe hash + optional codesign
  operation: Option<String>,  // github.set_actions_secret, k8s.set_secret, ...
  target: Option<TargetSummary>,

  outcome: Option<String>,    // ok|denied|error
  latency_ms: Option<i64>,    // approval latency, op latency, etc

  // Optional and sensitive: store only when explicitly enabled.
  location: Option<Location>,

  // No secret values.
  // Avoid full locators by default; use stable ids or hashed references.
  secret_names: Vec<String>,  // e.g. ["JWT","DATABASE_URL"]
  secret_ref_ids: Vec<String> // e.g. hashed refs or profile keys
}
```

### Location (optional, privacy-sensitive)

Location can mean multiple things:

- iOS approval device location (requires explicit permission)
- network info (LAN IP, WiFi SSID) is often *more sensitive* than helpful

Recommendation:

- default: `location = None`
- opt-in: store coarse location only:
  - country/region if available, or
  - geohash with low precision, or
  - just “network = home/office” tags from user config

## 4. Live Feed

### Feed requirements

- near-real-time UI updates:
  - new requests
  - pending approvals
  - granted/denied
  - operation outcomes
- filtering:
  - by repo/project/cluster
  - by operation kind
  - by client identity

### Implementation shape

Internally:

- append each event to SQLite
- publish each event to an in-memory pubsub (e.g. `tokio::broadcast`)

Externally (pick one or more):

- UDS stream for local UI/CLI tail (`opaque tail --follow`)
- HTTP `localhost` endpoint using SSE for a web/desktop UI
- (later) Arrow Flight / FlightSQL stream for Arrow-native consumers

### Preventing side channels

Make sure untrusted agent clients cannot subscribe to the human feed by default.

## 5. Analytics

### Built-in metrics (daemon can compute)

- approvals:
  - count granted/denied
  - median approval latency
  - step-up frequency (local_bio only vs local_bio+ios_faceid)
- operations:
  - success/error rates by operation
  - p95 latency by operation kind
  - top targets (repo/project/cluster)

### Columnar analytics with Arrow/Parquet + DuckDB

For long-term analysis:

- export audit events to Parquet partitions:
  - partition by date (`dt=YYYY-MM-DD`)
  - optionally partition by `operation_family`

DuckDB can query these locally with high performance, including joins, group-bys, and window functions.

## 6. Semantic Search

### What to embed

Only embed a **sanitized** textual summary, e.g.:

- `"approval denied for github.set_actions_secret repo=org/repo env=prod secret=JWT client=claude-code"`

Never embed:

- secret values
- access tokens
- raw HTTP bodies
- full secret ref locators if you consider them sensitive

### Indexing pipeline

- emit `AuditEvent`
- derive `event_text_sanitized`
- compute embedding asynchronously (so approvals/operations are not blocked)
- upsert into LanceDB with `event_id` as primary key

### Queries

- `audit.search_semantic(query, limit)` returns:
  - event_ids + similarity scores + short snippet
- then fetch details from SQLite (role-gated and redacted appropriately)

## 7. Retention and Backpressure

Audit can grow without bound.

Recommended:

- SQLite retains recent window (e.g. 30-90 days)
- daemon retention cleanup purges SQLite rows older than the configured window
- older events can later be rolled to Parquet when that pipeline is enabled
- embeddings store follows the same retention window
- live feed uses bounded channels (drop-oldest or apply backpressure)
