//! Audit event model and emission.
//!
//! Every operation, approval, and policy decision emits structured audit events.
//! Events carry correlation IDs ([`request_id`], [`approval_id`], [`event_id`])
//! for end-to-end tracing.
//!
//! Secret values NEVER appear in audit events.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::operation::{ClientIdentity, ClientType, OperationSafety};
use crate::policy::PolicyDecision;

// ---------------------------------------------------------------------------
// Audit event kind
// ---------------------------------------------------------------------------

/// The kind of audit event. Maps to the event taxonomy in `docs/audit-analytics.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A new operation request was received by the daemon.
    RequestReceived,

    /// The policy engine denied the request.
    PolicyDenied,

    /// An approval is required before the operation can proceed.
    ApprovalRequired,

    /// An approval challenge was presented to the user.
    ApprovalPresented,

    /// The user granted approval.
    ApprovalGranted,

    /// The user denied approval (or it timed out).
    ApprovalDenied,

    /// The operation handler has started execution.
    OperationStarted,

    /// The operation completed successfully.
    OperationSucceeded,

    /// The operation failed.
    OperationFailed,

    /// A provider fetch (secret retrieval) has started.
    ProviderFetchStarted,

    /// A provider fetch has completed.
    ProviderFetchFinished,

    /// A request was rate-limited.
    RateLimited,

    /// An approval lease was reused (FirstUse within TTL).
    LeaseHit,

    /// A sandbox environment was created for command execution.
    SandboxCreated,

    /// A sandboxed command execution completed.
    SandboxCompleted,

    /// A secret reference was resolved (value never logged).
    SecretResolved,
}

impl fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RequestReceived => "request.received",
            Self::PolicyDenied => "policy.denied",
            Self::ApprovalRequired => "approval.required",
            Self::ApprovalPresented => "approval.presented",
            Self::ApprovalGranted => "approval.granted",
            Self::ApprovalDenied => "approval.denied",
            Self::OperationStarted => "operation.started",
            Self::OperationSucceeded => "operation.succeeded",
            Self::OperationFailed => "operation.failed",
            Self::ProviderFetchStarted => "provider.fetch.started",
            Self::ProviderFetchFinished => "provider.fetch.finished",
            Self::RateLimited => "rate.limited",
            Self::LeaseHit => "lease.hit",
            Self::SandboxCreated => "sandbox.created",
            Self::SandboxCompleted => "sandbox.completed",
            Self::SecretResolved => "secret.resolved",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for AuditEventKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "request.received" => Ok(Self::RequestReceived),
            "policy.denied" => Ok(Self::PolicyDenied),
            "approval.required" => Ok(Self::ApprovalRequired),
            "approval.presented" => Ok(Self::ApprovalPresented),
            "approval.granted" => Ok(Self::ApprovalGranted),
            "approval.denied" => Ok(Self::ApprovalDenied),
            "operation.started" => Ok(Self::OperationStarted),
            "operation.succeeded" => Ok(Self::OperationSucceeded),
            "operation.failed" => Ok(Self::OperationFailed),
            "provider.fetch.started" => Ok(Self::ProviderFetchStarted),
            "provider.fetch.finished" => Ok(Self::ProviderFetchFinished),
            "rate.limited" => Ok(Self::RateLimited),
            "lease.hit" => Ok(Self::LeaseHit),
            "sandbox.created" => Ok(Self::SandboxCreated),
            "sandbox.completed" => Ok(Self::SandboxCompleted),
            "secret.resolved" => Ok(Self::SecretResolved),
            _ => Err(format!("unknown audit event kind: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit error type
// ---------------------------------------------------------------------------

/// Errors from the SQLite audit backend.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Client summary (safe for audit)
// ---------------------------------------------------------------------------

/// A summary of the client identity, safe for inclusion in audit events.
/// Does not contain secrets or full hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSummary {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    pub exe_path: Option<String>,
    /// Truncated hash prefix (first 16 hex chars) for identification without
    /// full disclosure.
    pub exe_sha256_prefix: Option<String>,
    pub codesign_team_id: Option<String>,
    pub client_type: ClientType,
}

impl From<(&ClientIdentity, ClientType)> for ClientSummary {
    fn from((id, ct): (&ClientIdentity, ClientType)) -> Self {
        Self {
            uid: id.uid,
            gid: id.gid,
            pid: id.pid,
            exe_path: id
                .exe_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            exe_sha256_prefix: id.exe_sha256.as_ref().map(|h| {
                let len = h.len().min(16);
                h[..len].to_owned()
            }),
            codesign_team_id: id.codesign_team_id.clone(),
            client_type: ct,
        }
    }
}

// ---------------------------------------------------------------------------
// Target summary (safe for audit)
// ---------------------------------------------------------------------------

/// A summary of the operation target, safe for audit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetSummary {
    /// Key-value pairs describing the target (e.g. repo, cluster, namespace).
    pub fields: std::collections::HashMap<String, String>,
}

impl TargetSummary {
    /// Create a sanitized target summary by scrubbing URLs and redacting
    /// secret patterns in all values.
    pub fn sanitized(target: &std::collections::HashMap<String, String>) -> Self {
        let patterns = crate::sanitize::SecretPatterns::compile();
        let fields = target
            .iter()
            .map(|(k, v)| {
                let scrubbed = crate::sanitize::scrub_urls(v);
                let redacted = patterns.redact(&scrubbed);
                (k.clone(), redacted)
            })
            .collect();
        Self { fields }
    }
}

// ---------------------------------------------------------------------------
// Workspace summary (safe for audit)
// ---------------------------------------------------------------------------

/// A summary of the workspace context, safe for inclusion in audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    /// Git remote URL.
    pub remote_url: Option<String>,
    /// Current branch name.
    pub branch: Option<String>,
    /// Whether the working tree is dirty.
    pub dirty: bool,
}

impl WorkspaceSummary {
    /// Create a sanitized workspace summary, stripping userinfo from the
    /// remote URL.
    pub fn sanitized(ws: &crate::operation::WorkspaceContext) -> Self {
        Self {
            remote_url: ws
                .remote_url
                .as_deref()
                .map(crate::validate::InputValidator::sanitize_url),
            branch: ws.branch.clone(),
            dirty: ws.dirty,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// A structured audit event.
///
/// Fields align with the schema in `docs/audit-analytics.md`.
/// Secret values NEVER appear here.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub event_id: Uuid,

    /// Monotonically increasing sequence number assigned by the emitter.
    pub sequence_number: u64,

    /// UTC timestamp in milliseconds since epoch.
    pub ts_utc_ms: i64,

    /// Event severity level.
    pub level: AuditLevel,

    /// The kind of event.
    pub kind: AuditEventKind,

    /// Correlation: end-to-end request identifier.
    pub request_id: Option<Uuid>,

    /// Correlation: approval request identifier (may differ per step-up).
    pub approval_id: Option<Uuid>,

    /// Client summary.
    pub client: Option<ClientSummary>,

    /// Operation name (e.g. `"github.set_actions_secret"`).
    pub operation: Option<String>,

    /// Operation safety classification.
    pub safety: Option<OperationSafety>,

    /// Target summary.
    pub target: Option<TargetSummary>,

    /// Outcome string: `"ok"`, `"denied"`, `"error"`.
    pub outcome: Option<String>,

    /// Latency in milliseconds (approval latency, operation latency, etc.).
    pub latency_ms: Option<i64>,

    /// Secret variable names referenced (never values).
    pub secret_names: Vec<String>,

    /// Policy decision summary (for policy events).
    pub policy_decision: Option<String>,

    /// Human-readable detail message (sanitized).
    pub detail: Option<String>,

    /// Workspace summary (git repo/branch info).
    pub workspace: Option<WorkspaceSummary>,

    /// SHA-256 content hash of the operation request (for approval binding).
    /// Not secret — safe for display and audit.
    pub request_hash: Option<String>,
}

// Custom Debug to avoid any accidental leakage.
impl fmt::Debug for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEvent")
            .field("event_id", &self.event_id)
            .field("sequence_number", &self.sequence_number)
            .field("kind", &self.kind)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("outcome", &self.outcome)
            .field("latency_ms", &self.latency_ms)
            .field("request_hash", &self.request_hash)
            .finish()
    }
}

/// Severity level for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    Info,
    Warn,
    Error,
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditEvent builder
// ---------------------------------------------------------------------------

impl AuditEvent {
    /// Create a new audit event with the given kind. Timestamps and event_id
    /// are set automatically.
    pub fn new(kind: AuditEventKind) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();

        Self {
            event_id: Uuid::new_v4(),
            sequence_number: 0,
            ts_utc_ms: now.as_millis() as i64,
            level: default_level_for_kind(kind),
            kind,
            request_id: None,
            approval_id: None,
            client: None,
            operation: None,
            safety: None,
            target: None,
            outcome: None,
            latency_ms: None,
            secret_names: vec![],
            policy_decision: None,
            detail: None,
            workspace: None,
            request_hash: None,
        }
    }

    /// Set the sequence number.
    pub fn with_sequence_number(mut self, seq: u64) -> Self {
        self.sequence_number = seq;
        self
    }

    /// Set the request correlation ID.
    pub fn with_request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Set the approval correlation ID.
    pub fn with_approval_id(mut self, id: Uuid) -> Self {
        self.approval_id = Some(id);
        self
    }

    /// Set the client summary.
    pub fn with_client(mut self, client: ClientSummary) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the operation name.
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Set the safety classification.
    pub fn with_safety(mut self, safety: OperationSafety) -> Self {
        self.safety = Some(safety);
        self
    }

    /// Set the target summary.
    pub fn with_target(mut self, target: TargetSummary) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the outcome.
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Set the latency.
    pub fn with_latency_ms(mut self, ms: i64) -> Self {
        self.latency_ms = Some(ms);
        self
    }

    /// Set secret names.
    pub fn with_secret_names(mut self, names: Vec<String>) -> Self {
        self.secret_names = names;
        self
    }

    /// Set policy decision summary.
    pub fn with_policy_decision(mut self, decision: &PolicyDecision) -> Self {
        self.policy_decision = Some(format!("{decision}"));
        self
    }

    /// Set a detail message.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Override the level.
    pub fn with_level(mut self, level: AuditLevel) -> Self {
        self.level = level;
        self
    }

    /// Set the workspace summary.
    pub fn with_workspace(mut self, workspace: WorkspaceSummary) -> Self {
        self.workspace = Some(workspace);
        self
    }

    /// Set the request content hash (for approval binding).
    pub fn with_request_hash(mut self, hash: impl Into<String>) -> Self {
        self.request_hash = Some(hash.into());
        self
    }
}

/// Default severity level based on event kind.
fn default_level_for_kind(kind: AuditEventKind) -> AuditLevel {
    match kind {
        AuditEventKind::PolicyDenied
        | AuditEventKind::ApprovalDenied
        | AuditEventKind::RateLimited => AuditLevel::Warn,
        AuditEventKind::OperationFailed => AuditLevel::Error,
        _ => AuditLevel::Info,
    }
}

// ---------------------------------------------------------------------------
// Audit emitter trait
// ---------------------------------------------------------------------------

/// Trait for emitting audit events.
///
/// Implementations should be non-blocking. For I/O-bound backends (SQLite,
/// network), buffer events internally and flush asynchronously.
///
/// This is the primary interface used by the enclave.
pub trait AuditSink: Send + Sync + fmt::Debug {
    /// Emit an audit event. Must not block the caller.
    fn emit(&self, event: AuditEvent);
}

// ---------------------------------------------------------------------------
// In-memory audit emitter (for testing)
// ---------------------------------------------------------------------------

/// Internal state for `InMemoryAuditEmitter`.
#[derive(Debug)]
struct InMemoryAuditState {
    events: Vec<AuditEvent>,
    next_sequence: u64,
}

/// An in-memory audit emitter that stores events in a `Vec` behind a mutex.
/// Assigns monotonically increasing sequence numbers. Useful for testing.
#[derive(Debug, Clone)]
pub struct InMemoryAuditEmitter {
    state: std::sync::Arc<std::sync::Mutex<InMemoryAuditState>>,
}

impl InMemoryAuditEmitter {
    /// Create a new empty emitter.
    pub fn new() -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(InMemoryAuditState {
                events: Vec::new(),
                next_sequence: 0,
            })),
        }
    }

    /// Retrieve a snapshot of all emitted events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.state
            .lock()
            .expect("audit mutex poisoned")
            .events
            .clone()
    }

    /// Number of emitted events.
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("audit mutex poisoned")
            .events
            .len()
    }

    /// Whether any events have been emitted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all stored events.
    pub fn clear(&self) {
        let mut state = self.state.lock().expect("audit mutex poisoned");
        state.events.clear();
    }

    /// Get events of a specific kind.
    pub fn events_of_kind(&self, kind: AuditEventKind) -> Vec<AuditEvent> {
        self.state
            .lock()
            .expect("audit mutex poisoned")
            .events
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect()
    }
}

impl Default for InMemoryAuditEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for InMemoryAuditEmitter {
    fn emit(&self, mut event: AuditEvent) {
        let mut state = self.state.lock().expect("audit mutex poisoned");
        event.sequence_number = state.next_sequence;
        state.next_sequence += 1;
        state.events.push(event);
    }
}

// ---------------------------------------------------------------------------
// Tracing audit emitter (logs events via tracing)
// ---------------------------------------------------------------------------

/// An audit emitter that logs events via the `tracing` crate.
/// Assigns monotonically increasing sequence numbers.
#[derive(Debug)]
pub struct TracingAuditEmitter {
    next_sequence: AtomicU64,
}

impl TracingAuditEmitter {
    /// Create a new tracing audit emitter.
    pub fn new() -> Self {
        Self {
            next_sequence: AtomicU64::new(0),
        }
    }
}

impl Default for TracingAuditEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for TracingAuditEmitter {
    fn emit(&self, mut event: AuditEvent) {
        event.sequence_number = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            event_id = %event.event_id,
            sequence_number = event.sequence_number,
            kind = %event.kind,
            request_id = ?event.request_id,
            operation = ?event.operation,
            outcome = ?event.outcome,
            latency_ms = ?event.latency_ms,
            "audit event"
        );
    }
}

// ---------------------------------------------------------------------------
// SQLite audit sink (persistent storage)
// ---------------------------------------------------------------------------

const SCHEMA_SQL: &str = "\
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    sequence_number INTEGER NOT NULL,
    ts_utc_ms INTEGER NOT NULL,
    level TEXT NOT NULL,
    kind TEXT NOT NULL,
    request_id TEXT,
    approval_id TEXT,
    client_json TEXT,
    operation TEXT,
    safety TEXT,
    target_json TEXT,
    outcome TEXT,
    latency_ms INTEGER,
    secret_names TEXT,
    policy_decision TEXT,
    detail TEXT,
    workspace_json TEXT,
    request_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts ON audit_events(ts_utc_ms);
CREATE INDEX IF NOT EXISTS idx_kind ON audit_events(kind);
CREATE INDEX IF NOT EXISTS idx_operation ON audit_events(operation);
CREATE INDEX IF NOT EXISTS idx_request_id ON audit_events(request_id);
";

/// A persistent audit sink backed by SQLite.
///
/// Events are sent through a bounded channel and written by a dedicated
/// background thread to avoid blocking the enclave pipeline.
pub struct SqliteAuditSink {
    sender: std::sync::mpsc::SyncSender<AuditEvent>,
    next_sequence: AtomicU64,
    writer_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    sanitizer: crate::sanitize::Sanitizer,
}

impl fmt::Debug for SqliteAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteAuditSink")
            .field("next_sequence", &self.next_sequence.load(Ordering::Relaxed))
            .finish()
    }
}

impl SqliteAuditSink {
    /// Open (or create) the audit database at `db_path`.
    ///
    /// Creates the schema if needed and runs retention cleanup, deleting events
    /// older than `retention_days`.
    pub fn new(db_path: PathBuf, retention_days: u64) -> Result<Self, AuditError> {
        // Ensure parent directory exists.
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open connection, create schema, run retention cleanup.
        let conn = rusqlite::Connection::open(&db_path)?;
        conn.execute_batch(SCHEMA_SQL)?;

        let cutoff_ms = {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            now - (retention_days as i64) * 86_400 * 1000
        };
        conn.execute(
            "DELETE FROM audit_events WHERE ts_utc_ms < ?1",
            rusqlite::params![cutoff_ms],
        )?;
        drop(conn);

        let (sender, receiver) = std::sync::mpsc::sync_channel::<AuditEvent>(4096);

        let writer_path = db_path.clone();
        let writer_handle = std::thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || {
                Self::writer_loop(&writer_path, receiver);
            })
            .map_err(|e| AuditError::Other(format!("failed to spawn writer thread: {e}")))?;

        Ok(Self {
            sender,
            next_sequence: AtomicU64::new(0),
            writer_handle: std::sync::Mutex::new(Some(writer_handle)),
            sanitizer: crate::sanitize::Sanitizer::new(),
        })
    }

    /// Background writer loop. Drains the channel and inserts events in batches.
    fn writer_loop(db_path: &Path, receiver: std::sync::mpsc::Receiver<AuditEvent>) {
        let conn = match rusqlite::Connection::open(db_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("audit writer failed to open db: {e}");
                return;
            }
        };

        // WAL mode for better concurrent read performance.
        let _ = conn.pragma_update(None, "journal_mode", "WAL");

        let mut batch = Vec::with_capacity(64);

        while let Ok(event) = receiver.recv() {
            batch.push(event);

            // Drain any additional pending events without blocking.
            while batch.len() < 256 {
                match receiver.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }

            if let Err(e) = Self::insert_batch(&conn, &batch) {
                tracing::error!("audit writer insert failed: {e}");
            }
            batch.clear();
        }
    }

    /// Insert a batch of events within a single transaction.
    fn insert_batch(
        conn: &rusqlite::Connection,
        events: &[AuditEvent],
    ) -> Result<(), rusqlite::Error> {
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO audit_events (
                    event_id, sequence_number, ts_utc_ms, level, kind,
                    request_id, approval_id, client_json, operation, safety,
                    target_json, outcome, latency_ms, secret_names,
                    policy_decision, detail, workspace_json, request_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            )?;

            for event in events {
                let client_json = event
                    .client
                    .as_ref()
                    .and_then(|c| serde_json::to_string(c).ok());
                let target_json = event
                    .target
                    .as_ref()
                    .and_then(|t| serde_json::to_string(t).ok());
                let safety_str = event.safety.as_ref().map(|s| format!("{s:?}"));
                let secret_names_str = if event.secret_names.is_empty() {
                    None
                } else {
                    Some(event.secret_names.join(","))
                };
                let workspace_json = event
                    .workspace
                    .as_ref()
                    .and_then(|w| serde_json::to_string(w).ok());

                stmt.execute(rusqlite::params![
                    event.event_id.to_string(),
                    event.sequence_number,
                    event.ts_utc_ms,
                    event.level.to_string(),
                    event.kind.to_string(),
                    event.request_id.map(|u| u.to_string()),
                    event.approval_id.map(|u| u.to_string()),
                    client_json,
                    event.operation,
                    safety_str,
                    target_json,
                    event.outcome,
                    event.latency_ms,
                    secret_names_str,
                    event.policy_decision,
                    event.detail,
                    workspace_json,
                    event.request_hash,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Flush pending events and join the writer thread.
    pub fn close(&self) {
        // Drop the sender by replacing it — but we can't move out of self easily.
        // Instead, rely on Drop. This method is for explicit shutdown.
        let handle = self.writer_handle.lock().expect("lock poisoned").take();
        if let Some(h) = handle {
            // The sender will be dropped when Self is dropped, closing the channel.
            // But we need to signal the writer to stop. Since we can't drop sender
            // from &self, we wait with a timeout — the writer will exit when the
            // channel is closed on Drop.
            let _ = h.join();
        }
    }
}

impl AuditSink for SqliteAuditSink {
    fn emit(&self, mut event: AuditEvent) {
        event.sequence_number = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        // Sanitize the detail field to prevent secret leakage into the audit DB.
        if let Some(ref detail) = event.detail {
            event.detail = Some(
                self.sanitizer
                    .redact_audit_text(detail, crate::sanitize::RedactionLevel::Human),
            );
        }
        // Non-blocking send. If the channel is full, drop the event.
        let _ = self.sender.try_send(event);
    }
}

impl Drop for SqliteAuditSink {
    fn drop(&mut self) {
        // Drop the sender to signal the writer thread to finish.
        // We create a dummy channel and swap to effectively drop our sender.
        let (new_sender, _) = std::sync::mpsc::sync_channel(1);
        let _ = std::mem::replace(&mut self.sender, new_sender);

        // Join the writer thread.
        if let Ok(mut guard) = self.writer_handle.lock()
            && let Some(h) = guard.take()
        {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Audit filter & query
// ---------------------------------------------------------------------------

/// Filter criteria for querying audit events from the SQLite database.
pub struct AuditFilter {
    /// Filter by event kind.
    pub kind: Option<AuditEventKind>,
    /// Filter by operation name.
    pub operation: Option<String>,
    /// Only events after this timestamp (ms since epoch).
    pub since_ms: Option<i64>,
    /// Maximum number of events to return.
    pub limit: usize,
    /// Filter by request correlation ID.
    pub request_id: Option<Uuid>,
    /// Filter by outcome value (e.g. "allowed", "denied", "error").
    pub outcome: Option<String>,
}

impl Default for AuditFilter {
    fn default() -> Self {
        Self {
            kind: None,
            operation: None,
            since_ms: None,
            limit: 50,
            request_id: None,
            outcome: None,
        }
    }
}

/// Query audit events from a SQLite database file.
///
/// Opens the database read-only and returns matching events ordered by
/// timestamp descending (most recent first).
pub fn query_audit_db(db_path: &Path, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AuditError> {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let mut sql = String::from("SELECT * FROM audit_events WHERE 1=1");
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref kind) = filter.kind {
        sql.push_str(" AND kind = ?");
        param_values.push(Box::new(kind.to_string()));
    }
    if let Some(ref op) = filter.operation {
        sql.push_str(" AND operation = ?");
        param_values.push(Box::new(op.clone()));
    }
    if let Some(since) = filter.since_ms {
        sql.push_str(" AND ts_utc_ms >= ?");
        param_values.push(Box::new(since));
    }
    if let Some(ref rid) = filter.request_id {
        sql.push_str(" AND request_id = ?");
        param_values.push(Box::new(rid.to_string()));
    }
    if let Some(ref outcome) = filter.outcome {
        sql.push_str(" AND outcome = ?");
        param_values.push(Box::new(outcome.clone()));
    }

    sql.push_str(" ORDER BY ts_utc_ms DESC LIMIT ?");
    param_values.push(Box::new(filter.limit as i64));

    let params: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|b| b.as_ref()).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params.as_slice(), row_to_audit_event)?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    Ok(events)
}

/// Reconstruct an `AuditEvent` from a database row.
fn row_to_audit_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEvent> {
    let event_id_str: String = row.get("event_id")?;
    let event_id = Uuid::parse_str(&event_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let sequence_number: u64 = row.get("sequence_number")?;
    let ts_utc_ms: i64 = row.get("ts_utc_ms")?;

    let level_str: String = row.get("level")?;
    let level = match level_str.as_str() {
        "info" => AuditLevel::Info,
        "warn" => AuditLevel::Warn,
        "error" => AuditLevel::Error,
        _ => AuditLevel::Info,
    };

    let kind_str: String = row.get("kind")?;
    let kind: AuditEventKind = kind_str.parse().map_err(|e: String| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(AuditError::Other(e)),
        )
    })?;

    let request_id: Option<String> = row.get("request_id")?;
    let request_id = request_id.and_then(|s| Uuid::parse_str(&s).ok());

    let approval_id: Option<String> = row.get("approval_id")?;
    let approval_id = approval_id.and_then(|s| Uuid::parse_str(&s).ok());

    let client_json: Option<String> = row.get("client_json")?;
    let client: Option<ClientSummary> = client_json.and_then(|s| serde_json::from_str(&s).ok());

    let operation: Option<String> = row.get("operation")?;

    let safety_str: Option<String> = row.get("safety")?;
    let safety = safety_str.and_then(|s| match s.as_str() {
        "Safe" => Some(OperationSafety::Safe),
        "SensitiveOutput" => Some(OperationSafety::SensitiveOutput),
        "Reveal" => Some(OperationSafety::Reveal),
        _ => None,
    });

    let target_json: Option<String> = row.get("target_json")?;
    let target: Option<TargetSummary> = target_json.and_then(|s| serde_json::from_str(&s).ok());

    let outcome: Option<String> = row.get("outcome")?;
    let latency_ms: Option<i64> = row.get("latency_ms")?;

    let secret_names_str: Option<String> = row.get("secret_names")?;
    let secret_names = secret_names_str
        .map(|s| s.split(',').map(|part| part.to_owned()).collect())
        .unwrap_or_default();

    let policy_decision: Option<String> = row.get("policy_decision")?;
    let detail: Option<String> = row.get("detail")?;

    let workspace_json: Option<String> = row.get("workspace_json")?;
    let workspace: Option<WorkspaceSummary> =
        workspace_json.and_then(|s| serde_json::from_str(&s).ok());

    let request_hash: Option<String> = row.get("request_hash")?;

    Ok(AuditEvent {
        event_id,
        sequence_number,
        ts_utc_ms,
        level,
        kind,
        request_id,
        approval_id,
        client,
        operation,
        safety,
        target,
        outcome,
        latency_ms,
        secret_names,
        policy_decision,
        detail,
        workspace,
        request_hash,
    })
}

// ---------------------------------------------------------------------------
// Multi-sink fan-out
// ---------------------------------------------------------------------------

/// Fans out audit events to multiple sinks.
pub struct MultiAuditSink {
    sinks: Vec<std::sync::Arc<dyn AuditSink>>,
}

impl MultiAuditSink {
    /// Create a new multi-sink that dispatches to all provided sinks.
    pub fn new(sinks: Vec<std::sync::Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

impl fmt::Debug for MultiAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiAuditSink")
            .field("sink_count", &self.sinks.len())
            .finish()
    }
}

impl AuditSink for MultiAuditSink {
    fn emit(&self, event: AuditEvent) {
        for sink in &self.sinks {
            sink.emit(event.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation::{ApprovalRequirement, ClientIdentity, ClientType, OperationSafety};

    #[test]
    fn audit_event_builder() {
        let event = AuditEvent::new(AuditEventKind::RequestReceived)
            .with_request_id(Uuid::new_v4())
            .with_operation("github.set_actions_secret")
            .with_outcome("ok")
            .with_latency_ms(42);

        assert_eq!(event.kind, AuditEventKind::RequestReceived);
        assert_eq!(
            event.operation.as_deref(),
            Some("github.set_actions_secret")
        );
        assert_eq!(event.outcome.as_deref(), Some("ok"));
        assert_eq!(event.latency_ms, Some(42));
        assert_eq!(event.level, AuditLevel::Info);
    }

    #[test]
    fn audit_event_kind_display() {
        assert_eq!(
            format!("{}", AuditEventKind::RequestReceived),
            "request.received"
        );
        assert_eq!(
            format!("{}", AuditEventKind::ApprovalGranted),
            "approval.granted"
        );
        assert_eq!(
            format!("{}", AuditEventKind::OperationFailed),
            "operation.failed"
        );
    }

    #[test]
    fn default_levels() {
        assert_eq!(
            default_level_for_kind(AuditEventKind::PolicyDenied),
            AuditLevel::Warn
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::OperationFailed),
            AuditLevel::Error
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::OperationSucceeded),
            AuditLevel::Info
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::LeaseHit),
            AuditLevel::Info
        );
    }

    #[test]
    fn in_memory_emitter() {
        let emitter = InMemoryAuditEmitter::new();
        assert!(emitter.is_empty());

        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        emitter.emit(AuditEvent::new(AuditEventKind::PolicyDenied));
        emitter.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));

        assert_eq!(emitter.len(), 3);
        assert_eq!(
            emitter.events_of_kind(AuditEventKind::PolicyDenied).len(),
            1
        );

        emitter.clear();
        assert!(emitter.is_empty());
    }

    #[test]
    fn client_summary_from_identity() {
        let id = ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/test".into()),
            exe_sha256: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
            ),
            codesign_team_id: Some("TEAM123".into()),
        };
        let summary = ClientSummary::from((&id, ClientType::Agent));
        assert_eq!(summary.uid, 501);
        assert_eq!(
            summary.exe_sha256_prefix.as_deref(),
            Some("abcdef0123456789")
        );
        assert_eq!(summary.codesign_team_id.as_deref(), Some("TEAM123"));
    }

    #[test]
    fn audit_event_debug_is_safe() {
        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_detail("some detail with password=hunter2");
        let dbg = format!("{event:?}");
        // Debug impl only shows selected fields, not detail.
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn all_event_kind_display() {
        let kinds = vec![
            (AuditEventKind::RequestReceived, "request.received"),
            (AuditEventKind::PolicyDenied, "policy.denied"),
            (AuditEventKind::ApprovalRequired, "approval.required"),
            (AuditEventKind::ApprovalPresented, "approval.presented"),
            (AuditEventKind::ApprovalGranted, "approval.granted"),
            (AuditEventKind::ApprovalDenied, "approval.denied"),
            (AuditEventKind::OperationStarted, "operation.started"),
            (AuditEventKind::OperationSucceeded, "operation.succeeded"),
            (AuditEventKind::OperationFailed, "operation.failed"),
            (
                AuditEventKind::ProviderFetchStarted,
                "provider.fetch.started",
            ),
            (
                AuditEventKind::ProviderFetchFinished,
                "provider.fetch.finished",
            ),
            (AuditEventKind::RateLimited, "rate.limited"),
            (AuditEventKind::LeaseHit, "lease.hit"),
            (AuditEventKind::SandboxCreated, "sandbox.created"),
            (AuditEventKind::SandboxCompleted, "sandbox.completed"),
            (AuditEventKind::SecretResolved, "secret.resolved"),
        ];
        for (kind, expected) in kinds {
            assert_eq!(format!("{kind}"), expected);
        }
    }

    #[test]
    fn all_audit_level_display() {
        assert_eq!(format!("{}", AuditLevel::Info), "info");
        assert_eq!(format!("{}", AuditLevel::Warn), "warn");
        assert_eq!(format!("{}", AuditLevel::Error), "error");
    }

    #[test]
    fn audit_event_all_builder_methods() {
        let id = Uuid::new_v4();
        let approval_id = Uuid::new_v4();
        let summary = ClientSummary {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/test".into()),
            exe_sha256_prefix: Some("aabb".into()),
            codesign_team_id: None,
            client_type: ClientType::Agent,
        };
        let target = TargetSummary {
            fields: {
                let mut m = std::collections::HashMap::new();
                m.insert("repo".into(), "org/repo".into());
                m
            },
        };
        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_request_id(id)
            .with_approval_id(approval_id)
            .with_client(summary)
            .with_operation("test.op")
            .with_safety(OperationSafety::Safe)
            .with_target(target)
            .with_outcome("ok")
            .with_latency_ms(100)
            .with_secret_names(vec!["SECRET".into()])
            .with_detail("test detail");

        assert_eq!(event.request_id, Some(id));
        assert_eq!(event.approval_id, Some(approval_id));
        assert!(event.client.is_some());
        assert_eq!(event.operation.as_deref(), Some("test.op"));
        assert_eq!(event.safety, Some(OperationSafety::Safe));
        assert!(event.target.is_some());
        assert_eq!(event.outcome.as_deref(), Some("ok"));
        assert_eq!(event.latency_ms, Some(100));
        assert_eq!(event.secret_names, vec!["SECRET"]);
        assert_eq!(event.detail.as_deref(), Some("test detail"));
    }

    #[test]
    fn audit_event_with_level_override() {
        let event =
            AuditEvent::new(AuditEventKind::OperationSucceeded).with_level(AuditLevel::Error);
        assert_eq!(event.level, AuditLevel::Error);
    }

    #[test]
    fn audit_event_with_policy_decision() {
        let decision = PolicyDecision {
            allowed: false,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            matched_rule: Some("deny-rule".into()),
            denial_reason: Some("denied".into()),
        };
        let event = AuditEvent::new(AuditEventKind::PolicyDenied).with_policy_decision(&decision);
        assert!(event.policy_decision.is_some());
        let pd = event.policy_decision.unwrap();
        assert!(pd.contains("DENY"));
    }

    #[test]
    fn client_summary_no_hash() {
        let id = ClientIdentity {
            uid: 501,
            gid: 20,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        };
        let summary = ClientSummary::from((&id, ClientType::Human));
        assert!(summary.exe_sha256_prefix.is_none());
        assert!(summary.pid.is_none());
        assert!(summary.exe_path.is_none());
    }

    #[test]
    fn client_summary_short_hash() {
        let id = ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1),
            exe_path: None,
            exe_sha256: Some("abcdef01".into()),
            codesign_team_id: None,
        };
        let summary = ClientSummary::from((&id, ClientType::Agent));
        assert_eq!(summary.exe_sha256_prefix.as_deref(), Some("abcdef01"));
    }

    #[test]
    fn in_memory_emitter_events_of_kind_empty() {
        let emitter = InMemoryAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        let policy_events = emitter.events_of_kind(AuditEventKind::PolicyDenied);
        assert!(policy_events.is_empty());
    }

    #[test]
    fn in_memory_emitter_default() {
        let emitter = InMemoryAuditEmitter::default();
        assert!(emitter.is_empty());
    }

    #[test]
    fn target_summary_default() {
        let target = TargetSummary::default();
        assert!(target.fields.is_empty());
    }

    #[test]
    fn tracing_emitter_does_not_panic() {
        let emitter = TracingAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        emitter.emit(
            AuditEvent::new(AuditEventKind::OperationFailed)
                .with_operation("test.op")
                .with_outcome("error")
                .with_latency_ms(5),
        );
    }

    #[test]
    fn sequence_numbers_monotonic() {
        let emitter = InMemoryAuditEmitter::new();
        for _ in 0..10 {
            emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        }
        let events = emitter.events();
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.sequence_number, i as u64);
        }
    }

    #[test]
    fn sequence_starts_at_zero() {
        let emitter = InMemoryAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        let events = emitter.events();
        assert_eq!(events[0].sequence_number, 0);
    }

    #[test]
    fn sequence_in_debug() {
        let event = AuditEvent::new(AuditEventKind::RequestReceived).with_sequence_number(42);
        let dbg = format!("{event:?}");
        assert!(dbg.contains("sequence_number: 42"));
    }

    #[test]
    fn rate_limited_kind_display() {
        assert_eq!(format!("{}", AuditEventKind::RateLimited), "rate.limited");
    }

    #[test]
    fn rate_limited_default_level() {
        assert_eq!(
            default_level_for_kind(AuditEventKind::RateLimited),
            AuditLevel::Warn
        );
    }

    #[test]
    fn audit_event_with_request_hash() {
        let event = AuditEvent::new(AuditEventKind::ApprovalRequired)
            .with_request_hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        assert_eq!(
            event.request_hash.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        );
    }

    #[test]
    fn audit_event_debug_shows_request_hash() {
        let event =
            AuditEvent::new(AuditEventKind::ApprovalGranted).with_request_hash("deadbeef01234567");
        let dbg = format!("{event:?}");
        assert!(dbg.contains("request_hash"));
        assert!(dbg.contains("deadbeef01234567"));
    }

    #[test]
    fn tracing_emitter_assigns_sequence_numbers() {
        let emitter = TracingAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        emitter.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));
        // We can't inspect the events directly from TracingAuditEmitter,
        // but we can verify the counter advanced.
        assert_eq!(
            emitter
                .next_sequence
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    // -- Sanitized constructor tests --

    #[test]
    fn target_summary_redacts_jwt_in_value() {
        let mut target = std::collections::HashMap::new();
        target.insert("repo".into(), "org/myrepo".into());
        target.insert(
            "header".into(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".into(),
        );
        let summary = TargetSummary::sanitized(&target);
        assert_eq!(summary.fields["repo"], "org/myrepo");
        assert!(!summary.fields["header"].contains("eyJ"));
        assert!(summary.fields["header"].contains("[REDACTED:"));
    }

    #[test]
    fn target_summary_redacts_credential_url() {
        let mut target = std::collections::HashMap::new();
        target.insert(
            "endpoint".into(),
            "https://admin:secret@db.example.com/mydb".into(),
        );
        let summary = TargetSummary::sanitized(&target);
        assert!(!summary.fields["endpoint"].contains("admin:secret"));
        assert!(summary.fields["endpoint"].contains("[URL:REDACTED]"));
    }

    #[test]
    fn workspace_summary_strips_userinfo() {
        use crate::operation::WorkspaceContext;
        use std::path::PathBuf;
        let ws = WorkspaceContext {
            repo_root: PathBuf::from("/tmp/repo"),
            remote_url: Some("https://user:pass@github.com/org/repo.git".into()),
            branch: Some("main".into()),
            head_sha: None,
            dirty: false,
        };
        let summary = WorkspaceSummary::sanitized(&ws);
        let url = summary.remote_url.unwrap();
        assert!(!url.contains("user:pass"));
        assert_eq!(url, "https://github.com/org/repo.git");
        assert_eq!(summary.branch.as_deref(), Some("main"));
    }

    // -- AuditEventKind FromStr tests --

    #[test]
    fn audit_event_kind_from_str_roundtrip() {
        let kinds = vec![
            AuditEventKind::RequestReceived,
            AuditEventKind::PolicyDenied,
            AuditEventKind::ApprovalRequired,
            AuditEventKind::ApprovalPresented,
            AuditEventKind::ApprovalGranted,
            AuditEventKind::ApprovalDenied,
            AuditEventKind::OperationStarted,
            AuditEventKind::OperationSucceeded,
            AuditEventKind::OperationFailed,
            AuditEventKind::ProviderFetchStarted,
            AuditEventKind::ProviderFetchFinished,
            AuditEventKind::RateLimited,
            AuditEventKind::LeaseHit,
            AuditEventKind::SandboxCreated,
            AuditEventKind::SandboxCompleted,
            AuditEventKind::SecretResolved,
        ];
        for kind in kinds {
            let s = format!("{kind}");
            let parsed: AuditEventKind = s.parse().unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn audit_event_kind_from_str_unknown() {
        let result = "nonexistent.kind".parse::<AuditEventKind>();
        assert!(result.is_err());
    }

    // -- SqliteAuditSink tests --

    fn temp_db_path() -> PathBuf {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        dir.join(format!("opaque-test-audit-{}.db", Uuid::new_v4()))
    }

    fn make_test_event(kind: AuditEventKind) -> AuditEvent {
        AuditEvent::new(kind)
            .with_operation("test.op")
            .with_outcome("ok")
            .with_latency_ms(42)
    }

    #[test]
    fn sqlite_sink_schema_creation() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        drop(sink);

        // Verify schema exists by opening read-only and querying.
        let conn = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_sink_emit_and_query() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let req_id = Uuid::new_v4();
        let event = make_test_event(AuditEventKind::RequestReceived)
            .with_request_id(req_id)
            .with_secret_names(vec!["SECRET_A".into(), "SECRET_B".into()])
            .with_detail("test detail");
        sink.emit(event);

        let event2 = make_test_event(AuditEventKind::OperationSucceeded)
            .with_request_id(req_id)
            .with_safety(OperationSafety::Safe);
        sink.emit(event2);

        // Drop to flush and join writer thread.
        drop(sink);

        let filter = AuditFilter::default();
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 2);

        // Most recent first.
        assert_eq!(events[0].kind, AuditEventKind::OperationSucceeded);
        assert_eq!(events[1].kind, AuditEventKind::RequestReceived);
        assert_eq!(events[1].operation.as_deref(), Some("test.op"));
        assert_eq!(events[1].secret_names, vec!["SECRET_A", "SECRET_B"]);
        assert_eq!(events[1].detail.as_deref(), Some("test detail"));
        assert_eq!(events[0].safety, Some(OperationSafety::Safe));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_kind() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        sink.emit(make_test_event(AuditEventKind::PolicyDenied));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
        drop(sink);

        let filter = AuditFilter {
            kind: Some(AuditEventKind::PolicyDenied),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::PolicyDenied);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_operation() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        sink.emit(AuditEvent::new(AuditEventKind::RequestReceived).with_operation("github.sync"));
        sink.emit(AuditEvent::new(AuditEventKind::RequestReceived).with_operation("k8s.apply"));
        drop(sink);

        let filter = AuditFilter {
            operation: Some("github.sync".into()),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation.as_deref(), Some("github.sync"));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_request_id() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let target_id = Uuid::new_v4();
        sink.emit(make_test_event(AuditEventKind::RequestReceived).with_request_id(target_id));
        sink.emit(make_test_event(AuditEventKind::RequestReceived).with_request_id(Uuid::new_v4()));
        drop(sink);

        let filter = AuditFilter {
            request_id: Some(target_id),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id, Some(target_id));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_since_ms() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        // Emit events — they'll all have "now" timestamps.
        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        drop(sink);

        let now_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Since in the future — should return nothing.
        let filter = AuditFilter {
            since_ms: Some(now_ms + 60_000),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert!(events.is_empty());

        // Since in the past — should return everything.
        let filter = AuditFilter {
            since_ms: Some(now_ms - 60_000),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_limit() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        for _ in 0..10 {
            sink.emit(make_test_event(AuditEventKind::RequestReceived));
        }
        drop(sink);

        let filter = AuditFilter {
            limit: 3,
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 3);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_retention_cleanup() {
        let db_path = temp_db_path();

        // Insert an old event directly.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(SCHEMA_SQL).unwrap();
            let old_ts = 1000i64; // very old timestamp
            conn.execute(
                "INSERT INTO audit_events (event_id, sequence_number, ts_utc_ms, level, kind)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    0,
                    old_ts,
                    "info",
                    "request.received"
                ],
            )
            .unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1);
        }

        // Opening with retention_days=90 should clean up the old event.
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        drop(sink);

        let filter = AuditFilter::default();
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert!(events.is_empty());

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_sink_with_client_and_target() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let client = ClientSummary {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/test".into()),
            exe_sha256_prefix: Some("aabb".into()),
            codesign_team_id: None,
            client_type: ClientType::Human,
        };
        let target = TargetSummary {
            fields: {
                let mut m = std::collections::HashMap::new();
                m.insert("repo".into(), "org/repo".into());
                m
            },
        };
        let workspace = WorkspaceSummary {
            remote_url: Some("https://github.com/org/repo.git".into()),
            branch: Some("main".into()),
            dirty: false,
        };

        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_client(client)
            .with_target(target)
            .with_workspace(workspace)
            .with_request_hash("abcdef");
        sink.emit(event);
        drop(sink);

        let filter = AuditFilter::default();
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);

        let e = &events[0];
        let c = e.client.as_ref().unwrap();
        assert_eq!(c.uid, 501);
        assert_eq!(c.client_type, ClientType::Human);
        let t = e.target.as_ref().unwrap();
        assert_eq!(t.fields["repo"], "org/repo");
        let w = e.workspace.as_ref().unwrap();
        assert_eq!(w.branch.as_deref(), Some("main"));
        assert_eq!(e.request_hash.as_deref(), Some("abcdef"));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn audit_filter_defaults() {
        let filter = AuditFilter::default();
        assert!(filter.kind.is_none());
        assert!(filter.operation.is_none());
        assert!(filter.since_ms.is_none());
        assert_eq!(filter.limit, 50);
        assert!(filter.request_id.is_none());
    }

    // -- MultiAuditSink tests --

    #[test]
    fn multi_sink_fans_out() {
        let a = std::sync::Arc::new(InMemoryAuditEmitter::new());
        let b = std::sync::Arc::new(InMemoryAuditEmitter::new());
        let multi = MultiAuditSink::new(vec![
            a.clone() as std::sync::Arc<dyn AuditSink>,
            b.clone() as std::sync::Arc<dyn AuditSink>,
        ]);

        multi.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        multi.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));

        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn multi_sink_debug() {
        let multi = MultiAuditSink::new(vec![]);
        let dbg = format!("{multi:?}");
        assert!(dbg.contains("MultiAuditSink"));
        assert!(dbg.contains("sink_count: 0"));
    }

    #[test]
    fn sqlite_sink_debug() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("SqliteAuditSink"));
        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    // -- AuditError tests --

    #[test]
    fn audit_error_display() {
        let err = AuditError::Other("test error".into());
        assert_eq!(format!("{err}"), "test error");

        let io_err = AuditError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(format!("{io_err}").contains("not found"));
    }

    #[test]
    fn sqlite_sink_sanitizes_detail() {
        // P0-4: The SqliteAuditSink must sanitize the detail field
        // before persisting to prevent secret leakage in the audit DB.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sanitize_test.db");
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let secret_detail =
            "command=[\"/bin/sh\", \"-c\", \"echo ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"]";
        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_detail(secret_detail.to_owned());
        sink.emit(event);
        drop(sink);

        // Query the DB directly to verify the detail was sanitized.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let detail: String = conn
            .query_row(
                "SELECT detail FROM audit_events WHERE detail IS NOT NULL LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(
            !detail.contains("ghp_ABCDEF"),
            "audit detail should not contain the raw GitHub PAT"
        );
        assert!(
            detail.contains("[REDACTED:github_token]"),
            "audit detail should contain redaction marker"
        );
    }
}
