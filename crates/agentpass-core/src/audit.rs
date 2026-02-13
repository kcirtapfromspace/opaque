//! Audit event model and emission.
//!
//! Every operation, approval, and policy decision emits structured audit events.
//! Events carry correlation IDs ([`request_id`], [`approval_id`], [`event_id`])
//! for end-to-end tracing.
//!
//! Secret values NEVER appear in audit events.

use std::fmt;
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
        };
        write!(f, "{s}")
    }
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
}
