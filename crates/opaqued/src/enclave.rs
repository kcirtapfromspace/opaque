//! Enclave: the central enforcement funnel for all secret-using operations.
//!
//! **Every** operation request flows through [`Enclave::execute()`]. There are
//! no bypass paths. The type system enforces that only sanitized responses
//! can be returned to the client.
//!
//! The execution pipeline:
//!
//! 1. Verify client identity
//! 2. Look up operation in registry
//! 3. Check safety-class / client-type constraints
//! 4. Evaluate policy
//! 5. If approval required, trigger operation-bound approval
//! 6. Execute the operation handler
//! 7. Sanitize the response
//! 8. Emit audit events at each step
//! 9. Return sanitized response

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opaque_core::audit::{
    AuditEvent, AuditEventKind, AuditLevel, AuditSink, ClientSummary, TargetSummary,
    WorkspaceSummary,
};
use opaque_core::operation::{
    ApprovalFactor, ApprovalRequirement, OperationDef, OperationRegistry, OperationRequest,
    OperationSafety, validate_params,
};
use opaque_core::policy::{PolicyDecision, PolicyEngine};
use opaque_core::sanitize::{Sanitized, SanitizedResponse, Sanitizer, Unsanitized};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Approval lease constants
// ---------------------------------------------------------------------------

/// Default TTL for approval leases when the policy rule does not specify one.
const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(600); // 10 minutes

/// Maximum TTL cap for any approval lease.
const MAX_LEASE_TTL: Duration = Duration::from_secs(3600); // 60 minutes

// ---------------------------------------------------------------------------
// Enclave error
// ---------------------------------------------------------------------------

/// Errors that can occur within the enclave.
///
/// These are internal errors. The enclave always returns a
/// `SanitizedResponse<Sanitized>` to the caller, converting these errors
/// into sanitized error responses.
#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("client identity verification failed: {0}")]
    IdentityVerification(String),

    #[error("unknown operation: {0}")]
    UnknownOperation(String),

    #[error("operation safety violation: {0}")]
    SafetyViolation(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("approval required but not granted: {0}")]
    ApprovalNotGranted(String),

    #[error("approval unavailable: {0}")]
    ApprovalUnavailable(String),

    #[error("operation execution failed: {0}")]
    OperationFailed(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl EnclaveError {
    /// Map to a stable error code for the client.
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityVerification(_) => "identity_verification_failed",
            Self::InvalidInput(_) => "bad_request",
            Self::UnknownOperation(_) => "unknown_operation",
            Self::SafetyViolation(_) => "safety_violation",
            Self::PolicyDenied(_) => "policy_denied",
            Self::ApprovalNotGranted(_) => "approval_not_granted",
            Self::ApprovalUnavailable(_) => "approval_unavailable",
            Self::OperationFailed(_) => "operation_failed",
            Self::RateLimited(_) => "rate_limited",
            Self::InvalidParams(_) => "invalid_params",
            Self::Internal(_) => "internal_error",
        }
    }
}

// ---------------------------------------------------------------------------
// Approval rate limiter
// ---------------------------------------------------------------------------

/// Rate limiter for approval requests. Prevents rapid-fire approval prompt
/// fatigue attacks by limiting requests per (pid, operation) window.
struct ApprovalRateLimiter {
    /// Map from (pid, operation) to timestamps of recent requests.
    #[allow(clippy::type_complexity)]
    window: Mutex<HashMap<(Option<i32>, String), Vec<Instant>>>,
    /// Maximum requests allowed in the window.
    max_requests: usize,
    /// Duration of the sliding window.
    window_duration: Duration,
}

impl ApprovalRateLimiter {
    fn new(max_requests: usize, window_duration: Duration) -> Self {
        Self {
            window: Mutex::new(HashMap::new()),
            max_requests,
            window_duration,
        }
    }

    /// Check if a request is allowed. Returns `true` if within limits.
    fn check_and_record(&self, pid: Option<i32>, operation: &str) -> bool {
        let key = (pid, operation.to_owned());
        let now = Instant::now();
        let mut window = self.window.lock().expect("rate limiter mutex poisoned");
        let entries = window.entry(key).or_default();

        // Remove expired entries.
        entries.retain(|t| now.duration_since(*t) < self.window_duration);

        if entries.len() >= self.max_requests {
            return false;
        }

        entries.push(now);
        true
    }
}

impl fmt::Debug for ApprovalRateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalRateLimiter")
            .field("max_requests", &self.max_requests)
            .field("window_duration", &self.window_duration)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Approval lease cache
// ---------------------------------------------------------------------------

/// Key for the approval lease cache. Identifies a unique (client, operation,
/// target, secrets) tuple. Deliberately excludes PID so the same binary can
/// reuse a lease across reconnects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LeaseKey {
    /// SHA-256 of stable client identity fields (uid, gid, exe_path,
    /// exe_sha256, codesign_team_id). PID is excluded.
    client_fingerprint: String,
    operation: String,
    /// Sorted "key1=val1\0key2=val2\0..."
    target_canonical: String,
    /// Sorted "NAME1\0NAME2\0..."
    secret_refs_canonical: String,
}

impl LeaseKey {
    /// Compute a lease key from an operation request.
    fn from_request(request: &OperationRequest) -> Self {
        // Client fingerprint: hash stable identity fields (no PID).
        let mut hasher = Sha256::new();
        hasher.update(request.client_identity.uid.to_le_bytes());
        hasher.update(request.client_identity.gid.to_le_bytes());
        if let Some(ref p) = request.client_identity.exe_path {
            hasher.update(p.to_string_lossy().as_bytes());
        }
        hasher.update(b"\0");
        if let Some(ref h) = request.client_identity.exe_sha256 {
            hasher.update(h.as_bytes());
        }
        hasher.update(b"\0");
        if let Some(ref t) = request.client_identity.codesign_team_id {
            hasher.update(t.as_bytes());
        }
        let client_fingerprint = format!("{:x}", hasher.finalize());

        // Sorted target entries.
        let mut target_entries: Vec<_> = request.target.iter().collect();
        target_entries.sort_by_key(|(k, _)| k.as_str());
        let target_canonical = target_entries
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\0");

        // Sorted secret ref names.
        let mut refs = request.secret_ref_names.clone();
        refs.sort();
        let secret_refs_canonical = refs.join("\0");

        Self {
            client_fingerprint,
            operation: request.operation.clone(),
            target_canonical,
            secret_refs_canonical,
        }
    }
}

/// A single approval lease entry.
struct LeaseEntry {
    granted_at: tokio::time::Instant,
    ttl: Duration,
    one_time: bool,
}

/// In-memory cache of approval leases. Cleared on daemon restart (fail closed).
struct LeaseCache {
    leases: Mutex<HashMap<LeaseKey, LeaseEntry>>,
    max_ttl: Duration,
}

impl LeaseCache {
    /// Create an empty lease cache with the default max TTL.
    fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
            max_ttl: MAX_LEASE_TTL,
        }
    }

    /// Check if a valid lease exists for the given key.
    ///
    /// Returns `true` if a valid (non-expired) lease exists. Lazily removes
    /// expired entries. Consumes one-time leases on hit.
    fn check(&self, key: &LeaseKey) -> bool {
        let mut leases = self.leases.lock().expect("lease cache mutex poisoned");
        let now = tokio::time::Instant::now();

        if let Some(entry) = leases.get(key) {
            if now.duration_since(entry.granted_at) < entry.ttl {
                if entry.one_time {
                    // Consume the one-time lease.
                    leases.remove(key);
                }
                return true;
            }
            // Expired — remove lazily.
            leases.remove(key);
        }
        false
    }

    /// Grant a new lease. TTL is capped at `max_ttl`.
    fn grant(&self, key: LeaseKey, ttl: Duration, one_time: bool) {
        let capped_ttl = ttl.min(self.max_ttl);
        let mut leases = self.leases.lock().expect("lease cache mutex poisoned");
        leases.insert(
            key,
            LeaseEntry {
                granted_at: tokio::time::Instant::now(),
                ttl: capped_ttl,
                one_time,
            },
        );
    }

    /// Clear all leases.
    #[cfg(test)]
    fn clear(&self) {
        self.leases
            .lock()
            .expect("lease cache mutex poisoned")
            .clear();
    }

    /// Return a snapshot of active (non-expired) leases for introspection.
    fn active_leases(&self) -> Vec<LeaseInfo> {
        let leases = self.leases.lock().expect("lease cache mutex poisoned");
        let now = tokio::time::Instant::now();
        leases
            .iter()
            .filter_map(|(key, entry)| {
                let elapsed = now.duration_since(entry.granted_at);
                if elapsed >= entry.ttl {
                    return None; // expired
                }
                Some(LeaseInfo {
                    operation: key.operation.clone(),
                    target: key.target_canonical.clone(),
                    client_fingerprint: key.client_fingerprint[..12].to_string(),
                    ttl_remaining_secs: (entry.ttl - elapsed).as_secs(),
                    one_time: entry.one_time,
                })
            })
            .collect()
    }
}

/// Serializable snapshot of a single active lease.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LeaseInfo {
    pub operation: String,
    pub target: String,
    pub client_fingerprint: String,
    pub ttl_remaining_secs: u64,
    pub one_time: bool,
}

impl fmt::Debug for LeaseCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.leases.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("LeaseCache")
            .field("entries", &count)
            .field("max_ttl", &self.max_ttl)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Operation handler trait
// ---------------------------------------------------------------------------

/// Trait for operation handlers. Each registered operation has a corresponding
/// handler that performs the actual work.
///
/// Handlers receive the validated request and return a raw JSON payload.
/// The enclave sanitizes the payload before returning it to the client.
pub trait OperationHandler: Send + Sync + fmt::Debug {
    /// Execute the operation. Returns a raw (unsanitized) JSON payload.
    ///
    /// The handler must NOT return secret values in the payload. The sanitizer
    /// provides defense-in-depth, but handlers should be written to avoid
    /// including secrets in the first place.
    fn execute(
        &self,
        request: &OperationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + '_>,
    >;
}

// ---------------------------------------------------------------------------
// Approval gate trait
// ---------------------------------------------------------------------------

/// Trait for the approval gate. The enclave calls this to present
/// operation-bound approval challenges to the user.
///
/// Approval is ALWAYS bound to a specific operation request. There is no
/// generic "approve" endpoint.
pub trait ApprovalGate: Send + Sync + fmt::Debug {
    /// Present an approval challenge for the given operation request.
    ///
    /// The implementation must:
    /// - Display the operation, target, client identity, and TTL to the user
    /// - Use the specified approval factor(s)
    /// - Return `Ok(true)` if approved, `Ok(false)` if denied
    /// - Return `Err` if the approval mechanism is unavailable
    ///
    /// The `approval_id` is used for audit correlation.
    fn request_approval(
        &self,
        approval_id: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        description: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// Enclave
// ---------------------------------------------------------------------------

/// The central enforcement funnel.
///
/// All secret-using operations MUST pass through `Enclave::execute()`.
/// The type system guarantees that only sanitized responses are returned.
pub struct Enclave {
    /// Operation registry (immutable after construction).
    registry: OperationRegistry,

    /// Policy engine.
    policy: PolicyEngine,

    /// Operation handlers, keyed by operation name.
    handlers: HashMap<String, Box<dyn OperationHandler>>,

    /// Approval gate (native OS prompts, iOS, FIDO2).
    approval_gate: Box<dyn ApprovalGate>,

    /// Audit event sink.
    audit: Arc<dyn AuditSink>,

    /// Response sanitizer.
    sanitizer: Sanitizer,

    /// Semaphore to serialize approval prompts (avoid prompt races).
    approval_semaphore: Semaphore,

    /// Rate limiter for approval requests.
    rate_limiter: ApprovalRateLimiter,

    /// In-memory approval lease cache. Cleared on daemon restart.
    lease_cache: LeaseCache,
}

impl fmt::Debug for Enclave {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enclave")
            .field("registry_size", &self.registry.len())
            .field("policy_rules", &self.policy.rule_count())
            .field("handlers", &self.handlers.len())
            .finish()
    }
}

/// Builder for constructing an [`Enclave`].
pub struct EnclaveBuilder {
    registry: OperationRegistry,
    policy: PolicyEngine,
    handlers: HashMap<String, Box<dyn OperationHandler>>,
    approval_gate: Option<Box<dyn ApprovalGate>>,
    audit: Option<Arc<dyn AuditSink>>,
    sanitizer: Sanitizer,
}

impl EnclaveBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            registry: OperationRegistry::new(),
            policy: PolicyEngine::new(),
            handlers: HashMap::new(),
            approval_gate: None,
            audit: None,
            sanitizer: Sanitizer::new(),
        }
    }

    /// Set the operation registry.
    pub fn registry(mut self, registry: OperationRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Set the policy engine.
    pub fn policy(mut self, policy: PolicyEngine) -> Self {
        self.policy = policy;
        self
    }

    /// Register an operation handler.
    pub fn handler(
        mut self,
        operation_name: impl Into<String>,
        handler: Box<dyn OperationHandler>,
    ) -> Self {
        self.handlers.insert(operation_name.into(), handler);
        self
    }

    /// Set the approval gate.
    pub fn approval_gate(mut self, gate: Box<dyn ApprovalGate>) -> Self {
        self.approval_gate = Some(gate);
        self
    }

    /// Set the audit sink.
    pub fn audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// Set a custom sanitizer.
    #[allow(dead_code)] // Part of the builder API; used once provider integrations land
    pub fn sanitizer(mut self, sanitizer: Sanitizer) -> Self {
        self.sanitizer = sanitizer;
        self
    }

    /// Build the enclave. Panics if required components are missing.
    pub fn build(self) -> Enclave {
        Enclave {
            registry: self.registry,
            policy: self.policy,
            handlers: self.handlers,
            approval_gate: self.approval_gate.expect("approval gate is required"),
            audit: self.audit.expect("audit sink is required"),
            sanitizer: self.sanitizer,
            approval_semaphore: Semaphore::new(1),
            rate_limiter: ApprovalRateLimiter::new(3, Duration::from_secs(60)),
            lease_cache: LeaseCache::new(),
        }
    }
}

impl Default for EnclaveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Enclave {
    /// Create a builder for constructing an enclave.
    pub fn builder() -> EnclaveBuilder {
        EnclaveBuilder::new()
    }

    /// Return a snapshot of active (non-expired) approval leases.
    pub fn active_leases(&self) -> Vec<LeaseInfo> {
        self.lease_cache.active_leases()
    }

    /// Execute an operation request through the full enforcement funnel.
    ///
    /// This is the **ONLY** path to run any operation. The return type
    /// `SanitizedResponse<Sanitized>` guarantees at compile time that the
    /// response has been sanitized.
    ///
    /// Pipeline:
    /// 1. Verify client identity (defense-in-depth)
    /// 2. Emit request-received audit event
    /// 3. Look up operation in registry, validate target keys and params
    /// 4. Check safety-class constraints
    /// 5. Evaluate policy
    /// 6. Trigger approval if required
    /// 7. Execute operation handler
    /// 8. Sanitize response
    /// 9. Emit outcome audit event
    pub async fn execute(&self, request: OperationRequest) -> SanitizedResponse<Sanitized> {
        let start = Instant::now();
        let request_id = request.request_id;
        let client_summary = ClientSummary::from((&request.client_identity, request.client_type));
        let target_summary = TargetSummary::sanitized(&request.target);

        let workspace_summary = request.workspace.as_ref().map(WorkspaceSummary::sanitized);

        // --- Step 1: Verify client identity ---
        // Defense-in-depth: reject requests with the fallback identity
        // (uid == u32::MAX means peer credentials were unavailable).
        if request.client_identity.uid == u32::MAX {
            let err = EnclaveError::IdentityVerification(
                "peer credentials unavailable (uid unresolved)".into(),
            );
            return self.error_to_sanitized(&err);
        }

        // --- Step 2: Emit request received ---
        let mut event = AuditEvent::new(AuditEventKind::RequestReceived)
            .with_request_id(request_id)
            .with_client(client_summary.clone())
            .with_operation(&request.operation)
            .with_target(target_summary.clone())
            .with_secret_names(request.secret_ref_names.clone());
        if let Some(ref ws) = workspace_summary {
            event = event.with_workspace(ws.clone());
        }
        self.audit.emit(event);

        // --- Step 3: Look up operation in registry ---
        let op_def = match self.registry.get(&request.operation) {
            Ok(def) => def.clone(),
            Err(_) => {
                let err = EnclaveError::UnknownOperation(request.operation.clone());
                return self.emit_and_sanitize_error(
                    request_id,
                    &client_summary,
                    &request.operation,
                    &target_summary,
                    &request.secret_ref_names,
                    &err,
                    start,
                );
            }
        };

        // --- Step 3b: Validate target keys against allowed set ---
        if !op_def.allowed_target_keys.is_empty() {
            for key in request.target.keys() {
                if !op_def.allowed_target_keys.iter().any(|k| k == key) {
                    let err = EnclaveError::InvalidInput(format!("unexpected target key: {key}"));
                    return self.emit_and_sanitize_error(
                        request_id,
                        &client_summary,
                        &request.operation,
                        &target_summary,
                        &request.secret_ref_names,
                        &err,
                        start,
                    );
                }
            }
        }

        // --- Step 3c: Validate params against schema ---
        if let Some(ref schema) = op_def.params_schema
            && let Err(errors) = validate_params(schema, &request.params)
        {
            let err = EnclaveError::InvalidParams(errors.join("; "));
            return self.emit_and_sanitize_error(
                request_id,
                &client_summary,
                &request.operation,
                &target_summary,
                &request.secret_ref_names,
                &err,
                start,
            );
        }

        // --- Step 4: Safety-class / client-type constraints ---
        if let Err(err) = self.check_safety_constraints(&request, &op_def) {
            return self.emit_and_sanitize_error(
                request_id,
                &client_summary,
                &request.operation,
                &target_summary,
                &request.secret_ref_names,
                &err,
                start,
            );
        }

        // --- Step 5: Evaluate policy ---
        let decision = self.policy.evaluate(&request, op_def.safety);

        if !decision.allowed {
            let reason = decision
                .denial_reason
                .clone()
                .unwrap_or_else(|| "policy denied".into());

            self.audit.emit(
                AuditEvent::new(AuditEventKind::PolicyDenied)
                    .with_request_id(request_id)
                    .with_client(client_summary.clone())
                    .with_operation(&request.operation)
                    .with_target(target_summary.clone())
                    .with_outcome("denied")
                    .with_policy_decision(&decision)
                    .with_detail(&reason),
            );

            let err = EnclaveError::PolicyDenied(reason);
            return self.error_to_sanitized(&err);
        }

        // --- Step 6: Approval gate ---
        if let Err(err) = self
            .handle_approval(
                &request,
                &op_def,
                &decision,
                &client_summary,
                &target_summary,
            )
            .await
        {
            return self.emit_and_sanitize_error(
                request_id,
                &client_summary,
                &request.operation,
                &target_summary,
                &request.secret_ref_names,
                &err,
                start,
            );
        }

        // --- Step 7: Execute operation handler ---
        self.audit.emit(
            AuditEvent::new(AuditEventKind::OperationStarted)
                .with_request_id(request_id)
                .with_client(client_summary.clone())
                .with_operation(&request.operation)
                .with_target(target_summary.clone())
                .with_safety(op_def.safety),
        );

        let handler = match self.handlers.get(&request.operation) {
            Some(h) => h,
            None => {
                let err = EnclaveError::Internal(format!(
                    "no handler registered for operation: {}",
                    request.operation
                ));
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::OperationFailed)
                        .with_request_id(request_id)
                        .with_client(client_summary.clone())
                        .with_operation(&request.operation)
                        .with_target(target_summary.clone())
                        .with_outcome("error")
                        .with_detail("no handler registered")
                        .with_latency_ms(start.elapsed().as_millis() as i64),
                );
                return self.error_to_sanitized(&err);
            }
        };

        let op_start = Instant::now();
        let result = handler.execute(&request).await;
        let op_latency = op_start.elapsed();

        match result {
            Ok(payload) => {
                // --- Step 8: Sanitize response ---
                let raw = SanitizedResponse::<Unsanitized>::from_payload(payload);
                let sanitized = self.sanitizer.sanitize_response(raw);

                // --- Step 9: Emit success ---
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::OperationSucceeded)
                        .with_request_id(request_id)
                        .with_client(client_summary)
                        .with_operation(&request.operation)
                        .with_target(target_summary)
                        .with_safety(op_def.safety)
                        .with_outcome("ok")
                        .with_latency_ms(op_latency.as_millis() as i64)
                        .with_secret_names(request.secret_ref_names.clone()),
                );

                sanitized
            }
            Err(err_msg) => {
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::OperationFailed)
                        .with_request_id(request_id)
                        .with_client(client_summary)
                        .with_operation(&request.operation)
                        .with_target(target_summary)
                        .with_safety(op_def.safety)
                        .with_outcome("error")
                        .with_latency_ms(op_latency.as_millis() as i64),
                );

                let err = EnclaveError::OperationFailed(err_msg);
                self.error_to_sanitized(&err)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check safety-class constraints before policy evaluation.
    fn check_safety_constraints(
        &self,
        _request: &OperationRequest,
        op_def: &OperationDef,
    ) -> Result<(), EnclaveError> {
        // REVEAL operations are hard-blocked for ALL clients in v1.
        // This is a defense-in-depth measure: even if policy somehow allows it,
        // the safety check prevents plaintext secret disclosure.
        if op_def.safety == OperationSafety::Reveal {
            return Err(EnclaveError::SafetyViolation(
                "REVEAL operations are not permitted in v1".into(),
            ));
        }
        Ok(())
    }

    /// Handle the approval gate if the policy decision requires it.
    async fn handle_approval(
        &self,
        request: &OperationRequest,
        op_def: &OperationDef,
        decision: &PolicyDecision,
        client_summary: &ClientSummary,
        target_summary: &TargetSummary,
    ) -> Result<(), EnclaveError> {
        let needs_approval = match decision.approval_requirement {
            ApprovalRequirement::Always => true,
            ApprovalRequirement::FirstUse => {
                let lease_key = LeaseKey::from_request(request);
                if self.lease_cache.check(&lease_key) {
                    // Lease hit — emit audit event, skip approval.
                    self.audit.emit(
                        AuditEvent::new(AuditEventKind::LeaseHit)
                            .with_request_id(request.request_id)
                            .with_client(client_summary.clone())
                            .with_operation(&request.operation)
                            .with_target(target_summary.clone())
                            .with_outcome("lease_used"),
                    );
                    false
                } else {
                    true
                }
            }
            ApprovalRequirement::Never => false,
        };

        if !needs_approval || decision.required_factors.is_empty() {
            return Ok(());
        }

        // Rate limit check before presenting approval prompt.
        // The audit event is emitted by emit_and_sanitize_error in execute().
        if !self
            .rate_limiter
            .check_and_record(request.client_identity.pid, &request.operation)
        {
            return Err(EnclaveError::RateLimited(format!(
                "too many approval requests for operation '{}'",
                request.operation,
            )));
        }

        let approval_id = Uuid::new_v4();
        let content_hash = request.content_hash();

        // Emit approval required event.
        self.audit.emit(
            AuditEvent::new(AuditEventKind::ApprovalRequired)
                .with_request_id(request.request_id)
                .with_approval_id(approval_id)
                .with_client(client_summary.clone())
                .with_operation(&request.operation)
                .with_target(target_summary.clone())
                .with_request_hash(&content_hash),
        );

        // Build the approval description that the user will see.
        // SECURITY: Never use {:?} on raw client-controlled maps — it could
        // embed secrets or control characters in the approval UI.
        let mut description = format!("Operation: {}", op_def.description);
        for (k, v) in &request.target {
            let v_display = if v.len() > 128 { &v[..128] } else { v };
            description.push_str(&format!("\n  {k}: {v_display}"));
        }
        description.push_str(&format!("\nClient: {}", request.client_identity));
        let ref_display: Vec<&str> = request
            .secret_ref_names
            .iter()
            .take(8)
            .map(|s| s.as_str())
            .collect();
        description.push_str(&format!("\nSecrets: [{}]", ref_display.join(", ")));
        if let Some(ref ws) = request.workspace {
            let url = ws.remote_url.as_deref().unwrap_or("?");
            description.push_str(&format!(
                "\nWorkspace: repo={}, branch={}",
                opaque_core::validate::InputValidator::sanitize_url(url),
                ws.branch.as_deref().unwrap_or("?"),
            ));
        }
        // Append truncated content hash for cryptographic binding.
        description.push_str(&format!("\nRequest Hash: {}", &content_hash[..16]));

        // Serialize approval prompts to avoid races.
        let _permit = self
            .approval_semaphore
            .acquire()
            .await
            .map_err(|_| EnclaveError::ApprovalUnavailable("approval gate closed".into()))?;

        // Emit approval presented event.
        self.audit.emit(
            AuditEvent::new(AuditEventKind::ApprovalPresented)
                .with_request_id(request.request_id)
                .with_approval_id(approval_id)
                .with_client(client_summary.clone())
                .with_operation(&request.operation)
                .with_target(target_summary.clone())
                .with_request_hash(&content_hash),
        );

        let approval_start = Instant::now();
        let result = self
            .approval_gate
            .request_approval(
                approval_id,
                request,
                &decision.required_factors,
                &description,
            )
            .await;
        let approval_latency = approval_start.elapsed();

        match result {
            Ok(true) => {
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::ApprovalGranted)
                        .with_request_id(request.request_id)
                        .with_approval_id(approval_id)
                        .with_client(client_summary.clone())
                        .with_operation(&request.operation)
                        .with_target(target_summary.clone())
                        .with_outcome("granted")
                        .with_latency_ms(approval_latency.as_millis() as i64)
                        .with_request_hash(&content_hash),
                );

                // Grant a lease for FirstUse approvals.
                if decision.approval_requirement == ApprovalRequirement::FirstUse {
                    let ttl = decision.lease_ttl.unwrap_or(DEFAULT_LEASE_TTL);
                    let lease_key = LeaseKey::from_request(request);
                    self.lease_cache.grant(lease_key, ttl, decision.one_time);
                }

                Ok(())
            }
            Ok(false) => {
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::ApprovalDenied)
                        .with_request_id(request.request_id)
                        .with_approval_id(approval_id)
                        .with_client(client_summary.clone())
                        .with_operation(&request.operation)
                        .with_target(target_summary.clone())
                        .with_outcome("denied")
                        .with_latency_ms(approval_latency.as_millis() as i64)
                        .with_request_hash(&content_hash),
                );
                Err(EnclaveError::ApprovalNotGranted(
                    "user denied the approval request".into(),
                ))
            }
            Err(e) => {
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::ApprovalDenied)
                        .with_request_id(request.request_id)
                        .with_approval_id(approval_id)
                        .with_client(client_summary.clone())
                        .with_operation(&request.operation)
                        .with_target(target_summary.clone())
                        .with_outcome("error")
                        .with_level(AuditLevel::Error)
                        .with_latency_ms(approval_latency.as_millis() as i64)
                        .with_request_hash(&content_hash),
                );
                Err(EnclaveError::ApprovalUnavailable(e))
            }
        }
    }

    /// Convert an error to a sanitized error response.
    fn error_to_sanitized(&self, err: &EnclaveError) -> SanitizedResponse<Sanitized> {
        let raw = SanitizedResponse::<Unsanitized>::from_error(
            err.error_code(),
            err.to_string(),
            serde_json::Value::Null,
        );
        self.sanitizer.sanitize_response(raw)
    }

    /// Emit an error audit event and return a sanitized error response.
    #[allow(clippy::too_many_arguments)]
    fn emit_and_sanitize_error(
        &self,
        request_id: Uuid,
        client_summary: &ClientSummary,
        operation: &str,
        target_summary: &TargetSummary,
        secret_names: &[String],
        err: &EnclaveError,
        start: Instant,
    ) -> SanitizedResponse<Sanitized> {
        let kind = match err {
            EnclaveError::PolicyDenied(_) => AuditEventKind::PolicyDenied,
            EnclaveError::ApprovalNotGranted(_) | EnclaveError::ApprovalUnavailable(_) => {
                AuditEventKind::ApprovalDenied
            }
            EnclaveError::RateLimited(_) => AuditEventKind::RateLimited,
            _ => AuditEventKind::OperationFailed,
        };

        self.audit.emit(
            AuditEvent::new(kind)
                .with_request_id(request_id)
                .with_client(client_summary.clone())
                .with_operation(operation)
                .with_target(target_summary.clone())
                .with_outcome("error")
                .with_latency_ms(start.elapsed().as_millis() as i64)
                .with_secret_names(secret_names.to_vec())
                .with_detail(err.error_code()),
        );

        self.error_to_sanitized(err)
    }
}

// ---------------------------------------------------------------------------
// Native approval gate (production)
// ---------------------------------------------------------------------------

/// Native OS approval gate that delegates to the platform-specific
/// approval prompt (macOS LocalAuthentication / Linux polkit).
#[derive(Debug)]
pub struct NativeApprovalGate;

impl ApprovalGate for NativeApprovalGate {
    fn request_approval(
        &self,
        _approval_id: Uuid,
        _request: &OperationRequest,
        _factors: &[ApprovalFactor],
        description: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>
    {
        let desc = description.to_owned();
        Box::pin(async move {
            crate::approval::prompt(&desc)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

// ---------------------------------------------------------------------------
// Test support: stub implementations
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_support {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// An approval gate that always approves and counts invocations.
    /// Used to assert "approval was called exactly N times" for lease tests.
    #[derive(Debug)]
    pub struct CountingApproveGate {
        pub count: Arc<AtomicU32>,
    }

    impl CountingApproveGate {
        pub fn new() -> (Self, Arc<AtomicU32>) {
            let count = Arc::new(AtomicU32::new(0));
            (
                Self {
                    count: count.clone(),
                },
                count,
            )
        }
    }

    impl ApprovalGate for CountingApproveGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            _request: &OperationRequest,
            _factors: &[ApprovalFactor],
            _description: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>
        {
            self.count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(true) })
        }
    }

    /// A no-op approval gate that always approves. For testing only.
    #[derive(Debug)]
    pub struct AlwaysApproveGate;

    impl ApprovalGate for AlwaysApproveGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            _request: &OperationRequest,
            _factors: &[ApprovalFactor],
            _description: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>
        {
            Box::pin(async { Ok(true) })
        }
    }

    /// A no-op approval gate that always denies. For testing only.
    #[derive(Debug)]
    pub struct AlwaysDenyGate;

    impl ApprovalGate for AlwaysDenyGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            _request: &OperationRequest,
            _factors: &[ApprovalFactor],
            _description: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>
        {
            Box::pin(async { Ok(false) })
        }
    }

    /// A stub operation handler that returns a fixed payload. For testing only.
    #[derive(Debug)]
    pub struct StubHandler {
        pub response: serde_json::Value,
    }

    impl OperationHandler for StubHandler {
        fn execute(
            &self,
            _request: &OperationRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + '_>,
        > {
            let resp = self.response.clone();
            Box::pin(async move { Ok(resp) })
        }
    }

    /// A stub operation handler that always fails. For testing only.
    #[derive(Debug)]
    pub struct FailingHandler {
        pub error_message: String,
    }

    impl OperationHandler for FailingHandler {
        fn execute(
            &self,
            _request: &OperationRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + '_>,
        > {
            let msg = self.error_message.clone();
            Box::pin(async move { Err(msg) })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use opaque_core::audit::InMemoryAuditEmitter;
    use std::time::SystemTime;

    use opaque_core::operation::{
        ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationDef,
        OperationRequest, OperationSafety, WorkspaceContext,
    };
    use opaque_core::policy::*;

    fn test_identity() -> ClientIdentity {
        ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/claude-code".into()),
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
        }
    }

    fn test_request(operation: &str, client_type: ClientType) -> OperationRequest {
        OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: test_identity(),
            client_type,
            operation: operation.into(),
            target: {
                let mut m = HashMap::new();
                m.insert("repo".into(), "org/myrepo".into());
                m
            },
            secret_ref_names: vec!["JWT".into()],
            created_at: SystemTime::now(),
            expires_at: None,
            params: serde_json::Value::Null,
            workspace: None,
        }
    }

    fn test_registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        reg.register(OperationDef {
            name: "github.set_actions_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Actions repository secret".into(),
            params_schema: None,
            allowed_target_keys: vec![],
        })
        .unwrap();
        reg.register(OperationDef {
            name: "secret.reveal".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::Fido2],
            description: "Reveal a secret value (human only)".into(),
            params_schema: None,
            allowed_target_keys: vec![],
        })
        .unwrap();
        reg
    }

    fn test_policy() -> PolicyEngine {
        PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-claude-github".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "org/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: true,
            },
        }])
    }

    fn build_enclave(gate: Box<dyn ApprovalGate>, audit: Arc<InMemoryAuditEmitter>) -> Enclave {
        Enclave::builder()
            .registry(test_registry())
            .policy(test_policy())
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok", "repo": "org/myrepo", "name": "JWT"}),
                }),
            )
            .approval_gate(gate)
            .audit(audit)
            .build()
    }

    #[tokio::test]
    async fn successful_operation() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        // Response should be sanitized and successful.
        assert!(resp.error_code().is_none());
        assert_eq!(resp.payload()["status"], "ok");

        // Audit should contain the full event chain.
        let events = audit.events();
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&AuditEventKind::RequestReceived));
        assert!(kinds.contains(&AuditEventKind::ApprovalRequired));
        assert!(kinds.contains(&AuditEventKind::ApprovalPresented));
        assert!(kinds.contains(&AuditEventKind::ApprovalGranted));
        assert!(kinds.contains(&AuditEventKind::OperationStarted));
        assert!(kinds.contains(&AuditEventKind::OperationSucceeded));
    }

    #[tokio::test]
    async fn unknown_operation_denied() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        let req = test_request("k8s.set_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("unknown_operation"));
    }

    #[tokio::test]
    async fn reveal_denied_for_agent() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        // Add a policy rule for secret.reveal to test safety enforcement.
        let mut policy = test_policy();
        policy.add_rule(PolicyRule {
            name: "allow-reveal".into(),
            client: ClientMatch::default(),
            operation_pattern: "secret.*".into(),
            target: TargetMatch::default(),
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::Fido2],
                lease_ttl: None,
                one_time: true,
            },
        });

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(policy)
            .handler(
                "secret.reveal",
                Box::new(StubHandler {
                    response: serde_json::json!({"value": "supersecret"}),
                }),
            )
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        let req = test_request("secret.reveal", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("safety_violation"));
        // Verify error message reflects v1 hard-block.
        let msg = resp.error_message.as_deref().unwrap_or("");
        assert!(msg.contains("not permitted in v1"));
    }

    #[tokio::test]
    async fn reveal_denied_for_human() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mut policy = test_policy();
        policy.add_rule(PolicyRule {
            name: "allow-reveal".into(),
            client: ClientMatch::default(),
            operation_pattern: "secret.*".into(),
            target: TargetMatch::default(),
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: true,
            },
        });

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(policy)
            .handler(
                "secret.reveal",
                Box::new(StubHandler {
                    response: serde_json::json!({"value": "supersecret"}),
                }),
            )
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        // Human client should ALSO be blocked from REVEAL in v1.
        let req = test_request("secret.reveal", ClientType::Human);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("safety_violation"));
        let msg = resp.error_message.as_deref().unwrap_or("");
        assert!(msg.contains("not permitted in v1"));
    }

    #[tokio::test]
    async fn policy_denied() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        // Request with wrong target (other-org).
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.target.insert("repo".into(), "other-org/repo".into());
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("policy_denied"));

        // Audit should contain a policy denied event.
        let denied = audit.events_of_kind(AuditEventKind::PolicyDenied);
        assert_eq!(denied.len(), 1);
    }

    #[tokio::test]
    async fn approval_denied() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysDenyGate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("approval_not_granted"));

        let denied = audit.events_of_kind(AuditEventKind::ApprovalDenied);
        assert!(!denied.is_empty());
    }

    #[tokio::test]
    async fn operation_failure_sanitized() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(test_policy())
            .handler(
                "github.set_actions_secret",
                Box::new(FailingHandler {
                    error_message: "failed to connect to https://admin:p4ss@github.com from /Users/alice/.config/gh".into(),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("operation_failed"));
        // The error message should be sanitized.
        let msg = resp.error_message.as_deref().unwrap_or("");
        assert!(!msg.contains("p4ss"));
        assert!(!msg.contains("/Users/alice"));
    }

    #[tokio::test]
    async fn response_payload_sanitized() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Handler returns a payload with a secret-like field.
        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(test_policy())
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({
                        "status": "ok",
                        "password": "hunter2",
                        "token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
                    }),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        // Secret-named fields should be redacted.
        assert_eq!(resp.payload()["password"], "[REDACTED]");
        assert_eq!(resp.payload()["token"], "[REDACTED]");
        assert_eq!(resp.payload()["status"], "ok");
    }

    #[tokio::test]
    async fn full_audit_chain_on_success() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;

        let events = audit.events();
        // Expected chain: RequestReceived, ApprovalRequired, ApprovalPresented,
        // ApprovalGranted, OperationStarted, OperationSucceeded
        assert!(
            events.len() >= 6,
            "expected at least 6 audit events, got {}",
            events.len()
        );

        // All events should share the same request_id.
        let rid = events[0].request_id.unwrap();
        for event in &events {
            if let Some(eid) = event.request_id {
                assert_eq!(eid, rid, "all events should share the same request_id");
            }
        }
    }

    #[tokio::test]
    async fn approval_events_contain_request_hash() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;

        // All approval-related events should carry the request_hash.
        let approval_kinds = [
            AuditEventKind::ApprovalRequired,
            AuditEventKind::ApprovalPresented,
            AuditEventKind::ApprovalGranted,
        ];
        for kind in &approval_kinds {
            let events = audit.events_of_kind(*kind);
            assert!(!events.is_empty(), "expected at least one {kind:?} event");
            for event in &events {
                assert!(
                    event.request_hash.is_some(),
                    "{kind:?} event missing request_hash"
                );
                let hash = event.request_hash.as_ref().unwrap();
                assert_eq!(hash.len(), 64, "request_hash should be 64 hex chars");
                assert!(
                    hash.chars().all(|c| c.is_ascii_hexdigit()),
                    "request_hash should be hex"
                );
            }
        }
    }

    // -- Rate limiter unit tests --

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = ApprovalRateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check_and_record(Some(1), "op1"));
        assert!(limiter.check_and_record(Some(1), "op1"));
        assert!(limiter.check_and_record(Some(1), "op1"));
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let limiter = ApprovalRateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check_and_record(Some(1), "op1"));
        assert!(limiter.check_and_record(Some(1), "op1"));
        assert!(!limiter.check_and_record(Some(1), "op1"));
    }

    #[test]
    fn rate_limiter_different_ops_independent() {
        let limiter = ApprovalRateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_and_record(Some(1), "op1"));
        assert!(limiter.check_and_record(Some(1), "op2"));
        // op1 is now exhausted
        assert!(!limiter.check_and_record(Some(1), "op1"));
        // op2 is also exhausted
        assert!(!limiter.check_and_record(Some(1), "op2"));
    }

    #[test]
    fn rate_limiter_different_pids_independent() {
        let limiter = ApprovalRateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_and_record(Some(1), "op1"));
        assert!(limiter.check_and_record(Some(2), "op1"));
        assert!(!limiter.check_and_record(Some(1), "op1"));
    }

    #[test]
    fn rate_limiter_window_expires() {
        let limiter = ApprovalRateLimiter::new(1, Duration::from_millis(1));
        assert!(limiter.check_and_record(Some(1), "op1"));
        // Sleep to let the window expire.
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check_and_record(Some(1), "op1"));
    }

    #[tokio::test]
    async fn rate_limited_emits_audit_event() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        // Exhaust the rate limit (default 3 per 60s).
        for _ in 0..3 {
            let req = test_request("github.set_actions_secret", ClientType::Agent);
            let _ = enclave.execute(req).await;
        }
        audit.clear();

        // Fourth request should be rate limited.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("rate_limited"));

        let rate_events = audit.events_of_kind(AuditEventKind::RateLimited);
        assert_eq!(rate_events.len(), 1);
    }

    // -- LeaseKey unit tests --

    #[test]
    fn lease_key_deterministic() {
        // Same request fields but different PID → same key.
        let mut req1 = test_request("github.set_actions_secret", ClientType::Agent);
        req1.client_identity.pid = Some(100);
        let mut req2 = req1.clone();
        req2.client_identity.pid = Some(999);
        req2.request_id = Uuid::new_v4(); // different request_id too

        assert_eq!(LeaseKey::from_request(&req1), LeaseKey::from_request(&req2));
    }

    #[test]
    fn lease_key_differs_on_target() {
        let req1 = test_request("github.set_actions_secret", ClientType::Agent);
        let mut req2 = req1.clone();
        req2.target.insert("repo".into(), "other-org/repo".into());

        assert_ne!(LeaseKey::from_request(&req1), LeaseKey::from_request(&req2));
    }

    #[test]
    fn lease_key_differs_on_operation() {
        let mut reg = test_registry();
        // Register a second operation so both are valid.
        reg.register(OperationDef {
            name: "github.delete_actions_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Delete a GitHub Actions secret".into(),
            params_schema: None,
            allowed_target_keys: vec![],
        })
        .unwrap();
        let _ = reg; // just needed to prove it's valid

        let req1 = test_request("github.set_actions_secret", ClientType::Agent);
        let mut req2 = req1.clone();
        req2.operation = "github.delete_actions_secret".into();

        assert_ne!(LeaseKey::from_request(&req1), LeaseKey::from_request(&req2));
    }

    #[test]
    fn lease_key_differs_on_client() {
        let req1 = test_request("github.set_actions_secret", ClientType::Agent);
        let mut req2 = req1.clone();
        req2.client_identity.exe_sha256 = Some("different_hash".into());

        assert_ne!(LeaseKey::from_request(&req1), LeaseKey::from_request(&req2));
    }

    // -- LeaseCache unit tests --

    #[test]
    fn lease_cache_grant_and_check() {
        let cache = LeaseCache::new();
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let key = LeaseKey::from_request(&req);
        cache.grant(key.clone(), Duration::from_secs(60), false);
        assert!(cache.check(&key));
    }

    #[tokio::test]
    async fn lease_cache_expired() {
        let cache = LeaseCache::new();
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let key = LeaseKey::from_request(&req);
        cache.grant(key.clone(), Duration::from_millis(1), false);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!cache.check(&key));
    }

    #[test]
    fn lease_cache_one_time_consumed() {
        let cache = LeaseCache::new();
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let key = LeaseKey::from_request(&req);
        cache.grant(key.clone(), Duration::from_secs(60), true);
        assert!(cache.check(&key)); // first check consumes
        assert!(!cache.check(&key)); // second check → gone
    }

    #[test]
    fn lease_cache_clear() {
        let cache = LeaseCache::new();
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let key = LeaseKey::from_request(&req);
        cache.grant(key.clone(), Duration::from_secs(60), false);
        cache.clear();
        assert!(!cache.check(&key));
    }

    #[test]
    fn lease_cache_different_keys_independent() {
        let cache = LeaseCache::new();
        let req1 = test_request("github.set_actions_secret", ClientType::Agent);
        let mut req2 = req1.clone();
        req2.target.insert("repo".into(), "other/repo".into());
        let key1 = LeaseKey::from_request(&req1);
        let key2 = LeaseKey::from_request(&req2);
        cache.grant(key1.clone(), Duration::from_secs(60), false);
        assert!(cache.check(&key1));
        assert!(!cache.check(&key2));
    }

    // -- Lease integration tests --

    /// Build a policy with a FirstUse rule for github.set_actions_secret.
    fn test_first_use_policy(lease_ttl: Option<Duration>, one_time: bool) -> PolicyEngine {
        PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-claude-github-first-use".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "org/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::FirstUse,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl,
                one_time,
            },
        }])
    }

    fn build_lease_enclave(
        gate: Box<dyn ApprovalGate>,
        audit: Arc<InMemoryAuditEmitter>,
        policy: PolicyEngine,
    ) -> Enclave {
        Enclave::builder()
            .registry(test_registry())
            .policy(policy)
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(gate)
            .audit(audit)
            .build()
    }

    #[tokio::test]
    async fn lease_skips_approval_within_ttl() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();
        let policy = test_first_use_policy(Some(Duration::from_secs(300)), false);
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        // First execution: approval required.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Second execution: lease hit, no approval.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lease_expires_triggers_new_approval() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();
        // 1ms TTL so it expires immediately.
        let policy = test_first_use_policy(Some(Duration::from_millis(1)), false);
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Second execution after expiry: approval required again.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn lease_different_target_no_reuse() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();
        let policy = test_first_use_policy(Some(Duration::from_secs(300)), false);

        // Need a policy that also matches the second target.
        let mut policy_engine = policy;
        policy_engine.add_rule(PolicyRule {
            name: "allow-claude-github-other".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "other/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::FirstUse,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: Some(Duration::from_secs(300)),
                one_time: false,
            },
        });

        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy_engine);

        // First target.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Different target → new approval needed.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.target.insert("repo".into(), "other/repo".into());
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn one_time_lease_consumed() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();
        let policy = test_first_use_policy(Some(Duration::from_secs(300)), true);
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        // 1st execution: approval.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // 2nd execution: lease hit (consumed).
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // 3rd execution: lease gone, approval again.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn always_approval_never_grants_lease() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();
        // Use the original Always policy.
        let policy = test_policy();
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        // Two executions, both should require approval.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn lease_hit_emits_audit_event() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, _count) = CountingApproveGate::new();
        let policy = test_first_use_policy(Some(Duration::from_secs(300)), false);
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        // First: triggers approval, grants lease.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert!(audit.events_of_kind(AuditEventKind::LeaseHit).is_empty());

        // Second: lease hit.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;

        let lease_hits = audit.events_of_kind(AuditEventKind::LeaseHit);
        assert_eq!(lease_hits.len(), 1);
        let hit = &lease_hits[0];
        assert_eq!(hit.outcome.as_deref(), Some("lease_used"));
        assert_eq!(hit.operation.as_deref(), Some("github.set_actions_secret"));
        assert!(hit.request_id.is_some());
        assert!(hit.client.is_some());
        assert!(hit.target.is_some());
    }

    // ======================================================================
    // Approval flow integration tests
    // ======================================================================

    /// An approval gate that returns Err (simulating unavailable approval UI).
    #[derive(Debug)]
    struct ErrorGate {
        message: String,
    }

    impl ApprovalGate for ErrorGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            _request: &OperationRequest,
            _factors: &[ApprovalFactor],
            _description: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>
        {
            let msg = self.message.clone();
            Box::pin(async move { Err(msg) })
        }
    }

    /// An approval gate that sleeps for a configurable duration before approving.
    /// Tracks how many concurrent approvals are in-flight.
    #[derive(Debug)]
    struct SlowApproveGate {
        delay: Duration,
        max_concurrent: Arc<std::sync::atomic::AtomicU32>,
        current: Arc<std::sync::atomic::AtomicU32>,
    }

    impl SlowApproveGate {
        fn new(delay: Duration) -> (Self, Arc<std::sync::atomic::AtomicU32>) {
            let max_concurrent = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let current = Arc::new(std::sync::atomic::AtomicU32::new(0));
            (
                Self {
                    delay,
                    max_concurrent: max_concurrent.clone(),
                    current,
                },
                max_concurrent,
            )
        }
    }

    impl ApprovalGate for SlowApproveGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            _request: &OperationRequest,
            _factors: &[ApprovalFactor],
            _description: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>
        {
            let delay = self.delay;
            let max_conc = self.max_concurrent.clone();
            let current = self.current.clone();
            Box::pin(async move {
                let prev = current.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let in_flight = prev + 1;
                // Update high water mark.
                max_conc.fetch_max(in_flight, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                current.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Ok(true)
            })
        }
    }

    /// An approval gate that captures the description string for assertion.
    #[derive(Debug)]
    struct CapturingGate {
        descriptions: Arc<Mutex<Vec<String>>>,
    }

    impl CapturingGate {
        fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
            let descriptions = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    descriptions: descriptions.clone(),
                },
                descriptions,
            )
        }
    }

    impl ApprovalGate for CapturingGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            _request: &OperationRequest,
            _factors: &[ApprovalFactor],
            description: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + '_>>
        {
            self.descriptions
                .lock()
                .expect("capturing gate mutex")
                .push(description.to_owned());
            Box::pin(async { Ok(true) })
        }
    }

    // -- Approval gate error path --

    #[tokio::test]
    async fn approval_gate_error_returns_unavailable() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let gate = ErrorGate {
            message: "Touch ID not available in SSH session".into(),
        };
        let enclave = build_enclave(Box::new(gate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("approval_unavailable"));

        // Audit should record the approval denial with "error" outcome.
        let denied = audit.events_of_kind(AuditEventKind::ApprovalDenied);
        assert!(!denied.is_empty());
        assert_eq!(denied[0].outcome.as_deref(), Some("error"));
    }

    // -- Never approval skips gate --

    #[tokio::test]
    async fn never_approval_skips_gate_entirely() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-no-approval".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "org/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Never,
                factors: vec![],
                lease_ttl: None,
                one_time: false,
            },
        }]);

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(policy)
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(gate))
            .audit(audit.clone())
            .build();

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert!(resp.error_code().is_none());
        // Gate should never have been called.
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);

        // No approval events should be emitted.
        assert!(audit
            .events_of_kind(AuditEventKind::ApprovalRequired)
            .is_empty());
        assert!(audit
            .events_of_kind(AuditEventKind::ApprovalPresented)
            .is_empty());
        assert!(audit
            .events_of_kind(AuditEventKind::ApprovalGranted)
            .is_empty());
    }

    // -- Concurrent approval serialization --

    #[tokio::test]
    async fn approval_serialized_by_semaphore() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, max_concurrent) = SlowApproveGate::new(Duration::from_millis(50));

        // Use a FirstUse policy so leases don't interfere between requests
        // (different targets → no lease reuse).
        let mut policy = test_first_use_policy(Some(Duration::from_secs(300)), false);
        // Add a second target rule.
        policy.add_rule(PolicyRule {
            name: "allow-other".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "other/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: false,
            },
        });

        let enclave = Arc::new(
            Enclave::builder()
                .registry(test_registry())
                .policy(policy)
                .handler(
                    "github.set_actions_secret",
                    Box::new(StubHandler {
                        response: serde_json::json!({"status": "ok"}),
                    }),
                )
                .approval_gate(Box::new(gate))
                .audit(audit.clone())
                .build(),
        );

        // Fire 3 concurrent requests with different targets (so no lease hits).
        let targets = ["org/repo1", "org/repo2", "other/repo3"];
        let mut handles = vec![];
        for target in targets {
            let enc = enclave.clone();
            let t = target.to_string();
            handles.push(tokio::spawn(async move {
                let mut req = test_request("github.set_actions_secret", ClientType::Agent);
                req.target.insert("repo".into(), t);
                enc.execute(req).await
            }));
        }

        for h in handles {
            let resp = h.await.unwrap();
            assert!(resp.error_code().is_none());
        }

        // The semaphore should ensure max 1 concurrent approval prompt.
        assert_eq!(
            max_concurrent.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "semaphore should serialize approval prompts to max 1 concurrent"
        );
    }

    // -- Target key validation --

    #[tokio::test]
    async fn unexpected_target_key_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let mut registry = OperationRegistry::new();
        registry
            .register(OperationDef {
                name: "restricted.op".into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Never,
                default_factors: vec![],
                description: "Op with restricted target keys".into(),
                params_schema: None,
                allowed_target_keys: vec!["repo".into(), "environment".into()],
            })
            .unwrap();

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-restricted".into(),
            client: ClientMatch::default(),
            operation_pattern: "restricted.*".into(),
            target: TargetMatch::default(),
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Never,
                factors: vec![],
                lease_ttl: None,
                one_time: false,
            },
        }]);

        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .handler(
                "restricted.op",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        // Request with allowed keys → success.
        let mut req = test_request("restricted.op", ClientType::Human);
        req.target.clear();
        req.target.insert("repo".into(), "org/repo".into());
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());

        // Request with unexpected key → rejected.
        let mut req = test_request("restricted.op", ClientType::Human);
        req.target.clear();
        req.target
            .insert("repo".into(), "org/repo".into());
        req.target
            .insert("injected_field".into(), "malicious".into());
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("bad_request"));
    }

    // -- Params schema validation at enclave level --

    #[tokio::test]
    async fn params_schema_validation_at_enclave() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let mut registry = OperationRegistry::new();
        registry
            .register(OperationDef {
                name: "schema.op".into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Never,
                default_factors: vec![],
                description: "Op with param schema".into(),
                params_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "count": { "type": "integer" }
                    },
                    "required": ["count"]
                })),
                allowed_target_keys: vec![],
            })
            .unwrap();

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-schema".into(),
            client: ClientMatch::default(),
            operation_pattern: "schema.*".into(),
            target: TargetMatch::default(),
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Never,
                factors: vec![],
                lease_ttl: None,
                one_time: false,
            },
        }]);

        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .handler(
                "schema.op",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        // Valid params → success.
        let mut req = test_request("schema.op", ClientType::Human);
        req.params = serde_json::json!({"count": 42});
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());

        // Missing required param → rejected.
        let mut req = test_request("schema.op", ClientType::Human);
        req.params = serde_json::json!({});
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("invalid_params"));

        // Wrong type → rejected.
        let mut req = test_request("schema.op", ClientType::Human);
        req.params = serde_json::json!({"count": "not_a_number"});
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("invalid_params"));
    }

    // -- Workspace-scoped policy through enclave --

    #[tokio::test]
    async fn workspace_constraint_enforced_through_enclave() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-main-only".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "org/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch {
                remote_url_pattern: Some("*github.com:org/*".into()),
                branch_pattern: Some("main".into()),
                require_clean: false,
            },
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: false,
            },
        }]);

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(policy)
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        // Request without workspace → denied (rule requires workspace).
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("policy_denied"));

        // Request with wrong branch → denied.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(WorkspaceContext {
            repo_root: "/tmp/repo".into(),
            remote_url: Some("git@github.com:org/repo.git".into()),
            branch: Some("feature/x".into()),
            head_sha: None,
            dirty: false,
        });
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("policy_denied"));

        // Request with correct workspace → allowed.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(WorkspaceContext {
            repo_root: "/tmp/repo".into(),
            remote_url: Some("git@github.com:org/repo.git".into()),
            branch: Some("main".into()),
            head_sha: None,
            dirty: false,
        });
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
    }

    // -- Secret name constraint through enclave --

    #[tokio::test]
    async fn secret_name_constraint_enforced_through_enclave() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-jwt-only".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "org/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch {
                patterns: vec!["JWT".into(), "GH_*".into()],
            },
            allow: true,
            client_types: vec![ClientType::Agent],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: false,
            },
        }]);

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(policy)
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        // Request with allowed secret name → success.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        // req.secret_ref_names is ["JWT"] from test_request
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());

        // Request with disallowed secret name → denied.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.secret_ref_names = vec!["AWS_SECRET_KEY".into()];
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("policy_denied"));
    }

    // -- Approval description content binding --

    #[tokio::test]
    async fn approval_description_contains_operation_details() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, descriptions) = CapturingGate::new();
        let enclave = build_enclave(Box::new(gate), audit.clone());

        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.target.insert("repo".into(), "org/myrepo".into());
        req.secret_ref_names = vec!["JWT".into(), "API_KEY".into()];
        let _ = enclave.execute(req).await;

        let descs = descriptions.lock().expect("desc lock");
        assert_eq!(descs.len(), 1);
        let desc = &descs[0];

        // Should contain the operation description.
        assert!(
            desc.contains("Set a GitHub Actions repository secret"),
            "description should contain op description"
        );
        // Should contain target fields.
        assert!(
            desc.contains("repo: org/myrepo"),
            "description should contain target repo"
        );
        // Should contain secret ref names.
        assert!(desc.contains("JWT"), "description should list secret refs");
        assert!(
            desc.contains("API_KEY"),
            "description should list secret refs"
        );
        // Should contain a request hash (16 hex chars prefix).
        assert!(
            desc.contains("Request Hash:"),
            "description should contain request hash"
        );
        // Should contain client identity info.
        assert!(
            desc.contains("uid=501"),
            "description should contain client identity"
        );
    }

    // -- Handler execution receives correct request --

    /// A handler that records the request it received.
    #[derive(Debug)]
    struct RecordingHandler {
        received: Arc<Mutex<Vec<OperationRequest>>>,
    }

    impl OperationHandler for RecordingHandler {
        fn execute(
            &self,
            request: &OperationRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + '_>,
        > {
            self.received
                .lock()
                .expect("recording handler mutex")
                .push(request.clone());
            Box::pin(async { Ok(serde_json::json!({"status": "ok"})) })
        }
    }

    #[tokio::test]
    async fn handler_receives_original_request() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let received = Arc::new(Mutex::new(Vec::new()));

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(test_policy())
            .handler(
                "github.set_actions_secret",
                Box::new(RecordingHandler {
                    received: received.clone(),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        let request_id = req.request_id;
        req.target.insert("repo".into(), "org/myrepo".into());
        req.secret_ref_names = vec!["DEPLOY_KEY".into()];
        let resp = enclave.execute(req).await;

        assert!(resp.error_code().is_none());

        let recorded = received.lock().expect("recorded lock");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].request_id, request_id);
        assert_eq!(recorded[0].operation, "github.set_actions_secret");
        assert_eq!(recorded[0].target["repo"], "org/myrepo");
        assert_eq!(recorded[0].secret_ref_names, vec!["DEPLOY_KEY"]);
    }

    // -- Multiple operations with different approval requirements --

    #[tokio::test]
    async fn mixed_approval_requirements() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();

        let mut registry = test_registry();
        registry
            .register(OperationDef {
                name: "github.list_secrets".into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Never,
                default_factors: vec![],
                description: "List secrets (read-only)".into(),
                params_schema: None,
                allowed_target_keys: vec![],
            })
            .unwrap();

        let policy = PolicyEngine::with_rules(vec![
            // list_secrets: no approval needed.
            PolicyRule {
                name: "allow-list".into(),
                client: ClientMatch {
                    uid: Some(501),
                    exe_path: Some("/usr/bin/claude*".into()),
                    ..Default::default()
                },
                operation_pattern: "github.list_secrets".into(),
                target: TargetMatch {
                    fields: {
                        let mut m = HashMap::new();
                        m.insert("repo".into(), "org/*".into());
                        m
                    },
                },
                workspace: WorkspaceMatch::default(),
                secret_names: SecretNameMatch::default(),
                allow: true,
                client_types: vec![ClientType::Agent],
                approval: ApprovalConfig {
                    require: ApprovalRequirement::Never,
                    factors: vec![],
                    lease_ttl: None,
                    one_time: false,
                },
            },
            // set_actions_secret: Always approval.
            PolicyRule {
                name: "allow-set".into(),
                client: ClientMatch {
                    uid: Some(501),
                    exe_path: Some("/usr/bin/claude*".into()),
                    ..Default::default()
                },
                operation_pattern: "github.set_actions_secret".into(),
                target: TargetMatch {
                    fields: {
                        let mut m = HashMap::new();
                        m.insert("repo".into(), "org/*".into());
                        m
                    },
                },
                workspace: WorkspaceMatch::default(),
                secret_names: SecretNameMatch::default(),
                allow: true,
                client_types: vec![ClientType::Agent],
                approval: ApprovalConfig {
                    require: ApprovalRequirement::Always,
                    factors: vec![ApprovalFactor::LocalBio],
                    lease_ttl: None,
                    one_time: false,
                },
            },
        ]);

        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .handler(
                "github.list_secrets",
                Box::new(StubHandler {
                    response: serde_json::json!({"total_count": 0, "secrets": []}),
                }),
            )
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(gate))
            .audit(audit.clone())
            .build();

        // list_secrets: no approval.
        let req = test_request("github.list_secrets", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);

        // set_actions_secret: requires approval.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    // -- Denied policy then allowed on different target --

    #[tokio::test]
    async fn policy_deny_does_not_block_subsequent_allowed_requests() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        // First: denied (wrong target).
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.target.insert("repo".into(), "evil-org/repo".into());
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("policy_denied"));

        // Second: allowed (correct target).
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
    }

    // -- Handler failure does not poison enclave --

    #[tokio::test]
    async fn handler_failure_does_not_poison_enclave() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Register a second operation alongside the failing one.
        let mut registry = test_registry();
        registry
            .register(OperationDef {
                name: "github.list_secrets".into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Always,
                default_factors: vec![ApprovalFactor::LocalBio],
                description: "List secrets".into(),
                params_schema: None,
                allowed_target_keys: vec![],
            })
            .unwrap();

        let enclave = Enclave::builder()
            .registry(registry)
            .policy(test_policy())
            .handler(
                "github.set_actions_secret",
                Box::new(FailingHandler {
                    error_message: "connection refused".into(),
                }),
            )
            .handler(
                "github.list_secrets",
                Box::new(StubHandler {
                    response: serde_json::json!({"total_count": 0, "secrets": []}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        // First: fails.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("operation_failed"));

        // Second: succeeds on a different operation.
        let req = test_request("github.list_secrets", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
    }

    // -- Lease key excludes workspace context --

    #[tokio::test]
    async fn lease_key_excludes_workspace() {
        // Workspace context is intentionally NOT part of the lease key.
        // The lease is scoped to (client, operation, target, secret_refs).
        // Workspace scoping is handled by policy rules, not lease keys.
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();
        let policy = test_first_use_policy(Some(Duration::from_secs(300)), false);
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        // First request with workspace A → triggers approval.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(WorkspaceContext {
            repo_root: "/tmp/repoA".into(),
            remote_url: Some("https://github.com/org/repoA".into()),
            branch: Some("main".into()),
            head_sha: None,
            dirty: false,
        });
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Same canonical fields but different workspace → lease still hits
        // because workspace is NOT in the lease key.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(WorkspaceContext {
            repo_root: "/tmp/repoB".into(),
            remote_url: Some("https://github.com/org/repoB".into()),
            branch: Some("develop".into()),
            head_sha: None,
            dirty: true,
        });
        let _ = enclave.execute(req).await;
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "lease key excludes workspace — should reuse lease"
        );

        // Request without workspace → also reuses same lease.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no workspace also reuses same lease"
        );
    }

    // -- Lease differs by secret_ref_names --

    #[tokio::test]
    async fn lease_differs_by_secret_refs() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, count) = CountingApproveGate::new();
        let policy = test_first_use_policy(Some(Duration::from_secs(300)), false);
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        // First request with secret_ref "JWT" → triggers approval.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Same secret_ref → lease hit.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Different secret_ref → new approval.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.secret_ref_names = vec!["DEPLOY_TOKEN".into()];
        let _ = enclave.execute(req).await;
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "different secret_ref_names should require new approval"
        );
    }

    // -- Audit event ordering --

    #[tokio::test]
    async fn audit_events_in_correct_order() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let _ = enclave.execute(req).await;

        let events = audit.events();
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();

        // Verify strict ordering.
        let expected_order = [
            AuditEventKind::RequestReceived,
            AuditEventKind::ApprovalRequired,
            AuditEventKind::ApprovalPresented,
            AuditEventKind::ApprovalGranted,
            AuditEventKind::OperationStarted,
            AuditEventKind::OperationSucceeded,
        ];

        let mut last_idx = 0;
        for expected in &expected_order {
            let idx = kinds
                .iter()
                .position(|k| k == expected)
                .unwrap_or_else(|| panic!("missing event: {expected:?}"));
            assert!(
                idx >= last_idx,
                "{expected:?} at index {idx} should come after index {last_idx}"
            );
            last_idx = idx;
        }
    }

    // -- SensitiveOutput safety enforcement through enclave --

    #[tokio::test]
    async fn sensitive_output_blocked_for_agent_without_explicit_allowance() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let mut registry = OperationRegistry::new();
        registry
            .register(OperationDef {
                name: "ecr.get_auth_token".into(),
                safety: OperationSafety::SensitiveOutput,
                default_approval: ApprovalRequirement::Always,
                default_factors: vec![ApprovalFactor::LocalBio],
                description: "Get ECR auth token".into(),
                params_schema: None,
                allowed_target_keys: vec![],
            })
            .unwrap();

        // Rule does NOT explicitly include Agent in client_types.
        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-ecr".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "ecr.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "org/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![], // Empty = matches all for matching, but NOT for SENSITIVE_OUTPUT
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: false,
            },
        }]);

        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .handler(
                "ecr.get_auth_token",
                Box::new(StubHandler {
                    response: serde_json::json!({"token": "secret_token"}),
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build();

        // Agent client → policy denied due to SENSITIVE_OUTPUT without explicit allowance.
        let req = test_request("ecr.get_auth_token", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("policy_denied"));

        // Human client → allowed.
        let req = test_request("ecr.get_auth_token", ClientType::Human);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
    }

    // -- Active leases introspection --

    #[tokio::test]
    async fn active_leases_returns_non_expired_entries() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (gate, _count) = CountingApproveGate::new();
        let policy = test_first_use_policy(Some(Duration::from_secs(300)), false);
        let enclave = build_lease_enclave(Box::new(gate), audit.clone(), policy);

        // Before any requests, no leases.
        assert!(enclave.active_leases().is_empty());

        // Execute a request → should create a lease.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());

        // Now should have one active lease.
        let leases = enclave.active_leases();
        assert_eq!(leases.len(), 1, "expected 1 active lease, got {}", leases.len());
        assert_eq!(leases[0].operation, "github.set_actions_secret");
        assert!(leases[0].ttl_remaining_secs > 0);
        assert!(!leases[0].one_time);
    }

    #[tokio::test]
    async fn unresolved_identity_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        // Build a request with the fallback identity (uid == u32::MAX).
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.client_identity.uid = u32::MAX;

        let resp = enclave.execute(req).await;
        assert_eq!(resp.error_code(), Some("identity_verification_failed"));
    }
}
