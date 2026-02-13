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

use agentpass_core::audit::{
    AuditEvent, AuditEventKind, AuditLevel, AuditSink, ClientSummary, TargetSummary,
    WorkspaceSummary,
};
use agentpass_core::operation::{
    ApprovalFactor, ApprovalRequirement, ClientType, OperationDef, OperationRegistry,
    OperationRequest, OperationSafety, validate_params,
};
use agentpass_core::policy::{PolicyDecision, PolicyEngine};
use agentpass_core::sanitize::{Sanitized, SanitizedResponse, Sanitizer, Unsanitized};
use tokio::sync::Semaphore;
use uuid::Uuid;

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
    #[allow(dead_code)] // Will be used when identity verification is implemented
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
    #[allow(dead_code)] // Part of the builder API; used once provider integrations land
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

    /// Execute an operation request through the full enforcement funnel.
    ///
    /// This is the **ONLY** path to run any operation. The return type
    /// `SanitizedResponse<Sanitized>` guarantees at compile time that the
    /// response has been sanitized.
    ///
    /// Pipeline:
    /// 1. Verify client identity
    /// 2. Look up operation in registry
    /// 3. Check safety-class constraints
    /// 4. Evaluate policy
    /// 5. Trigger approval if required
    /// 6. Execute operation handler
    /// 7. Sanitize response
    /// 8. Emit audit events
    pub async fn execute(&self, request: OperationRequest) -> SanitizedResponse<Sanitized> {
        let start = Instant::now();
        let request_id = request.request_id;
        let client_summary = ClientSummary::from((&request.client_identity, request.client_type));
        let target_summary = TargetSummary {
            fields: request.target.clone(),
        };

        let workspace_summary = request.workspace.as_ref().map(|ws| WorkspaceSummary {
            remote_url: ws.remote_url.clone(),
            branch: ws.branch.clone(),
            dirty: ws.dirty,
        });

        // --- Step 1: Emit request received ---
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

        // --- Step 2: Look up operation in registry ---
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

        // --- Step 2b: Validate params against schema ---
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

        // --- Step 3: Safety-class / client-type constraints ---
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

        // --- Step 4: Evaluate policy ---
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

        // --- Step 5: Approval gate ---
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

        // --- Step 6: Execute operation handler ---
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
                // --- Step 7: Sanitize response ---
                let raw = SanitizedResponse::<Unsanitized>::from_payload(payload);
                let sanitized = self.sanitizer.sanitize_response(raw);

                // --- Step 8: Emit success ---
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
        request: &OperationRequest,
        op_def: &OperationDef,
    ) -> Result<(), EnclaveError> {
        match (request.client_type, op_def.safety) {
            // REVEAL is never allowed for agent clients.
            (ClientType::Agent, OperationSafety::Reveal) => Err(EnclaveError::SafetyViolation(
                "REVEAL operations are never permitted for agent clients".into(),
            )),
            // All other combinations are checked by the policy engine.
            _ => Ok(()),
        }
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
                // In a full implementation, check lease cache here.
                // For now, always require approval (fail closed).
                true
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

        // Emit approval required event.
        self.audit.emit(
            AuditEvent::new(AuditEventKind::ApprovalRequired)
                .with_request_id(request.request_id)
                .with_approval_id(approval_id)
                .with_client(client_summary.clone())
                .with_operation(&request.operation)
                .with_target(target_summary.clone()),
        );

        // Build the approval description that the user will see.
        let mut description = format!(
            "Operation: {}\nTarget: {:?}\nClient: {}\nSecrets: [{}]",
            op_def.description,
            request.target,
            request.client_identity,
            request.secret_ref_names.join(", "),
        );
        if let Some(ref ws) = request.workspace {
            description.push_str(&format!(
                "\nWorkspace: repo={}, branch={}, dirty={}",
                ws.remote_url.as_deref().unwrap_or("?"),
                ws.branch.as_deref().unwrap_or("?"),
                ws.dirty,
            ));
        }

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
                .with_target(target_summary.clone()),
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
                        .with_latency_ms(approval_latency.as_millis() as i64),
                );
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
                        .with_latency_ms(approval_latency.as_millis() as i64),
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
                        .with_latency_ms(approval_latency.as_millis() as i64),
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
    use agentpass_core::audit::InMemoryAuditEmitter;
    use std::time::SystemTime;

    use agentpass_core::operation::{
        ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationDef,
        OperationRequest, OperationSafety,
    };
    use agentpass_core::policy::*;

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
        })
        .unwrap();
        reg.register(OperationDef {
            name: "secret.reveal".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::Fido2],
            description: "Reveal a secret value (human only)".into(),
            params_schema: None,
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
}
