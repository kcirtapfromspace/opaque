//! Enclave: the central enforcement funnel for all secret-using operations.
//!
//! Individual operations flow through [`Enclave::execute()`]. Immutable task
//! manifests use `Enclave::execute_task`, which checks every child operation,
//! obtains a fresh native approval and charges durable slots before dispatch.
//! Both transport paths sanitize their responses before returning to clients.
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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opaque_core::audit::{
    AuditEvent, AuditEventKind, AuditLevel, AuditSink, ClientSummary, TargetSummary,
    WorkspaceSummary,
};
use opaque_core::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationDef,
    OperationRegistry, OperationRequest, OperationSafety,
};
use opaque_core::policy::{PolicyDecision, PolicyEngine};
use opaque_core::sanitize::{Sanitized, SanitizedResponse, Sanitizer, Unsanitized};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use uuid::Uuid;

mod audit_durability;
mod task;
pub use task::{
    inference_task_operations, release_task_operations, ssh_task_operations, task_operation,
};

// ---------------------------------------------------------------------------
// Server-side secret ref name derivation
// ---------------------------------------------------------------------------

/// Extract secret reference names from operation params server-side.
///
/// This replaces client-supplied `secret_ref_names` with values derived
/// from the actual operation params using the operation definition's
/// `secret_ref_param_keys`. This prevents policy bypass where a malicious
/// client sends empty or incorrect `secret_ref_names` to sidestep
/// `[rules.secret_names]` constraints.
///
/// For each entry in `param_keys`:
/// - direct key mode: `"value_ref"` extracts params[`value_ref`]
/// - template mode: `"onepassword:{vault}/{item}/{field}"` renders from params
///
/// Non-string, empty, or missing values are skipped (params schema validation
/// has already run by this point).
fn render_secret_ref_template(
    template: &str,
    params: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let mut out = String::new();
    let mut idx = 0usize;

    while idx < template.len() {
        if template.as_bytes()[idx] == b'{' {
            let close = template[idx + 1..].find('}')?;
            let end = idx + 1 + close;
            let key = &template[idx + 1..end];
            if key.is_empty() {
                return None;
            }
            let value = params.get(key)?.as_str()?;
            if value.is_empty() {
                return None;
            }
            out.push_str(value);
            idx = end + 1;
        } else {
            let next = template[idx..]
                .find('{')
                .map(|off| idx + off)
                .unwrap_or(template.len());
            out.push_str(&template[idx..next]);
            idx = next;
        }
    }

    Some(out)
}

fn derive_secret_ref_names(param_keys: &[String], params: &serde_json::Value) -> Vec<String> {
    let mut refs = Vec::new();
    if let serde_json::Value::Object(map) = params {
        for key in param_keys {
            if key.contains('{') {
                if let Some(rendered) = render_secret_ref_template(key, map)
                    && !rendered.is_empty()
                {
                    refs.push(rendered);
                }
                continue;
            }

            if let Some(serde_json::Value::String(val)) = map.get(key.as_str())
                && !val.is_empty()
            {
                refs.push(val.clone());
            }
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

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
/// target, secrets, params) tuple. Deliberately excludes PID so the same
/// binary can reuse a lease across reconnects.
///
/// SECURITY: `params_hash` ensures that different operation parameters
/// (e.g. different `secret_name` or `environment`) produce distinct lease
/// keys, preventing param-swapping under an existing first-use lease.
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
    /// SHA-256 of canonical JSON-serialized params.
    params_hash: String,
    /// Delegation binding `(sub principal id, jti)` when the request runs
    /// under a verified principal context; `None` for un-delegated requests.
    ///
    /// SECURITY: without this, a first-use lease granted to one principal
    /// would be reused by a different principal (or a different delegation
    /// session) at the same uid — leases must never cross principals.
    delegation: Option<(String, String)>,
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

        // Hash of canonical params to prevent param-swapping under a lease.
        let mut params_hasher = Sha256::new();
        let params_canonical = serde_json::to_string(&request.params).unwrap_or_default();
        params_hasher.update(params_canonical.as_bytes());
        let params_hash = format!("{:x}", params_hasher.finalize());

        Self {
            client_fingerprint,
            operation: request.operation.clone(),
            target_canonical,
            secret_refs_canonical,
            params_hash,
            delegation: request
                .principal
                .as_ref()
                .map(|p| (p.sub.as_str().to_owned(), p.jti.clone())),
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
    /// Whether this implementation only supports explicit test endpoints.
    /// Capability status comes from the installed handler, not its name.
    fn fixture_only(&self) -> bool {
        false
    }

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

/// The result of one approval interaction.
///
/// SECURITY INVARIANT: `approver` must only ever be attached by the gate that
/// actually VERIFIED the identity it names. The local biometric factor proves
/// device-owner presence and binds the *name* to the active login session
/// (source `LocalBioSession`). Paired-device / FIDO2 attribution (source
/// `PairedDevice`) requires real signature verification against the pairing
/// store — the dormant `approval_server` relays client-supplied device ids
/// WITHOUT verification and must never be used as an approver source.
#[derive(Debug, Clone)]
pub struct ApprovalOutcome {
    /// Whether the human (or configured backend) approved the request.
    pub approved: bool,
    /// The verified approver identity, when the gate could establish one.
    /// `None` on denial, and on approval paths with no identity binding
    /// (e.g. biometric passed but nobody is logged in).
    pub approver: Option<opaque_core::audit::ApproverIdentity>,
}

impl ApprovalOutcome {
    /// Approved, with no approver identity binding available.
    pub fn approved_anonymous() -> Self {
        Self {
            approved: true,
            approver: None,
        }
    }

    /// Approved by a verified identity.
    pub fn approved_by(approver: opaque_core::audit::ApproverIdentity) -> Self {
        Self {
            approved: true,
            approver: Some(approver),
        }
    }

    /// Denied.
    pub fn denied() -> Self {
        Self {
            approved: false,
            approver: None,
        }
    }
}

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
    /// - Return `Ok` with [`ApprovalOutcome`] (approved/denied, plus the
    ///   verified approver identity when one exists — see the invariant on
    ///   [`ApprovalOutcome`])
    /// - Return `Err` if the approval mechanism is unavailable
    ///
    /// The `approval_id` is used for audit correlation.
    fn request_approval(
        &self,
        approval_id: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        description: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
    >;
}

// ---------------------------------------------------------------------------
// Enclave
// ---------------------------------------------------------------------------

/// The central enforcement funnel.
///
/// All secret-using operations pass through this enclave, via individual
/// execution or the typed, durably accounted task path.
pub struct Enclave {
    inference_profile: Option<crate::inference::TrustedInferenceProfile>,
    ssh_profile: Option<crate::ssh::TrustedSshProfile>,
    /// Exact session/provisioning ceremonies use this complete-review factor.
    session_approval_factor: ApprovalFactor,
    /// Operation registry (immutable after construction).
    registry: OperationRegistry,

    /// Policy engine. Behind an RwLock so a federation bundle refresh can
    /// hot-swap the whole rule set without restarting the daemon; the read
    /// path takes an uncontended read lock per evaluation.
    policy: std::sync::RwLock<PolicyEngine>,
    policy_generation: std::sync::atomic::AtomicU64,

    /// Operation handlers, keyed by operation name.
    handlers: HashMap<String, Box<dyn OperationHandler>>,

    /// Operations supported by the configured bounded-task transport.
    task_operations: HashSet<String>,

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
            .field(
                "policy_rules",
                &self.policy.read().map(|p| p.rule_count()).unwrap_or(0),
            )
            .field("handlers", &self.handlers.len())
            .finish()
    }
}

/// Builder for constructing an [`Enclave`].
pub struct EnclaveBuilder {
    task_grants_enabled: bool,
    inference_profile: Option<crate::inference::TrustedInferenceProfile>,
    ssh_profile: Option<crate::ssh::TrustedSshProfile>,
    session_approval_factor: ApprovalFactor,
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
            task_grants_enabled: false,
            inference_profile: None,
            ssh_profile: None,
            session_approval_factor: ApprovalFactor::LocalBio,
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

    /// Record whether the daemon installed the bounded-task ledger/transport.
    /// Profile-dependent task capabilities also require their trusted profile.
    pub fn task_grants_enabled(mut self, enabled: bool) -> Self {
        self.task_grants_enabled = enabled;
        self
    }

    pub fn inference_profile(
        mut self,
        profile: Option<crate::inference::TrustedInferenceProfile>,
    ) -> Self {
        self.inference_profile = profile;
        self
    }

    pub fn ssh_profile(mut self, profile: Option<crate::ssh::TrustedSshProfile>) -> Self {
        self.ssh_profile = profile;
        self
    }

    /// Choose the trusted review channel for agent-session creation only.
    /// Other control-plane approvals always retain the local native factor.
    pub fn session_approval_factor(mut self, factor: ApprovalFactor) -> Self {
        self.session_approval_factor = factor;
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

    /// Build the enclave. Returns an error if required components are missing.
    pub fn build(self) -> Result<Enclave, String> {
        if !matches!(
            self.session_approval_factor,
            ApprovalFactor::LocalBio | ApprovalFactor::PairedWorkstation
        ) {
            return Err("agent-session approval requires local_bio or paired_workstation".into());
        }
        Ok(Enclave {
            task_operations: task::enabled_operation_names(
                self.task_grants_enabled,
                self.inference_profile.is_some(),
                self.ssh_profile.is_some(),
            ),
            inference_profile: self.inference_profile,
            ssh_profile: self.ssh_profile,
            session_approval_factor: self.session_approval_factor,
            registry: self.registry,
            policy: std::sync::RwLock::new(self.policy),
            policy_generation: std::sync::atomic::AtomicU64::new(0),
            handlers: self.handlers,
            approval_gate: self.approval_gate.ok_or("approval gate is required")?,
            audit: self.audit.ok_or("audit sink is required")?,
            sanitizer: self.sanitizer,
            approval_semaphore: Semaphore::new(1),
            rate_limiter: ApprovalRateLimiter::new(3, Duration::from_secs(60)),
            lease_cache: LeaseCache::new(),
        })
    }
}

impl Default for EnclaveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Enclave {
    pub fn ssh_profile(&self) -> Result<&crate::ssh::TrustedSshProfile, String> {
        self.ssh_profile
            .as_ref()
            .ok_or_else(|| "tenant SSH is not configured".into())
    }
    pub fn inference_profile(&self) -> Result<&crate::inference::TrustedInferenceProfile, String> {
        self.inference_profile
            .as_ref()
            .ok_or_else(|| "tenant inference is not configured".into())
    }
    /// Create a builder for constructing an enclave.
    pub fn builder() -> EnclaveBuilder {
        EnclaveBuilder::new()
    }

    /// Registry and configured execution-path facts only. Policy is evaluated
    /// against the actual principal, target and parameters for each request.
    pub fn operation_catalog(&self) -> Vec<serde_json::Value> {
        let mut operations: Vec<_> = self
            .registry
            .iter()
            .map(|def| {
                let handler = self.handlers.get(&def.name);
                let task_enabled = self.task_operations.contains(&def.name);
                let availability = match (handler, task_enabled) {
                    (_, true) => "enabled",
                    (None, false) => "disabled",
                    (Some(handler), false) if handler.fixture_only() => "fixture_only",
                    (Some(_), false) => "enabled",
                };
                let execution_paths: Vec<_> = [
                    handler.is_some().then_some("operation"),
                    task_enabled.then_some("task"),
                ]
                .into_iter()
                .flatten()
                .collect();
                serde_json::json!({
                    "name": def.name,
                    "provider": def.name.split('.').next().unwrap_or("unknown"),
                    "safety": format!("{:?}", def.safety),
                    "default_approval": def.default_approval,
                    "default_factors": def.default_factors,
                    "description": def.description,
                    "mcp_exposed": opaque_core::capability::mcp_exposes(&def.name),
                    "availability": availability,
                    "execution_paths": execution_paths,
                    "policy_status": "evaluated_per_request",
                })
            })
            .collect();
        operations.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        operations
    }

    /// Return a snapshot of active (non-expired) approval leases.
    pub fn active_leases(&self) -> Vec<LeaseInfo> {
        self.lease_cache.active_leases()
    }

    /// Replace the policy engine in place (federation bundle hot-swap).
    ///
    /// Requests already past their policy evaluation finish under the old
    /// rules; every evaluation after the swap sees the new set. Returns the
    /// new rule count.
    pub fn swap_policy(&self, policy: PolicyEngine) -> usize {
        let count = policy.rule_count();
        let mut current = self
            .policy
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = policy;
        self.policy_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        count
    }

    /// Execute an operation request through the full enforcement funnel.
    ///
    /// This is the path for individual operations. The return type
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
    pub async fn execute(&self, mut request: OperationRequest) -> SanitizedResponse<Sanitized> {
        let start = Instant::now();
        let request_id = request.request_id;
        let mut client_summary =
            ClientSummary::from((&request.client_identity, request.client_type));
        // Attach the verified delegation context so every operation audit
        // record attributes the request to its principal (on-behalf-of).
        if let Some(ref ctx) = request.principal {
            client_summary = client_summary.with_principal(ctx);
        }
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
        if let Err(errors) = self
            .registry
            .validate_params(&request.operation, &request.params)
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

        // --- Step 3d: Derive secret_ref_names server-side ---
        // SECURITY: Never trust client-supplied secret_ref_names. Extract
        // them from the operation params using the operation definition's
        // `secret_ref_param_keys`. This prevents policy bypass where a
        // client sends empty secret_ref_names to sidestep secret name
        // constraints.
        if !op_def.secret_ref_param_keys.is_empty() {
            let derived = derive_secret_ref_names(&op_def.secret_ref_param_keys, &request.params);
            request.secret_ref_names = derived;
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
        let mut decision = self
            .policy
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .evaluate(&request, op_def.safety);

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

            let err = EnclaveError::PolicyDenied(format!(
                "operation '{}' denied by policy \u{2014} debug with: opaque policy simulate --operation {}",
                request.operation, request.operation
            ));
            return self.error_to_sanitized(&err);
        }

        // --- Step 5b: Clamp the approval decision (defense-in-depth) ---
        //
        // SECURITY (H10 + software-first): the operation's `default_approval` is a
        // floor a policy rule may raise but never lower, and a SensitiveOutput
        // operation always requires out-of-band approval — presence is proven by
        // the approval act, not by client classification (which is audit-only).
        decision.approval_requirement =
            stricter_requirement(op_def.default_approval, decision.approval_requirement);
        if op_def.safety == OperationSafety::SensitiveOutput {
            decision.approval_requirement = ApprovalRequirement::Always;
        }
        if decision.required_factors.is_empty() {
            decision.required_factors = op_def.default_factors.clone();
        }
        if decision.approval_requirement != ApprovalRequirement::Never
            && decision.required_factors.is_empty()
        {
            let err = EnclaveError::SafetyViolation(format!(
                "operation '{}' requires approval but no approval factor is configured",
                request.operation
            ));
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

        if let Err(error) = self.confirm_audit(false).await {
            return self.error_to_sanitized(&error);
        }
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

                if let Err(error) = self.confirm_audit(true).await {
                    return self.error_to_sanitized(&error);
                }
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
        // REVEAL operations are hard-blocked for ALL clients. Defense-in-depth:
        // even if policy somehow allows it, this prevents plaintext disclosure.
        if op_def.safety == OperationSafety::Reveal {
            return Err(EnclaveError::SafetyViolation(
                "REVEAL operations are not permitted in v1".into(),
            ));
        }
        // NOTE (software-first, C1): SensitiveOutput is NOT gated on client
        // classification here — classification is audit-only and cannot be a
        // security boundary at a shared uid, where an agent drives the same signed
        // CLI a human does. SensitiveOutput is instead gated on mandatory
        // out-of-band approval, enforced by the approval clamp in `execute`: a
        // human proves presence at the prompt; the agent cannot satisfy it.
        Ok(())
    }

    /// Run a standalone out-of-band approval not tied to a registered operation.
    ///
    /// Used for privileged control-plane actions — minting an agent session
    /// token, starting or confirming a device pairing: the act must be
    /// authorized by a fresh human approval (which an agent cannot satisfy),
    /// never by client classification. Reuses the same rate limiter, prompt
    /// serialization, and audit trail as operation approvals. On success,
    /// returns the verified approver identity when the gate could establish
    /// one.
    pub async fn request_control_approval(
        &self,
        identity: &ClientIdentity,
        client_type: ClientType,
        operation_label: &str,
        action_description: &str,
        reason: &str,
    ) -> Result<Option<opaque_core::audit::ApproverIdentity>, EnclaveError> {
        let client_summary = ClientSummary::from((identity, client_type));
        let complete_review = matches!(
            operation_label,
            "agent_session_start"
                | "identity.provisioning.bind_start"
                | "identity.provisioning.mandate_start"
        );
        let reviewed_reason = if complete_review {
            // The caller constructs trusted authority fields and a bounded
            // label. Preserve every reviewed byte; invalid or oversized
            // content must fail rather than hide authority by truncation.
            if reason.trim().is_empty() || reason.len() > 8 * 1024 || reason.chars().any(|c| {
                (c.is_control() && c != '\n' && c != '\t')
                    || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            }) {
                return Err(EnclaveError::InvalidInput("control review must be complete, bounded, and free of display controls".into()));
            }
            reason.to_owned()
        } else {
            sanitize_for_display(reason, 256)
        };
        let factor = if complete_review {
            self.session_approval_factor
        } else {
            ApprovalFactor::LocalBio
        };

        if !self
            .rate_limiter
            .check_and_record(identity.pid, operation_label)
        {
            return Err(EnclaveError::RateLimited(
                "too many session approval requests".into(),
            ));
        }

        let approval_id = Uuid::new_v4();
        self.audit.emit(
            AuditEvent::new(AuditEventKind::ApprovalRequired)
                .with_approval_id(approval_id)
                .with_client(client_summary.clone())
                .with_operation(operation_label),
        );

        // Serialize prompts to avoid races / approval stacking.
        let _permit = self
            .approval_semaphore
            .acquire()
            .await
            .map_err(|_| EnclaveError::ApprovalUnavailable("approval gate closed".into()))?;

        let description = format!(
            "Operation: {action_description}\n  {reviewed_reason}\nClient: {}",
            identity
        );
        // Bind the full session/provisioning review into request authority as well
        // as the workstation protocol's exact reviewed-content signature.
        let synth = OperationRequest {
            principal: None,
            request_id: approval_id,
            client_identity: identity.clone(),
            client_type,
            operation: operation_label.to_owned(),
            target: std::collections::HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: if complete_review {
                serde_json::json!({"control_review": description})
            } else {
                serde_json::Value::Null
            },
            workspace: None,
        };

        self.audit.emit(
            AuditEvent::new(AuditEventKind::ApprovalPresented)
                .with_approval_id(approval_id)
                .with_client(client_summary.clone())
                .with_operation(operation_label),
        );

        let result = self
            .approval_gate
            .request_approval(approval_id, &synth, &[factor], &description)
            .await;

        match result {
            Ok(outcome) if outcome.approved => {
                let mut granted = AuditEvent::new(AuditEventKind::ApprovalGranted)
                    .with_approval_id(approval_id)
                    .with_client(client_summary)
                    .with_operation(operation_label)
                    .with_outcome("granted");
                if let Some(ref approver) = outcome.approver {
                    granted = granted.with_approver(approver.clone());
                }
                self.audit.emit(granted);
                self.confirm_audit(false).await?;
                Ok(outcome.approver)
            }
            Ok(_) => {
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::ApprovalDenied)
                        .with_approval_id(approval_id)
                        .with_client(client_summary)
                        .with_operation(operation_label)
                        .with_outcome("denied"),
                );
                Err(EnclaveError::ApprovalNotGranted(format!(
                    "{operation_label} was not approved"
                )))
            }
            Err(e) => {
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::ApprovalDenied)
                        .with_approval_id(approval_id)
                        .with_client(client_summary)
                        .with_operation(operation_label)
                        .with_outcome("error"),
                );
                Err(EnclaveError::ApprovalUnavailable(e))
            }
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

        // Segregation of duties: `require_distinct_approver` only makes sense
        // when an approval actually happens and the request is bound to a
        // principal. Both misconfigurations fail closed (never silently skip).
        if decision.require_distinct_approver {
            if decision.approval_requirement == ApprovalRequirement::Never {
                return Err(EnclaveError::SafetyViolation(
                    "require_distinct_approver is set but the rule never requires approval".into(),
                ));
            }
            if request.principal.is_none() {
                self.audit.emit(
                    AuditEvent::new(AuditEventKind::ApprovalDenied)
                        .with_request_id(request.request_id)
                        .with_client(client_summary.clone())
                        .with_operation(&request.operation)
                        .with_target(target_summary.clone())
                        .with_outcome("denied")
                        .with_detail("distinct approver required but request has no principal"),
                );
                return Err(EnclaveError::ApprovalNotGranted(
                    "this operation requires a distinct approver, which needs an \
                     identity-bound request — run it under a delegation"
                        .into(),
                ));
            }
        }

        if !needs_approval {
            return Ok(());
        }
        // SECURITY (H10): a required approval with no configured factor must fail
        // closed, never be silently skipped. `execute` clamps factors to the
        // operation's defaults before this point, so an empty set here is a real
        // misconfiguration rather than a valid "no approval needed" signal.
        if decision.required_factors.is_empty() {
            return Err(EnclaveError::SafetyViolation(
                "approval required but no approval factor is configured".into(),
            ));
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
        // SECURITY: Defensively sanitize all client-controlled strings before
        // rendering into the approval prompt. This is defense-in-depth: even
        // if upstream validation is bypassed, the prompt cannot be spoofed.
        let mut description = format!("Operation: {}", op_def.description);
        if matches!(
            request.operation.as_str(),
            "github.publish_manifest"
                | "github.release_manifest"
                | "inference.fixed_manifest"
                | "ssh.health_manifest"
        ) {
            description.push_str(&task::approval_description(
                request,
                self.inference_profile.as_ref(),
                self.ssh_profile.as_ref(),
            )?);
        }
        for (k, v) in &request.target {
            // SECURITY (C3): the command is the security-critical field the approver
            // must actually read, so render it in full (sanitized to a single line)
            // with an explicit truncation marker — never silently cut it, which would
            // let an attacker hide an exfil tail past a truncation limit. Other target
            // fields are short identifiers and keep the conservative cap.
            if k == "command" {
                let full = sanitize_for_display(v, 4096);
                let marker = if v.chars().count() > 4096 {
                    " …(truncated)"
                } else {
                    ""
                };
                description.push_str(&format!("\n  command: {full}{marker}"));
                continue;
            }
            let v_safe = sanitize_for_display(v, 128);
            description.push_str(&format!("\n  {k}: {v_safe}"));
        }
        description.push_str(&format!("\nClient: {}", request.client_identity));
        let ref_display: Vec<String> = request
            .secret_ref_names
            .iter()
            .take(8)
            .map(|s| sanitize_for_display(s, 128))
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
            Ok(outcome) if outcome.approved => {
                // Segregation of duties: the approver must be a verified
                // identity DIFFERENT from the principal the operation is for.
                // An anonymous approval (nobody logged in) fails closed —
                // presence alone cannot satisfy a distinct-approver rule.
                if decision.require_distinct_approver {
                    let sub = request
                        .principal
                        .as_ref()
                        .map(|p| p.sub.as_str())
                        .unwrap_or_default();
                    let distinct = outcome
                        .approver
                        .as_ref()
                        .is_some_and(|a| a.principal_id != sub);
                    if !distinct {
                        let mut denied = AuditEvent::new(AuditEventKind::ApprovalDenied)
                            .with_request_id(request.request_id)
                            .with_approval_id(approval_id)
                            .with_client(client_summary.clone())
                            .with_operation(&request.operation)
                            .with_target(target_summary.clone())
                            .with_outcome("denied")
                            .with_latency_ms(approval_latency.as_millis() as i64)
                            .with_request_hash(&content_hash)
                            .with_detail("distinct approver required");
                        if let Some(ref approver) = outcome.approver {
                            denied = denied.with_approver(approver.clone());
                        }
                        self.audit.emit(denied);
                        return Err(EnclaveError::ApprovalNotGranted(
                            "approval was granted, but this operation requires an approver \
                             distinct from the principal it runs on behalf of"
                                .into(),
                        ));
                    }
                }

                let mut granted = AuditEvent::new(AuditEventKind::ApprovalGranted)
                    .with_request_id(request.request_id)
                    .with_approval_id(approval_id)
                    .with_client(client_summary.clone())
                    .with_operation(&request.operation)
                    .with_target(target_summary.clone())
                    .with_outcome("granted")
                    .with_latency_ms(approval_latency.as_millis() as i64)
                    .with_request_hash(&content_hash);
                if let Some(ref approver) = outcome.approver {
                    granted = granted.with_approver(approver.clone());
                }
                self.audit.emit(granted);

                // Grant a lease for FirstUse approvals.
                if decision.approval_requirement == ApprovalRequirement::FirstUse {
                    let ttl = decision.lease_ttl.unwrap_or(DEFAULT_LEASE_TTL);
                    let lease_key = LeaseKey::from_request(request);
                    self.lease_cache.grant(lease_key, ttl, decision.one_time);
                }

                Ok(())
            }
            Ok(_) => {
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
                let factor_names: Vec<&str> = decision
                    .required_factors
                    .iter()
                    .map(|f| match f {
                        ApprovalFactor::LocalBio => "local_bio",
                        ApprovalFactor::IosFaceId => "ios_faceid",
                        ApprovalFactor::Fido2 => "fido2",
                        ApprovalFactor::PairedWorkstation => "paired_workstation",
                    })
                    .collect();
                let factor_str = factor_names.join(", ");
                let platform_hint = if cfg!(target_os = "macos") {
                    "Touch ID will prompt on the next attempt"
                } else if cfg!(target_os = "linux") {
                    "configure polkit for biometric approval"
                } else {
                    "approve via the configured factor"
                };
                Err(EnclaveError::ApprovalNotGranted(format!(
                    "operation '{}' requires approval ({}) \u{2014} {}",
                    request.operation, factor_str, platform_hint
                )))
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
pub struct NativeApprovalGate {
    registry: crate::factors::FactorRegistry,
}

impl std::fmt::Debug for NativeApprovalGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeApprovalGate")
            .field("registry", &self.registry)
            .finish()
    }
}

/// Resolves the approver identity to bind to a successful local-biometric
/// approval (re-exported from the factors module for wiring convenience).
#[cfg(test)]
pub type ApproverResolver = crate::factors::ApproverResolver;

impl NativeApprovalGate {
    /// Create a gate over an explicit verifier registry (the daemon builds
    /// one from its configured factors: local, paired device, FIDO2, …).
    pub fn with_registry(registry: crate::factors::FactorRegistry) -> Self {
        Self { registry }
    }

    /// Create a gate with only the local (biometric/polkit) factor — the
    /// pre-registry shape, kept for tests.
    #[cfg(test)]
    pub fn new() -> Self {
        let mut registry = crate::factors::FactorRegistry::new();
        registry.register(Arc::new(crate::factors::LocalBioVerifier::new(None)));
        Self { registry }
    }

    /// Attach an approver resolver (identity runtime hook) to a default
    /// local-only gate (test builder mirroring the daemon's wiring).
    #[cfg(test)]
    pub fn with_approver_resolver(self, resolver: ApproverResolver) -> Self {
        let mut registry = crate::factors::FactorRegistry::new();
        registry.register(Arc::new(crate::factors::LocalBioVerifier::new(Some(
            resolver,
        ))));
        Self { registry }
    }
}

impl ApprovalGate for NativeApprovalGate {
    fn request_approval(
        &self,
        approval_id: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        description: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
    > {
        let ctx = crate::factors::ApprovalContext {
            approval_id,
            request_id: request.request_id,
            operation: request.operation.clone(),
            client_label: sanitize_for_display(&request.client_identity.to_string(), 128),
            description: description.to_owned(),
        };
        let factors = factors.to_vec();
        Box::pin(async move {
            let decision = self.registry.request_approval(&factors, &ctx).await?;
            Ok(if !decision.approved {
                ApprovalOutcome::denied()
            } else {
                match decision.approver {
                    Some(approver) => ApprovalOutcome::approved_by(approver),
                    None => ApprovalOutcome::approved_anonymous(),
                }
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Insecure auto-approve gate (tests / e2e ONLY)
// ---------------------------------------------------------------------------

/// An approval gate that approves everything without human interaction.
///
/// FOR TESTS AND E2E ONLY. The daemon refuses to select this backend unless
/// BOTH `approval_backend = "insecure_auto_approve"` is set in the config AND
/// the environment carries `OPAQUE_INSECURE_AUTO_APPROVE=1` at startup — and
/// it announces itself with an Error-level audit event. Every approval it
/// grants is attributed to the synthetic `insecure-auto-approve` approver
/// (source `InsecureAutoApprove`), never to a person.
#[derive(Debug)]
pub struct InsecureAutoApproveGate;

impl InsecureAutoApproveGate {
    /// The synthetic approver identity attached to every auto-approval.
    pub fn approver() -> opaque_core::audit::ApproverIdentity {
        opaque_core::audit::ApproverIdentity {
            principal_id: "insecure-auto-approve".into(),
            label: "insecure test backend".into(),
            source: opaque_core::audit::ApproverSource::InsecureAutoApprove,
        }
    }
}

impl ApprovalGate for InsecureAutoApproveGate {
    fn request_approval(
        &self,
        approval_id: Uuid,
        request: &OperationRequest,
        _factors: &[ApprovalFactor],
        _description: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
    > {
        tracing::error!(
            approval_id = %approval_id,
            operation = %request.operation,
            "INSECURE AUTO-APPROVE: granting approval without human interaction (test backend)"
        );
        Box::pin(async move { Ok(ApprovalOutcome::approved_by(Self::approver())) })
    }
}

// ---------------------------------------------------------------------------
// Approval display sanitization
// ---------------------------------------------------------------------------

/// Return the stricter of two approval requirements (Always > FirstUse > Never).
/// Used to clamp a policy decision against an operation's `default_approval` floor,
/// so a rule can only make approval stricter, never weaker (H10).
fn stricter_requirement(a: ApprovalRequirement, b: ApprovalRequirement) -> ApprovalRequirement {
    fn rank(r: ApprovalRequirement) -> u8 {
        match r {
            ApprovalRequirement::Always => 2,
            ApprovalRequirement::FirstUse => 1,
            ApprovalRequirement::Never => 0,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

/// Sanitize a string for display in the approval prompt.
///
/// Strips control characters (0x00-0x1F), RTL overrides (U+202A-U+202E),
/// and bidi isolates (U+2066-U+2069). Truncates to `max_len` chars.
/// This is defense-in-depth: even if upstream validation is bypassed,
/// the approval UI cannot be spoofed with control characters.
pub(crate) fn sanitize_for_display(s: &str, max_len: usize) -> String {
    let cleaned: String = s
        .chars()
        .filter(|&ch| {
            let cp = ch as u32;
            // Reject control characters (0x00-0x1F).
            if cp <= 0x1F {
                return false;
            }
            // Reject RTL override characters (U+202A-U+202E).
            if (0x202A..=0x202E).contains(&cp) {
                return false;
            }
            // Reject bidi isolate characters (U+2066-U+2069).
            if (0x2066..=0x2069).contains(&cp) {
                return false;
            }
            true
        })
        .take(max_len)
        .collect();
    cleaned
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            self.count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(ApprovalOutcome::approved_anonymous()) })
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            Box::pin(async { Ok(ApprovalOutcome::approved_anonymous()) })
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            Box::pin(async { Ok(ApprovalOutcome::denied()) })
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
            principal: None,
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

    #[test]
    fn lease_key_isolates_principals_at_same_uid() {
        use opaque_core::identity::{AccessMode, PrincipalContext, PrincipalId, PrincipalKind};

        fn ctx(sub_sub: &str, jti: &str) -> PrincipalContext {
            PrincipalContext {
                sub: PrincipalId::generate(&PrincipalKind::Human {
                    iss: "https://idp.example.com".into(),
                    sub: sub_sub.into(),
                    email: None,
                    name: None,
                }),
                sub_label: "x".into(),
                sub_roles: Default::default(),
                sub_teams: vec![],
                act: PrincipalId::generate(&PrincipalKind::Agent {
                    tool: "claude-code".into(),
                }),
                act_label: "agent:claude-code".into(),
                mode: AccessMode::Delegated,
                jti: jti.into(),
                human_session_id: Some("hses_1".into()),
            }
        }
        let with = |c: Option<PrincipalContext>| {
            let mut r = test_request("github.set_actions_secret", ClientType::Agent);
            r.principal = c;
            LeaseKey::from_request(&r)
        };

        let none = with(None);
        let a = with(Some(ctx("alice", "j1")));
        let b = with(Some(ctx("bob", "j1")));
        let a2 = with(Some(ctx("alice", "j2")));

        // Different principals at the same uid → different lease keys.
        assert_ne!(a, b);
        // Same principal, different delegation session → different keys.
        assert_ne!(a, a2);
        // Un-delegated key differs from any delegated key but stays stable.
        assert_ne!(none, a);
        assert_eq!(none, with(None));
    }

    // -- Stage D: approver identity + distinct-approver ---------------------

    use opaque_core::audit::{ApproverIdentity, ApproverSource};
    use opaque_core::identity::{AccessMode, PrincipalContext, PrincipalId, PrincipalKind};

    fn human_ctx(sub_sub: &str) -> PrincipalContext {
        PrincipalContext {
            sub: PrincipalId::generate(&PrincipalKind::Human {
                iss: "https://idp.example.com".into(),
                sub: sub_sub.into(),
                email: None,
                name: None,
            }),
            sub_label: sub_sub.into(),
            sub_roles: Default::default(),
            sub_teams: vec![],
            act: PrincipalId::generate(&PrincipalKind::Agent {
                tool: "claude-code".into(),
            }),
            act_label: "agent:claude-code".into(),
            mode: AccessMode::Delegated,
            jti: "j1".into(),
            human_session_id: Some("hses_1".into()),
        }
    }

    fn approver(id: &str) -> ApproverIdentity {
        ApproverIdentity {
            principal_id: id.into(),
            label: id.into(),
            source: ApproverSource::LocalBioSession,
        }
    }

    /// A gate returning a fixed outcome, for approver-shaping tests.
    #[derive(Debug)]
    struct FixedOutcomeGate(ApprovalOutcome);
    impl ApprovalGate for FixedOutcomeGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            _request: &OperationRequest,
            _factors: &[ApprovalFactor],
            _description: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            let o = self.0.clone();
            Box::pin(async move { Ok(o) })
        }
    }

    fn distinct_policy() -> PolicyEngine {
        let mut p = PolicyEngine::new();
        p.add_rule(PolicyRule {
            identity: Default::default(),
            name: "distinct".into(),
            client: ClientMatch::default(),
            operation_pattern: "github.*".into(),
            target: TargetMatch::default(),
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: false,
                require_distinct_approver: true,
            },
        });
        p
    }

    fn build_enclave_with(
        gate: Box<dyn ApprovalGate>,
        policy: PolicyEngine,
        audit: Arc<InMemoryAuditEmitter>,
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
            .unwrap()
    }

    async fn run_distinct(
        gate: Box<dyn ApprovalGate>,
        principal: Option<PrincipalContext>,
    ) -> bool {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave_with(gate, distinct_policy(), audit);
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.principal = principal;
        enclave.execute(req).await.error_code().is_none()
    }

    #[tokio::test]
    async fn distinct_approver_denies_without_principal() {
        // No principal context → the constraint is unsatisfiable → deny.
        let gate = Box::new(FixedOutcomeGate(ApprovalOutcome::approved_by(approver(
            "hum_approver",
        ))));
        assert!(!run_distinct(gate, None).await);
    }

    #[tokio::test]
    async fn distinct_approver_denies_anonymous_approval() {
        // Approval with no approver identity (nobody logged in) → deny.
        let ctx = human_ctx("alice");
        let gate = Box::new(FixedOutcomeGate(ApprovalOutcome::approved_anonymous()));
        assert!(!run_distinct(gate, Some(ctx)).await);
    }

    #[tokio::test]
    async fn distinct_approver_denies_self_approval() {
        // Approver == the delegating principal → segregation of duties fails.
        let ctx = human_ctx("alice");
        let self_id = ctx.sub.as_str().to_owned();
        let gate = Box::new(FixedOutcomeGate(ApprovalOutcome::approved_by(approver(
            &self_id,
        ))));
        assert!(!run_distinct(gate, Some(ctx)).await);
    }

    #[tokio::test]
    async fn distinct_approver_allows_distinct_identity() {
        // A different approver satisfies the constraint.
        let ctx = human_ctx("alice");
        let gate = Box::new(FixedOutcomeGate(ApprovalOutcome::approved_by(approver(
            "hum_bob_distinct",
        ))));
        assert!(run_distinct(gate, Some(ctx)).await);
    }

    #[tokio::test]
    async fn approver_identity_lands_in_audit() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let gate = Box::new(FixedOutcomeGate(ApprovalOutcome::approved_by(approver(
            "hum_approver",
        ))));
        let enclave = build_enclave(gate, audit.clone());
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        assert!(enclave.execute(req).await.error_code().is_none());
        let granted = audit
            .events()
            .into_iter()
            .find(|e| e.kind == AuditEventKind::ApprovalGranted)
            .expect("granted event");
        assert_eq!(
            granted.approver.expect("approver recorded").principal_id,
            "hum_approver"
        );
    }

    #[tokio::test]
    async fn native_gate_registers_the_local_factor() {
        use opaque_core::operation::ApprovalFactor;
        // The prompt path isn't exercised here (no OS prompt in tests); the
        // registry's dispatch semantics are covered in factors::tests. Assert
        // the gate's construction shape: both variants serve LocalBio.
        let resolver: ApproverResolver = Arc::new(|| Some(approver("hum_session")));
        let gate = NativeApprovalGate::new().with_approver_resolver(resolver);
        assert_eq!(
            gate.registry.available_factors(),
            vec![ApprovalFactor::LocalBio]
        );
        let bare = NativeApprovalGate::new();
        assert_eq!(
            bare.registry.available_factors(),
            vec![ApprovalFactor::LocalBio]
        );
    }

    #[tokio::test]
    async fn insecure_auto_approve_gate_attributes_synthetic_approver() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(InsecureAutoApproveGate), audit.clone());
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        assert!(enclave.execute(req).await.error_code().is_none());
        let granted = audit
            .events()
            .into_iter()
            .find(|e| e.kind == AuditEventKind::ApprovalGranted)
            .expect("granted");
        let a = granted.approver.expect("approver");
        assert_eq!(a.principal_id, "insecure-auto-approve");
        assert_eq!(a.source, ApproverSource::InsecureAutoApprove);
    }

    #[tokio::test]
    async fn distinct_approver_misconfig_without_approval_fails_closed() {
        // require_distinct_approver on a rule that never requires approval is
        // a misconfiguration → fail closed, don't silently allow.
        let mut policy = PolicyEngine::new();
        policy.add_rule(PolicyRule {
            identity: Default::default(),
            name: "bad".into(),
            client: ClientMatch::default(),
            operation_pattern: "github.*".into(),
            target: TargetMatch::default(),
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Never,
                factors: vec![],
                lease_ttl: None,
                one_time: false,
                require_distinct_approver: true,
            },
        });
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave_with(Box::new(AlwaysApproveGate), policy, audit);
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.principal = Some(human_ctx("alice"));
        assert!(enclave.execute(req).await.error_code().is_some());
    }

    fn test_registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        reg.register(OperationDef {
            name: "github.set_actions_secret".into(),
            safety: OperationSafety::Safe,
            // FirstUse in the fixture so lease tests can exercise leasing; the
            // approval clamp still raises this to Always under an Always policy.
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Actions repository secret".into(),
            params_schema: None,
            allowed_target_keys: vec![],
            secret_ref_param_keys: vec![],
        })
        .unwrap();
        // A Never-approval op for exercising the "no approval needed" path.
        reg.register(OperationDef {
            name: "test.noop".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Never,
            default_factors: vec![],
            description: "No-op test operation".into(),
            params_schema: None,
            allowed_target_keys: vec![],
            secret_ref_param_keys: vec![],
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
            secret_ref_param_keys: vec![],
        })
        .unwrap();
        reg
    }

    fn test_policy() -> PolicyEngine {
        PolicyEngine::with_rules(vec![PolicyRule {
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .build().unwrap()
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
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .build()
            .unwrap();

        let req = test_request("secret.reveal", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("safety_violation"));
        // Verify error message reflects v1 hard-block.
        let msg = resp.error_message().unwrap_or("");
        assert!(msg.contains("not permitted in v1"));
    }

    #[tokio::test]
    async fn reveal_denied_for_human() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mut policy = test_policy();
        policy.add_rule(PolicyRule {
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .build()
            .unwrap();

        // Human client should ALSO be blocked from REVEAL in v1.
        let req = test_request("secret.reveal", ClientType::Human);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("safety_violation"));
        let msg = resp.error_message().unwrap_or("");
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
            .build().unwrap();

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("operation_failed"));
        // The error message should be sanitized.
        let msg = resp.error_message().unwrap_or("");
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
            .build()
            .unwrap();

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
            secret_ref_param_keys: vec![],
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
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .unwrap()
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
            identity: Default::default(),
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
                require_distinct_approver: false,
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
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
                Ok(ApprovalOutcome::approved_anonymous())
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
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            self.descriptions
                .lock()
                .expect("capturing gate mutex")
                .push(description.to_owned());
            Box::pin(async { Ok(ApprovalOutcome::approved_anonymous()) })
        }
    }

    type CapturedControlReview = (OperationRequest, Vec<ApprovalFactor>, String);

    #[derive(Debug, Default)]
    struct ControlCaptureGate {
        captured: Arc<Mutex<Vec<CapturedControlReview>>>,
    }

    impl ApprovalGate for ControlCaptureGate {
        fn request_approval(
            &self,
            _approval_id: Uuid,
            request: &OperationRequest,
            factors: &[ApprovalFactor],
            description: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            self.captured.lock().unwrap().push((
                request.clone(),
                factors.to_vec(),
                description.to_owned(),
            ));
            Box::pin(async { Ok(ApprovalOutcome::denied()) })
        }
    }

    #[test]
    fn agent_session_factor_accepts_only_complete_review_factors() {
        for factor in [ApprovalFactor::Fido2, ApprovalFactor::IosFaceId] {
            let result = Enclave::builder()
                .session_approval_factor(factor)
                .approval_gate(Box::new(ControlCaptureGate::default()))
                .audit(Arc::new(InMemoryAuditEmitter::new()))
                .build();
            assert!(
                result
                    .unwrap_err()
                    .contains("local_bio or paired_workstation")
            );
        }
        for factor in [ApprovalFactor::LocalBio, ApprovalFactor::PairedWorkstation] {
            assert!(
                Enclave::builder()
                    .session_approval_factor(factor)
                    .approval_gate(Box::new(ControlCaptureGate::default()))
                    .audit(Arc::new(InMemoryAuditEmitter::new()))
                    .build()
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn agent_session_factor_selection_never_changes_other_control_approval() {
        for configured in [None, Some(ApprovalFactor::PairedWorkstation)] {
            let gate = ControlCaptureGate::default();
            let captured = gate.captured.clone();
            let audit = Arc::new(InMemoryAuditEmitter::new());
            let mut builder = Enclave::builder()
                .approval_gate(Box::new(gate))
                .audit(audit.clone());
            if let Some(factor) = configured {
                builder = builder.session_approval_factor(factor);
            }
            let enclave = builder.build().unwrap();
            let identity = test_request("test", ClientType::Agent).client_identity;
            for operation in [
                "agent_session_start",
                "device_pair_start",
                "device_pair_confirm",
                "fido2_register",
                "identity.role_set",
                "agent_session_start.other",
            ] {
                let result = enclave
                    .request_control_approval(
                        &identity,
                        ClientType::Agent,
                        operation,
                        "Control approval",
                        "Tenant: test\nTTL: 600 seconds",
                    )
                    .await;
                assert!(matches!(result, Err(EnclaveError::ApprovalNotGranted(_))));
            }
            let records = captured.lock().unwrap();
            assert_eq!(records.len(), 6);
            assert_eq!(
                records[0].1,
                vec![configured.unwrap_or(ApprovalFactor::LocalBio)]
            );
            for (_, factors, _) in &records[1..] {
                assert_eq!(factors, &vec![ApprovalFactor::LocalBio]);
            }
            assert_eq!(
                audit.events_of_kind(AuditEventKind::ApprovalRequired).len(),
                6
            );
            assert_eq!(
                audit
                    .events_of_kind(AuditEventKind::ApprovalPresented)
                    .len(),
                6
            );
            assert_eq!(
                audit.events_of_kind(AuditEventKind::ApprovalDenied).len(),
                6
            );
            assert!(
                audit
                    .events_of_kind(AuditEventKind::ApprovalGranted)
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn agent_session_review_keeps_full_authority_and_binds_request_content() {
        let gate = ControlCaptureGate::default();
        let captured = gate.captured.clone();
        let enclave = Enclave::builder()
            .session_approval_factor(ApprovalFactor::PairedWorkstation)
            .approval_gate(Box::new(gate))
            .audit(Arc::new(InMemoryAuditEmitter::new()))
            .build()
            .unwrap();
        let identity = test_request("test", ClientType::Agent).client_identity;
        let reason = format!(
            "Tenant: exact-tenant\nTenant broker: 7f720ac8-fac2-4b5f-966c-ed2de3a738a8\nSubject principal: opaque-human-123\nMode: delegated\nPeer UID: {}\nLabel: {}\nTTL: 600 seconds\nFinal reviewed authority",
            identity.uid,
            "label".repeat(100)
        );
        let result = enclave
            .request_control_approval(
                &identity,
                ClientType::Agent,
                "agent_session_start",
                "Start one delegated agent session",
                &reason,
            )
            .await;
        assert!(matches!(result, Err(EnclaveError::ApprovalNotGranted(_))));
        let records = captured.lock().unwrap();
        let (request, _, description) = &records[0];
        assert!(description.contains(&reason));
        assert!(description.contains("Final reviewed authority"));
        assert_eq!(request.params["control_review"], *description);
        let original_hash = request.content_hash();
        let mut changed = request.clone();
        changed.params["control_review"] = description.replace("600 seconds", "601 seconds").into();
        assert_ne!(changed.content_hash(), original_hash);
        let mut changed = request.clone();
        changed.operation = "device_pair_start".into();
        assert_ne!(changed.content_hash(), original_hash);
    }

    #[tokio::test]
    async fn agent_session_review_rejects_overflow_and_display_controls_without_prompt() {
        let gate = ControlCaptureGate::default();
        let captured = gate.captured.clone();
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = Enclave::builder()
            .session_approval_factor(ApprovalFactor::PairedWorkstation)
            .approval_gate(Box::new(gate))
            .audit(audit.clone())
            .build()
            .unwrap();
        let identity = test_request("test", ClientType::Agent).client_identity;
        for reason in [
            "".into(),
            "x".repeat(8193),
            "Tenant: a\0hidden".into(),
            "Tenant: a\u{202e}other".into(),
        ] {
            assert!(matches!(
                enclave
                    .request_control_approval(
                        &identity,
                        ClientType::Agent,
                        "agent_session_start",
                        "Start agent session",
                        &reason
                    )
                    .await,
                Err(EnclaveError::InvalidInput(_))
            ));
        }
        assert!(captured.lock().unwrap().is_empty());
        assert!(audit.events().is_empty());
    }

    #[tokio::test]
    async fn provisioning_review_preserves_exact_terms_with_configured_full_review_factor() {
        let gate = ControlCaptureGate::default();
        let captured = gate.captured.clone();
        let enclave = Enclave::builder()
            .session_approval_factor(ApprovalFactor::PairedWorkstation)
            .approval_gate(Box::new(gate))
            .audit(Arc::new(InMemoryAuditEmitter::new()))
            .build()
            .unwrap();
        let identity = test_request("test", ClientType::Agent).client_identity;
        let reason = format!(
            "Tenant: engineering\nProfile terms: {}\nExact subject: issuer|subject\nCumulative budget: 2\nRedelegation: forbidden",
            "reviewed profile ".repeat(40)
        );
        for operation in [
            "identity.provisioning.bind_start",
            "identity.provisioning.mandate_start",
        ] {
            assert!(matches!(
                enclave
                    .request_control_approval(
                        &identity,
                        ClientType::Agent,
                        operation,
                        "Review provisioning authority",
                        &reason
                    )
                    .await,
                Err(EnclaveError::ApprovalNotGranted(_))
            ));
        }
        for operation in [
            "identity.provisioning.mandate_start.other",
            "identity.provisioning.issue",
            "identity.role_set",
        ] {
            assert!(matches!(
                enclave
                    .request_control_approval(
                        &identity,
                        ClientType::Agent,
                        operation,
                        "Other control",
                        "Other reason"
                    )
                    .await,
                Err(EnclaveError::ApprovalNotGranted(_))
            ));
        }
        let records = captured.lock().unwrap();
        for (request, factors, description) in &records[..2] {
            assert_eq!(factors, &vec![ApprovalFactor::PairedWorkstation]);
            assert!(description.contains(&reason));
            assert_eq!(request.params["control_review"], *description);
            let mut modified = request.clone();
            modified.params["control_review"] =
                description.replace("budget: 2", "budget: 3").into();
            assert_ne!(request.content_hash(), modified.content_hash());
        }
        for (request, factors, _) in &records[2..] {
            assert_eq!(factors, &vec![ApprovalFactor::LocalBio]);
            assert!(request.params.is_null());
        }
    }

    #[tokio::test]
    async fn provisioning_review_rejects_overflow_or_hidden_terms_before_prompt() {
        let gate = ControlCaptureGate::default();
        let captured = gate.captured.clone();
        let enclave = Enclave::builder()
            .session_approval_factor(ApprovalFactor::PairedWorkstation)
            .approval_gate(Box::new(gate))
            .audit(Arc::new(InMemoryAuditEmitter::new()))
            .build()
            .unwrap();
        let identity = test_request("test", ClientType::Agent).client_identity;
        for operation in [
            "identity.provisioning.bind_start",
            "identity.provisioning.mandate_start",
        ] {
            for reason in [
                "".into(),
                "x".repeat(8193),
                "Group: legitimate\u{202e}hidden".into(),
                "Subject: normal\0other".into(),
            ] {
                assert!(matches!(
                    enclave
                        .request_control_approval(
                            &identity,
                            ClientType::Agent,
                            operation,
                            "Review provisioning",
                            &reason
                        )
                        .await,
                    Err(EnclaveError::InvalidInput(_))
                ));
            }
        }
        assert!(captured.lock().unwrap().is_empty());
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
            identity: Default::default(),
            name: "allow-no-approval".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "test.noop".into(),
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
                require_distinct_approver: false,
            },
        }]);

        let enclave = Enclave::builder()
            .registry(test_registry())
            .policy(policy)
            .handler(
                "test.noop",
                Box::new(StubHandler {
                    response: serde_json::json!({"status": "ok"}),
                }),
            )
            .approval_gate(Box::new(gate))
            .audit(audit.clone())
            .build()
            .unwrap();

        let req = test_request("test.noop", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert!(resp.error_code().is_none());
        // Gate should never have been called.
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);

        // No approval events should be emitted.
        assert!(
            audit
                .events_of_kind(AuditEventKind::ApprovalRequired)
                .is_empty()
        );
        assert!(
            audit
                .events_of_kind(AuditEventKind::ApprovalPresented)
                .is_empty()
        );
        assert!(
            audit
                .events_of_kind(AuditEventKind::ApprovalGranted)
                .is_empty()
        );
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
            identity: Default::default(),
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
                require_distinct_approver: false,
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
                .build()
                .unwrap(),
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
                secret_ref_param_keys: vec![],
            })
            .unwrap();

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .build()
            .unwrap();

        // Request with allowed keys → success.
        let mut req = test_request("restricted.op", ClientType::Human);
        req.target.clear();
        req.target.insert("repo".into(), "org/repo".into());
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());

        // Request with unexpected key → rejected.
        let mut req = test_request("restricted.op", ClientType::Human);
        req.target.clear();
        req.target.insert("repo".into(), "org/repo".into());
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
                secret_ref_param_keys: vec![],
            })
            .unwrap();

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .build()
            .unwrap();

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
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .build()
            .unwrap();

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
            workspace_verified: true,
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
            workspace_verified: true,
        });
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
    }

    // -- Secret name constraint through enclave --

    #[tokio::test]
    async fn secret_name_constraint_enforced_through_enclave() {
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            identity: Default::default(),
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
                require_distinct_approver: false,
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
            .build()
            .unwrap();

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

    mod audit_barrier_tests {
        use super::*;
        use opaque_core::audit::AuditFlushError;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct InjectedAudit {
            calls: AtomicUsize,
            fail_at: usize,
        }
        impl AuditSink for InjectedAudit {
            fn emit(&self, _: AuditEvent) {}
            fn flush(&self, _: Duration) -> Result<(), AuditFlushError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at {
                    Err(AuditFlushError::Storage("injected failure".into()))
                } else {
                    Ok(())
                }
            }
        }

        #[tokio::test]
        async fn control_approval_cannot_grant_authority_without_durable_evidence() {
            let audit = Arc::new(InjectedAudit {
                calls: AtomicUsize::new(0),
                fail_at: 1,
            });
            let enclave = Enclave::builder()
                .registry(test_registry())
                .policy(test_policy())
                .approval_gate(Box::new(AlwaysApproveGate))
                .audit(audit)
                .build()
                .unwrap();
            let result = enclave
                .request_control_approval(
                    &test_identity(),
                    ClientType::Human,
                    "agent_session_start",
                    "Fixture session",
                    "Fixture review",
                )
                .await;
            assert!(result.unwrap_err().to_string().contains("not dispatched"));
        }

        #[tokio::test]
        async fn missing_evidence_prevents_dispatch_and_success_disclosure() {
            for (fail_at, effects, succeeded) in [(1, 0, false), (2, 1, false), (0, 1, true)] {
                let audit = Arc::new(InjectedAudit {
                    calls: AtomicUsize::new(0),
                    fail_at,
                });
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
                    .build()
                    .unwrap();
                let response = enclave
                    .execute(test_request("github.set_actions_secret", ClientType::Agent))
                    .await;
                assert_eq!(received.lock().unwrap().len(), effects);
                assert_eq!(response.error_code().is_none(), succeeded);
                assert_eq!(
                    audit.calls.load(Ordering::SeqCst),
                    if fail_at == 1 { 1 } else { 2 }
                );
                if !succeeded {
                    assert!(response.payload().is_null());
                    let message = response.error_message().unwrap();
                    assert!(message.contains(if effects == 0 {
                        "not dispatched"
                    } else {
                        "outcome unknown"
                    }));
                }
            }
        }
    }

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
            .build()
            .unwrap();

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
                secret_ref_param_keys: vec![],
            })
            .unwrap();

        let policy = PolicyEngine::with_rules(vec![
            // list_secrets: no approval needed.
            PolicyRule {
                identity: Default::default(),
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
                    require_distinct_approver: false,
                },
            },
            // set_actions_secret: Always approval.
            PolicyRule {
                identity: Default::default(),
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
                    require_distinct_approver: false,
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
            .build()
            .unwrap();

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
                secret_ref_param_keys: vec![],
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
            .build()
            .unwrap();

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
            workspace_verified: false,
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
            workspace_verified: false,
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

    // -- SensitiveOutput is gated on approval, not classification --

    #[tokio::test]
    async fn sensitive_output_requires_approval_not_classification() {
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
                secret_ref_param_keys: vec![],
            })
            .unwrap();

        // Policy sets approval to "never"; the enclave clamp must still force
        // mandatory approval because the op is SensitiveOutput.
        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            identity: Default::default(),
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
            client_types: vec![], // classification no longer gates SensitiveOutput
            approval: ApprovalConfig {
                require: ApprovalRequirement::Never,
                factors: vec![],
                lease_ttl: None,
                one_time: false,
                require_distinct_approver: false,
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
            .build()
            .unwrap();

        // Agent client: despite the "never" policy, the SensitiveOutput clamp
        // forces approval. With an approving gate the op then succeeds — and the
        // approval was genuinely required (proving presence, not classification,
        // is the gate).
        let req = test_request("ecr.get_auth_token", ClientType::Agent);
        let resp = enclave.execute(req).await;
        assert!(resp.error_code().is_none());
        assert!(
            !audit
                .events_of_kind(AuditEventKind::ApprovalRequired)
                .is_empty(),
            "SensitiveOutput must require approval regardless of the policy's 'never'"
        );

        // Human client is treated identically — no free pass from classification.
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
        assert_eq!(
            leases.len(),
            1,
            "expected 1 active lease, got {}",
            leases.len()
        );
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

    #[tokio::test]
    async fn secret_ref_names_derived_server_side() {
        // Verifies P0 fix: client-supplied secret_ref_names are overridden
        // when the operation has secret_ref_param_keys configured.
        let audit = Arc::new(InMemoryAuditEmitter::new());

        let mut registry = OperationRegistry::new();
        registry
            .register(OperationDef {
                name: "github.set_actions_secret".into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Always,
                default_factors: vec![ApprovalFactor::LocalBio],
                description: "Set a GitHub Actions secret".into(),
                params_schema: None,
                allowed_target_keys: vec![],
                secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
            })
            .unwrap();

        // Policy that restricts to specific secret names.
        let policy = PolicyEngine::with_rules(vec![PolicyRule {
            identity: Default::default(),
            name: "allow-only-specific-secrets".into(),
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
                patterns: vec!["env:MY_TOKEN".into()],
            },
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: true,
                require_distinct_approver: false,
            },
        }]);

        // A handler that captures the request to verify secret_ref_names.
        let handler_response = serde_json::json!({"status": "ok"});

        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .handler(
                "github.set_actions_secret",
                Box::new(StubHandler {
                    response: handler_response,
                }),
            )
            .approval_gate(Box::new(AlwaysApproveGate))
            .audit(audit.clone())
            .build()
            .unwrap();

        // Client tries to LIE about secret_ref_names — claims "ADMIN_KEY"
        // but params actually reference "env:MY_TOKEN".
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.secret_ref_names = vec!["ADMIN_KEY".into()]; // attacker-supplied
        req.params = serde_json::json!({
            "value_ref": "env:MY_TOKEN",
            "github_token_ref": "env:MY_TOKEN",
            "secret_name": "MY_SECRET",
            "repo": "org/myrepo"
        });

        let resp = enclave.execute(req).await;
        // Should succeed because server-side derivation extracts "env:MY_TOKEN"
        // which IS allowed by the policy.
        assert!(
            resp.error_code().is_none(),
            "expected success, got: {:?}",
            resp.error_code()
        );

        // Now test the DENY case: params reference a secret NOT in the policy.
        let mut req2 = test_request("github.set_actions_secret", ClientType::Agent);
        req2.secret_ref_names = vec!["env:MY_TOKEN".into()]; // attacker claims allowed name
        req2.params = serde_json::json!({
            "value_ref": "env:ADMIN_KEY",
            "github_token_ref": "env:SUPER_SECRET"
        });

        let resp2 = enclave.execute(req2).await;
        // Should be DENIED because server-side derivation extracts
        // ["env:ADMIN_KEY", "env:SUPER_SECRET"] which are NOT in the policy.
        assert_eq!(
            resp2.error_code(),
            Some("policy_denied"),
            "expected policy_denied for unauthorized secret refs, got: {:?}",
            resp2.error_code()
        );
    }

    #[test]
    fn derive_secret_ref_names_extracts_from_params() {
        let keys = vec!["value_ref".into(), "github_token_ref".into()];
        let params = serde_json::json!({
            "value_ref": "env:DB_PASSWORD",
            "github_token_ref": "keychain:github-token",
            "secret_name": "MY_SECRET"
        });
        let result = super::derive_secret_ref_names(&keys, &params);
        assert_eq!(result, vec!["env:DB_PASSWORD", "keychain:github-token"]);
    }

    #[test]
    fn derive_secret_ref_names_ignores_missing_and_empty() {
        let keys = vec!["value_ref".into(), "missing_key".into(), "empty_key".into()];
        let params = serde_json::json!({
            "value_ref": "env:TOKEN",
            "empty_key": ""
        });
        let result = super::derive_secret_ref_names(&keys, &params);
        assert_eq!(result, vec!["env:TOKEN"]);
    }

    #[test]
    fn derive_secret_ref_names_deduplicates() {
        let keys = vec!["value_ref".into(), "github_token_ref".into()];
        let params = serde_json::json!({
            "value_ref": "env:SAME_TOKEN",
            "github_token_ref": "env:SAME_TOKEN"
        });
        let result = super::derive_secret_ref_names(&keys, &params);
        assert_eq!(result, vec!["env:SAME_TOKEN"]);
    }

    #[test]
    fn derive_secret_ref_names_empty_keys() {
        let keys: Vec<String> = vec![];
        let params = serde_json::json!({"value_ref": "env:TOKEN"});
        let result = super::derive_secret_ref_names(&keys, &params);
        assert!(result.is_empty());
    }

    #[test]
    fn derive_secret_ref_names_supports_templates() {
        let keys = vec!["onepassword:{vault}/{item}/{field}".into()];
        let params = serde_json::json!({
            "vault": "Personal",
            "item": "GitHub Token",
            "field": "password"
        });
        let result = super::derive_secret_ref_names(&keys, &params);
        assert_eq!(result, vec!["onepassword:Personal/GitHub Token/password"]);
    }

    #[test]
    fn derive_secret_ref_names_template_skips_when_placeholder_missing() {
        let keys = vec!["onepassword:{vault}/{item}/{field}".into()];
        let params = serde_json::json!({
            "vault": "Personal",
            "item": "GitHub Token"
        });
        let result = super::derive_secret_ref_names(&keys, &params);
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn error_message_operation_denied_includes_simulate_hint() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysApproveGate), audit.clone());

        // Request with wrong target (other-org) to trigger policy deny.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.target.insert("repo".into(), "other-org/repo".into());
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("policy_denied"));
        let msg = resp.error_message().unwrap_or("");
        assert!(
            msg.contains("opaque policy simulate"),
            "policy denied message should contain simulate hint, got: {msg}"
        );
        assert!(
            msg.contains("github.set_actions_secret"),
            "policy denied message should contain the operation name, got: {msg}"
        );
    }

    #[tokio::test]
    async fn error_message_approval_required_includes_factor() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysDenyGate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        assert_eq!(resp.error_code(), Some("approval_not_granted"));
        let msg = resp.error_message().unwrap_or("");
        assert!(
            msg.contains("local_bio"),
            "approval error should contain the factor name, got: {msg}"
        );
        assert!(
            msg.contains("github.set_actions_secret"),
            "approval error should contain the operation name, got: {msg}"
        );
    }

    #[tokio::test]
    async fn error_message_platform_hint_macos() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let enclave = build_enclave(Box::new(AlwaysDenyGate), audit.clone());

        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let resp = enclave.execute(req).await;

        let msg = resp.error_message().unwrap_or("");
        if cfg!(target_os = "macos") {
            assert!(
                msg.contains("Touch ID"),
                "on macOS, approval error should mention Touch ID, got: {msg}"
            );
        }
    }
}

#[cfg(test)]
mod operation_catalog_tests {
    use super::test_support::{AlwaysDenyGate, StubHandler};
    use super::*;
    use opaque_core::{
        audit::InMemoryAuditEmitter,
        operation::{ApprovalRequirement, OperationSafety},
    };

    #[test]
    fn catalog_distinguishes_task_transport_and_profile_requirements() {
        let ssh_profile = crate::ssh::test_profile();
        let inference_profile = crate::inference::InferenceProfileConfig {
            profile_id: "catalog-fixture".into(),
            api_url: "https://inference.example.test".into(),
            model_id: "public-fixture.gguf".into(),
            model_path: "/models/public-fixture.gguf".into(),
            model_artifact_sha256: "a".repeat(64),
            chat_template_sha256: "b".repeat(64),
            server_build: "catalog-fixture-v1".into(),
            service_uid: Uuid::new_v4(),
            source_id: crate::inference::DEMO_SOURCE_ID.into(),
            source_snapshot_sha256: crate::inference::demo_source_snapshot_sha256(),
            credential_ref: None,
            allow_loopback_http: false,
        }
        .bind(&ssh_profile.tenant)
        .unwrap();

        for task_enabled in [false, true] {
            for inference_configured in [false, true] {
                for ssh_configured in [false, true] {
                    let mut registry = OperationRegistry::new();
                    for operation in [task_operation()]
                        .into_iter()
                        .chain(release_task_operations())
                        .chain(inference_task_operations())
                        .chain(ssh_task_operations())
                    {
                        registry.register(operation).unwrap();
                    }
                    // The publish child has both a direct handler and a typed
                    // task path; unrelated names must not acquire capabilities.
                    for name in ["github.set_actions_secret", "github.unimplemented_manifest"] {
                        let mut operation = task_operation();
                        operation.name = name.into();
                        registry.register(operation).unwrap();
                    }
                    let enclave = Enclave::builder()
                        .registry(registry)
                        .task_grants_enabled(task_enabled)
                        .inference_profile(inference_configured.then(|| inference_profile.clone()))
                        .ssh_profile(ssh_configured.then(|| ssh_profile.clone()))
                        .handler(
                            "github.set_actions_secret",
                            Box::new(StubHandler {
                                response: serde_json::json!({}),
                            }),
                        )
                        .approval_gate(Box::new(AlwaysDenyGate))
                        .audit(Arc::new(InMemoryAuditEmitter::new()))
                        .build()
                        .unwrap();
                    let catalog: HashMap<_, _> = enclave
                        .operation_catalog()
                        .into_iter()
                        .map(|row| (row["name"].as_str().unwrap().to_owned(), row))
                        .collect();
                    for (name, expected_enabled) in [
                        ("github.publish_manifest", task_enabled),
                        ("github.release_manifest", task_enabled),
                        ("github.dispatch_staging_workflow", task_enabled),
                        ("github.observe_staging_workflow", task_enabled),
                        (
                            "inference.fixed_manifest",
                            task_enabled && inference_configured,
                        ),
                        (
                            "inference.fixed_completion",
                            task_enabled && inference_configured,
                        ),
                        (
                            opaque_core::ssh::SSH_TASK_OPERATION,
                            task_enabled && ssh_configured,
                        ),
                        (
                            opaque_core::ssh::SSH_OPERATION,
                            task_enabled && ssh_configured,
                        ),
                        ("github.unimplemented_manifest", false),
                    ] {
                        let row = &catalog[name];
                        assert_eq!(
                            row["availability"],
                            if expected_enabled {
                                "enabled"
                            } else {
                                "disabled"
                            },
                            "{name}: tasks={task_enabled}, inference={inference_configured}, ssh={ssh_configured}"
                        );
                        assert_eq!(
                            row["execution_paths"],
                            if expected_enabled {
                                serde_json::json!(["task"])
                            } else {
                                serde_json::json!([])
                            }
                        );
                        assert_eq!(row["policy_status"], "evaluated_per_request");
                        assert_eq!(row["mcp_exposed"], false);
                    }
                    let publish = &catalog["github.set_actions_secret"];
                    assert_eq!(publish["availability"], "enabled");
                    assert_eq!(
                        publish["execution_paths"],
                        if task_enabled {
                            serde_json::json!(["operation", "task"])
                        } else {
                            serde_json::json!(["operation"])
                        }
                    );
                    assert_eq!(publish["mcp_exposed"], true);
                }
            }
        }
    }

    #[test]
    fn catalog_reports_registered_handlers_without_claiming_policy_permission() {
        let mut registry = OperationRegistry::new();
        for name in [
            "test.disabled",
            "aws.create_secret",
            "github.set_actions_secret",
            "onepassword.read_field",
        ] {
            registry
                .register(OperationDef {
                    name: name.into(),
                    safety: if name == "onepassword.read_field" {
                        OperationSafety::Reveal
                    } else {
                        OperationSafety::Safe
                    },
                    default_approval: ApprovalRequirement::Always,
                    default_factors: vec![],
                    description: format!("Registry description for {name}"),
                    params_schema: None,
                    allowed_target_keys: vec![],
                    secret_ref_param_keys: vec![],
                })
                .unwrap();
        }
        let handler = || {
            Box::new(StubHandler {
                response: serde_json::json!({}),
            })
        };
        let enclave = Enclave::builder()
            .registry(registry)
            .handler(
                "aws.create_secret",
                Box::new(crate::aws::AwsHandler::new(
                    Arc::new(InMemoryAuditEmitter::new()),
                    crate::aws::client::AwsClient::new_single("http://127.0.0.1:1"),
                )),
            )
            .handler("github.set_actions_secret", handler())
            .handler("onepassword.read_field", handler())
            .handler("unregistered.handler", handler())
            .approval_gate(Box::new(AlwaysDenyGate))
            .audit(Arc::new(InMemoryAuditEmitter::new()))
            .build()
            .unwrap();
        let rows = enclave.operation_catalog();
        assert_eq!(rows.len(), 4);
        let names = rows
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "aws.create_secret",
                "github.set_actions_secret",
                "onepassword.read_field",
                "test.disabled"
            ]
        );
        assert_eq!(rows[0]["availability"], "fixture_only");
        assert_eq!(rows[1]["availability"], "enabled");
        assert_eq!(rows[3]["availability"], "disabled");
        assert_eq!(rows[1]["mcp_exposed"], true);
        assert_eq!(rows[2]["mcp_exposed"], false);
        assert_eq!(rows[2]["safety"], "Reveal");
        assert_eq!(rows[1]["provider"], "github");
        for row in rows {
            assert_eq!(row["policy_status"], "evaluated_per_request");
            assert_eq!(row["default_approval"], "always");
            assert!(
                row["description"]
                    .as_str()
                    .unwrap()
                    .starts_with("Registry description")
            );
        }
    }
}
