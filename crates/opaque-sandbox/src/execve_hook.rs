//! Handler for execve policy checks from external sandboxes.
//!
//! When an external sandbox (e.g., Codex shell-tool-mcp) intercepts an execve(2)
//! call, it can query Opaque for a policy decision before allowing execution.
//!
//! ## `sandbox.execve_check`
//!
//! Request params:
//! ```json
//! {
//!     "executable": "/usr/bin/git",
//!     "args": ["push", "origin", "main"],
//!     "cwd": "/home/user/project",
//!     "env_keys": ["PATH", "HOME", "GITHUB_TOKEN"],
//!     "sandbox_id": "codex-session-abc123"
//! }
//! ```
//!
//! Response:
//! ```json
//! {
//!     "decision": "allow",
//!     "reason": "matched rule: git push *",
//!     "secrets_to_inject": ["GITHUB_TOKEN"],
//!     "approval_id": null,
//!     "lease_ttl_secs": 300
//! }
//! ```
//!
//! ## `sandbox.execve_approve`
//!
//! Request params:
//! ```json
//! {
//!     "approval_id": "uuid-from-check",
//!     "decision": "allow",
//!     "lease_for_pattern": true
//! }
//! ```
//!
//! Response:
//! ```json
//! {
//!     "status": "ok",
//!     "lease_ttl_secs": 300
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::execve_map::{ExecveDefaultDecision, ExecveMapper};
use opaque_core::operation::OperationRequest;
use uuid::Uuid;

use opaque_core::operation_handler::{OperationHandler, PreparedOperation, render_argv};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default lease TTL for execve approval decisions.
const DEFAULT_EXECVE_LEASE_TTL: Duration = Duration::from_secs(300);

/// Maximum argument string length included in audit details.
const MAX_ARGS_AUDIT_LENGTH: usize = 256;

// ---------------------------------------------------------------------------
// Execve lease cache
// ---------------------------------------------------------------------------

/// Key for the execve-specific lease cache. Uses the matched pattern
/// (or raw command string for unmatched commands) as the identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExecveLeaseKey {
    /// The matched pattern or normalized command string.
    pattern_or_command: String,
    /// The sandbox session ID for correlation.
    sandbox_id: String,
}

/// A lease entry for a previously approved execve pattern.
#[derive(Debug, Clone)]
struct ExecveLeaseEntry {
    granted_at: Instant,
    ttl: Duration,
}

/// In-memory cache of execve approval leases.
///
/// Separate from the main enclave lease cache because execve leases
/// are keyed by pattern + sandbox_id rather than the full operation request.
#[derive(Debug)]
pub(crate) struct ExecveLeaseCache {
    leases: Mutex<HashMap<ExecveLeaseKey, ExecveLeaseEntry>>,
}

impl ExecveLeaseCache {
    fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a valid lease exists for the given key.
    fn check(&self, key: &ExecveLeaseKey) -> bool {
        let mut leases = self
            .leases
            .lock()
            .expect("execve lease cache mutex poisoned");
        if let Some(entry) = leases.get(key) {
            if entry.granted_at.elapsed() < entry.ttl {
                return true;
            }
            // Expired; remove lazily.
            leases.remove(key);
        }
        false
    }

    /// Grant a new lease.
    fn grant(&self, key: ExecveLeaseKey, ttl: Duration) {
        let mut leases = self
            .leases
            .lock()
            .expect("execve lease cache mutex poisoned");
        leases.insert(
            key,
            ExecveLeaseEntry {
                granted_at: Instant::now(),
                ttl,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Pending approval tracking
// ---------------------------------------------------------------------------

/// Tracks a pending execve approval (for the prompt flow).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PendingApproval {
    /// Fresh server generation; approval IDs alone never identify replacement state.
    generation: Uuid,
    /// Exact check input and mapping being approved, including argv boundaries.
    check: ExecveCheckAction,
    /// Verified request context supplied by the daemon.
    request_context: serde_json::Value,
    /// The matched pattern (for leasing on approve).
    pattern_or_command: String,
    /// The sandbox session ID.
    sandbox_id: String,
    /// When this pending approval was created.
    #[serde(skip)]
    created_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecveCheckInput {
    executable: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: String,
    #[serde(default)]
    env_keys: Vec<String>,
    #[serde(default)]
    sandbox_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ExecveRuleMatch {
    operation: Option<String>,
    secret_refs: Vec<String>,
    matched_pattern: Option<String>,
    is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ExecveCheckAction {
    version: &'static str,
    input: ExecveCheckInput,
    rule_match: ExecveRuleMatch,
    default_decision: ExecveDefaultDecision,
}

impl ExecveCheckInput {
    fn parse(request: &OperationRequest) -> Result<Self, String> {
        if request.operation != "sandbox.execve_check" {
            return Err("unknown execve check operation".into());
        }
        if request.params.get("executable").is_none() {
            return Err("missing 'executable' parameter".into());
        }
        let input: Self = serde_json::from_value(request.params.clone())
            .map_err(|_| "invalid execve check parameters")?;
        if input.executable.is_empty()
            || input.executable.contains('\0')
            || input.args.iter().any(|arg| arg.contains('\0'))
            || input.cwd.contains('\0')
            || input.sandbox_id.chars().any(char::is_control)
            || input.env_keys.iter().any(|key| {
                let mut chars = key.bytes();
                !chars
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                    || !chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
        {
            return Err("invalid execve check input".into());
        }
        Ok(input)
    }

    fn command(&self) -> String {
        format_command(&self.executable, &self.args)
    }

    fn target(&self) -> HashMap<String, String> {
        HashMap::from([
            ("executable".into(), self.executable.clone()),
            ("command".into(), self.command()),
            ("cwd".into(), self.cwd.clone()),
            ("env_keys".into(), render_argv(&self.env_keys)),
            ("sandbox_id".into(), self.sandbox_id.clone()),
        ])
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecveApproveInput {
    approval_id: Uuid,
    decision: String,
    #[serde(default = "default_lease_for_pattern")]
    lease_for_pattern: bool,
}

fn default_lease_for_pattern() -> bool {
    true
}

#[derive(Serialize)]
struct ExecveApproveAction {
    version: &'static str,
    input: ExecveApproveInput,
    pending: PendingApproval,
}

// ---------------------------------------------------------------------------
// ExecveCheckHandler
// ---------------------------------------------------------------------------

/// Handler for `sandbox.execve_check` operations.
///
/// Evaluates an execve request against the configured execve rules,
/// returns a policy decision, and emits audit events.
pub struct ExecveCheckHandler {
    audit: Arc<dyn AuditSink>,
    mapper: Arc<ExecveMapper>,
    lease_cache: Arc<ExecveLeaseCache>,
    pending_approvals: Arc<Mutex<HashMap<Uuid, PendingApproval>>>,
}

impl fmt::Debug for ExecveCheckHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecveCheckHandler")
            .field("rules", &self.mapper.rule_count())
            .finish()
    }
}

impl ExecveCheckHandler {
    /// Create a new execve check handler.
    ///
    /// `pub(crate)`: only called by `create_execve_handlers` below, which is
    /// this module's actual public entry point (and the only one `opaqued`
    /// needs) — `ExecveLeaseCache`/`PendingApproval` are `pub(crate)` too, so
    /// a `pub fn` here would expose parameter types callers outside this
    /// crate can't name.
    pub(crate) fn new(
        audit: Arc<dyn AuditSink>,
        mapper: Arc<ExecveMapper>,
        lease_cache: Arc<ExecveLeaseCache>,
        pending_approvals: Arc<Mutex<HashMap<Uuid, PendingApproval>>>,
    ) -> Self {
        Self {
            audit,
            mapper,
            lease_cache,
            pending_approvals,
        }
    }
}

impl OperationHandler for ExecveCheckHandler {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let input = ExecveCheckInput::parse(request)?;
        let target = input.target();
        let matched = self.mapper.match_execve(&input.executable, &input.args);
        let secret_refs = matched.secret_refs.clone();
        let action = ExecveCheckAction {
            version: "sandbox.execve_check.v1",
            input,
            rule_match: ExecveRuleMatch {
                operation: matched.operation,
                secret_refs: matched.secret_refs,
                matched_pattern: matched.matched_pattern,
                is_default: matched.is_default,
            },
            default_decision: self.mapper.default_decision(),
        };
        let request_context = serde_json::json!({
            "client_identity": request.client_identity,
            "principal": request.principal,
            "workspace": request.workspace,
        });
        let request_id = request.request_id;
        let audit = self.audit.clone();
        let lease_cache = self.lease_cache.clone();
        let pending_approvals = self.pending_approvals.clone();

        PreparedOperation::new(action, target, secret_refs, move |action| async move {
            let pending_check = action.clone();
            let ExecveCheckAction {
                input,
                rule_match: match_result,
                default_decision,
                ..
            } = action;
            let ExecveCheckInput {
                executable,
                args,
                cwd,
                env_keys,
                sandbox_id,
            } = input;
            // Emit ExecveChecked audit event.
            let args_truncated = truncate_args(&args);
            let detail = format!(
                "executable={executable} args=[{args_truncated}] cwd={cwd} sandbox_id={sandbox_id}"
            );
            audit.emit(
                AuditEvent::new(AuditEventKind::ExecveChecked)
                    .with_request_id(request_id)
                    .with_operation("sandbox.execve_check")
                    .with_detail(&detail),
            );

            // Build the lease key from matched pattern or command string.
            let pattern_or_command = match_result
                .matched_pattern
                .clone()
                .unwrap_or_else(|| format_command(&executable, &args));

            let lease_key = ExecveLeaseKey {
                pattern_or_command: pattern_or_command.clone(),
                sandbox_id: sandbox_id.clone(),
            };

            // Check for an existing lease.
            if lease_cache.check(&lease_key) {
                let reason = format!(
                    "cached lease for pattern: {}",
                    match_result
                        .matched_pattern
                        .as_deref()
                        .unwrap_or("<default>")
                );
                audit.emit(
                    AuditEvent::new(AuditEventKind::ExecveAllowed)
                        .with_request_id(request_id)
                        .with_operation("sandbox.execve_check")
                        .with_outcome("allow")
                        .with_detail(format!("lease_hit=true {detail}")),
                );
                return Ok(serde_json::json!({
                    "decision": "allow",
                    "reason": reason,
                    "secrets_to_inject": filter_secret_refs(&env_keys, &match_result.secret_refs),
                    "approval_id": null,
                    "lease_ttl_secs": DEFAULT_EXECVE_LEASE_TTL.as_secs(),
                }));
            }

            // Determine decision from match result + default.
            let (decision, reason, secrets) = if match_result.is_default {
                // No rule matched; use default decision.
                match default_decision {
                    ExecveDefaultDecision::Allow => (
                        "allow",
                        "no matching rule (default: allow)".to_string(),
                        filter_secret_refs(&env_keys, &[]),
                    ),
                    ExecveDefaultDecision::Prompt => (
                        "prompt",
                        "no matching rule (default: prompt)".to_string(),
                        filter_secret_refs(&env_keys, &[]),
                    ),
                    ExecveDefaultDecision::Deny => (
                        "deny",
                        "no matching rule (default: deny)".to_string(),
                        vec![],
                    ),
                }
            } else {
                // A rule matched; the fact that we have a mapped operation
                // means the command is known. If the operation requires
                // secrets, that implies it needs approval.
                let secrets = filter_secret_refs(&env_keys, &match_result.secret_refs);
                if match_result.secret_refs.is_empty() {
                    (
                        "allow",
                        format!(
                            "matched rule: {}",
                            match_result.matched_pattern.as_deref().unwrap_or("?")
                        ),
                        secrets,
                    )
                } else {
                    // Commands that reference secrets require a prompt
                    // (unless there's a cached lease, which we already checked).
                    (
                        "prompt",
                        format!(
                            "matched rule: {} (secrets required)",
                            match_result.matched_pattern.as_deref().unwrap_or("?")
                        ),
                        secrets,
                    )
                }
            };

            // Emit decision-specific audit event.
            let (audit_kind, outcome) = match decision {
                "allow" => (AuditEventKind::ExecveAllowed, "allow"),
                "deny" => (AuditEventKind::ExecveDenied, "deny"),
                _ => (AuditEventKind::ExecvePrompted, "prompt"),
            };
            audit.emit(
                AuditEvent::new(audit_kind)
                    .with_request_id(request_id)
                    .with_operation("sandbox.execve_check")
                    .with_outcome(outcome)
                    .with_detail(format!(
                        "rule={} {detail}",
                        match_result
                            .matched_pattern
                            .as_deref()
                            .unwrap_or("<default>")
                    )),
            );

            // For allow decisions, auto-grant a lease.
            if decision == "allow" {
                lease_cache.grant(lease_key, DEFAULT_EXECVE_LEASE_TTL);
            }

            // For prompt decisions, create a pending approval.
            let approval_id = if decision == "prompt" {
                let id = Uuid::new_v4();
                let mut pending = pending_approvals
                    .lock()
                    .expect("pending approvals mutex poisoned");
                pending.insert(
                    id,
                    PendingApproval {
                        generation: Uuid::new_v4(),
                        check: pending_check,
                        request_context,
                        pattern_or_command,
                        sandbox_id,
                        created_at: Instant::now(),
                    },
                );
                Some(id)
            } else {
                None
            };

            let lease_ttl = if decision == "allow" {
                DEFAULT_EXECVE_LEASE_TTL.as_secs()
            } else {
                0
            };

            Ok(serde_json::json!({
                "decision": decision,
                "reason": reason,
                "secrets_to_inject": secrets,
                "approval_id": approval_id,
                "lease_ttl_secs": lease_ttl,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// ExecveApproveHandler
// ---------------------------------------------------------------------------

/// Handler for `sandbox.execve_approve` operations.
///
/// Completes a pending execve approval and optionally creates a lease
/// for the matched pattern.
pub struct ExecveApproveHandler {
    audit: Arc<dyn AuditSink>,
    lease_cache: Arc<ExecveLeaseCache>,
    pending_approvals: Arc<Mutex<HashMap<Uuid, PendingApproval>>>,
}

impl fmt::Debug for ExecveApproveHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecveApproveHandler").finish()
    }
}

impl ExecveApproveHandler {
    /// Create a new execve approve handler.
    ///
    /// `pub(crate)`: see `ExecveCheckHandler::new` above — same reasoning.
    pub(crate) fn new(
        audit: Arc<dyn AuditSink>,
        lease_cache: Arc<ExecveLeaseCache>,
        pending_approvals: Arc<Mutex<HashMap<Uuid, PendingApproval>>>,
    ) -> Self {
        Self {
            audit,
            lease_cache,
            pending_approvals,
        }
    }
}

impl OperationHandler for ExecveApproveHandler {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        if request.operation != "sandbox.execve_approve" {
            return Err("unknown execve approve operation".into());
        }
        let input: ExecveApproveInput = serde_json::from_value(request.params.clone())
            .map_err(|_| "invalid execve approval parameters")?;
        if !matches!(input.decision.as_str(), "allow" | "deny") {
            return Err("invalid decision: must be 'allow' or 'deny'".into());
        }
        let pending = self
            .pending_approvals
            .lock()
            .expect("pending approvals mutex poisoned")
            .get(&input.approval_id)
            .cloned()
            .ok_or("unknown or expired approval_id")?;
        if pending.created_at.elapsed() >= Duration::from_secs(600) {
            return Err("approval has expired (10 minutes)".into());
        }
        let target = HashMap::from([
            ("approval_id".into(), input.approval_id.to_string()),
            ("decision".into(), input.decision.clone()),
            (
                "lease_for_pattern".into(),
                input.lease_for_pattern.to_string(),
            ),
            ("command".into(), pending.check.input.command()),
            ("sandbox_id".into(), pending.sandbox_id.clone()),
            ("pattern".into(), pending.pattern_or_command.clone()),
        ]);
        let secret_refs = pending.check.rule_match.secret_refs.clone();
        let action = ExecveApproveAction {
            version: "sandbox.execve_approve.v1",
            input,
            pending,
        };
        let request_id = request.request_id;
        let audit = self.audit.clone();
        let lease_cache = self.lease_cache.clone();
        let pending_approvals = self.pending_approvals.clone();
        PreparedOperation::new(action, target, secret_refs, move |action| async move {
            let ExecveApproveAction { input, pending, .. } = action;
            let ExecveApproveInput {
                approval_id,
                decision,
                lease_for_pattern,
            } = input;
            // Preparation does not consume authority. Atomically compare and
            // remove only the exact pending generation reviewed above.
            {
                let mut map = pending_approvals
                    .lock()
                    .expect("pending approvals mutex poisoned");
                let current = map
                    .get(&approval_id)
                    .ok_or("unknown or expired approval_id")?;
                if current != &pending {
                    return Err("pending approval changed after preparation".into());
                }
                if current.created_at.elapsed() >= Duration::from_secs(600) {
                    map.remove(&approval_id);
                    return Err("approval has expired (10 minutes)".into());
                }
                map.remove(&approval_id);
            }
            let lease_ttl = if decision == "allow" && lease_for_pattern {
                // Grant a lease for the pattern.
                let lease_key = ExecveLeaseKey {
                    pattern_or_command: pending.pattern_or_command.clone(),
                    sandbox_id: pending.sandbox_id.clone(),
                };
                lease_cache.grant(lease_key, DEFAULT_EXECVE_LEASE_TTL);
                DEFAULT_EXECVE_LEASE_TTL.as_secs()
            } else {
                0
            };

            // Emit audit event.
            let audit_kind = if decision == "allow" {
                AuditEventKind::ExecveAllowed
            } else {
                AuditEventKind::ExecveDenied
            };
            audit.emit(
                AuditEvent::new(audit_kind)
                    .with_request_id(request_id)
                    .with_approval_id(approval_id)
                    .with_operation("sandbox.execve_approve")
                    .with_outcome(&decision)
                    .with_detail(format!(
                        "pattern={} sandbox_id={} lease_for_pattern={lease_for_pattern}",
                        pending.pattern_or_command, pending.sandbox_id
                    )),
            );

            Ok(serde_json::json!({
                "status": "ok",
                "lease_ttl_secs": lease_ttl,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Shared state factory
// ---------------------------------------------------------------------------

/// Shared state between ExecveCheckHandler and ExecveApproveHandler.
///
/// Both handlers need access to the same lease cache and pending approvals map.
///
/// `pub(crate)`: only used internally by `create_execve_handlers` (and its
/// own tests); not part of this crate's external API.
pub(crate) struct ExecveSharedState {
    pub lease_cache: Arc<ExecveLeaseCache>,
    pub pending_approvals: Arc<Mutex<HashMap<Uuid, PendingApproval>>>,
}

impl ExecveSharedState {
    /// Create a new shared state instance.
    pub fn new() -> Self {
        Self {
            lease_cache: Arc::new(ExecveLeaseCache::new()),
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for ExecveSharedState {
    fn default() -> Self {
        Self::new()
    }
}

/// Create both execve handlers with shared state.
pub fn create_execve_handlers(
    audit: Arc<dyn AuditSink>,
    mapper: Arc<ExecveMapper>,
) -> (ExecveCheckHandler, ExecveApproveHandler) {
    let shared = ExecveSharedState::new();
    let check_handler = ExecveCheckHandler::new(
        audit.clone(),
        mapper,
        shared.lease_cache.clone(),
        shared.pending_approvals.clone(),
    );
    let approve_handler =
        ExecveApproveHandler::new(audit, shared.lease_cache, shared.pending_approvals);
    (check_handler, approve_handler)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Truncate arguments for audit logging.
fn truncate_args(args: &[String]) -> String {
    let joined = args.join(", ");
    if joined.len() > MAX_ARGS_AUDIT_LENGTH {
        {
            let mut end = MAX_ARGS_AUDIT_LENGTH;
            while !joined.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &joined[..end])
        }
    } else {
        joined
    }
}

/// Format a command string for display/keying.
fn format_command(executable: &str, args: &[String]) -> String {
    let mut command = Vec::with_capacity(args.len() + 1);
    command.push(executable.to_owned());
    command.extend_from_slice(args);
    render_argv(&command)
}

/// Filter secret refs to only include those present in env_keys.
///
/// The `secret_refs` from the matched rule define which secrets the command
/// needs. We return only those that are also present in the sandbox's
/// env_keys (the keys the sandbox knows about).
fn filter_secret_refs(env_keys: &[String], secret_refs: &[String]) -> Vec<String> {
    secret_refs
        .iter()
        .filter(|s| env_keys.contains(s))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::execve_map::{ExecveDefault, ExecveDefaultDecision, ExecveRule};
    use opaque_core::operation::{ClientIdentity, ClientType};

    fn test_mapper() -> ExecveMapper {
        ExecveMapper::new(
            vec![
                ExecveRule {
                    pattern: "git push *".into(),
                    operation: "git.push".into(),
                    secret_refs: vec!["GITHUB_TOKEN".into()],
                    description: Some("Push to remote".into()),
                },
                ExecveRule {
                    pattern: "curl **".into(),
                    operation: "network.curl".into(),
                    secret_refs: vec![],
                    description: None,
                },
            ],
            ExecveDefault {
                decision: ExecveDefaultDecision::Allow,
            },
        )
    }

    fn test_mapper_deny_default() -> ExecveMapper {
        ExecveMapper::new(
            vec![],
            ExecveDefault {
                decision: ExecveDefaultDecision::Deny,
            },
        )
    }

    fn test_request(params: serde_json::Value) -> OperationRequest {
        OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: ClientType::Agent,
            operation: "sandbox.execve_check".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params,
            workspace: None,
        }
    }

    fn approve_request(params: serde_json::Value) -> OperationRequest {
        OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: ClientType::Agent,
            operation: "sandbox.execve_approve".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params,
            workspace: None,
        }
    }

    #[tokio::test]
    async fn execve_check_allows_known_safe_command() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (check_handler, _approve_handler) = create_execve_handlers(audit.clone(), mapper);

        // "ls" doesn't match any rule, default is allow.
        let req = test_request(serde_json::json!({
            "executable": "/bin/ls",
            "args": ["-la"],
            "cwd": "/home/user",
            "env_keys": ["PATH", "HOME"],
            "sandbox_id": "test-session-1",
        }));

        let result = check_handler.execute(&req).await.unwrap();
        assert_eq!(result["decision"], "allow");
        assert!(
            result["reason"]
                .as_str()
                .unwrap()
                .contains("default: allow")
        );
        assert_eq!(result["lease_ttl_secs"], 300);
    }

    #[tokio::test]
    async fn execve_check_denies_unknown_with_deny_default() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper_deny_default());
        let (check_handler, _approve_handler) = create_execve_handlers(audit.clone(), mapper);

        let req = test_request(serde_json::json!({
            "executable": "/bin/unknown",
            "args": ["--flag"],
            "cwd": "/home/user",
            "env_keys": [],
            "sandbox_id": "test-session-2",
        }));

        let result = check_handler.execute(&req).await.unwrap();
        assert_eq!(result["decision"], "deny");
        assert!(result["reason"].as_str().unwrap().contains("default: deny"));
    }

    #[tokio::test]
    async fn execve_check_prompts_sensitive_command() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (check_handler, _approve_handler) = create_execve_handlers(audit.clone(), mapper);

        // "git push" matches a rule with secret_refs, should prompt.
        let req = test_request(serde_json::json!({
            "executable": "/usr/bin/git",
            "args": ["push", "origin", "main"],
            "cwd": "/home/user/project",
            "env_keys": ["PATH", "GITHUB_TOKEN"],
            "sandbox_id": "codex-abc",
        }));

        let result = check_handler.execute(&req).await.unwrap();
        assert_eq!(result["decision"], "prompt");
        assert!(result["approval_id"].is_string());
        assert!(
            result["reason"]
                .as_str()
                .unwrap()
                .contains("secrets required")
        );
    }

    #[tokio::test]
    async fn execve_check_maps_to_correct_operation() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (check_handler, _approve_handler) = create_execve_handlers(audit.clone(), mapper);

        // "curl" matches the network.curl rule with no secrets.
        let req = test_request(serde_json::json!({
            "executable": "/usr/bin/curl",
            "args": ["https://example.com"],
            "cwd": "/tmp",
            "env_keys": ["PATH"],
            "sandbox_id": "test-session-3",
        }));

        let result = check_handler.execute(&req).await.unwrap();
        assert_eq!(result["decision"], "allow");
        assert!(result["reason"].as_str().unwrap().contains("curl *"));

        // Check audit events include the correct operation.
        let events = audit.events();
        let allowed_events = events
            .iter()
            .filter(|e| e.kind == AuditEventKind::ExecveAllowed)
            .collect::<Vec<_>>();
        assert!(!allowed_events.is_empty());
    }

    #[tokio::test]
    async fn execve_check_returns_secret_names() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (check_handler, _approve_handler) = create_execve_handlers(audit.clone(), mapper);

        // "git push" should return GITHUB_TOKEN in secrets_to_inject
        // (since it's also in env_keys).
        let req = test_request(serde_json::json!({
            "executable": "/usr/bin/git",
            "args": ["push", "origin", "main"],
            "cwd": "/home/user/project",
            "env_keys": ["PATH", "GITHUB_TOKEN"],
            "sandbox_id": "codex-abc",
        }));

        let result = check_handler.execute(&req).await.unwrap();
        let secrets: Vec<String> =
            serde_json::from_value(result["secrets_to_inject"].clone()).unwrap();
        assert_eq!(secrets, vec!["GITHUB_TOKEN"]);
    }

    #[tokio::test]
    async fn execve_approve_creates_lease() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (check_handler, approve_handler) = create_execve_handlers(audit.clone(), mapper);

        // First, get a prompt decision.
        let req = test_request(serde_json::json!({
            "executable": "/usr/bin/git",
            "args": ["push", "origin", "main"],
            "cwd": "/home/user/project",
            "env_keys": ["GITHUB_TOKEN"],
            "sandbox_id": "codex-lease-test",
        }));
        let check_result = check_handler.execute(&req).await.unwrap();
        assert_eq!(check_result["decision"], "prompt");
        let approval_id = check_result["approval_id"].as_str().unwrap();

        // Now approve it.
        let approve_req = approve_request(serde_json::json!({
            "approval_id": approval_id,
            "decision": "allow",
            "lease_for_pattern": true,
        }));
        let approve_result = approve_handler.execute(&approve_req).await.unwrap();
        assert_eq!(approve_result["status"], "ok");
        assert_eq!(approve_result["lease_ttl_secs"], 300);
    }

    #[tokio::test]
    async fn execve_check_uses_lease() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (check_handler, approve_handler) = create_execve_handlers(audit.clone(), mapper);

        // 1. Get a prompt decision.
        let req = test_request(serde_json::json!({
            "executable": "/usr/bin/git",
            "args": ["push", "origin", "main"],
            "cwd": "/home/user/project",
            "env_keys": ["GITHUB_TOKEN"],
            "sandbox_id": "codex-reuse-test",
        }));
        let check_result = check_handler.execute(&req).await.unwrap();
        assert_eq!(check_result["decision"], "prompt");
        let approval_id = check_result["approval_id"].as_str().unwrap();

        // 2. Approve it.
        let approve_req = approve_request(serde_json::json!({
            "approval_id": approval_id,
            "decision": "allow",
            "lease_for_pattern": true,
        }));
        approve_handler.execute(&approve_req).await.unwrap();

        // 3. Re-check the same command. Should use cached lease.
        let req2 = test_request(serde_json::json!({
            "executable": "/usr/bin/git",
            "args": ["push", "origin", "main"],
            "cwd": "/home/user/project",
            "env_keys": ["GITHUB_TOKEN"],
            "sandbox_id": "codex-reuse-test",
        }));
        let check_result2 = check_handler.execute(&req2).await.unwrap();
        assert_eq!(check_result2["decision"], "allow");
        assert!(
            check_result2["reason"]
                .as_str()
                .unwrap()
                .contains("cached lease")
        );
    }

    #[tokio::test]
    async fn execve_check_missing_executable_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (check_handler, _) = create_execve_handlers(audit.clone(), mapper);

        let req = test_request(serde_json::json!({
            "args": ["push"],
        }));

        let result = check_handler.execute(&req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'executable'"));
    }

    #[tokio::test]
    async fn execve_approve_invalid_id_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (_, approve_handler) = create_execve_handlers(audit.clone(), mapper);

        let req = approve_request(serde_json::json!({
            "approval_id": Uuid::new_v4().to_string(),
            "decision": "allow",
        }));

        let result = approve_handler.execute(&req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown or expired"));
    }

    #[tokio::test]
    async fn execve_approve_invalid_decision_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (_, approve_handler) = create_execve_handlers(audit.clone(), mapper);

        let req = approve_request(serde_json::json!({
            "approval_id": Uuid::new_v4().to_string(),
            "decision": "maybe",
        }));

        let result = approve_handler.execute(&req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid decision"));
    }

    #[test]
    fn truncate_args_short() {
        let args: Vec<String> = vec!["push".into(), "origin".into()];
        let result = truncate_args(&args);
        assert_eq!(result, "push, origin");
    }

    #[test]
    fn truncate_args_long() {
        let args: Vec<String> = (0..100).map(|i| format!("arg{i}")).collect();
        let result = truncate_args(&args);
        assert!(result.len() <= MAX_ARGS_AUDIT_LENGTH + 3); // +3 for "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn filter_secret_refs_intersection() {
        let env_keys = vec!["PATH".into(), "GITHUB_TOKEN".into(), "HOME".into()];
        let secret_refs = vec!["GITHUB_TOKEN".into(), "NPM_TOKEN".into()];
        let result = filter_secret_refs(&env_keys, &secret_refs);
        assert_eq!(result, vec!["GITHUB_TOKEN"]);
    }

    #[test]
    fn filter_secret_refs_empty() {
        let env_keys: Vec<String> = vec!["PATH".into()];
        let secret_refs: Vec<String> = vec![];
        let result = filter_secret_refs(&env_keys, &secret_refs);
        assert!(result.is_empty());
    }

    #[test]
    fn execve_shared_state_default() {
        let state = ExecveSharedState::default();
        assert!(state.pending_approvals.lock().unwrap().is_empty());
    }

    #[test]
    fn execve_lease_cache_grant_and_check() {
        let cache = ExecveLeaseCache::new();
        let key = ExecveLeaseKey {
            pattern_or_command: "git push *".into(),
            sandbox_id: "test".into(),
        };
        assert!(!cache.check(&key));
        cache.grant(key.clone(), Duration::from_secs(60));
        assert!(cache.check(&key));
    }

    #[test]
    fn execve_check_handler_debug() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (handler, _) = create_execve_handlers(audit, mapper);
        let dbg = format!("{handler:?}");
        assert!(dbg.contains("ExecveCheckHandler"));
        assert!(dbg.contains("rules"));
    }

    #[test]
    fn execve_approve_handler_debug() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mapper = Arc::new(test_mapper());
        let (_, handler) = create_execve_handlers(audit, mapper);
        let dbg = format!("{handler:?}");
        assert!(dbg.contains("ExecveApproveHandler"));
    }

    #[tokio::test]
    async fn malformed_hook_parameters_never_create_pending_or_cached_authority() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let (check, approve) = create_execve_handlers(audit.clone(), Arc::new(test_mapper()));
        for field in ["args", "cwd", "env_keys", "sandbox_id", "extra"] {
            let mut params = serde_json::json!({"executable":"/bin/echo"});
            params[field] = true.into();
            assert!(check.execute(&test_request(params)).await.is_err());
        }
        for params in [
            serde_json::json!({"executable":"/bin/echo","args":[1]}),
            serde_json::json!({"executable":"/bin/echo","env_keys":["TOKEN=secret"]}),
            serde_json::json!({"executable":"/bin/echo","cwd":null}),
            serde_json::json!({"executable":"/bin/echo","args":null}),
        ] {
            assert!(check.execute(&test_request(params)).await.is_err());
        }
        let result = check
            .execute(&test_request(serde_json::json!({
                "executable":"/usr/bin/git", "args":["push","origin","main"], "sandbox_id":"session"
            })))
            .await
            .unwrap();
        let pending_count = check.pending_approvals.lock().unwrap().len();
        let events = audit.events().len();
        for field in ["lease_for_pattern", "extra"] {
            let mut params =
                serde_json::json!({"approval_id":result["approval_id"],"decision":"allow"});
            params[field] = "not-a-boolean".into();
            assert!(approve.execute(&approve_request(params)).await.is_err());
        }
        assert_eq!(check.pending_approvals.lock().unwrap().len(), pending_count);
        assert!(check.lease_cache.leases.lock().unwrap().is_empty());
        assert_eq!(audit.events().len(), events);
    }

    #[tokio::test]
    async fn approval_snapshots_server_command_and_rejects_replacement_without_consuming_it() {
        let (check, approve) = create_execve_handlers(
            Arc::new(InMemoryAuditEmitter::new()),
            Arc::new(test_mapper()),
        );
        let input = test_request(serde_json::json!({
            "executable":"/usr/bin/git", "args":["push","origin","main"], "cwd":"/approved", "sandbox_id":"session"
        }));
        let result = check.execute(&input).await.unwrap();
        let approval_id: Uuid = result["approval_id"].as_str().unwrap().parse().unwrap();
        let request =
            approve_request(serde_json::json!({"approval_id":approval_id,"decision":"allow"}));
        let prepared = approve.prepare(&request).unwrap();
        assert_eq!(
            prepared.target()["command"],
            r#"["/usr/bin/git","push","origin","main"]"#
        );
        assert_eq!(prepared.target()["sandbox_id"], "session");
        assert_eq!(prepared.target()["pattern"], "git push *");
        assert_eq!(
            prepared.params()["pending"]["request_context"]["client_identity"]["uid"],
            501
        );
        assert_eq!(check.pending_approvals.lock().unwrap().len(), 1);
        let replacement = {
            let mut pending = check.pending_approvals.lock().unwrap();
            let item = pending.get_mut(&approval_id).unwrap();
            item.generation = Uuid::new_v4();
            item.check.input.args.push("--different".into());
            item.clone()
        };
        assert!(prepared.execute().await.unwrap_err().contains("changed"));
        assert_eq!(
            check.pending_approvals.lock().unwrap().get(&approval_id),
            Some(&replacement)
        );
        assert!(check.lease_cache.leases.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn prepared_approval_consumes_once_and_ignores_later_request_edits() {
        let (check, approve) = create_execve_handlers(
            Arc::new(InMemoryAuditEmitter::new()),
            Arc::new(test_mapper()),
        );
        let result = check
            .execute(&test_request(serde_json::json!({
                "executable":"/usr/bin/git", "args":["push","origin","main"], "sandbox_id":"session"
            })))
            .await
            .unwrap();
        let mut request = approve_request(
            serde_json::json!({"approval_id":result["approval_id"],"decision":"allow"}),
        );
        let prepared = approve.prepare(&request).unwrap();
        let duplicate = approve.prepare(&request).unwrap();
        request.params["decision"] = "deny".into();
        request.params["lease_for_pattern"] = false.into();
        assert_eq!(prepared.execute().await.unwrap()["lease_ttl_secs"], 300);
        assert!(duplicate.execute().await.is_err());
        assert!(check.pending_approvals.lock().unwrap().is_empty());
        assert_eq!(check.lease_cache.leases.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn expired_pending_authority_rejects_before_preparation() {
        let (check, approve) = create_execve_handlers(
            Arc::new(InMemoryAuditEmitter::new()),
            Arc::new(test_mapper()),
        );
        let result = check
            .execute(&test_request(serde_json::json!({
                "executable":"/usr/bin/git", "args":["push","origin","main"]
            })))
            .await
            .unwrap();
        let approval_id: Uuid = result["approval_id"].as_str().unwrap().parse().unwrap();
        check
            .pending_approvals
            .lock()
            .unwrap()
            .get_mut(&approval_id)
            .unwrap()
            .created_at = Instant::now() - Duration::from_secs(600);
        let request =
            approve_request(serde_json::json!({"approval_id":approval_id,"decision":"allow"}));
        assert!(approve.prepare(&request).unwrap_err().contains("expired"));
        assert!(check.lease_cache.leases.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unmatched_argv_boundaries_cannot_reuse_another_commands_lease() {
        let mapper = ExecveMapper::new(
            vec![],
            ExecveDefault {
                decision: ExecveDefaultDecision::Prompt,
            },
        );
        let (check, approve) =
            create_execve_handlers(Arc::new(InMemoryAuditEmitter::new()), Arc::new(mapper));
        let first = test_request(
            serde_json::json!({"executable":"/bin/tool","args":["a b"],"sandbox_id":"session"}),
        );
        let prompted = check.execute(&first).await.unwrap();
        approve
            .execute(&approve_request(
                serde_json::json!({"approval_id":prompted["approval_id"],"decision":"allow"}),
            ))
            .await
            .unwrap();
        assert_eq!(check.execute(&first).await.unwrap()["decision"], "allow");
        let second = test_request(
            serde_json::json!({"executable":"/bin/tool","args":["a","b"],"sandbox_id":"session"}),
        );
        assert_eq!(check.execute(&second).await.unwrap()["decision"], "prompt");
    }

    #[test]
    fn truncating_multibyte_hook_arguments_preserves_utf8() {
        for prefix in [253, 254, 255, 256] {
            let result = truncate_args(&[format!("{}🙂more", "a".repeat(prefix))]);
            assert!(result.len() <= MAX_ARGS_AUDIT_LENGTH + 3);
            assert!(result.ends_with("..."));
        }
    }

    #[tokio::test]
    async fn pending_expiry_is_rechecked_after_preparation_before_grant() {
        let (check, approve) = create_execve_handlers(
            Arc::new(InMemoryAuditEmitter::new()),
            Arc::new(test_mapper()),
        );
        let result = check
            .execute(&test_request(serde_json::json!({
                "executable":"/usr/bin/git", "args":["push","origin","main"]
            })))
            .await
            .unwrap();
        let approval_id: Uuid = result["approval_id"].as_str().unwrap().parse().unwrap();
        check
            .pending_approvals
            .lock()
            .unwrap()
            .get_mut(&approval_id)
            .unwrap()
            .created_at = Instant::now() - Duration::from_millis(599_500);
        let request =
            approve_request(serde_json::json!({"approval_id":approval_id,"decision":"allow"}));
        let prepared = approve.prepare(&request).unwrap();
        tokio::time::sleep(Duration::from_millis(550)).await;
        assert!(prepared.execute().await.unwrap_err().contains("expired"));
        assert!(check.lease_cache.leases.lock().unwrap().is_empty());
        assert!(check.pending_approvals.lock().unwrap().is_empty());
    }
}
