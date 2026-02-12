//! Policy engine: allowlist-based authorization for operation requests.
//!
//! The policy engine evaluates every [`OperationRequest`] against a set of
//! [`PolicyRule`]s. The default behaviour is **deny-all** unless a rule
//! explicitly allows the request.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationRequest,
    OperationSafety,
};

// ---------------------------------------------------------------------------
// Client match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching a client identity. All present fields must match.
/// Absent (None) fields are treated as "any".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMatch {
    /// Match on UID.
    pub uid: Option<u32>,

    /// Glob pattern on executable path (e.g. `"/Applications/Claude Code*"`).
    pub exe_path: Option<String>,

    /// Exact match on executable SHA-256.
    pub exe_sha256: Option<String>,

    /// Exact match on macOS code signature Team ID.
    pub codesign_team_id: Option<String>,
}

impl ClientMatch {
    /// Returns `true` if the given identity matches this pattern.
    pub fn matches(&self, identity: &ClientIdentity) -> bool {
        if let Some(uid) = self.uid {
            if identity.uid != uid {
                return false;
            }
        }

        if let Some(ref pattern) = self.exe_path {
            match &identity.exe_path {
                Some(exe) => {
                    let path_str = exe.to_string_lossy();
                    if !glob_match::glob_match(pattern, &path_str) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if let Some(ref expected_hash) = self.exe_sha256 {
            match &identity.exe_sha256 {
                Some(actual) => {
                    if !actual.eq_ignore_ascii_case(expected_hash) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if let Some(ref expected_team) = self.codesign_team_id {
            match &identity.codesign_team_id {
                Some(actual) => {
                    if actual != expected_team {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Target match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching operation target fields. Each entry is a field name
/// mapped to a glob pattern. All present entries must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetMatch {
    /// Map of target field name to glob pattern.
    /// e.g. `{ "repo": "org/*", "environment": "prod*" }`.
    pub fields: std::collections::HashMap<String, String>,
}

impl TargetMatch {
    /// Returns `true` if the given target map matches all patterns.
    pub fn matches(&self, target: &std::collections::HashMap<String, String>) -> bool {
        for (field, pattern) in &self.fields {
            match target.get(field) {
                Some(value) => {
                    if !glob_match::glob_match(pattern, value) {
                        return false;
                    }
                }
                // If the target does not have the required field, no match.
                None => return false,
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Approval configuration within a rule
// ---------------------------------------------------------------------------

/// Approval configuration attached to a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    /// When approval is required.
    pub require: ApprovalRequirement,

    /// Acceptable approval factors (any-of).
    pub factors: Vec<ApprovalFactor>,

    /// Lease duration after approval (for `FirstUse`).
    #[serde(
        default,
        with = "optional_duration_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_ttl: Option<Duration>,

    /// If true, the approval is consumed after a single use.
    #[serde(default)]
    pub one_time: bool,
}

mod optional_duration_secs {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dur: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dur {
            Some(d) => serializer.serialize_u64(d.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<u64> = Option::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_secs))
    }
}

// ---------------------------------------------------------------------------
// Policy rule
// ---------------------------------------------------------------------------

/// A single policy rule. Rules are evaluated in order; the first matching rule
/// determines the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable rule name (for audit/logging).
    pub name: String,

    /// Client match pattern.
    pub client: ClientMatch,

    /// Glob pattern on operation name (e.g. `"github.*"`).
    pub operation_pattern: String,

    /// Target field constraints.
    #[serde(default)]
    pub target: TargetMatch,

    /// Whether this rule allows the matched request.
    #[serde(default = "default_true")]
    pub allow: bool,

    /// What client types this rule applies to.
    /// If empty, applies to all client types.
    #[serde(default)]
    pub client_types: Vec<ClientType>,

    /// Approval configuration (required factors, lease, one-time).
    pub approval: ApprovalConfig,
}

fn default_true() -> bool {
    true
}

impl PolicyRule {
    /// Check whether this rule matches the given request.
    fn matches(&self, request: &OperationRequest) -> bool {
        // Client type filter.
        if !self.client_types.is_empty() && !self.client_types.contains(&request.client_type) {
            return false;
        }

        // Client identity match.
        if !self.client.matches(&request.client_identity) {
            return false;
        }

        // Operation name glob.
        if !glob_match::glob_match(&self.operation_pattern, &request.operation) {
            return false;
        }

        // Target constraints.
        if !self.target.matches(&request.target) {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Policy decision
// ---------------------------------------------------------------------------

/// The result of evaluating a request against the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the request is allowed.
    pub allowed: bool,

    /// If allowed, the set of required approval factors.
    pub required_factors: Vec<ApprovalFactor>,

    /// Approval requirement mode.
    pub approval_requirement: ApprovalRequirement,

    /// Lease TTL granted after approval.
    #[serde(
        default,
        with = "optional_duration_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_ttl: Option<Duration>,

    /// If true, the approval is consumed after one use.
    pub one_time: bool,

    /// Name of the rule that matched (for audit).
    pub matched_rule: Option<String>,

    /// Human-readable reason for denial (if denied).
    pub denial_reason: Option<String>,
}

impl PolicyDecision {
    /// Construct a deny decision.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            matched_rule: None,
            denial_reason: Some(reason.into()),
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allowed {
            write!(f, "ALLOW")?;
            if let Some(ref rule) = self.matched_rule {
                write!(f, " (rule={rule})")?;
            }
        } else {
            write!(f, "DENY")?;
            if let Some(ref reason) = self.denial_reason {
                write!(f, ": {reason}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

/// Error type for policy engine operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyError {
    #[error("policy evaluation failed: {0}")]
    EvaluationFailed(String),
}

/// The policy engine holds an ordered list of rules and evaluates requests
/// against them. Default behaviour is **deny-all**.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create a policy engine with no rules (deny-all).
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    /// Create a policy engine from a list of rules.
    pub fn with_rules(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluate a request against the policy rules.
    ///
    /// Applies additional safety-class enforcement:
    /// - `REVEAL` operations are always denied for `Agent` clients.
    /// - `SENSITIVE_OUTPUT` operations are denied for `Agent` clients unless
    ///   the matching rule explicitly allows agent client types.
    pub fn evaluate(
        &self,
        request: &OperationRequest,
        safety: OperationSafety,
    ) -> PolicyDecision {
        // Hard safety-class enforcement before rule evaluation.
        if request.client_type == ClientType::Agent && safety == OperationSafety::Reveal {
            return PolicyDecision::deny(
                "REVEAL operations are never permitted for agent clients",
            );
        }

        // Find the first matching rule.
        for rule in &self.rules {
            if rule.matches(request) {
                if !rule.allow {
                    return PolicyDecision {
                        allowed: false,
                        required_factors: vec![],
                        approval_requirement: ApprovalRequirement::Never,
                        lease_ttl: None,
                        one_time: false,
                        matched_rule: Some(rule.name.clone()),
                        denial_reason: Some(format!("denied by rule: {}", rule.name)),
                    };
                }

                // For SENSITIVE_OUTPUT with agent clients, the rule must
                // explicitly include Agent in client_types to allow it.
                if request.client_type == ClientType::Agent
                    && safety == OperationSafety::SensitiveOutput
                    && !rule.client_types.contains(&ClientType::Agent)
                {
                    return PolicyDecision::deny(
                        "SENSITIVE_OUTPUT operations require explicit agent client allowance in policy",
                    );
                }

                return PolicyDecision {
                    allowed: true,
                    required_factors: rule.approval.factors.clone(),
                    approval_requirement: rule.approval.require,
                    lease_ttl: rule.approval.lease_ttl,
                    one_time: rule.approval.one_time,
                    matched_rule: Some(rule.name.clone()),
                    denial_reason: None,
                };
            }
        }

        // No matching rule: deny by default.
        PolicyDecision::deny("no matching policy rule (default deny)")
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::SystemTime;

    use uuid::Uuid;

    use super::*;
    use crate::operation::{ClientIdentity, ClientType, OperationRequest};

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
        }
    }

    fn allow_rule() -> PolicyRule {
        PolicyRule {
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
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: true,
            },
        }
    }

    #[test]
    fn default_deny() {
        let engine = PolicyEngine::new();
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
        assert!(decision.denial_reason.unwrap().contains("default deny"));
    }

    #[test]
    fn matching_rule_allows() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(decision.allowed);
        assert_eq!(decision.required_factors, vec![ApprovalFactor::LocalBio]);
        assert!(decision.one_time);
    }

    #[test]
    fn reveal_denied_for_agents() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Reveal);
        assert!(!decision.allowed);
        assert!(decision.denial_reason.unwrap().contains("REVEAL"));
    }

    #[test]
    fn sensitive_output_requires_explicit_agent_allowance() {
        // Rule without explicit Agent client type.
        let mut rule = allow_rule();
        rule.client_types = vec![]; // empty means "applies to all" for matching, but not for SENSITIVE_OUTPUT gate
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::SensitiveOutput);
        assert!(!decision.allowed);
    }

    #[test]
    fn sensitive_output_allowed_when_agent_explicit() {
        let rule = allow_rule(); // already has Agent in client_types
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::SensitiveOutput);
        assert!(decision.allowed);
    }

    #[test]
    fn client_match_uid_mismatch() {
        let mut rule = allow_rule();
        rule.client.uid = Some(999);
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn target_mismatch_denies() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let mut req = test_request("github.set_actions_secret", ClientType::Human);
        req.target.insert("repo".into(), "other-org/repo".into());
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn explicit_deny_rule() {
        let mut rule = allow_rule();
        rule.allow = false;
        rule.name = "deny-rule".into();
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
        assert!(decision.denial_reason.unwrap().contains("deny-rule"));
    }

    #[test]
    fn policy_decision_display() {
        let allow = PolicyDecision {
            allowed: true,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            matched_rule: Some("test-rule".into()),
            denial_reason: None,
        };
        assert_eq!(format!("{allow}"), "ALLOW (rule=test-rule)");

        let deny = PolicyDecision::deny("no rule matched");
        assert!(format!("{deny}").starts_with("DENY"));
    }
}
