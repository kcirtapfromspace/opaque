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
    OperationSafety, WorkspaceContext,
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
        if let Some(uid) = self.uid
            && identity.uid != uid
        {
            return false;
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
// Workspace match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching git workspace context. When a rule has workspace
/// constraints, requests without workspace context are denied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceMatch {
    /// Glob pattern for the git remote URL (e.g. `"*github.com:org/*"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_url_pattern: Option<String>,

    /// Glob pattern for the branch name (e.g. `"main"`, `"release/*"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_pattern: Option<String>,

    /// If true, deny requests from dirty (uncommitted changes) workspaces.
    #[serde(default)]
    pub require_clean: bool,
}

impl WorkspaceMatch {
    /// Returns `true` if the workspace context (or lack thereof) matches.
    ///
    /// - No constraints + no workspace = match (backward compat)
    /// - Constraints + no workspace = deny
    /// - Constraints + workspace = check each field via glob
    /// - `require_clean && dirty = deny`
    pub fn matches(&self, workspace: Option<&WorkspaceContext>) -> bool {
        let has_constraints = self.remote_url_pattern.is_some()
            || self.branch_pattern.is_some()
            || self.require_clean;

        match (has_constraints, workspace) {
            // No constraints, no workspace — backward compat match.
            (false, None) => true,
            // No constraints, workspace present — match.
            (false, Some(_)) => true,
            // Constraints but no workspace — deny.
            (true, None) => false,
            // Constraints + workspace — check each.
            (true, Some(ws)) => {
                if let Some(ref pattern) = self.remote_url_pattern {
                    match &ws.remote_url {
                        Some(url) => {
                            if !glob_match::glob_match(pattern, url) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }

                if let Some(ref pattern) = self.branch_pattern {
                    match &ws.branch {
                        Some(branch) => {
                            if !glob_match::glob_match(pattern, branch) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }

                if self.require_clean && ws.dirty {
                    return false;
                }

                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Secret name match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching secret ref names referenced in an operation request.
/// Constrains which secrets a policy rule permits, preventing "secret
/// transporter" attacks where a client with access to one operation can
/// reference any secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretNameMatch {
    /// Glob patterns for allowed secret ref names. Empty = match any.
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl SecretNameMatch {
    /// Returns `true` if all secret ref names match at least one pattern.
    /// An empty pattern list matches any set of names (backward compat).
    /// A non-empty pattern list requires at least one secret ref name —
    /// empty `secret_ref_names` fails closed when patterns are specified.
    pub fn matches(&self, secret_ref_names: &[String]) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        if secret_ref_names.is_empty() {
            return false;
        }
        secret_ref_names.iter().all(|name| {
            self.patterns
                .iter()
                .any(|p| glob_match::glob_match(p, name))
        })
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

    /// Workspace (git repo/branch) constraints.
    #[serde(default)]
    pub workspace: WorkspaceMatch,

    /// Secret ref name constraints (glob patterns).
    #[serde(default)]
    pub secret_names: SecretNameMatch,

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

        // Workspace constraints.
        if !self.workspace.matches(request.workspace.as_ref()) {
            return false;
        }

        // Secret ref name constraints.
        if !self.secret_names.matches(&request.secret_ref_names) {
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
    pub fn evaluate(&self, request: &OperationRequest, safety: OperationSafety) -> PolicyDecision {
        // Hard safety-class enforcement before rule evaluation.
        if request.client_type == ClientType::Agent && safety == OperationSafety::Reveal {
            return PolicyDecision::deny("REVEAL operations are never permitted for agent clients");
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

    use std::time::Duration;

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
            workspace: None,
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

    #[test]
    fn client_match_exe_sha256_mismatch() {
        let cm = ClientMatch {
            exe_sha256: Some("expected_hash".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.exe_sha256 = Some("different_hash".into());
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_exe_sha256_none() {
        let cm = ClientMatch {
            exe_sha256: Some("expected_hash".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.exe_sha256 = None;
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_codesign_mismatch() {
        let cm = ClientMatch {
            codesign_team_id: Some("TEAM_A".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.codesign_team_id = Some("TEAM_B".into());
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_codesign_none() {
        let cm = ClientMatch {
            codesign_team_id: Some("TEAM_A".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.codesign_team_id = None;
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_exe_path_none() {
        let cm = ClientMatch {
            exe_path: Some("/usr/bin/*".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.exe_path = None;
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_all_none() {
        let cm = ClientMatch::default();
        let id = test_identity();
        assert!(cm.matches(&id));
    }

    #[test]
    fn target_match_empty_matches_all() {
        let tm = TargetMatch::default();
        let mut target = HashMap::new();
        target.insert("repo".into(), "anything".into());
        assert!(tm.matches(&target));
    }

    #[test]
    fn target_match_missing_field() {
        let tm = TargetMatch {
            fields: {
                let mut m = HashMap::new();
                m.insert("repo".into(), "org/*".into());
                m
            },
        };
        let target = HashMap::new();
        assert!(!tm.matches(&target));
    }

    #[test]
    fn policy_engine_add_rule_and_count() {
        let mut engine = PolicyEngine::new();
        assert_eq!(engine.rule_count(), 0);
        engine.add_rule(allow_rule());
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn policy_engine_default() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn client_type_filter_mismatch() {
        let mut rule = allow_rule();
        rule.client_types = vec![ClientType::Human];
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn operation_pattern_mismatch() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let req = test_request("k8s.set_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn reveal_allowed_for_human() {
        let mut rule = allow_rule();
        rule.operation_pattern = "*".into();
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("secret.reveal", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Reveal);
        assert!(decision.allowed);
    }

    #[test]
    fn human_sensitive_output_allowed() {
        let mut rule = allow_rule();
        rule.client_types = vec![ClientType::Human];
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::SensitiveOutput);
        assert!(decision.allowed);
    }

    #[test]
    fn policy_decision_display_no_rule() {
        let decision = PolicyDecision {
            allowed: true,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            matched_rule: None,
            denial_reason: None,
        };
        assert_eq!(format!("{decision}"), "ALLOW");
    }

    #[test]
    fn policy_decision_display_deny_no_reason() {
        let decision = PolicyDecision {
            allowed: false,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            matched_rule: None,
            denial_reason: None,
        };
        assert_eq!(format!("{decision}"), "DENY");
    }

    #[test]
    fn approval_config_serde_with_lease_ttl() {
        let config = ApprovalConfig {
            require: ApprovalRequirement::FirstUse,
            factors: vec![ApprovalFactor::LocalBio],
            lease_ttl: Some(Duration::from_secs(300)),
            one_time: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let roundtripped: ApprovalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.lease_ttl, Some(Duration::from_secs(300)));
    }

    #[test]
    fn approval_config_serde_without_lease_ttl() {
        let config = ApprovalConfig {
            require: ApprovalRequirement::Always,
            factors: vec![],
            lease_ttl: None,
            one_time: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("lease_ttl"));
        let roundtripped: ApprovalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.lease_ttl, None);
        assert!(roundtripped.one_time);
    }

    // -- Workspace match tests --

    fn test_workspace() -> WorkspaceContext {
        WorkspaceContext {
            repo_root: "/home/user/project".into(),
            remote_url: Some("git@github.com:org/repo.git".into()),
            branch: Some("main".into()),
            head_sha: Some("abc123".into()),
            dirty: false,
        }
    }

    #[test]
    fn workspace_match_empty_matches_all() {
        let wm = WorkspaceMatch::default();
        assert!(wm.matches(None));
        assert!(wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_remote_url_pattern() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            ..Default::default()
        };
        assert!(wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_remote_url_mismatch() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*gitlab.com:org/*".into()),
            ..Default::default()
        };
        assert!(!wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_branch_pattern() {
        let wm = WorkspaceMatch {
            branch_pattern: Some("main".into()),
            ..Default::default()
        };
        assert!(wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_branch_mismatch() {
        let wm = WorkspaceMatch {
            branch_pattern: Some("release/*".into()),
            ..Default::default()
        };
        assert!(!wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_require_clean_dirty_fails() {
        let wm = WorkspaceMatch {
            require_clean: true,
            ..Default::default()
        };
        let mut ws = test_workspace();
        ws.dirty = true;
        assert!(!wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_require_clean_clean_passes() {
        let wm = WorkspaceMatch {
            require_clean: true,
            ..Default::default()
        };
        let ws = test_workspace(); // dirty = false
        assert!(wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_no_ws_with_constraints_fails() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*".into()),
            ..Default::default()
        };
        assert!(!wm.matches(None));
    }

    #[test]
    fn workspace_match_no_ws_no_constraints_passes() {
        let wm = WorkspaceMatch::default();
        assert!(wm.matches(None));
    }

    #[test]
    fn policy_rule_with_workspace_constraint() {
        let mut rule = allow_rule();
        rule.workspace = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            branch_pattern: Some("main".into()),
            require_clean: false,
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        // Request with matching workspace.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(test_workspace());
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(decision.allowed);

        // Request without workspace — denied.
        let req2 = test_request("github.set_actions_secret", ClientType::Agent);
        let decision2 = engine.evaluate(&req2, OperationSafety::Safe);
        assert!(!decision2.allowed);
    }

    // -- SecretNameMatch tests --

    #[test]
    fn secret_name_empty_allows_any() {
        let snm = SecretNameMatch::default();
        assert!(snm.matches(&["ANY_SECRET".into(), "OTHER".into()]));
        assert!(snm.matches(&[]));
    }

    #[test]
    fn secret_name_exact() {
        let snm = SecretNameMatch {
            patterns: vec!["JWT".into()],
        };
        assert!(snm.matches(&["JWT".into()]));
        assert!(!snm.matches(&["AWS_KEY".into()]));
    }

    #[test]
    fn secret_name_glob() {
        let snm = SecretNameMatch {
            patterns: vec!["db/*".into()],
        };
        assert!(snm.matches(&["db/password".into()]));
        assert!(snm.matches(&["db/username".into()]));
        assert!(!snm.matches(&["aws/key".into()]));
    }

    #[test]
    fn secret_name_rejects_unmatched() {
        let snm = SecretNameMatch {
            patterns: vec!["JWT".into()],
        };
        assert!(!snm.matches(&["JWT".into(), "UNALLOWED_SECRET".into()]));
    }

    #[test]
    fn secret_name_multiple_patterns() {
        let snm = SecretNameMatch {
            patterns: vec!["JWT".into(), "AWS_*".into()],
        };
        assert!(snm.matches(&["JWT".into()]));
        assert!(snm.matches(&["AWS_ACCESS_KEY".into()]));
        assert!(snm.matches(&["JWT".into(), "AWS_SECRET".into()]));
        assert!(!snm.matches(&["GH_TOKEN".into()]));
    }

    #[test]
    fn secret_name_all_refs_must_match() {
        let snm = SecretNameMatch {
            patterns: vec!["allowed_*".into()],
        };
        // All refs match
        assert!(snm.matches(&["allowed_one".into(), "allowed_two".into()]));
        // One ref doesn't match
        assert!(!snm.matches(&["allowed_one".into(), "forbidden".into()]));
    }

    #[test]
    fn policy_with_secret_constraint() {
        let mut rule = allow_rule();
        rule.secret_names = SecretNameMatch {
            patterns: vec!["JWT".into(), "GH_*".into()],
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        // Request with JWT — allowed.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(decision.allowed);
    }

    #[test]
    fn policy_denies_unlisted_secret() {
        let mut rule = allow_rule();
        rule.secret_names = SecretNameMatch {
            patterns: vec!["ONLY_THIS".into()],
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        // Request has "JWT" which doesn't match "ONLY_THIS".
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
        assert!(
            decision
                .denial_reason
                .as_ref()
                .unwrap()
                .contains("default deny")
        );
    }

    #[test]
    fn secret_name_match_empty_refs_fails_closed() {
        // P0-3: When patterns are specified but secret_ref_names is empty,
        // matches() must return false (fail-closed).
        let matcher = SecretNameMatch {
            patterns: vec!["CI_*".into()],
        };
        assert!(!matcher.matches(&[]));
    }

    #[test]
    fn secret_name_match_empty_patterns_matches_anything() {
        // Empty patterns means "no constraint" — should match any refs.
        let matcher = SecretNameMatch {
            patterns: vec![],
        };
        assert!(matcher.matches(&[]));
        assert!(matcher.matches(&["FOO".into()]));
    }

    #[test]
    fn secret_name_match_populated_refs_still_works() {
        let matcher = SecretNameMatch {
            patterns: vec!["CI_*".into()],
        };
        assert!(matcher.matches(&["CI_TOKEN".into()]));
        assert!(!matcher.matches(&["DB_PASSWORD".into()]));
    }

    #[test]
    fn policy_denies_empty_secret_refs_when_rule_has_patterns() {
        // P0-3: A policy rule with secret_names patterns should reject
        // requests that don't declare any secret refs.
        let mut rule = allow_rule();
        rule.secret_names = SecretNameMatch {
            patterns: vec!["CI_*".into()],
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.secret_ref_names = vec![]; // Empty — should fail closed.
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }
}
