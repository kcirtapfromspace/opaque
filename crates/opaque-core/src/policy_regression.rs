//! Offline, deterministic regression checks for the policy engine.
//!
//! Fixtures are reviewed, synthetic or sanitized policy inputs, not credentials
//! or executable requests. This does not replay daemon authorization, registered
//! operation approval floors, leases, delegation validation, or provider calls.

use std::collections::{BTreeMap, HashSet};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bundle::Team;
use crate::identity::PrincipalContext;
use crate::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationRequest,
    OperationSafety, WorkspaceContext,
};
use crate::policy::{PolicyDecision, PolicyEngine, PolicyRule};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_CASES: usize = 10_000;

/// A policy and, for a bundle, its authoritative team membership snapshot.
/// `None` preserves fixture teams for a rules-only local policy comparison.
#[derive(Clone, Serialize)]
pub struct PolicySnapshot {
    pub rules: Vec<PolicyRule>,
    pub teams: Option<Vec<Team>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionSuite {
    pub schema_version: u32,
    pub cases: Vec<GoldenCase>,
}

/// Contains only fields consumed by policy evaluation. Safety and identity
/// must be reviewed test inputs; this tool cannot attest to their provenance.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenCase {
    pub id: String,
    pub operation: String,
    pub safety: OperationSafety,
    pub client_type: ClientType,
    pub client_identity: ClientIdentity,
    #[serde(default)]
    pub target: BTreeMap<String, String>,
    #[serde(default)]
    pub secret_ref_names: Vec<String>,
    #[serde(default)]
    pub workspace: Option<WorkspaceContext>,
    #[serde(default)]
    pub principal: Option<PrincipalContext>,
    /// Exact expected candidate decision, including all approval properties.
    pub expect: DecisionSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Deny,
    Allow,
    HumanGated,
}

/// Semantics of a policy decision. Rule names and denial prose are excluded:
/// renaming a rule is not an authorization change. Factors are an any-of set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionSnapshot {
    pub decision: DecisionKind,
    #[serde(default)]
    pub approval_requirement: ApprovalRequirement,
    #[serde(default)]
    pub required_factors: Vec<ApprovalFactor>,
    #[serde(default)]
    pub lease_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub one_time: bool,
    #[serde(default)]
    pub require_distinct_approver: bool,
}

impl DecisionSnapshot {
    fn normalize(mut self) -> Self {
        self.required_factors
            .sort_by_key(|factor| factor.to_string());
        self.required_factors.dedup();
        self
    }

    fn from_decision(decision: PolicyDecision) -> Self {
        Self {
            decision: if !decision.allowed {
                DecisionKind::Deny
            } else if decision.approval_requirement == ApprovalRequirement::Never {
                DecisionKind::Allow
            } else {
                DecisionKind::HumanGated
            },
            approval_requirement: decision.approval_requirement,
            required_factors: decision.required_factors,
            lease_ttl_seconds: decision.lease_ttl.map(|ttl| ttl.as_secs()),
            one_time: decision.one_time,
            require_distinct_approver: decision.require_distinct_approver,
        }
        .normalize()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionChange {
    NewlyAllowed,
    NewlyBlocked,
    NewlyHumanGated,
    HumanGateRemoved,
    ApprovalChanged,
}

#[derive(Debug, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub baseline: DecisionSnapshot,
    pub candidate: DecisionSnapshot,
    pub expected: DecisionSnapshot,
    pub changes: Vec<DecisionChange>,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct RegressionReport {
    pub schema_version: u32,
    pub scope: &'static str,
    pub engine_version: &'static str,
    /// Digests bind normalized parsed inputs, not the original file bytes.
    pub baseline_sha256: String,
    pub candidate_sha256: String,
    pub suite_sha256: String,
    pub total_cases: usize,
    pub changed_cases: usize,
    pub expectation_failures: usize,
    pub fail_on_change: bool,
    pub passed: bool,
    /// No targets, secret references, executable paths or principals emitted.
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegressionError {
    #[error("unsupported regression suite schema version")]
    UnsupportedVersion,
    #[error("regression suite must contain between 1 and {MAX_CASES} cases")]
    InvalidCaseCount,
    #[error("case {index}: id must use 1-128 ASCII letters, digits, dots, dashes or underscores")]
    InvalidId { index: usize },
    #[error("case {index}: duplicate case id")]
    DuplicateId { index: usize },
    #[error("case {index}: operation must not be empty")]
    EmptyOperation { index: usize },
    #[error("case {index}: expected decision and approval requirement disagree")]
    InvalidExpectation { index: usize },
    #[error("could not serialize regression input")]
    Serialization,
}

impl RegressionSuite {
    pub fn validate(&self) -> Result<(), RegressionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RegressionError::UnsupportedVersion);
        }
        if self.cases.is_empty() || self.cases.len() > MAX_CASES {
            return Err(RegressionError::InvalidCaseCount);
        }
        let mut ids = HashSet::new();
        for (index, case) in self.cases.iter().enumerate() {
            if case.id.is_empty()
                || case.id.len() > 128
                || !case
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(RegressionError::InvalidId { index });
            }
            if !ids.insert(&case.id) {
                return Err(RegressionError::DuplicateId { index });
            }
            if case.operation.trim().is_empty() {
                return Err(RegressionError::EmptyOperation { index });
            }
            let gated = case.expect.approval_requirement != ApprovalRequirement::Never;
            if (case.expect.decision == DecisionKind::HumanGated) != gated {
                return Err(RegressionError::InvalidExpectation { index });
            }
        }
        Ok(())
    }
}

fn request_for(case: &GoldenCase, policy: &PolicySnapshot) -> OperationRequest {
    let mut principal = case.principal.clone();
    if let (Some(principal), Some(teams)) = (&mut principal, &policy.teams) {
        // Same label matching as FederationRuntime::teams_of. This models
        // bundle membership edits without trusting stale recorded teams.
        principal.sub_teams = teams
            .iter()
            .filter(|team| {
                team.members
                    .iter()
                    .any(|member| member.eq_ignore_ascii_case(&principal.sub_label))
            })
            .map(|team| team.name.clone())
            .collect();
    }
    OperationRequest {
        request_id: uuid::Uuid::nil(),
        client_identity: case.client_identity.clone(),
        client_type: case.client_type,
        operation: case.operation.clone(),
        target: case.target.clone().into_iter().collect(),
        secret_ref_names: case.secret_ref_names.clone(),
        created_at: UNIX_EPOCH,
        expires_at: None,
        params: serde_json::Value::Null,
        workspace: case.workspace.clone(),
        principal,
    }
}

fn digest(value: &impl Serialize) -> Result<String, RegressionError> {
    // Value uses sorted object keys, including maps nested within policy rules.
    let value = serde_json::to_value(value).map_err(|_| RegressionError::Serialization)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| RegressionError::Serialization)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn changes(before: &DecisionSnapshot, after: &DecisionSnapshot) -> Vec<DecisionChange> {
    use DecisionKind::{Allow, Deny, HumanGated};
    let mut result = Vec::new();
    match (before.decision, after.decision) {
        (Deny, Allow | HumanGated) => result.push(DecisionChange::NewlyAllowed),
        (Allow | HumanGated, Deny) => result.push(DecisionChange::NewlyBlocked),
        (HumanGated, Allow) => result.push(DecisionChange::HumanGateRemoved),
        _ => {}
    }
    if before.decision != HumanGated && after.decision == HumanGated {
        result.push(DecisionChange::NewlyHumanGated);
    }
    if before.decision == after.decision && before != after {
        result.push(DecisionChange::ApprovalChanged);
    }
    result
}

/// Compare identical reviewed cases against two policies without side effects.
/// A failed expectation always fails the gate; `fail_on_change` additionally
/// blocks any changed decision even when the new behavior is expected.
pub fn compare(
    baseline: &PolicySnapshot,
    candidate: &PolicySnapshot,
    suite: &RegressionSuite,
    fail_on_change: bool,
) -> Result<RegressionReport, RegressionError> {
    suite.validate()?;
    let before = PolicyEngine::with_rules(baseline.rules.clone());
    let after = PolicyEngine::with_rules(candidate.rules.clone());
    let cases: Vec<_> = suite
        .cases
        .iter()
        .map(|case| {
            let baseline = DecisionSnapshot::from_decision(
                before.evaluate(&request_for(case, baseline), case.safety),
            );
            let candidate = DecisionSnapshot::from_decision(
                after.evaluate(&request_for(case, candidate), case.safety),
            );
            let expected = case.expect.clone().normalize();
            CaseResult {
                id: case.id.clone(),
                changes: changes(&baseline, &candidate),
                passed: candidate == expected,
                baseline,
                candidate,
                expected,
            }
        })
        .collect();
    let changed_cases = cases.iter().filter(|case| !case.changes.is_empty()).count();
    let expectation_failures = cases.iter().filter(|case| !case.passed).count();
    Ok(RegressionReport {
        schema_version: SCHEMA_VERSION,
        scope: "policy_engine_only",
        engine_version: env!("CARGO_PKG_VERSION"),
        baseline_sha256: digest(baseline)?,
        candidate_sha256: digest(candidate)?,
        suite_sha256: digest(suite)?,
        total_cases: cases.len(),
        changed_cases,
        expectation_failures,
        fail_on_change,
        passed: expectation_failures == 0 && (!fail_on_change || changed_cases == 0),
        cases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(rules: serde_json::Value) -> PolicySnapshot {
        PolicySnapshot {
            rules: serde_json::from_value(rules).unwrap(),
            teams: None,
        }
    }

    fn rule(name: &str, operation: &str, allow: bool) -> serde_json::Value {
        json!({"name":name,"operation_pattern":operation,"allow":allow})
    }

    fn case(id: &str, operation: &str, expect: serde_json::Value) -> GoldenCase {
        serde_json::from_value(json!({
            "id":id,"operation":operation,"safety":"SAFE","client_type":"agent",
            "client_identity":{"uid":1000,"gid":1000},"expect":expect
        }))
        .unwrap()
    }

    fn suite(cases: Vec<GoldenCase>) -> RegressionSuite {
        RegressionSuite {
            schema_version: 1,
            cases,
        }
    }

    #[test]
    fn classifies_newly_allowed_blocked_gated_and_removed_gates() {
        let baseline = policy(json!([
            rule("blocked", "blocked", true),
            rule("gate", "gated", true),
            {"name":"ungate","operation_pattern":"ungated","approval":{"require":"always","factors":["local_bio"]}}
        ]));
        let candidate = policy(json!([
            rule("new", "new", true),
            {"name":"gate","operation_pattern":"gated","approval":{"require":"always","factors":["local_bio"]}},
            rule("ungate", "ungated", true)
        ]));
        let report = compare(&baseline, &candidate, &suite(vec![
            case("new", "new", json!({"decision":"allow"})),
            case("blocked", "blocked", json!({"decision":"deny"})),
            case("gated", "gated", json!({"decision":"human_gated","approval_requirement":"always","required_factors":["local_bio"]})),
            case("ungated", "ungated", json!({"decision":"allow"})),
        ]), false).unwrap();
        assert!(report.passed);
        assert_eq!(report.changed_cases, 4);
        assert_eq!(report.cases[0].changes, [DecisionChange::NewlyAllowed]);
        assert_eq!(report.cases[1].changes, [DecisionChange::NewlyBlocked]);
        assert_eq!(report.cases[2].changes, [DecisionChange::NewlyHumanGated]);
        assert_eq!(report.cases[3].changes, [DecisionChange::HumanGateRemoved]);
    }

    #[test]
    fn newly_allowed_with_approval_reports_both_changes() {
        let candidate = policy(
            json!([{"name":"gate","operation_pattern":"*","approval":{"require":"always"}}]),
        );
        let report = compare(
            &policy(json!([])),
            &candidate,
            &suite(vec![case(
                "new",
                "new",
                json!({"decision":"human_gated","approval_requirement":"always"}),
            )]),
            false,
        )
        .unwrap();
        assert_eq!(
            report.cases[0].changes,
            [
                DecisionChange::NewlyAllowed,
                DecisionChange::NewlyHumanGated
            ]
        );
    }

    #[test]
    fn weakening_approval_fails_exact_expectation_without_allow_deny_change() {
        let baseline = policy(
            json!([{"name":"gate","operation_pattern":"*","approval":{"require":"first_use","factors":["local_bio"],"lease_ttl":60,"one_time":true,"require_distinct_approver":true}}]),
        );
        let mut candidate = baseline.clone();
        candidate.rules[0].approval.lease_ttl = Some(std::time::Duration::from_secs(3600));
        candidate.rules[0].approval.require_distinct_approver = false;
        let suite = suite(vec![case(
            "approval",
            "read",
            json!({
                "decision":"human_gated","approval_requirement":"first_use","required_factors":["local_bio"],
                "lease_ttl_seconds":60,"one_time":true,"require_distinct_approver":true
            }),
        )]);
        let report = compare(&baseline, &candidate, &suite, false).unwrap();
        assert!(!report.passed);
        assert_eq!(report.expectation_failures, 1);
        assert_eq!(report.cases[0].changes, [DecisionChange::ApprovalChanged]);
    }

    #[test]
    fn first_match_and_reveal_safety_floor_use_real_engine() {
        let baseline = policy(json!([
            rule("deny", "secret.*", false),
            rule("broad", "*", true)
        ]));
        let candidate = policy(json!([
            rule("broad", "*", true),
            rule("deny", "secret.*", false)
        ]));
        let mut reveal = case("reveal", "secret.reveal", json!({"decision":"deny"}));
        reveal.safety = OperationSafety::Reveal;
        let report = compare(
            &baseline,
            &candidate,
            &suite(vec![
                case("reorder", "secret.read", json!({"decision":"deny"})),
                reveal,
            ]),
            false,
        )
        .unwrap();
        assert!(!report.passed);
        assert_eq!(report.expectation_failures, 1);
        assert_eq!(report.cases[0].changes, [DecisionChange::NewlyAllowed]);
        assert!(report.cases[1].passed);
    }

    #[test]
    fn unverified_workspace_and_missing_identity_remain_fail_closed() {
        let policy = policy(json!([{
            "name":"scoped","operation_pattern":"*",
            "workspace":{"branch_pattern":"main"},"identity":{"require_principal":true}
        }]));
        let suite = suite(vec![case(
            "missing-context",
            "read",
            json!({"decision":"deny"}),
        )]);
        assert!(compare(&policy, &policy, &suite, false).unwrap().passed);
    }

    #[test]
    fn bundle_membership_is_recomputed_and_can_revoke_access() {
        let mut baseline = policy(json!([{
            "name":"team","operation_pattern":"*","identity":{"teams":["platform"]}
        }]));
        baseline.teams = Some(vec![Team {
            name: "platform".into(),
            members: vec!["OWNER@EXAMPLE.INVALID".into()],
        }]);
        let mut candidate = baseline.clone();
        candidate.teams = Some(vec![]);
        let mut input = case("removed-member", "read", json!({"decision":"deny"}));
        input.principal = Some(
            serde_json::from_value(json!({
                "sub":"hum_00000000000000000000000000000001","sub_label":"owner@example.invalid",
                "sub_roles":[],"sub_teams":["stale-recorded-team"],
                "act":"agt_00000000000000000000000000000002","act_label":"agent:test",
                "mode":"delegated","jti":"synthetic-session"
            }))
            .unwrap(),
        );
        let report = compare(&baseline, &candidate, &suite(vec![input]), false).unwrap();
        assert!(report.passed);
        assert_eq!(report.cases[0].changes, [DecisionChange::NewlyBlocked]);
    }

    #[test]
    fn strict_gate_blocks_expected_changes_and_rule_renames_are_ignored() {
        let baseline = policy(json!([]));
        let mut candidate = policy(json!([rule("new", "*", true)]));
        let suite = suite(vec![case("new", "read", json!({"decision":"allow"}))]);
        assert!(!compare(&baseline, &candidate, &suite, true).unwrap().passed);
        let old = candidate.clone();
        candidate.rules[0].name = "renamed".into();
        assert!(compare(&old, &candidate, &suite, true).unwrap().passed);
    }

    #[test]
    fn factors_are_a_set_and_reports_are_deterministic_and_minimized() {
        let policy = policy(json!([{
            "name":"not-in-report","operation_pattern":"*",
            "target":{"fields":{"repo":"private-*","env":"*"}},
            "approval":{"require":"always","factors":["fido2","local_bio"]}
        }]));
        let mut input = case(
            "case-1",
            "not-in-report",
            json!({
                "decision":"human_gated","approval_requirement":"always","required_factors":["local_bio","fido2","fido2"]
            }),
        );
        input.target.insert("repo".into(), "private-target".into());
        input.target.insert("env".into(), "internal".into());
        input.secret_ref_names = vec!["private-secret-name".into()];
        let suite = suite(vec![input]);
        let first = compare(&policy, &policy, &suite, false).unwrap();
        assert!(first.passed);
        let json = serde_json::to_string(&first).unwrap();
        let reparsed = policy
            .rules
            .iter()
            .map(|r| serde_json::from_value(serde_json::to_value(r).unwrap()).unwrap())
            .collect();
        let second_policy = PolicySnapshot {
            rules: reparsed,
            teams: None,
        };
        assert_eq!(
            json,
            serde_json::to_string(&compare(&second_policy, &second_policy, &suite, false).unwrap())
                .unwrap()
        );
        assert!(!json.contains("private-target"));
        assert!(!json.contains("private-secret-name"));
        assert!(!json.contains("not-in-report"));
    }

    #[test]
    fn malformed_empty_duplicate_and_missing_expectations_cannot_pass() {
        assert!(matches!(
            suite(vec![]).validate(),
            Err(RegressionError::InvalidCaseCount)
        ));
        let input = case("same", "read", json!({"decision":"deny"}));
        assert!(matches!(
            suite(vec![input.clone(), input.clone()]).validate(),
            Err(RegressionError::DuplicateId { .. })
        ));
        let mut wrong_version = suite(vec![input.clone()]);
        wrong_version.schema_version = 2;
        assert!(wrong_version.validate().is_err());
        let mut invalid = input.clone();
        invalid.id = "line\nbreak".into();
        assert!(suite(vec![invalid]).validate().is_err());
        let mut value = serde_json::to_value(input).unwrap();
        value.as_object_mut().unwrap().remove("expect");
        assert!(serde_json::from_value::<GoldenCase>(value).is_err());
        assert!(
            serde_json::from_str::<RegressionSuite>(
                r#"{"schema_version":1,"cases":[],"params":{"token":"never-accepted"}}"#
            )
            .is_err()
        );
    }
}
