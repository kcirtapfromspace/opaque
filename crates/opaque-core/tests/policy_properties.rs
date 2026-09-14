//! Generated tests call the production PolicyEngine, including its matchers and
//! kernel adapter. Expected decisions are built independently of that kernel.
use std::time::{Duration, SystemTime};

use opaque_core::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationRequest,
    OperationSafety,
};
use opaque_core::policy::{ApprovalConfig, PolicyDecision, PolicyEngine, PolicyRule};
use proptest::prelude::*;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct RuleSpec {
    matches: bool,
    allow: bool,
    requirement: u8,
    budget: Option<u32>,
    ttl: Option<u16>,
    one_time: bool,
    distinct: bool,
    factor: bool,
}

fn specs() -> impl Strategy<Value = RuleSpec> {
    (
        any::<bool>(),
        any::<bool>(),
        0u8..3,
        prop::option::of(prop_oneof![
            Just(0u32),
            Just(1),
            Just(u32::MAX),
            any::<u32>()
        ]),
        prop::option::of(any::<u16>()),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(matches, allow, requirement, budget, ttl, one_time, distinct, factor)| RuleSpec {
                matches,
                allow,
                requirement,
                budget,
                ttl,
                one_time,
                distinct,
                factor,
            },
        )
}

fn requirement(value: u8) -> ApprovalRequirement {
    [
        ApprovalRequirement::Never,
        ApprovalRequirement::Always,
        ApprovalRequirement::FirstUse,
    ][value as usize]
}

fn rule(spec: &RuleSpec, index: usize) -> PolicyRule {
    PolicyRule {
        name: format!("rule-{index}"),
        operation_pattern: if spec.matches { "github.*" } else { "vault.*" }.into(),
        allow: spec.allow,
        approval: ApprovalConfig {
            require: requirement(spec.requirement),
            factors: if spec.factor {
                vec![ApprovalFactor::Fido2]
            } else {
                vec![]
            },
            lease_ttl: spec
                .ttl
                .map(|seconds| Duration::from_secs(u64::from(seconds))),
            one_time: spec.one_time,
            budget: spec.budget,
            require_distinct_approver: spec.distinct,
        },
        client: Default::default(),
        target: Default::default(),
        workspace: Default::default(),
        secret_names: Default::default(),
        client_types: vec![],
        identity: Default::default(),
    }
}

fn request(agent: bool, uid: u32) -> OperationRequest {
    OperationRequest {
        request_id: Uuid::nil(),
        client_identity: ClientIdentity {
            uid,
            gid: 20,
            pid: Some(42),
            exe_path: Some("/usr/bin/fixture".into()),
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        },
        client_type: if agent {
            ClientType::Agent
        } else {
            ClientType::Human
        },
        operation: "github.set_actions_secret".into(),
        target: Default::default(),
        secret_ref_names: vec!["TOKEN".into()],
        created_at: SystemTime::UNIX_EPOCH,
        expires_at: None,
        params: serde_json::Value::Null,
        workspace: None,
        principal: None,
    }
}

fn safety(value: u8) -> OperationSafety {
    [
        OperationSafety::Safe,
        OperationSafety::SensitiveOutput,
        OperationSafety::Reveal,
    ][value as usize]
}

fn denied(reason: String, matched_rule: Option<String>) -> PolicyDecision {
    // Deliberately do not use PolicyDecision::deny: metadata clearing is checked.
    PolicyDecision {
        allowed: false,
        required_factors: vec![],
        approval_requirement: ApprovalRequirement::Never,
        lease_ttl: None,
        one_time: false,
        budget: None,
        require_distinct_approver: false,
        matched_rule,
        denial_reason: Some(reason),
    }
}

fn reference(specs: &[RuleSpec], agent: bool, safety: u8) -> PolicyDecision {
    if (agent, safety) == (true, 2) {
        return denied(
            "REVEAL operations are never permitted for agent clients".into(),
            None,
        );
    }
    let selected = specs.iter().enumerate().find(|(_, spec)| spec.matches);
    match selected {
        None => denied("no matching policy rule (default deny)".into(), None),
        Some((index, spec)) => {
            let name = format!("rule-{index}");
            match (spec.allow, spec.budget, spec.requirement) {
                (false, _, _) => denied(format!("denied by rule: {name}"), Some(name)),
                (true, Some(0), _) | (true, Some(_), 0 | 1) => denied(
                    "approval budget requires first_use and a positive count".into(),
                    None,
                ),
                _ => PolicyDecision {
                    allowed: true,
                    required_factors: if spec.factor {
                        vec![ApprovalFactor::Fido2]
                    } else {
                        vec![]
                    },
                    approval_requirement: requirement(spec.requirement),
                    lease_ttl: spec.ttl.map(|value| Duration::from_secs(value.into())),
                    one_time: spec.one_time,
                    budget: spec.budget,
                    require_distinct_approver: spec.distinct,
                    matched_rule: Some(name),
                    denial_reason: None,
                },
            }
        }
    }
}

fn value(decision: PolicyDecision) -> serde_json::Value {
    serde_json::to_value(decision).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn ordered_engine_agrees_with_independent_decision_table(
        input in prop::collection::vec(specs(), 0..33), agent in any::<bool>(), classification in 0u8..3,
    ) {
        let engine = PolicyEngine::with_rules(input.iter().enumerate().map(|(i, s)| rule(s, i)).collect());
        prop_assert_eq!(value(engine.evaluate(&request(agent, 501), safety(classification))),
            value(reference(&input, agent, classification)));
    }

    #[test]
    fn a_selected_rule_cannot_be_overridden_by_an_arbitrary_suffix(
        mut selected in specs(), suffix in prop::collection::vec(specs(), 0..33),
        agent in any::<bool>(), classification in 0u8..3,
    ) {
        selected.matches = true;
        let mut engine = PolicyEngine::with_rules(vec![rule(&selected, 0)]);
        let before = value(engine.evaluate(&request(agent, 501), safety(classification)));
        for (i, spec) in suffix.iter().enumerate() { engine.add_rule(rule(spec, i + 1)); }
        prop_assert_eq!(value(engine.evaluate(&request(agent, 501), safety(classification))), before);
    }

    #[test]
    fn unmatched_rules_cannot_change_a_decision_or_its_approval_obligations(
        mut selected in specs(), mut prefix in prop::collection::vec(specs(), 0..33),
        classification in 0u8..3,
    ) {
        selected.matches = true;
        let selected_rule = rule(&selected, 99);
        let before = PolicyEngine::with_rules(vec![selected_rule.clone()]);
        for spec in &mut prefix { spec.matches = false; }
        let mut rules: Vec<_> = prefix.iter().enumerate().map(|(i, s)| rule(s, i)).collect();
        rules.push(selected_rule);
        let after = PolicyEngine::with_rules(rules);
        prop_assert_eq!(value(before.evaluate(&request(false, 501), safety(classification))),
            value(after.evaluate(&request(false, 501), safety(classification))));
    }

    #[test]
    fn agent_reveal_is_denied_even_with_arbitrary_allow_policies(
        input in prop::collection::vec(specs(), 0..33), uid in any::<u32>(),
    ) {
        let engine = PolicyEngine::with_rules(input.iter().enumerate().map(|(i, s)| rule(s, i)).collect());
        prop_assert_eq!(value(engine.evaluate(&request(true, uid), OperationSafety::Reveal)),
            value(denied("REVEAL operations are never permitted for agent clients".into(), None)));
    }

    #[test]
    fn narrowing_an_allow_to_a_verified_uid_never_admits_another_uid(
        mut spec in specs(), uid in any::<u32>(),
    ) {
        spec.matches = true; spec.allow = true; spec.requirement = 2; spec.budget = Some(1);
        let mut narrow = rule(&spec, 0);
        let broad = PolicyEngine::with_rules(vec![narrow.clone()]);
        narrow.client.uid = Some(uid);
        let narrow = PolicyEngine::with_rules(vec![narrow]);
        let admitted = request(false, uid);
        let other = request(false, uid.wrapping_add(1));
        prop_assert!(broad.evaluate(&other, OperationSafety::Safe).allowed);
        prop_assert_eq!(value(broad.evaluate(&admitted, OperationSafety::Safe)),
            value(narrow.evaluate(&admitted, OperationSafety::Safe)));
        prop_assert_eq!(value(narrow.evaluate(&other, OperationSafety::Safe)),
            value(denied("no matching policy rule (default deny)".into(), None)));
    }

    #[test]
    fn rule_roundtrip_preserves_order_digest_and_complete_decision(
        input in prop::collection::vec(specs(), 0..33), agent in any::<bool>(), classification in 0u8..3,
    ) {
        let rules: Vec<_> = input.iter().enumerate().map(|(i, s)| rule(s, i)).collect();
        let decoded = serde_json::from_slice::<Vec<PolicyRule>>(&serde_json::to_vec(&rules).unwrap()).unwrap();
        let original = PolicyEngine::with_rules(rules);
        let restored = PolicyEngine::with_rules(decoded);
        prop_assert_eq!(original.digest().unwrap(), restored.digest().unwrap());
        prop_assert_eq!(value(original.evaluate(&request(agent, 501), safety(classification))),
            value(restored.evaluate(&request(agent, 501), safety(classification))));
    }
}
