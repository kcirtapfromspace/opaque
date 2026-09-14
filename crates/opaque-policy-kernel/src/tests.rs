use super::*;

// An independent decision table. No call to the production kernel or its
// predicates participates in the expected result.
fn reference(agent: bool, reveal: bool, rules: &[RuleFacts]) -> Decision {
    match (agent, reveal) {
        (true, true) => Decision::AgentRevealDenied,
        _ => match rules.iter().position(|rule| rule.matches) {
            None => Decision::DefaultDenied,
            Some(index) => match rules[index] {
                RuleFacts { allow: false, .. } => Decision::RuleDenied(index),
                RuleFacts { budget: None, .. }
                | RuleFacts {
                    first_use: true,
                    budget: Some(1..=u32::MAX),
                    ..
                } => Decision::Allow(index),
                _ => Decision::InvalidBudget,
            },
        },
    }
}

fn facts(value: u8) -> RuleFacts {
    RuleFacts {
        matches: value & 1 != 0,
        allow: value & 2 != 0,
        first_use: value & 4 != 0,
        budget: [None, Some(0), Some(1), Some(u32::MAX)][(value >> 3) as usize],
    }
}

#[test]
fn all_short_rule_sequences_agree_with_the_decision_table() {
    let mut checked = 0;
    for agent in [false, true] {
        for reveal in [false, true] {
            for length in 0..=3 {
                for mut code in 0..32_usize.pow(length as u32) {
                    let rules: [RuleFacts; 3] = core::array::from_fn(|_| {
                        let rule = facts((code % 32) as u8);
                        code /= 32;
                        rule
                    });
                    assert_eq!(
                        evaluate(agent, reveal, rules[..length].iter().copied()),
                        reference(agent, reveal, &rules[..length]),
                        "agent={agent} reveal={reveal} rules={:?}",
                        &rules[..length],
                    );
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 135_300);
}

#[test]
fn reveal_denial_never_observes_rule_matches() {
    let rules = core::iter::from_fn(|| -> Option<RuleFacts> {
        panic!("hard denial must precede even the first matcher")
    });
    assert_eq!(evaluate(true, true, rules), Decision::AgentRevealDenied);
}

#[test]
fn every_selected_outcome_stops_before_the_next_matcher() {
    for (rule, expected) in [
        (facts(1), Decision::RuleDenied(0)),
        (facts(3), Decision::Allow(0)),
        (facts(11), Decision::InvalidBudget),
    ] {
        let rules = core::iter::once(rule).chain(core::iter::from_fn(|| {
            panic!("a later matcher cannot alter a selected outcome")
        }));
        assert_eq!(evaluate(false, false, rules), expected);
    }
}
