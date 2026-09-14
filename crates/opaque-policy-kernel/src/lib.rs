//! Pure policy decision precedence, shared by the production policy engine.
//!
//! The caller supplies request classification and lazily computed rule
//! matches. Parsing, identity verification, matching, approval verification and
//! durable consumption remain enforcement responsibilities outside this kernel.
//! An allow result selects a rule; it does not authorize an external effect.

#![no_std]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

/// Facts for one rule, in policy order. Approval budgets are attempt counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleFacts {
    pub matches: bool,
    pub allow: bool,
    pub first_use: bool,
    pub budget: Option<u32>,
}

/// The selected index refers to the original ordered rule sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    AgentRevealDenied,
    RuleDenied(usize),
    InvalidBudget,
    Allow(usize),
    DefaultDenied,
}

/// Hard safety denial precedes matching; the first matching rule is final.
///
/// The iterator is never advanced for agent reveal requests, or beyond the
/// selected rule. A malformed allow budget denies; it cannot fall through to a
/// later allow. Explicit deny rules do not acquire approval obligations.
pub fn evaluate(
    is_agent: bool,
    is_reveal: bool,
    rules: impl IntoIterator<Item = RuleFacts>,
) -> Decision {
    if is_agent && is_reveal {
        return Decision::AgentRevealDenied;
    }
    for (index, rule) in rules.into_iter().enumerate() {
        if !rule.matches {
            continue;
        }
        if !rule.allow {
            return Decision::RuleDenied(index);
        }
        if let Some(budget) = rule.budget
            && (!rule.first_use || budget == 0)
        {
            return Decision::InvalidBudget;
        }
        return Decision::Allow(index);
    }
    Decision::DefaultDenied
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
