//! Trusted presentation profile and early feedback. These word-based guards
//! grant no authority; authenticated aggregate-only MCP remains the boundary.
use serde::{Deserialize, Serialize};

pub const CREDIT_METRICS: [&str; 3] = [
    "credit_applications_per_minute",
    "manual_review_rate_percent",
    "identity_mismatch_rate_percent",
];
pub const CREDIT_POLICY_ID: &str = "portfolio-analyst-v1";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Experience {
    #[default]
    OperationalMetrics,
    CreditPortfolio,
}

pub struct CreditDenial {
    pub reason_code: &'static str,
    pub message: &'static str,
}

pub fn credit_request_denial(message: &str) -> Option<CreditDenial> {
    let lower = message.to_ascii_lowercase();
    let words: Vec<_> = lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .collect();
    let has = |values: &[&str]| words.iter().any(|word| values.contains(word));
    let phrase = |left: &str, right: &str| words.windows(2).any(|p| p == [left, right]);
    let (reason_code, message) = if has(&["ssn", "ssns", "borrower", "borrowers"])
        || phrase("social", "security")
        || phrase("raw", "records")
        || phrase("application", "records")
        || phrase("application", "rows")
    {
        (
            "raw_records_denied",
            "Borrower records and SSNs are outside this demo's aggregate-only access. Ask for application rate, manual review rate, or identity mismatch rate.",
        )
    } else if has(&["other", "another", "all"])
        && has(&[
            "lender",
            "lenders",
            "customer",
            "customers",
            "tenant",
            "tenants",
            "union",
            "unions",
        ])
    {
        (
            "customer_scope_denied",
            "This session can read only your credit union's synthetic portfolio aggregates. Another lender's data is outside its customer scope.",
        )
    } else if has(&[
        "credential",
        "credentials",
        "password",
        "passwords",
        "secret",
        "secrets",
        "token",
        "tokens",
        "bearer",
    ]) || phrase("api", "key")
        || phrase("private", "key")
    {
        (
            "credentials_denied",
            "Source credentials stay with the gateway and cannot be retrieved through this read-only portfolio tool.",
        )
    } else if (words.windows(2).any(|pair| {
        ["change", "update"].contains(&pair[0])
            && [
                "loan",
                "loans",
                "application",
                "applications",
                "record",
                "records",
            ]
            .contains(&pair[1])
    })) || has(&["approve", "deny", "reject", "write", "delete", "modify"])
        && has(&[
            "loan",
            "loans",
            "application",
            "applications",
            "decision",
            "decisions",
            "record",
            "records",
        ])
    {
        (
            "mutation_denied",
            "This portfolio analyst session can read aggregate metrics; it cannot approve, deny, or change loan applications.",
        )
    } else if has(&["average_credit_score"])
        || phrase("credit", "score")
        || phrase("credit", "scores")
    {
        (
            "metric_scope_denied",
            "Average credit score is outside this session's allowed metric scope. Application rate, manual review rate, and identity mismatch rate are available.",
        )
    } else {
        return None;
    };
    Some(CreditDenial {
        reason_code,
        message,
    })
}
