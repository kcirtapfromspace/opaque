//! Review presentation and acknowledgment recovery never create new authority.
use crate::{
    client::BrokerClient,
    custody::{BrokerEnrollment, WorkstationState},
};
use opaque_core::workstation::{
    SignedWorkstationReceipt, WorkstationDecision, WorkstationResponse, WorkstationReview,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ReviewContext {
    pub broker_id: String,
    pub approval_id: String,
    pub request_id: String,
    pub operation: String,
    pub expires_at: i64,
    pub tenant: Option<String>,
    pub requester: Option<String>,
    pub reviewer: Option<String>,
    pub required_role: Option<String>,
    pub content_hash: String,
}

impl From<&WorkstationReview> for ReviewContext {
    fn from(review: &WorkstationReview) -> Self {
        let c = &review.challenge;
        let a = c.authority.as_ref();
        Self {
            broker_id: c.broker_id.clone(),
            approval_id: c.approval_id.clone(),
            request_id: c.request_id.clone(),
            operation: c.operation.clone(),
            expires_at: c.expires_at,
            tenant: a.map(|a| a.binding.tenant.tenant_id.to_string()),
            requester: a.map(|a| a.binding.requester.clone()),
            reviewer: a.map(|a| a.principal_id.clone()),
            required_role: a.map(|a| a.required_role.clone()),
            content_hash: c.content_hash.clone(),
        }
    }
}

/// Typed, broker-bound context precedes every byte of the immutable document.
/// Targets and allowances remain in that document; do not guess them from prose.
pub fn display(review: &WorkstationReview, now: i64) -> String {
    let c = &review.challenge;
    let mut text = format!(
        "OPAQUE / EXACT TASK REVIEW\n\nOperation: {}\nTrusted broker: {}\nApproval: {}\nRequest: {}\nExpires in: {} seconds (Unix {})\n",
        c.operation,
        c.broker_id,
        c.approval_id,
        c.request_id,
        c.expires_at.saturating_sub(now).max(0),
        c.expires_at
    );
    if let Some(a) = &c.authority {
        text.push_str(&format!("Tenant: {}\nRequester: {}\nReviewer: {}\nRequired role: {}\nAuthority epoch: {}\nTask: {}\nBroker lineage: {}\nManifest SHA256: {}\nPolicy SHA256: {}\n", a.binding.tenant.tenant_id, a.binding.requester, a.principal_id, a.required_role, a.authority_epoch, a.binding.task_id, a.binding.tenant.broker_id, a.binding.manifest_digest, a.binding.policy_digest));
    }
    text.push_str(&format!("Review content SHA256: {}\n\nCheck every target, argument and allowance in the complete document below. A decision permits only its bound authority; it does not establish execution success. Expiry requires a fresh request and review.\n\n----- COMPLETE IMMUTABLE REVIEW -----\n{}", c.content_hash, review.review_text));
    text
}

pub fn validate_receipt(
    receipt: &SignedWorkstationReceipt,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    id: &str,
) -> Result<(), String> {
    receipt.verify().map_err(|_| "invalid signed receipt")?;
    if receipt.review.challenge.approval_id != id
        || receipt.review.challenge.broker_id != enrollment.broker_id
        || receipt.response.device_id != enrollment.device_id
        || receipt
            .review
            .challenge
            .authority
            .as_ref()
            .is_none_or(|a| a.public_key_hex != state.public_key_hex)
    {
        return Err("receipt belongs to another enrollment".into());
    }
    Ok(())
}

pub async fn receipt(
    client: &BrokerClient,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    id: &str,
) -> Result<SignedWorkstationReceipt, String> {
    let receipt = client
        .request(
            reqwest::Method::GET,
            &format!("/workstation/receipts/{id}"),
            None,
            Some((&enrollment.device_id, &enrollment.token)),
        )
        .await?;
    validate_receipt(&receipt, enrollment, state, id)?;
    Ok(receipt)
}

#[derive(Debug, Serialize)]
pub struct DecisionReport {
    pub schema_version: u32,
    pub approval_id: String,
    pub broker_id: String,
    pub decision: WorkstationDecision,
    pub decision_status: &'static str,
    pub execution_status: &'static str,
    pub recovered_via_receipt: bool,
    pub message: &'static str,
}

/// Exactly one POST. A missing acknowledgment triggers only a GET for the
/// same signed decision; neither this function nor the launcher retries work.
pub async fn submit(
    client: &BrokerClient,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    review: &WorkstationReview,
    response: WorkstationResponse,
) -> Result<DecisionReport, String> {
    let id = &review.challenge.approval_id;
    let accepted = client
        .request::<serde_json::Value>(
            reqwest::Method::POST,
            &format!("/workstation/approvals/{id}/respond"),
            Some(serde_json::to_value(&response).map_err(|_| "decision encoding failed")?),
            Some((&enrollment.device_id, &enrollment.token)),
        )
        .await
        .is_ok();
    let recovered = if accepted {
        false
    } else {
        receipt(client, enrollment, state, id)
            .await
            .is_ok_and(|r| r.review == *review && r.response == response)
    };
    Ok(DecisionReport {
        schema_version: 1,
        approval_id: id.clone(),
        broker_id: enrollment.broker_id.clone(),
        decision: response.decision,
        decision_status: if accepted || recovered {
            "accepted"
        } else {
            "unknown"
        },
        execution_status: "not_observed",
        recovered_via_receipt: recovered,
        message: if accepted || recovered {
            "Decision accepted. Execution outcome is not established by this receipt."
        } else {
            "Decision acknowledgment unknown. Use read-only receipt lookup; do not retry the operation."
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::workstation::{WorkstationChallenge, review_hash};

    #[test]
    fn context_precedes_complete_unchanged_bytes_and_does_not_invent_scope() {
        let body = "Destination: exact\nAllowance: 1\n  KEEP whitespace\n";
        let review = WorkstationReview {
            challenge: WorkstationChallenge {
                schema_version: 1,
                authority: None,
                broker_id: "opq-test".into(),
                approval_id: "id".into(),
                request_id: "request".into(),
                operation: "github.release_manifest".into(),
                content_hash: review_hash(body),
                nonce: "aa".repeat(32),
                created_at: 100,
                expires_at: 120,
            },
            review_text: body.into(),
        };
        let display = display(&review, 110);
        assert!(display.ends_with(body));
        assert!(
            display.find("Trusted broker").unwrap() < display.find("COMPLETE IMMUTABLE").unwrap()
        );
        assert!(display.contains("Expires in: 10 seconds"));
        let context = ReviewContext::from(&review);
        assert!(context.tenant.is_none());
        assert_eq!(context.content_hash, review_hash(body));
    }
}
