//! A fixed, public-data inference task: three immutable prompts and three
//! permanently reserved generation allowances. No free-form provider payloads.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const INFERENCE_OPERATION: &str = "inference.fixed_completion";
pub const INFERENCE_TASK_OPERATION: &str = "inference.fixed_manifest";
pub const INFERENCE_INPUT_TOKENS: u32 = 512;
pub const INFERENCE_OUTPUT_TOKENS: u32 = 96;
pub const INFERENCE_DEADLINE_SECS: u32 = 30;
pub const INFERENCE_TASK_SLOTS: usize = 3;

pub fn fixed_prompt(id: &str) -> Option<&'static str> {
    match id {
        "receipt_summary" => Some(
            "Summarize this synthetic deployment receipt in two short sentences. Public test data: application=example-app; environment=staging; workflow=artifact-smoke; provider=GitHub; dispatch=accepted; workflow_result=succeeded; service_health=not_observed. Do not infer a deployment or healthy service from a successful artifact smoke test.",
        ),
        "uncertainty_check" => Some(
            "Identify the unresolved fact and one safe next action in this synthetic receipt. Public test data: application=example-app; environment=staging; dispatch=transport_unknown; retry_allowance=0; run_observation=not_available. Answer in two short sentences. Do not recommend redispatching or changing production.",
        ),
        "next_safe_step" => Some(
            "Give one read-only verification step for this synthetic operation and explain its limit. Public test data: application=example-app; immutable_image_digest=verified; artifact_smoke=passed; rollout=not_requested; service_health=not_observed. Answer in two short sentences without commands or URLs.",
        ),
        _ => None,
    }
}

pub fn sha256(value: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(value);
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn prompt_sha256(id: &str) -> Option<String> {
    fixed_prompt(id).map(|prompt| sha256(prompt.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceOptions {
    pub max_input_tokens: u32,
    pub max_output_tokens: u32,
    pub deadline_secs: u32,
    pub temperature: u32,
    pub seed: u32,
    pub cache_prompt: bool,
    pub stream: bool,
}

impl Default for InferenceOptions {
    fn default() -> Self {
        Self {
            max_input_tokens: INFERENCE_INPUT_TOKENS,
            max_output_tokens: INFERENCE_OUTPUT_TOKENS,
            deadline_secs: INFERENCE_DEADLINE_SECS,
            temperature: 0,
            seed: 0,
            cache_prompt: false,
            stream: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceAction {
    pub operation: String,
    pub ordinal: u32,
    /// These bindings are copied from a server-selected trusted profile before
    /// policy evaluation, never used to choose a provider or another tenant.
    pub tenant: crate::tenant::TenantBinding,
    #[serde(default)]
    pub profile_id: String,
    #[serde(default)]
    pub profile_sha256: String,
    #[serde(default)]
    pub model_id: String,
    /// Operator-attested artifact identity; the inference HTTP API cannot
    /// establish the bytes of the served model file.
    #[serde(default)]
    pub model_artifact_sha256: String,
    pub source_id: String,
    pub source_snapshot_sha256: String,
    #[serde(default)]
    pub prompt_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    pub options: InferenceOptions,
}

pub fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

pub fn valid_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:".contains(&b))
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl InferenceAction {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.tenant
            .validate()
            .map_err(|_| "invalid inference tenant")?;
        if let Some(reference) = &self.credential_ref {
            crate::task::validate_github_token_ref(reference)
                .map_err(|_| "invalid inference credential reference")?;
        }
        if self.operation != INFERENCE_OPERATION
            || !(1..=3).contains(&self.ordinal)
            || !valid_label(&self.source_id)
            || !valid_sha256(&self.source_snapshot_sha256)
            || !valid_sha256(&self.prompt_sha256)
            || !valid_label(&self.profile_id)
            || !valid_model_id(&self.model_id)
            || !valid_sha256(&self.profile_sha256)
            || !valid_sha256(&self.model_artifact_sha256)
            || self.options != InferenceOptions::default()
        {
            return Err("invalid fixed inference authority");
        }
        Ok(())
    }
}

pub fn validate_inference_actions(actions: &[&InferenceAction]) -> Result<(), &'static str> {
    if actions.len() != INFERENCE_TASK_SLOTS {
        return Err("inference requires three slots");
    }
    let first = actions[0];
    let mut ordinals = [false; INFERENCE_TASK_SLOTS];
    for action in actions {
        action.validate()?;
        let index = action.ordinal as usize - 1;
        if ordinals[index]
            || action.tenant != first.tenant
            || action.profile_id != first.profile_id
            || action.profile_sha256 != first.profile_sha256
            || action.model_id != first.model_id
            || action.model_artifact_sha256 != first.model_artifact_sha256
            || action.credential_ref != first.credential_ref
            || action.source_id != first.source_id
            || action.source_snapshot_sha256 != first.source_snapshot_sha256
        {
            return Err("inference slots must share one trusted profile");
        }
        ordinals[index] = true;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceReceiptCode {
    CompletionObserved,
    ProviderRejected,
    TransportUnknown,
    ProviderContractViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceReceipt {
    pub tenant: crate::tenant::TenantBinding,
    pub profile_sha256: String,
    pub prompt_sha256: String,
    pub code: InferenceReceiptCode,
    /// Reserved once before dispatch. Observed usage never replenishes it.
    pub reserved_output_tokens: u32,
    pub input_tokens: u32,
    pub observed_output_tokens: Option<u32>,
    pub output_sha256: Option<String>,
    pub output_text: Option<String>,
    pub duration_ms: u64,
    pub completed_at: i64,
}

pub fn valid_output_text(text: &str) -> bool {
    static PATTERNS: std::sync::OnceLock<crate::sanitize::SecretPatterns> =
        std::sync::OnceLock::new();
    text.len() <= 4096 && text.chars().all(|c| {
        (c == '\n' || c == '\t' || !c.is_control())
            && !matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }) && !PATTERNS.get_or_init(crate::sanitize::SecretPatterns::compile).contains_secret(text)
}

impl InferenceReceipt {
    pub fn validate(&self, action: &InferenceAction) -> Result<(), &'static str> {
        action.validate()?;
        if self.tenant != action.tenant
            || self.profile_sha256 != action.profile_sha256
            || self.prompt_sha256 != action.prompt_sha256
            || self.reserved_output_tokens != INFERENCE_OUTPUT_TOKENS
            || !(1..=INFERENCE_INPUT_TOKENS).contains(&self.input_tokens)
            || self.completed_at <= 0
            || self.duration_ms > 31_000
        {
            return Err("invalid inference receipt binding");
        }
        match self.code {
            InferenceReceiptCode::CompletionObserved => {
                if self
                    .observed_output_tokens
                    .is_none_or(|tokens| tokens > INFERENCE_OUTPUT_TOKENS)
                    || !self.output_text.as_deref().is_some_and(valid_output_text)
                    || self
                        .output_text
                        .as_deref()
                        .map(|text| sha256(text.as_bytes()))
                        != self.output_sha256
                {
                    return Err("invalid inference completion evidence");
                }
            }
            _ => {
                if self.observed_output_tokens.is_some()
                    || self.output_sha256.is_some()
                    || self.output_text.is_some()
                {
                    return Err("uncertain inference cannot claim completed output");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(ordinal: u32) -> InferenceAction {
        let prompt_id =
            ["receipt_summary", "uncertainty_check", "next_safe_step"][ordinal as usize - 1];
        InferenceAction {
            operation: INFERENCE_OPERATION.into(), ordinal, tenant: serde_json::from_value(serde_json::json!({"schema_version":1,"tenant_id":"tenant-a","broker_id":"00000000-0000-4000-8000-000000000001"})).unwrap(),
            profile_id: "public-dogfood".into(), profile_sha256: "a".repeat(64),
            model_id: "fixed-model".into(), model_artifact_sha256: "b".repeat(64),
            source_id: "public-demo".into(), source_snapshot_sha256: "c".repeat(64), prompt_sha256: prompt_sha256(prompt_id).unwrap(),
            credential_ref: None, options: InferenceOptions::default(),
        }
    }

    #[test]
    fn three_fixed_prompts_and_budget_are_immutable() {
        let mut actions = [action(1), action(2), action(3)];
        assert!(validate_inference_actions(&actions.iter().collect::<Vec<_>>()).is_ok());
        actions[2].profile_id = "other-profile".into();
        assert!(validate_inference_actions(&actions.iter().collect::<Vec<_>>()).is_err());
        let mut changed = action(1);
        changed.options.max_output_tokens = 97;
        assert!(changed.validate().is_err());
        changed = action(1);
        changed.prompt_sha256 = "malformed".into();
        assert!(changed.validate().is_err());
        changed = action(1);
        changed.ordinal = 4;
        assert!(changed.validate().is_err());
        assert!(validate_inference_actions(&[&action(1), &action(1), &action(3)]).is_err());
    }

    #[test]
    fn receipts_bind_tenant_budget_and_evidence() {
        let action = action(1);
        let mut receipt = InferenceReceipt {
            tenant: action.tenant.clone(),
            profile_sha256: action.profile_sha256.clone(),
            prompt_sha256: action.prompt_sha256.clone(),
            code: InferenceReceiptCode::CompletionObserved,
            reserved_output_tokens: 96,
            input_tokens: 70,
            observed_output_tokens: Some(20),
            output_sha256: Some(sha256(b"public output")),
            output_text: Some("public output".into()),
            duration_ms: 10,
            completed_at: 1,
        };
        assert!(receipt.validate(&action).is_ok());
        receipt.reserved_output_tokens = 20;
        assert!(receipt.validate(&action).is_err());
        receipt.reserved_output_tokens = 96;
        receipt.code = InferenceReceiptCode::TransportUnknown;
        assert!(receipt.validate(&action).is_err());
        receipt.observed_output_tokens = None;
        receipt.output_sha256 = None;
        receipt.output_text = None;
        assert!(receipt.validate(&action).is_ok());
        receipt.profile_sha256 = "f".repeat(64);
        assert!(receipt.validate(&action).is_err());
    }
}
