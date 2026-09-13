//! Bounded public-data inference through one server-selected tenant profile.
//! The caller owns policy, trusted approval, reservation, and slot consumption.

mod client;
mod github_source;
pub use github_source::capture_public_github_ci;

use opaque_core::inference::github::{GithubCiSource, SOURCE_ID as GITHUB_SOURCE_ID};
use opaque_core::inference::{
    INFERENCE_OUTPUT_TOKENS, InferenceAction, InferenceReceipt, InferenceReceiptCode, fixed_prompt,
    prompt_sha256, sha256, valid_label, valid_model_id, valid_output_text, valid_sha256,
};
use opaque_core::task::{SlotOutcome, SlotState, TaskManifest};
use opaque_core::tenant::TenantBinding;
use serde::{Deserialize, Serialize};

use client::{CompletionResult, InferenceClient};
use opaque_core::resolver::SecretResolver;
use opaque_sandbox::resolve::CompositeResolver;

pub const DEMO_SOURCE_ID: &str = "opaque-public-receipts-v1";
static INFERENCE_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn unavailable() -> String {
    "inference profile or provider evidence unavailable".into()
}

pub fn demo_source_snapshot_sha256() -> String {
    sha256(
        &serde_json::to_vec(&[demo_prompt(1), demo_prompt(2), demo_prompt(3)])
            .expect("fixed public prompts"),
    )
}

fn demo_prompt_id(ordinal: u32) -> Option<&'static str> {
    match ordinal {
        1 => Some("receipt_summary"),
        2 => Some("uncertainty_check"),
        3 => Some("next_safe_step"),
        _ => None,
    }
}

pub fn demo_prompt(ordinal: u32) -> Option<&'static str> {
    demo_prompt_id(ordinal).and_then(fixed_prompt)
}

/// Trusted startup configuration, never deserialized from a task request.
/// A profile's service and model artifact identities are operator attestations;
/// the llama.cpp metadata API cannot prove the mounted model/executable bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceProfileConfig {
    pub profile_id: String,
    pub api_url: String,
    pub model_id: String,
    pub model_path: String,
    pub model_artifact_sha256: String,
    pub chat_template_sha256: String,
    pub server_build: String,
    pub service_uid: uuid::Uuid,
    pub source_id: String,
    #[serde(default)]
    pub source_snapshot_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_ci: Option<GithubCiSource>,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default)]
    pub allow_loopback_http: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustedInferenceProfile {
    pub tenant: TenantBinding,
    #[serde(flatten)]
    pub config: InferenceProfileConfig,
}

impl std::ops::Deref for TrustedInferenceProfile {
    type Target = InferenceProfileConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl InferenceProfileConfig {
    pub fn bind(&self, tenant: &TenantBinding) -> Result<TrustedInferenceProfile, String> {
        let profile = TrustedInferenceProfile {
            tenant: tenant.clone(),
            config: self.clone(),
        };
        profile.validate()?;
        Ok(profile)
    }
}

impl TrustedInferenceProfile {
    pub fn validate(&self) -> Result<(), String> {
        self.tenant.validate().map_err(|_| unavailable())?;
        let url = reqwest::Url::parse(&self.api_url).map_err(|_| unavailable())?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
            || !(url.scheme() == "https"
                || url.scheme() == "http" && loopback && self.allow_loopback_http)
            || !valid_label(&self.profile_id)
            || !valid_model_id(&self.model_id)
            || !self.model_path.starts_with('/')
            || self.model_path.len() > 512
            || !self
                .model_path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
            || !valid_label(&self.server_build)
            || self.service_uid.is_nil()
            || !valid_sha256(&self.model_artifact_sha256)
            || self.model_artifact_sha256 == "0".repeat(64)
            || !valid_sha256(&self.chat_template_sha256)
            || match &self.github_ci {
                Some(source) => {
                    source.validate().is_err()
                        || self.source_id != GITHUB_SOURCE_ID
                        || !self.source_snapshot_sha256.is_empty()
                }
                None => {
                    self.source_id != DEMO_SOURCE_ID
                        || self.source_snapshot_sha256 != demo_source_snapshot_sha256()
                }
            }
        {
            return Err(unavailable());
        }
        if let Some(reference) = &self.credential_ref {
            if reference.len() > 128 {
                return Err(unavailable());
            }
            if let Some(body) = reference.strip_prefix("keychain:") {
                if !body
                    .split_once('/')
                    .is_some_and(|(service, account)| !service.is_empty() && !account.is_empty())
                    || opaque_core::validate::InputValidator::validate_secret_ref_names(
                        std::slice::from_ref(reference),
                    )
                    .is_err()
                {
                    return Err(unavailable());
                }
            } else if !reference.starts_with("vault:")
                || opaque_providers::vault::resolve::validate_pinned_ref(reference).is_err()
            {
                return Err(unavailable());
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let mut bytes = b"opaque.inference-profile.v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| unavailable())?);
        Ok(sha256(&bytes))
    }

    fn matches(&self, action: &InferenceAction) -> bool {
        action.validate().is_ok()
            && self.validate().is_ok()
            && action.tenant == self.tenant
            && action.profile_id == self.profile_id
            && self.digest().as_deref() == Ok(action.profile_sha256.as_str())
            && action.model_id == self.model_id
            && action.model_artifact_sha256 == self.model_artifact_sha256
            && action.credential_ref == self.credential_ref
            && action.source_id == self.source_id
            && match (&self.github_ci, &action.github_ci_snapshot) {
                (Some(source), Some(snapshot)) => snapshot.source == *source,
                // This seed is used only for policy preflight before capture.
                // It is never persisted or accepted by the execution path.
                (Some(source), None) => {
                    action.source_snapshot_sha256 == source.digest()
                        && demo_prompt_id(action.ordinal)
                            .and_then(prompt_sha256)
                            .as_deref()
                            == Some(action.prompt_sha256.as_str())
                }
                (None, None) => {
                    action.source_snapshot_sha256 == self.source_snapshot_sha256
                        && demo_prompt_id(action.ordinal)
                            .and_then(prompt_sha256)
                            .as_deref()
                            == Some(action.prompt_sha256.as_str())
                }
                (None, Some(_)) => false,
            }
    }
}

/// Complete reviewed prompt. GitHub source records contain only bounded typed
/// public observations and never arbitrary repository text, logs or instructions.
pub fn action_prompt(
    profile: &TrustedInferenceProfile,
    action: &InferenceAction,
) -> Option<String> {
    if !profile.matches(action) {
        return None;
    }
    match (&profile.github_ci, &action.github_ci_snapshot) {
        (Some(_), Some(snapshot)) => snapshot.prompt(action.ordinal),
        (None, None) => demo_prompt(action.ordinal).map(str::to_owned),
        _ => None,
    }
}

pub fn prepare_inference_manifest(
    manifest: &mut TaskManifest,
    profile: &TrustedInferenceProfile,
) -> Result<(), String> {
    profile.validate()?;
    manifest.validate().map_err(|_| unavailable())?;
    if manifest.schema_version != 3
        || manifest.actions.len() != 3
        || !manifest.actions.iter().all(|action| {
            action
                .as_inference()
                .is_some_and(|action| profile.matches(action))
        })
    {
        return Err(unavailable());
    }
    Ok(())
}

/// The bootstrap RPC accepts only a title and expiry. All authority is made
/// here from the server-selected profile. A GitHub seed needs broker capture
/// before it can be persisted or executed.
pub fn public_demo_manifest(
    profile: &TrustedInferenceProfile,
    title: String,
    expires_in_secs: u64,
) -> Result<TaskManifest, String> {
    profile.validate()?;
    let digest = profile.digest()?;
    let actions = (1..=3)
        .map(|ordinal| {
            opaque_core::task::TaskAction::Inference(InferenceAction {
                operation: opaque_core::inference::INFERENCE_OPERATION.into(),
                ordinal,
                tenant: profile.tenant.clone(),
                profile_id: profile.profile_id.clone(),
                profile_sha256: digest.clone(),
                model_id: profile.model_id.clone(),
                model_artifact_sha256: profile.model_artifact_sha256.clone(),
                source_id: profile.source_id.clone(),
                source_snapshot_sha256: profile.github_ci.as_ref().map_or_else(
                    || profile.source_snapshot_sha256.clone(),
                    GithubCiSource::digest,
                ),
                github_ci_snapshot: None,
                prompt_sha256: demo_prompt_id(ordinal)
                    .and_then(prompt_sha256)
                    .expect("fixed public prompt"),
                credential_ref: profile.credential_ref.clone(),
                options: opaque_core::inference::InferenceOptions::default(),
            })
        })
        .collect();
    let mut manifest = TaskManifest {
        schema_version: 3,
        title,
        expires_in_secs,
        github_api_url: String::new(),
        vault_api_url: String::new(),
        actions,
    };
    prepare_inference_manifest(&mut manifest, profile)?;
    Ok(manifest)
}

fn credential(
    profile: &TrustedInferenceProfile,
) -> Result<Option<opaque_core::secret::SecretValue>, String> {
    profile
        .credential_ref
        .as_deref()
        .map(|reference| {
            let secret = CompositeResolver::new(opaque_providers::default_secret_resolvers())
                .resolve(reference)
                .map_err(|_| unavailable())?;
            secret.mlock();
            if secret.as_str().is_none() {
                return Err(unavailable());
            }
            Ok(secret)
        })
        .transpose()
}

/// Planning captures the configured public source and checks model identity
/// and prompt tokens. Private-source preprocessing is not supported.
pub async fn plan_inference_manifest(
    mut manifest: TaskManifest,
    profile: &TrustedInferenceProfile,
) -> Result<TaskManifest, String> {
    prepare_inference_manifest(&mut manifest, profile)?;
    if let Some(source) = &profile.github_ci {
        if manifest.actions.iter().any(|action| {
            action
                .as_inference()
                .is_some_and(|a| a.github_ci_snapshot.is_some())
        }) {
            return Err("GitHub snapshots must be captured by the broker".into());
        }
        let snapshot = capture_public_github_ci(source).await?;
        attach_github_snapshot(&mut manifest, profile, snapshot)?;
    }
    let client = InferenceClient::new(profile)?;
    let credential = credential(profile)?;
    let token = credential.as_ref().and_then(|secret| secret.as_str());
    client.verify_identity(profile, token).await?;
    for action in &manifest.actions {
        let action = action.as_inference().ok_or_else(unavailable)?;
        client
            .tokenize_prompt(
                &action_prompt(profile, action).ok_or_else(unavailable)?,
                token,
            )
            .await?;
    }
    Ok(manifest)
}

fn attach_github_snapshot(
    manifest: &mut TaskManifest,
    profile: &TrustedInferenceProfile,
    snapshot: opaque_core::inference::github::GithubCiSnapshot,
) -> Result<(), String> {
    snapshot.validate().map_err(|_| unavailable())?;
    if profile.github_ci.as_ref() != Some(&snapshot.source) {
        return Err(unavailable());
    }
    for action in &mut manifest.actions {
        let opaque_core::task::TaskAction::Inference(action) = action else {
            return Err(unavailable());
        };
        action.source_snapshot_sha256 = snapshot.digest();
        action.prompt_sha256 = sha256(
            snapshot
                .prompt(action.ordinal)
                .ok_or_else(unavailable)?
                .as_bytes(),
        );
        action.github_ci_snapshot = Some(snapshot.clone());
    }
    prepare_inference_manifest(manifest, profile)
}

pub struct InferenceExecution {
    pub outcome: SlotOutcome,
    pub receipt: Option<InferenceReceipt>,
}

fn outcome(state: SlotState, code: &str) -> SlotOutcome {
    SlotOutcome {
        state,
        code: code.into(),
        provider_run_id: None,
        ssh_receipt: None,
        inference_receipt: None,
    }
}

fn rejected() -> InferenceExecution {
    InferenceExecution {
        outcome: outcome(SlotState::Rejected, "source_unavailable"),
        receipt: None,
    }
}

/// One native completion after the final caller-owned live authority fence.
/// A client timeout does not prove server cancellation. The caller must stop
/// later slots after uncertainty and never restore the reserved allowance.
pub async fn execute_inference_action<F, Fut>(
    manifest: &TaskManifest,
    action: &InferenceAction,
    profile: &TrustedInferenceProfile,
    before_dispatch: F,
) -> InferenceExecution
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), SlotOutcome>>,
{
    execute_with_deadline(
        manifest,
        action,
        profile,
        std::time::Duration::from_secs(30),
        before_dispatch,
    )
    .await
}

async fn execute_with_deadline<F, Fut>(
    manifest: &TaskManifest,
    action: &InferenceAction,
    profile: &TrustedInferenceProfile,
    deadline: std::time::Duration,
    before_dispatch: F,
) -> InferenceExecution
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), SlotOutcome>>,
{
    if manifest.validate().is_err()
        || !profile.matches(action)
        || !manifest
            .actions
            .iter()
            .any(|candidate| candidate.as_inference() == Some(action))
    {
        return rejected();
    }
    let Some(prompt) = action_prompt(profile, action) else {
        return rejected();
    };
    let _serial = INFERENCE_SERIAL.lock().await;
    let Ok(client) = InferenceClient::new(profile) else {
        return rejected();
    };
    let Ok(credential) = credential(profile) else {
        return rejected();
    };
    let token = credential.as_ref().and_then(|secret| secret.as_str());
    if client.verify_identity(profile, token).await.is_err() {
        return rejected();
    }
    let Ok(tokens) = client.tokenize_prompt(&prompt, token).await else {
        return rejected();
    };
    // Recheck identity after asynchronous template/tokenizer work. This is
    // evidence of the configured server, not atomic remote model immutability.
    if client.verify_identity(profile, token).await.is_err() {
        return rejected();
    }
    if let Err(rejection) = before_dispatch().await {
        return InferenceExecution {
            outcome: if rejection.validate().is_ok() {
                rejection
            } else {
                outcome(SlotState::Rejected, "internal_error")
            },
            receipt: None,
        };
    }
    let started = std::time::Instant::now();
    let completion = tokio::time::timeout(deadline, client.complete(profile, &tokens, token))
        .await
        .unwrap_or(CompletionResult::Unknown);
    let (state, code, receipt_code, output, observed_tokens) = match completion {
        CompletionResult::Observed { output, tokens } if valid_output_text(&output) => (
            SlotState::ApiAccepted,
            "api_accepted",
            InferenceReceiptCode::CompletionObserved,
            Some(output),
            Some(tokens),
        ),
        CompletionResult::Observed { .. } | CompletionResult::ContractViolation => (
            SlotState::Unknown,
            "provider_contract_violation",
            InferenceReceiptCode::ProviderContractViolation,
            None,
            None,
        ),
        CompletionResult::Rejected => (
            SlotState::Rejected,
            "provider_rejected",
            InferenceReceiptCode::ProviderRejected,
            None,
            None,
        ),
        CompletionResult::Unknown => (
            SlotState::Unknown,
            "transport_unknown",
            InferenceReceiptCode::TransportUnknown,
            None,
            None,
        ),
    };
    let receipt = InferenceReceipt {
        tenant: action.tenant.clone(),
        profile_sha256: action.profile_sha256.clone(),
        prompt_sha256: action.prompt_sha256.clone(),
        code: receipt_code,
        reserved_output_tokens: INFERENCE_OUTPUT_TOKENS,
        input_tokens: tokens.len() as u32,
        observed_output_tokens: observed_tokens,
        output_sha256: output.as_deref().map(|value| sha256(value.as_bytes())),
        output_text: output,
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        completed_at: opaque_core::identity::now_unix(),
    };
    let mut outcome = outcome(state, code);
    outcome.inference_receipt = Some(receipt.clone());
    InferenceExecution {
        outcome,
        receipt: Some(receipt),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
