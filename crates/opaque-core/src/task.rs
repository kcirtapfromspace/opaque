//! Immutable manifests and receipts for bounded broker operations.
//!
//! These types describe authority, never secret values. A manifest is approved
//! as a whole, while each action owns exactly one permanently charged slot.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TASK_SCHEMA_VERSION: u32 = 1;
pub const MAX_TASK_ACTIONS: usize = 32;
pub const MAX_TASK_DURATION_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskManifest {
    pub schema_version: u32,
    pub title: String,
    pub expires_in_secs: u64,
    /// Bound by the daemon at planning time, then compared at execution.
    #[serde(default)]
    pub github_api_url: String,
    #[serde(default)]
    pub vault_api_url: String,
    pub actions: Vec<TaskAction>,
}

/// V1 secret actions retain their exact wire representation. V2 release
/// actions carry an explicit operation and cannot be mixed with V1 actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TaskAction {
    PublishSecret(PublishAction),
    StagingRelease(crate::release::StagingReleaseAction),
    Inference(crate::inference::InferenceAction),
}

impl From<PublishAction> for TaskAction {
    fn from(action: PublishAction) -> Self {
        Self::PublishSecret(action)
    }
}

impl From<crate::release::StagingReleaseAction> for TaskAction {
    fn from(action: crate::release::StagingReleaseAction) -> Self {
        Self::StagingRelease(action)
    }
}

impl TaskAction {
    pub fn as_inference(&self) -> Option<&crate::inference::InferenceAction> {
        match self {
            Self::Inference(action) => Some(action),
            _ => None,
        }
    }
    pub fn as_inference_mut(&mut self) -> Option<&mut crate::inference::InferenceAction> {
        match self {
            Self::Inference(action) => Some(action),
            _ => None,
        }
    }
    pub fn as_publish(&self) -> Option<&PublishAction> {
        match self {
            Self::PublishSecret(action) => Some(action),
            _ => None,
        }
    }
    pub fn as_publish_mut(&mut self) -> Option<&mut PublishAction> {
        match self {
            Self::PublishSecret(action) => Some(action),
            _ => None,
        }
    }
    pub fn as_release(&self) -> Option<&crate::release::StagingReleaseAction> {
        match self {
            Self::StagingRelease(action) => Some(action),
            _ => None,
        }
    }
    pub fn as_release_mut(&mut self) -> Option<&mut crate::release::StagingReleaseAction> {
        match self {
            Self::StagingRelease(action) => Some(action),
            _ => None,
        }
    }
    pub fn repo(&self) -> &str {
        match self {
            Self::PublishSecret(a) => &a.repo,
            Self::StagingRelease(a) => &a.repo,
            Self::Inference(_) => "",
        }
    }
    pub fn repository_id(&self) -> u64 {
        match self {
            Self::PublishSecret(a) => a.repository_id,
            Self::StagingRelease(a) => a.repository_id,
            Self::Inference(_) => 0,
        }
    }
    pub fn github_token_ref(&self) -> Option<&str> {
        match self {
            Self::PublishSecret(a) => a.github_token_ref.as_deref(),
            Self::StagingRelease(a) => a.github_token_ref.as_deref(),
            Self::Inference(_) => None,
        }
    }
    pub fn secret_refs(&self) -> Vec<String> {
        let mut refs = self
            .github_token_ref()
            .map(str::to_owned)
            .into_iter()
            .collect::<Vec<_>>();
        if let Self::PublishSecret(a) = self {
            refs.push(a.value_ref.clone());
        }
        if let Self::Inference(a) = self
            && let Some(reference) = &a.credential_ref
        {
            refs.push(reference.clone());
        }
        refs
    }
    fn sort_key(&self) -> (String, String) {
        (
            self.repo().to_ascii_lowercase(),
            match self {
                Self::PublishSecret(a) => a.secret_name.clone(),
                Self::StagingRelease(a) => a.workflow_path.clone(),
                Self::Inference(a) => format!("{:02}", a.ordinal),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishAction {
    pub repo: String,
    /// GitHub's stable numeric identity, resolved by the daemon before review.
    #[serde(default)]
    pub repository_id: u64,
    pub secret_name: String,
    /// Only an explicit Vault KV v2 version is accepted for this first workflow.
    pub value_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_token_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Planned,
    /// Claimed by one broker execution; `approved_at` records the trusted gate.
    Running,
    Completed,
    Partial,
    Revoked,
    Expired,
}

/// Approval provenance recorded by the trusted broker when the gate succeeds.
/// This belongs to the receipt, independent of a later daemon configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskApprovalMode {
    Native,
    PairedWorkstation,
    InsecureTest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotState {
    Pending,
    Reserved,
    /// GitHub accepted the write; the secret value cannot be read back.
    ApiAccepted,
    Rejected,
    /// A write may have happened. This slot must never be reused.
    Unknown,
}

impl SlotState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::ApiAccepted | Self::Rejected | Self::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotOutcome {
    pub state: SlotState,
    /// A bounded, broker-generated code. Raw provider errors are never stored.
    pub code: String,
    /// Direct GitHub run identity when returned by a staging dispatch. Older
    /// API acceptance responses may lack it; this never authorizes a retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_run_id: Option<u64>,
    /// Provider evidence for a fixed inference slot; never refunds allowance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference_receipt: Option<crate::inference::InferenceReceipt>,
}

impl SlotOutcome {
    pub fn validate(&self) -> Result<(), TaskValidationError> {
        if self
            .provider_run_id
            .is_some_and(|id| id == 0 || self.state != SlotState::ApiAccepted)
        {
            return Err(TaskValidationError::InvalidOutcome);
        }
        let allowed = match self.state {
            SlotState::ApiAccepted => self.code == "api_accepted",
            SlotState::Rejected => matches!(
                self.code.as_str(),
                "provider_rejected"
                    | "source_unavailable"
                    | "policy_denied"
                    | "approval_denied"
                    | "internal_error"
                    | "revoked"
                    | "expired"
            ),
            SlotState::Unknown => matches!(
                self.code.as_str(),
                "transport_unknown"
                    | "interrupted"
                    | "internal_error"
                    | "provider_contract_violation"
            ),
            _ => false,
        };
        if !allowed {
            return Err(TaskValidationError::InvalidOutcome);
        }
        if let Some(receipt) = &self.inference_receipt {
            use crate::inference::InferenceReceiptCode as Code;
            let expected = match receipt.code {
                Code::CompletionObserved => (SlotState::ApiAccepted, "api_accepted"),
                Code::ProviderRejected => (SlotState::Rejected, "provider_rejected"),
                Code::TransportUnknown => (SlotState::Unknown, "transport_unknown"),
                Code::ProviderContractViolation => {
                    (SlotState::Unknown, "provider_contract_violation")
                }
            };
            if self.provider_run_id.is_some() || (self.state, self.code.as_str()) != expected {
                return Err(TaskValidationError::InvalidOutcome);
            }
        }
        Ok(())
    }

    pub fn validate_for_action(&self, action: &TaskAction) -> Result<(), TaskValidationError> {
        self.validate()?;
        match (action.as_inference(), &self.inference_receipt) {
            (Some(action), Some(receipt)) => receipt
                .validate(action)
                .map_err(|_| TaskValidationError::Inference),
            (None, Some(_)) => Err(TaskValidationError::Inference),
            (Some(_), None) if self.state == SlotState::ApiAccepted => {
                Err(TaskValidationError::Inference)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSlot {
    pub id: String,
    pub action: TaskAction,
    pub state: SlotState,
    pub request_id: Option<String>,
    pub reserved_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub outcome: Option<SlotOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    pub id: String,
    pub manifest_digest: String,
    pub manifest: TaskManifest,
    /// Broker-derived durable owner binding, never a resettable agent ID.
    pub owner_key: String,
    /// Trusted runtime custody binding, absent only on legacy local tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<crate::tenant::TenantBinding>,
    pub created_at: i64,
    pub expires_at: i64,
    pub approved_at: Option<i64>,
    /// Absent on legacy receipts whose approval provenance is unavailable.
    #[serde(default)]
    pub approval_mode: Option<TaskApprovalMode>,
    pub state: TaskState,
    pub slots: Vec<TaskSlot>,
    /// Read-only provider evidence, independent of the consumed dispatch slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_observation: Option<crate::release::ReleaseObservation>,
}

impl TaskRecord {
    pub fn validate_tenant_and_inference_receipts(&self) -> Result<(), TaskValidationError> {
        if let Some(tenant) = &self.tenant {
            tenant.validate().map_err(|_| TaskValidationError::Tenant)?;
            let prefix = format!(
                "tenant:{}:broker:{}:uid:",
                tenant.tenant_id, tenant.broker_id
            );
            if !self.owner_key.starts_with(&prefix) {
                return Err(TaskValidationError::Tenant);
            }
        }
        for action in &self.manifest.actions {
            if let Some(action) = action.as_inference()
                && self.tenant.as_ref() != Some(&action.tenant)
            {
                return Err(TaskValidationError::Tenant);
            }
        }
        for slot in &self.slots {
            if let Some(outcome) = &slot.outcome {
                outcome.validate_for_action(&slot.action)?;
                if let Some(receipt) = &outcome.inference_receipt
                    && (slot.finished_at.is_none_or(|at| receipt.completed_at > at)
                        || slot.reserved_at.is_none_or(|at| receipt.completed_at < at))
                {
                    return Err(TaskValidationError::Inference);
                }
            }
        }
        Ok(())
    }
    pub fn validate_release_observation(&self) -> Result<(), TaskValidationError> {
        for slot in &self.slots {
            if slot
                .outcome
                .as_ref()
                .is_some_and(|outcome| outcome.provider_run_id.is_some())
                && (!self.manifest.is_release() || slot.action.as_release().is_none())
            {
                return Err(TaskValidationError::Release);
            }
        }
        if let Some(observation) = &self.release_observation {
            let action = self
                .manifest
                .actions
                .first()
                .and_then(TaskAction::as_release)
                .ok_or(TaskValidationError::Release)?;
            if !self.manifest.is_release()
                || self.slots.len() != 1
                || !matches!(
                    self.slots[0].state,
                    SlotState::ApiAccepted | SlotState::Unknown
                )
                || self.slots[0].reserved_at.is_none()
                || self.approved_at.is_none()
                || observation.checked_at < self.created_at
            {
                return Err(TaskValidationError::Release);
            }
            observation
                .validate(action, &self.manifest.github_api_url)
                .map_err(|_| TaskValidationError::Release)?;
            if let Some(expected) = self.slots[0]
                .outcome
                .as_ref()
                .and_then(|outcome| outcome.provider_run_id)
                && observation
                    .run_id
                    .is_some_and(|observed| observed != expected)
            {
                return Err(TaskValidationError::Release);
            }
            let has_direct_id = self.slots[0]
                .outcome
                .as_ref()
                .and_then(|outcome| outcome.provider_run_id)
                .is_some();
            if has_direct_id
                != (observation.correlation == crate::release::ReleaseCorrelation::DispatchResponse)
            {
                return Err(TaskValidationError::Release);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedVaultRef<'a> {
    pub path: &'a str,
    pub version: u64,
    pub field: &'a str,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TaskValidationError {
    #[error(
        "task schema_version must be 1 (secret publishing), 2 (one staging release), or 3 (three fixed inference requests)"
    )]
    SchemaVersion,
    #[error("invalid fixed inference scope or evidence")]
    Inference,
    #[error("task tenant and broker binding does not match its authority")]
    Tenant,
    #[error("invalid staging release scope")]
    Release,
    #[error("task title must be 1–160 printable ASCII characters without secret values")]
    Title,
    #[error("task expires_in_secs must be between 1 and 3600")]
    Duration,
    #[error("task must contain between 1 and 32 actions")]
    ActionCount,
    #[error("repository must be an exact GitHub owner/repository name")]
    Repository,
    #[error("repository_id must be resolved to a positive GitHub repository identity")]
    RepositoryId,
    #[error("provider API URLs must be exact HTTPS endpoints (HTTP is allowed only on loopback)")]
    ProviderUrl,
    #[error("secret_name must be an uppercase GitHub secret name and must not start with GITHUB_")]
    SecretName,
    #[error("each repository/secret_name pair may occur only once")]
    DuplicateAction,
    #[error(
        "value_ref must be a pinned Vault KV v2 reference: vault:mount/data/path?version=1#FIELD"
    )]
    PinnedSource,
    #[error("github_token_ref must be a supported secret reference, never a literal credential")]
    TokenRef,
    #[error("slot outcome must use a terminal state and an approved receipt code")]
    InvalidOutcome,
}

impl TaskManifest {
    pub fn validate(&self) -> Result<(), TaskValidationError> {
        if !matches!(self.schema_version, TASK_SCHEMA_VERSION | 2 | 3) {
            return Err(TaskValidationError::SchemaVersion);
        }
        if self.title.is_empty()
            || self.title.len() > 160
            || self.title.trim() != self.title
            || !self.title.bytes().all(|b| (b' '..=b'~').contains(&b))
            || secret_patterns().contains_secret(&self.title)
        {
            return Err(TaskValidationError::Title);
        }
        if !(1..=MAX_TASK_DURATION_SECS).contains(&self.expires_in_secs) {
            return Err(TaskValidationError::Duration);
        }
        if self.actions.is_empty() || self.actions.len() > MAX_TASK_ACTIONS {
            return Err(TaskValidationError::ActionCount);
        }
        if self.is_inference() {
            if !self.github_api_url.is_empty()
                || !self.vault_api_url.is_empty()
                || self.expires_in_secs > 600
            {
                return Err(TaskValidationError::Inference);
            }
            let actions = self
                .actions
                .iter()
                .map(TaskAction::as_inference)
                .collect::<Option<Vec<_>>>()
                .ok_or(TaskValidationError::Inference)?;
            crate::inference::validate_inference_actions(&actions)
                .map_err(|_| TaskValidationError::Inference)?;
            return Ok(());
        }
        validate_provider_url(&self.github_api_url)?;
        if self.is_release() {
            if !self.vault_api_url.is_empty() || self.actions.len() != 1 {
                return Err(TaskValidationError::Release);
            }
            self.actions[0]
                .as_release()
                .ok_or(TaskValidationError::Release)?
                .validate()
                .map_err(|_| TaskValidationError::Release)?;
            return Ok(());
        }
        validate_provider_url(&self.vault_api_url)?;
        let mut pairs = HashSet::new();
        let mut identity_pairs = HashSet::new();
        for action in &self.actions {
            let action = action
                .as_publish()
                .ok_or(TaskValidationError::SchemaVersion)?;
            action.validate()?;
            // GitHub repository identity is case-insensitive. Retain spelling
            // in the approved manifest but never mint duplicate authority.
            if !pairs.insert((action.repo.to_ascii_lowercase(), action.secret_name.clone()))
                || !identity_pairs.insert((action.repository_id, action.secret_name.clone()))
            {
                return Err(TaskValidationError::DuplicateAction);
            }
        }
        Ok(())
    }

    pub fn canonicalized(&self) -> Result<Self, TaskValidationError> {
        self.validate()?;
        let mut manifest = self.clone();
        manifest.actions.sort_by_key(TaskAction::sort_key);
        Ok(manifest)
    }

    /// Domain-separated SHA-256 of a deterministic JSON representation.
    pub fn digest(&self) -> Result<String, TaskValidationError> {
        let canonical = self.canonicalized()?;
        let bytes = serde_json::to_vec(&canonical).expect("manifest contains serializable fields");
        let mut hash = Sha256::new();
        hash.update(if self.is_inference() {
            b"opaque.fixed-inference-manifest.v3\0".as_slice()
        } else if self.is_release() {
            b"opaque.github-staging-release.v2\0".as_slice()
        } else {
            b"opaque.github-publish-manifest.v1\0".as_slice()
        });
        hash.update(bytes);
        Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }

    pub fn is_release(&self) -> bool {
        self.schema_version == 2
    }

    pub fn is_inference(&self) -> bool {
        self.schema_version == 3
    }

    pub fn operation_name(&self) -> &'static str {
        if self.is_inference() {
            crate::inference::INFERENCE_TASK_OPERATION
        } else if self.is_release() {
            "github.release_manifest"
        } else {
            "github.publish_manifest"
        }
    }
}

impl PublishAction {
    pub fn validate(&self) -> Result<(), TaskValidationError> {
        let (owner, repo) = self
            .repo
            .split_once('/')
            .ok_or(TaskValidationError::Repository)?;
        if owner.is_empty()
            || owner.len() > 39
            || owner.starts_with('-')
            || owner.ends_with('-')
            || !owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || repo.is_empty()
            || repo.len() > 100
            || matches!(repo, "." | "..")
            || !repo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(TaskValidationError::Repository);
        }
        if self.repository_id == 0 {
            return Err(TaskValidationError::RepositoryId);
        }
        if self.secret_name.is_empty()
            || self.secret_name.len() > 100
            || self.secret_name.as_bytes()[0].is_ascii_digit()
            || self.secret_name.starts_with("GITHUB_")
            || !self
                .secret_name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(TaskValidationError::SecretName);
        }
        parse_pinned_vault_ref(&self.value_ref)?;
        if let Some(reference) = &self.github_token_ref {
            validate_github_token_ref(reference)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_github_token_ref(reference: &str) -> Result<(), TaskValidationError> {
    // Credentials follow the existing 128-byte reference limit,
    // including Vault credentials. This also bounds a full 32-slot
    // receipt below one IPC/list page after actions are repeated.
    if reference.len() > 128 {
        return Err(TaskValidationError::TokenRef);
    }
    if reference.starts_with("vault:") {
        parse_pinned_vault_ref(reference).map_err(|_| TaskValidationError::TokenRef)?;
    } else {
        let body = crate::profile::ALLOWED_REF_SCHEMES
            .iter()
            .find_map(|scheme| reference.strip_prefix(scheme))
            .ok_or(TaskValidationError::TokenRef)?;
        if reference.len() > 128
            || body.is_empty()
            || !body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
            || secret_patterns().contains_secret(body)
        {
            return Err(TaskValidationError::TokenRef);
        }
    }
    Ok(())
}

fn secret_patterns() -> &'static crate::sanitize::SecretPatterns {
    static PATTERNS: std::sync::OnceLock<crate::sanitize::SecretPatterns> =
        std::sync::OnceLock::new();
    PATTERNS.get_or_init(crate::sanitize::SecretPatterns::compile)
}

fn validate_provider_url(url: &str) -> Result<(), TaskValidationError> {
    let invalid = || TaskValidationError::ProviderUrl;
    if url.len() > 2048 {
        return Err(invalid());
    }
    let (scheme, rest) = url.split_once("://").ok_or_else(invalid)?;
    if !matches!(scheme, "https" | "http") || rest.is_empty() {
        return Err(invalid());
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (address, remainder) = bracketed.split_once(']').ok_or_else(invalid)?;
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid());
        }
        let port = if remainder.is_empty() {
            None
        } else {
            Some(remainder.strip_prefix(':').ok_or_else(invalid)?)
        };
        (address, port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(invalid());
        }
        (host, port)
    };
    if let Some(port) = port
        && (port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|port| *port > 0).is_none())
    {
        return Err(invalid());
    }
    if scheme == "http" && !matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Err(invalid());
    }
    if path.split('/').any(|part| {
        matches!(part, "." | "..")
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
    }) {
        return Err(invalid());
    }
    Ok(())
}

/// Accept a deliberately narrow, unambiguous KV v2 URI grammar. Percent
/// escapes, extra query parameters, traversal, wildcards, and implicit latest
/// versions are rejected before provider access or an approval prompt.
pub fn parse_pinned_vault_ref(reference: &str) -> Result<PinnedVaultRef<'_>, TaskValidationError> {
    let invalid = || TaskValidationError::PinnedSource;
    if reference.len() > 768 {
        return Err(invalid());
    }
    let body = reference.strip_prefix("vault:").ok_or_else(invalid)?;
    let (path_query, field) = body.split_once('#').ok_or_else(invalid)?;
    let (path, version) = path_query.split_once("?version=").ok_or_else(invalid)?;
    if path.len() > 512
        || field.is_empty()
        || field.len() > 128
        || field.as_bytes()[0].is_ascii_digit()
        || !field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        || version.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() < 3
        || parts[1] != "data"
        || parts.iter().any(|part| {
            part.is_empty()
                || matches!(*part, "." | "..")
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
    {
        return Err(invalid());
    }
    let version = version.parse::<u64>().map_err(|_| invalid())?;
    // Vault's version is a positive signed integer.
    if version > i64::MAX as u64 {
        return Err(invalid());
    }
    Ok(PinnedVaultRef {
        path,
        version,
        field,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_v1_manifest_keeps_its_original_approval_digest() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/task-manifest-v1.json")).unwrap();
        let manifest: TaskManifest = serde_json::from_value(fixture["manifest"].clone()).unwrap();
        assert_eq!(
            manifest.digest().unwrap(),
            fixture["manifest_digest"].as_str().unwrap()
        );
        assert!(
            manifest
                .actions
                .iter()
                .all(|action| action.as_publish().is_some())
        );
        assert!(
            !serde_json::to_value(manifest).unwrap()["actions"][0]
                .as_object()
                .unwrap()
                .contains_key("operation")
        );
    }

    #[test]
    fn release_schema_is_one_typed_action_and_digest_binds_its_authority() {
        let value = serde_json::json!({
            "schema_version":2,"title":"Staging artifact","expires_in_secs":600,
            "github_api_url":"https://api.github.com", "actions":[{
                "operation":"github.dispatch_staging_workflow", "repo":"owner/app", "repository_id":42,
                "workflow_path":".github/workflows/staging.yml", "workflow_id":7,"workflow_ref":"main",
                "approved_commit_sha":"a".repeat(40),"workflow_sha256":"b".repeat(64),
                "image_repository":"ghcr.io/owner/app","image_digest":format!("sha256:{}","c".repeat(64)),
                "environment":"staging","github_token_ref":"keychain:opaque/github-pat"
            }]
        });
        let original: TaskManifest = serde_json::from_value(value).unwrap();
        let digest = original.digest().unwrap();
        let mut changed = original.clone();
        changed.actions[0].as_release_mut().unwrap().image_digest =
            format!("sha256:{}", "d".repeat(64));
        assert_ne!(changed.digest().unwrap(), digest);
        changed = original.clone();
        changed.actions.push(changed.actions[0].clone());
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.actions = manifest().actions;
        assert!(changed.validate().is_err());
        changed = original;
        changed.schema_version = 1;
        assert!(changed.validate().is_err());
    }

    fn manifest() -> TaskManifest {
        TaskManifest {
            schema_version: 1,
            title: "Publish dogfood configuration".into(),
            expires_in_secs: 600,
            github_api_url: "https://api.github.com".into(),
            vault_api_url: "https://vault.example.com".into(),
            actions: vec![
                PublishAction {
                    repo: "thinkstudio/opaque".into(),
                    repository_id: 101,
                    secret_name: "DOGFOOD_MARKER".into(),
                    value_ref: "vault:kv/data/demo?version=7#MARKER".into(),
                    github_token_ref: Some("keychain:opaque/github-pat".into()),
                }
                .into(),
            ],
        }
    }

    #[test]
    fn canonical_digest_is_order_independent_and_binds_every_authority_field() {
        let mut first = manifest();
        let mut second_action = first.actions[0].as_publish().unwrap().clone();
        second_action.repo = "thinkstudio/adanima.ai".into();
        second_action.repository_id = 102;
        first.actions.push(second_action.into());
        let mut reversed = first.clone();
        reversed.actions.reverse();
        assert_eq!(first.digest().unwrap(), reversed.digest().unwrap());
        let original = first.digest().unwrap();
        let changes: [fn(&mut TaskManifest); 9] = [
            |m| m.title = "Another review".into(),
            |m| m.expires_in_secs = 601,
            |m| m.actions[0].as_publish_mut().unwrap().repo = "thinkstudio/another".into(),
            |m| m.actions[0].as_publish_mut().unwrap().secret_name = "ANOTHER".into(),
            |m| {
                m.actions[0].as_publish_mut().unwrap().value_ref =
                    "vault:kv/data/demo?version=8#MARKER".into()
            },
            |m| {
                m.actions[0].as_publish_mut().unwrap().github_token_ref =
                    Some("keychain:opaque/other-pat".into())
            },
            |m| m.actions[0].as_publish_mut().unwrap().repository_id = 103,
            |m| m.github_api_url = "https://github.example.com/api/v3".into(),
            |m| m.vault_api_url = "https://vault.other.example.com".into(),
        ];
        for change in changes {
            let mut altered = first.clone();
            change(&mut altered);
            assert_ne!(original, altered.digest().unwrap());
        }
    }

    #[test]
    fn rejects_duplicate_case_insensitive_destinations_and_invalid_bounds() {
        let mut m = manifest();
        let mut duplicate = m.actions[0].as_publish().unwrap().clone();
        duplicate.repo = "ThinkStudio/Opaque".into();
        m.actions.push(duplicate.into());
        assert_eq!(m.validate(), Err(TaskValidationError::DuplicateAction));
        for duration in [0, 3601, u64::MAX] {
            let mut m = manifest();
            m.expires_in_secs = duration;
            assert_eq!(m.validate(), Err(TaskValidationError::Duration));
        }
        let mut m = manifest();
        m.actions.clear();
        assert_eq!(m.validate(), Err(TaskValidationError::ActionCount));
        m.actions = vec![manifest().actions[0].clone(); 33];
        assert_eq!(m.validate(), Err(TaskValidationError::ActionCount));
    }

    #[test]
    fn pinned_reference_rejects_ambiguous_or_mutable_sources() {
        let parsed = parse_pinned_vault_ref("vault:kv/data/demo?version=7#FIELD").unwrap();
        assert_eq!(parsed.path, "kv/data/demo");
        assert_eq!(parsed.version, 7);
        assert_eq!(parsed.field, "FIELD");
        for reference in [
            "env:MARKER",
            "vault:kv/data/demo#FIELD",
            "vault:kv/demo?version=7#FIELD",
            "vault:kv/data/demo?version=0#FIELD",
            "vault:kv/data/demo?version=07#FIELD",
            "vault:kv/data/demo?version=-1#FIELD",
            "vault:kv/data/demo?version=+1#FIELD",
            "vault:kv/data/demo?version=7&x=1#FIELD",
            "vault:kv/data/demo?version=7#FIELD#OTHER",
            "vault:kv/data/demo?version=7#",
            "vault:kv/data//demo?version=7#FIELD",
            "vault:kv/data/../demo?version=7#FIELD",
            "vault:kv/data/%2e%2e/demo?version=7#FIELD",
            "vault:kv/data/*?version=7#FIELD",
            "vault:kv/data/demo?version=9223372036854775808#FIELD",
            "vault:/kv/data/demo?version=7#FIELD",
            "vault:kv/data/demo?version=7#F\nIELD",
        ] {
            assert!(
                parse_pinned_vault_ref(reference).is_err(),
                "accepted {reference}"
            );
        }
    }

    #[test]
    fn rejects_scope_tricks_and_prompt_injection() {
        for repo in [
            "*/*",
            "owner/repo/other",
            "owner/..",
            "owner/%2f",
            "-owner/repo",
            "o/r\nApprove all",
        ] {
            let mut m = manifest();
            m.actions[0].as_publish_mut().unwrap().repo = repo.into();
            assert_eq!(m.validate(), Err(TaskValidationError::Repository));
        }
        for name in ["", "lowercase", "1FIRST", "GITHUB_TOKEN", "A/B", "A\nB"] {
            let mut m = manifest();
            m.actions[0].as_publish_mut().unwrap().secret_name = name.into();
            assert_eq!(m.validate(), Err(TaskValidationError::SecretName));
        }
        for title in [
            "",
            " leading",
            "line\nbreak",
            "Approve\u{202e}everything",
            "secret ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        ] {
            let mut m = manifest();
            m.title = title.into();
            assert_eq!(m.validate(), Err(TaskValidationError::Title));
        }
        let mut m = manifest();
        m.actions[0].as_publish_mut().unwrap().github_token_ref =
            Some("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".into());
        assert_eq!(m.validate(), Err(TaskValidationError::TokenRef));
    }

    #[test]
    fn cannot_deserialize_authority_extensions_or_literal_secret_values() {
        let mut value = serde_json::to_value(manifest()).unwrap();
        value["approved"] = true.into();
        assert!(serde_json::from_value::<TaskManifest>(value).is_err());
        let mut value = serde_json::to_value(manifest()).unwrap();
        value["actions"][0]["value"] = "plaintext".into();
        assert!(serde_json::from_value::<TaskManifest>(value).is_err());
    }

    #[test]
    fn receipt_codes_cannot_contain_raw_provider_data() {
        assert!(
            SlotOutcome {
                provider_run_id: None,
                inference_receipt: None,
                state: SlotState::Unknown,
                code: "transport_unknown".into()
            }
            .validate()
            .is_ok()
        );
        for (state, code) in [
            (SlotState::Reserved, "api_accepted"),
            (SlotState::Unknown, "api_accepted"),
            (SlotState::Rejected, "token ghp_not-for-receipts"),
        ] {
            assert!(
                SlotOutcome {
                    provider_run_id: None,
                    inference_receipt: None,
                    state,
                    code: code.into()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn pinned_credential_references_share_the_128_byte_limit() {
        let mut manifest = manifest();
        let prefix = "vault:kv/data/";
        let suffix = "?version=7#TOKEN";
        manifest.actions[0]
            .as_publish_mut()
            .unwrap()
            .github_token_ref = Some(format!(
            "{prefix}{}{suffix}",
            "p".repeat(128 - prefix.len() - suffix.len())
        ));
        assert!(manifest.validate().is_ok());
        manifest.actions[0]
            .as_publish_mut()
            .unwrap()
            .github_token_ref = Some(format!(
            "{prefix}{}{suffix}",
            "p".repeat(129 - prefix.len() - suffix.len())
        ));
        assert_eq!(manifest.validate(), Err(TaskValidationError::TokenRef));
    }

    #[test]
    fn provider_urls_require_unambiguous_authorities() {
        for url in [
            "https://api.github.com",
            "https://ghe.example/api/v3",
            "http://127.0.0.1:5678",
            "http://[::1]:8000",
            "http://localhost:1234/",
            "https://[2001:db8::1]:443",
        ] {
            assert!(validate_provider_url(url).is_ok(), "rejected {url}");
        }
        for url in [
            "",
            "http://vault.example.com",
            "https://user:pass@example.com",
            "https://x.example?token=x",
            "https://x.example/#fragment",
            "https://x.example/../other",
            "https://x.example/%2fother",
            "https://x.example:0",
            "https://x.example:65536",
            "https://x.example\\@other",
            "https://bad..example",
        ] {
            assert!(validate_provider_url(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn typed_receipt_sanitizer_preserves_verified_authority_and_scrubs_free_metadata() {
        let manifest = manifest();
        let action = manifest.actions[0].clone();
        let record = TaskRecord {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            manifest_digest: manifest.digest().unwrap(),
            manifest,
            owner_key: "owner:ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".into(),
            tenant: None,
            created_at: 100,
            expires_at: 700,
            approved_at: None,
            approval_mode: None,
            state: TaskState::Planned,
            release_observation: None,
            slots: vec![TaskSlot {
                id: "550e8400-e29b-41d4-a716-446655440000:01".into(),
                action,
                state: SlotState::Pending,
                request_id: None,
                reserved_at: None,
                finished_at: None,
                outcome: None,
            }],
        };
        let sanitizer = crate::sanitize::Sanitizer::new();
        let public = sanitizer.sanitize_task_record(&record).unwrap();
        assert_eq!(public["manifest_digest"], record.manifest_digest);
        assert_eq!(
            public["manifest"]["actions"][0]["value_ref"],
            record.manifest.actions[0].as_publish().unwrap().value_ref
        );
        assert_eq!(
            public["slots"][0]["action"]["github_token_ref"],
            "keychain:opaque/github-pat"
        );
        assert!(
            !public
                .to_string()
                .contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        );

        let mut invalid = record.clone();
        invalid.manifest_digest = "0".repeat(64);
        assert!(sanitizer.sanitize_task_record(&invalid).is_err());
        let mut invalid = record.clone();
        invalid.slots[0].action.as_publish_mut().unwrap().repo = "another/target".into();
        assert!(sanitizer.sanitize_task_record(&invalid).is_err());
        let mut invalid = record.clone();
        invalid.slots[0].outcome = Some(SlotOutcome {
            provider_run_id: None,
            inference_receipt: None,
            state: SlotState::Unknown,
            code: "raw provider token".into(),
        });
        assert!(sanitizer.sanitize_task_record(&invalid).is_err());
        let mut invalid = record;
        invalid.manifest.title = "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".into();
        assert!(sanitizer.sanitize_task_record(&invalid).is_err());
    }

    fn inference_manifest() -> TaskManifest {
        let tenant = crate::tenant::TenantBinding::new(
            crate::tenant::TenantId::parse("tenant-a").unwrap(),
            uuid::Uuid::new_v4(),
        )
        .unwrap();
        serde_json::from_value(serde_json::json!({
            "schema_version": 3, "title": "Three public inference requests",
            "expires_in_secs": 600, "github_api_url": "", "vault_api_url": "",
            "actions": (1..=3).map(|ordinal| serde_json::json!({
                "operation": crate::inference::INFERENCE_OPERATION, "ordinal": ordinal,
                "tenant": tenant, "profile_id": "public-demo", "profile_sha256": "a".repeat(64),
                "model_id": "fixed-model", "model_artifact_sha256": "b".repeat(64),
                "source_id": "public-data", "source_snapshot_sha256": "c".repeat(64),
                "prompt_sha256": "d".repeat(64), "options": crate::inference::InferenceOptions::default()
            })).collect::<Vec<_>>()
        })).unwrap()
    }

    #[test]
    fn inference_schema_has_exact_slots_duration_and_independent_digest_domain() {
        let manifest = inference_manifest();
        manifest.validate().unwrap();
        let digest = manifest.digest().unwrap();
        let mut reordered = manifest.clone();
        reordered.actions.reverse();
        assert_eq!(digest, reordered.digest().unwrap());
        let mut hash = Sha256::new();
        hash.update(b"opaque.fixed-inference-manifest.v3\0");
        hash.update(serde_json::to_vec(&manifest.canonicalized().unwrap()).unwrap());
        assert_eq!(
            digest,
            hash.finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        for changed in [
            {
                let mut m = manifest.clone();
                m.actions.pop();
                m
            },
            {
                let mut m = manifest.clone();
                m.actions.push(m.actions[0].clone());
                m
            },
            {
                let mut m = manifest.clone();
                m.actions[2] = m.actions[0].clone();
                m
            },
            {
                let mut m = manifest.clone();
                m.expires_in_secs = 601;
                m
            },
            {
                let mut m = manifest.clone();
                m.github_api_url = "https://api.github.com".into();
                m
            },
            {
                let mut m = manifest.clone();
                m.vault_api_url = "https://vault.example".into();
                m
            },
            {
                let mut m = manifest.clone();
                m.schema_version = 1;
                m
            },
        ] {
            assert!(changed.validate().is_err());
        }
        let mut changed = manifest.clone();
        changed.actions[0] = super::tests::manifest().actions[0].clone();
        assert!(changed.validate().is_err());
        for change in 0..3 {
            let mut changed = manifest.clone();
            for action in &mut changed.actions {
                let action = action.as_inference_mut().unwrap();
                match change {
                    0 => {
                        action.tenant.tenant_id =
                            crate::tenant::TenantId::parse("tenant-b").unwrap()
                    }
                    1 => action.tenant.broker_id = uuid::Uuid::nil(),
                    _ => action.credential_ref = Some("keychain:opaque/other-provider".into()),
                }
            }
            if change == 1 {
                assert!(changed.validate().is_err());
            } else {
                assert_ne!(changed.digest().unwrap(), digest);
            }
        }
    }

    #[test]
    fn inference_outcomes_require_matching_evidence_and_permanent_reservation() {
        use crate::inference::{InferenceReceipt, InferenceReceiptCode as Code};
        let manifest = inference_manifest();
        let action = &manifest.actions[0];
        let inference = action.as_inference().unwrap();
        let receipt = InferenceReceipt {
            tenant: inference.tenant.clone(),
            profile_sha256: inference.profile_sha256.clone(),
            prompt_sha256: inference.prompt_sha256.clone(),
            code: Code::CompletionObserved,
            reserved_output_tokens: 96,
            input_tokens: 50,
            observed_output_tokens: Some(4),
            output_sha256: Some(crate::inference::sha256(b"Public output.")),
            output_text: Some("Public output.".into()),
            duration_ms: 10,
            completed_at: 101,
        };
        let valid = SlotOutcome {
            state: SlotState::ApiAccepted,
            code: "api_accepted".into(),
            provider_run_id: None,
            inference_receipt: Some(receipt),
        };
        valid.validate_for_action(action).unwrap();
        let mut changed = valid.clone();
        changed.inference_receipt = None;
        assert!(changed.validate_for_action(action).is_err());
        assert!(
            valid
                .validate_for_action(&super::tests::manifest().actions[0])
                .is_err()
        );
        let mut changed = valid.clone();
        changed.inference_receipt.as_mut().unwrap().tenant.broker_id = uuid::Uuid::new_v4();
        assert!(changed.validate_for_action(action).is_err());
        let mut changed = valid.clone();
        changed
            .inference_receipt
            .as_mut()
            .unwrap()
            .reserved_output_tokens = 4;
        assert!(changed.validate_for_action(action).is_err());
        let mut changed = valid.clone();
        changed.inference_receipt.as_mut().unwrap().code = Code::TransportUnknown;
        assert!(changed.validate_for_action(action).is_err());
        let mut changed = valid;
        changed.provider_run_id = Some(1);
        assert!(changed.validate_for_action(action).is_err());
    }
}
