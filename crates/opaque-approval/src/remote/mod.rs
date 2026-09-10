//! Collaboration delivery carries an opaque reference only. Authorization is
//! still a full review on a separately enrolled workstation.
mod slack;
pub mod store;

use crate::pairing::PairingManager;
use crate::pairing::store::PairedDevice;
use opaque_core::tenant::TenantBinding;
use opaque_core::workstation::{
    ApprovalBinding, SignedWorkstationReceipt, WorkstationAuthority, WorkstationResponse,
    WorkstationReview,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use store::RemoteStore;

/// Current enabled human, admission and required role, yielding an authority
/// epoch that changes on removal/regrant. The daemon owns this resolver.
pub type ReviewerResolver = Arc<dyn Fn(&str, &str) -> Result<u64, String> + Send + Sync>;
pub type ReviewerAuthorityGuard = Arc<
    dyn Fn(
            Option<&opaque_core::identity::PrincipalContext>,
            &str,
            &str,
            u64,
            &mut dyn FnMut() -> Result<(), String>,
        ) -> Result<(), String>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalConfig {
    pub reviewer_public_key_hex: String,
    pub required_role: String,
    #[serde(default)]
    pub slack: Option<SlackConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlackConfig {
    pub channel_id: String,
    pub token_file: PathBuf,
    /// Production is fixed to Slack. The optional fixture endpoint must be a
    /// literal loopback HTTP address, never a production credential destination.
    #[serde(default)]
    pub fixture_endpoint: Option<String>,
}

pub struct RemoteApprovals {
    config: RemoteApprovalConfig,
    tenant: TenantBinding,
    pairing: Arc<PairingManager>,
    resolver: ReviewerResolver,
    authority_guard: ReviewerAuthorityGuard,
    pub store: Arc<RemoteStore>,
    slack: Option<slack::SlackTransport>,
}

impl std::fmt::Debug for RemoteApprovals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteApprovals")
            .field("notifications_enabled", &self.slack.is_some())
            .finish()
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl RemoteApprovals {
    pub fn open(
        config: RemoteApprovalConfig,
        path: &Path,
        tenant: TenantBinding,
        pairing: Arc<PairingManager>,
        resolver: ReviewerResolver,
        authority_guard: ReviewerAuthorityGuard,
    ) -> Result<Arc<Self>, String> {
        opaque_core::workstation::decode_hex::<32>(&config.reviewer_public_key_hex)
            .map_err(|_| "invalid remote reviewer key")?;
        config
            .required_role
            .parse::<opaque_core::identity::Role>()
            .map_err(|_| "invalid remote reviewer role")?;
        let slack = config
            .slack
            .clone()
            .map(slack::SlackTransport::new)
            .transpose()?;
        let store = Arc::new(RemoteStore::open(
            path,
            tenant.clone(),
            pairing.server_id().into(),
        )?);
        let remote = Arc::new(Self {
            config,
            tenant,
            pairing,
            resolver,
            authority_guard,
            store,
            slack,
        });
        // Enrollment may not yet have completed its transport-token exchange.
        // Principal mapping must already be explicit in trusted configuration.
        remote.configured_device()?;
        Ok(remote)
    }

    fn configured_device(&self) -> Result<PairedDevice, String> {
        let device = self
            .pairing
            .list_devices()
            .map_err(|_| "reviewer enrollment unavailable")?
            .into_iter()
            .find(|device| device.public_key_hex == self.config.reviewer_public_key_hex)
            .ok_or("configured remote reviewer is not enrolled")?;
        let device = self
            .pairing
            .workstation_device(&device.device_id)
            .map_err(|_| "remote reviewer device is revoked")?;
        if device.paired_by.is_none() {
            return Err("remote reviewer requires a named human principal".into());
        }
        Ok(device)
    }

    pub fn bind(
        &self,
        review: &mut WorkstationReview,
        binding: ApprovalBinding,
    ) -> Result<(), String> {
        self.tenant
            .require_same(&binding.tenant)
            .map_err(|_| "wrong approval tenant")?;
        let device = self.configured_device()?;
        let principal_id = device
            .paired_by
            .ok_or("reviewer has no current human mapping")?;
        let epoch = (self.resolver)(&principal_id, &self.config.required_role)?;
        review.challenge.schema_version = 2;
        review.challenge.authority = Some(WorkstationAuthority {
            binding,
            principal_id,
            public_key_hex: device.public_key_hex,
            required_role: self.config.required_role.clone(),
            authority_epoch: epoch,
        });
        review
            .validate(self.pairing.server_id(), now())
            .map_err(|_| "invalid bound remote review")?;
        Ok(())
    }

    pub fn enqueue(&self, review: &WorkstationReview) -> Result<(), String> {
        self.check_current(review, None)?;
        self.store.enqueue(review, now(), self.slack.is_some())
    }

    pub(crate) fn check_current(
        &self,
        review: &WorkstationReview,
        device: Option<&PairedDevice>,
    ) -> Result<(), String> {
        review
            .validate(self.pairing.server_id(), now())
            .map_err(|_| "remote approval expired or invalid")?;
        let authority = review
            .challenge
            .authority
            .as_ref()
            .ok_or("remote approval lacks authority")?;
        self.tenant
            .require_same(&authority.binding.tenant)
            .map_err(|_| "remote approval tenant changed")?;
        let current = self.configured_device()?;
        if current.public_key_hex != authority.public_key_hex
            || current.paired_by.as_deref() != Some(authority.principal_id.as_str())
            || authority.required_role != self.config.required_role
            || device.is_some_and(|device| device.device_id != current.device_id)
            || (self.resolver)(&authority.principal_id, &authority.required_role)?
                != authority.authority_epoch
        {
            return Err("remote reviewer authority changed".into());
        }
        Ok(())
    }

    /// Historical receipts remain evidence after challenge expiry. Reading
    /// them still requires the same enrolled device and a currently eligible
    /// human; a restored role does not revive the old decision as authority.
    pub(crate) fn can_read_receipt(
        &self,
        receipt: &SignedWorkstationReceipt,
        device_id: &str,
    ) -> Result<(), String> {
        let authority = receipt
            .review
            .challenge
            .authority
            .as_ref()
            .ok_or("missing receipt authority")?;
        let current = self.configured_device()?;
        if current.device_id != device_id
            || receipt.response.device_id != device_id
            || current.public_key_hex != authority.public_key_hex
            || current.paired_by.as_deref() != Some(authority.principal_id.as_str())
            || authority.required_role != self.config.required_role
        {
            return Err("receipt belongs to another reviewer".into());
        }
        (self.resolver)(&authority.principal_id, &authority.required_role)?;
        Ok(())
    }

    pub fn accept(
        &self,
        review: &WorkstationReview,
        response: WorkstationResponse,
        device: &PairedDevice,
    ) -> Result<SignedWorkstationReceipt, String> {
        self.check_current(review, Some(device))?;
        if response.device_id != device.device_id {
            return Err("wrong reviewer device".into());
        }
        let receipt = SignedWorkstationReceipt {
            schema_version: 1,
            review: review.clone(),
            response,
            accepted_at: now(),
        };
        // Signature independently verified again before durable acceptance.
        receipt
            .verify()
            .map_err(|_| "invalid signed remote decision")?;
        self.with_authority(None, &receipt, &mut || self.store.accept(&receipt))?;
        Ok(receipt)
    }

    fn with_authority(
        &self,
        requester: Option<&opaque_core::identity::PrincipalContext>,
        receipt: &SignedWorkstationReceipt,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let authority = receipt
            .review
            .challenge
            .authority
            .as_ref()
            .ok_or("remote authority missing")?;
        self.pairing
            .with_workstation_authority(&receipt.response.device_id, &mut |device| {
                if device.public_key_hex != authority.public_key_hex
                    || device.public_key_hex != self.config.reviewer_public_key_hex
                    || device.paired_by.as_deref() != Some(&authority.principal_id)
                    || authority.required_role != self.config.required_role
                {
                    return Err("remote reviewer enrollment changed".into());
                }
                (self.authority_guard)(
                    requester,
                    &authority.principal_id,
                    &authority.required_role,
                    authority.authority_epoch,
                    &mut || {
                        // The identity/key guards remain held through the irreversible
                        // ledger transition. Time is checked after acquiring them.
                        receipt
                            .review
                            .validate(self.pairing.server_id(), now())
                            .map_err(|_| "remote review expired")?;
                        self.tenant
                            .require_same(&authority.binding.tenant)
                            .map_err(|_| "wrong remote tenant")?;
                        authorize()
                    },
                )
            })
    }

    pub fn authorize(
        &self,
        requester: Option<&opaque_core::identity::PrincipalContext>,
        receipt: &SignedWorkstationReceipt,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.revalidate(receipt)?;
        let authority = receipt
            .review
            .challenge
            .authority
            .as_ref()
            .ok_or("missing remote authority")?;
        if requester.is_none_or(|requester| requester.sub.as_str() != authority.binding.requester) {
            return Err("remote dispatch requires the reviewed requester".into());
        }
        self.with_authority(requester, receipt, authorize)
    }

    pub fn revalidate(&self, receipt: &SignedWorkstationReceipt) -> Result<(), String> {
        if receipt.response.decision != opaque_core::workstation::WorkstationDecision::Approve {
            return Err("remote decision did not approve execution".into());
        }
        receipt.verify().map_err(|_| "invalid remote receipt")?;
        self.check_current(&receipt.review, None)?;
        if self
            .store
            .receipt(&receipt.review.challenge.approval_id)?
            .as_ref()
            != Some(receipt)
        {
            return Err("remote decision is not durably accepted".into());
        }
        let current = self.configured_device()?;
        if current.device_id != receipt.response.device_id {
            return Err("remote reviewer enrollment changed".into());
        }
        Ok(())
    }

    /// A delivery failure is never an approval. Notifications alone may retry;
    /// the durable decision and task dispatch remain single consumption.
    pub async fn deliver_one(&self) -> Result<bool, String> {
        let Some(slack) = &self.slack else {
            return Ok(false);
        };
        let Some(notice) = self.store.claim_notice(now())? else {
            return Ok(false);
        };
        if !self.store.notice_active(&notice, now())? {
            return Ok(true);
        }
        let delivered = slack.send(&notice).await.is_ok();
        self.store.finish_notice(&notice, delivered, now())?;
        Ok(true)
    }

    pub async fn run_notifications(self: Arc<Self>) {
        if self.slack.is_none() {
            return;
        }
        loop {
            match self.deliver_one().await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => tracing::warn!("remote approval notification ledger unavailable"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests;
