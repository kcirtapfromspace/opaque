//! Immutable authority for one fixed SSH health operation. Private keys, CA
//! material and transport controls belong exclusively to the trusted broker.

use serde::{Deserialize, Serialize};

use crate::identity::PrincipalId;
use crate::inference::{sha256, valid_output_text, valid_sha256};
use crate::tenant::TenantBinding;

pub const SSH_OPERATION: &str = "ssh.service_health";
pub const SSH_TASK_OPERATION: &str = "ssh.health_manifest";
pub const SSH_FIXED_COMMAND: &str = "opaque-service-health";
pub const MAX_SSH_TASK_DURATION_SECS: u64 = 300;
pub const MAX_SSH_SESSION_SECS: u32 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshHealthAction {
    pub operation: String,
    pub tenant: TenantBinding,
    pub subject: PrincipalId,
    pub delegation_id: String,
    pub workload_uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_exe_sha256: Option<String>,
    pub profile_id: String,
    pub profile_sha256: String,
    /// Canonical IP addresses exclude DNS rebinding and SSH option syntax.
    pub destination_host: String,
    pub destination_port: u16,
    /// SHA-256 of the decoded OpenSSH public-key wire blob, in lowercase hex.
    pub host_key_sha256: String,
    pub vault_role: String,
    pub vault_ca_sha256: String,
    pub vault_token_ref: String,
    pub principal: String,
    pub login_user: String,
    pub source_address: String,
    pub command: String,
    pub max_session_secs: u32,
    pub grant_id: String,
}

pub fn valid_ssh_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

pub fn canonical_ip(value: &str) -> bool {
    value
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.to_string() == value && !ip.is_unspecified() && !ip.is_multicast())
}

pub fn canonical_grant_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

impl SshHealthAction {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.tenant.validate().map_err(|_| "invalid SSH tenant")?;
        crate::task::validate_github_token_ref(&self.vault_token_ref)
            .map_err(|_| "invalid Vault signer credential reference")?;
        if self.operation != SSH_OPERATION
            || !valid_ssh_label(&self.profile_id)
            || !valid_sha256(&self.profile_sha256)
            || !valid_sha256(&self.host_key_sha256)
            || !valid_sha256(&self.vault_ca_sha256)
            || !valid_ssh_label(&self.vault_role)
            || !canonical_ip(&self.destination_host)
            || self.destination_port == 0
            || !canonical_ip(&self.source_address)
            || !valid_ssh_label(&self.principal)
            || !valid_ssh_label(&self.login_user)
            || self.login_user == "root"
            || self.command != SSH_FIXED_COMMAND
            || !(1..=MAX_SSH_SESSION_SECS).contains(&self.max_session_secs)
            || !canonical_grant_id(&self.grant_id)
            || self.workload_uid == u32::MAX
            || self
                .workload_exe_sha256
                .as_ref()
                .is_some_and(|hash| !valid_sha256(hash))
            || self.delegation_id.is_empty()
            || self.delegation_id.len() > 128
            || !self
                .delegation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err("invalid fixed SSH authority");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshReceiptCode {
    HealthObserved,
    Denied,
    TimedOut,
    Expired,
    Revoked,
}

/// Authenticated host evidence, recorded only after the trusted broker verifies
/// the host signature. The signed wire envelope stays in private operator state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshReceipt {
    pub tenant: TenantBinding,
    pub profile_sha256: String,
    pub grant_id: String,
    pub host_key_sha256: String,
    pub code: SshReceiptCode,
    pub host: String,
    pub principal: String,
    pub operation: String,
    pub started_at: i64,
    pub completed_at: i64,
    pub output_sha256: Option<String>,
    pub output_text: Option<String>,
    pub signed_receipt_sha256: String,
}

impl SshReceipt {
    pub fn validate(&self, action: &SshHealthAction) -> Result<(), &'static str> {
        action.validate()?;
        if self.tenant != action.tenant
            || self.profile_sha256 != action.profile_sha256
            || self.grant_id != action.grant_id
            || self.host_key_sha256 != action.host_key_sha256
            || self.host != action.destination_host
            || self.principal != action.principal
            || self.operation != SSH_OPERATION
            || !valid_sha256(&self.signed_receipt_sha256)
            || self.started_at <= 0
            || self.completed_at < self.started_at
            || self.completed_at - self.started_at > i64::from(action.max_session_secs) + 1
        {
            return Err("invalid SSH receipt binding");
        }
        if self.code == SshReceiptCode::HealthObserved {
            if !self.output_text.as_deref().is_some_and(valid_output_text)
                || self
                    .output_text
                    .as_deref()
                    .map(|text| sha256(text.as_bytes()))
                    != self.output_sha256
            {
                return Err("invalid SSH health evidence");
            }
        } else if self.output_text.is_some() || self.output_sha256.is_some() {
            return Err("incomplete SSH operation cannot claim health evidence");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{TaskAction, TaskManifest};

    pub(crate) fn action() -> SshHealthAction {
        SshHealthAction {
            operation: SSH_OPERATION.into(), tenant: serde_json::from_value(serde_json::json!({"schema_version":1,"tenant_id":"tenant-a","broker_id":"00000000-0000-4000-8000-000000000001"})).unwrap(),
            subject: PrincipalId::parse("hum_00000000000000000000000000000001").unwrap(),
            delegation_id: "session-1".into(), workload_uid: 1000, workload_exe_sha256: None,
            profile_id: "fixture-health".into(), profile_sha256: "a".repeat(64),
            destination_host: "192.0.2.1".into(), destination_port: 22,
            host_key_sha256: "b".repeat(64), vault_role: "fixture-health".into(), vault_ca_sha256: "e".repeat(64), vault_token_ref: "env:VAULT_SIGNER_TOKEN".into(), principal: "fixture-health".into(), login_user: "opaque".into(),
            source_address: "192.0.2.2".into(), command: SSH_FIXED_COMMAND.into(), max_session_secs: 30,
            grant_id: "00000000-0000-4000-8000-000000000002".into(),
        }
    }

    fn manifest() -> TaskManifest {
        TaskManifest {
            schema_version: 4,
            title: "Check fixture service".into(),
            expires_in_secs: 300,
            github_api_url: String::new(),
            vault_api_url: String::new(),
            actions: vec![action().into()],
        }
    }

    #[test]
    fn fixed_ssh_schema_rejects_general_shell_authority_and_ambiguous_destinations() {
        let valid = action();
        valid.validate().unwrap();
        for (field, value) in [
            ("operation", "ssh.exec"),
            ("command", "opaque-service-health; id"),
            ("principal", "*"),
            ("login_user", "root"),
            ("login_user", "-oProxyCommand=id"),
            ("destination_host", "fixture.example.com"),
            ("destination_host", "192.0.2.01"),
            ("destination_host", "0.0.0.0"),
            ("destination_host", "ff02::1"),
            ("source_address", "192.0.2.0/24"),
            ("grant_id", "00000000000040008000000000000002"),
            ("grant_id", "00000000-0000-0000-0000-000000000000"),
            ("host_key_sha256", "SHA256:unbound"),
            ("profile_id", "../../other"),
            ("delegation_id", "session\nforged"),
        ] {
            let mut data = serde_json::to_value(&valid).unwrap();
            data[field] = value.into();
            assert!(
                serde_json::from_value::<SshHealthAction>(data)
                    .unwrap()
                    .validate()
                    .is_err(),
                "accepted {field}={value}"
            );
        }
        for field in [
            "argv",
            "url",
            "environment",
            "private_key",
            "ca_key",
            "forwarding",
            "pty",
            "shell",
        ] {
            let mut data = serde_json::to_value(&valid).unwrap();
            data[field] = "unreviewed".into();
            assert!(
                serde_json::from_value::<TaskAction>(data).is_err(),
                "accepted {field}"
            );
        }
        for seconds in [0, 31, u32::MAX] {
            let mut action = valid.clone();
            action.max_session_secs = seconds;
            assert!(action.validate().is_err());
        }
    }

    #[test]
    fn ssh_is_one_slot_five_minutes_and_domain_separated() {
        let valid = manifest();
        valid.validate().unwrap();
        assert_eq!(valid.operation_name(), SSH_TASK_OPERATION);
        for schema in [1, 2, 3, 5] {
            let mut changed = valid.clone();
            changed.schema_version = schema;
            assert!(changed.validate().is_err());
        }
        for seconds in [0, 301, 3600] {
            let mut changed = valid.clone();
            changed.expires_in_secs = seconds;
            assert!(changed.validate().is_err());
        }
        let mut changed = valid.clone();
        changed.actions.push(action().into());
        assert!(changed.validate().is_err());
        changed = valid.clone();
        changed.github_api_url = "https://api.github.com".into();
        assert!(changed.validate().is_err());
        for field in [
            "grant_id",
            "subject",
            "delegation_id",
            "profile_sha256",
            "destination_host",
            "host_key_sha256",
            "principal",
            "source_address",
        ] {
            let mut data = serde_json::to_value(&valid).unwrap();
            data["actions"][0][field] = match field {
                "grant_id" => "00000000-0000-4000-8000-000000000003".into(),
                "subject" => "hum_00000000000000000000000000000002".into(),
                "destination_host" | "source_address" => "192.0.2.3".into(),
                "profile_sha256" | "host_key_sha256" => "c".repeat(64).into(),
                _ => "other-binding".into(),
            };
            let changed: TaskManifest = serde_json::from_value(data).unwrap();
            assert_ne!(
                valid.digest().unwrap(),
                changed.digest().unwrap(),
                "unbound {field}"
            );
        }
    }

    #[test]
    fn authenticated_health_receipt_requires_exact_authority_and_complete_hashed_output() {
        let action = action();
        let receipt = SshReceipt {
            tenant: action.tenant.clone(),
            profile_sha256: action.profile_sha256.clone(),
            grant_id: action.grant_id.clone(),
            host_key_sha256: action.host_key_sha256.clone(),
            code: SshReceiptCode::HealthObserved,
            host: action.destination_host.clone(),
            principal: action.principal.clone(),
            operation: SSH_OPERATION.into(),
            started_at: 100,
            completed_at: 101,
            output_sha256: Some(sha256(b"healthy")),
            output_text: Some("healthy".into()),
            signed_receipt_sha256: "d".repeat(64),
        };
        receipt.validate(&action).unwrap();
        let mut changed = receipt.clone();
        changed.grant_id = uuid::Uuid::new_v4().to_string();
        assert!(changed.validate(&action).is_err());
        changed = receipt.clone();
        changed.output_text = Some("unhealthy".into());
        assert!(changed.validate(&action).is_err());
        changed = receipt.clone();
        changed.code = SshReceiptCode::TimedOut;
        assert!(changed.validate(&action).is_err());
        changed.output_text = None;
        changed.output_sha256 = None;
        changed.validate(&action).unwrap();
        changed.completed_at = 132;
        assert!(changed.validate(&action).is_err());
    }

    #[test]
    fn ssh_success_requires_authenticated_evidence_and_does_not_change_legacy_outcomes() {
        use crate::task::{SlotOutcome, SlotState};
        let old = r#"{"state":"unknown","code":"transport_unknown"}"#;
        let outcome: SlotOutcome = serde_json::from_str(old).unwrap();
        assert_eq!(serde_json::to_string(&outcome).unwrap(), old);
        let action: TaskAction = action().into();
        outcome.validate_for_action(&action).unwrap();
        let forged_success = SlotOutcome {
            state: SlotState::ApiAccepted,
            code: "api_accepted".into(),
            provider_run_id: None,
            inference_receipt: None,
            ssh_receipt: None,
        };
        assert!(forged_success.validate_for_action(&action).is_err());
    }

    #[test]
    fn ssh_record_and_sanitizer_bind_host_evidence_to_the_reserved_slot_and_tenant() {
        use crate::task::{
            SlotOutcome, SlotState, TaskApprovalMode, TaskRecord, TaskSlot, TaskState,
        };
        let manifest = manifest();
        let action = manifest.actions[0].as_ssh().unwrap();
        let receipt = SshReceipt {
            tenant: action.tenant.clone(),
            profile_sha256: action.profile_sha256.clone(),
            grant_id: action.grant_id.clone(),
            host_key_sha256: action.host_key_sha256.clone(),
            code: SshReceiptCode::HealthObserved,
            host: action.destination_host.clone(),
            principal: action.principal.clone(),
            operation: SSH_OPERATION.into(),
            started_at: 101,
            completed_at: 102,
            output_sha256: Some(sha256(b"healthy")),
            output_text: Some("healthy".into()),
            signed_receipt_sha256: "d".repeat(64),
        };
        let mut record = TaskRecord {
            id: uuid::Uuid::new_v4().to_string(),
            manifest_digest: manifest.digest().unwrap(),
            owner_key: action
                .tenant
                .owner_key(action.workload_uid, Some(&action.subject)),
            tenant: Some(action.tenant.clone()),
            created_at: 100,
            expires_at: 400,
            approved_at: Some(101),
            approval_mode: Some(TaskApprovalMode::Native),
            workstation_receipt: None,
            state: TaskState::Completed,
            slots: vec![TaskSlot {
                id: "slot-1".into(),
                action: manifest.actions[0].clone(),
                state: SlotState::ApiAccepted,
                request_id: Some("request-1".into()),
                reserved_at: Some(101),
                finished_at: Some(102),
                outcome: Some(SlotOutcome {
                    state: SlotState::ApiAccepted,
                    code: "api_accepted".into(),
                    provider_run_id: None,
                    inference_receipt: None,
                    ssh_receipt: Some(receipt.clone()),
                }),
            }],
            manifest,
            release_observation: None,
        };
        let sanitizer = crate::sanitize::Sanitizer::new();
        let encoded = sanitizer.sanitize_task_record(&record).unwrap();
        assert_eq!(
            encoded["slots"][0]["outcome"]["ssh_receipt"],
            serde_json::to_value(receipt).unwrap()
        );
        record.slots[0].reserved_at = Some(102);
        assert!(sanitizer.sanitize_task_record(&record).is_err());
        record.slots[0].reserved_at = Some(101);
        let owner = record.owner_key.clone();
        record.owner_key = record.tenant.as_ref().unwrap().owner_key(501, None);
        assert!(sanitizer.sanitize_task_record(&record).is_err());
        record.owner_key = owner;
        record.approved_at = None;
        assert!(sanitizer.sanitize_task_record(&record).is_err());
        record.approved_at = Some(101);
        record.tenant = None;
        assert!(sanitizer.sanitize_task_record(&record).is_err());
    }
}
