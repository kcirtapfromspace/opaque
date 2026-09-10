//! Provider-neutral broker reporting contracts and bounded reporter transport.
//!
//! The v1 wire protocol binds a software attestation to a tenant, broker,
//! enrollment epoch, challenge and compact audit metadata. Any collector can
//! consume these contracts without an enterprise service dependency. Reports
//! prove possession of a pinned key, not hardware measurement or discovery.
//!
//! [`verify_heartbeat`] performs stateless verification only. Consumers must
//! authenticate and enroll their own keys, compare the exact outstanding
//! challenge, enforce revocation, and atomically consume accepted challenges.
use opaque_core::{
    attest::{ReportPayload, verify_report},
    tenant::TenantBinding,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod reporter;
/// Error returned by the bounded v1 reporting contract.
pub type Result<T> = std::result::Result<T, String>;
/// Maximum compact audit entries carried by a single signed heartbeat.
pub const MAX_EXPORT_BATCH: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub binding: TenantBinding,
    pub epoch: u64,
    pub nonce: String,
    pub expires_at: i64,
    pub acknowledged_sequence: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEntry {
    pub sequence: u64,
    pub event_id: String,
    pub record_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub audit_head: Option<u64>,
    pub export_entries: Vec<ExportEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub schema_version: u32,
    pub challenge: Challenge,
    pub evidence: Evidence,
    pub report: String,
}
impl Heartbeat {
    /// Existing attestation signatures bind this exact tenant, broker, key
    /// epoch, nonce and evidence by hashing them into the attestation nonce.
    pub fn nonce_for(challenge: &Challenge, evidence: &Evidence) -> Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"opaque.fleet.heartbeat.v1\0");
        hash.update(serde_json::to_vec(&(challenge, evidence)).map_err(|_| "invalid heartbeat")?);
        Ok(format!("{:x}", hash.finalize()))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgment {
    pub binding: TenantBinding,
    pub epoch: u64,
    pub received_at: i64,
    pub acknowledged_sequence: Option<u64>,
    pub receipt_digest: Option<String>,
    pub evidence_health: String,
}

/// Verify the signed v1 envelope against a caller-pinned identity and key.
///
/// This checks binding, schema/batch limits, signature and the challenge's
/// 60-second report window. It does not enroll a key, decide whether a broker is
/// revoked, accept an evidence frontier, or prevent replay. A collector must
/// check and consume its exact outstanding challenge in one transaction around
/// this call; neither a signed report nor a Kubernetes lease grants authority.
pub fn verify_heartbeat(
    heartbeat: &Heartbeat,
    binding: &TenantBinding,
    public_key: &ed25519_dalek::VerifyingKey,
    now: i64,
) -> Result<ReportPayload> {
    binding
        .validate()
        .map_err(|_| "invalid tenant/broker binding")?;
    if heartbeat.schema_version != 1
        || heartbeat.challenge.binding != *binding
        || heartbeat.challenge.epoch == 0
        || heartbeat.challenge.nonce.len() != 32
        || !heartbeat
            .challenge
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || heartbeat.evidence.export_entries.len() > MAX_EXPORT_BATCH
        || heartbeat.report.len() > 128 * 1024
    {
        return Err("invalid heartbeat envelope".into());
    }
    let start = heartbeat
        .challenge
        .expires_at
        .checked_sub(60)
        .ok_or("invalid challenge window")?;
    if now < 0 || now < start || now >= heartbeat.challenge.expires_at {
        return Err("heartbeat challenge outside freshness window".into());
    }
    let expected_nonce = Heartbeat::nonce_for(&heartbeat.challenge, &heartbeat.evidence)?;
    let verified = verify_report(&heartbeat.report, public_key, &expected_nonce, now, 60)
        .map_err(|_| "heartbeat signature, binding or freshness rejected")?;
    if verified.payload.issued_at > now || verified.payload.issued_at < start {
        return Err("broker clock is outside challenge window".into());
    }
    Ok(verified.payload)
}
