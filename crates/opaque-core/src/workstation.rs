//! Protocol for a trusted, separately enrolled approval workstation.
//!
//! A signature proves possession of the enrolled workstation key. The broker
//! trusts that workstation's custody and review application; it does not prove
//! remotely that a biometric sensor was used. Signatures bind the exact review
//! bytes, broker, request, approval round, random nonce, expiry, and decision.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_REVIEW_BYTES: usize = 120 * 1024;
pub const MAX_CHALLENGE_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationChallenge {
    pub schema_version: u32,
    pub broker_id: String,
    pub approval_id: String,
    pub request_id: String,
    pub operation: String,
    /// SHA-256 of every UTF-8 byte in WorkstationReview.review_text.
    pub content_hash: String,
    /// A fresh 256-bit broker nonce, encoded as lowercase hex.
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationReview {
    pub challenge: WorkstationChallenge,
    /// The complete broker-generated review, never a summary or truncation.
    pub review_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub schema_version: u32,
    pub broker_id: String,
    pub public_key_hex: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkstationDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationResponse {
    pub device_id: String,
    pub decision: WorkstationDecision,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub public_key_hex: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentResponse {
    pub device_id: String,
    pub server_id: String,
    pub token: String,
}

impl std::fmt::Debug for EnrollmentResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollmentResponse")
            .field("device_id", &self.device_id)
            .field("server_id", &self.server_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkstationError {
    #[error("invalid workstation challenge")]
    InvalidChallenge,
    #[error("workstation challenge expired or is not yet valid")]
    Expired,
    #[error("workstation challenge belongs to another broker")]
    WrongBroker,
    #[error("review content does not match the issued challenge")]
    ContentMismatch,
    #[error("workstation signature is invalid")]
    InvalidSignature,
    #[error("invalid hexadecimal encoding")]
    InvalidHex,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], WorkstationError> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(WorkstationError::InvalidHex);
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| WorkstationError::InvalidHex)?;
    }
    Ok(result)
}

pub fn review_hash(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn validate_times(created_at: i64, expires_at: i64, now: i64) -> Result<(), WorkstationError> {
    if created_at < 0
        || expires_at <= created_at
        || expires_at.saturating_sub(created_at) > MAX_CHALLENGE_TTL_SECS
    {
        return Err(WorkstationError::InvalidChallenge);
    }
    if now < created_at || now >= expires_at {
        return Err(WorkstationError::Expired);
    }
    Ok(())
}

impl WorkstationChallenge {
    pub fn validate(&self, broker_id: &str, now: i64) -> Result<(), WorkstationError> {
        if self.schema_version != 1
            || !valid_identifier(&self.broker_id)
            || uuid::Uuid::parse_str(&self.approval_id).is_err()
            || uuid::Uuid::parse_str(&self.request_id).is_err()
            || !matches!(
                self.operation.as_str(),
                "github.publish_manifest"
                    | "github.release_manifest"
                    | "inference.fixed_manifest"
                    | "agent_session_start"
                    | "identity.provisioning.bind_start"
                    | "identity.provisioning.mandate_start"
            )
            || decode_hex::<32>(&self.nonce).is_err()
            || decode_hex::<32>(&self.content_hash).is_err()
        {
            return Err(WorkstationError::InvalidChallenge);
        }
        if self.broker_id != broker_id {
            return Err(WorkstationError::WrongBroker);
        }
        validate_times(self.created_at, self.expires_at, now)
    }
}

impl WorkstationReview {
    pub fn validate(&self, broker_id: &str, now: i64) -> Result<(), WorkstationError> {
        self.challenge.validate(broker_id, now)?;
        if self.review_text.trim().is_empty()
            || self.review_text.len() > MAX_REVIEW_BYTES
            || self.review_text.chars().any(|c| {
                (c.is_control() && c != '\n' && c != '\t')
                    || matches!(c as u32, 0x202a..=0x202e | 0x2066..=0x2069)
            })
            || review_hash(&self.review_text) != self.challenge.content_hash
        {
            return Err(WorkstationError::ContentMismatch);
        }
        Ok(())
    }
}

impl EnrollmentChallenge {
    pub fn validate(
        &self,
        broker_id: &str,
        public_key: &str,
        now: i64,
    ) -> Result<(), WorkstationError> {
        if self.schema_version != 1
            || !valid_identifier(&self.broker_id)
            || decode_hex::<32>(&self.public_key_hex).is_err()
            || decode_hex::<32>(&self.nonce).is_err()
            || self.public_key_hex != public_key
        {
            return Err(WorkstationError::InvalidChallenge);
        }
        if self.broker_id != broker_id {
            return Err(WorkstationError::WrongBroker);
        }
        validate_times(self.created_at, self.expires_at, now)
    }
}

/// Hash a domain-separated sequence of u32-little-endian length-prefixed
/// fields. This is the same unambiguous encoding principle as paired iOS
/// challenges, with a distinct protocol domain preventing cross-factor use.
fn signed_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u32).to_le_bytes());
        hash.update(field);
    }
    hash.finalize().to_vec()
}

/// The 32 bytes the workstation signs using Ed25519 (no prehashed Ed25519).
/// A caller MUST validate the complete review and show it before approving.
pub fn workstation_decision_bytes(challenge: &WorkstationChallenge, approve: bool) -> Vec<u8> {
    signed_fields(&[
        b"opaque.workstation-decision.v1",
        challenge.broker_id.as_bytes(),
        challenge.approval_id.as_bytes(),
        challenge.request_id.as_bytes(),
        challenge.operation.as_bytes(),
        challenge.content_hash.as_bytes(),
        challenge.nonce.as_bytes(),
        &challenge.created_at.to_le_bytes(),
        &challenge.expires_at.to_le_bytes(),
        if approve { b"approve" } else { b"reject" },
    ])
}

pub fn enrollment_bytes(challenge: &EnrollmentChallenge) -> Vec<u8> {
    signed_fields(&[
        b"opaque.workstation-enrollment.v1",
        challenge.broker_id.as_bytes(),
        challenge.public_key_hex.as_bytes(),
        challenge.nonce.as_bytes(),
        &challenge.created_at.to_le_bytes(),
        &challenge.expires_at.to_le_bytes(),
    ])
}

pub fn verify_signature(
    public_key: &str,
    signature: &str,
    message: &[u8],
) -> Result<(), WorkstationError> {
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(public_key)?)
        .map_err(|_| WorkstationError::InvalidSignature)?;
    let signature = Signature::from_bytes(&decode_hex::<64>(signature)?);
    key.verify_strict(message, &signature)
        .map_err(|_| WorkstationError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn review() -> WorkstationReview {
        let text = "Publish\n1. owner/repo / NAME\nSource: vault:kv/data/app?version=7#VALUE\nBudget: 1 write\nExact request content hash: abc";
        WorkstationReview {
            challenge: WorkstationChallenge {
                schema_version: 1,
                broker_id: "opq-broker".into(),
                approval_id: uuid::Uuid::new_v4().to_string(),
                request_id: uuid::Uuid::new_v4().to_string(),
                operation: "github.publish_manifest".into(),
                content_hash: review_hash(text),
                nonce: "ab".repeat(32),
                created_at: 100,
                expires_at: 200,
            },
            review_text: text.into(),
        }
    }

    #[test]
    fn signature_binds_every_authority_field_and_decision() {
        let review = review();
        let key = SigningKey::from_bytes(&[11; 32]);
        let public = hex(key.verifying_key().as_bytes());
        let signature = hex(&key
            .sign(&workstation_decision_bytes(&review.challenge, true))
            .to_bytes());
        verify_signature(
            &public,
            &signature,
            &workstation_decision_bytes(&review.challenge, true),
        )
        .unwrap();
        assert!(
            verify_signature(
                &public,
                &signature,
                &workstation_decision_bytes(&review.challenge, false)
            )
            .is_err()
        );
        let changes: [fn(&mut WorkstationChallenge); 8] = [
            |c| c.broker_id = "other".into(),
            |c| c.approval_id = uuid::Uuid::new_v4().to_string(),
            |c| c.request_id = uuid::Uuid::new_v4().to_string(),
            |c| c.operation = "github.release_manifest".into(),
            |c| c.content_hash = "cd".repeat(32),
            |c| c.nonce = "ef".repeat(32),
            |c| c.created_at += 1,
            |c| c.expires_at += 1,
        ];
        for change in changes {
            let mut challenge = review.challenge.clone();
            change(&mut challenge);
            assert!(
                verify_signature(
                    &public,
                    &signature,
                    &workstation_decision_bytes(&challenge, true)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn review_requires_full_unchanged_content_and_exact_deadline() {
        let mut review = review();
        review.validate("opq-broker", 100).unwrap();
        assert!(review.validate("opq-broker", 200).is_err());
        assert!(review.validate("other", 101).is_err());
        review.review_text.push_str("\nAnother target");
        assert!(review.validate("opq-broker", 101).is_err());
        review.challenge.content_hash = review_hash(&review.review_text);
        review.validate("opq-broker", 101).unwrap();
        review.review_text.push('\0');
        review.challenge.content_hash = review_hash(&review.review_text);
        assert!(review.validate("opq-broker", 101).is_err());
    }

    #[test]
    fn provisioning_whitelist_and_signature_bind_exact_ceremony_and_terms() {
        for operation in [
            "identity.provisioning.bind_start",
            "identity.provisioning.mandate_start",
        ] {
            let mut review = review();
            review.challenge.operation = operation.into();
            review.review_text="Tenant: engineering\nIssuer: exact-subject\nProfile: metrics\nCumulative allowance: 2\nRedelegation: forbidden".into();
            review.challenge.content_hash = review_hash(&review.review_text);
            review.validate("opq-broker", 101).unwrap();
            let key = SigningKey::from_bytes(&[29; 32]);
            let public = hex(key.verifying_key().as_bytes());
            let signature = hex(&key
                .sign(&workstation_decision_bytes(&review.challenge, true))
                .to_bytes());
            let mut changed = review.challenge.clone();
            changed.content_hash =
                review_hash(&review.review_text.replace("allowance: 2", "allowance: 3"));
            assert!(
                verify_signature(
                    &public,
                    &signature,
                    &workstation_decision_bytes(&changed, true)
                )
                .is_err()
            );
            changed = review.challenge.clone();
            changed.operation = "agent_session_start".into();
            assert!(
                verify_signature(
                    &public,
                    &signature,
                    &workstation_decision_bytes(&changed, true)
                )
                .is_err()
            );
        }
        for operation in [
            "identity.provisioning.issue",
            "identity.provisioning.mandate_start.other",
            "identity.role_set",
        ] {
            let mut review = review();
            review.challenge.operation = operation.into();
            assert!(review.validate("opq-broker", 101).is_err());
        }
    }

    #[test]
    fn agent_session_approval_signature_binds_operation_and_full_review() {
        let mut review = review();
        review.challenge.operation = "agent_session_start".into();
        review.review_text = format!(
            "Tenant: tenant-a\nBroker: broker-a\nSubject: human-a\nMode: delegated\nPeer UID: 500\nLabel: {}\nTTL: 600 seconds",
            "label".repeat(100)
        );
        review.challenge.content_hash = review_hash(&review.review_text);
        review.validate("opq-broker", 101).unwrap();
        let key = SigningKey::from_bytes(&[71; 32]);
        let public = hex(key.verifying_key().as_bytes());
        let signature = hex(&key
            .sign(&workstation_decision_bytes(&review.challenge, true))
            .to_bytes());
        verify_signature(
            &public,
            &signature,
            &workstation_decision_bytes(&review.challenge, true),
        )
        .unwrap();
        let mut changed = review.challenge.clone();
        changed.operation = "github.publish_manifest".into();
        changed.validate("opq-broker", 101).unwrap();
        assert!(
            verify_signature(
                &public,
                &signature,
                &workstation_decision_bytes(&changed, true)
            )
            .is_err()
        );
        changed.operation = "device_pair_start".into();
        assert!(changed.validate("opq-broker", 101).is_err());
        let mut changed = review.clone();
        changed.review_text = changed.review_text.replace("600 seconds", "601 seconds");
        assert!(changed.validate("opq-broker", 101).is_err());
        changed.challenge.content_hash = review_hash(&changed.review_text);
        changed.validate("opq-broker", 101).unwrap();
        assert!(
            verify_signature(
                &public,
                &signature,
                &workstation_decision_bytes(&changed.challenge, true)
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_hex_is_rejected_without_unicode_slicing_panics() {
        assert!(decode_hex::<2>("éé").is_err());
        assert!(decode_hex::<2>("zzzz").is_err());
        assert_eq!(decode_hex::<2>("abCD").unwrap(), [0xab, 0xcd]);
    }
}
