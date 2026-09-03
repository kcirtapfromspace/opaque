//! Signed posture attestation reports.
//!
//! A report is the daemon's own account of its integrity posture — custody
//! verification, audit-chain verification, trust-domain enforcement, applied
//! federation bundle — signed with the daemon's attestation key and bound to
//! a caller-supplied nonce (anti-replay). Format `opqa1.<payload>.<sig>`,
//! the same compact shape as delegation tokens and policy bundles.
//!
//! Honesty note: this is SOFTWARE attestation. The report proves "a holder
//! of the enrolled attestation key claims this posture, freshly" — it is not
//! hardware-rooted measurement. Its role is the verify-before-trust seam:
//! a key-release verifier (or auditor) checks the report against the key it
//! enrolled and a posture policy before handing out custody material. The
//! same seam is where a KMS release policy or SPIFFE/SPIRE SVID exchange
//! slots in for hardware-backed deployments.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const REPORT_PREFIX: &str = "opqa1";
const SIG_DOMAIN: &[u8] = b"opaque-attest-v1:";
const MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// Errors from attestation handling.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("malformed report")]
    Malformed,
    #[error("unsupported report version tag")]
    UnsupportedVersion,
    #[error("report signature did not verify")]
    BadSignature,
    #[error("invalid report payload: {0}")]
    InvalidPayload(String),
    #[error("report nonce mismatch (expected {expected}, got {got})")]
    NonceMismatch { expected: String, got: String },
    #[error("report is stale: issued {issued_at}, now {now}, max age {max_age_secs}s")]
    Stale {
        issued_at: i64,
        now: i64,
        max_age_secs: i64,
    },
}

/// Trust-domain posture as observed at report time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustDomainPosture {
    /// Is `[trust_domain] enforce` on?
    pub enforce: bool,
    /// Did the custody set verify clean just now?
    pub custody_ok: bool,
    /// Human-readable custody violations (empty when clean).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custody_violations: Vec<String>,
}

/// Audit-chain posture as observed at report time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPosture {
    /// Did the full chain verify just now?
    pub chain_ok: bool,
    /// Records checked.
    pub records: u64,
    /// Detail when the chain failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Applied federation bundle, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationPosture {
    pub org: String,
    pub version: u64,
    pub digest: String,
}

/// The signed payload of an attestation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportPayload {
    /// Caller-supplied nonce this report answers (hex, anti-replay).
    pub nonce: String,
    /// Issued-at, unix seconds.
    pub issued_at: i64,
    /// Daemon version string.
    pub daemon_version: String,
    /// Effective uid the daemon runs as.
    pub uid: u32,
    pub trust_domain: TrustDomainPosture,
    pub audit: AuditPosture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationPosture>,
    /// Registered approval factors (serde names).
    #[serde(default)]
    pub factors: Vec<String>,
}

impl ReportPayload {
    fn validate(&self) -> Result<(), AttestError> {
        if self.nonce.len() < 16 || self.nonce.len() > 128 {
            return Err(AttestError::InvalidPayload(
                "nonce must be 16..=128 chars".into(),
            ));
        }
        if !self.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AttestError::InvalidPayload("nonce must be hex".into()));
        }
        Ok(())
    }

    /// Is anything actually BROKEN? Custody intact and the audit chain
    /// verifying. A session-mode daemon (no trust-domain split) with clean
    /// custody is healthy — it simply guarantees less.
    pub fn integrity_ok(&self) -> bool {
        self.trust_domain.custody_ok && self.audit.chain_ok
    }

    /// The posture a key-release verifier demands before handing over
    /// custody material: integrity intact AND the trust-domain split
    /// enforced. Stricter than [`Self::integrity_ok`] on purpose — keys must
    /// not flow to a daemon that shares a uid with the agent, even a
    /// perfectly healthy one.
    pub fn healthy_for_release(&self) -> bool {
        self.trust_domain.enforce && self.integrity_ok()
    }
}

/// A verified report plus the key that vouched for it.
#[derive(Debug, Clone)]
pub struct VerifiedReport {
    pub payload: ReportPayload,
    /// Hex of the attestation public key that verified the signature.
    pub verified_by: String,
}

/// Sign a report payload: `opqa1.<payload b64url>.<sig b64url>`.
pub fn sign_report(payload: &ReportPayload, key: &SigningKey) -> Result<String, AttestError> {
    payload.validate()?;
    let payload_json =
        serde_json::to_vec(payload).map_err(|e| AttestError::InvalidPayload(e.to_string()))?;
    if payload_json.len() > MAX_PAYLOAD_LEN {
        return Err(AttestError::InvalidPayload("payload too large".into()));
    }
    let mut msg = Vec::with_capacity(SIG_DOMAIN.len() + payload_json.len());
    msg.extend_from_slice(SIG_DOMAIN);
    msg.extend_from_slice(&payload_json);
    let sig = key.sign(&msg);
    Ok(format!(
        "{REPORT_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(&payload_json),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    ))
}

/// Verify a report's structure and signature; then bind it to the expected
/// nonce and freshness window. Signature first, interpretation after.
pub fn verify_report(
    report: &str,
    key: &VerifyingKey,
    expected_nonce: &str,
    now_unix: i64,
    max_age_secs: i64,
) -> Result<VerifiedReport, AttestError> {
    let report = report.trim();
    let mut parts = report.split('.');
    let (prefix, payload_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(p), Some(c), Some(s), None) => (p, c, s),
            _ => return Err(AttestError::Malformed),
        };
    if prefix != REPORT_PREFIX {
        return Err(AttestError::UnsupportedVersion);
    }
    if payload_b64.len() > MAX_PAYLOAD_LEN * 2 {
        return Err(AttestError::Malformed);
    }
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AttestError::Malformed)?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AttestError::Malformed)?
        .try_into()
        .map_err(|_| AttestError::Malformed)?;

    let mut msg = Vec::with_capacity(SIG_DOMAIN.len() + payload_json.len());
    msg.extend_from_slice(SIG_DOMAIN);
    msg.extend_from_slice(&payload_json);
    key.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| AttestError::BadSignature)?;

    let payload: ReportPayload =
        serde_json::from_slice(&payload_json).map_err(|_| AttestError::Malformed)?;
    payload.validate()?;

    if payload.nonce != expected_nonce {
        return Err(AttestError::NonceMismatch {
            expected: expected_nonce.into(),
            got: payload.nonce,
        });
    }
    if now_unix - payload.issued_at > max_age_secs || payload.issued_at - now_unix > 60 {
        return Err(AttestError::Stale {
            issued_at: payload.issued_at,
            now: now_unix,
            max_age_secs,
        });
    }

    Ok(VerifiedReport {
        verified_by: payload_hex(key.as_bytes()),
        payload,
    })
}

fn payload_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn payload(nonce: &str) -> ReportPayload {
        ReportPayload {
            nonce: nonce.into(),
            issued_at: 1_700_000_000,
            daemon_version: "0.1.0+test".into(),
            uid: 7381,
            trust_domain: TrustDomainPosture {
                enforce: true,
                custody_ok: true,
                custody_violations: vec![],
            },
            audit: AuditPosture {
                chain_ok: true,
                records: 42,
                detail: None,
            },
            federation: Some(FederationPosture {
                org: "acme".into(),
                version: 3,
                digest: "abc123".into(),
            }),
            factors: vec!["local_bio".into(), "ios_face_id".into()],
        }
    }

    const NONCE: &str = "aabbccdd11223344aabbccdd11223344";

    #[test]
    fn sign_verify_roundtrip_binds_nonce_and_freshness() {
        let report = sign_report(&payload(NONCE), &key()).unwrap();
        assert!(report.starts_with("opqa1."));

        let verified =
            verify_report(&report, &key().verifying_key(), NONCE, 1_700_000_030, 300).unwrap();
        assert!(verified.payload.healthy_for_release());
        assert!(verified.payload.integrity_ok());
        assert_eq!(verified.payload.uid, 7381);

        // Wrong nonce: rejected even with a valid signature.
        let err = verify_report(
            &report,
            &key().verifying_key(),
            "ffffffffffffffffffffffffffffffff",
            1_700_000_030,
            300,
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::NonceMismatch { .. }));

        // Stale: rejected.
        let err =
            verify_report(&report, &key().verifying_key(), NONCE, 1_700_009_999, 300).unwrap_err();
        assert!(matches!(err, AttestError::Stale { .. }));

        // Future-dated beyond skew: rejected.
        let err =
            verify_report(&report, &key().verifying_key(), NONCE, 1_699_999_000, 300).unwrap_err();
        assert!(matches!(err, AttestError::Stale { .. }));

        // Wrong key: rejected.
        let other = SigningKey::from_bytes(&[13u8; 32]);
        let err =
            verify_report(&report, &other.verifying_key(), NONCE, 1_700_000_030, 300).unwrap_err();
        assert_eq!(err, AttestError::BadSignature);
    }

    #[test]
    fn session_mode_is_healthy_but_not_release_eligible() {
        // A developer's session-mode daemon with clean custody is NOT broken
        // — it just guarantees less, so it must never receive custody keys.
        let mut p = payload(NONCE);
        p.trust_domain.enforce = false;
        assert!(p.integrity_ok(), "clean custody + chain is healthy");
        assert!(
            !p.healthy_for_release(),
            "keys must not flow to a shared-uid daemon"
        );
    }

    #[test]
    fn unhealthy_postures_are_reported_faithfully() {
        let mut p = payload(NONCE);
        p.trust_domain.custody_ok = false;
        p.trust_domain.custody_violations = vec!["audit chain key stolen".into()];
        assert!(!p.healthy_for_release());
        assert!(!p.integrity_ok(), "broken custody is a real health failure");

        // The report still signs and verifies — attestation reports the
        // truth; the RELEASE POLICY refuses, not the transport.
        let report = sign_report(&p, &key()).unwrap();
        let verified =
            verify_report(&report, &key().verifying_key(), NONCE, 1_700_000_030, 300).unwrap();
        assert!(!verified.payload.healthy_for_release());
        assert_eq!(
            verified.payload.trust_domain.custody_violations,
            vec!["audit chain key stolen"]
        );
    }

    #[test]
    fn nonce_validation() {
        // Too short.
        assert!(sign_report(&payload("abcd"), &key()).is_err());
        // Non-hex.
        assert!(sign_report(&payload("zzzzzzzzzzzzzzzzzzzzzzzz"), &key()).is_err());
    }

    #[test]
    fn tampered_payload_rejected() {
        let report = sign_report(&payload(NONCE), &key()).unwrap();
        let mut parts: Vec<&str> = report.split('.').collect();
        let mut json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        json["trust_domain"]["custody_ok"] = serde_json::json!(true);
        json["uid"] = serde_json::json!(0);
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        parts[1] = &forged;
        let forged_report = parts.join(".");

        let err = verify_report(
            &forged_report,
            &key().verifying_key(),
            NONCE,
            1_700_000_030,
            300,
        )
        .unwrap_err();
        assert_eq!(err, AttestError::BadSignature);
    }
}
