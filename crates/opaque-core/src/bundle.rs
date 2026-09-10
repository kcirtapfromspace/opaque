//! Signed policy bundles — the federation unit of central control.
//!
//! A bundle carries an org's policy (rules + team namespaces) as a compact
//! signed document: `opqb1.<payload b64url>.<sig b64url>`, mirroring the
//! `opqd1` delegation-token shape. The Ed25519 signature covers the literal
//! payload bytes under a domain separator, so there is no canonicalization
//! step to get wrong — what was signed is exactly what is verified.
//!
//! Trust model:
//! - The daemon is configured with one or more **trust anchors** (org signing
//!   public keys, hex). A bundle verifies iff some anchor's signature checks.
//! - **Anti-rollback**: the daemon persists the last-applied `(org, version,
//!   digest)` in its custody set. A bundle with a lower version is refused
//!   outright; an equal version is accepted only if it is byte-identical
//!   (idempotent re-apply). Only signed, newer bundles move policy forward.
//! - Bundles may carry an expiry: a stale bundle is a warning in ordinary
//!   operation (policy keeps working if the fetch source is down) but is
//!   refused as the *initial* bundle under `require_bundle`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::PolicyRule;

/// Bundle format version tag (also part of the signature domain).
const BUNDLE_PREFIX: &str = "opqb1";
const SIG_DOMAIN: &[u8] = b"opaque-bundle-v1:";
/// Hard ceiling on encoded payload size — a policy bundle is not a data lake.
const MAX_PAYLOAD_LEN: usize = 1024 * 1024;

/// Errors from bundle handling.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("malformed bundle")]
    Malformed,
    #[error("unsupported bundle version tag")]
    UnsupportedVersion,
    #[error("bundle signature did not verify against any trust anchor")]
    BadSignature,
    #[error("invalid bundle payload: {0}")]
    InvalidPayload(String),
    #[error("bundle expired at {expired_at} (now {now})")]
    Expired { expired_at: i64, now: i64 },
    #[error(
        "bundle version {offered} is older than the applied version {applied} — \
         rollback refused"
    )]
    Rollback { offered: u64, applied: u64 },
    #[error(
        "bundle version {version} was already applied with different content — \
         refusing the substitution"
    )]
    VersionReuse { version: u64 },
    #[error("no trust anchors configured")]
    NoAnchors,
}

/// A team namespace inside an org.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Team {
    /// Team name (one path segment: `platform`, `ml-infra`).
    pub name: String,
    /// Member principals, by display label (email for humans,
    /// `service:<name>` for service principals). Resolved against the
    /// identity store at request time — the bundle names members, the
    /// store decides whether they exist.
    #[serde(default)]
    pub members: Vec<String>,
}

/// The signed payload of a policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundlePayload {
    /// Org identifier — the namespace root (`acme`).
    pub org: String,
    /// Monotonic bundle version. The anti-rollback counter.
    pub version: u64,
    /// Issued-at, unix seconds.
    pub issued_at: i64,
    /// Optional expiry, unix seconds. See module docs for staleness policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Hex prefix (16 chars) of the signing public key — anchor routing hint
    /// only; verification still tries anchors until one matches.
    #[serde(default)]
    pub key_id: String,
    /// Team namespaces (federation F2).
    #[serde(default)]
    pub teams: Vec<Team>,
    /// The org policy. When a bundle is applied these rules are authoritative
    /// (they replace local `[[rules]]`).
    pub rules: Vec<PolicyRule>,
    /// Optional pinned MCP registry. Runtime consumption is opt-in and strictly expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_registry: Option<crate::mcp::RegistryDocument>,
}

impl BundlePayload {
    fn validate(&self) -> Result<(), BundleError> {
        if self.org.is_empty() || self.org.len() > 64 {
            return Err(BundleError::InvalidPayload("bad org".into()));
        }
        if !self
            .org
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(BundleError::InvalidPayload(
                "org must be alphanumeric/-_.".into(),
            ));
        }
        if self.version == 0 {
            return Err(BundleError::InvalidPayload("version must be >= 1".into()));
        }
        if let Some(exp) = self.expires_at
            && exp <= self.issued_at
        {
            return Err(BundleError::InvalidPayload(
                "expires_at <= issued_at".into(),
            ));
        }
        if let Some(registry) = &self.mcp_registry {
            crate::mcp::Registry::from_document(registry)
                .map_err(|_| BundleError::InvalidPayload("invalid MCP registry".into()))?;
        }
        for team in &self.teams {
            if team.name.is_empty()
                || team.name.len() > 64
                || !team
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            {
                return Err(BundleError::InvalidPayload(format!(
                    "bad team name {:?}",
                    team.name
                )));
            }
        }
        Ok(())
    }
}

/// A verified bundle: the parsed payload plus the digest of the exact signed
/// bytes (the anti-rollback identity of this content).
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub payload: BundlePayload,
    /// SHA-256 (hex) of the signed payload bytes.
    pub digest: String,
    /// Hex of the anchor public key that verified the signature.
    pub verified_by: String,
}

/// Sign a payload into a compact bundle string.
pub fn sign_bundle(payload: &BundlePayload, key: &SigningKey) -> Result<String, BundleError> {
    payload.validate()?;
    let payload_json =
        serde_json::to_vec(payload).map_err(|e| BundleError::InvalidPayload(e.to_string()))?;
    if payload_json.len() > MAX_PAYLOAD_LEN {
        return Err(BundleError::InvalidPayload("payload too large".into()));
    }
    let mut msg = Vec::with_capacity(SIG_DOMAIN.len() + payload_json.len());
    msg.extend_from_slice(SIG_DOMAIN);
    msg.extend_from_slice(&payload_json);
    let sig = key.sign(&msg);
    Ok(format!(
        "{BUNDLE_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(&payload_json),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    ))
}

/// Parse a hex-encoded Ed25519 public key (a trust anchor).
pub fn parse_anchor(hex: &str) -> Result<VerifyingKey, BundleError> {
    let bytes = decode_hex(hex).ok_or(BundleError::Malformed)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| BundleError::Malformed)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| BundleError::Malformed)
}

/// Verify a bundle against a set of trust anchors.
///
/// Signature first, on the exact transmitted bytes; only then is the payload
/// interpreted. Expiry is checked against `now_unix` and reported as
/// [`BundleError::Expired`] — the CALLER decides whether staleness is fatal
/// (initial `require_bundle` load) or a warning (refresh of a running daemon),
/// via [`verify_bundle_allow_expired`].
pub fn verify_bundle(
    bundle: &str,
    anchors: &[VerifyingKey],
    now_unix: i64,
) -> Result<VerifiedBundle, BundleError> {
    let verified = verify_bundle_allow_expired(bundle, anchors)?;
    if let Some(exp) = verified.payload.expires_at
        && now_unix >= exp
    {
        return Err(BundleError::Expired {
            expired_at: exp,
            now: now_unix,
        });
    }
    Ok(verified)
}

/// Verify structure + signature + payload validity, WITHOUT the expiry check.
pub fn verify_bundle_allow_expired(
    bundle: &str,
    anchors: &[VerifyingKey],
) -> Result<VerifiedBundle, BundleError> {
    if anchors.is_empty() {
        return Err(BundleError::NoAnchors);
    }
    let bundle = bundle.trim();
    let mut parts = bundle.split('.');
    let (prefix, payload_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(p), Some(c), Some(s), None) => (p, c, s),
            _ => return Err(BundleError::Malformed),
        };
    if prefix != BUNDLE_PREFIX {
        return Err(BundleError::UnsupportedVersion);
    }
    if payload_b64.len() > MAX_PAYLOAD_LEN * 2 {
        return Err(BundleError::Malformed);
    }
    let payload_json = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| BundleError::Malformed)?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| BundleError::Malformed)?
        .try_into()
        .map_err(|_| BundleError::Malformed)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let mut msg = Vec::with_capacity(SIG_DOMAIN.len() + payload_json.len());
    msg.extend_from_slice(SIG_DOMAIN);
    msg.extend_from_slice(&payload_json);

    let anchor = anchors
        .iter()
        .find(|key| key.verify(&msg, &signature).is_ok())
        .ok_or(BundleError::BadSignature)?;

    // Only after the signature checks out do we interpret the payload.
    let payload: BundlePayload =
        serde_json::from_slice(&payload_json).map_err(|_| BundleError::Malformed)?;
    payload.validate()?;

    Ok(VerifiedBundle {
        payload,
        digest: hex_encode(&Sha256::digest(&payload_json)),
        verified_by: hex_encode(anchor.as_bytes()),
    })
}

// ---------------------------------------------------------------------------
// Anti-rollback state
// ---------------------------------------------------------------------------

/// The persisted record of the last applied bundle. Lives in the daemon's
/// custody set — under the trust-domain split the agent cannot rewind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleState {
    pub org: String,
    pub version: u64,
    /// SHA-256 (hex) of the applied bundle's payload bytes.
    pub digest: String,
    /// When it was applied, unix seconds.
    pub applied_at: i64,
}

/// Enforce monotonic versions against the stored state.
///
/// - No prior state: anything verified is applicable.
/// - Older version: [`BundleError::Rollback`].
/// - Same version, same digest: idempotent re-apply, fine.
/// - Same version, different digest: [`BundleError::VersionReuse`] — someone
///   minted two different bundles under one version; refuse the substitution.
pub fn check_rollback(
    verified: &VerifiedBundle,
    state: Option<&BundleState>,
) -> Result<(), BundleError> {
    let Some(state) = state else {
        return Ok(());
    };
    // A different org under the same state file is a reconfiguration, not a
    // rollback of the same org's policy — allow it (the operator changed
    // anchors/org deliberately; the signature already proved authority).
    if state.org != verified.payload.org {
        return Ok(());
    }
    if verified.payload.version < state.version {
        return Err(BundleError::Rollback {
            offered: verified.payload.version,
            applied: state.version,
        });
    }
    if verified.payload.version == state.version && verified.digest != state.digest {
        return Err(BundleError::VersionReuse {
            version: verified.payload.version,
        });
    }
    Ok(())
}

/// Load persisted bundle state (`Ok(None)` when absent).
pub fn load_state(path: &std::path::Path) -> std::io::Result<Option<BundleState>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Persist bundle state (0600).
pub fn save_state(path: &std::path::Path, state: &BundleState) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(state)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&bytes)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, &bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hex helpers (no extra dependency)
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn payload(version: u64) -> BundlePayload {
        BundlePayload {
            org: "acme".into(),
            version,
            issued_at: 1_700_000_000,
            expires_at: None,
            key_id: String::new(),
            teams: vec![Team {
                name: "platform".into(),
                members: vec!["alice@acme.com".into()],
            }],
            rules: vec![],
            mcp_registry: None,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = test_key();
        let bundle = sign_bundle(&payload(1), &key).unwrap();
        assert!(bundle.starts_with("opqb1."));

        let verified = verify_bundle(&bundle, &[key.verifying_key()], 1_700_000_100).unwrap();
        assert_eq!(verified.payload.org, "acme");
        assert_eq!(verified.payload.version, 1);
        assert_eq!(verified.payload.teams[0].name, "platform");
        assert_eq!(
            verified.verified_by,
            hex_encode(key.verifying_key().as_bytes())
        );
    }

    #[test]
    fn wrong_key_rejected_but_any_matching_anchor_accepts() {
        let key = test_key();
        let bundle = sign_bundle(&payload(1), &key).unwrap();

        // Only the wrong anchor: rejected.
        let err =
            verify_bundle(&bundle, &[other_key().verifying_key()], 1_700_000_100).unwrap_err();
        assert_eq!(err, BundleError::BadSignature);

        // Wrong + right anchors (rotation window): accepted.
        let verified = verify_bundle(
            &bundle,
            &[other_key().verifying_key(), key.verifying_key()],
            1_700_000_100,
        )
        .unwrap();
        assert_eq!(verified.payload.version, 1);
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = test_key();
        let bundle = sign_bundle(&payload(1), &key).unwrap();
        // Flip the version inside the payload by re-encoding a modified copy.
        let mut parts: Vec<&str> = bundle.split('.').collect();
        let mut json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        json["version"] = serde_json::json!(999);
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        parts[1] = &forged;
        let forged_bundle = parts.join(".");

        let err = verify_bundle(&forged_bundle, &[key.verifying_key()], 1_700_000_100).unwrap_err();
        assert_eq!(err, BundleError::BadSignature);
    }

    #[test]
    fn expiry_enforced_and_bypassable_only_explicitly() {
        let key = test_key();
        let mut p = payload(1);
        p.expires_at = Some(1_700_000_050);
        let bundle = sign_bundle(&p, &key).unwrap();

        let err = verify_bundle(&bundle, &[key.verifying_key()], 1_700_000_100).unwrap_err();
        assert!(matches!(err, BundleError::Expired { .. }));

        // The explicit allow-expired path still verifies the signature.
        let verified = verify_bundle_allow_expired(&bundle, &[key.verifying_key()]).unwrap();
        assert_eq!(verified.payload.version, 1);
    }

    #[test]
    fn rollback_and_version_reuse_refused() {
        let key = test_key();
        let v2 = sign_bundle(&payload(2), &key).unwrap();
        let verified_v2 = verify_bundle(&v2, &[key.verifying_key()], 1_700_000_100).unwrap();
        let state = BundleState {
            org: "acme".into(),
            version: 2,
            digest: verified_v2.digest.clone(),
            applied_at: 1_700_000_100,
        };

        // Older version: rollback refused.
        let v1 = sign_bundle(&payload(1), &key).unwrap();
        let verified_v1 = verify_bundle(&v1, &[key.verifying_key()], 1_700_000_100).unwrap();
        assert_eq!(
            check_rollback(&verified_v1, Some(&state)).unwrap_err(),
            BundleError::Rollback {
                offered: 1,
                applied: 2
            }
        );

        // Same version, same digest: idempotent re-apply.
        check_rollback(&verified_v2, Some(&state)).unwrap();

        // Same version, different content: substitution refused.
        let mut p2b = payload(2);
        p2b.teams.clear();
        let v2b = sign_bundle(&p2b, &key).unwrap();
        let verified_v2b = verify_bundle(&v2b, &[key.verifying_key()], 1_700_000_100).unwrap();
        assert_eq!(
            check_rollback(&verified_v2b, Some(&state)).unwrap_err(),
            BundleError::VersionReuse { version: 2 }
        );

        // Newer version: fine. No prior state: fine.
        let v3 = sign_bundle(&payload(3), &key).unwrap();
        let verified_v3 = verify_bundle(&v3, &[key.verifying_key()], 1_700_000_100).unwrap();
        check_rollback(&verified_v3, Some(&state)).unwrap();
        check_rollback(&verified_v1, None).unwrap();
    }

    #[test]
    fn different_org_is_reconfiguration_not_rollback() {
        let key = test_key();
        let state = BundleState {
            org: "acme".into(),
            version: 9,
            digest: "d".into(),
            applied_at: 0,
        };
        let mut p = payload(1);
        p.org = "globex".into();
        let b = sign_bundle(&p, &key).unwrap();
        let verified = verify_bundle(&b, &[key.verifying_key()], 1_700_000_100).unwrap();
        check_rollback(&verified, Some(&state)).unwrap();
    }

    #[test]
    fn state_roundtrip_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.state");
        assert_eq!(load_state(&path).unwrap(), None);

        let state = BundleState {
            org: "acme".into(),
            version: 4,
            digest: "abc".into(),
            applied_at: 1_700_000_000,
        };
        save_state(&path, &state).unwrap();
        assert_eq!(load_state(&path).unwrap(), Some(state));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn malformed_inputs_rejected() {
        let key = test_key();
        let anchors = [key.verifying_key()];
        for bad in [
            "",
            "opqb1",
            "opqb1.abc",
            "opqb1.a.b.c",
            "opqd1.a.b",
            "opqb1.!!.??",
        ] {
            assert!(verify_bundle(bad, &anchors, 0).is_err(), "{bad:?}");
        }
        // Empty anchor set fails closed.
        let bundle = sign_bundle(&payload(1), &key).unwrap();
        assert_eq!(
            verify_bundle(&bundle, &[], 0).unwrap_err(),
            BundleError::NoAnchors
        );
    }

    #[test]
    fn payload_validation() {
        let key = test_key();
        let mut p = payload(1);
        p.org = String::new();
        assert!(sign_bundle(&p, &key).is_err());

        let mut p = payload(0);
        p.org = "acme".into();
        assert!(sign_bundle(&p, &key).is_err());

        let mut p = payload(1);
        p.teams[0].name = "bad team!".into();
        assert!(sign_bundle(&p, &key).is_err());

        let mut p = payload(1);
        p.expires_at = Some(p.issued_at);
        assert!(sign_bundle(&p, &key).is_err());
    }

    #[test]
    fn anchor_parsing() {
        let key = test_key();
        let hex = hex_encode(key.verifying_key().as_bytes());
        let parsed = parse_anchor(&hex).unwrap();
        assert_eq!(parsed, key.verifying_key());
        assert!(parse_anchor("zz").is_err());
        assert!(parse_anchor("abcd").is_err()); // wrong length
    }
}
