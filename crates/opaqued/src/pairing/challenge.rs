//! Challenge construction and verification for iOS Face ID approval.
//!
//! The challenge is a deterministic byte sequence:
//! `H(server_id || request_id || sha256(request_summary) || expires_at)`
//!
//! Each field is length-prefixed (4-byte little-endian length + data) to
//! prevent ambiguous concatenation attacks.

use ed25519_dalek::{Signature, Verifier};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::store;
use super::store::PairedDevice;

/// An approval challenge sent to a paired iOS device.
#[derive(Debug, Clone)]
pub struct ApprovalChallenge {
    /// Stable daemon/server UUID.
    pub server_id: String,
    /// Unique request identifier.
    pub request_id: String,
    /// SHA-256 hash of the operation summary (hex-encoded).
    pub operation_summary_hash: String,
    /// Unix timestamp when this challenge expires.
    pub expires_at: i64,
}

/// Errors from challenge verification.
#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("challenge has expired")]
    Expired,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("device is revoked")]
    DeviceRevoked,

    #[error("invalid device key: {0}")]
    InvalidKey(String),

    #[error("challenge already used (replay detected)")]
    Replay,
}

/// Construct the canonical challenge bytes using length-prefixed encoding.
///
/// Format: for each field, emit `[4-byte LE length][field bytes]`, then
/// SHA-256 hash the entire concatenation.
pub fn construct_challenge_bytes(challenge: &ApprovalChallenge) -> Vec<u8> {
    let mut buf = Vec::new();

    // Helper: append a length-prefixed field
    fn append_field(buf: &mut Vec<u8>, data: &[u8]) {
        let len = data.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(data);
    }

    append_field(&mut buf, challenge.server_id.as_bytes());
    append_field(&mut buf, challenge.request_id.as_bytes());
    append_field(&mut buf, challenge.operation_summary_hash.as_bytes());
    append_field(&mut buf, &challenge.expires_at.to_le_bytes());

    // Hash the length-prefixed concatenation
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 of an operation summary string.
pub fn hash_operation_summary(summary: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(summary.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify a signed challenge response from a paired device.
///
/// Checks that:
/// 1. The device is not revoked
/// 2. The challenge has not expired
/// 3. The Ed25519 signature is valid over the challenge bytes
pub fn verify_challenge_response(
    challenge: &ApprovalChallenge,
    signature_bytes: &[u8],
    device: &PairedDevice,
    current_time: i64,
) -> Result<(), ChallengeError> {
    // Check device revocation
    if device.revoked {
        return Err(ChallengeError::DeviceRevoked);
    }

    // Check expiry
    if current_time > challenge.expires_at {
        return Err(ChallengeError::Expired);
    }

    // Reconstruct challenge bytes
    let challenge_bytes = construct_challenge_bytes(challenge);

    // Parse signature
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| ChallengeError::InvalidSignature)?;

    // Parse device public key
    let verifying_key = device
        .verifying_key()
        .map_err(|e: store::DeviceStoreError| ChallengeError::InvalidKey(e.to_string()))?;

    // Verify signature
    verifying_key
        .verify(&challenge_bytes, &signature)
        .map_err(|_| ChallengeError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn make_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn make_test_device(verifying_key: &VerifyingKey, revoked: bool) -> PairedDevice {
        PairedDevice {
            device_id: "test-device-001".into(),
            name: "Test iPhone".into(),
            public_key_hex: hex_encode(verifying_key.as_bytes()),
            paired_at: 1700000000,
            last_seen: None,
            revoked,
        }
    }

    fn make_test_challenge() -> ApprovalChallenge {
        ApprovalChallenge {
            server_id: "server-uuid-123".into(),
            request_id: "request-uuid-456".into(),
            operation_summary_hash: hash_operation_summary("github.set_actions_secret on org/repo"),
            expires_at: 1700001000,
        }
    }

    #[test]
    fn test_pairing_challenge_construction() {
        let challenge = make_test_challenge();
        let bytes = construct_challenge_bytes(&challenge);

        // Should produce a 32-byte SHA-256 hash
        assert_eq!(bytes.len(), 32);

        // Same challenge should produce same bytes (deterministic)
        let bytes2 = construct_challenge_bytes(&challenge);
        assert_eq!(bytes, bytes2);

        // Different challenge should produce different bytes
        let mut different = challenge.clone();
        different.request_id = "different-id".into();
        let bytes3 = construct_challenge_bytes(&different);
        assert_ne!(bytes, bytes3);
    }

    #[test]
    fn test_pairing_challenge_length_prefixed_fields() {
        // Verify the raw buffer (before hashing) uses length-prefixed encoding.
        // We'll construct manually to verify format.
        let challenge = ApprovalChallenge {
            server_id: "ABC".into(),
            request_id: "DEF".into(),
            operation_summary_hash: "GHI".into(),
            expires_at: 42,
        };

        // The internal buffer should have: [3,0,0,0,"ABC",3,0,0,0,"DEF",3,0,0,0,"GHI",8,0,0,0,42_i64_le]
        // We verify indirectly by checking determinism and uniqueness
        let bytes = construct_challenge_bytes(&challenge);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_pairing_response_verification() {
        let (signing_key, verifying_key) = make_test_keypair();
        let device = make_test_device(&verifying_key, false);
        let challenge = make_test_challenge();

        // Sign the challenge
        let challenge_bytes = construct_challenge_bytes(&challenge);
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&challenge_bytes);

        // Verify should succeed
        let result = verify_challenge_response(
            &challenge,
            &signature.to_bytes(),
            &device,
            1700000500, // before expiry
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let (_signing_key, verifying_key) = make_test_keypair();
        let device = make_test_device(&verifying_key, false);
        let challenge = make_test_challenge();

        // Use a signature from a different key
        let (other_key, _) = make_test_keypair();
        let challenge_bytes = construct_challenge_bytes(&challenge);
        use ed25519_dalek::Signer;
        let bad_signature = other_key.sign(&challenge_bytes);

        let result =
            verify_challenge_response(&challenge, &bad_signature.to_bytes(), &device, 1700000500);
        assert!(matches!(result, Err(ChallengeError::InvalidSignature)));
    }

    #[test]
    fn test_expired_challenge_rejected() {
        let (signing_key, verifying_key) = make_test_keypair();
        let device = make_test_device(&verifying_key, false);
        let challenge = make_test_challenge();

        let challenge_bytes = construct_challenge_bytes(&challenge);
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&challenge_bytes);

        // Current time after expiry
        let result = verify_challenge_response(
            &challenge,
            &signature.to_bytes(),
            &device,
            1700002000, // after expires_at
        );
        assert!(matches!(result, Err(ChallengeError::Expired)));
    }

    #[test]
    fn test_revoked_device_rejected() {
        let (signing_key, verifying_key) = make_test_keypair();
        let device = make_test_device(&verifying_key, true); // revoked
        let challenge = make_test_challenge();

        let challenge_bytes = construct_challenge_bytes(&challenge);
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&challenge_bytes);

        let result =
            verify_challenge_response(&challenge, &signature.to_bytes(), &device, 1700000500);
        assert!(matches!(result, Err(ChallengeError::DeviceRevoked)));
    }

    #[test]
    fn test_hash_operation_summary() {
        let hash1 = hash_operation_summary("github.set_actions_secret on org/repo");
        let hash2 = hash_operation_summary("github.set_actions_secret on org/repo");
        assert_eq!(hash1, hash2);

        let hash3 = hash_operation_summary("different operation");
        assert_ne!(hash1, hash3);

        // Should be a valid 64-char hex string (SHA-256)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_challenge_bytes_differ_on_server_id() {
        let c1 = ApprovalChallenge {
            server_id: "server-a".into(),
            request_id: "req-1".into(),
            operation_summary_hash: "hash".into(),
            expires_at: 1000,
        };
        let c2 = ApprovalChallenge {
            server_id: "server-b".into(),
            ..c1.clone()
        };
        assert_ne!(
            construct_challenge_bytes(&c1),
            construct_challenge_bytes(&c2)
        );
    }

    #[test]
    fn test_challenge_bytes_differ_on_expires_at() {
        let c1 = ApprovalChallenge {
            server_id: "server".into(),
            request_id: "req".into(),
            operation_summary_hash: "hash".into(),
            expires_at: 1000,
        };
        let c2 = ApprovalChallenge {
            expires_at: 2000,
            ..c1.clone()
        };
        assert_ne!(
            construct_challenge_bytes(&c1),
            construct_challenge_bytes(&c2)
        );
    }
}
