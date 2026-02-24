//! Pairing protocol for iOS companion app.
//!
//! Handles QR code generation, ephemeral pairing sessions, device registration,
//! and challenge-response verification for the `IosFaceId` approval factor.

pub mod challenge;
pub mod store;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use self::challenge::{
    ApprovalChallenge, ChallengeError, construct_challenge_bytes, verify_challenge_response,
};
use self::store::{DeviceStore, DeviceStoreError, PairedDevice};

/// Default QR code / pairing session TTL: 5 minutes.
const PAIRING_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// Default challenge TTL: 2 minutes.
const CHALLENGE_TTL: Duration = Duration::from_secs(2 * 60);

/// QR code payload sent to the iOS app for pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPayload {
    /// Stable daemon UUID.
    pub server_id: String,
    /// Daemon's Ed25519 public key (hex-encoded).
    pub public_key: String,
    /// Daemon port for HTTPS.
    pub port: u16,
    /// One-time pairing nonce (hex-encoded, 32 bytes).
    pub nonce: String,
    /// Unix timestamp when the QR code was created.
    pub created_at: i64,
    /// Unix timestamp when the QR code expires.
    pub expires_at: i64,
}

/// Ephemeral pairing session created when generating a QR code.
#[derive(Debug)]
pub struct PairingSession {
    /// The nonce for this session (hex-encoded).
    pub nonce: String,
    /// Server ID bound to this session.
    pub server_id: String,
    /// When this session expires.
    pub expires_at: i64,
    /// Whether this session has been consumed.
    consumed: bool,
}

/// Errors from the pairing manager.
#[derive(Debug, Error)]
pub enum PairingError {
    #[error("pairing session expired")]
    Expired,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("device already paired: {0}")]
    AlreadyPaired(String),

    #[error("storage error: {0}")]
    StorageError(#[from] DeviceStoreError),

    #[error("pairing session already consumed")]
    SessionConsumed,

    #[error("invalid nonce")]
    InvalidNonce,
}

/// The pairing manager handles QR generation, pairing completion, and
/// challenge-response for iOS device approval.
pub struct PairingManager {
    /// Stable server/daemon ID.
    server_id: String,
    /// Daemon's Ed25519 signing key.
    signing_key: SigningKey,
    /// HTTPS port for the local approval server.
    port: u16,
    /// Device store for persisting paired devices.
    device_store: DeviceStore,
    /// Active (unconsumed) pairing sessions, keyed by nonce.
    active_sessions: Mutex<HashMap<String, PairingSession>>,
    /// Set of used challenge hashes for replay detection.
    used_challenges: Mutex<HashSet<String>>,
}

/// Simple hex encoding.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

impl PairingManager {
    /// Create a new pairing manager.
    pub fn new(
        server_id: String,
        signing_key: SigningKey,
        port: u16,
        device_store: DeviceStore,
    ) -> Self {
        Self {
            server_id,
            signing_key,
            port,
            device_store,
            active_sessions: Mutex::new(HashMap::new()),
            used_challenges: Mutex::new(HashSet::new()),
        }
    }

    /// Get the server's public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Generate a QR code payload and an ephemeral pairing session.
    ///
    /// The QR payload is sent to the iOS app (via terminal QR code).
    /// The pairing session is retained server-side until the device completes
    /// pairing or the session expires.
    pub fn generate_qr_payload(&self) -> (QrPayload, String) {
        let mut nonce_bytes = [0u8; 32];
        getrandom::fill(&mut nonce_bytes).expect("failed to generate random nonce");
        let nonce = hex_encode(&nonce_bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + PAIRING_SESSION_TTL.as_secs() as i64;

        let payload = QrPayload {
            server_id: self.server_id.clone(),
            public_key: hex_encode(self.signing_key.verifying_key().as_bytes()),
            port: self.port,
            nonce: nonce.clone(),
            created_at: now,
            expires_at,
        };

        let session = PairingSession {
            nonce: nonce.clone(),
            server_id: self.server_id.clone(),
            expires_at,
            consumed: false,
        };

        self.active_sessions
            .lock()
            .expect("session lock")
            .insert(nonce.clone(), session);

        (payload, nonce)
    }

    /// Complete the pairing handshake.
    ///
    /// Called when the iOS app submits its device public key after scanning
    /// the QR code. Validates the nonce and TTL, then stores the device.
    pub fn complete_pairing(
        &self,
        nonce: &str,
        device_public_key: &[u8],
        device_name: &str,
    ) -> Result<PairedDevice, PairingError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Look up and consume the session
        let mut sessions = self.active_sessions.lock().expect("session lock");
        let session = sessions.get_mut(nonce).ok_or(PairingError::InvalidNonce)?;

        if session.consumed {
            return Err(PairingError::SessionConsumed);
        }

        if now > session.expires_at {
            sessions.remove(nonce);
            return Err(PairingError::Expired);
        }

        session.consumed = true;

        // Validate the public key
        let key_bytes: [u8; 32] = device_public_key
            .try_into()
            .map_err(|_| PairingError::InvalidSignature)?;
        let _verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| PairingError::InvalidSignature)?;

        let device_id = Uuid::new_v4().to_string();
        let device = PairedDevice {
            device_id: device_id.clone(),
            name: device_name.to_owned(),
            public_key_hex: hex_encode(device_public_key),
            paired_at: now,
            last_seen: None,
            revoked: false,
        };

        // Drop the lock before accessing store
        drop(sessions);

        self.device_store.add_device(device.clone())?;

        Ok(device)
    }

    /// Verify a signed approval response from a paired device.
    ///
    /// Includes replay detection: the same challenge+response pair cannot
    /// be accepted twice.
    pub fn verify_approval(
        &self,
        challenge: &ApprovalChallenge,
        signature: &[u8],
        device_id: &str,
    ) -> Result<(), PairingError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let device = self.device_store.get_device(device_id)?;

        // Replay detection: hash the challenge bytes + signature
        let challenge_bytes = construct_challenge_bytes(challenge);
        let replay_key = hex_encode(&challenge_bytes) + ":" + &hex_encode(signature);

        {
            let used = self.used_challenges.lock().expect("replay lock");
            if used.contains(&replay_key) {
                return Err(PairingError::InvalidSignature);
            }
            // We'll insert after verification succeeds
        }

        verify_challenge_response(challenge, signature, &device, now).map_err(|e| match e {
            ChallengeError::Expired => PairingError::Expired,
            ChallengeError::InvalidSignature => PairingError::InvalidSignature,
            ChallengeError::DeviceRevoked => PairingError::InvalidSignature,
            ChallengeError::InvalidKey(_) => PairingError::InvalidSignature,
            ChallengeError::Replay => PairingError::InvalidSignature,
        })?;

        // Mark as used
        {
            let mut used = self.used_challenges.lock().expect("replay lock");
            used.insert(replay_key);
        }

        // Update last_seen
        let _ = self.device_store.touch_device(device_id, now);

        Ok(())
    }

    /// Create an approval challenge for the given request.
    pub fn create_challenge(&self, request_id: &str, operation_summary: &str) -> ApprovalChallenge {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        ApprovalChallenge {
            server_id: self.server_id.clone(),
            request_id: request_id.to_owned(),
            operation_summary_hash: challenge::hash_operation_summary(operation_summary),
            expires_at: now + CHALLENGE_TTL.as_secs() as i64,
        }
    }

    /// List all paired devices.
    pub fn list_devices(&self) -> Result<Vec<PairedDevice>, PairingError> {
        Ok(self.device_store.list_devices()?)
    }

    /// Remove a paired device.
    pub fn remove_device(&self, device_id: &str) -> Result<PairedDevice, PairingError> {
        Ok(self.device_store.remove_device(device_id)?)
    }

    /// Revoke a paired device (keeps record for audit).
    pub fn revoke_device(&self, device_id: &str) -> Result<(), PairingError> {
        Ok(self.device_store.revoke_device(device_id)?)
    }

    /// Rename a paired device.
    pub fn rename_device(&self, device_id: &str, new_name: &str) -> Result<(), PairingError> {
        Ok(self.device_store.rename_device(device_id, new_name)?)
    }

    /// Get the server ID.
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Clean up expired pairing sessions.
    pub fn cleanup_expired_sessions(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut sessions = self.active_sessions.lock().expect("session lock");
        sessions.retain(|_, session| now <= session.expires_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    fn temp_manager() -> (tempfile::TempDir, PairingManager) {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("paired_devices.json");
        let store = DeviceStore::new(store_path, b"test-key".to_vec());
        let signing_key = SigningKey::generate(&mut OsRng);

        let manager = PairingManager::new("test-server-id".into(), signing_key, 8443, store);
        (dir, manager)
    }

    #[test]
    fn test_generate_pairing_qr_data() {
        let (_dir, manager) = temp_manager();
        let (payload, nonce) = manager.generate_qr_payload();

        // Validate JSON fields
        assert_eq!(payload.server_id, "test-server-id");
        assert_eq!(payload.port, 8443);
        assert!(!payload.public_key.is_empty());
        assert!(!payload.nonce.is_empty());
        assert_eq!(payload.nonce, nonce);

        // Nonce should be 64 hex chars (32 bytes)
        assert_eq!(payload.nonce.len(), 64);
        assert!(payload.nonce.chars().all(|c| c.is_ascii_hexdigit()));

        // Public key should be 64 hex chars (32 bytes)
        assert_eq!(payload.public_key.len(), 64);

        // Verify JSON serialization
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("server_id"));
        assert!(json.contains("public_key"));
        assert!(json.contains("port"));
        assert!(json.contains("nonce"));
    }

    #[test]
    fn test_pairing_nonce_uniqueness() {
        let (_dir, manager) = temp_manager();

        let (p1, _) = manager.generate_qr_payload();
        let (p2, _) = manager.generate_qr_payload();
        let (p3, _) = manager.generate_qr_payload();

        // Each QR code must have a unique nonce
        assert_ne!(p1.nonce, p2.nonce);
        assert_ne!(p1.nonce, p3.nonce);
        assert_ne!(p2.nonce, p3.nonce);
    }

    #[test]
    fn test_pairing_expiry() {
        let (_dir, manager) = temp_manager();
        let (payload, _) = manager.generate_qr_payload();

        // QR should expire after 5 minutes
        let ttl = payload.expires_at - payload.created_at;
        assert_eq!(ttl, 300); // 5 * 60
    }

    #[test]
    fn test_device_registration() {
        let (_dir, manager) = temp_manager();
        let (_payload, nonce) = manager.generate_qr_payload();

        // Generate a device key
        let device_key = SigningKey::generate(&mut OsRng);
        let device_pub = device_key.verifying_key();

        let device = manager
            .complete_pairing(&nonce, device_pub.as_bytes(), "My iPhone 15")
            .unwrap();

        assert_eq!(device.name, "My iPhone 15");
        assert!(!device.device_id.is_empty());
        assert!(!device.revoked);

        // Verify device is stored
        let devices = manager.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, device.device_id);
    }

    #[test]
    fn test_device_revocation() {
        let (_dir, manager) = temp_manager();
        let (_payload, nonce) = manager.generate_qr_payload();

        let device_key = SigningKey::generate(&mut OsRng);
        let device_pub = device_key.verifying_key();

        let device = manager
            .complete_pairing(&nonce, device_pub.as_bytes(), "iPhone")
            .unwrap();

        // Revoke the device
        manager.revoke_device(&device.device_id).unwrap();

        // Create a challenge and sign it
        let challenge = manager.create_challenge("req-1", "test operation");
        let challenge_bytes = construct_challenge_bytes(&challenge);
        let signature = device_key.sign(&challenge_bytes);

        // Verification should fail (device revoked)
        let result = manager.verify_approval(&challenge, &signature.to_bytes(), &device.device_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_devices() {
        let (_dir, manager) = temp_manager();

        // Pair three devices
        for i in 0..3 {
            let (_payload, nonce) = manager.generate_qr_payload();
            let key = SigningKey::generate(&mut OsRng);
            let pub_key = key.verifying_key();
            manager
                .complete_pairing(&nonce, pub_key.as_bytes(), &format!("Device {i}"))
                .unwrap();
        }

        let devices = manager.list_devices().unwrap();
        assert_eq!(devices.len(), 3);
    }

    #[test]
    fn test_replay_rejection() {
        let (_dir, manager) = temp_manager();
        let (_payload, nonce) = manager.generate_qr_payload();

        let device_key = SigningKey::generate(&mut OsRng);
        let device_pub = device_key.verifying_key();

        let device = manager
            .complete_pairing(&nonce, device_pub.as_bytes(), "iPhone")
            .unwrap();

        let challenge = manager.create_challenge("req-1", "test op");
        let challenge_bytes = construct_challenge_bytes(&challenge);
        let signature = device_key.sign(&challenge_bytes);

        // First verification should succeed
        let result = manager.verify_approval(&challenge, &signature.to_bytes(), &device.device_id);
        assert!(result.is_ok());

        // Same challenge+response should be rejected (replay)
        let result = manager.verify_approval(&challenge, &signature.to_bytes(), &device.device_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_rejected() {
        let (_dir, manager) = temp_manager();
        let device_key = SigningKey::generate(&mut OsRng);
        let device_pub = device_key.verifying_key();

        let result = manager.complete_pairing("invalid-nonce", device_pub.as_bytes(), "iPhone");
        assert!(matches!(result, Err(PairingError::InvalidNonce)));
    }

    #[test]
    fn test_consumed_session_rejected() {
        let (_dir, manager) = temp_manager();
        let (_payload, nonce) = manager.generate_qr_payload();

        let key1 = SigningKey::generate(&mut OsRng);
        let pub1 = key1.verifying_key();
        manager
            .complete_pairing(&nonce, pub1.as_bytes(), "iPhone 1")
            .unwrap();

        // Try to use the same nonce again
        let key2 = SigningKey::generate(&mut OsRng);
        let pub2 = key2.verifying_key();
        let result = manager.complete_pairing(&nonce, pub2.as_bytes(), "iPhone 2");
        assert!(matches!(result, Err(PairingError::SessionConsumed)));
    }

    #[test]
    fn test_remove_device_from_manager() {
        let (_dir, manager) = temp_manager();
        let (_payload, nonce) = manager.generate_qr_payload();

        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key();
        let device = manager
            .complete_pairing(&nonce, pubkey.as_bytes(), "iPhone")
            .unwrap();

        let removed = manager.remove_device(&device.device_id).unwrap();
        assert_eq!(removed.device_id, device.device_id);

        let devices = manager.list_devices().unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_rename_device_from_manager() {
        let (_dir, manager) = temp_manager();
        let (_payload, nonce) = manager.generate_qr_payload();

        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key();
        let device = manager
            .complete_pairing(&nonce, pubkey.as_bytes(), "Old Name")
            .unwrap();

        manager
            .rename_device(&device.device_id, "New Name")
            .unwrap();

        let devices = manager.list_devices().unwrap();
        assert_eq!(devices[0].name, "New Name");
    }

    #[test]
    fn test_cleanup_expired_sessions() {
        let (_dir, manager) = temp_manager();

        // Generate some sessions
        let _ = manager.generate_qr_payload();
        let _ = manager.generate_qr_payload();

        // Sessions should exist
        {
            let sessions = manager.active_sessions.lock().unwrap();
            assert_eq!(sessions.len(), 2);
        }

        // Cleanup shouldn't remove non-expired sessions
        manager.cleanup_expired_sessions();
        {
            let sessions = manager.active_sessions.lock().unwrap();
            assert_eq!(sessions.len(), 2);
        }
    }

    #[test]
    fn test_qr_payload_json_roundtrip() {
        let (_dir, manager) = temp_manager();
        let (payload, _) = manager.generate_qr_payload();

        let json = serde_json::to_string(&payload).unwrap();
        let parsed: QrPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.server_id, payload.server_id);
        assert_eq!(parsed.public_key, payload.public_key);
        assert_eq!(parsed.port, payload.port);
        assert_eq!(parsed.nonce, payload.nonce);
        assert_eq!(parsed.created_at, payload.created_at);
        assert_eq!(parsed.expires_at, payload.expires_at);
    }
}
