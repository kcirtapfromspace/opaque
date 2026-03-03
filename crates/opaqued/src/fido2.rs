//! FIDO2/WebAuthn hardware key approval factor.
//!
//! Provides credential registration, authentication challenge/response,
//! and credential storage for hardware security keys (FIDO2/WebAuthn).
//!
//! Since Opaque is a CLI daemon (no browser), this module implements the
//! WebAuthn data structures and signature verification directly using
//! ECDSA P-256 (the standard FIDO2 authenticator curve).
//!
//! In production, the USB HID transport layer would use CTAP2 to communicate
//! with physical keys. For testability, the transport is abstracted behind
//! the [`Fido2Transport`] trait.

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from the FIDO2 subsystem.
#[derive(Debug, Error)]
pub enum Fido2Error {
    #[error("no FIDO2 device found")]
    NoDevice,

    #[error("user cancelled the FIDO2 operation")]
    UserCancelled,

    #[error("invalid signature in FIDO2 assertion")]
    InvalidSignature,

    #[error("sign counter replay detected: got {got}, expected > {expected}")]
    CounterReplay { got: u32, expected: u32 },

    #[error("user presence flag not set in authenticator data")]
    UserPresenceNotSet,

    #[error("credential storage error: {0}")]
    StorageError(String),

    #[error("credential not found: {0}")]
    CredentialNotFound(String),

    #[error("invalid authenticator data: {0}")]
    InvalidAuthData(String),

    #[error("FIDO2 transport error: {0}")]
    TransportError(String),
}

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

/// A stored FIDO2 credential (public key + metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Credential {
    /// Unique credential identifier (base64url-encoded).
    pub credential_id: String,

    /// ECDSA P-256 public key in SEC1 uncompressed format (base64url-encoded).
    pub public_key: String,

    /// Last known sign counter value.
    pub counter: u32,

    /// When this credential was registered.
    pub created_at: DateTime<Utc>,

    /// Human-readable label for this key.
    pub label: String,
}

/// A FIDO2 authentication assertion returned by the authenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Assertion {
    /// Credential ID that was used (base64url-encoded).
    pub credential_id: String,

    /// Raw authenticator data bytes (base64url-encoded).
    pub authenticator_data: String,

    /// The client data JSON (base64url-encoded).
    pub client_data_json: String,

    /// ECDSA P-256 signature over (authenticator_data || SHA-256(client_data_json))
    /// (base64url-encoded, DER format).
    pub signature: String,
}

/// A FIDO2 registration response from the authenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2RegistrationResponse {
    /// Credential ID (base64url-encoded).
    pub credential_id: String,

    /// ECDSA P-256 public key in SEC1 uncompressed format (base64url-encoded).
    pub public_key: String,

    /// Initial sign counter.
    pub counter: u32,

    /// Raw authenticator data (base64url-encoded).
    pub authenticator_data: String,
}

/// A WebAuthn challenge sent to the authenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Challenge {
    /// Random challenge bytes (base64url-encoded).
    pub challenge: String,

    /// Relying party ID (domain-style identifier).
    pub rp_id: String,

    /// For authentication: which credential IDs are acceptable.
    #[serde(default)]
    pub allowed_credentials: Vec<String>,
}

// ---------------------------------------------------------------------------
// Authenticator data parsing
// ---------------------------------------------------------------------------

/// Parsed authenticator data flags.
#[derive(Debug, Clone)]
pub struct AuthenticatorData {
    /// RP ID hash (32 bytes).
    pub rp_id_hash: [u8; 32],
    /// Flags byte.
    pub flags: u8,
    /// Sign counter (big-endian u32).
    pub counter: u32,
}

impl AuthenticatorData {
    /// Minimum authenticator data length: 32 (rpIdHash) + 1 (flags) + 4 (counter) = 37.
    const MIN_LENGTH: usize = 37;

    /// Parse raw authenticator data bytes.
    pub fn parse(data: &[u8]) -> Result<Self, Fido2Error> {
        if data.len() < Self::MIN_LENGTH {
            return Err(Fido2Error::InvalidAuthData(format!(
                "authenticator data too short: {} bytes, need at least {}",
                data.len(),
                Self::MIN_LENGTH
            )));
        }

        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&data[..32]);

        let flags = data[32];
        let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

        Ok(Self {
            rp_id_hash,
            flags,
            counter,
        })
    }

    /// Check if the User Presence (UP) flag is set (bit 0).
    pub fn user_present(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

// ---------------------------------------------------------------------------
// FIDO2 Transport trait (for mockability)
// ---------------------------------------------------------------------------

/// Abstraction over the physical FIDO2 transport (USB HID / NFC / etc.).
///
/// In production, this communicates with a real hardware key via CTAP2.
/// In tests, a mock implementation provides simulated authenticator responses.
pub trait Fido2Transport: Send + Sync + std::fmt::Debug {
    /// Perform a registration ceremony: create a new credential.
    fn register(
        &self,
        challenge: &Fido2Challenge,
        user_name: &str,
    ) -> Result<Fido2RegistrationResponse, Fido2Error>;

    /// Perform an authentication ceremony: sign a challenge.
    fn authenticate(&self, challenge: &Fido2Challenge) -> Result<Fido2Assertion, Fido2Error>;
}

// ---------------------------------------------------------------------------
// Credential store
// ---------------------------------------------------------------------------

/// File-based FIDO2 credential storage.
///
/// Stores credentials as JSON at `~/.config/opaque/fido2_credentials.json`.
/// The file is integrity-checked via HMAC-SHA256.
#[derive(Debug)]
pub struct Fido2CredentialStore {
    path: PathBuf,
}

/// On-disk representation with integrity check.
#[derive(Debug, Serialize, Deserialize)]
struct CredentialFile {
    credentials: Vec<Fido2Credential>,
    /// HMAC-SHA256 of the serialized credentials array (hex-encoded).
    /// The HMAC key is derived from the username as a basic integrity check.
    integrity_tag: String,
}

impl Fido2CredentialStore {
    /// Create a new credential store at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Default credential store path.
    pub fn default_path() -> PathBuf {
        let config_dir = dirs_path();
        config_dir.join("fido2_credentials.json")
    }

    /// Compute HMAC key from username (deterministic per-user).
    fn hmac_key() -> Vec<u8> {
        let username = std::env::var("USER").unwrap_or_else(|_| "opaque".into());
        let mut hasher = Sha256::new();
        hasher.update(b"opaque-fido2-integrity-");
        hasher.update(username.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Compute integrity tag for the given credentials.
    fn compute_tag(credentials: &[Fido2Credential]) -> Result<String, Fido2Error> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let key = Self::hmac_key();
        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|e| Fido2Error::StorageError(format!("HMAC key error: {e}")))?;
        let data = serde_json::to_string(credentials)
            .map_err(|e| Fido2Error::StorageError(format!("serialization error: {e}")))?;
        mac.update(data.as_bytes());
        let result = mac.finalize();
        Ok(hex_encode(result.into_bytes()))
    }

    /// Load credentials from disk. Returns empty vec if file doesn't exist.
    pub fn load(&self) -> Result<Vec<Fido2Credential>, Fido2Error> {
        if !self.path.exists() {
            return Ok(vec![]);
        }

        let data = std::fs::read_to_string(&self.path)
            .map_err(|e| Fido2Error::StorageError(format!("read error: {e}")))?;
        let file: CredentialFile = serde_json::from_str(&data)
            .map_err(|e| Fido2Error::StorageError(format!("parse error: {e}")))?;

        // Verify integrity.
        let expected_tag = Self::compute_tag(&file.credentials)?;
        if file.integrity_tag != expected_tag {
            return Err(Fido2Error::StorageError(
                "integrity check failed: credential file may have been tampered with".into(),
            ));
        }

        Ok(file.credentials)
    }

    /// Save credentials to disk.
    pub fn save(&self, credentials: &[Fido2Credential]) -> Result<(), Fido2Error> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Fido2Error::StorageError(format!("mkdir error: {e}")))?;
        }

        let tag = Self::compute_tag(credentials)?;
        let file = CredentialFile {
            credentials: credentials.to_vec(),
            integrity_tag: tag,
        };

        let data = serde_json::to_string_pretty(&file)
            .map_err(|e| Fido2Error::StorageError(format!("serialization error: {e}")))?;

        std::fs::write(&self.path, data)
            .map_err(|e| Fido2Error::StorageError(format!("write error: {e}")))?;

        // Set restrictive permissions (owner-only read/write).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, perms)
                .map_err(|e| Fido2Error::StorageError(format!("chmod error: {e}")))?;
        }

        Ok(())
    }

    /// Add a credential to the store.
    pub fn add(&self, credential: Fido2Credential) -> Result<(), Fido2Error> {
        let mut creds = self.load()?;
        creds.push(credential);
        self.save(&creds)
    }

    /// Remove a credential by ID. Returns the removed credential.
    pub fn remove(&self, credential_id: &str) -> Result<Fido2Credential, Fido2Error> {
        let mut creds = self.load()?;
        let idx = creds
            .iter()
            .position(|c| c.credential_id == credential_id)
            .ok_or_else(|| Fido2Error::CredentialNotFound(credential_id.to_string()))?;
        let removed = creds.remove(idx);
        self.save(&creds)?;
        Ok(removed)
    }

    /// Update the counter for a credential.
    pub fn update_counter(&self, credential_id: &str, new_counter: u32) -> Result<(), Fido2Error> {
        let mut creds = self.load()?;
        let cred = creds
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
            .ok_or_else(|| Fido2Error::CredentialNotFound(credential_id.to_string()))?;
        cred.counter = new_counter;
        self.save(&creds)
    }

    /// Find a credential by ID.
    pub fn find(&self, credential_id: &str) -> Result<Fido2Credential, Fido2Error> {
        let creds = self.load()?;
        creds
            .into_iter()
            .find(|c| c.credential_id == credential_id)
            .ok_or_else(|| Fido2Error::CredentialNotFound(credential_id.to_string()))
    }
}

/// Get the opaque config directory path.
fn dirs_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config").join("opaque")
    } else {
        PathBuf::from("/tmp/opaque")
    }
}

/// Simple hex encoding utility.
fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// FIDO2 Manager
// ---------------------------------------------------------------------------

/// Central FIDO2 manager that coordinates registration and authentication
/// ceremonies with the transport layer and credential store.
#[derive(Debug)]
pub struct Fido2Manager {
    store: Fido2CredentialStore,
    transport: Box<dyn Fido2Transport>,
    rp_id: String,
}

impl Fido2Manager {
    /// Create a new FIDO2 manager.
    pub fn new(
        store: Fido2CredentialStore,
        transport: Box<dyn Fido2Transport>,
        rp_id: String,
    ) -> Self {
        Self {
            store,
            transport,
            rp_id,
        }
    }

    /// Generate a registration challenge.
    pub fn registration_challenge(&self) -> Result<Fido2Challenge, Fido2Error> {
        let challenge_bytes = generate_challenge()?;
        Ok(Fido2Challenge {
            challenge: URL_SAFE_NO_PAD.encode(challenge_bytes),
            rp_id: self.rp_id.clone(),
            allowed_credentials: vec![],
        })
    }

    /// Register a new hardware key.
    pub fn register(&self, user_name: &str, label: &str) -> Result<Fido2Credential, Fido2Error> {
        let challenge = self.registration_challenge()?;
        let response = self.transport.register(&challenge, user_name)?;

        // Validate the response: parse authenticator data, check UP flag.
        let auth_data_bytes = URL_SAFE_NO_PAD
            .decode(&response.authenticator_data)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("base64 decode: {e}")))?;
        let auth_data = AuthenticatorData::parse(&auth_data_bytes)?;

        if !auth_data.user_present() {
            return Err(Fido2Error::UserPresenceNotSet);
        }

        // Verify the RP ID hash matches.
        let expected_rp_hash = Sha256::digest(self.rp_id.as_bytes());
        if auth_data.rp_id_hash != expected_rp_hash.as_slice() {
            return Err(Fido2Error::InvalidAuthData("RP ID hash mismatch".into()));
        }

        // Verify the public key is a valid P-256 point.
        let pk_bytes = URL_SAFE_NO_PAD
            .decode(&response.public_key)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("public key decode: {e}")))?;
        let _vk = VerifyingKey::from_sec1_bytes(&pk_bytes)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("invalid P-256 key: {e}")))?;

        let credential = Fido2Credential {
            credential_id: response.credential_id,
            public_key: response.public_key,
            counter: response.counter,
            created_at: Utc::now(),
            label: label.to_string(),
        };

        self.store.add(credential.clone())?;
        Ok(credential)
    }

    /// Generate an authentication challenge for stored credentials.
    pub fn authentication_challenge(
        &self,
        credential_ids: &[String],
    ) -> Result<Fido2Challenge, Fido2Error> {
        let challenge_bytes = generate_challenge()?;
        Ok(Fido2Challenge {
            challenge: URL_SAFE_NO_PAD.encode(challenge_bytes),
            rp_id: self.rp_id.clone(),
            allowed_credentials: credential_ids.to_vec(),
        })
    }

    /// Authenticate using a hardware key.
    ///
    /// Generates a challenge, prompts the user to touch the key, then
    /// verifies the assertion signature and counter.
    pub fn authenticate(&self) -> Result<Fido2Assertion, Fido2Error> {
        let credentials = self.store.load()?;
        if credentials.is_empty() {
            return Err(Fido2Error::NoDevice);
        }

        let credential_ids: Vec<String> = credentials
            .iter()
            .map(|c| c.credential_id.clone())
            .collect();
        let challenge = self.authentication_challenge(&credential_ids)?;
        let assertion = self.transport.authenticate(&challenge)?;

        // Verify the assertion.
        let credential = self.store.find(&assertion.credential_id)?;
        self.verify_assertion(&assertion, &credential)?;

        // Update the counter.
        let auth_data_bytes = URL_SAFE_NO_PAD
            .decode(&assertion.authenticator_data)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("base64 decode: {e}")))?;
        let auth_data = AuthenticatorData::parse(&auth_data_bytes)?;
        self.store
            .update_counter(&assertion.credential_id, auth_data.counter)?;

        Ok(assertion)
    }

    /// Verify an assertion response against a stored credential.
    pub fn verify_assertion(
        &self,
        assertion: &Fido2Assertion,
        credential: &Fido2Credential,
    ) -> Result<(), Fido2Error> {
        // 1. Decode authenticator data.
        let auth_data_bytes = URL_SAFE_NO_PAD
            .decode(&assertion.authenticator_data)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("base64 decode: {e}")))?;
        let auth_data = AuthenticatorData::parse(&auth_data_bytes)?;

        // 2. Check User Presence flag.
        if !auth_data.user_present() {
            return Err(Fido2Error::UserPresenceNotSet);
        }

        // 3. Check RP ID hash.
        let expected_rp_hash = Sha256::digest(self.rp_id.as_bytes());
        if auth_data.rp_id_hash != expected_rp_hash.as_slice() {
            return Err(Fido2Error::InvalidAuthData("RP ID hash mismatch".into()));
        }

        // 4. Counter replay protection.
        // If stored counter is > 0, the new counter must be strictly greater.
        if credential.counter > 0 && auth_data.counter <= credential.counter {
            return Err(Fido2Error::CounterReplay {
                got: auth_data.counter,
                expected: credential.counter,
            });
        }

        // 5. Verify signature.
        // WebAuthn signature is over: authenticator_data || SHA-256(client_data_json)
        let client_data_bytes = URL_SAFE_NO_PAD
            .decode(&assertion.client_data_json)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("client data decode: {e}")))?;
        let client_data_hash = Sha256::digest(&client_data_bytes);

        let mut signed_data = auth_data_bytes.clone();
        signed_data.extend_from_slice(&client_data_hash);

        let pk_bytes = URL_SAFE_NO_PAD
            .decode(&credential.public_key)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("public key decode: {e}")))?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("invalid P-256 key: {e}")))?;

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(&assertion.signature)
            .map_err(|e| Fido2Error::InvalidAuthData(format!("signature decode: {e}")))?;
        let signature =
            Signature::from_der(&sig_bytes).map_err(|_| Fido2Error::InvalidSignature)?;

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| Fido2Error::InvalidSignature)?;

        Ok(())
    }

    /// List all stored credentials.
    pub fn list_credentials(&self) -> Result<Vec<Fido2Credential>, Fido2Error> {
        self.store.load()
    }

    /// Remove a credential by ID.
    pub fn remove_credential(&self, credential_id: &str) -> Result<Fido2Credential, Fido2Error> {
        self.store.remove(credential_id)
    }
}

/// Generate 32 random bytes for a challenge.
fn generate_challenge() -> Result<[u8; 32], Fido2Error> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| Fido2Error::TransportError(format!("RNG error: {e}")))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::elliptic_curve::rand_core::OsRng;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Mock transport
    // -----------------------------------------------------------------------

    /// A mock FIDO2 transport that simulates a hardware key.
    /// Uses a real P-256 keypair for signature generation.
    #[derive(Debug, Clone)]
    struct MockTransport {
        signing_key: SigningKey,
        rp_id: String,
        /// Counter increments on each authentication.
        counter: Arc<Mutex<u32>>,
        /// If true, omit the UP flag from authenticator data.
        omit_user_presence: bool,
    }

    impl MockTransport {
        fn new(rp_id: &str) -> Self {
            let signing_key = SigningKey::random(&mut OsRng);
            Self {
                signing_key,
                rp_id: rp_id.to_string(),
                counter: Arc::new(Mutex::new(0)),
                omit_user_presence: false,
            }
        }

        fn public_key_bytes(&self) -> Vec<u8> {
            let point = self.signing_key.verifying_key().to_encoded_point(false);
            point.as_bytes().to_vec()
        }

        fn build_authenticator_data(&self, counter_val: u32) -> Vec<u8> {
            let rp_hash = Sha256::digest(self.rp_id.as_bytes());
            let mut data = Vec::with_capacity(37);
            data.extend_from_slice(&rp_hash);

            let flags: u8 = if self.omit_user_presence { 0x00 } else { 0x01 };
            data.push(flags);
            data.extend_from_slice(&counter_val.to_be_bytes());
            data
        }
    }

    impl Fido2Transport for MockTransport {
        fn register(
            &self,
            _challenge: &Fido2Challenge,
            _user_name: &str,
        ) -> Result<Fido2RegistrationResponse, Fido2Error> {
            let mut cred_id = [0u8; 32];
            getrandom::fill(&mut cred_id)
                .map_err(|e| Fido2Error::TransportError(format!("RNG: {e}")))?;

            let auth_data = self.build_authenticator_data(0);

            Ok(Fido2RegistrationResponse {
                credential_id: URL_SAFE_NO_PAD.encode(cred_id),
                public_key: URL_SAFE_NO_PAD.encode(self.public_key_bytes()),
                counter: 0,
                authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
            })
        }

        fn authenticate(&self, challenge: &Fido2Challenge) -> Result<Fido2Assertion, Fido2Error> {
            if challenge.allowed_credentials.is_empty() {
                return Err(Fido2Error::NoDevice);
            }
            let credential_id = challenge.allowed_credentials[0].clone();

            let counter_val = {
                let mut c = self.counter.lock().unwrap();
                *c += 1;
                *c
            };
            let auth_data = self.build_authenticator_data(counter_val);

            // Build client data JSON.
            let client_data = serde_json::json!({
                "type": "webauthn.get",
                "challenge": challenge.challenge,
                "origin": format!("opaque://{}", challenge.rp_id),
            });
            let client_data_json = serde_json::to_string(&client_data)
                .map_err(|e| Fido2Error::TransportError(format!("json: {e}")))?;

            // Sign: authenticator_data || SHA-256(client_data_json).
            let client_data_hash = Sha256::digest(client_data_json.as_bytes());
            let mut signed_data = auth_data.clone();
            signed_data.extend_from_slice(&client_data_hash);

            let (signature, _) = self.signing_key.sign(&signed_data);

            Ok(Fido2Assertion {
                credential_id,
                authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
                client_data_json: URL_SAFE_NO_PAD.encode(client_data_json.as_bytes()),
                signature: URL_SAFE_NO_PAD.encode(signature.to_der()),
            })
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn temp_store() -> (Fido2CredentialStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fido2_credentials.json");
        (Fido2CredentialStore::new(path), dir)
    }

    fn test_manager(transport: MockTransport) -> (Fido2Manager, tempfile::TempDir) {
        let (store, dir) = temp_store();
        let rp_id = transport.rp_id.clone();
        let manager = Fido2Manager::new(store, Box::new(transport), rp_id);
        (manager, dir)
    }

    /// Build authenticator data bytes for a given rp_id, flags, and counter.
    fn build_auth_data(rp_id: &str, up: bool, counter: u32) -> Vec<u8> {
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&rp_hash);
        data.push(if up { 0x01 } else { 0x00 });
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    /// Create a signed assertion using a fresh keypair.
    fn make_signed_assertion(
        rp_id: &str,
        up: bool,
        counter: u32,
        credential_id: &str,
    ) -> (Fido2Assertion, Fido2Credential) {
        let sk = SigningKey::random(&mut OsRng);
        let pk_bytes = sk.verifying_key().to_encoded_point(false);

        let cred = Fido2Credential {
            credential_id: credential_id.into(),
            public_key: URL_SAFE_NO_PAD.encode(pk_bytes.as_bytes()),
            counter: 0,
            created_at: Utc::now(),
            label: "test".into(),
        };

        let auth_data = build_auth_data(rp_id, up, counter);
        let client_data = r#"{"type":"webauthn.get","challenge":"test-challenge"}"#;
        let client_data_hash = Sha256::digest(client_data.as_bytes());

        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        let (sig, _) = sk.sign(&signed_data);

        let assertion = Fido2Assertion {
            credential_id: credential_id.into(),
            authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
            signature: URL_SAFE_NO_PAD.encode(sig.to_der()),
        };

        (assertion, cred)
    }

    // -----------------------------------------------------------------------
    // Registration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_registration_challenge_generation() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        let challenge = manager.registration_challenge().unwrap();
        assert_eq!(challenge.rp_id, "opaque.local");
        assert!(challenge.allowed_credentials.is_empty());

        // Challenge should be 32 bytes base64url-encoded.
        let decoded = URL_SAFE_NO_PAD.decode(&challenge.challenge).unwrap();
        assert_eq!(decoded.len(), 32);

        // Each challenge should be unique (with overwhelming probability).
        let challenge2 = manager.registration_challenge().unwrap();
        assert_ne!(challenge.challenge, challenge2.challenge);
    }

    #[test]
    fn test_registration_response_validation() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        let credential = manager.register("testuser", "My YubiKey").unwrap();
        assert_eq!(credential.label, "My YubiKey");
        assert_eq!(credential.counter, 0);
        assert!(!credential.credential_id.is_empty());
        assert!(!credential.public_key.is_empty());

        // Verify the public key is a valid P-256 point.
        let pk_bytes = URL_SAFE_NO_PAD.decode(&credential.public_key).unwrap();
        VerifyingKey::from_sec1_bytes(&pk_bytes).expect("valid P-256 key");

        // Credential should be stored.
        let stored = manager.list_credentials().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].credential_id, credential.credential_id);
    }

    // -----------------------------------------------------------------------
    // Authentication tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_authentication_challenge_generation() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        // Register first.
        let cred = manager.register("testuser", "key1").unwrap();

        let challenge = manager
            .authentication_challenge(std::slice::from_ref(&cred.credential_id))
            .unwrap();
        assert_eq!(challenge.rp_id, "opaque.local");
        assert_eq!(challenge.allowed_credentials.len(), 1);
        assert_eq!(challenge.allowed_credentials[0], cred.credential_id);

        // Challenge should be 32 bytes.
        let decoded = URL_SAFE_NO_PAD.decode(&challenge.challenge).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_authentication_response_validation() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        // Register.
        let _cred = manager.register("testuser", "key1").unwrap();

        // Authenticate.
        let assertion = manager.authenticate().unwrap();
        assert!(!assertion.credential_id.is_empty());
        assert!(!assertion.signature.is_empty());

        // Counter should have been updated in the store.
        let stored = manager.list_credentials().unwrap();
        assert!(stored[0].counter > 0);
    }

    // -----------------------------------------------------------------------
    // Credential storage tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_credential_storage_and_retrieval() {
        let (store, _dir) = temp_store();

        // Initially empty.
        let creds = store.load().unwrap();
        assert!(creds.is_empty());

        // Add a credential.
        let cred = Fido2Credential {
            credential_id: "test-cred-id".into(),
            public_key: "test-pk".into(),
            counter: 42,
            created_at: Utc::now(),
            label: "Test Key".into(),
        };
        store.add(cred).unwrap();

        // Reload and verify.
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].credential_id, "test-cred-id");
        assert_eq!(loaded[0].counter, 42);
        assert_eq!(loaded[0].label, "Test Key");
    }

    #[test]
    fn test_multiple_credentials() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        let cred1 = manager.register("user", "YubiKey 5").unwrap();
        let cred2 = manager.register("user", "YubiKey 5C").unwrap();

        let creds = manager.list_credentials().unwrap();
        assert_eq!(creds.len(), 2);
        assert_ne!(cred1.credential_id, cred2.credential_id);

        // Remove one.
        let removed = manager.remove_credential(&cred1.credential_id).unwrap();
        assert_eq!(removed.credential_id, cred1.credential_id);

        let remaining = manager.list_credentials().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].credential_id, cred2.credential_id);
    }

    // -----------------------------------------------------------------------
    // Signature verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_signature_rejected() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        let cred = manager.register("user", "key").unwrap();
        let credentials = manager.list_credentials().unwrap();

        // Build a fake assertion signed with a DIFFERENT key.
        let bad_sk = SigningKey::random(&mut OsRng);
        let auth_data = build_auth_data("opaque.local", true, 2);
        let client_data = r#"{"type":"webauthn.get","challenge":"test"}"#;
        let client_data_hash = Sha256::digest(client_data.as_bytes());
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        let (bad_sig, _) = bad_sk.sign(&signed_data);

        let bad_assertion = Fido2Assertion {
            credential_id: cred.credential_id.clone(),
            authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
            signature: URL_SAFE_NO_PAD.encode(bad_sig.to_der()),
        };

        let result = manager.verify_assertion(&bad_assertion, &credentials[0]);
        assert!(matches!(result, Err(Fido2Error::InvalidSignature)));
    }

    // -----------------------------------------------------------------------
    // Counter replay protection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_counter_replay_protection() {
        let (assertion, mut cred) = make_signed_assertion("opaque.local", true, 3, "replay-test");

        // Stored counter is 5 — assertion counter 3 should be rejected.
        cred.counter = 5;

        let (store, _dir) = temp_store();
        let transport = MockTransport::new("opaque.local");
        let mgr = Fido2Manager::new(store, Box::new(transport), "opaque.local".into());

        let result = mgr.verify_assertion(&assertion, &cred);
        assert!(matches!(
            result,
            Err(Fido2Error::CounterReplay {
                got: 3,
                expected: 5
            })
        ));
    }

    #[test]
    fn test_counter_equal_rejected() {
        let (assertion, mut cred) = make_signed_assertion("opaque.local", true, 5, "counter-eq");

        // Same counter: should also be rejected.
        cred.counter = 5;

        let (store, _dir) = temp_store();
        let transport = MockTransport::new("opaque.local");
        let mgr = Fido2Manager::new(store, Box::new(transport), "opaque.local".into());

        let result = mgr.verify_assertion(&assertion, &cred);
        assert!(matches!(
            result,
            Err(Fido2Error::CounterReplay {
                got: 5,
                expected: 5
            })
        ));
    }

    // -----------------------------------------------------------------------
    // User presence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_user_presence_required() {
        let mut transport = MockTransport::new("opaque.local");
        transport.omit_user_presence = true;
        let (manager, _dir) = test_manager(transport);

        // Registration should fail if UP flag not set.
        let result = manager.register("user", "key");
        assert!(matches!(result, Err(Fido2Error::UserPresenceNotSet)));
    }

    #[test]
    fn test_user_presence_required_in_assertion() {
        // Create a valid signed assertion but with UP=0.
        let (assertion, cred) = make_signed_assertion("opaque.local", false, 1, "up-test");

        let (store, _dir) = temp_store();
        let transport = MockTransport::new("opaque.local");
        let mgr = Fido2Manager::new(store, Box::new(transport), "opaque.local".into());

        let result = mgr.verify_assertion(&assertion, &cred);
        assert!(matches!(result, Err(Fido2Error::UserPresenceNotSet)));
    }

    // -----------------------------------------------------------------------
    // Integrity / storage edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_credential_store_integrity_check() {
        let (store, _dir) = temp_store();

        let cred = Fido2Credential {
            credential_id: "integrity-test".into(),
            public_key: "pk".into(),
            counter: 0,
            created_at: Utc::now(),
            label: "key".into(),
        };
        store.add(cred).unwrap();

        // Tamper with the file.
        let data = std::fs::read_to_string(&store.path).unwrap();
        let tampered = data.replace("integrity-test", "tampered-id!!");
        std::fs::write(&store.path, tampered).unwrap();

        // Load should fail integrity check.
        let result = store.load();
        assert!(
            matches!(result, Err(Fido2Error::StorageError(ref msg)) if msg.contains("integrity"))
        );
    }

    #[test]
    fn test_remove_nonexistent_credential() {
        let (store, _dir) = temp_store();
        let result = store.remove("nonexistent");
        assert!(matches!(result, Err(Fido2Error::CredentialNotFound(_))));
    }

    #[test]
    fn test_authenticator_data_too_short() {
        let result = AuthenticatorData::parse(&[0u8; 10]);
        assert!(matches!(result, Err(Fido2Error::InvalidAuthData(_))));
    }

    // -----------------------------------------------------------------------
    // End-to-end flow test
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_registration_and_authentication_flow() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        // Register two keys.
        let _cred1 = manager.register("alice", "YubiKey 5").unwrap();
        let _cred2 = manager.register("alice", "YubiKey 5C NFC").unwrap();

        assert_eq!(manager.list_credentials().unwrap().len(), 2);

        // Authenticate (the mock will use the first allowed credential).
        let assertion = manager.authenticate().unwrap();

        // Verify counter was updated.
        let creds = manager.list_credentials().unwrap();
        let used_cred = creds
            .iter()
            .find(|c| c.credential_id == assertion.credential_id)
            .unwrap();
        assert!(used_cred.counter > 0);
    }

    #[test]
    fn test_authenticate_no_credentials_returns_no_device() {
        let transport = MockTransport::new("opaque.local");
        let (manager, _dir) = test_manager(transport);

        // No credentials registered — should fail.
        let result = manager.authenticate();
        assert!(matches!(result, Err(Fido2Error::NoDevice)));
    }

    #[test]
    fn test_credential_find() {
        let (store, _dir) = temp_store();

        let cred = Fido2Credential {
            credential_id: "findme".into(),
            public_key: "pk".into(),
            counter: 7,
            created_at: Utc::now(),
            label: "test".into(),
        };
        store.add(cred).unwrap();

        let found = store.find("findme").unwrap();
        assert_eq!(found.counter, 7);

        let not_found = store.find("missing");
        assert!(not_found.is_err());
    }

    #[test]
    fn test_update_counter() {
        let (store, _dir) = temp_store();

        let cred = Fido2Credential {
            credential_id: "ctr-test".into(),
            public_key: "pk".into(),
            counter: 1,
            created_at: Utc::now(),
            label: "test".into(),
        };
        store.add(cred).unwrap();

        store.update_counter("ctr-test", 42).unwrap();
        let updated = store.find("ctr-test").unwrap();
        assert_eq!(updated.counter, 42);
    }
}
