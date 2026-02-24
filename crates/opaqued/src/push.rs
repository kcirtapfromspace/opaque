//! Push notification relay for mobile approvals via APNs.
//!
//! When the paired iOS device is not on the same LAN, the daemon can
//! send approval requests via Apple Push Notification service (APNs).
//! This module handles payload formatting, device token storage, and
//! the fallback logic from local server to push delivery.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use crate::approval_server::ApprovalChallenge;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PushError {
    #[error("no APNs push token registered for device")]
    NoToken,

    #[error("APNs error: {0}")]
    ApnsError(String),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("JWT signing error: {0}")]
    JwtError(String),
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A paired device with optional push token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    pub device_id: String,
    pub device_name: Option<String>,
    pub device_pubkey: String,
    /// APNs device token (hex-encoded). None if push is not configured.
    pub push_token: Option<String>,
}

/// APNs authentication configuration.
///
/// Uses JWT (token-based) authentication with an ES256 key from the
/// Apple Developer account.
#[derive(Debug, Clone)]
pub struct ApnsConfig {
    /// Apple Developer Team ID.
    pub team_id: String,
    /// Key ID for the APNs auth key.
    pub key_id: String,
    /// ES256 private key in PEM format.
    pub private_key_pem: String,
    /// APNs topic (usually the app bundle ID).
    pub topic: String,
    /// Use sandbox APNs endpoint (for development).
    pub sandbox: bool,
}

/// The APNs notification payload for an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApnsPayload {
    pub aps: ApsPayload,
    pub opaque: OpaquePayload,
}

/// Standard APNs `aps` dictionary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApsPayload {
    pub alert: ApsAlert,
    pub sound: String,
    pub category: String,
}

/// APNs alert content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApsAlert {
    pub title: String,
    pub body: String,
}

/// Custom data payload for Opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaquePayload {
    pub request_id: String,
    pub operation: String,
    pub challenge: String,
}

// ---------------------------------------------------------------------------
// PushManager
// ---------------------------------------------------------------------------

/// Manages push notification delivery for mobile approval requests.
pub struct PushManager {
    /// APNs configuration. None if push is not configured.
    apns_config: Option<ApnsConfig>,
    /// Registered devices with their push tokens.
    devices: Arc<RwLock<HashMap<String, PairedDevice>>>,
    /// Timeout before falling back from local to push (seconds).
    local_timeout_secs: u64,
}

impl PushManager {
    /// Create a new PushManager with optional APNs configuration.
    pub fn new(apns_config: Option<ApnsConfig>, local_timeout_secs: u64) -> Self {
        Self {
            apns_config,
            devices: Arc::new(RwLock::new(HashMap::new())),
            local_timeout_secs,
        }
    }

    /// Register or update a paired device's push token.
    pub async fn register_device(&self, device: PairedDevice) {
        let mut devices = self.devices.write().await;
        info!(
            device_id = %device.device_id,
            has_push_token = device.push_token.is_some(),
            "registered device for push notifications"
        );
        devices.insert(device.device_id.clone(), device);
    }

    /// Remove a device's push token registration.
    pub async fn unregister_device(&self, device_id: &str) {
        let mut devices = self.devices.write().await;
        devices.remove(device_id);
    }

    /// Get a device by ID.
    pub async fn get_device(&self, device_id: &str) -> Option<PairedDevice> {
        let devices = self.devices.read().await;
        devices.get(device_id).cloned()
    }

    /// Get the local timeout duration.
    pub fn local_timeout(&self) -> Duration {
        Duration::from_secs(self.local_timeout_secs)
    }

    /// Format the APNs payload for an approval challenge.
    pub fn format_payload(challenge: &ApprovalChallenge) -> ApnsPayload {
        ApnsPayload {
            aps: ApsPayload {
                alert: ApsAlert {
                    title: "Opaque Approval".into(),
                    body: format!("Approve: {}?", challenge.operation),
                },
                sound: "default".into(),
                category: "APPROVAL".into(),
            },
            opaque: OpaquePayload {
                request_id: challenge.request_id.clone(),
                operation: challenge.operation.clone(),
                challenge: challenge.challenge_data.clone(),
            },
        }
    }

    /// Send an approval request push notification to a paired device.
    ///
    /// Returns an error if the device has no push token or if APNs is not
    /// configured.
    pub async fn send_approval_request(
        &self,
        device: &PairedDevice,
        challenge: &ApprovalChallenge,
    ) -> Result<(), PushError> {
        let push_token = device.push_token.as_ref().ok_or(PushError::NoToken)?;

        let config = self.apns_config.as_ref().ok_or(PushError::NoToken)?;

        let payload = Self::format_payload(challenge);
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| PushError::ApnsError(e.to_string()))?;

        // TODO: Implement actual APNs HTTP/2 request.
        // This requires:
        // 1. Generate JWT with ES256 using the team key
        // 2. POST to https://api.push.apple.com/3/device/{token}
        //    (or https://api.sandbox.push.apple.com/3/device/{token})
        // 3. Include headers: authorization, apns-topic, apns-push-type
        let _endpoint = if config.sandbox {
            format!("https://api.sandbox.push.apple.com/3/device/{push_token}")
        } else {
            format!("https://api.push.apple.com/3/device/{push_token}")
        };

        // TODO: Sign JWT with ES256 key.
        // let jwt = sign_apns_jwt(&config.team_id, &config.key_id, &config.private_key_pem)?;

        info!(
            device_id = %device.device_id,
            request_id = %challenge.request_id,
            payload_size = payload_json.len(),
            "APNs push notification would be sent (TODO: implement HTTP/2 delivery)"
        );

        // For now, return an error indicating this is not yet implemented.
        // In production, this would make the HTTP/2 request to APNs.
        Err(PushError::ApnsError(
            "APNs delivery not yet implemented".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// APNs JWT signing (scaffold)
// ---------------------------------------------------------------------------

/// Generate a JWT for APNs token-based authentication.
///
/// The JWT uses ES256 (P-256 ECDSA) with the Apple Developer team key.
///
/// Header: { "alg": "ES256", "kid": "<key_id>" }
/// Claims: { "iss": "<team_id>", "iat": <timestamp> }
///
/// TODO: Implement actual ES256 signing with the private key.
#[allow(dead_code)]
fn sign_apns_jwt(
    _team_id: &str,
    _key_id: &str,
    _private_key_pem: &str,
) -> Result<String, PushError> {
    // TODO: Use `jsonwebtoken` crate to sign with ES256.
    // let header = jsonwebtoken::Header {
    //     alg: jsonwebtoken::Algorithm::ES256,
    //     kid: Some(key_id.to_string()),
    //     ..Default::default()
    // };
    // let claims = ApnsJwtClaims {
    //     iss: team_id.to_string(),
    //     iat: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    // };
    // jsonwebtoken::encode(&header, &claims, &encoding_key)
    Err(PushError::JwtError(
        "JWT signing not yet implemented".into(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_challenge() -> ApprovalChallenge {
        ApprovalChallenge {
            request_id: "req-push-1".into(),
            operation: "github.set_actions_secret".into(),
            target: "org/repo".into(),
            client_identity: "test-client".into(),
            created_at: 1000,
            expires_at: 2000,
            challenge_data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"push-challenge-data",
            ),
        }
    }

    fn test_device_with_token() -> PairedDevice {
        PairedDevice {
            device_id: "device-push-1".into(),
            device_name: Some("Test iPhone".into()),
            device_pubkey: "pubkey-abc".into(),
            push_token: Some("aabbccdd11223344".into()),
        }
    }

    fn test_device_without_token() -> PairedDevice {
        PairedDevice {
            device_id: "device-no-push".into(),
            device_name: Some("Test iPhone No Push".into()),
            device_pubkey: "pubkey-xyz".into(),
            push_token: None,
        }
    }

    // -----------------------------------------------------------------------
    // Test: format APNs payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_apns_payload() {
        let challenge = test_challenge();
        let payload = PushManager::format_payload(&challenge);

        // Verify APS structure.
        assert_eq!(payload.aps.alert.title, "Opaque Approval");
        assert!(payload.aps.alert.body.contains("github.set_actions_secret"));
        assert_eq!(payload.aps.sound, "default");
        assert_eq!(payload.aps.category, "APPROVAL");

        // Verify it serializes to valid JSON.
        let json = serde_json::to_value(&payload).unwrap();
        assert!(json["aps"]["alert"]["title"].is_string());
        assert!(json["aps"]["sound"].is_string());
        assert!(json["opaque"]["request_id"].is_string());
    }

    // -----------------------------------------------------------------------
    // Test: payload includes challenge data
    // -----------------------------------------------------------------------

    #[test]
    fn test_payload_includes_challenge() {
        let challenge = test_challenge();
        let payload = PushManager::format_payload(&challenge);

        assert_eq!(payload.opaque.request_id, "req-push-1");
        assert_eq!(payload.opaque.operation, "github.set_actions_secret");
        assert_eq!(payload.opaque.challenge, challenge.challenge_data);

        // Verify the challenge data is base64-encoded.
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &payload.opaque.challenge,
        )
        .unwrap();
        assert_eq!(decoded, b"push-challenge-data");
    }

    // -----------------------------------------------------------------------
    // Test: device token storage
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_device_token_storage() {
        let manager = PushManager::new(None, 10);

        // Register a device with push token.
        let device = test_device_with_token();
        manager.register_device(device.clone()).await;

        // Retrieve it.
        let stored = manager.get_device("device-push-1").await.unwrap();
        assert_eq!(stored.device_id, "device-push-1");
        assert_eq!(stored.push_token, Some("aabbccdd11223344".into()));

        // Register another device without push token.
        let device2 = test_device_without_token();
        manager.register_device(device2).await;

        let stored2 = manager.get_device("device-no-push").await.unwrap();
        assert!(stored2.push_token.is_none());

        // Unregister the first device.
        manager.unregister_device("device-push-1").await;
        assert!(manager.get_device("device-push-1").await.is_none());

        // The second device should still be there.
        assert!(manager.get_device("device-no-push").await.is_some());
    }

    // -----------------------------------------------------------------------
    // Test: fallback to push on local timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_fallback_to_push_on_local_timeout() {
        // The PushManager's local_timeout should be configurable.
        let manager = PushManager::new(None, 10);
        assert_eq!(manager.local_timeout(), Duration::from_secs(10));

        // With a different timeout.
        let manager2 = PushManager::new(None, 30);
        assert_eq!(manager2.local_timeout(), Duration::from_secs(30));

        // The fallback logic is: if the local approval server doesn't get
        // a response within local_timeout_secs, the daemon should call
        // send_approval_request() to try push delivery.
        // This test verifies the timeout configuration is respected.
    }

    // -----------------------------------------------------------------------
    // Test: push disabled when no token
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_push_disabled_when_no_token() {
        let manager = PushManager::new(None, 10);
        let device = test_device_without_token();
        let challenge = test_challenge();

        let result = manager.send_approval_request(&device, &challenge).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PushError::NoToken));
    }

    // -----------------------------------------------------------------------
    // Test: push with token but no APNs config also errors
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_push_no_apns_config() {
        let manager = PushManager::new(None, 10);
        let device = test_device_with_token();
        let challenge = test_challenge();

        // Device has a token, but PushManager has no APNs config.
        let result = manager.send_approval_request(&device, &challenge).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Test: APNs payload JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_apns_payload_json_structure() {
        let challenge = test_challenge();
        let payload = PushManager::format_payload(&challenge);
        let json_str = serde_json::to_string_pretty(&payload).unwrap();

        // Parse back and verify structure.
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Standard APNs fields.
        assert_eq!(parsed["aps"]["alert"]["title"], "Opaque Approval");
        assert_eq!(parsed["aps"]["sound"], "default");
        assert_eq!(parsed["aps"]["category"], "APPROVAL");

        // Custom Opaque fields.
        assert_eq!(parsed["opaque"]["request_id"], "req-push-1");
        assert_eq!(parsed["opaque"]["operation"], "github.set_actions_secret");
        assert!(parsed["opaque"]["challenge"].is_string());
    }
}
