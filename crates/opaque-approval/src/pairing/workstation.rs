//! Workstation capability enrollment from trusted daemon configuration.
use super::store::DeviceKind;
use super::*;
use opaque_core::workstation::{
    EnrollmentChallenge, EnrollmentRequest, EnrollmentResponse, WorkstationChallenge, decode_hex,
    enrollment_bytes, hex, verify_signature, workstation_decision_bytes,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationApproverConfig {
    pub public_key_hex: String,
    pub name: String,
    #[serde(default)]
    pub principal_id: Option<String>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl PairingManager {
    /// Called only from trusted startup configuration, never from an HTTP or
    /// agent IPC request. Re-enrollment cannot resurrect a revoked key.
    pub fn enroll_workstation(
        &self,
        config: &WorkstationApproverConfig,
    ) -> Result<PairedDevice, PairingError> {
        let _guard = self
            .workstation_auth
            .lock()
            .map_err(|_| PairingError::InvalidSignature)?;
        let public_key =
            decode_hex::<32>(&config.public_key_hex).map_err(|_| PairingError::InvalidSignature)?;
        VerifyingKey::from_bytes(&public_key).map_err(|_| PairingError::InvalidSignature)?;
        let public_key_hex = hex(&public_key);
        if config.name.is_empty()
            || config.name.len() > 64
            || !config
                .name
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte))
            || config.principal_id.as_ref().is_some_and(|id| {
                id.is_empty()
                    || id.len() > 256
                    || !id.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
            })
        {
            return Err(PairingError::InvalidSignature);
        }
        let existing = self
            .device_store
            .list_devices()?
            .into_iter()
            .find(|device| device.public_key_hex == public_key_hex);
        let device = if let Some(device) = existing {
            if device.kind != DeviceKind::Workstation || device.paired_by != config.principal_id {
                return Err(PairingError::InvalidSignature);
            }
            device
        } else {
            let device = PairedDevice {
                device_id: Uuid::new_v4().to_string(),
                name: config.name.clone(),
                public_key_hex: public_key_hex.clone(),
                paired_at: now(),
                last_seen: None,
                revoked: false,
                paired_by: config.principal_id.clone(),
                token_sha256: None,
                confirmed: true,
                kind: DeviceKind::Workstation,
            };
            self.device_store.add_device(device.clone())?;
            device
        };
        self.workstation_allowlist
            .lock()
            .map_err(|_| PairingError::InvalidSignature)?
            .insert(public_key_hex);
        Ok(device)
    }

    pub(super) fn workstation_allowed(&self, device: &PairedDevice) -> bool {
        device.kind == DeviceKind::Workstation
            && device.confirmed
            && !device.revoked
            && self
                .workstation_allowlist
                .lock()
                .is_ok_and(|keys| keys.contains(&device.public_key_hex))
    }

    pub fn workstation_device(&self, device_id: &str) -> Result<PairedDevice, PairingError> {
        let device = self.device_store.get_device(device_id)?;
        if !self.workstation_allowed(&device) {
            return Err(PairingError::InvalidSignature);
        }
        Ok(device)
    }

    pub fn has_workstation(&self) -> bool {
        self.device_store.list_devices().is_ok_and(|devices| {
            devices
                .iter()
                .any(|device| self.workstation_allowed(device) && device.token_sha256.is_some())
        })
    }

    pub fn begin_workstation_enrollment(
        &self,
        public_key: &str,
    ) -> Result<EnrollmentChallenge, PairingError> {
        let public_key =
            hex(&decode_hex::<32>(public_key).map_err(|_| PairingError::InvalidSignature)?);
        let device = self
            .device_store
            .list_devices()?
            .into_iter()
            .find(|device| device.public_key_hex == public_key)
            .ok_or(PairingError::InvalidSignature)?;
        if !self.workstation_allowed(&device) {
            return Err(PairingError::InvalidSignature);
        }
        let now = now();
        let mut pending = self
            .workstation_enrollments
            .lock()
            .map_err(|_| PairingError::InvalidSignature)?;
        pending.retain(|_, challenge| challenge.expires_at > now);
        if let Some(challenge) = pending.get(&public_key) {
            return Ok(challenge.clone());
        }
        if pending.len() >= 64 {
            return Err(PairingError::InvalidNonce);
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| PairingError::InvalidNonce)?;
        let challenge = EnrollmentChallenge {
            schema_version: 1,
            broker_id: self.server_id.clone(),
            public_key_hex: public_key.clone(),
            nonce: hex(&nonce),
            created_at: now,
            expires_at: now + 120,
        };
        pending.insert(public_key, challenge.clone());
        Ok(challenge)
    }

    pub fn complete_workstation_enrollment(
        &self,
        request: &EnrollmentRequest,
    ) -> Result<EnrollmentResponse, PairingError> {
        let _guard = self
            .workstation_auth
            .lock()
            .map_err(|_| PairingError::InvalidSignature)?;
        let public_key = hex(&decode_hex::<32>(&request.public_key_hex)
            .map_err(|_| PairingError::InvalidSignature)?);
        let mut pending = self
            .workstation_enrollments
            .lock()
            .map_err(|_| PairingError::InvalidSignature)?;
        let challenge = pending.get(&public_key).ok_or(PairingError::InvalidNonce)?;
        challenge
            .validate(&self.server_id, &public_key, now())
            .map_err(|_| PairingError::Expired)?;
        if request.nonce != challenge.nonce {
            return Err(PairingError::InvalidNonce);
        }
        let device = self
            .device_store
            .list_devices()?
            .into_iter()
            .find(|device| device.public_key_hex == public_key)
            .ok_or(PairingError::InvalidSignature)?;
        if !self.workstation_allowed(&device) {
            return Err(PairingError::InvalidSignature);
        }
        verify_signature(
            &public_key,
            &request.signature,
            &enrollment_bytes(challenge),
        )
        .map_err(|_| PairingError::InvalidSignature)?;
        let mut token_bytes = [0; 32];
        getrandom::fill(&mut token_bytes).map_err(|_| PairingError::InvalidNonce)?;
        let token = hex(&token_bytes);
        self.device_store
            .rotate_workstation_token(&device.device_id, sha256_hex(token.as_bytes()))?;
        pending.remove(&public_key);
        Ok(EnrollmentResponse {
            device_id: device.device_id,
            server_id: self.server_id.clone(),
            token,
        })
    }

    /// Verify against an enrolled, currently allowed, unrevoked workstation.
    /// The approval server consumes its pending round atomically afterward.
    pub fn verify_workstation_decision(
        &self,
        challenge: &WorkstationChallenge,
        signature: &str,
        device_id: &str,
        approve: bool,
    ) -> Result<PairedDevice, PairingError> {
        let _guard = self
            .workstation_auth
            .lock()
            .map_err(|_| PairingError::InvalidSignature)?;
        challenge
            .validate(&self.server_id, now())
            .map_err(|_| PairingError::Expired)?;
        let device = self.workstation_device(device_id)?;
        verify_signature(
            &device.public_key_hex,
            signature,
            &workstation_decision_bytes(challenge, approve),
        )
        .map_err(|_| PairingError::InvalidSignature)?;
        let _ = self.device_store.touch_device(device_id, now());
        Ok(device)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn workstation_enrollment_requires_allowed_key_proof_and_preserves_revocation() {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[19; 32]);
        let config = WorkstationApproverConfig {
            public_key_hex: hex(key.verifying_key().as_bytes()),
            name: "Workstation".into(),
            principal_id: Some("human-owner".into()),
        };
        let path = directory.path().join("devices.json");
        let manager = PairingManager::new(
            "opq-test".into(),
            SigningKey::from_bytes(&[20; 32]),
            8443,
            DeviceStore::new(path.clone(), vec![8; 32]),
        );
        assert!(
            manager
                .begin_workstation_enrollment(&config.public_key_hex)
                .is_err()
        );
        let enrolled = manager.enroll_workstation(&config).unwrap();
        assert_eq!(enrolled.kind, DeviceKind::Workstation);
        assert!(!manager.has_workstation());
        let challenge = manager
            .begin_workstation_enrollment(&config.public_key_hex)
            .unwrap();
        assert_eq!(
            manager
                .begin_workstation_enrollment(&config.public_key_hex)
                .unwrap(),
            challenge
        );
        let mut request = EnrollmentRequest {
            public_key_hex: config.public_key_hex.clone(),
            nonce: challenge.nonce.clone(),
            signature: "00".repeat(64),
        };
        assert!(manager.complete_workstation_enrollment(&request).is_err());
        request.signature = hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes());
        let response = manager.complete_workstation_enrollment(&request).unwrap();
        assert!(manager.verify_device_token(&response.device_id, &response.token));
        assert!(manager.has_workstation());
        assert!(manager.complete_workstation_enrollment(&request).is_err());
        manager.revoke_device(&enrolled.device_id).unwrap();
        assert!(!manager.verify_device_token(&response.device_id, &response.token));
        drop(manager);
        let manager = PairingManager::new(
            "opq-test".into(),
            SigningKey::from_bytes(&[20; 32]),
            8443,
            DeviceStore::new(path, vec![8; 32]),
        );
        assert!(manager.enroll_workstation(&config).unwrap().revoked);
        assert!(
            manager
                .begin_workstation_enrollment(&config.public_key_hex)
                .is_err()
        );
    }

    #[test]
    fn removing_trusted_configuration_disables_persisted_workstation_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("devices.json");
        let key = SigningKey::from_bytes(&[22; 32]);
        let config = WorkstationApproverConfig {
            public_key_hex: hex(key.verifying_key().as_bytes()),
            name: "Workstation".into(),
            principal_id: None,
        };
        let manager = PairingManager::new(
            "opq-test".into(),
            SigningKey::from_bytes(&[23; 32]),
            8443,
            DeviceStore::new(path.clone(), vec![8; 32]),
        );
        manager.enroll_workstation(&config).unwrap();
        let challenge = manager
            .begin_workstation_enrollment(&config.public_key_hex)
            .unwrap();
        let request = EnrollmentRequest {
            public_key_hex: config.public_key_hex.clone(),
            nonce: challenge.nonce.clone(),
            signature: hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes()),
        };
        let enrollment = manager.complete_workstation_enrollment(&request).unwrap();
        assert!(manager.has_workstation());
        drop(manager);
        let manager = PairingManager::new(
            "opq-test".into(),
            SigningKey::from_bytes(&[23; 32]),
            8443,
            DeviceStore::new(path, vec![8; 32]),
        );
        assert!(!manager.has_workstation());
        assert!(!manager.verify_device_token(&enrollment.device_id, &enrollment.token));
        assert!(manager.workstation_device(&enrollment.device_id).is_err());
        assert!(
            manager
                .begin_workstation_enrollment(&config.public_key_hex)
                .is_err()
        );
    }

    #[test]
    fn valid_key_cannot_authorize_foreign_broker_expired_or_legacy_challenges() {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[24; 32]);
        let manager = PairingManager::new(
            "opq-test".into(),
            SigningKey::from_bytes(&[25; 32]),
            8443,
            DeviceStore::new(directory.path().join("devices.json"), vec![8; 32]),
        );
        let device = manager
            .enroll_workstation(&WorkstationApproverConfig {
                public_key_hex: hex(key.verifying_key().as_bytes()),
                name: "Workstation".into(),
                principal_id: None,
            })
            .unwrap();
        let valid = WorkstationChallenge {
            schema_version: 1,
            authority: None,
            broker_id: "opq-test".into(),
            approval_id: Uuid::new_v4().to_string(),
            request_id: Uuid::new_v4().to_string(),
            operation: "github.publish_manifest".into(),
            content_hash: "07".repeat(32),
            nonce: "08".repeat(32),
            created_at: now() - 1,
            expires_at: now() + 59,
        };
        let sign = |challenge: &WorkstationChallenge| {
            hex(&key
                .sign(&workstation_decision_bytes(challenge, true))
                .to_bytes())
        };
        assert!(
            manager
                .verify_workstation_decision(&valid, &sign(&valid), &device.device_id, true)
                .is_ok()
        );
        for field in 0..4 {
            let mut invalid = valid.clone();
            match field {
                0 => invalid.broker_id = "other-broker".into(),
                1 => invalid.expires_at = now(),
                2 => invalid.operation = "github.set_actions_secret".into(),
                _ => {
                    // Keep a valid duration wholly in the future. A one-second
                    // lead can elapse while signing or scheduling this test.
                    // Exact clock boundaries are tested by validate with a
                    // supplied observation time in opaque-core.
                    invalid.created_at = i64::MAX - 60;
                    invalid.expires_at = i64::MAX;
                }
            }
            assert!(
                manager
                    .verify_workstation_decision(&invalid, &sign(&invalid), &device.device_id, true)
                    .is_err(),
                "signed mutation {field} was accepted"
            );
        }
        let legacy = manager.create_challenge(&valid.request_id, "Legacy mobile review");
        let signature = key
            .sign(&super::super::challenge::decision_bytes(&legacy, true))
            .to_bytes();
        assert!(
            manager
                .verify_approval(&legacy, &signature, &device.device_id, true)
                .is_err()
        );
    }

    fn fixture() -> (
        tempfile::TempDir,
        PairingManager,
        SigningKey,
        WorkstationApproverConfig,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[61; 32]);
        let config = WorkstationApproverConfig {
            public_key_hex: hex(key.verifying_key().as_bytes()),
            name: "Owned workstation".into(),
            principal_id: Some("human-61".into()),
        };
        let manager = PairingManager::new(
            "opq-test".into(),
            SigningKey::from_bytes(&[62; 32]),
            8443,
            DeviceStore::new(directory.path().join("devices.json"), vec![8; 32]),
        );
        (directory, manager, key, config)
    }

    #[test]
    fn malformed_workstation_names_and_principals_leave_no_persistent_identity() {
        let (_directory, manager, _key, config) = fixture();
        for name in [
            "".to_owned(),
            "x".repeat(65),
            "embedded\nnewline".into(),
            "nönascii".into(),
        ] {
            let mut invalid = config.clone();
            invalid.name = name;
            assert!(matches!(
                manager.enroll_workstation(&invalid),
                Err(PairingError::InvalidSignature)
            ));
            assert!(manager.device_store.list_devices().unwrap().is_empty());
        }
        for principal in [
            "".to_owned(),
            "x".repeat(257),
            "has space".into(),
            "tab\there".into(),
        ] {
            let mut invalid = config.clone();
            invalid.principal_id = Some(principal);
            assert!(matches!(
                manager.enroll_workstation(&invalid),
                Err(PairingError::InvalidSignature)
            ));
            assert!(manager.device_store.list_devices().unwrap().is_empty());
        }
        let device = manager.enroll_workstation(&config).unwrap();
        assert_eq!(device.paired_by, config.principal_id);
        assert_eq!(manager.device_store.list_devices().unwrap().len(), 1);
    }

    #[test]
    fn workstation_key_cannot_change_owner_or_promote_a_phone_identity() {
        let (_directory, manager, _key, config) = fixture();
        let device = manager.enroll_workstation(&config).unwrap();
        let mut renamed = config.clone();
        renamed.name = "Changed display label".into();
        assert_eq!(
            manager.enroll_workstation(&renamed).unwrap().device_id,
            device.device_id
        );
        renamed.principal_id = Some("other-owner".into());
        assert!(matches!(
            manager.enroll_workstation(&renamed),
            Err(PairingError::InvalidSignature)
        ));
        assert_eq!(
            manager
                .device_store
                .get_device(&device.device_id)
                .unwrap()
                .paired_by,
            config.principal_id
        );
        let (_directory, manager, _key, config) = fixture();
        let mut phone = device.clone();
        phone.kind = DeviceKind::Ios;
        manager.device_store.add_device(phone.clone()).unwrap();
        assert!(matches!(
            manager.enroll_workstation(&config),
            Err(PairingError::InvalidSignature)
        ));
        assert_eq!(
            manager
                .device_store
                .get_device(&phone.device_id)
                .unwrap()
                .kind,
            DeviceKind::Ios
        );
        assert!(!manager.workstation_allowed(&phone));
        phone.kind = DeviceKind::Workstation;
        phone.confirmed = false;
        assert!(!manager.workstation_allowed(&phone));
    }

    #[test]
    fn enrollment_capacity_expiry_nonce_and_revocation_preserve_pending_authority() {
        let (_directory, manager, key, config) = fixture();
        let device = manager.enroll_workstation(&config).unwrap();
        let original = manager
            .begin_workstation_enrollment(&config.public_key_hex)
            .unwrap();
        let mut request = EnrollmentRequest {
            public_key_hex: config.public_key_hex.clone(),
            nonce: "ab".repeat(32),
            signature: hex(&key.sign(&enrollment_bytes(&original)).to_bytes()),
        };
        assert!(matches!(
            manager.complete_workstation_enrollment(&request),
            Err(PairingError::InvalidNonce)
        ));
        assert_eq!(
            manager
                .begin_workstation_enrollment(&config.public_key_hex)
                .unwrap(),
            original
        );
        assert!(!manager.has_workstation());
        request.nonce = original.nonce.clone();
        manager.revoke_device(&device.device_id).unwrap();
        assert!(matches!(
            manager.complete_workstation_enrollment(&request),
            Err(PairingError::InvalidSignature)
        ));
        assert!(
            manager
                .device_store
                .get_device(&device.device_id)
                .unwrap()
                .token_sha256
                .is_none()
        );

        let (_directory, manager, _key, config) = fixture();
        manager.enroll_workstation(&config).unwrap();
        let original = manager
            .begin_workstation_enrollment(&config.public_key_hex)
            .unwrap();
        let mut pending = manager.workstation_enrollments.lock().unwrap();
        pending.get_mut(&config.public_key_hex).unwrap().expires_at = now() - 1;
        drop(pending);
        let replacement = manager
            .begin_workstation_enrollment(&config.public_key_hex)
            .unwrap();
        assert_ne!(replacement.nonce, original.nonce);
        assert!(replacement.expires_at > now());
        let mut pending = manager.workstation_enrollments.lock().unwrap();
        pending.clear();
        for index in 0..64 {
            pending.insert(format!("occupied-{index}"), replacement.clone());
        }
        drop(pending);
        assert!(matches!(
            manager.begin_workstation_enrollment(&config.public_key_hex),
            Err(PairingError::InvalidNonce)
        ));
        assert_eq!(manager.workstation_enrollments.lock().unwrap().len(), 64);
        manager
            .workstation_enrollments
            .lock()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()
            .expires_at = now() - 1;
        let admitted = manager
            .begin_workstation_enrollment(&config.public_key_hex)
            .unwrap();
        assert_eq!(admitted.public_key_hex, config.public_key_hex);
        assert_eq!(manager.workstation_enrollments.lock().unwrap().len(), 64);
    }
}
