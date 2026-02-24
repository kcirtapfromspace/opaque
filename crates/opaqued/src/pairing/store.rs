//! Persistent storage for paired iOS devices.
//!
//! Stores paired device records in a JSON file at
//! `~/.config/opaque/paired_devices.json` with an HMAC integrity check
//! using the daemon's master key.

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A successfully paired device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    /// Unique device identifier (UUID).
    pub device_id: String,
    /// Human-readable device name.
    pub name: String,
    /// Ed25519 public key bytes (32 bytes, hex-encoded for JSON).
    pub public_key_hex: String,
    /// Unix timestamp when the device was paired.
    pub paired_at: i64,
    /// Unix timestamp of last successful approval, if any.
    pub last_seen: Option<i64>,
    /// Whether this device has been revoked.
    #[serde(default)]
    pub revoked: bool,
}

impl PairedDevice {
    /// Decode the stored hex public key into an Ed25519 verifying key.
    pub fn verifying_key(&self) -> Result<VerifyingKey, DeviceStoreError> {
        let bytes = hex::decode(&self.public_key_hex)
            .map_err(|e| DeviceStoreError::Integrity(format!("invalid public key hex: {e}")))?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DeviceStoreError::Integrity("public key must be 32 bytes".into()))?;
        VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| DeviceStoreError::Integrity(format!("invalid Ed25519 key: {e}")))
    }
}

/// Errors from the device store.
#[derive(Debug, Error)]
pub enum DeviceStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("integrity check failed: {0}")]
    Integrity(String),

    #[error("device not found: {0}")]
    NotFound(String),

    #[error("device already exists: {0}")]
    AlreadyExists(String),
}

/// On-disk format with HMAC integrity.
#[derive(Debug, Serialize, Deserialize)]
struct DeviceStoreFile {
    devices: Vec<PairedDevice>,
    /// HMAC-SHA256 over the serialized devices list, hex-encoded.
    hmac: String,
}

/// Persistent store for paired devices.
pub struct DeviceStore {
    path: PathBuf,
    /// HMAC key (daemon's master key or derived key).
    hmac_key: Vec<u8>,
}

/// Simple hex encoding (no extra dependency needed).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd-length hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at position {i}: {e}"))
            })
            .collect()
    }
}

impl DeviceStore {
    /// Create a new device store at the given path with the given HMAC key.
    pub fn new(path: PathBuf, hmac_key: Vec<u8>) -> Self {
        Self { path, hmac_key }
    }

    /// Default store path: `~/.config/opaque/paired_devices.json`.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home)
            .join(".config")
            .join("opaque")
            .join("paired_devices.json")
    }

    /// Compute HMAC-SHA256 over the given data.
    fn compute_hmac(&self, data: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC accepts any key size");
        mac.update(data);
        let result = mac.finalize();
        hex::encode(&result.into_bytes())
    }

    /// Load the device list from disk, verifying integrity.
    fn load(&self) -> Result<Vec<PairedDevice>, DeviceStoreError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let contents = std::fs::read_to_string(&self.path)?;
        let store_file: DeviceStoreFile = serde_json::from_str(&contents)?;

        // Verify HMAC
        let devices_json = serde_json::to_string(&store_file.devices)?;
        let expected_hmac = self.compute_hmac(devices_json.as_bytes());
        if expected_hmac != store_file.hmac {
            return Err(DeviceStoreError::Integrity(
                "HMAC mismatch — device store may have been tampered with".into(),
            ));
        }

        Ok(store_file.devices)
    }

    /// Save the device list to disk with HMAC integrity.
    fn save(&self, devices: &[PairedDevice]) -> Result<(), DeviceStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let devices_json = serde_json::to_string(devices)?;
        let hmac = self.compute_hmac(devices_json.as_bytes());
        let store_file = DeviceStoreFile {
            devices: devices.to_vec(),
            hmac,
        };

        let contents = serde_json::to_string_pretty(&store_file)?;

        // Write atomically via temp file
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, contents)?;
        std::fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }

    /// Add a new paired device.
    pub fn add_device(&self, device: PairedDevice) -> Result<(), DeviceStoreError> {
        let mut devices = self.load()?;
        if devices.iter().any(|d| d.device_id == device.device_id) {
            return Err(DeviceStoreError::AlreadyExists(device.device_id));
        }
        devices.push(device);
        self.save(&devices)
    }

    /// List all paired devices (including revoked).
    pub fn list_devices(&self) -> Result<Vec<PairedDevice>, DeviceStoreError> {
        self.load()
    }

    /// Get a specific device by ID.
    pub fn get_device(&self, device_id: &str) -> Result<PairedDevice, DeviceStoreError> {
        let devices = self.load()?;
        devices
            .into_iter()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| DeviceStoreError::NotFound(device_id.to_owned()))
    }

    /// Remove a device by ID.
    pub fn remove_device(&self, device_id: &str) -> Result<PairedDevice, DeviceStoreError> {
        let mut devices = self.load()?;
        let idx = devices
            .iter()
            .position(|d| d.device_id == device_id)
            .ok_or_else(|| DeviceStoreError::NotFound(device_id.to_owned()))?;
        let removed = devices.remove(idx);
        self.save(&devices)?;
        Ok(removed)
    }

    /// Mark a device as revoked (keeps it in the store for audit trail).
    pub fn revoke_device(&self, device_id: &str) -> Result<(), DeviceStoreError> {
        let mut devices = self.load()?;
        let device = devices
            .iter_mut()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| DeviceStoreError::NotFound(device_id.to_owned()))?;
        device.revoked = true;
        self.save(&devices)
    }

    /// Update last_seen timestamp for a device.
    pub fn touch_device(&self, device_id: &str, timestamp: i64) -> Result<(), DeviceStoreError> {
        let mut devices = self.load()?;
        let device = devices
            .iter_mut()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| DeviceStoreError::NotFound(device_id.to_owned()))?;
        device.last_seen = Some(timestamp);
        self.save(&devices)
    }

    /// Rename a device.
    pub fn rename_device(&self, device_id: &str, new_name: &str) -> Result<(), DeviceStoreError> {
        let mut devices = self.load()?;
        let device = devices
            .iter_mut()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| DeviceStoreError::NotFound(device_id.to_owned()))?;
        device.name = new_name.to_owned();
        self.save(&devices)
    }

    /// Get the store file path (for testing/diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, DeviceStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("paired_devices.json");
        let store = DeviceStore::new(path, b"test-hmac-key".to_vec());
        (dir, store)
    }

    fn sample_device(id: &str, name: &str) -> PairedDevice {
        // Generate a valid Ed25519 key for testing
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        PairedDevice {
            device_id: id.to_owned(),
            name: name.to_owned(),
            public_key_hex: hex::encode(verifying_key.as_bytes()),
            paired_at: 1700000000,
            last_seen: None,
            revoked: false,
        }
    }

    #[test]
    fn test_add_and_list_devices() {
        let (_dir, store) = temp_store();
        let device = sample_device("dev-001", "iPhone 15");
        store.add_device(device).unwrap();

        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "dev-001");
        assert_eq!(devices[0].name, "iPhone 15");
    }

    #[test]
    fn test_add_duplicate_device_rejected() {
        let (_dir, store) = temp_store();
        let device = sample_device("dev-001", "iPhone 15");
        store.add_device(device.clone()).unwrap();
        let result = store.add_device(device);
        assert!(matches!(result, Err(DeviceStoreError::AlreadyExists(_))));
    }

    #[test]
    fn test_get_device() {
        let (_dir, store) = temp_store();
        let device = sample_device("dev-002", "iPad Pro");
        store.add_device(device).unwrap();

        let found = store.get_device("dev-002").unwrap();
        assert_eq!(found.name, "iPad Pro");
    }

    #[test]
    fn test_get_device_not_found() {
        let (_dir, store) = temp_store();
        let result = store.get_device("nonexistent");
        assert!(matches!(result, Err(DeviceStoreError::NotFound(_))));
    }

    #[test]
    fn test_remove_device() {
        let (_dir, store) = temp_store();
        store
            .add_device(sample_device("dev-001", "iPhone"))
            .unwrap();
        store.add_device(sample_device("dev-002", "iPad")).unwrap();

        let removed = store.remove_device("dev-001").unwrap();
        assert_eq!(removed.device_id, "dev-001");

        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "dev-002");
    }

    #[test]
    fn test_remove_nonexistent_device() {
        let (_dir, store) = temp_store();
        let result = store.remove_device("nonexistent");
        assert!(matches!(result, Err(DeviceStoreError::NotFound(_))));
    }

    #[test]
    fn test_revoke_device() {
        let (_dir, store) = temp_store();
        store
            .add_device(sample_device("dev-001", "iPhone"))
            .unwrap();

        store.revoke_device("dev-001").unwrap();
        let device = store.get_device("dev-001").unwrap();
        assert!(device.revoked);
    }

    #[test]
    fn test_touch_device() {
        let (_dir, store) = temp_store();
        store
            .add_device(sample_device("dev-001", "iPhone"))
            .unwrap();

        store.touch_device("dev-001", 1700001000).unwrap();
        let device = store.get_device("dev-001").unwrap();
        assert_eq!(device.last_seen, Some(1700001000));
    }

    #[test]
    fn test_rename_device() {
        let (_dir, store) = temp_store();
        store
            .add_device(sample_device("dev-001", "iPhone"))
            .unwrap();

        store.rename_device("dev-001", "My iPhone 15 Pro").unwrap();
        let device = store.get_device("dev-001").unwrap();
        assert_eq!(device.name, "My iPhone 15 Pro");
    }

    #[test]
    fn test_hmac_integrity_check() {
        let (_dir, store) = temp_store();
        store
            .add_device(sample_device("dev-001", "iPhone"))
            .unwrap();

        // Tamper with the file
        let contents = std::fs::read_to_string(store.path()).unwrap();
        let tampered = contents.replace("iPhone", "Evil Device");
        std::fs::write(store.path(), tampered).unwrap();

        let result = store.load();
        assert!(matches!(result, Err(DeviceStoreError::Integrity(_))));
    }

    #[test]
    fn test_empty_store_returns_empty_list() {
        let (_dir, store) = temp_store();
        let devices = store.list_devices().unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_paired_device_verifying_key() {
        let device = sample_device("dev-001", "iPhone");
        let key = device.verifying_key().unwrap();
        assert_eq!(hex::encode(key.as_bytes()), device.public_key_hex);
    }

    #[test]
    fn test_multiple_devices() {
        let (_dir, store) = temp_store();
        store
            .add_device(sample_device("dev-001", "iPhone 15"))
            .unwrap();
        store
            .add_device(sample_device("dev-002", "iPad Pro"))
            .unwrap();
        store
            .add_device(sample_device("dev-003", "iPhone SE"))
            .unwrap();

        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 3);
    }
}
