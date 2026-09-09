//! Credentials live on the trusted workstation, never in the agent environment.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationState {
    pub schema_version: u32,
    pub name: String,
    pub public_key_hex: String,
    pub enrollment: Option<BrokerEnrollment>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerEnrollment {
    pub endpoint: String,
    pub broker_id: String,
    pub tls_fingerprint: String,
    pub device_id: String,
    pub token: String,
}

impl std::fmt::Debug for BrokerEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerEnrollment")
            .field("endpoint", &self.endpoint)
            .field("broker_id", &self.broker_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

pub fn validate_directory(path: &Path) -> Result<PathBuf, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "workstation custody directory unavailable")?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(
            "workstation custody must be an owned, private 0700 directory without symlinks".into(),
        );
    }
    path.canonicalize()
        .map_err(|_| "workstation custody path unavailable".into())
}

fn open_private(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "workstation credential unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "workstation credential metadata unavailable")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("workstation credential must be an owned private file".into());
    }
    Ok(file)
}

fn create_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "workstation credential already exists or cannot be created")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "workstation credential could not be saved".into())
}

pub fn initialize(directory: &Path, name: &str) -> Result<WorkstationState, String> {
    if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        return Err("workstation name must be 1–64 printable ASCII characters".into());
    }
    if !directory.exists() {
        std::fs::create_dir(directory)
            .map_err(|_| "create the parent directory before initializing workstation custody")?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot secure workstation custody directory")?;
    }
    let directory = validate_directory(directory)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| "workstation randomness unavailable")?;
    let key = SigningKey::from_bytes(&seed);
    let state = WorkstationState {
        schema_version: 1,
        name: name.into(),
        public_key_hex: opaque_core::workstation::hex(key.verifying_key().as_bytes()),
        enrollment: None,
    };
    create_private(&directory.join("workstation.key"), seed.as_ref())?;
    create_private(
        &directory.join("workstation.json"),
        &serde_json::to_vec_pretty(&state).map_err(|_| "state encoding failed")?,
    )?;
    Ok(state)
}

pub fn load(directory: &Path) -> Result<(WorkstationState, SigningKey), String> {
    let directory = validate_directory(directory)?;
    let mut bytes = Zeroizing::new(Vec::new());
    open_private(&directory.join("workstation.key"))?
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| "workstation key could not be read")?;
    let seed: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid workstation key length")?;
    let key = SigningKey::from_bytes(seed);
    let mut json = Zeroizing::new(Vec::new());
    open_private(&directory.join("workstation.json"))?
        .take(16 * 1024 + 1)
        .read_to_end(&mut json)
        .map_err(|_| "workstation state could not be read")?;
    if json.len() > 16 * 1024 {
        return Err("workstation state is too large".into());
    }
    let state: WorkstationState =
        serde_json::from_slice(&json).map_err(|_| "invalid workstation state")?;
    if state.schema_version != 1
        || state.public_key_hex != opaque_core::workstation::hex(key.verifying_key().as_bytes())
    {
        return Err("workstation state/key mismatch".into());
    }
    Ok((state, key))
}

pub fn save(directory: &Path, state: &WorkstationState) -> Result<(), String> {
    let directory = validate_directory(directory)?;
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).map_err(|_| "randomness unavailable")?;
    let temporary = directory.join(format!(".state-{}", opaque_core::workstation::hex(&nonce)));
    let bytes =
        Zeroizing::new(serde_json::to_vec_pretty(state).map_err(|_| "state encoding failed")?);
    create_private(&temporary, &bytes)?;
    std::fs::rename(&temporary, directory.join("workstation.json"))
        .map_err(|_| "workstation state replacement failed")?;
    File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "workstation custody sync failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_separate_private_files_and_mismatched_or_readable_custody_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("approver");
        let state = initialize(&path, "Test workstation").unwrap();
        assert_eq!(load(&path).unwrap().0.public_key_hex, state.public_key_hex);
        assert!(initialize(&path, "Another").is_err());
        std::fs::set_permissions(
            path.join("workstation.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn symlink_hardlink_and_mismatched_key_custody_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("approver");
        initialize(&path, "Test workstation").unwrap();
        std::os::unix::fs::symlink(&path, temporary.path().join("alias")).unwrap();
        assert!(load(&temporary.path().join("alias")).is_err());
        let key_path = path.join("workstation.key");
        let second_link = path.join("hardlink");
        std::fs::hard_link(&key_path, &second_link).unwrap();
        assert!(load(&path).is_err());
        std::fs::remove_file(&second_link).unwrap();
        std::fs::rename(&key_path, path.join("original.key")).unwrap();
        std::os::unix::fs::symlink(path.join("original.key"), &key_path).unwrap();
        assert!(load(&path).is_err());
        std::fs::remove_file(&key_path).unwrap();
        create_private(&key_path, &[0; 32]).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn bearer_is_private_after_save_and_never_in_debug_output() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("approver");
        let mut state = initialize(&path, "Test workstation").unwrap();
        state.enrollment = Some(BrokerEnrollment {
            endpoint: "https://localhost:8443".into(),
            broker_id: "broker".into(),
            tls_fingerprint: "00".repeat(32),
            device_id: "device".into(),
            token: "never-print-this-token".into(),
        });
        save(&path, &state).unwrap();
        let loaded = load(&path).unwrap().0;
        assert_eq!(
            loaded.enrollment.as_ref().unwrap().token,
            "never-print-this-token"
        );
        assert!(!format!("{loaded:?}").contains("never-print-this-token"));
        assert_eq!(
            std::fs::metadata(path.join("workstation.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load(&path).is_err());
    }
}
