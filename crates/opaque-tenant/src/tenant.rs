//! One tenant per independently deployed broker custody boundary.
//!
//! Call after verifying the sealed configuration and custody root, before
//! opening any identity, task, audit, approval, or provider state. This module
//! binds that state lineage; it does not create OS accounts, mount isolation,
//! or an authorization boundary between two processes sharing filesystem access.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use opaque_core::identity::PrincipalId;
use opaque_core::tenant::{TenantBinding, TenantError, TenantId};
use serde::Deserialize;
use thiserror::Error;

pub const BINDING_FILE: &str = "tenant.binding.json";
pub const LOCK_FILE: &str = "tenant.binding.lock";

/// Trusted, sealed daemon configuration. There is no RPC equivalent.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub id: TenantId,
}

#[derive(Debug, Error)]
pub enum TenantBoundaryError {
    #[error("tenant mode requires trust_domain.enforce=true and a separately isolated broker")]
    EnforcementRequired,
    #[error(
        "tenant state must be an absolute, owned private directory without a substituted symlink"
    )]
    UnsafeState,
    #[error(
        "existing broker state has no tenant binding; use fresh tenant custody or an explicit offline migration"
    )]
    UnboundExistingState,
    #[error("configured tenant differs from the immutable broker state binding")]
    TenantChanged,
    #[error("tenant custody is already open by another broker")]
    Locked,
    #[error("tenant binding or lock is invalid; automatic rebinding is refused")]
    Corrupt,
    #[error(transparent)]
    Binding(#[from] TenantError),
    #[error("tenant state I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

struct CustodyLock(File);

impl Drop for CustodyLock {
    fn drop(&mut self) {
        // Explicitly unlock the shared open-file description before closing
        // it: a concurrent fork must not hold this broker lease until exec.
        // SAFETY: the lock owns a valid descriptor; LOCK_UN takes no pointer.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub struct TenantBoundary {
    binding: TenantBinding,
    _lock: CustodyLock,
}

impl std::fmt::Debug for TenantBoundary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantBoundary")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl TenantBoundary {
    pub fn open(
        config: &TenantConfig,
        data_dir: &Path,
        trust_domain_enforced: bool,
    ) -> Result<Self, TenantBoundaryError> {
        if !trust_domain_enforced {
            return Err(TenantBoundaryError::EnforcementRequired);
        }
        let metadata = std::fs::symlink_metadata(data_dir)?;
        if !data_dir.is_absolute()
            || !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7077 != 0
        {
            return Err(TenantBoundaryError::UnsafeState);
        }
        // The caller already verified ancestor custody; canonicalization also
        // accommodates OS-owned aliases such as macOS /var -> /private/var.
        let state_dir = data_dir.canonicalize()?;
        let lock_path = state_dir.join(LOCK_FILE);
        let existed = match std::fs::symlink_metadata(&lock_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(lock_path)?;
        validate_private_file(&lock)?;
        // SAFETY: lock owns a live descriptor; these are valid flock flags.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::WouldBlock {
                Err(TenantBoundaryError::Locked)
            } else {
                Err(error.into())
            };
        }
        let lock = CustodyLock(lock);
        let marker = state_dir.join(BINDING_FILE);
        let binding = match read_binding(&marker) {
            Ok(binding) => binding,
            Err(TenantBoundaryError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                // The durable lock file also serves as an initialization
                // witness. Deleting a binding cannot silently mint a new one.
                if existed || has_prior_state(&state_dir)? {
                    return Err(TenantBoundaryError::UnboundExistingState);
                }
                let binding = TenantBinding::new(config.id.clone(), uuid::Uuid::new_v4())?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&marker)?;
                let bytes = serde_json::to_vec_pretty(&binding)
                    .map_err(|_| TenantBoundaryError::Corrupt)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                File::open(&state_dir)?.sync_all()?;
                binding
            }
            Err(error) => return Err(error),
        };
        if binding.tenant_id != config.id {
            return Err(TenantBoundaryError::TenantChanged);
        }
        Ok(Self {
            binding,
            _lock: lock,
        })
    }

    pub fn binding(&self) -> &TenantBinding {
        &self.binding
    }

    pub fn require_binding(&self, offered: &TenantBinding) -> Result<(), TenantBoundaryError> {
        Ok(self.binding.require_same(offered)?)
    }

    pub fn owner_key(&self, uid: u32, principal: Option<&PrincipalId>) -> String {
        self.binding.owner_key(uid, principal)
    }
}

fn validate_private_file(file: &File) -> Result<(), TenantBoundaryError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7177 != 0
    {
        return Err(TenantBoundaryError::Corrupt);
    }
    Ok(())
}

fn read_binding(path: &Path) -> Result<TenantBinding, TenantBoundaryError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    validate_private_file(&file)?;
    if file.metadata()?.len() > 4096 {
        return Err(TenantBoundaryError::Corrupt);
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(TenantBoundaryError::Corrupt);
    }
    let binding: TenantBinding =
        serde_json::from_slice(&bytes).map_err(|_| TenantBoundaryError::Corrupt)?;
    binding
        .validate()
        .map_err(|_| TenantBoundaryError::Corrupt)?;
    Ok(binding)
}

fn has_prior_state(directory: &Path) -> Result<bool, TenantBoundaryError> {
    // A new deployment may already have its sealed configuration and the
    // empty approval directory made by startup. Nothing else is adopted.
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(true);
        };
        if name == LOCK_FILE {
            continue;
        }
        let metadata = entry.path().symlink_metadata()?;
        if metadata.file_type().is_symlink() {
            return Ok(true);
        }
        if name == "approval"
            && metadata.is_dir()
            && std::fs::read_dir(entry.path())?.next().is_none()
        {
            continue;
        }
        if metadata.is_file()
            && (name.ends_with(".toml")
                || matches!(name, "config.seal" | "config.seal.key" | "seal.key"))
        {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn config(id: &str) -> TenantConfig {
        TenantConfig {
            id: TenantId::parse(id).unwrap(),
        }
    }

    #[test]
    fn tenant_binding_survives_restart_and_cannot_be_changed_or_reset() {
        let directory = private_dir();
        let first = TenantBoundary::open(&config("tenant-a"), directory.path(), true).unwrap();
        let binding = first.binding().clone();
        assert!(matches!(
            TenantBoundary::open(&config("tenant-a"), directory.path(), true),
            Err(TenantBoundaryError::Locked)
        ));
        drop(first);
        let reopened = TenantBoundary::open(&config("tenant-a"), directory.path(), true).unwrap();
        assert_eq!(reopened.binding(), &binding);
        drop(reopened);
        assert!(matches!(
            TenantBoundary::open(&config("tenant-b"), directory.path(), true),
            Err(TenantBoundaryError::TenantChanged)
        ));
        std::fs::remove_file(directory.path().join(BINDING_FILE)).unwrap();
        assert!(matches!(
            TenantBoundary::open(&config("tenant-a"), directory.path(), true),
            Err(TenantBoundaryError::UnboundExistingState)
        ));
    }

    #[test]
    fn same_uid_or_same_tenant_label_does_not_share_resource_authority() {
        let a_dir = private_dir();
        let b_dir = private_dir();
        let a = TenantBoundary::open(&config("tenant-a"), a_dir.path(), true).unwrap();
        let b = TenantBoundary::open(&config("tenant-b"), b_dir.path(), true).unwrap();
        assert!(b.require_binding(a.binding()).is_err());
        assert_ne!(a.owner_key(7382, None), b.owner_key(7382, None));
        assert_ne!(
            a.binding().approval_context(),
            b.binding().approval_context()
        );
        let other_dir = private_dir();
        let same_tenant =
            TenantBoundary::open(&config("tenant-a"), other_dir.path(), true).unwrap();
        assert!(same_tenant.require_binding(a.binding()).is_err());
    }

    #[test]
    fn tenant_mode_rejects_shared_uid_mode_and_unbound_existing_state() {
        let directory = private_dir();
        assert!(matches!(
            TenantBoundary::open(&config("tenant-a"), directory.path(), false),
            Err(TenantBoundaryError::EnforcementRequired)
        ));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        std::fs::write(directory.path().join("tasks.db"), b"existing custody").unwrap();
        assert!(matches!(
            TenantBoundary::open(&config("tenant-a"), directory.path(), true),
            Err(TenantBoundaryError::UnboundExistingState)
        ));
        assert!(!directory.path().join(BINDING_FILE).exists());
    }

    #[test]
    fn tenant_marker_rejects_corruption_symlinks_hardlinks_and_readable_modes() {
        for failure in 0..4 {
            let directory = private_dir();
            let boundary =
                TenantBoundary::open(&config("tenant-a"), directory.path(), true).unwrap();
            drop(boundary);
            let marker = directory.path().join(BINDING_FILE);
            match failure {
                0 => std::fs::write(&marker, b"invalid JSON").unwrap(),
                1 => {
                    std::fs::rename(&marker, directory.path().join("original")).unwrap();
                    std::os::unix::fs::symlink(directory.path().join("original"), &marker).unwrap();
                }
                2 => std::fs::hard_link(&marker, directory.path().join("second-link")).unwrap(),
                _ => std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644))
                    .unwrap(),
            }
            assert!(TenantBoundary::open(&config("tenant-a"), directory.path(), true).is_err());
        }
    }

    #[test]
    fn sealed_bootstrap_files_are_allowed_but_existing_approval_state_is_not() {
        let directory = private_dir();
        std::fs::create_dir(directory.path().join("approval")).unwrap();
        std::fs::write(directory.path().join("config.toml"), b"trusted config").unwrap();
        std::fs::write(directory.path().join("config.seal"), b"trusted seal").unwrap();
        TenantBoundary::open(&config("tenant-a"), directory.path(), true).unwrap();
        let other = private_dir();
        std::fs::create_dir(other.path().join("approval")).unwrap();
        std::fs::write(
            other.path().join("approval/paired_devices.json"),
            b"existing authority",
        )
        .unwrap();
        assert!(matches!(
            TenantBoundary::open(&config("tenant-b"), other.path(), true),
            Err(TenantBoundaryError::UnboundExistingState)
        ));
    }
}
