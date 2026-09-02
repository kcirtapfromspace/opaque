//! Delegation-token signing key management.
//!
//! A 32-byte Ed25519 seed stored at `<state_dir>/identity.key`, mode 0600,
//! created on first use — the same custody pattern as the audit chain key
//! (`<db>.hmac`). Same-uid caveat applies: this is honest attribution and
//! tamper evidence, not tamper prevention, until the daemon runs under a
//! dedicated service account.

use std::io;
use std::path::Path;

use ed25519_dalek::SigningKey;

/// Load the Ed25519 signing key from `path`, creating it (0600) if missing.
pub fn load_or_create_signing_key(path: &Path) -> io::Result<SigningKey> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "identity key {} is {} bytes, expected 32 — refusing to guess",
                        path.display(),
                        bytes.len()
                    ),
                )
            })?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)
                .map_err(|e| io::Error::other(format!("csprng failure: {e}")))?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, seed)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_key_with_0600_and_reloads_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let k1 = load_or_create_signing_key(&path).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let k2 = load_or_create_signing_key(&path).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn rejects_wrong_length_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        std::fs::write(&path, b"short").unwrap();
        let err = load_or_create_signing_key(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
