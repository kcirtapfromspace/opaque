//! Shared 32-byte key-file custody: create with CSPRNG on first use, 0600,
//! load thereafter. Backs the seal key, the pairing-store integrity key, and
//! any future file-custody key. Under the trust-domain split these files are
//! exactly what the agent's uid cannot read — which is what upgrades the
//! constructs they key from tamper-evident to tamper-proof.

use std::io;
use std::path::Path;

/// Load the 32-byte key at `path`, creating it (0600, CSPRNG) if absent.
///
/// A present-but-wrong-length file is corruption and errors — it never
/// silently regenerates, because a regenerated key would orphan everything
/// the old key authenticated.
pub fn load_or_create_key_file(path: &Path) -> io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("key file {} is corrupt (wrong length)", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key)
        .map_err(|e| io::Error::other(format!("failed to generate key: {e}")))?;
    write_key_file(path, &key)?;
    Ok(key)
}

/// Load the 32-byte key at `path` if it exists (`Ok(None)` when absent).
pub fn load_key_file(path: &Path) -> io::Result<Option<[u8; 32]>> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Some(key))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("key file {} is corrupt (wrong length)", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn write_key_file(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(key)
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, key: &[u8; 32]) -> io::Result<()> {
    std::fs::write(path, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("some.key");
        let first = load_or_create_key_file(&path).unwrap();
        let second = load_or_create_key_file(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(load_key_file(&path).unwrap(), Some(first));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn corrupt_key_errors_rather_than_regenerating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("some.key");
        std::fs::write(&path, b"short").unwrap();
        assert!(load_or_create_key_file(&path).is_err());
        assert!(load_key_file(&path).is_err());
        // The corrupt file is left in place for the operator to inspect.
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    #[test]
    fn absent_key_is_none_for_load_only() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_key_file(&dir.path().join("nope.key")).unwrap(), None);
    }
}
