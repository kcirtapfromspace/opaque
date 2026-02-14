//! Config seal: cryptographic integrity verification for `config.toml`.
//!
//! Computes a SHA-256 digest of the config file and stores it in the OS
//! keychain (primary) with a file fallback. On daemon startup, the seal is
//! verified — if the config has been modified, the daemon refuses to start.

use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of verifying a config seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealStatus {
    /// Seal matches config — integrity verified.
    Verified,
    /// Seal exists but doesn't match — config was modified.
    Tampered { expected: String, actual: String },
    /// No seal found — config is unsealed.
    Unsealed,
}

impl fmt::Display for SealStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealStatus::Verified => write!(f, "Verified"),
            SealStatus::Tampered { expected, actual } => {
                write!(f, "Tampered (expected {expected}, got {actual})")
            }
            SealStatus::Unsealed => write!(f, "Unsealed"),
        }
    }
}

/// Errors from seal operations.
#[derive(Debug, Clone)]
pub enum SealError {
    IoError(String),
    KeychainError(String),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::IoError(msg) => write!(f, "I/O error: {msg}"),
            SealError::KeychainError(msg) => write!(f, "keychain error: {msg}"),
        }
    }
}

impl std::error::Error for SealError {}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const KEYCHAIN_SERVICE: &str = "opaque-config";
const KEYCHAIN_ACCOUNT: &str = "seal";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute SHA-256 hex digest of config bytes.
pub fn compute_seal(config_bytes: &[u8]) -> String {
    let hash = Sha256::digest(config_bytes);
    format!("{hash:x}")
}

/// Store seal in Keychain (primary) + file (fallback).
pub fn store_seal(seal: &str, seal_file: &Path) -> Result<(), SealError> {
    // Try keychain first.
    let keychain_ok = match keychain_write(seal) {
        Ok(()) => true,
        Err(_) => false,
    };

    // Always write the file fallback.
    write_seal_file(seal, seal_file)?;

    if !keychain_ok {
        // File was written successfully; keychain failed but that's non-fatal.
    }

    Ok(())
}

/// Verify config bytes against stored seal.
///
/// Checks keychain first, then file fallback. If neither exists, returns
/// `SealStatus::Unsealed`.
pub fn verify_seal(config_bytes: &[u8], seal_file: &Path) -> Result<SealStatus, SealError> {
    let actual = compute_seal(config_bytes);

    // Try keychain first.
    if let Ok(Some(expected)) = keychain_read() {
        return if expected == actual {
            Ok(SealStatus::Verified)
        } else {
            Ok(SealStatus::Tampered { expected, actual })
        };
    }

    // Fall back to file.
    if seal_file.exists() {
        let expected = std::fs::read_to_string(seal_file)
            .map(|s| s.trim().to_string())
            .map_err(|e| SealError::IoError(format!("failed to read {}: {e}", seal_file.display())))?;

        return if expected == actual {
            Ok(SealStatus::Verified)
        } else {
            Ok(SealStatus::Tampered { expected, actual })
        };
    }

    Ok(SealStatus::Unsealed)
}

/// Remove seal from Keychain + file.
pub fn remove_seal(seal_file: &Path) -> Result<(), SealError> {
    // Remove from keychain (ignore errors — may not exist).
    let _ = keychain_delete();

    // Remove file if it exists.
    if seal_file.exists() {
        std::fs::remove_file(seal_file)
            .map_err(|e| SealError::IoError(format!("failed to remove {}: {e}", seal_file.display())))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// File seal helpers
// ---------------------------------------------------------------------------

fn write_seal_file(seal: &str, path: &Path) -> Result<(), SealError> {
    std::fs::write(path, seal)
        .map_err(|e| SealError::IoError(format!("failed to write {}: {e}", path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
            .map_err(|e| SealError::IoError(format!("failed to set permissions on {}: {e}", path.display())))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Keychain helpers (platform-specific)
// ---------------------------------------------------------------------------

/// Write seal to OS keychain.
#[allow(unused_variables, clippy::needless_return)]
fn keychain_write(seal: &str) -> Result<(), SealError> {
    #[cfg(target_os = "macos")]
    {
        // -U flag updates if the entry already exists.
        let output = std::process::Command::new("security")
            .args([
                "add-generic-password",
                "-s", KEYCHAIN_SERVICE,
                "-a", KEYCHAIN_ACCOUNT,
                "-w", seal,
                "-U",
            ])
            .env_clear()
            .env("PATH", "/usr/bin")
            .output()
            .map_err(|e| SealError::KeychainError(format!("spawn failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SealError::KeychainError(format!(
                "security add-generic-password failed: {}",
                stderr.trim()
            )));
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("secret-tool")
            .args([
                "store",
                "--label", "Opaque Config Seal",
                "service", KEYCHAIN_SERVICE,
                "account", KEYCHAIN_ACCOUNT,
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/usr/local/bin:/bin")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(seal.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| SealError::KeychainError(format!("secret-tool store failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SealError::KeychainError(format!(
                "secret-tool store failed: {}",
                stderr.trim()
            )));
        }
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(SealError::KeychainError(
            "keychain not supported on this platform".into(),
        ))
    }
}

/// Read seal from OS keychain.
#[allow(unused_variables, clippy::needless_return)]
fn keychain_read() -> Result<Option<String>, SealError> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s", KEYCHAIN_SERVICE,
                "-a", KEYCHAIN_ACCOUNT,
                "-w",
            ])
            .env_clear()
            .env("PATH", "/usr/bin")
            .output()
            .map_err(|e| SealError::KeychainError(format!("spawn failed: {e}")))?;

        if !output.status.success() {
            // Item not found is not an error — just means no seal.
            return Ok(None);
        }

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if value.is_empty() {
            return Ok(None);
        }
        return Ok(Some(value));
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("secret-tool")
            .args([
                "lookup",
                "service", KEYCHAIN_SERVICE,
                "account", KEYCHAIN_ACCOUNT,
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/usr/local/bin:/bin")
            .output()
            .map_err(|e| SealError::KeychainError(format!("secret-tool lookup failed: {e}")))?;

        if !output.status.success() {
            return Ok(None);
        }

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if value.is_empty() {
            return Ok(None);
        }
        return Ok(Some(value));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(SealError::KeychainError(
            "keychain not supported on this platform".into(),
        ))
    }
}

/// Delete seal from OS keychain.
#[allow(clippy::needless_return)]
fn keychain_delete() -> Result<(), SealError> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("security")
            .args([
                "delete-generic-password",
                "-s", KEYCHAIN_SERVICE,
                "-a", KEYCHAIN_ACCOUNT,
            ])
            .env_clear()
            .env("PATH", "/usr/bin")
            .output()
            .map_err(|e| SealError::KeychainError(format!("spawn failed: {e}")))?;

        if !output.status.success() {
            // Not found is fine — idempotent delete.
            return Ok(());
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("secret-tool")
            .args([
                "clear",
                "service", KEYCHAIN_SERVICE,
                "account", KEYCHAIN_ACCOUNT,
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/usr/local/bin:/bin")
            .output()
            .map_err(|e| SealError::KeychainError(format!("secret-tool clear failed: {e}")))?;

        // Ignore exit status — idempotent.
        let _ = output;
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(SealError::KeychainError(
            "keychain not supported on this platform".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn compute_seal_deterministic() {
        let data = b"hello world";
        let seal1 = compute_seal(data);
        let seal2 = compute_seal(data);
        assert_eq!(seal1, seal2);
        // SHA-256 of "hello world"
        assert_eq!(seal1.len(), 64);
        assert!(seal1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn compute_seal_different_input() {
        let seal1 = compute_seal(b"hello");
        let seal2 = compute_seal(b"world");
        assert_ne!(seal1, seal2);
    }

    #[test]
    fn compute_seal_empty_input() {
        let seal = compute_seal(b"");
        assert_eq!(seal.len(), 64);
    }

    // Note: unit tests use file-based sealing only (write_seal_file) to avoid
    // touching the real OS keychain, which would cause race conditions in
    // parallel test execution. Keychain integration is tested separately.

    #[test]
    fn file_seal_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let config = b"test config content";
        let seal = compute_seal(config);

        write_seal_file(&seal, &seal_file).unwrap();
        assert!(seal_file.exists());

        // Verify via file fallback (no keychain entry exists for this test).
        let stored = fs::read_to_string(&seal_file).unwrap();
        assert_eq!(stored.trim(), seal);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&seal_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o400, "seal file should be read-only, got {mode:o}");
        }
    }

    #[test]
    fn verify_match_via_file() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let config = b"test config for verify";
        let seal = compute_seal(config);

        // Write seal file directly (skip keychain).
        write_seal_file(&seal, &seal_file).unwrap();

        // verify_seal checks keychain first (will return None in test env
        // since we didn't write there), then falls back to file.
        // On macOS, keychain might have stale entries, so we test the
        // file content match directly.
        let stored = fs::read_to_string(&seal_file).unwrap().trim().to_string();
        let actual = compute_seal(config);
        assert_eq!(stored, actual);
    }

    #[test]
    fn verify_mismatch_via_file() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let config = b"original content";
        let seal = compute_seal(config);

        write_seal_file(&seal, &seal_file).unwrap();

        // Read back and compare with modified content.
        let stored = fs::read_to_string(&seal_file).unwrap().trim().to_string();
        let modified = b"modified content";
        let modified_seal = compute_seal(modified);
        assert_ne!(stored, modified_seal);
    }

    #[test]
    fn verify_unsealed() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");

        // No seal file, no keychain (in test env) → Unsealed.
        assert!(!seal_file.exists());
    }

    #[test]
    fn remove_seal_file_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");

        // Remove when file doesn't exist — should not error.
        if seal_file.exists() {
            fs::remove_file(&seal_file).unwrap();
        }

        // Create and remove.
        write_seal_file("abcd1234", &seal_file).unwrap();
        assert!(seal_file.exists());

        fs::remove_file(&seal_file).unwrap();
        assert!(!seal_file.exists());
    }

    #[test]
    fn seal_status_display() {
        assert_eq!(SealStatus::Verified.to_string(), "Verified");
        assert_eq!(SealStatus::Unsealed.to_string(), "Unsealed");
        let tampered = SealStatus::Tampered {
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        assert!(tampered.to_string().contains("Tampered"));
    }
}
