//! Config seal: cryptographic integrity verification for `config.toml`.
//!
//! Two seal formats exist:
//!
//! - **Keyed (`opqs1:` prefix, current):** HMAC-SHA256 over the config bytes
//!   with a 32-byte key held beside the seal (`<seal>.key`, 0600, part of the
//!   daemon's custody set). Unforgeable by any principal that cannot read the
//!   key — under the trust-domain split that includes the agent, which is
//!   what makes the seal tamper-*proof* rather than tamper-evident there.
//! - **Legacy (bare hex):** unkeyed SHA-256. Anyone who can write the seal
//!   file can recompute it after modifying the config, so it only detects
//!   accidental drift. Verified for backward compatibility and reported as
//!   [`SealStatus::VerifiedLegacy`] so callers can ratchet: the daemon warns
//!   in shared-uid mode and refuses under `trust_domain.enforce`.
//!
//! The seal value itself also lands in the OS keychain (primary) with the
//! file as fallback; the *key* is file-custody only, because at a shared uid
//! the keychain is readable by the same processes as the file anyway, and
//! under the split the file is exactly what the agent cannot reach.

use std::fmt;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of verifying a config seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealStatus {
    /// Keyed seal matches config — integrity verified, unforgeable without
    /// the seal key.
    Verified,
    /// Legacy unkeyed seal matches config. Detects accidental drift only —
    /// any writer can recompute it. Callers decide whether that is enough.
    VerifiedLegacy,
    /// Seal exists but doesn't match — config was modified.
    Tampered { expected: String, actual: String },
    /// The seal is keyed but the seal key is gone. Verification is
    /// impossible; treat as custody breakage, not as "unsealed".
    KeyMissing,
    /// No seal found — config is unsealed.
    Unsealed,
}

impl fmt::Display for SealStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealStatus::Verified => write!(f, "Verified"),
            SealStatus::VerifiedLegacy => write!(f, "Verified (legacy unkeyed seal)"),
            SealStatus::Tampered { expected, actual } => {
                write!(f, "Tampered (expected {expected}, got {actual})")
            }
            SealStatus::KeyMissing => write!(f, "Keyed seal present but seal key missing"),
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

/// Prefix identifying a keyed (HMAC) seal value.
pub const KEYED_SEAL_PREFIX: &str = "opqs1:";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the legacy (unkeyed) SHA-256 hex digest of config bytes.
///
/// Kept for verifying pre-existing seals; new seals are keyed — see
/// [`compute_seal_keyed`].
pub fn compute_seal(config_bytes: &[u8]) -> String {
    let hash = Sha256::digest(config_bytes);
    format!("{hash:x}")
}

/// Compute the keyed seal value: `opqs1:<hex hmac-sha256>`.
pub fn compute_seal_keyed(config_bytes: &[u8], key: &[u8; 32]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(config_bytes);
    let out = mac.finalize().into_bytes();
    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    format!("{KEYED_SEAL_PREFIX}{hex}")
}

/// Path of the seal key beside its seal file: `config.seal` → `config.seal.key`.
pub fn seal_key_path(seal_file: &Path) -> PathBuf {
    let mut s = seal_file.as_os_str().to_owned();
    s.push(".key");
    PathBuf::from(s)
}

/// Load the seal key if present. `Ok(None)` means no key file exists.
pub fn load_seal_key(seal_file: &Path) -> Result<Option<[u8; 32]>, SealError> {
    crate::keyfile::load_key_file(&seal_key_path(seal_file))
        .map_err(|e| SealError::IoError(e.to_string()))
}

/// Load the seal key, creating it (0600, CSPRNG) on first use.
pub fn load_or_create_seal_key(seal_file: &Path) -> Result<[u8; 32], SealError> {
    crate::keyfile::load_or_create_key_file(&seal_key_path(seal_file))
        .map_err(|e| SealError::IoError(e.to_string()))
}

/// Seal config bytes with the keyed format, creating the seal key on first
/// use, and store the seal (keychain + file). The one-stop entry point for
/// `opaque setup --seal` and the wizard.
pub fn store_seal_keyed(config_bytes: &[u8], seal_file: &Path) -> Result<(), SealError> {
    let key = load_or_create_seal_key(seal_file)?;
    let seal = compute_seal_keyed(config_bytes, &key);
    store_seal(&seal, seal_file)
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
/// `SealStatus::Unsealed`. The stored value's format decides the algorithm:
/// `opqs1:` seals verify via HMAC with the sibling key file, bare hex seals
/// via legacy unkeyed SHA-256 (reported as [`SealStatus::VerifiedLegacy`]).
pub fn verify_seal(config_bytes: &[u8], seal_file: &Path) -> Result<SealStatus, SealError> {
    // Try keychain first.
    if let Ok(Some(stored)) = keychain_read() {
        return evaluate_stored_seal(&stored, config_bytes, seal_file);
    }

    verify_seal_from_file(config_bytes, seal_file)
}

/// Verify config bytes against the seal file only (no keychain).
///
/// Use this when you need verification isolated from system keychain state,
/// e.g. in tests, independently custodied tenants, or config files outside the
/// default location. A missing local seal remains `Unsealed`; this function
/// never substitutes a global keychain seal for missing local authority.
pub fn verify_seal_from_file(
    config_bytes: &[u8],
    seal_file: &Path,
) -> Result<SealStatus, SealError> {
    if !seal_file.exists() {
        return Ok(SealStatus::Unsealed);
    }
    let stored = std::fs::read_to_string(seal_file)
        .map(|s| s.trim().to_string())
        .map_err(|e| SealError::IoError(format!("failed to read {}: {e}", seal_file.display())))?;
    evaluate_stored_seal(&stored, config_bytes, seal_file)
}

/// Compare a stored seal value against the config, dispatching on its format.
fn evaluate_stored_seal(
    stored: &str,
    config_bytes: &[u8],
    seal_file: &Path,
) -> Result<SealStatus, SealError> {
    if stored.starts_with(KEYED_SEAL_PREFIX) {
        let Some(key) = load_seal_key(seal_file)? else {
            return Ok(SealStatus::KeyMissing);
        };
        let actual = compute_seal_keyed(config_bytes, &key);
        return if actual == stored {
            Ok(SealStatus::Verified)
        } else {
            Ok(SealStatus::Tampered {
                expected: stored.to_string(),
                actual,
            })
        };
    }

    let actual = compute_seal(config_bytes);
    if actual == stored {
        Ok(SealStatus::VerifiedLegacy)
    } else {
        Ok(SealStatus::Tampered {
            expected: stored.to_string(),
            actual,
        })
    }
}

/// Remove seal from Keychain + file (and the seal key beside it).
pub fn remove_seal(seal_file: &Path) -> Result<(), SealError> {
    // Remove from keychain (ignore errors — may not exist).
    let _ = keychain_delete();

    remove_seal_files(seal_file)
}

/// File-side half of [`remove_seal`] (no keychain), separated for tests.
fn remove_seal_files(seal_file: &Path) -> Result<(), SealError> {
    if seal_file.exists() {
        std::fs::remove_file(seal_file).map_err(|e| {
            SealError::IoError(format!("failed to remove {}: {e}", seal_file.display()))
        })?;
    }

    // An orphaned key would just confuse the next seal — remove it with its seal.
    let key_path = seal_key_path(seal_file);
    if key_path.exists() {
        std::fs::remove_file(&key_path).map_err(|e| {
            SealError::IoError(format!("failed to remove {}: {e}", key_path.display()))
        })?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// File seal helpers
// ---------------------------------------------------------------------------

fn write_seal_file(seal: &str, path: &Path) -> Result<(), SealError> {
    // The previous seal (if any) is 0400, which fails a plain overwrite —
    // and re-sealing over an old seal is exactly how the legacy→keyed
    // upgrade works. Remove it first.
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| {
            SealError::IoError(format!(
                "failed to replace existing seal {}: {e}",
                path.display()
            ))
        })?;
    }

    std::fs::write(path, seal)
        .map_err(|e| SealError::IoError(format!("failed to write {}: {e}", path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).map_err(|e| {
            SealError::IoError(format!(
                "failed to set permissions on {}: {e}",
                path.display()
            ))
        })?;
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
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
                seal,
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
                "--label",
                "Opaque Config Seal",
                "service",
                KEYCHAIN_SERVICE,
                "account",
                KEYCHAIN_ACCOUNT,
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
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                KEYCHAIN_ACCOUNT,
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
                "service",
                KEYCHAIN_SERVICE,
                "account",
                KEYCHAIN_ACCOUNT,
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
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                KEYCHAIN_ACCOUNT,
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
                "service",
                KEYCHAIN_SERVICE,
                "account",
                KEYCHAIN_ACCOUNT,
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
        assert!(SealStatus::VerifiedLegacy.to_string().contains("legacy"));
        assert!(SealStatus::KeyMissing.to_string().contains("key missing"));
    }

    // --- Keyed seal ---

    #[test]
    fn keyed_seal_roundtrip_via_file() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let config = b"keyed config content";

        let key = load_or_create_seal_key(&seal_file).unwrap();
        let value = compute_seal_keyed(config, &key);
        assert!(value.starts_with(KEYED_SEAL_PREFIX));
        write_seal_file(&value, &seal_file).unwrap();

        assert_eq!(
            verify_seal_from_file(config, &seal_file).unwrap(),
            SealStatus::Verified
        );

        // Key file sits beside the seal with private mode.
        let key_path = seal_key_path(&seal_file);
        assert!(key_path.ends_with("config.seal.key"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "seal key must be private, got {mode:o}");
        }

        // Key creation is stable: a second load returns the same key.
        assert_eq!(load_or_create_seal_key(&seal_file).unwrap(), key);
    }

    #[test]
    fn keyed_seal_detects_config_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");

        let key = load_or_create_seal_key(&seal_file).unwrap();
        write_seal_file(&compute_seal_keyed(b"original", &key), &seal_file).unwrap();

        match verify_seal_from_file(b"modified", &seal_file).unwrap() {
            SealStatus::Tampered { .. } => {}
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn keyed_seal_cannot_be_forged_without_the_key() {
        // The attack the legacy seal permits: rewrite config, recompute the
        // seal, overwrite the seal file. With the keyed format the forger
        // does not hold the key, so the best they can do is an unkeyed value
        // or an HMAC under the wrong key — both fail verification.
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let key = load_or_create_seal_key(&seal_file).unwrap();
        write_seal_file(&compute_seal_keyed(b"honest config", &key), &seal_file).unwrap();

        let evil = b"evil config";

        // Forgery 1: legacy unkeyed recompute (what worked before) — the
        // seal now downgrades to VerifiedLegacy at best, never Verified.
        write_seal_file(&compute_seal(evil), &seal_file).unwrap();
        assert_eq!(
            verify_seal_from_file(evil, &seal_file).unwrap(),
            SealStatus::VerifiedLegacy,
            "unkeyed forgery must be distinguishable from a keyed seal"
        );

        // Forgery 2: HMAC under an attacker-chosen key.
        let wrong_key = [0x42u8; 32];
        write_seal_file(&compute_seal_keyed(evil, &wrong_key), &seal_file).unwrap();
        match verify_seal_from_file(evil, &seal_file).unwrap() {
            SealStatus::Tampered { .. } => {}
            other => panic!("wrong-key forgery must fail verification, got {other:?}"),
        }
    }

    #[test]
    fn keyed_seal_with_missing_key_reports_key_missing() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let key = load_or_create_seal_key(&seal_file).unwrap();
        write_seal_file(&compute_seal_keyed(b"cfg", &key), &seal_file).unwrap();

        fs::remove_file(seal_key_path(&seal_file)).unwrap();
        assert_eq!(
            verify_seal_from_file(b"cfg", &seal_file).unwrap(),
            SealStatus::KeyMissing
        );
    }

    #[test]
    fn legacy_seal_still_verifies_as_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let config = b"pre-upgrade config";
        write_seal_file(&compute_seal(config), &seal_file).unwrap();

        assert_eq!(
            verify_seal_from_file(config, &seal_file).unwrap(),
            SealStatus::VerifiedLegacy
        );
    }

    #[test]
    fn corrupt_seal_key_is_an_error_not_a_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let key = load_or_create_seal_key(&seal_file).unwrap();
        write_seal_file(&compute_seal_keyed(b"cfg", &key), &seal_file).unwrap();

        // Truncate the key: verification must hard-error, not degrade.
        fs::write(seal_key_path(&seal_file), b"short").unwrap();
        assert!(verify_seal_from_file(b"cfg", &seal_file).is_err());
    }

    #[test]
    fn remove_seal_files_removes_the_key_too() {
        // Files only — remove_seal itself also touches the OS keychain,
        // which tests must not do (see the module-test preamble).
        let dir = tempfile::tempdir().unwrap();
        let seal_file = dir.path().join("config.seal");
        let key = load_or_create_seal_key(&seal_file).unwrap();
        write_seal_file(&compute_seal_keyed(b"cfg", &key), &seal_file).unwrap();
        assert!(seal_file.exists());
        assert!(seal_key_path(&seal_file).exists());

        remove_seal_files(&seal_file).unwrap();
        assert!(!seal_file.exists());
        assert!(!seal_key_path(&seal_file).exists());
    }
}
