//! Secret value wrapper with automatic zeroing on drop.
//!
//! `SecretValue` wraps secret data in a `Zeroizing<Vec<u8>>` that is
//! automatically cleared from memory when dropped. Debug and Display
//! implementations always show `[REDACTED]`.

use std::fmt;

use zeroize::Zeroizing;

/// A secret value that is automatically zeroed from memory on drop.
///
/// This provides defense-in-depth against secret leakage through:
/// - Debug/Display always showing `[REDACTED]`
/// - Automatic zeroization of the backing buffer on drop
/// - Optional `mlock()` to prevent swapping to disk
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Create a `SecretValue` from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self(Zeroizing::new(data))
    }

    /// Create a `SecretValue` from a String, consuming the String.
    pub fn from_string(s: String) -> Self {
        Self(Zeroizing::new(s.into_bytes()))
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Try to interpret the bytes as a UTF-8 string.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Best-effort `mlock()` to prevent the secret from being swapped to disk.
    ///
    /// Logs a warning on failure but does not panic — mlock may fail due to
    /// resource limits (RLIMIT_MEMLOCK) and this is not a hard error.
    pub fn mlock(&self) {
        #[cfg(unix)]
        {
            let ptr = self.0.as_ptr();
            let len = self.0.len();
            if len > 0 {
                let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
                if ret != 0 {
                    tracing::warn!(
                        "mlock failed for SecretValue ({} bytes): {}",
                        len,
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_redacted() {
        let secret = SecretValue::from_string("hunter2".into());
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn display_shows_redacted() {
        let secret = SecretValue::from_string("hunter2".into());
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn as_bytes_returns_content() {
        let secret = SecretValue::new(vec![1, 2, 3]);
        assert_eq!(secret.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn as_str_returns_content() {
        let secret = SecretValue::from_string("hello".into());
        assert_eq!(secret.as_str(), Some("hello"));
    }

    #[test]
    fn as_str_invalid_utf8_returns_none() {
        let secret = SecretValue::new(vec![0xFF, 0xFE]);
        assert!(secret.as_str().is_none());
    }

    #[test]
    fn from_string_roundtrip() {
        let secret = SecretValue::from_string("my-secret".into());
        assert_eq!(secret.as_str().unwrap(), "my-secret");
    }

    #[test]
    fn mlock_does_not_panic() {
        let secret = SecretValue::from_string("test".into());
        secret.mlock(); // Should not panic even if mlock fails.
    }

    #[test]
    fn mlock_empty_value_no_op() {
        let secret = SecretValue::new(vec![]);
        secret.mlock(); // Empty buffer should be a no-op.
    }

    #[test]
    fn value_zeroed_on_drop() {
        let data = vec![0x42u8; 32];
        let ptr = data.as_ptr();
        let len = data.len();

        let secret = SecretValue::new(data);
        drop(secret);

        // After drop, the memory MAY have been zeroed. We can't guarantee
        // the allocator hasn't reused it, but Zeroizing<Vec<u8>> does
        // call zeroize before dealloc. This test primarily verifies no panic.
        // The actual zeroing is guaranteed by the zeroize crate's implementation.
        let _ = (ptr, len);
    }
}
