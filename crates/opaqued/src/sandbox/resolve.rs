//! Secret reference resolution.
//!
//! Resolves secret refs (e.g. `env:NAME`, `keychain:service/account`) to
//! their actual values. Resolved values are held in memory only until
//! injected into the child process environment.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Resolver trait
// ---------------------------------------------------------------------------

/// Trait for resolving secret references to their values.
pub trait SecretResolver: Send + Sync {
    /// Resolve a secret reference string to its value.
    ///
    /// The returned value is the actual secret. It must be zeroized
    /// after use (handled by the sandbox orchestrator).
    fn resolve(&self, ref_str: &str) -> Result<String, ResolveError>;
}

/// Errors from secret resolution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ResolveError {
    #[error("unknown ref scheme in '{0}' (expected env: or keychain:)")]
    UnknownScheme(String),

    #[error("environment variable '{0}' not found")]
    EnvNotFound(String),

    #[error("keychain lookup failed for '{0}': {1}")]
    KeychainError(String, String),

    #[error("empty ref value for '{0}'")]
    EmptyValue(String),
}

// ---------------------------------------------------------------------------
// Environment resolver
// ---------------------------------------------------------------------------

/// Resolves `env:NAME` refs by reading from the daemon's own environment.
#[derive(Debug)]
pub struct EnvResolver;

impl SecretResolver for EnvResolver {
    fn resolve(&self, ref_str: &str) -> Result<String, ResolveError> {
        let name = ref_str
            .strip_prefix("env:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if name.is_empty() {
            return Err(ResolveError::EmptyValue(ref_str.to_owned()));
        }

        std::env::var(name).map_err(|_| ResolveError::EnvNotFound(name.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Keychain resolver
// ---------------------------------------------------------------------------

/// Resolves `keychain:service/account` refs via OS keychain commands.
///
/// - macOS: `security find-generic-password -s <service> -a <account> -w`
/// - Linux: `secret-tool lookup service <service> account <account>`
#[derive(Debug)]
pub struct KeychainResolver;

impl KeychainResolver {
    /// Parse a keychain ref: `keychain:service/account` -> (service, account).
    fn parse_ref(ref_str: &str) -> Result<(&str, &str), ResolveError> {
        let path = ref_str
            .strip_prefix("keychain:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        let (service, account) = path.split_once('/').ok_or_else(|| {
            ResolveError::KeychainError(
                ref_str.to_owned(),
                "expected format keychain:service/account".into(),
            )
        })?;

        if service.is_empty() || account.is_empty() {
            return Err(ResolveError::EmptyValue(ref_str.to_owned()));
        }

        Ok((service, account))
    }
}

impl SecretResolver for KeychainResolver {
    #[allow(clippy::needless_return)]
    fn resolve(&self, ref_str: &str) -> Result<String, ResolveError> {
        let (service, account) = Self::parse_ref(ref_str)?;

        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("security")
                .args(["find-generic-password", "-s", service, "-a", account, "-w"])
                .env_clear()
                .env("PATH", "/usr/bin")
                .output()
                .map_err(|e| {
                    ResolveError::KeychainError(ref_str.to_owned(), format!("spawn failed: {e}"))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ResolveError::KeychainError(
                    ref_str.to_owned(),
                    format!("security command failed: {}", stderr.trim()),
                ));
            }

            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if value.is_empty() {
                return Err(ResolveError::EmptyValue(ref_str.to_owned()));
            }
            return Ok(value);
        }

        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("secret-tool")
                .args(["lookup", "service", service, "account", account])
                .env_clear()
                .env("PATH", "/usr/bin:/usr/local/bin:/bin")
                .output()
                .map_err(|e| {
                    ResolveError::KeychainError(ref_str.to_owned(), format!("spawn failed: {e}"))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ResolveError::KeychainError(
                    ref_str.to_owned(),
                    format!("secret-tool failed: {}", stderr.trim()),
                ));
            }

            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if value.is_empty() {
                return Err(ResolveError::EmptyValue(ref_str.to_owned()));
            }
            return Ok(value);
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (service, account);
            Err(ResolveError::KeychainError(
                ref_str.to_owned(),
                "keychain resolution not supported on this platform".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Composite resolver
// ---------------------------------------------------------------------------

/// A composite resolver that dispatches to the correct resolver based on
/// the ref scheme prefix.
#[derive(Debug)]
pub struct CompositeResolver {
    env: EnvResolver,
    keychain: KeychainResolver,
}

impl CompositeResolver {
    pub fn new() -> Self {
        Self {
            env: EnvResolver,
            keychain: KeychainResolver,
        }
    }
}

impl Default for CompositeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretResolver for CompositeResolver {
    fn resolve(&self, ref_str: &str) -> Result<String, ResolveError> {
        if ref_str.starts_with("env:") {
            self.env.resolve(ref_str)
        } else if ref_str.starts_with("keychain:") {
            self.keychain.resolve(ref_str)
        } else {
            Err(ResolveError::UnknownScheme(ref_str.to_owned()))
        }
    }
}

/// Resolve all secret refs in a profile to their values.
///
/// Returns a map of `ENV_NAME -> secret_value`.
pub fn resolve_all(
    secrets: &HashMap<String, String>,
    resolver: &dyn SecretResolver,
) -> Result<HashMap<String, String>, ResolveError> {
    let mut resolved = HashMap::with_capacity(secrets.len());
    for (env_name, ref_str) in secrets {
        let value = resolver.resolve(ref_str)?;
        resolved.insert(env_name.clone(), value);
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_resolver_reads_daemon_env() {
        // Set a test env var.
        unsafe { std::env::set_var("OPAQUE_TEST_SECRET_42", "test_value_42") };
        let resolver = EnvResolver;
        let value = resolver.resolve("env:OPAQUE_TEST_SECRET_42").unwrap();
        assert_eq!(value, "test_value_42");
        unsafe { std::env::remove_var("OPAQUE_TEST_SECRET_42") };
    }

    #[test]
    fn env_resolver_not_found() {
        let resolver = EnvResolver;
        let result = resolver.resolve("env:OPAQUE_NONEXISTENT_VAR_XYZ");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResolveError::EnvNotFound(_)));
    }

    #[test]
    fn env_resolver_wrong_scheme() {
        let resolver = EnvResolver;
        let result = resolver.resolve("keychain:foo/bar");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn env_resolver_empty_name() {
        let resolver = EnvResolver;
        let result = resolver.resolve("env:");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResolveError::EmptyValue(_)));
    }

    #[test]
    fn keychain_parse_ref_valid() {
        let (service, account) = KeychainResolver::parse_ref("keychain:opaque/my-token").unwrap();
        assert_eq!(service, "opaque");
        assert_eq!(account, "my-token");
    }

    #[test]
    fn keychain_parse_ref_wrong_scheme() {
        let result = KeychainResolver::parse_ref("env:FOO");
        assert!(result.is_err());
    }

    #[test]
    fn keychain_parse_ref_no_slash() {
        let result = KeychainResolver::parse_ref("keychain:no-slash");
        assert!(result.is_err());
    }

    #[test]
    fn keychain_parse_ref_empty_parts() {
        let result = KeychainResolver::parse_ref("keychain:/account");
        assert!(result.is_err());

        let result = KeychainResolver::parse_ref("keychain:service/");
        assert!(result.is_err());
    }

    #[test]
    fn composite_resolver_dispatches_env() {
        unsafe { std::env::set_var("OPAQUE_COMPOSITE_TEST", "comp_val") };
        let resolver = CompositeResolver::new();
        let value = resolver.resolve("env:OPAQUE_COMPOSITE_TEST").unwrap();
        assert_eq!(value, "comp_val");
        unsafe { std::env::remove_var("OPAQUE_COMPOSITE_TEST") };
    }

    #[test]
    fn composite_resolver_unknown_scheme() {
        let resolver = CompositeResolver::new();
        let result = resolver.resolve("literal:foo");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn resolve_all_works() {
        unsafe { std::env::set_var("OPAQUE_RA_A", "val_a") };
        unsafe { std::env::set_var("OPAQUE_RA_B", "val_b") };
        let mut secrets = HashMap::new();
        secrets.insert("VAR_A".into(), "env:OPAQUE_RA_A".into());
        secrets.insert("VAR_B".into(), "env:OPAQUE_RA_B".into());

        let resolver = CompositeResolver::new();
        let resolved = resolve_all(&secrets, &resolver).unwrap();
        assert_eq!(resolved["VAR_A"], "val_a");
        assert_eq!(resolved["VAR_B"], "val_b");

        unsafe { std::env::remove_var("OPAQUE_RA_A") };
        unsafe { std::env::remove_var("OPAQUE_RA_B") };
    }

    #[test]
    fn resolve_all_fails_on_missing() {
        let mut secrets = HashMap::new();
        secrets.insert("VAR_X".into(), "env:OPAQUE_DEFINITELY_NOT_SET_XYZ".into());

        let resolver = CompositeResolver::new();
        let result = resolve_all(&secrets, &resolver);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_all_empty() {
        let secrets = HashMap::new();
        let resolver = CompositeResolver::new();
        let resolved = resolve_all(&secrets, &resolver).unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_error_display() {
        let err = ResolveError::UnknownScheme("literal:foo".into());
        assert!(format!("{err}").contains("unknown ref scheme"));

        let err = ResolveError::EnvNotFound("MISSING".into());
        assert!(format!("{err}").contains("not found"));

        let err = ResolveError::KeychainError("kc:x/y".into(), "failed".into());
        assert!(format!("{err}").contains("keychain lookup failed"));
    }
}
