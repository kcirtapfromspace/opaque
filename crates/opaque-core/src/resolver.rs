//! Secret reference resolution: the resolver trait family plus the handful
//! of provider-agnostic resolvers (`env:`, `keychain:`, `profile:`).
//!
//! Promoted from `opaqued::sandbox::resolve` so that provider crates (each
//! implementing [`SecretResolver`] once per provider) do not need to depend
//! on a "sandbox" crate for the trait, and a sandbox crate does not need to
//! depend on every provider crate just to type-erase them. Concrete,
//! provider-specific resolvers (AWS, Vault, 1Password, ...) stay in their
//! respective provider modules/crates and are wired together, as
//! `Box<dyn SecretResolver>` trait objects, by the composition root.

use crate::secret::SecretValue;

// ---------------------------------------------------------------------------
// Resolver trait
// ---------------------------------------------------------------------------

/// Trait for resolving secret references to their values.
pub trait SecretResolver: Send + Sync {
    /// Resolve a secret reference string to its value.
    ///
    /// Returns a [`SecretValue`] that is automatically zeroed on drop.
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError>;
}

/// Errors from secret resolution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ResolveError {
    #[error(
        "unknown ref scheme in '{0}' (expected env:, keychain:, profile:, onepassword:, bitwarden:, aws:, or vault:)"
    )]
    UnknownScheme(String),

    #[error("environment variable '{0}' not found")]
    EnvNotFound(String),

    #[error("keychain lookup failed for '{0}': {1}")]
    KeychainError(String, String),

    #[error("empty ref value for '{0}'")]
    EmptyValue(String),

    #[error("profile resolution failed for '{0}': {1}")]
    ProfileError(String, String),

    #[error("1Password resolution failed for '{0}': {1}")]
    OnePasswordError(String, String),

    #[error("Bitwarden resolution failed for '{0}': {1}")]
    BitwardenError(String, String),

    #[error("AWS resolution failed for '{0}': {1}")]
    AwsError(String, String),

    #[error("Vault resolution failed for '{0}': {1}")]
    VaultError(String, String),

    #[error("Azure resolution failed for '{0}': {1}")]
    AzureError(String, String),

    #[error("GCP resolution failed for '{0}': {1}")]
    GcpError(String, String),

    #[error("Doppler resolution failed for '{0}': {1}")]
    DopplerError(String, String),

    #[error("Infisical resolution failed for '{0}': {1}")]
    InfisicalError(String, String),
}

// ---------------------------------------------------------------------------
// Environment resolver
// ---------------------------------------------------------------------------

/// Resolves `env:NAME` refs by reading from the daemon's own environment.
#[derive(Debug)]
pub struct EnvResolver;

impl SecretResolver for EnvResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let name = ref_str
            .strip_prefix("env:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if name.is_empty() {
            return Err(ResolveError::EmptyValue(ref_str.to_owned()));
        }

        let val = std::env::var(name).map_err(|_| ResolveError::EnvNotFound(name.to_owned()))?;
        Ok(SecretValue::from_string(val))
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
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
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
                let _stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ResolveError::KeychainError(
                    ref_str.to_owned(),
                    format!(
                        "secret '{}/{}' not found in keychain \u{2014} store it with: opaque secrets add {}",
                        service, account, account
                    ),
                ));
            }

            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if value.is_empty() {
                return Err(ResolveError::EmptyValue(ref_str.to_owned()));
            }
            return Ok(SecretValue::from_string(value));
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
                let _stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ResolveError::KeychainError(
                    ref_str.to_owned(),
                    format!(
                        "secret '{}/{}' not found in keychain \u{2014} store it with: opaque secrets add {}",
                        service, account, account
                    ),
                ));
            }

            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if value.is_empty() {
                return Err(ResolveError::EmptyValue(ref_str.to_owned()));
            }
            return Ok(SecretValue::from_string(value));
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
// Profile resolver
// ---------------------------------------------------------------------------

/// Resolves `profile:<name>:<key>` refs by loading a named profile and
/// resolving the underlying secret ref through the base resolvers.
///
/// Cycle prevention: the base resolver used for the underlying ref excludes
/// `ProfileResolver` itself.
#[derive(Debug)]
pub struct ProfileResolver;

impl ProfileResolver {
    /// Parse a profile ref: `profile:<name>:<key>` -> (name, key).
    fn parse_ref(ref_str: &str) -> Result<(&str, &str), ResolveError> {
        let rest = ref_str
            .strip_prefix("profile:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        let (name, key) = rest.split_once(':').ok_or_else(|| {
            ResolveError::ProfileError(
                ref_str.to_owned(),
                "expected format profile:<name>:<key>".into(),
            )
        })?;

        if name.is_empty() || key.is_empty() {
            return Err(ResolveError::EmptyValue(ref_str.to_owned()));
        }

        Ok((name, key))
    }
}

impl SecretResolver for ProfileResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let (profile_name, key) = Self::parse_ref(ref_str)?;

        let profile = crate::profile::load_named_profile(profile_name).map_err(|e| {
            ResolveError::ProfileError(ref_str.to_owned(), format!("failed to load profile: {e}"))
        })?;

        let underlying_ref = profile.secrets.get(key).ok_or_else(|| {
            ResolveError::ProfileError(
                ref_str.to_owned(),
                format!("key '{key}' not found in profile '{profile_name}'"),
            )
        })?;

        // Resolve the underlying ref through base resolvers only (no ProfileResolver)
        // to prevent cycles.
        let base = BaseResolver::new();
        base.resolve(underlying_ref)
    }
}

/// Base resolver that dispatches to env: and keychain: only.
/// Used by ProfileResolver and OnePasswordResolver to prevent resolution cycles.
#[derive(Debug)]
pub struct BaseResolver {
    env: EnvResolver,
    keychain: KeychainResolver,
}

impl BaseResolver {
    pub fn new() -> Self {
        Self {
            env: EnvResolver,
            keychain: KeychainResolver,
        }
    }
}

impl Default for BaseResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretResolver for BaseResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        if ref_str.starts_with("env:") {
            self.env.resolve(ref_str)
        } else if ref_str.starts_with("keychain:") {
            self.keychain.resolve(ref_str)
        } else {
            Err(ResolveError::UnknownScheme(ref_str.to_owned()))
        }
    }
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
        unsafe { std::env::set_var("OPAQUE_CORE_TEST_SECRET_42", "test_value_42") };
        let resolver = EnvResolver;
        let value = resolver.resolve("env:OPAQUE_CORE_TEST_SECRET_42").unwrap();
        assert_eq!(value.as_str().unwrap(), "test_value_42");
        unsafe { std::env::remove_var("OPAQUE_CORE_TEST_SECRET_42") };
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
    fn resolve_error_display() {
        let err = ResolveError::UnknownScheme("literal:foo".into());
        assert!(format!("{err}").contains("unknown ref scheme"));

        let err = ResolveError::EnvNotFound("MISSING".into());
        assert!(format!("{err}").contains("not found"));

        let err = ResolveError::KeychainError("kc:x/y".into(), "failed".into());
        assert!(format!("{err}").contains("keychain lookup failed"));

        let err = ResolveError::ProfileError("profile:x:y".into(), "not found".into());
        assert!(format!("{err}").contains("profile resolution failed"));

        let err = ResolveError::OnePasswordError("onepassword:v/i".into(), "not configured".into());
        assert!(format!("{err}").contains("1Password resolution failed"));

        let err =
            ResolveError::BitwardenError("bitwarden:proj/key".into(), "not configured".into());
        assert!(format!("{err}").contains("Bitwarden resolution failed"));

        let err = ResolveError::VaultError("vault:secret/data/app#TOKEN".into(), "failed".into());
        assert!(format!("{err}").contains("Vault resolution failed"));
    }

    // -- ProfileResolver tests --

    #[test]
    fn profile_parse_ref_valid() {
        let (name, key) = ProfileResolver::parse_ref("profile:myapp:JWT").unwrap();
        assert_eq!(name, "myapp");
        assert_eq!(key, "JWT");
    }

    #[test]
    fn profile_parse_ref_wrong_scheme() {
        let result = ProfileResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn profile_parse_ref_no_key_separator() {
        let result = ProfileResolver::parse_ref("profile:myapp");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::ProfileError(..)
        ));
    }

    #[test]
    fn profile_parse_ref_empty_parts() {
        let result = ProfileResolver::parse_ref("profile::KEY");
        assert!(result.is_err());

        let result = ProfileResolver::parse_ref("profile:name:");
        assert!(result.is_err());
    }

    #[test]
    fn profile_resolver_missing_profile_errors() {
        let resolver = ProfileResolver;
        let result = resolver.resolve("profile:nonexistent_profile_xyz:KEY");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::ProfileError(..)
        ));
    }

    #[test]
    fn error_message_keychain_not_found_includes_add_hint() {
        let err = ResolveError::KeychainError(
            "keychain:opaque/foo".into(),
            "secret 'opaque/foo' not found in keychain \u{2014} store it with: opaque secrets add foo".into(),
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("opaque secrets add"),
            "keychain error should suggest 'opaque secrets add', got: {msg}"
        );
        assert!(
            msg.contains("foo"),
            "keychain error should contain the secret name, got: {msg}"
        );
    }
}
