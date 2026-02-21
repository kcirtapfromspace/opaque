//! Secret reference resolution.
//!
//! Resolves secret refs (e.g. `env:NAME`, `keychain:service/account`) to
//! their actual values. Resolved values are held in memory only until
//! injected into the child process environment.

use std::collections::HashMap;

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
        "unknown ref scheme in '{0}' (expected env:, keychain:, profile:, onepassword:, or bitwarden:)"
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

        let profile = opaque_core::profile::load_named_profile(profile_name).map_err(|e| {
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
// Composite resolver
// ---------------------------------------------------------------------------

/// A composite resolver that dispatches to the correct resolver based on
/// the ref scheme prefix (`env:`, `keychain:`, `profile:`, `onepassword:`, `bitwarden:`).
#[derive(Debug)]
pub struct CompositeResolver {
    env: EnvResolver,
    keychain: KeychainResolver,
    profile: ProfileResolver,
    onepassword: Option<crate::onepassword::resolve::OnePasswordResolver>,
    bitwarden: Option<crate::bitwarden::resolve::BitwardenResolver>,
}

impl CompositeResolver {
    pub fn new() -> Self {
        // 1Password backend selection:
        // 1. Connect Server URL configured → use Connect Server
        // 2. `op` CLI found in PATH → use `op` CLI
        // 3. Neither → onepassword disabled
        let onepassword =
            if let Ok(url) = std::env::var(crate::onepassword::client::CONNECT_URL_ENV) {
                let client = crate::onepassword::client::OnePasswordClient::new(&url);
                Some(crate::onepassword::resolve::OnePasswordResolver::new(
                    client,
                ))
            } else if let Ok(cli) = crate::onepassword::op_cli::OpCliClient::new() {
                Some(crate::onepassword::resolve::OnePasswordResolver::from_cli(
                    cli,
                ))
            } else {
                None
            };

        // Bitwarden backend: always available (uses default or configured URL).
        let bitwarden_url = std::env::var(crate::bitwarden::client::BITWARDEN_URL_ENV)
            .unwrap_or_else(|_| crate::bitwarden::client::DEFAULT_BASE_URL.to_owned());
        let bitwarden = Some(crate::bitwarden::resolve::BitwardenResolver::new(
            crate::bitwarden::client::BitwardenClient::new(&bitwarden_url),
        ));

        Self {
            env: EnvResolver,
            keychain: KeychainResolver,
            profile: ProfileResolver,
            onepassword,
            bitwarden,
        }
    }

    /// Create a resolver without 1Password or Bitwarden backends (for testing).
    #[cfg(test)]
    fn without_onepassword() -> Self {
        Self {
            env: EnvResolver,
            keychain: KeychainResolver,
            profile: ProfileResolver,
            onepassword: None,
            bitwarden: None,
        }
    }
}

impl Default for CompositeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretResolver for CompositeResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        if ref_str.starts_with("env:") {
            self.env.resolve(ref_str)
        } else if ref_str.starts_with("keychain:") {
            self.keychain.resolve(ref_str)
        } else if ref_str.starts_with("profile:") {
            self.profile.resolve(ref_str)
        } else if ref_str.starts_with("onepassword:") {
            match &self.onepassword {
                Some(r) => r.resolve(ref_str),
                None => Err(ResolveError::OnePasswordError(
                    ref_str.to_owned(),
                    "1Password not configured (set OPAQUE_1PASSWORD_CONNECT_URL or install op CLI)"
                        .into(),
                )),
            }
        } else if ref_str.starts_with("bitwarden:") {
            match &self.bitwarden {
                Some(r) => r.resolve(ref_str),
                None => Err(ResolveError::BitwardenError(
                    ref_str.to_owned(),
                    "Bitwarden not configured".into(),
                )),
            }
        } else {
            Err(ResolveError::UnknownScheme(ref_str.to_owned()))
        }
    }
}

/// Resolve all secret refs in a profile to their values.
///
/// Returns a map of `ENV_NAME -> SecretValue`. Each resolved value is
/// `mlock`'d to prevent it from being swapped to disk while in use.
pub fn resolve_all(
    secrets: &HashMap<String, String>,
    resolver: &dyn SecretResolver,
) -> Result<HashMap<String, SecretValue>, ResolveError> {
    let mut resolved = HashMap::with_capacity(secrets.len());
    for (env_name, ref_str) in secrets {
        let value = resolver.resolve(ref_str)?;
        value.mlock();
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
        assert_eq!(value.as_str().unwrap(), "test_value_42");
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
        assert_eq!(value.as_str().unwrap(), "comp_val");
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
        assert_eq!(resolved["VAR_A"].as_str().unwrap(), "val_a");
        assert_eq!(resolved["VAR_B"].as_str().unwrap(), "val_b");

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

        let err = ResolveError::ProfileError("profile:x:y".into(), "not found".into());
        assert!(format!("{err}").contains("profile resolution failed"));

        let err = ResolveError::OnePasswordError("onepassword:v/i".into(), "not configured".into());
        assert!(format!("{err}").contains("1Password resolution failed"));

        let err =
            ResolveError::BitwardenError("bitwarden:proj/key".into(), "not configured".into());
        assert!(format!("{err}").contains("Bitwarden resolution failed"));
    }

    #[test]
    fn composite_resolver_onepassword_dispatch() {
        // Use without_onepassword() to avoid hitting the real `op` CLI.
        let resolver = CompositeResolver::without_onepassword();
        let result = resolver.resolve("onepassword:nonexistent-vault-xyz/item");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::OnePasswordError(..)));
        assert!(format!("{err}").contains("not configured"));
    }

    #[test]
    fn composite_resolver_bitwarden_dispatch() {
        // Use without_onepassword() which also has bitwarden=None.
        let resolver = CompositeResolver::without_onepassword();
        let result = resolver.resolve("bitwarden:nonexistent-id");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::BitwardenError(..)));
        assert!(format!("{err}").contains("not configured"));
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
    fn composite_resolver_dispatches_profile() {
        let resolver = CompositeResolver::new();
        // This will fail because the profile doesn't exist, but it proves
        // dispatch to ProfileResolver is working.
        let result = resolver.resolve("profile:nonexistent:KEY");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::ProfileError(..)
        ));
    }
}
