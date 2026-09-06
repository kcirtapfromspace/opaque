//! Secret reference resolution.
//!
//! Resolves secret refs (e.g. `env:NAME`, `keychain:service/account`) to
//! their actual values. Resolved values are held in memory only until
//! injected into the child process environment.
//!
//! The [`SecretResolver`]/[`ResolveError`]/`BaseResolver` trait family and
//! the provider-agnostic `env:`/`keychain:`/`profile:` resolvers now live in
//! `opaque_core::resolver` (re-used here via `use` below) so that provider
//! crates implementing `SecretResolver` do not need to depend on this
//! "sandbox" module, and this module does not need to depend on every
//! provider crate just to name their concrete resolver types.
//!
//! [`CompositeResolver`] itself stays here, but holds its provider resolvers
//! as type-erased `Box<dyn SecretResolver>` trait objects rather than named
//! `Option<ConcreteProviderResolver>` fields. The composition root
//! (`main.rs`, via `default_secret_resolvers()`, which already depends on
//! every provider module) is what actually constructs the concrete
//! resolvers — this module never names a concrete provider type.

use std::collections::HashMap;
use std::fmt;

use opaque_core::resolver::{
    EnvResolver, KeychainResolver, ProfileResolver, ResolveError, SecretResolver,
};
use opaque_core::secret::SecretValue;

// ---------------------------------------------------------------------------
// Composite resolver
// ---------------------------------------------------------------------------

/// A composite resolver that dispatches to the correct resolver based on
/// the ref scheme prefix (`env:`, `keychain:`, `profile:`, `onepassword:`, `bitwarden:`, `vault:`).
///
/// `providers` holds whichever provider resolvers the composition root
/// decided are configured (see `default_secret_resolvers()` in `main.rs`);
/// an unconfigured provider is simply absent from the list rather than
/// represented as a field set to `None`. Each entry's `resolve()` is tried
/// in turn; a resolver that does not recognize a ref's scheme returns
/// [`ResolveError::UnknownScheme`], which this dispatcher treats as "try the
/// next one" rather than a hard failure.
pub struct CompositeResolver {
    env: EnvResolver,
    keychain: KeychainResolver,
    profile: ProfileResolver,
    providers: Vec<Box<dyn SecretResolver>>,
}

// Manual impl: `SecretResolver` (unlike `OperationHandler`/`ApprovalGate`)
// does not require `Debug` of its implementors — provider resolvers hold
// live client handles with no useful debug representation — so `providers`
// can't be derived. Print just the count instead.
impl fmt::Debug for CompositeResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeResolver")
            .field("env", &self.env)
            .field("keychain", &self.keychain)
            .field("profile", &self.profile)
            .field(
                "providers",
                &format_args!("[{} configured]", self.providers.len()),
            )
            .finish()
    }
}

impl CompositeResolver {
    /// Build a composite resolver from an explicit set of provider
    /// resolvers. Callers outside this module get their provider set from
    /// `crate::default_secret_resolvers()` (the composition root).
    pub fn new(providers: Vec<Box<dyn SecretResolver>>) -> Self {
        Self {
            env: EnvResolver,
            keychain: KeychainResolver,
            profile: ProfileResolver,
            providers,
        }
    }

    /// Create a resolver with no provider backends configured (for testing).
    #[cfg(test)]
    fn without_onepassword() -> Self {
        Self::new(Vec::new())
    }
}

impl Default for CompositeResolver {
    fn default() -> Self {
        Self::new(crate::default_secret_resolvers())
    }
}

impl SecretResolver for CompositeResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        if ref_str.starts_with("env:") {
            return self.env.resolve(ref_str);
        }
        if ref_str.starts_with("keychain:") {
            return self.keychain.resolve(ref_str);
        }
        if ref_str.starts_with("profile:") {
            return self.profile.resolve(ref_str);
        }
        for provider in &self.providers {
            match provider.resolve(ref_str) {
                Err(ResolveError::UnknownScheme(_)) => continue,
                other => return other,
            }
        }
        // No configured provider claimed this scheme. Preserve specific,
        // actionable error messages for the provider schemes `main.rs`'s
        // `default_secret_resolvers()` knows how to wire up, even though an
        // unconfigured provider is simply absent from `self.providers`
        // rather than represented as a field here.
        if ref_str.starts_with("onepassword:") {
            return Err(ResolveError::OnePasswordError(
                ref_str.to_owned(),
                "1Password not configured (set OPAQUE_1PASSWORD_CONNECT_URL or install op CLI)"
                    .into(),
            ));
        }
        if ref_str.starts_with("bitwarden:") {
            return Err(ResolveError::BitwardenError(
                ref_str.to_owned(),
                "Bitwarden not configured".into(),
            ));
        }
        if ref_str.starts_with("aws:") {
            return Err(ResolveError::AwsError(
                ref_str.to_owned(),
                "AWS support disabled pending SigV4 (only explicit loopback mock configuration is supported)".into(),
            ));
        }
        if ref_str.starts_with("vault:") {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "Vault not configured".into(),
            ));
        }
        Err(ResolveError::UnknownScheme(ref_str.to_owned()))
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

// Unit tests for the `SecretResolver`/`ResolveError`/`BaseResolver` trait
// family and the provider-agnostic `EnvResolver`/`KeychainResolver`/
// `ProfileResolver` now live with their implementations in
// `opaque-core/src/resolver.rs`. This module keeps only the tests specific
// to `CompositeResolver`'s dispatch/type-erasure behavior.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_resolver_dispatches_env() {
        unsafe { std::env::set_var("OPAQUE_COMPOSITE_TEST", "comp_val") };
        let resolver = CompositeResolver::new(Vec::new());
        let value = resolver.resolve("env:OPAQUE_COMPOSITE_TEST").unwrap();
        assert_eq!(value.as_str().unwrap(), "comp_val");
        unsafe { std::env::remove_var("OPAQUE_COMPOSITE_TEST") };
    }

    #[test]
    fn composite_resolver_unknown_scheme() {
        let resolver = CompositeResolver::new(Vec::new());
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

        let resolver = CompositeResolver::new(Vec::new());
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

        let resolver = CompositeResolver::new(Vec::new());
        let result = resolve_all(&secrets, &resolver);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_all_empty() {
        let secrets = HashMap::new();
        let resolver = CompositeResolver::new(Vec::new());
        let resolved = resolve_all(&secrets, &resolver).unwrap();
        assert!(resolved.is_empty());
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
        // Use without_onepassword() which also has no bitwarden provider.
        let resolver = CompositeResolver::without_onepassword();
        let result = resolver.resolve("bitwarden:nonexistent-id");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::BitwardenError(..)));
        assert!(format!("{err}").contains("not configured"));
    }

    #[test]
    fn composite_resolver_aws_disabled_for_both_ref_forms() {
        let resolver = CompositeResolver::without_onepassword();
        for reference in ["aws:prod/db-password", "aws:ssm:/prod/password"] {
            let err = resolver.resolve(reference).unwrap_err();
            assert!(matches!(err, ResolveError::AwsError(..)));
            assert!(err.to_string().contains("disabled pending SigV4"));
        }
    }

    #[test]
    fn composite_resolver_vault_dispatch() {
        // Use without_onepassword() which also has no vault provider.
        let resolver = CompositeResolver::without_onepassword();
        let result = resolver.resolve("vault:secret/data/app#TOKEN");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::VaultError(..)));
        assert!(format!("{err}").contains("not configured"));
    }

    #[test]
    fn composite_resolver_dispatches_profile() {
        let resolver = CompositeResolver::new(Vec::new());
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
