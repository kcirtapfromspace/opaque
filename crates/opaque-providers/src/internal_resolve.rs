//! Crate-private "give me any secret ref" resolution for `github`/`gitlab`'s
//! own token-resolution needs (e.g. turning a `github_token_ref` param into
//! an actual PAT before calling the GitHub API).
//!
//! `opaqued::sandbox::resolve::CompositeResolver` (the daemon's real,
//! request-time secret-ref dispatcher, wired up via `main.rs`'s
//! `default_secret_resolvers()`) is deliberately NOT reused here: `sandbox`
//! stays in the `opaqued` binary crate (a later, separate `opaque-sandbox`
//! extraction), and `opaqued` depends on `opaque-providers` (for
//! `github::handle_github_rpc`, the resolver impls, etc.) — so a provider
//! module reaching back into `opaqued::sandbox` would be a two-way crate
//! cycle. Since every concrete resolver `CompositeResolver` type-erases
//! (onepassword/bitwarden/aws/vault) already lives in this same crate as a
//! sibling module, this is a small, self-contained, crate-private copy of
//! the same dispatch + construction logic instead — no cross-crate reach
//! needed. `opaqued::sandbox::resolve::CompositeResolver` is untouched and
//! remains the one used for real request-time sandbox env injection.

use opaque_core::resolver::{
    EnvResolver, KeychainResolver, ProfileResolver, ResolveError, SecretResolver,
};
use opaque_core::secret::SecretValue;

/// Build the standard set of provider secret resolvers for `github`/`gitlab`'s
/// own token/value-ref resolution. Mirrors `opaqued::main::default_secret_resolvers()`
/// exactly, sourced from sibling provider modules in this crate instead of
/// `opaqued`'s composition root.
pub(crate) fn default_secret_resolvers() -> Vec<Box<dyn SecretResolver>> {
    // `github`/`gitlab` (the only callers of this module) each only require
    // `vault` outright (see their own feature entries in Cargo.toml);
    // onepassword/bitwarden/aws are independently optional, so every block
    // below is individually feature-gated rather than assumed present.
    #[allow(unused_mut)]
    let mut resolvers: Vec<Box<dyn SecretResolver>> = Vec::new();

    // 1Password backend selection:
    // 1. Connect Server URL configured -> use Connect Server
    // 2. `op` CLI found in PATH -> use `op` CLI
    // 3. Neither -> onepassword disabled
    #[cfg(feature = "onepassword")]
    {
        if let Ok(url) = std::env::var(crate::onepassword::client::CONNECT_URL_ENV) {
            match crate::onepassword::client::OnePasswordClient::new(&url) {
                Ok(client) => resolvers.push(Box::new(
                    crate::onepassword::resolve::OnePasswordResolver::new(client),
                )),
                Err(e) => tracing::warn!("1Password Connect client disabled: {e}"),
            }
        } else if let Ok(cli) = crate::onepassword::op_cli::OpCliClient::new() {
            resolvers.push(Box::new(
                crate::onepassword::resolve::OnePasswordResolver::from_cli(cli),
            ));
        }
    }

    // Bitwarden backend: available if URL scheme is valid.
    #[cfg(feature = "bitwarden")]
    {
        let bitwarden_url = std::env::var(crate::bitwarden::client::BITWARDEN_URL_ENV)
            .unwrap_or_else(|_| crate::bitwarden::client::DEFAULT_BASE_URL.to_owned());
        match crate::bitwarden::client::BitwardenClient::new(&bitwarden_url) {
            Ok(client) => resolvers.push(Box::new(
                crate::bitwarden::resolve::BitwardenResolver::new(client),
            )),
            Err(e) => tracing::warn!("Bitwarden client disabled: {e}"),
        }
    }

    // AWS remains disabled until SigV4 exists. Only explicitly configured
    // loopback mocks can be reached by any aws: secret resolution path.
    #[cfg(feature = "aws")]
    {
        match crate::aws::client::AwsClient::from_mock_env() {
            Ok(Some(client)) => {
                resolvers.push(Box::new(crate::aws::resolve::AwsResolver::new(client)))
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("AWS client disabled: {e}"),
        }
    }

    // Vault backend: available if URL scheme is valid.
    #[cfg(feature = "vault")]
    {
        match crate::vault::client::VaultClient::new() {
            Ok(client) => {
                resolvers.push(Box::new(crate::vault::resolve::VaultResolver::new(client)))
            }
            Err(e) => tracing::warn!("Vault client disabled: {e}"),
        }
    }

    resolvers
}

/// A composite resolver that dispatches to the correct resolver based on
/// the ref scheme prefix (`env:`, `keychain:`, `profile:`, `onepassword:`,
/// `bitwarden:`, `vault:`). Crate-private mirror of
/// `opaqued::sandbox::resolve::CompositeResolver` — see module docs above
/// for why this isn't just reused directly.
pub(crate) struct CompositeResolver {
    env: EnvResolver,
    keychain: KeychainResolver,
    profile: ProfileResolver,
    providers: Vec<Box<dyn SecretResolver>>,
}

impl CompositeResolver {
    pub(crate) fn new(providers: Vec<Box<dyn SecretResolver>>) -> Self {
        Self {
            env: EnvResolver,
            keychain: KeychainResolver,
            profile: ProfileResolver,
            providers,
        }
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
        // actionable error messages for the provider schemes
        // `default_secret_resolvers()` above knows how to wire up, even
        // though an unconfigured provider is simply absent from
        // `self.providers` rather than represented as a field here.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_resolver_dispatches_env() {
        unsafe { std::env::set_var("OPAQUE_PROVIDERS_INTERNAL_COMPOSITE_TEST", "comp_val") };
        let resolver = CompositeResolver::new(Vec::new());
        let value = resolver
            .resolve("env:OPAQUE_PROVIDERS_INTERNAL_COMPOSITE_TEST")
            .unwrap();
        assert_eq!(value.as_str().unwrap(), "comp_val");
        unsafe { std::env::remove_var("OPAQUE_PROVIDERS_INTERNAL_COMPOSITE_TEST") };
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
    fn composite_resolver_vault_dispatch_without_providers() {
        let resolver = CompositeResolver::new(Vec::new());
        let result = resolver.resolve("vault:secret/data/app#TOKEN");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResolveError::VaultError(..)));
    }

    #[test]
    fn default_secret_resolvers_does_not_panic() {
        // Smoke test only: actual resolver set depends on the process
        // environment (op CLI presence, OPAQUE_AWS_ALLOW_INSECURE, etc.),
        // which is not controlled here. Just prove construction is safe.
        let _ = default_secret_resolvers();
    }
}
