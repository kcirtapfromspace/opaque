//! Credential provider integrations for the Opaque broker.
//!
//! Each provider implements [`opaque_core::operation_handler::OperationHandler`]
//! (all except `vault`, which is resolver-only — it exposes no
//! plaintext-returning daemon operations of its own) and most also implement
//! [`opaque_core::resolver::SecretResolver`] (all except `github`/`gitlab`,
//! which only *use* a composite resolver rather than being one).
//!
//! Extracted from `opaqued` (a binary-only crate, so none of this was
//! nameable from anywhere else) so providers can be built, tested, and
//! feature-gated independently of the daemon's kernel.
//!
//! Providers have independent Cargo features. The default set is `github`,
//! `gitlab`, `onepassword`, `bitwarden`, `vault`, and `aws`. The daemon also
//! enables `gcp` and `azure`, registering their configured handlers and secret
//! resolvers. `doppler` and `infisical` remain compiled but unwired in the daemon.
//! Availability follows explicit configuration; registry membership alone does
//! not enable an operation or grant policy permission.

#[cfg(any(
    feature = "aws",
    feature = "github",
    feature = "gitlab",
    feature = "onepassword",
    feature = "bitwarden"
))]
mod endpoint;

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "bitwarden")]
pub mod bitwarden;
#[cfg(feature = "doppler")]
#[allow(dead_code)]
pub mod doppler;
#[cfg(feature = "gcp")]
pub mod gcp;
#[cfg(feature = "github")]
pub mod github;
#[cfg(feature = "gitlab")]
pub mod gitlab;
#[cfg(feature = "infisical")]
#[allow(dead_code)]
pub mod infisical;
#[cfg(feature = "onepassword")]
pub mod onepassword;
#[cfg(feature = "vault")]
pub mod vault;

// Crate-private "give me any secret ref" resolution shared by `github` and
// `gitlab`'s own token/value-ref resolution needs (see that module's doc
// comment). Neither module can build without it, and it has no other
// callers, so it only needs to exist when one of them is enabled.
#[cfg(any(feature = "github", feature = "gitlab"))]
mod internal_resolve;

use opaque_core::resolver::SecretResolver;

/// Build the standard set of provider secret resolvers wired into every
/// `CompositeResolver` the daemon constructs.
///
/// Promoted here from `opaqued::main.rs` (the daemon's composition root,
/// where this originated) because it has zero `opaqued`-specific
/// dependencies — pure provider-client construction from env vars — and,
/// since the `opaque-bounded-work` extraction, is called from three
/// different crates: `opaqued::main.rs` itself (threaded into
/// `opaque_sandbox::SandboxExecutor::new` as a `ResolverFactory` fn
/// pointer, re-invoked on every `sandbox.exec` request),
/// `opaque_bounded_work::ssh` (Vault-signed SSH certificate issuance), and
/// `opaque_bounded_work::inference` (credential-ref resolution for a
/// trusted inference profile). `opaque-providers` is the only common
/// ancestor all three already depend on, so hosting it here — rather than
/// duplicating it a third time or reaching back into `opaqued` — is the
/// only non-circular fix.
///
/// Not to be confused with `internal_resolve::default_secret_resolvers`
/// (crate-private, a smaller/independent copy used only by `github`/
/// `gitlab`'s own secret-ref resolution needs — see that module's doc
/// comment for why it stays separate).
pub fn default_secret_resolvers() -> Vec<Box<dyn SecretResolver>> {
    #[allow(unused_mut)] // `mut` goes unused if every provider feature below is off.
    let mut resolvers: Vec<Box<dyn SecretResolver>> = Vec::new();

    // 1Password backend selection:
    // 1. Connect Server URL configured → use Connect Server
    // 2. `op` CLI found in PATH → use `op` CLI
    // 3. Neither → onepassword disabled
    #[cfg(feature = "onepassword")]
    {
        if let Ok(url) = std::env::var(onepassword::client::CONNECT_URL_ENV) {
            match onepassword::client::OnePasswordClient::new(&url) {
                Ok(client) => resolvers.push(Box::new(
                    onepassword::resolve::OnePasswordResolver::new(client),
                )),
                Err(e) => tracing::warn!("1Password Connect client disabled: {e}"),
            }
        } else if let Ok(cli) = onepassword::op_cli::OpCliClient::new() {
            resolvers.push(Box::new(
                onepassword::resolve::OnePasswordResolver::from_cli(cli),
            ));
        }
    }

    // Bitwarden backend: available if URL scheme is valid.
    #[cfg(feature = "bitwarden")]
    {
        let bitwarden_url = std::env::var(bitwarden::client::BITWARDEN_URL_ENV)
            .unwrap_or_else(|_| bitwarden::client::DEFAULT_BASE_URL.to_owned());
        match bitwarden::client::BitwardenClient::new(&bitwarden_url) {
            Ok(client) => {
                resolvers.push(Box::new(bitwarden::resolve::BitwardenResolver::new(client)))
            }
            Err(e) => tracing::warn!("Bitwarden client disabled: {e}"),
        }
    }

    // AWS remains disabled until SigV4 exists. Only explicitly configured
    // loopback mocks can be reached by any aws: secret resolution path.
    #[cfg(feature = "aws")]
    {
        match aws::client::AwsClient::from_mock_env() {
            Ok(Some(client)) => resolvers.push(Box::new(aws::resolve::AwsResolver::new(client))),
            Ok(None) => {}
            Err(e) => tracing::warn!("AWS client disabled: {e}"),
        }
    }

    // Vault backend: available if URL scheme is valid.
    #[cfg(feature = "vault")]
    {
        match vault::client::VaultClient::new() {
            Ok(client) => resolvers.push(Box::new(vault::resolve::VaultResolver::new(client))),
            Err(e) => tracing::warn!("Vault client disabled: {e}"),
        }
    }

    resolvers
}
