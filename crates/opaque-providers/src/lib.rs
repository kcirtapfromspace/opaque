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
//! (eventually) feature-gated independently of the daemon's kernel.
//!
//! `azure`, `doppler`, `gcp`, and `infisical` are not wired into the daemon's
//! `default_secret_resolvers()` or `Enclave::builder()` today (dormant,
//! compiled-but-unused, same as before this extraction) — `#[allow(dead_code)]`
//! mirrors the attribute `opaqued`'s `main.rs` used to carry on their `mod`
//! declarations.

pub mod aws;
#[allow(dead_code)]
pub mod azure;
pub mod bitwarden;
#[allow(dead_code)]
pub mod doppler;
#[allow(dead_code)]
pub mod gcp;
pub mod github;
pub mod gitlab;
#[allow(dead_code)]
pub mod infisical;
pub mod onepassword;
pub mod vault;

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
    let mut resolvers: Vec<Box<dyn SecretResolver>> = Vec::new();

    // 1Password backend selection:
    // 1. Connect Server URL configured → use Connect Server
    // 2. `op` CLI found in PATH → use `op` CLI
    // 3. Neither → onepassword disabled
    if let Ok(url) = std::env::var(onepassword::client::CONNECT_URL_ENV) {
        match onepassword::client::OnePasswordClient::new(&url) {
            Ok(client) => resolvers.push(Box::new(onepassword::resolve::OnePasswordResolver::new(
                client,
            ))),
            Err(e) => tracing::warn!("1Password Connect client disabled: {e}"),
        }
    } else if let Ok(cli) = onepassword::op_cli::OpCliClient::new() {
        resolvers.push(Box::new(onepassword::resolve::OnePasswordResolver::from_cli(
            cli,
        )));
    }

    // Bitwarden backend: available if URL scheme is valid.
    let bitwarden_url = std::env::var(bitwarden::client::BITWARDEN_URL_ENV)
        .unwrap_or_else(|_| bitwarden::client::DEFAULT_BASE_URL.to_owned());
    match bitwarden::client::BitwardenClient::new(&bitwarden_url) {
        Ok(client) => resolvers.push(Box::new(bitwarden::resolve::BitwardenResolver::new(client))),
        Err(e) => tracing::warn!("Bitwarden client disabled: {e}"),
    }

    // AWS remains disabled until SigV4 exists. Only explicitly configured
    // loopback mocks can be reached by any aws: secret resolution path.
    match aws::client::AwsClient::from_mock_env() {
        Ok(Some(client)) => resolvers.push(Box::new(aws::resolve::AwsResolver::new(client))),
        Ok(None) => {}
        Err(e) => tracing::warn!("AWS client disabled: {e}"),
    }

    // Vault backend: available if URL scheme is valid.
    match vault::client::VaultClient::new() {
        Ok(client) => resolvers.push(Box::new(vault::resolve::VaultResolver::new(client))),
        Err(e) => tracing::warn!("Vault client disabled: {e}"),
    }

    resolvers
}
