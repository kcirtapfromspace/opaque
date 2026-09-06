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
