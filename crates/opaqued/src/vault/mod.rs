//! HashiCorp Vault connector primitives.
//!
//! This module currently provides secret ref resolution via `vault:` refs.
//! It does not expose plaintext-returning daemon operations.

pub mod client;
pub mod resolve;
