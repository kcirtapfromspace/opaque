//! Operation handler trait.
//!
//! Promoted from `opaqued::enclave` so that provider crates (which each
//! implement this trait once per provider) do not need to depend on the
//! `opaqued` binary crate — which, having no `lib.rs`, cannot be depended on
//! by anything.

use std::fmt;

use crate::operation::OperationRequest;

// ---------------------------------------------------------------------------
// Operation handler trait
// ---------------------------------------------------------------------------

/// Trait for operation handlers. Each registered operation has a corresponding
/// handler that performs the actual work.
///
/// Handlers receive the validated request and return a raw JSON payload.
/// The enclave sanitizes the payload before returning it to the client.
pub trait OperationHandler: Send + Sync + fmt::Debug {
    /// Execute the operation. Returns a raw (unsanitized) JSON payload.
    ///
    /// The handler must NOT return secret values in the payload. The sanitizer
    /// provides defense-in-depth, but handlers should be written to avoid
    /// including secrets in the first place.
    fn execute(
        &self,
        request: &OperationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + '_>,
    >;
}
