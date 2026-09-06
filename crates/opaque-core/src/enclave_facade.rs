//! A narrow, kernel-facing trait covering the small set of `Enclave` (and
//! `DaemonState`-owned) operations needed by transport/dispatch code that is
//! destined to move out of the `opaqued` binary crate: the fixed-manifest
//! task API, the delegated-provisioning API, and the `github` RPC
//! convenience wrapper.
//!
//! `opaqued` is a binary-only crate (no `lib.rs`): `Enclave` and
//! `DaemonState` are defined in it and cannot be named from another crate.
//! Call sites that only need this narrow surface depend on `EnclaveFacade`
//! (statically or as `&dyn EnclaveFacade`) instead of the concrete types, so
//! the daemon can implement it once, centrally, rather than every future
//! extraction improvising its own seam.
//!
//! ## Deliberately not covered here
//!
//! Checked against the call sites this trait was extracted from
//! (`task_api.rs`, `provisioning_api.rs`, the `github` RPC arm in `main.rs`)
//! and left out because their signatures depend on opaqued-local types that
//! are not moving to `opaque-core` in this step:
//!
//! - `Enclave::ssh_profile` / `Enclave::inference_profile` — return
//!   `&TrustedSshProfile` / `&TrustedInferenceProfile`. Both types carry live
//!   credential/session state and live in `opaqued::ssh` /
//!   `opaqued::inference`, destined for `opaque-bounded-work`, not
//!   `opaque-core`.
//! - `Enclave::execute_task` — takes `&opaqued::task_store::TaskStore`
//!   (same destination), and is additionally generic over a `check_context`
//!   callback, which is not object-safe.
//!
//! Call sites that need these keep going through the concrete `Arc<Enclave>`
//! (via `DaemonState`) until `ssh.rs` / `inference/` / `task_store.rs` move.

use std::future::Future;
use std::pin::Pin;

use crate::audit::ApproverIdentity;
use crate::identity::PrincipalContext;
use crate::operation::{ClientIdentity, ClientType, OperationRequest};
use crate::policy::PolicyEngine;
use crate::sanitize::{Sanitized, SanitizedResponse};
use crate::task::TaskManifest;

/// The kernel-facing surface that transport/dispatch code depends on instead
/// of naming `Enclave`/`DaemonState` directly.
pub trait EnclaveFacade: Send + Sync {
    /// Validate a task manifest and derive its operation name / secret ref
    /// names before it is durably stored. Mirrors `Enclave::preflight_task`.
    fn preflight_task(
        &self,
        request: &mut OperationRequest,
        manifest: &TaskManifest,
    ) -> Result<(), String>;

    /// Read-only preflight for a staging-release reconciliation observation.
    /// Mirrors `Enclave::preflight_task_observation`.
    fn preflight_task_observation(
        &self,
        base: &OperationRequest,
        manifest: &TaskManifest,
    ) -> Result<(), String>;

    /// Execute a single operation request through the full enforcement
    /// funnel. Mirrors `Enclave::execute`.
    fn execute(
        &self,
        request: OperationRequest,
    ) -> Pin<Box<dyn Future<Output = SanitizedResponse<Sanitized>> + Send + '_>>;

    /// Hot-swap the policy engine (federation bundle refresh). Returns the
    /// new rule count. Mirrors `Enclave::swap_policy`.
    fn swap_policy(&self, policy: PolicyEngine) -> usize;

    /// Out-of-band control-plane approval (session start, role changes,
    /// delegated provisioning ceremonies). Mirrors
    /// `Enclave::request_control_approval`, with its error collapsed to a
    /// `String` so this trait does not need to name `opaqued`'s
    /// `EnclaveError`.
    fn request_control_approval<'a>(
        &'a self,
        identity: &'a ClientIdentity,
        client_type: ClientType,
        operation_label: &'a str,
        action_description: &'a str,
        reason: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ApproverIdentity>, String>> + Send + 'a>>;

    /// Resolve the verified principal context bound to an agent session
    /// (`None` for an unauthenticated / non-delegated session). Promoted
    /// from the `resolve_principal_context` free function in `opaqued`'s
    /// `main.rs`, which owns `agent_sessions`/`identity`/`federation` state
    /// that has no other reason to live in `opaque-core`.
    fn resolve_principal_context<'a>(
        &'a self,
        session_id: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PrincipalContext>, String>> + Send + 'a>>;

    /// Re-verify a previously-verified workspace claim against the client's
    /// live process state (a TOCTOU recheck point during long-running task
    /// planning/execution — the same shape of problem
    /// `resolve_principal_context` solves for principal liveness). Mirrors
    /// the free function `verify_workspace` in `opaqued`'s `main.rs`, which
    /// owns the bounded git-subprocess verifier (`workspace_process.rs`,
    /// deliberately kernel-side per the release security review that added
    /// it — a cross-cutting precondition check, not bounded-work-specific
    /// logic) that has no reason to live in `opaque-core`.
    ///
    /// Call sites that only need a *single*, transport-level verification
    /// (the `github`/`gitlab`/`onepassword`/`bitwarden`/`exec`/task-family
    /// RPC methods) do not need this method at all: `opaqued::main.rs`'s
    /// `handle_request` computes that once per request and passes the
    /// already-verified `WorkspaceContext` down by value. This method exists
    /// for the small number of call sites (currently: the fixed-manifest
    /// task API's release-observation reconciliation and task-execution
    /// paths) that must re-verify *again*, at a point in time chosen by
    /// their own control flow after further async work — a value computed
    /// once upfront cannot serve that, only a live callback into the kernel
    /// can.
    fn verify_workspace<'a>(
        &'a self,
        claimed: &'a crate::operation::WorkspaceContext,
        client_pid: Option<i32>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}
