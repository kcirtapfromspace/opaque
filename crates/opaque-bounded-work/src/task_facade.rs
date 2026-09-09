//! The other half of the kernel-facing seam this crate needs from `Enclave`.
//!
//! `opaque_core::enclave_facade::EnclaveFacade` deliberately does **not**
//! cover `Enclave::ssh_profile`, `Enclave::inference_profile`, or
//! `Enclave::execute_task` — see that trait's module doc for the exact
//! reasoning. All three name types that live in *this* crate
//! (`crate::ssh::TrustedSshProfile`, `crate::inference::TrustedInferenceProfile`,
//! `crate::task_store::TaskStore`), so `opaque-core` (which cannot depend on
//! `opaque-bounded-work` without a cycle) can never host a trait covering
//! them. This crate hosts it instead.
//!
//! `opaqued` implements this trait for its real `Enclave` — the same
//! "narrow trait defined by the crate that needs it, foreign crate
//! implements it" direction already established by `OperationHandler`
//! (providers implement a trait `opaque-core` defines) and `ApprovalGate`
//! (approval backends implement a trait `opaque-core` defines). Here the
//! direction is the same shape, just with the trait living downstream of
//! `opaque-core` instead of in it: `opaqued` depending on
//! `opaque-bounded-work` and implementing a trait it defines is a normal,
//! non-circular direction (`opaque-bounded-work` never depends on
//! `opaqued`).
//!
//! `task_api::handle` takes both this trait (as `&dyn BoundedWorkFacade`)
//! and `EnclaveFacade` (as `&dyn EnclaveFacade`) as two separate parameters
//! rather than one combined bound: the two traits are implemented by two
//! different objects in `opaqued` (`Enclave` and `DaemonState`
//! respectively — `DaemonState` *has* an `Enclave`, it is not one), so a
//! single combined trait would force `opaqued` to implement
//! `BoundedWorkFacade` on `DaemonState` purely to delegate to
//! `self.enclave`, adding a layer of indirection for no benefit over
//! passing the two objects `opaqued` already has on hand.

use std::future::Future;
use std::pin::Pin;

use opaque_core::identity::PrincipalContext;
use opaque_core::operation::OperationRequest;
use opaque_core::task::{TaskApprovalMode, TaskRecord};

use crate::inference::TrustedInferenceProfile;
use crate::ssh::TrustedSshProfile;
use crate::task_store::TaskStore;

/// A callback `execute_task` invokes immediately before dispatching a
/// claimed task, to re-check liveness (principal context, workspace state)
/// against daemon state that may have changed since planning. Boxed rather
/// than generic so this trait stays object-safe (`&dyn BoundedWorkFacade`).
pub type CheckContext<'a> = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<Option<PrincipalContext>, String>> + Send + 'a>>
        + Send
        + Sync
        + 'a,
>;

/// The kernel-facing surface `opaque-bounded-work` needs from `Enclave`
/// beyond what `opaque_core::enclave_facade::EnclaveFacade` already covers.
pub trait BoundedWorkFacade: Send + Sync {
    /// The tenant's trusted SSH profile, when configured. Mirrors
    /// `Enclave::ssh_profile`.
    fn ssh_profile(&self) -> Result<&TrustedSshProfile, String>;

    /// The tenant's trusted inference profile, when configured. Mirrors
    /// `Enclave::inference_profile`.
    fn inference_profile(&self) -> Result<&TrustedInferenceProfile, String>;

    /// Claim and execute one stored task through the full enforcement
    /// funnel. Mirrors `Enclave::execute_task`, with its generic
    /// `check_context: impl Fn() -> impl Future<...>` parameter replaced by
    /// an equivalent boxed [`CheckContext`] so the method stays object-safe.
    fn execute_task<'a>(
        &'a self,
        store: &'a TaskStore,
        owner: &'a str,
        id: &'a str,
        request: OperationRequest,
        approval_mode: TaskApprovalMode,
        check_context: CheckContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<TaskRecord, String>> + Send + 'a>>;
}
