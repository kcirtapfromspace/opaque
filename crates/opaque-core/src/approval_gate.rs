//! Approval gate trait and its outcome type.
//!
//! Promoted from `opaqued::enclave` together, since the trait's method
//! returns `ApprovalOutcome` — an implementor outside `opaqued` could not
//! otherwise name its own return type.

use uuid::Uuid;

use crate::audit::ApproverIdentity;
use crate::operation::{ApprovalFactor, OperationRequest};

// ---------------------------------------------------------------------------
// Approval gate trait
// ---------------------------------------------------------------------------

/// The result of one approval interaction.
///
/// SECURITY INVARIANT: `approver` must only ever be attached by the gate that
/// actually VERIFIED the identity it names. The local biometric factor proves
/// device-owner presence and binds the *name* to the active login session
/// (source `LocalBioSession`). Paired-device / FIDO2 attribution (source
/// `PairedDevice`) requires real signature verification against the pairing
/// store — the dormant `approval_server` relays client-supplied device ids
/// WITHOUT verification and must never be used as an approver source.
#[derive(Debug, Clone)]
pub struct ApprovalOutcome {
    /// Whether the human (or configured backend) approved the request.
    pub approved: bool,
    /// The verified approver identity, when the gate could establish one.
    /// `None` on denial, and on approval paths with no identity binding
    /// (e.g. biometric passed but nobody is logged in).
    pub approver: Option<ApproverIdentity>,
    pub workstation_receipt: Option<crate::workstation::SignedWorkstationReceipt>,
}

impl ApprovalOutcome {
    /// Approved, with no approver identity binding available.
    pub fn approved_anonymous() -> Self {
        Self {
            approved: true,
            approver: None,
            workstation_receipt: None,
        }
    }

    /// Approved by a verified identity.
    pub fn approved_by(approver: ApproverIdentity) -> Self {
        Self {
            approved: true,
            approver: Some(approver),
            workstation_receipt: None,
        }
    }

    /// Denied.
    pub fn denied() -> Self {
        Self {
            approved: false,
            approver: None,
            workstation_receipt: None,
        }
    }
}

/// Trait for the approval gate. The enclave calls this to present
/// operation-bound approval challenges to the user.
///
/// Approval is ALWAYS bound to a specific operation request. There is no
/// generic "approve" endpoint.
pub trait ApprovalGate: Send + Sync + std::fmt::Debug {
    fn authorize_receipt(
        &self,
        _requester: Option<&crate::identity::PrincipalContext>,
        _receipt: &crate::workstation::SignedWorkstationReceipt,
        _authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        Err("approval backend cannot fence remote authority".into())
    }
    /// Recheck the currently enrolled key, reviewer role and authority epoch
    /// immediately before the existing durable effect dispatch fence.
    fn revalidate_receipt(
        &self,
        _receipt: &crate::workstation::SignedWorkstationReceipt,
    ) -> Result<(), String> {
        Err("approval backend cannot revalidate a remote receipt".into())
    }

    fn request_bound_approval(
        &self,
        approval_id: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        description: &str,
        _binding: Option<crate::workstation::ApprovalBinding>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
    > {
        self.request_approval(approval_id, request, factors, description)
    }

    /// Present an approval challenge for the given operation request.
    ///
    /// The implementation must:
    /// - Display the operation, target, client identity, and TTL to the user
    /// - Use the specified approval factor(s)
    /// - Return `Ok` with [`ApprovalOutcome`] (approved/denied, plus the
    ///   verified approver identity when one exists — see the invariant on
    ///   [`ApprovalOutcome`])
    /// - Return `Err` if the approval mechanism is unavailable
    ///
    /// The `approval_id` is used for audit correlation.
    fn request_approval(
        &self,
        approval_id: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        description: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
    >;
}
