//! Pluggable approval-factor verifiers.
//!
//! Each configured [`ApprovalFactor`] maps to a [`FactorVerifier`] that knows
//! how to obtain a decision AND establish who made it. The contract that
//! matters: a verifier only ever returns an approver identity it has itself
//! verified — a paired device's Ed25519 signature checked against the pairing
//! store, a FIDO2 assertion checked against the stored credential, a login
//! session resolved at prompt time. Nothing client-relayed is trusted.
//!
//! When an operation requires approval with several factors configured, the
//! registry races them: the local prompt and the phone push run
//! simultaneously, and the first *verified* decision — approve or deny —
//! settles the approval. Factors that report themselves unavailable (no GUI
//! session, no paired devices, no server) drop out of the race; if every
//! factor drops out, the approval fails closed as unavailable.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::ApproverIdentity;
use opaque_core::operation::ApprovalFactor;
use uuid::Uuid;

/// What a verifier needs to run one approval round.
#[derive(Debug, Clone)]
pub struct ApprovalContext {
    pub binding: Option<opaque_core::workstation::ApprovalBinding>,
    pub approval_id: Uuid,
    pub request_id: Uuid,
    /// Operation name (e.g. `sandbox.exec`).
    pub operation: String,
    /// Sanitized client label for display on remote approvers.
    pub client_label: String,
    /// Human-readable, sanitized description rendered to the approver.
    /// Includes the request content hash (appended by the enclave), so
    /// factor challenges derived from the description are content-bound.
    pub description: String,
}

/// A decision from a factor, with the verified identity that made it.
#[derive(Debug, Clone)]
pub struct VerifiedDecision {
    pub workstation_receipt: Option<opaque_core::workstation::SignedWorkstationReceipt>,
    pub approved: bool,
    /// `None` only for factors that prove presence without naming anyone
    /// (a local biometric with no active login session).
    pub approver: Option<ApproverIdentity>,
}

/// Why a factor produced no decision.
#[derive(Debug)]
pub enum FactorError {
    /// The factor cannot run in this environment (no GUI session, no paired
    /// device, listener disabled). Other factors keep racing.
    Unavailable(String),
    /// The factor ran and broke (transport error, verification subsystem
    /// failure). Other factors keep racing; if all fail, approval fails.
    Failed(String),
}

impl fmt::Display for FactorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FactorError::Unavailable(msg) => write!(f, "unavailable: {msg}"),
            FactorError::Failed(msg) => write!(f, "failed: {msg}"),
        }
    }
}

type VerifyFuture = Pin<Box<dyn Future<Output = Result<VerifiedDecision, FactorError>> + Send>>;

/// One approval factor's implementation.
pub trait FactorVerifier: Send + Sync + fmt::Debug {
    fn authorize_receipt(
        &self,
        _requester: Option<&opaque_core::identity::PrincipalContext>,
        _receipt: &opaque_core::workstation::SignedWorkstationReceipt,
        _authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        Err("factor cannot fence remote authority".into())
    }
    fn revalidate_receipt(
        &self,
        _receipt: &opaque_core::workstation::SignedWorkstationReceipt,
    ) -> Result<(), String> {
        Err("factor cannot revalidate remote authority".into())
    }
    /// The factor this verifier serves.
    fn factor(&self) -> ApprovalFactor;

    /// Run one approval round. The returned future owns everything it needs
    /// (`'static`) so the registry can race and cancel freely — dropping the
    /// future must abandon the round cleanly.
    fn verify(&self, ctx: ApprovalContext) -> VerifyFuture;
}

/// Registry of verifiers, dispatching approval requests to every configured
/// factor concurrently.
#[derive(Default)]
pub struct FactorRegistry {
    verifiers: Vec<Arc<dyn FactorVerifier>>,
}

impl fmt::Debug for FactorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let factors: Vec<ApprovalFactor> = self.verifiers.iter().map(|v| v.factor()).collect();
        f.debug_struct("FactorRegistry")
            .field("factors", &factors)
            .finish()
    }
}

impl FactorRegistry {
    pub fn authorize_receipt(
        &self,
        requester: Option<&opaque_core::identity::PrincipalContext>,
        receipt: &opaque_core::workstation::SignedWorkstationReceipt,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.verifiers
            .iter()
            .find(|v| v.factor() == ApprovalFactor::PairedWorkstation)
            .ok_or("workstation verifier unavailable")?
            .authorize_receipt(requester, receipt, authorize)
    }
    pub fn revalidate_receipt(
        &self,
        receipt: &opaque_core::workstation::SignedWorkstationReceipt,
    ) -> Result<(), String> {
        let verifier = self
            .verifiers
            .iter()
            .find(|v| v.factor() == ApprovalFactor::PairedWorkstation)
            .ok_or("workstation verifier unavailable")?;
        verifier.revalidate_receipt(receipt)
    }
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a verifier. Later registrations for the same factor are kept
    /// too (e.g. two second-device transports) — all of them race.
    pub fn register(&mut self, verifier: Arc<dyn FactorVerifier>) {
        self.verifiers.push(verifier);
    }

    /// Which factors have at least one verifier.
    pub fn available_factors(&self) -> Vec<ApprovalFactor> {
        let mut factors: Vec<ApprovalFactor> = self.verifiers.iter().map(|v| v.factor()).collect();
        factors.dedup();
        factors
    }

    /// Race every verifier registered for the required factors; the first
    /// verified decision wins. Fails closed when no verifier can decide.
    pub async fn request_approval(
        &self,
        required_factors: &[ApprovalFactor],
        ctx: &ApprovalContext,
    ) -> Result<VerifiedDecision, String> {
        let mut in_flight: Vec<VerifyFuture> = Vec::new();
        let mut launched: Vec<ApprovalFactor> = Vec::new();

        for verifier in &self.verifiers {
            if required_factors.contains(&verifier.factor()) {
                launched.push(verifier.factor());
                in_flight.push(verifier.verify(ctx.clone()));
            }
        }

        if in_flight.is_empty() {
            // Mirrors H10: a required approval with no runnable factor must
            // fail closed, never silently pass.
            return Err(format!(
                "approval requires {required_factors:?} but no verifier is configured for any \
                 of them"
            ));
        }

        tracing::debug!(
            approval_id = %ctx.approval_id,
            factors = ?launched,
            "racing approval factors"
        );

        let mut failures: Vec<String> = Vec::new();
        while !in_flight.is_empty() {
            let (result, index, rest) = futures_util::future::select_all(in_flight).await;
            let factor = launched.remove(index);
            in_flight = rest;

            match result {
                Ok(decision) => {
                    tracing::info!(
                        approval_id = %ctx.approval_id,
                        %factor,
                        approved = decision.approved,
                        "approval settled by factor"
                    );
                    // Remaining futures drop here, abandoning their rounds.
                    return Ok(decision);
                }
                Err(e) => {
                    tracing::warn!(approval_id = %ctx.approval_id, %factor, "factor dropped out: {e}");
                    failures.push(format!("{factor}: {e}"));
                }
            }
        }

        Err(format!(
            "no approval factor could decide ({})",
            failures.join("; ")
        ))
    }
}

// ---------------------------------------------------------------------------
// Local biometric / polkit factor
// ---------------------------------------------------------------------------

/// Resolves the approver identity to bind to a successful local approval —
/// in production, the principal behind the daemon's current unexpired human
/// login session (source `LocalBioSession`).
pub type ApproverResolver = Arc<dyn Fn() -> Option<ApproverIdentity> + Send + Sync>;

/// The native local factor: macOS LocalAuthentication or the Linux polkit
/// helper. Presence is machine-verified; the *name* comes from the login
/// session (macOS) or the polkit-authenticated account (Linux helper).
pub struct LocalBioVerifier {
    approver_resolver: Option<ApproverResolver>,
}

impl fmt::Debug for LocalBioVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalBioVerifier")
            .field("has_approver_resolver", &self.approver_resolver.is_some())
            .finish()
    }
}

impl LocalBioVerifier {
    pub fn new(approver_resolver: Option<ApproverResolver>) -> Self {
        Self { approver_resolver }
    }
}

impl FactorVerifier for LocalBioVerifier {
    fn factor(&self) -> ApprovalFactor {
        ApprovalFactor::LocalBio
    }

    fn verify(&self, ctx: ApprovalContext) -> VerifyFuture {
        let resolver = self.approver_resolver.clone();
        Box::pin(async move {
            // Every operation can carry a scope, audience or argv too large for
            // the biometric reason line. Review the complete bound document in
            // the trusted scrollable helper, then authenticate its fingerprint.
            let result = crate::approval::prompt_task(&ctx.description).await;
            let outcome = result.map_err(|e| match e {
                crate::approval::ApprovalError::Unavailable => {
                    FactorError::Unavailable("no interactive session for local prompt".into())
                }
                other => FactorError::Failed(other.to_string()),
            })?;

            match outcome {
                crate::approval::PromptOutcome::Denied => Ok(VerifiedDecision {
                    workstation_receipt: None,
                    approved: false,
                    approver: None,
                }),
                crate::approval::PromptOutcome::Approved { account } => {
                    // Prefer the polkit-authenticated account when the helper
                    // reports one (Linux); otherwise bind the login-session
                    // principal (macOS LocalAuthentication proves presence,
                    // the session names the human).
                    let approver = account
                        .map(|acct| ApproverIdentity {
                            principal_id: format!("unix:{}", acct.uid),
                            label: acct.username,
                            source: opaque_core::audit::ApproverSource::PolkitAccount,
                        })
                        .or_else(|| resolver.as_ref().and_then(|r| r()));
                    Ok(VerifiedDecision {
                        workstation_receipt: None,
                        approved: true,
                        approver,
                    })
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Paired second-device factor
// ---------------------------------------------------------------------------

/// The second-device factor: pushes a challenge to the approval server where
/// a paired device fetches and signs it. The approval server verifies the
/// Ed25519 signature against the pairing store BEFORE relaying, so what this
/// verifier receives is already a [`VerifiedDeviceDecision`] — the approver
/// identity here is signature-bound, never client-claimed.
pub struct PairedDeviceVerifier {
    pairing: Arc<crate::pairing::PairingManager>,
    server: crate::approval_server::ApprovalServerHandle,
}

impl fmt::Debug for PairedDeviceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedDeviceVerifier").finish()
    }
}

impl PairedDeviceVerifier {
    pub fn new(
        pairing: Arc<crate::pairing::PairingManager>,
        server: crate::approval_server::ApprovalServerHandle,
    ) -> Self {
        Self { pairing, server }
    }
}

impl FactorVerifier for PairedDeviceVerifier {
    fn factor(&self) -> ApprovalFactor {
        ApprovalFactor::IosFaceId
    }

    fn verify(&self, ctx: ApprovalContext) -> VerifyFuture {
        let pairing = self.pairing.clone();
        let server = self.server.clone();
        Box::pin(async move {
            // No usable device → this factor cannot decide; let others race.
            let has_device = pairing
                .list_devices()
                .map(|devices| {
                    devices.iter().any(|d| {
                        !d.revoked
                            && d.confirmed
                            && d.kind == crate::pairing::store::DeviceKind::Ios
                    })
                })
                .unwrap_or(false);
            if !has_device {
                return Err(FactorError::Unavailable(
                    "no paired (unrevoked) device".into(),
                ));
            }

            let request_id = ctx.request_id.to_string();
            let pairing_challenge = pairing.create_challenge(&request_id, &ctx.description);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let wire = crate::approval_server::ApprovalChallenge {
                request_id: request_id.clone(),
                operation: ctx.operation.clone(),
                target: ctx.description.clone(),
                client_identity: ctx.client_label.clone(),
                created_at: now,
                expires_at: now + server.timeout().as_secs(),
                challenge_data: serde_json::to_string(&pairing_challenge)
                    .map_err(|e| FactorError::Failed(format!("challenge encode: {e}")))?,
            };

            let rx = server.submit_challenge(wire, pairing_challenge).await;

            match tokio::time::timeout(server.timeout(), rx).await {
                Ok(Ok(verified)) => {
                    let device = verified.device;
                    Ok(VerifiedDecision {
                        workstation_receipt: None,
                        approved: verified.approve,
                        approver: Some(ApproverIdentity {
                            // Attribute to the human who paired the device
                            // when known (lets require_distinct_approver
                            // catch self-approval via one's own phone);
                            // otherwise the cryptographic device identity.
                            principal_id: device
                                .paired_by
                                .clone()
                                .unwrap_or_else(|| format!("device:{}", device.device_id)),
                            label: format!("{} (paired device)", device.name),
                            source: opaque_core::audit::ApproverSource::PairedDevice,
                        }),
                    })
                }
                Ok(Err(_dropped)) => Err(FactorError::Failed(
                    "approval challenge expired unanswered".into(),
                )),
                Err(_elapsed) => Err(FactorError::Failed(
                    "second-device approval timed out".into(),
                )),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Paired workstation full-review factor
// ---------------------------------------------------------------------------

pub struct PairedWorkstationVerifier {
    pairing: Arc<crate::pairing::PairingManager>,
    server: crate::approval_server::ApprovalServerHandle,
}

impl fmt::Debug for PairedWorkstationVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedWorkstationVerifier").finish()
    }
}

impl PairedWorkstationVerifier {
    pub fn new(
        pairing: Arc<crate::pairing::PairingManager>,
        server: crate::approval_server::ApprovalServerHandle,
    ) -> Self {
        Self { pairing, server }
    }
}

impl FactorVerifier for PairedWorkstationVerifier {
    fn authorize_receipt(
        &self,
        requester: Option<&opaque_core::identity::PrincipalContext>,
        receipt: &opaque_core::workstation::SignedWorkstationReceipt,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.server.authorize_receipt(requester, receipt, authorize)
    }
    fn revalidate_receipt(
        &self,
        receipt: &opaque_core::workstation::SignedWorkstationReceipt,
    ) -> Result<(), String> {
        self.server.revalidate_receipt(receipt)
    }
    fn factor(&self) -> ApprovalFactor {
        ApprovalFactor::PairedWorkstation
    }

    fn verify(&self, ctx: ApprovalContext) -> VerifyFuture {
        let pairing = self.pairing.clone();
        let server = self.server.clone();
        Box::pin(async move {
            use opaque_core::workstation::{
                MAX_CHALLENGE_TTL_SECS, WorkstationChallenge, WorkstationReview, hex, review_hash,
            };
            if !pairing.has_workstation() {
                return Err(FactorError::Unavailable(
                    "no enrolled, allowed, unrevoked workstation".into(),
                ));
            }
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce)
                .map_err(|_| FactorError::Failed("workstation nonce unavailable".into()))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let ttl = server
                .timeout()
                .as_secs()
                .min(MAX_CHALLENGE_TTL_SECS as u64)
                .max(1) as i64;
            let mut review = WorkstationReview {
                challenge: WorkstationChallenge {
                    schema_version: 1,
                    authority: None,
                    broker_id: pairing.server_id().to_owned(),
                    approval_id: ctx.approval_id.to_string(),
                    request_id: ctx.request_id.to_string(),
                    operation: ctx.operation,
                    content_hash: review_hash(&ctx.description),
                    nonce: hex(&nonce),
                    created_at: now,
                    expires_at: now + ttl,
                },
                review_text: ctx.description,
            };
            if let Some(binding) = ctx.binding {
                server
                    .bind_remote_review(&mut review, binding)
                    .map_err(FactorError::Failed)?;
            }
            let verified = server
                .await_workstation_review(review)
                .await
                .map_err(FactorError::Failed)?;
            let device = pairing
                .workstation_device(&verified.device.device_id)
                .map_err(|_| {
                    FactorError::Failed("approving workstation is no longer authorized".into())
                })?;
            Ok(VerifiedDecision {
                workstation_receipt: verified.workstation_receipt,
                approved: verified.approve,
                approver: Some(ApproverIdentity {
                    principal_id: device
                        .paired_by
                        .unwrap_or_else(|| format!("workstation:{}", device.device_id)),
                    label: format!("{} (paired workstation)", device.name),
                    source: opaque_core::audit::ApproverSource::PairedWorkstation,
                }),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// FIDO2 / passkey factor
// ---------------------------------------------------------------------------

/// A FIDO2 approval whose assertion has been verified against the credential
/// store (challenge-bound, counter-checked).
#[derive(Debug, Clone)]
pub struct VerifiedFido2Approval {
    pub credential: crate::fido2::Fido2Credential,
}

struct Fido2Round {
    challenge_b64: String,
    started: std::time::Instant,
    ttl: std::time::Duration,
    tx: Option<tokio::sync::oneshot::Sender<VerifiedFido2Approval>>,
}

struct PendingRegistration {
    started: std::time::Instant,
    ttl: std::time::Duration,
}

/// Daemon-side FIDO2 approval coordination: issues per-approval challenges,
/// verifies assertions submitted over the daemon socket, and handles
/// credential registration. The authenticator ceremony itself (USB touch,
/// platform passkey UI) runs in whatever client drives it — this side only
/// ever accepts what verifies.
pub struct Fido2Approvals {
    manager: crate::fido2::Fido2Manager,
    rounds: std::sync::Mutex<std::collections::HashMap<String, Fido2Round>>,
    pending_registration: std::sync::Mutex<Option<PendingRegistration>>,
    round_ttl: std::time::Duration,
}

impl fmt::Debug for Fido2Approvals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fido2Approvals")
            .field("round_ttl", &self.round_ttl)
            .finish()
    }
}

impl Fido2Approvals {
    pub fn new(manager: crate::fido2::Fido2Manager, round_ttl: std::time::Duration) -> Self {
        Self {
            manager,
            rounds: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_registration: std::sync::Mutex::new(None),
            round_ttl,
        }
    }

    /// Whether at least one credential is registered.
    pub fn has_credentials(&self) -> bool {
        self.manager
            .list_credentials()
            .map(|c| !c.is_empty())
            .unwrap_or(false)
    }

    /// Registered credentials (for listing).
    pub fn list_credentials(
        &self,
    ) -> Result<Vec<crate::fido2::Fido2Credential>, crate::fido2::Fido2Error> {
        self.manager.list_credentials()
    }

    /// Remove a credential.
    pub fn remove_credential(
        &self,
        credential_id: &str,
    ) -> Result<crate::fido2::Fido2Credential, crate::fido2::Fido2Error> {
        self.manager.remove_credential(credential_id)
    }

    /// Issue an unpredictable key-possession challenge without creating a
    /// registration round. The caller owns its principal binding, deadline,
    /// human authorization and single-use nonce lifecycle.
    pub fn binding_challenge(&self) -> Result<(String, String), String> {
        self.manager
            .authentication_challenge(&[])
            .map(|challenge| (challenge.challenge, challenge.rp_id))
            .map_err(|error| format!("binding challenge unavailable: {error}"))
    }

    /// Associate an already enrolled key with a trusted verified principal.
    /// This cannot register a key or replace a different existing binding.
    pub fn bind_credential(
        &self,
        assertion: &crate::fido2::Fido2Assertion,
        challenge: &str,
        binding: &crate::fido2::Fido2PrincipalBinding,
    ) -> Result<crate::fido2::Fido2Credential, String> {
        self.manager
            .bind_credential(assertion, challenge, binding)
            .map_err(|error| format!("credential binding rejected: {error}"))
    }

    /// Verify possession only when the complete persisted principal/broker
    /// binding matches. The caller separately rechecks live authorization.
    pub fn verify_bound_assertion(
        &self,
        assertion: &crate::fido2::Fido2Assertion,
        challenge: &str,
        binding: &crate::fido2::Fido2PrincipalBinding,
    ) -> Result<crate::fido2::Fido2Credential, String> {
        self.manager
            .verify_bound_assertion(assertion, challenge, binding)
            .map_err(|error| format!("bound assertion rejected: {error}"))
    }

    /// Begin an approval round: issue a challenge and park a sender for the
    /// verified result. Returns the receiver the factor verifier awaits.
    fn begin_round(
        &self,
        request_id: &str,
    ) -> Result<tokio::sync::oneshot::Receiver<VerifiedFido2Approval>, String> {
        let challenge = self
            .manager
            .registration_challenge()
            .map_err(|e| format!("challenge generation failed: {e}"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.rounds.lock().expect("rounds lock").insert(
            request_id.to_owned(),
            Fido2Round {
                challenge_b64: challenge.challenge,
                started: std::time::Instant::now(),
                ttl: self.round_ttl,
                tx: Some(tx),
            },
        );
        Ok(rx)
    }

    /// Abandon a round (verifier future dropped or timed out).
    fn end_round(&self, request_id: &str) {
        self.rounds.lock().expect("rounds lock").remove(request_id);
    }

    /// Pending rounds, for a client that will drive an authenticator.
    pub fn pending_rounds(&self) -> Vec<(String, String, String, Vec<String>)> {
        let allowed: Vec<String> = self
            .manager
            .list_credentials()
            .map(|creds| creds.into_iter().map(|c| c.credential_id).collect())
            .unwrap_or_default();
        let rp_id = self.manager.rp_id().to_owned();
        let rounds = self.rounds.lock().expect("rounds lock");
        rounds
            .iter()
            .filter(|(_, r)| r.started.elapsed() <= r.ttl)
            .map(|(id, r)| {
                (
                    id.clone(),
                    r.challenge_b64.clone(),
                    rp_id.clone(),
                    allowed.clone(),
                )
            })
            .collect()
    }

    /// Verify a submitted assertion for a pending round; on success, the
    /// factor verifier's receiver resolves with the VERIFIED credential.
    /// The assertion must answer exactly the challenge this round issued.
    pub fn respond(
        &self,
        request_id: &str,
        assertion: &crate::fido2::Fido2Assertion,
    ) -> Result<VerifiedFido2Approval, String> {
        let challenge_b64 = {
            let rounds = self.rounds.lock().expect("rounds lock");
            let round = rounds
                .get(request_id)
                .ok_or_else(|| "no pending FIDO2 round for this request".to_owned())?;
            if round.started.elapsed() > round.ttl {
                return Err("FIDO2 round expired".into());
            }
            round.challenge_b64.clone()
        };

        let credential = self
            .manager
            .verify_and_record_assertion(assertion, &challenge_b64)
            .map_err(|e| format!("assertion verification failed: {e}"))?;

        let verified = VerifiedFido2Approval { credential };

        // Only after full verification does the round consume.
        let tx = {
            let mut rounds = self.rounds.lock().expect("rounds lock");
            rounds.get_mut(request_id).and_then(|round| round.tx.take())
        };
        if let Some(tx) = tx {
            let _ = tx.send(verified.clone());
        }
        Ok(verified)
    }

    /// Begin a registration ceremony: issue the challenge a client-side
    /// authenticator must incorporate.
    pub fn register_begin(&self) -> Result<(String, String), String> {
        let challenge = self
            .manager
            .registration_challenge()
            .map_err(|e| format!("challenge generation failed: {e}"))?;
        *self.pending_registration.lock().expect("registration lock") = Some(PendingRegistration {
            started: std::time::Instant::now(),
            ttl: self.round_ttl,
        });
        Ok((challenge.challenge, challenge.rp_id))
    }

    /// Complete registration with the authenticator's response. Validates
    /// user presence, the RP hash, and the key; the human authorization for
    /// adding this credential is the out-of-band approval gating the socket
    /// method (this simplified flow does not verify attestation chains).
    pub fn register_complete(
        &self,
        response: &crate::fido2::Fido2RegistrationResponse,
        label: &str,
    ) -> Result<crate::fido2::Fido2Credential, String> {
        {
            let pending = self.pending_registration.lock().expect("registration lock");
            let reg = pending.as_ref().ok_or_else(|| {
                "no registration in progress — run register start first".to_owned()
            })?;
            if reg.started.elapsed() > reg.ttl {
                return Err("registration window expired".into());
            }
        }

        let credential = self
            .manager
            .validate_and_store_registration(response, label)
            .map_err(|e| format!("registration invalid: {e}"))?;

        *self.pending_registration.lock().expect("registration lock") = None;
        Ok(credential)
    }
}

/// The FIDO2 / passkey factor. APPROVE-ONLY by design: a verified assertion
/// is an approval; anything else (timeout, unsigned rejection, transport
/// noise) just drops this factor from the race — an unverified party must
/// never produce a verified DENY.
pub struct Fido2Verifier {
    approvals: Arc<Fido2Approvals>,
}

impl fmt::Debug for Fido2Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fido2Verifier").finish()
    }
}

impl Fido2Verifier {
    pub fn new(approvals: Arc<Fido2Approvals>) -> Self {
        Self { approvals }
    }
}

impl FactorVerifier for Fido2Verifier {
    fn factor(&self) -> ApprovalFactor {
        ApprovalFactor::Fido2
    }

    fn verify(&self, ctx: ApprovalContext) -> VerifyFuture {
        let approvals = self.approvals.clone();
        Box::pin(async move {
            if !approvals.has_credentials() {
                return Err(FactorError::Unavailable(
                    "no FIDO2 credentials registered".into(),
                ));
            }

            let request_id = ctx.request_id.to_string();
            let rx = approvals
                .begin_round(&request_id)
                .map_err(FactorError::Failed)?;

            // Guard: whatever way this future ends, the round is cleaned up.
            struct RoundGuard<'a>(&'a Fido2Approvals, String);
            impl Drop for RoundGuard<'_> {
                fn drop(&mut self) {
                    self.0.end_round(&self.1);
                }
            }
            let _guard = RoundGuard(&approvals, request_id.clone());

            match tokio::time::timeout(approvals.round_ttl, rx).await {
                Ok(Ok(verified)) => {
                    let cred = verified.credential;
                    let id_prefix: String = cred.credential_id.chars().take(12).collect();
                    let principal_id = cred
                        .principal_binding
                        .as_ref()
                        .map(|binding| binding.principal_id.as_str().to_owned())
                        .unwrap_or_else(|| format!("fido2:{id_prefix}"));
                    Ok(VerifiedDecision {
                        workstation_receipt: None,
                        approved: true,
                        approver: Some(ApproverIdentity {
                            principal_id,
                            label: format!("{} (FIDO2 key)", cred.label),
                            source: opaque_core::audit::ApproverSource::Fido2,
                        }),
                    })
                }
                Ok(Err(_dropped)) => Err(FactorError::Failed("FIDO2 round abandoned".into())),
                Err(_elapsed) => Err(FactorError::Failed(
                    "FIDO2 approval timed out (no assertion submitted)".into(),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::audit::ApproverSource;

    /// Scripted verifier for registry tests.
    #[derive(Debug)]
    struct FakeVerifier {
        factor: ApprovalFactor,
        outcome: FakeOutcome,
        delay_ms: u64,
    }

    #[derive(Debug, Clone)]
    enum FakeOutcome {
        Approve(&'static str),
        Deny,
        Unavailable,
        Fail,
    }

    impl FactorVerifier for FakeVerifier {
        fn factor(&self) -> ApprovalFactor {
            self.factor
        }

        fn verify(&self, _ctx: ApprovalContext) -> VerifyFuture {
            let outcome = self.outcome.clone();
            let delay = self.delay_ms;
            Box::pin(async move {
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                match outcome {
                    FakeOutcome::Approve(who) => Ok(VerifiedDecision {
                        workstation_receipt: None,
                        approved: true,
                        approver: Some(ApproverIdentity {
                            principal_id: who.into(),
                            label: who.into(),
                            source: ApproverSource::PairedDevice,
                        }),
                    }),
                    FakeOutcome::Deny => Ok(VerifiedDecision {
                        workstation_receipt: None,
                        approved: false,
                        approver: None,
                    }),
                    FakeOutcome::Unavailable => Err(FactorError::Unavailable("not here".into())),
                    FakeOutcome::Fail => Err(FactorError::Failed("broke".into())),
                }
            })
        }
    }

    fn ctx() -> ApprovalContext {
        ApprovalContext {
            binding: None,
            approval_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            operation: "test.noop".into(),
            client_label: "test-client".into(),
            description: "test".into(),
        }
    }

    /// End-to-end through the REAL pairing manager and approval server state:
    /// a paired device signs the relayed challenge; the verifier returns a
    /// signature-bound approver attributed to the pairing human.
    #[tokio::test]
    async fn paired_device_verifier_end_to_end_with_real_signature() {
        use crate::approval_server::{
            ApprovalServer, ApprovalServerConfig, generate_self_signed_cert,
        };
        use crate::pairing::challenge::decision_bytes;
        use crate::pairing::store::DeviceStore;
        use ed25519_dalek::{Signer, SigningKey};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(dir.path().join("devices.json"), vec![9u8; 32]);
        let pairing = Arc::new(crate::pairing::PairingManager::new(
            "srv".into(),
            SigningKey::generate(&mut rand::rngs::OsRng),
            0,
            store,
        ));
        let (_qr, nonce) = pairing.generate_qr_payload(Some("hum_owner".into()));
        let device_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let (device, _token) = pairing
            .complete_pairing(&nonce, device_key.verifying_key().as_bytes(), "Phone")
            .unwrap();
        pairing.confirm_device(&device.device_id).unwrap();

        let identity = generate_self_signed_cert().unwrap();
        let server = ApprovalServer::new(
            ApprovalServerConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                tls_cert_der: identity.cert_der,
                tls_key_der: identity.key_der,
                timeout_secs: 5,
            },
            pairing.clone(),
        )
        .unwrap();
        let handle = server.handle();

        let verifier = PairedDeviceVerifier::new(pairing.clone(), handle.clone());

        // Race the verifier against a "device" task that pulls the pending
        // challenge (as the HTTP layer would), signs it with the real device
        // key, and pushes it through the same verification the respond
        // handler runs. The full HTTPS round-trip is covered in
        // approval_server tests; this exercises the verifier's side.
        let verify_fut = verifier.verify(ctx());
        let pairing2 = pairing.clone();
        let sign_task = tokio::spawn(async move {
            for _ in 0..100 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                if let Some((pc, tx)) = crate::approval_server::test_take_pending(&handle).await {
                    let sig = device_key.sign(&decision_bytes(&pc, true));
                    let verified = pairing2
                        .verify_approval(&pc, &sig.to_bytes(), &device.device_id, true)
                        .expect("signature must verify");
                    let _ = tx.send(crate::approval_server::VerifiedDeviceDecision {
                        workstation_receipt: None,
                        approve: true,
                        device: verified,
                    });
                    return;
                }
            }
            panic!("verifier never submitted a challenge");
        });

        let decision = verify_fut.await.unwrap();
        sign_task.await.unwrap();

        assert!(decision.approved);
        let approver = decision.approver.unwrap();
        assert_eq!(approver.principal_id, "hum_owner");
        assert_eq!(approver.source, ApproverSource::PairedDevice);
        assert!(approver.label.contains("Phone"));
    }

    #[tokio::test]
    async fn paired_device_verifier_unavailable_without_devices() {
        use crate::approval_server::{
            ApprovalServer, ApprovalServerConfig, generate_self_signed_cert,
        };
        use crate::pairing::store::DeviceStore;
        use ed25519_dalek::SigningKey;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(dir.path().join("devices.json"), vec![9u8; 32]);
        let pairing = Arc::new(crate::pairing::PairingManager::new(
            "srv".into(),
            SigningKey::generate(&mut rand::rngs::OsRng),
            0,
            store,
        ));
        let identity = generate_self_signed_cert().unwrap();
        let server = ApprovalServer::new(
            ApprovalServerConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                tls_cert_der: identity.cert_der,
                tls_key_der: identity.key_der,
                timeout_secs: 1,
            },
            pairing.clone(),
        )
        .unwrap();

        let verifier = PairedDeviceVerifier::new(pairing, server.handle());
        let err = verifier.verify(ctx()).await.unwrap_err();
        assert!(matches!(err, FactorError::Unavailable(_)));
    }

    /// Build a Fido2Approvals over a temp store, optionally with one
    /// registered software credential. Returns the signing key for it.
    fn fido2_rig(
        with_credential: bool,
    ) -> (
        Arc<Fido2Approvals>,
        Option<p256::ecdsa::SigningKey>,
        tempfile::TempDir,
    ) {
        use crate::fido2::{Fido2CredentialStore, Fido2Manager, NoLocalTransport};

        let dir = tempfile::tempdir().unwrap();
        let store = Fido2CredentialStore::new(dir.path().join("creds.json"), vec![3u8; 32]);
        let manager = Fido2Manager::new(store, Box::new(NoLocalTransport), "opaque.local".into());
        let approvals = Arc::new(Fido2Approvals::new(
            manager,
            std::time::Duration::from_secs(5),
        ));

        let sk = if with_credential {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use sha2::Digest;

            let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
            let pk = sk.verifying_key().to_encoded_point(false);
            // Register through the real validation path: UP set, correct RP.
            let rp_hash = sha2::Sha256::digest("opaque.local".as_bytes());
            let mut auth_data = Vec::with_capacity(37);
            auth_data.extend_from_slice(&rp_hash);
            auth_data.push(0x01);
            auth_data.extend_from_slice(&0u32.to_be_bytes());
            let response = crate::fido2::Fido2RegistrationResponse {
                credential_id: "soft-key-1".into(),
                public_key: URL_SAFE_NO_PAD.encode(pk.as_bytes()),
                counter: 0,
                authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
            };
            approvals.register_begin().unwrap();
            approvals
                .register_complete(&response, "Test Software Key")
                .unwrap();
            Some(sk)
        } else {
            None
        };

        (approvals, sk, dir)
    }

    /// Sign an assertion for a pending round with the software key —
    /// exactly what a client driving a real authenticator would submit.
    fn sign_round_assertion(
        sk: &p256::ecdsa::SigningKey,
        challenge_b64: &str,
        counter: u32,
    ) -> crate::fido2::Fido2Assertion {
        sign_assertion_with_options(sk, challenge_b64, counter, 0x01, None, false)
    }

    fn sign_assertion_with_options(
        sk: &p256::ecdsa::SigningKey,
        challenge_b64: &str,
        counter: u32,
        flags: u8,
        origin: Option<&str>,
        cross_origin: bool,
    ) -> crate::fido2::Fido2Assertion {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use p256::ecdsa::signature::Signer;
        use sha2::Digest;

        let rp_hash = sha2::Sha256::digest("opaque.local".as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());

        let mut client_data = serde_json::json!({"type":"webauthn.get","challenge":challenge_b64,"crossOrigin":cross_origin});
        if let Some(origin) = origin {
            client_data["origin"] = serde_json::json!(origin);
        }
        let client_data = serde_json::to_string(&client_data).unwrap();
        let client_data_hash = sha2::Sha256::digest(client_data.as_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let (sig, _): (p256::ecdsa::Signature, _) = sk.sign(&signed);

        crate::fido2::Fido2Assertion {
            credential_id: "soft-key-1".into(),
            authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json: URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
            signature: URL_SAFE_NO_PAD.encode(sig.to_der()),
        }
    }

    fn test_principal_binding() -> crate::fido2::Fido2PrincipalBinding {
        crate::fido2::Fido2PrincipalBinding {
            principal_id: opaque_core::identity::PrincipalId::parse(
                "hum_00000000000000000000000000000001",
            )
            .unwrap(),
            issuer: "https://idp.example.com".into(),
            subject: "employee-1".into(),
            tenant_id: "enterprise-a".into(),
            broker_id: "01a0729c-c688-7651-b876-4af57644d2f8".into(),
        }
    }

    fn sign_bound_assertion(
        sk: &p256::ecdsa::SigningKey,
        challenge: &str,
        counter: u32,
    ) -> crate::fido2::Fido2Assertion {
        sign_assertion_with_options(
            sk,
            challenge,
            counter,
            0x05,
            Some("https://opaque.local"),
            false,
        )
    }

    #[test]
    fn fido2_principal_binding_is_exact_persistent_and_requires_existing_key() {
        let (approvals, key, dir) = fido2_rig(true);
        let key = key.unwrap();
        let binding = test_principal_binding();
        let (challenge, rp_id) = approvals.binding_challenge().unwrap();
        assert_eq!(rp_id, "opaque.local");
        assert_ne!(challenge, approvals.binding_challenge().unwrap().0);
        let initial = sign_bound_assertion(&key, &challenge, 1);
        assert!(
            approvals
                .verify_bound_assertion(&initial, &challenge, &binding)
                .is_err()
        );
        let credential = approvals
            .bind_credential(&initial, &challenge, &binding)
            .unwrap();
        assert_eq!(credential.counter, 1);
        assert_eq!(credential.principal_binding, Some(binding.clone()));
        assert!(
            approvals
                .verify_bound_assertion(&initial, &challenge, &binding)
                .is_err()
        );

        let (challenge, _) = approvals.binding_challenge().unwrap();
        let assertion = sign_bound_assertion(&key, &challenge, 2);
        let mut mismatches = Vec::new();
        let mut other = binding.clone();
        other.principal_id =
            opaque_core::identity::PrincipalId::parse("hum_00000000000000000000000000000002")
                .unwrap();
        mismatches.push(other);
        let mut other = binding.clone();
        other.issuer = "https://other.example.com".into();
        mismatches.push(other);
        let mut other = binding.clone();
        other.subject = "employee-2".into();
        mismatches.push(other);
        let mut other = binding.clone();
        other.tenant_id = "enterprise-b".into();
        mismatches.push(other);
        let mut other = binding.clone();
        other.broker_id = "01a0729c-c688-7651-b876-4af57644d2f9".into();
        mismatches.push(other);
        for other in mismatches {
            assert!(
                approvals
                    .bind_credential(&assertion, &challenge, &other)
                    .is_err()
            );
            assert!(
                approvals
                    .verify_bound_assertion(&assertion, &challenge, &other)
                    .is_err()
            );
        }
        approvals
            .verify_bound_assertion(&assertion, &challenge, &binding)
            .unwrap();
        drop(approvals);

        let store =
            crate::fido2::Fido2CredentialStore::new(dir.path().join("creds.json"), vec![3u8; 32]);
        let manager = crate::fido2::Fido2Manager::new(
            store,
            Box::new(crate::fido2::NoLocalTransport),
            "opaque.local".into(),
        );
        let reopened = Fido2Approvals::new(manager, std::time::Duration::from_secs(5));
        assert_eq!(
            reopened.list_credentials().unwrap()[0].principal_binding,
            Some(binding.clone())
        );
        let mut other = binding.clone();
        other.subject = "employee-2".into();
        let fresh = sign_bound_assertion(&key, &challenge, 3);
        assert!(
            reopened
                .bind_credential(&fresh, &challenge, &other)
                .is_err()
        );
        assert_eq!(reopened.list_credentials().unwrap()[0].counter, 2);
        reopened
            .verify_bound_assertion(&fresh, &challenge, &binding)
            .unwrap();

        let (empty, _, _empty_dir) = fido2_rig(false);
        assert!(empty.bind_credential(&fresh, &challenge, &binding).is_err());
    }

    #[test]
    fn fido2_binding_rejects_forgery_wrong_ceremony_origin_and_missing_uv() {
        let (approvals, key, _dir) = fido2_rig(true);
        let key = key.unwrap();
        let binding = test_principal_binding();
        let (challenge, _) = approvals.binding_challenge().unwrap();
        let interloper = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let invalid = [
            sign_bound_assertion(&interloper, &challenge, 1),
            sign_bound_assertion(&key, "wrong-challenge", 1),
            sign_assertion_with_options(
                &key,
                &challenge,
                1,
                0x01,
                Some("https://opaque.local"),
                false,
            ),
            sign_assertion_with_options(
                &key,
                &challenge,
                1,
                0x04,
                Some("https://opaque.local"),
                false,
            ),
            sign_assertion_with_options(&key, &challenge, 1, 0x05, None, false),
            sign_assertion_with_options(
                &key,
                &challenge,
                1,
                0x05,
                Some("https://other.example.com"),
                false,
            ),
            sign_assertion_with_options(
                &key,
                &challenge,
                1,
                0x05,
                Some("https://opaque.local"),
                true,
            ),
        ];
        for assertion in invalid {
            assert!(
                approvals
                    .bind_credential(&assertion, &challenge, &binding)
                    .is_err()
            );
            let credential = approvals.list_credentials().unwrap().remove(0);
            assert_eq!(credential.counter, 0);
            assert_eq!(credential.principal_binding, None);
        }
        approvals
            .bind_credential(
                &sign_bound_assertion(&key, &challenge, 1),
                &challenge,
                &binding,
            )
            .unwrap();
    }

    #[test]
    fn fido2_concurrent_binding_never_overwrites_another_principal() {
        let (approvals, key, _dir) = fido2_rig(true);
        let (challenge, _) = approvals.binding_challenge().unwrap();
        let assertion = sign_bound_assertion(&key.unwrap(), &challenge, 1);
        let first = test_principal_binding();
        let mut second = first.clone();
        second.subject = "employee-2".into();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let attempts: Vec<_> = [first, second]
            .into_iter()
            .map(|binding| {
                let approvals = approvals.clone();
                let assertion = assertion.clone();
                let challenge = challenge.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    approvals.bind_credential(&assertion, &challenge, &binding)
                })
            })
            .collect();
        assert_eq!(
            attempts
                .into_iter()
                .map(|attempt| attempt.join().unwrap())
                .filter(Result::is_ok)
                .count(),
            1
        );
        assert_eq!(approvals.list_credentials().unwrap()[0].counter, 1);
    }

    #[tokio::test]
    async fn fido2_bound_key_attributes_the_complete_human_principal() {
        let (approvals, key, _dir) = fido2_rig(true);
        let key = key.unwrap();
        let binding = test_principal_binding();
        let (challenge, _) = approvals.binding_challenge().unwrap();
        approvals
            .bind_credential(
                &sign_bound_assertion(&key, &challenge, 1),
                &challenge,
                &binding,
            )
            .unwrap();
        let verifier = Fido2Verifier::new(approvals.clone());
        let responder = async {
            loop {
                if let Some((id, challenge, _, _)) = approvals.pending_rounds().first().cloned() {
                    approvals
                        .respond(&id, &sign_round_assertion(&key, &challenge, 2))
                        .unwrap();
                    break;
                }
                tokio::task::yield_now().await;
            }
        };
        let (decision, ()) = tokio::join!(verifier.verify(ctx()), responder);
        let approver = decision.unwrap().approver.unwrap();
        assert_eq!(approver.principal_id, binding.principal_id.as_str());
        assert_eq!(approver.source, ApproverSource::Fido2);
    }

    #[tokio::test]
    async fn fido2_verifier_end_to_end_with_software_key() {
        let (approvals, sk, _dir) = fido2_rig(true);
        let sk = sk.unwrap();
        let verifier = Fido2Verifier::new(approvals.clone());
        let context = ctx();
        let request_id = context.request_id.to_string();

        let verify_fut = verifier.verify(context);
        let responder = tokio::spawn({
            let approvals = approvals.clone();
            async move {
                // Wait for the round, sign its challenge, submit through the
                // same respond() path the socket method uses.
                for _ in 0..100 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let rounds = approvals.pending_rounds();
                    if let Some((rid, challenge, rp_id, allowed)) = rounds.first().cloned() {
                        assert_eq!(rid, request_id);
                        assert_eq!(rp_id, "opaque.local");
                        assert_eq!(allowed, vec!["soft-key-1".to_string()]);
                        let assertion = sign_round_assertion(&sk, &challenge, 7);
                        approvals.respond(&rid, &assertion).expect("must verify");
                        return;
                    }
                }
                panic!("verifier never opened a FIDO2 round");
            }
        });

        let decision = verify_fut.await.unwrap();
        responder.await.unwrap();

        assert!(decision.approved);
        let approver = decision.approver.unwrap();
        assert!(approver.principal_id.starts_with("fido2:"));
        assert_eq!(approver.source, ApproverSource::Fido2);
        assert!(approver.label.contains("Test Software Key"));
    }

    #[tokio::test]
    async fn fido2_respond_rejects_wrong_challenge_and_forged_signature() {
        let (approvals, sk, _dir) = fido2_rig(true);
        let sk = sk.unwrap();

        let rx = approvals.begin_round("req-x").unwrap();
        let (_, challenge, _, _) = approvals.pending_rounds().first().cloned().unwrap();

        // Assertion answering a DIFFERENT challenge: rejected.
        let stale = sign_round_assertion(&sk, "c29tZS1vdGhlci1jaGFsbGVuZ2U", 3);
        assert!(approvals.respond("req-x", &stale).is_err());

        // Forged signature (different key) over the RIGHT challenge: rejected.
        let interloper = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let forged = sign_round_assertion(&interloper, &challenge, 4);
        assert!(approvals.respond("req-x", &forged).is_err());

        // The round SURVIVES failed attempts; the genuine key still lands.
        let good = sign_round_assertion(&sk, &challenge, 5);
        approvals.respond("req-x", &good).unwrap();
        drop(rx);
    }

    #[tokio::test]
    async fn fido2_verifier_unavailable_without_credentials() {
        let (approvals, _none, _dir) = fido2_rig(false);
        let verifier = Fido2Verifier::new(approvals);
        let err = verifier.verify(ctx()).await.unwrap_err();
        assert!(matches!(err, FactorError::Unavailable(_)));
    }

    #[tokio::test]
    async fn fido2_round_cleaned_up_when_verifier_future_drops() {
        let (approvals, _sk, _dir) = fido2_rig(true);
        let verifier = Fido2Verifier::new(approvals.clone());

        let fut = verifier.verify(ctx());
        // Poll once to open the round, then drop (a faster factor won).
        tokio::select! {
            biased;
            _ = fut => panic!("verify cannot complete with nobody responding"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
        // RoundGuard must have cleared the pending round on drop.
        assert!(approvals.pending_rounds().is_empty());
    }

    fn registry(verifiers: Vec<FakeVerifier>) -> FactorRegistry {
        let mut reg = FactorRegistry::new();
        for v in verifiers {
            reg.register(Arc::new(v));
        }
        reg
    }

    #[tokio::test]
    async fn first_verified_decision_wins_the_race() {
        let reg = registry(vec![
            FakeVerifier {
                factor: ApprovalFactor::LocalBio,
                outcome: FakeOutcome::Approve("slow-local"),
                delay_ms: 200,
            },
            FakeVerifier {
                factor: ApprovalFactor::IosFaceId,
                outcome: FakeOutcome::Approve("fast-device"),
                delay_ms: 5,
            },
        ]);
        let decision = reg
            .request_approval(
                &[ApprovalFactor::LocalBio, ApprovalFactor::IosFaceId],
                &ctx(),
            )
            .await
            .unwrap();
        assert!(decision.approved);
        assert_eq!(decision.approver.unwrap().principal_id, "fast-device");
    }

    #[tokio::test]
    async fn verified_deny_settles_immediately() {
        let reg = registry(vec![
            FakeVerifier {
                factor: ApprovalFactor::LocalBio,
                outcome: FakeOutcome::Deny,
                delay_ms: 5,
            },
            FakeVerifier {
                factor: ApprovalFactor::IosFaceId,
                outcome: FakeOutcome::Approve("late-device"),
                delay_ms: 500,
            },
        ]);
        let decision = reg
            .request_approval(
                &[ApprovalFactor::LocalBio, ApprovalFactor::IosFaceId],
                &ctx(),
            )
            .await
            .unwrap();
        assert!(
            !decision.approved,
            "a verified deny is a decision, not a fallthrough"
        );
    }

    #[tokio::test]
    async fn unavailable_factor_drops_out_and_the_other_decides() {
        let reg = registry(vec![
            FakeVerifier {
                factor: ApprovalFactor::LocalBio,
                outcome: FakeOutcome::Unavailable,
                delay_ms: 0,
            },
            FakeVerifier {
                factor: ApprovalFactor::IosFaceId,
                outcome: FakeOutcome::Approve("device"),
                delay_ms: 20,
            },
        ]);
        let decision = reg
            .request_approval(
                &[ApprovalFactor::LocalBio, ApprovalFactor::IosFaceId],
                &ctx(),
            )
            .await
            .unwrap();
        assert!(decision.approved);
    }

    #[tokio::test]
    async fn all_factors_failing_fails_closed() {
        let reg = registry(vec![
            FakeVerifier {
                factor: ApprovalFactor::LocalBio,
                outcome: FakeOutcome::Unavailable,
                delay_ms: 0,
            },
            FakeVerifier {
                factor: ApprovalFactor::IosFaceId,
                outcome: FakeOutcome::Fail,
                delay_ms: 0,
            },
        ]);
        let err = reg
            .request_approval(
                &[ApprovalFactor::LocalBio, ApprovalFactor::IosFaceId],
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(err.contains("no approval factor could decide"), "{err}");
    }

    #[tokio::test]
    async fn no_verifier_for_required_factors_fails_closed() {
        let reg = registry(vec![FakeVerifier {
            factor: ApprovalFactor::LocalBio,
            outcome: FakeOutcome::Approve("x"),
            delay_ms: 0,
        }]);
        // Fido2 required, only LocalBio registered.
        let err = reg
            .request_approval(&[ApprovalFactor::Fido2], &ctx())
            .await
            .unwrap_err();
        assert!(err.contains("no verifier is configured"), "{err}");
    }

    #[tokio::test]
    async fn factor_not_required_does_not_run() {
        let reg = registry(vec![
            FakeVerifier {
                factor: ApprovalFactor::LocalBio,
                outcome: FakeOutcome::Approve("local"),
                delay_ms: 0,
            },
            // Would approve as the wrong identity if ever launched.
            FakeVerifier {
                factor: ApprovalFactor::Fido2,
                outcome: FakeOutcome::Approve("must-not-run"),
                delay_ms: 0,
            },
        ]);
        let decision = reg
            .request_approval(&[ApprovalFactor::LocalBio], &ctx())
            .await
            .unwrap();
        assert_eq!(decision.approver.unwrap().principal_id, "local");
    }
}
