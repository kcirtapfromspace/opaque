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
    pub approval_id: Uuid,
    pub request_id: Uuid,
    /// Operation name (e.g. `sandbox.exec`).
    pub operation: String,
    /// Sanitized client label for display on remote approvers.
    pub client_label: String,
    /// Human-readable, sanitized description rendered to the approver.
    pub description: String,
    /// Content hash binding the approval to the exact request.
    pub content_hash: String,
}

/// A decision from a factor, with the verified identity that made it.
#[derive(Debug, Clone)]
pub struct VerifiedDecision {
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
            let outcome = crate::approval::prompt(&ctx.description)
                .await
                .map_err(|e| match e {
                    crate::approval::ApprovalError::Unavailable => {
                        FactorError::Unavailable("no interactive session for local prompt".into())
                    }
                    other => FactorError::Failed(other.to_string()),
                })?;

            match outcome {
                crate::approval::PromptOutcome::Denied => Ok(VerifiedDecision {
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
                .map(|devices| devices.iter().any(|d| !d.revoked))
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
                        approved: true,
                        approver: Some(ApproverIdentity {
                            principal_id: who.into(),
                            label: who.into(),
                            source: ApproverSource::PairedDevice,
                        }),
                    }),
                    FakeOutcome::Deny => Ok(VerifiedDecision {
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
            approval_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            operation: "test.noop".into(),
            client_label: "test-client".into(),
            description: "test".into(),
            content_hash: "hash".into(),
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
