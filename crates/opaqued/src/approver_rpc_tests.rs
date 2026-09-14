//! Actual daemon dispatch and persistent approver stores with scripted review.
//! Public software keys exercise protocol verification, not physical presence.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use opaque_approval::{
    factors::{ApprovalContext, FactorVerifier, Fido2Approvals, Fido2Verifier},
    fido2::{
        Fido2Assertion, Fido2CredentialStore, Fido2Manager, Fido2RegistrationResponse,
        NoLocalTransport,
    },
    pairing::{PairingManager, store::DeviceStore},
};
use opaque_core::{approval_gate::ApprovalOutcome, audit::InMemoryAuditEmitter, identity::Role};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::{Mutex, atomic::AtomicBool};
use std::time::Duration;

pub(super) const ISSUER: &str = "https://idp.example.com";
const RP: &str = "opaque.fixture";
const CREDENTIAL: &str = "cHVibGljLWZpeHR1cmUta2V5";

#[derive(Debug)]
pub(super) struct Review {
    pub approve: AtomicBool,
    pub hold: AtomicBool,
    pub entered: tokio::sync::Semaphore,
    pub release: tokio::sync::Semaphore,
    pub requests: Mutex<Vec<(String, String)>>,
}
#[derive(Debug)]
struct ReviewGate(Arc<Review>);
impl ApprovalGate for ReviewGate {
    fn request_approval(
        &self,
        _: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        description: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalOutcome, String>> + Send + '_>> {
        assert_eq!(factors, &[ApprovalFactor::LocalBio]);
        self.0
            .requests
            .lock()
            .unwrap()
            .push((request.operation.clone(), description.into()));
        Box::pin(async {
            self.0.entered.add_permits(1);
            if self.0.hold.load(Ordering::SeqCst) {
                self.0.release.acquire().await.unwrap().forget();
            }
            Ok(if self.0.approve.load(Ordering::SeqCst) {
                ApprovalOutcome::approved_anonymous()
            } else {
                ApprovalOutcome::denied()
            })
        })
    }
}

pub(super) struct Fixture {
    pub state: DaemonState,
    pub audit: Arc<InMemoryAuditEmitter>,
    pub review: Arc<Review>,
    pub directory: tempfile::TempDir,
    pub admin: PrincipalId,
}
impl Fixture {
    pub fn new(approve: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let review = Arc::new(Review {
            approve: AtomicBool::new(approve),
            hold: AtomicBool::new(false),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            requests: Mutex::new(Vec::new()),
        });
        let mut state = crate::tests::build_test_state(audit.clone(), false);
        state.enclave = Arc::new(
            Enclave::builder()
                .approval_gate(Box::new(ReviewGate(review.clone())))
                .audit(audit.clone())
                .build()
                .unwrap(),
        );
        let runtime = identity::IdentityRuntime::initialize(
            identity::IdentityConfig {
                issuer: ISSUER.into(),
                client_id: "fixture-cli".into(),
                audience: None,
                redirect_port: None,
                session_ttl_secs: None,
                allowed_email_domains: vec![],
                allowed_subjects: vec![],
                required: false,
                persona: None,
                service_principals: vec![],
            },
            directory.path(),
        )
        .unwrap()
        .with_audit(audit.clone());
        let admin = runtime
            .store
            .upsert_human(ISSUER, "admin", None, None, &BTreeSet::from([Role::Admin]))
            .unwrap()
            .id;
        runtime
            .store
            .create_human_session(&admin, 3600, ISSUER)
            .unwrap();
        state.identity = Some(Arc::new(runtime));
        Self {
            state,
            audit,
            review,
            directory,
            admin,
        }
    }
    pub fn peer() -> ClientIdentity {
        ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(std::process::id() as i32),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        }
    }
    pub async fn call(&self, method: &str, params: Value) -> Response {
        handle_request(
            &self.state,
            Request {
                id: 17,
                method: method.into(),
                params,
            },
            &Self::peer(),
            ClientType::Human,
            None,
        )
        .await
    }
    pub fn succeeded(&self, method: &str) -> usize {
        self.audit
            .events()
            .iter()
            .filter(|e| {
                e.kind == AuditEventKind::OperationSucceeded
                    && e.operation.as_deref() == Some(method)
            })
            .count()
    }
    fn devices(&self) -> PathBuf {
        self.directory.path().join("devices.json")
    }
    fn credentials(&self) -> PathBuf {
        self.directory.path().join("credentials.json")
    }
    fn pairing(&self) -> PairingManager {
        PairingManager::new(
            "fixture-broker".into(),
            ed25519_dalek::SigningKey::from_bytes(&[19; 32]),
            12345,
            DeviceStore::new(self.devices(), vec![31; 32]),
        )
    }
    fn fido(&self) -> Fido2Approvals {
        Fido2Approvals::new(
            Fido2Manager::new(
                Fido2CredentialStore::new(self.credentials(), vec![32; 32]),
                Box::new(NoLocalTransport),
                RP.into(),
            ),
            Duration::from_secs(10),
        )
    }
    fn enable(&mut self) {
        self.state.pairing = Some(Arc::new(self.pairing()));
        self.state.fido2 = Some(Arc::new(self.fido()));
        self.state.approval_server_addr = Some("127.0.0.1:12345".parse().unwrap());
    }
}
pub(super) fn ok(response: Response) -> Value {
    assert!(response.error.is_none(), "{:?}", response.error);
    response.result.unwrap()
}
pub(super) fn error(response: Response, code: &str) {
    assert!(response.result.is_none());
    assert_eq!(response.error.unwrap().code, code);
}
fn signing() -> SigningKey {
    SigningKey::from_bytes((&[47; 32]).into()).unwrap()
}
fn auth_data(counter: u32) -> Vec<u8> {
    let mut data = Sha256::digest(RP.as_bytes()).to_vec();
    data.push(0x05);
    data.extend_from_slice(&counter.to_be_bytes());
    data
}
fn registration() -> Fido2RegistrationResponse {
    Fido2RegistrationResponse {
        credential_id: CREDENTIAL.into(),
        public_key: URL_SAFE_NO_PAD
            .encode(signing().verifying_key().to_encoded_point(false).as_bytes()),
        counter: 0,
        authenticator_data: URL_SAFE_NO_PAD.encode(auth_data(0)),
    }
}
fn assertion(challenge: &str, counter: u32) -> Fido2Assertion {
    let client = serde_json::to_vec(&json!({"type":"webauthn.get","challenge":challenge,"origin":format!("https://{RP}"),"crossOrigin":false})).unwrap();
    let auth = auth_data(counter);
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    let signature: Signature = signing().sign(&signed);
    Fido2Assertion {
        credential_id: CREDENTIAL.into(),
        authenticator_data: URL_SAFE_NO_PAD.encode(auth),
        client_data_json: URL_SAFE_NO_PAD.encode(client),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
    }
}

#[tokio::test]
async fn disabled_approver_routes_never_prompt_or_create_persistent_authority() {
    let fixture = Fixture::new(true);
    for method in [
        "device_pair_start",
        "device_pair_confirm",
        "device_list",
        "device_revoke",
        "fido2_register_start",
        "fido2_register_complete",
        "fido2_list",
        "fido2_remove",
        "fido2_pending",
        "fido2_respond",
    ] {
        error(fixture.call(method, json!({})).await, "factor_disabled");
        assert_eq!(fixture.succeeded(method), 0);
    }
    assert!(fixture.review.requests.lock().unwrap().is_empty());
    assert!(!fixture.devices().exists() && !fixture.credentials().exists());
}

#[tokio::test]
async fn device_confirmation_reviews_exact_fingerprint_and_revocation_survives_reopen() {
    let mut fixture = Fixture::new(false);
    fixture.enable();
    error(
        fixture.call("device_pair_start", json!({})).await,
        "permission_denied",
    );
    assert!(!fixture.devices().exists());
    assert_eq!(fixture.succeeded("device_pair_start"), 0);
    fixture.review.approve.store(true, Ordering::SeqCst);
    let start = ok(fixture.call("device_pair_start", json!({})).await);
    assert_eq!(start["server_addr"], "127.0.0.1:12345");
    let nonce = start["qr_payload"]["nonce"].as_str().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    let manager = fixture.state.pairing.as_ref().unwrap();
    let (device, token) = manager
        .complete_pairing(
            nonce,
            key.verifying_key().as_bytes(),
            "fixture\nphone\u{202e}",
        )
        .unwrap();
    assert_eq!(device.paired_by.as_deref(), Some(fixture.admin.as_str()));
    assert!(!manager.verify_device_token(&device.device_id, &token));
    let before = std::fs::read(fixture.devices()).unwrap();
    fixture.review.approve.store(false, Ordering::SeqCst);
    error(
        fixture
            .call("device_pair_confirm", json!({"device_id":device.device_id}))
            .await,
        "permission_denied",
    );
    assert_eq!(std::fs::read(fixture.devices()).unwrap(), before);
    assert!(!manager.verify_device_token(&device.device_id, &token));
    assert_eq!(fixture.succeeded("device_pair_confirm"), 0);
    let review = fixture
        .review
        .requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(review.0, "device_pair_confirm");
    assert!(review.1.contains(&device.key_fingerprint()));
    assert!(!review.1.contains('\u{202e}') && !review.1.contains("fixture\nphone"));
    fixture.review.approve.store(true, Ordering::SeqCst);
    assert_eq!(
        ok(fixture
            .call("device_pair_confirm", json!({"device_id":device.device_id}))
            .await)["confirmed"],
        true
    );
    assert!(
        fixture
            .pairing()
            .verify_device_token(&device.device_id, &token)
    );
    let listed = ok(fixture.call("device_list", json!({})).await);
    assert_eq!(listed["count"], 1);
    assert_eq!(
        listed["devices"][0]["fingerprint"],
        device.key_fingerprint()
    );
    assert!(!listed.to_string().contains(&token));
    let prompts = fixture.review.requests.lock().unwrap().len();
    assert_eq!(
        ok(fixture
            .call("device_revoke", json!({"device_id":device.device_id}))
            .await)["revoked"],
        true
    );
    assert!(
        !fixture
            .pairing()
            .verify_device_token(&device.device_id, &token)
    );
    assert_eq!(
        fixture.review.requests.lock().unwrap().len(),
        prompts,
        "revocation must not wait on killed factor"
    );
    assert_eq!(fixture.succeeded("device_pair_confirm"), 1);
    assert_eq!(fixture.succeeded("device_revoke"), 1);
}

#[tokio::test]
async fn device_bad_references_and_corrupt_store_never_claim_confirmation() {
    let mut fixture = Fixture::new(true);
    fixture.enable();
    for method in ["device_pair_confirm", "device_revoke"] {
        error(fixture.call(method, json!({})).await, "bad_request");
        error(
            fixture.call(method, json!({"device_id":"unknown"})).await,
            "not_found",
        );
    }
    assert!(fixture.review.requests.lock().unwrap().is_empty());
    assert_eq!(
        ok(fixture.call("device_list", json!({})).await),
        json!({"count":0,"devices":[]})
    );
    std::fs::write(fixture.devices(), b"corrupt retained store").unwrap();
    for (method, code) in [
        ("device_list", "internal"),
        ("device_pair_confirm", "internal"),
        ("device_revoke", "not_found"),
    ] {
        error(
            fixture.call(method, json!({"device_id":"unknown"})).await,
            code,
        );
        assert_eq!(fixture.succeeded(method), 0);
        assert_eq!(
            std::fs::read(fixture.devices()).unwrap(),
            b"corrupt retained store"
        );
    }
    assert!(fixture.review.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn fido_registration_requires_review_rejects_invalid_payload_and_consumes_success_once() {
    let mut fixture = Fixture::new(false);
    fixture.enable();
    error(
        fixture.call("fido2_register_start", json!({})).await,
        "permission_denied",
    );
    error(
        fixture
            .call(
                "fido2_register_complete",
                json!({"response":registration()}),
            )
            .await,
        "invalid_registration",
    );
    assert!(!fixture.credentials().exists());
    fixture.review.approve.store(true, Ordering::SeqCst);
    let start = ok(fixture.call("fido2_register_start", json!({})).await);
    assert_eq!(start["rp_id"], RP);
    assert!(start["challenge"].as_str().unwrap().len() >= 32);
    for malformed in [json!({}), json!({"response":{"credential_id":CREDENTIAL}})] {
        error(
            fixture.call("fido2_register_complete", malformed).await,
            "bad_request",
        );
    }
    let mut wrong = registration();
    wrong.authenticator_data = URL_SAFE_NO_PAD.encode(vec![0u8; 37]);
    error(
        fixture
            .call("fido2_register_complete", json!({"response":wrong}))
            .await,
        "invalid_registration",
    );
    assert!(!fixture.credentials().exists());
    assert_eq!(fixture.succeeded("fido2_register_complete"), 0);
    let result = ok(fixture
        .call(
            "fido2_register_complete",
            json!({"response":registration(),"label":"fixture\nkey\u{202e}"}),
        )
        .await);
    assert_eq!(result["credential_id"], CREDENTIAL);
    assert!(
        !result["label"]
            .as_str()
            .unwrap()
            .contains(['\n', '\u{202e}'])
    );
    let before = std::fs::read(fixture.credentials()).unwrap();
    error(
        fixture
            .call(
                "fido2_register_complete",
                json!({"response":registration()}),
            )
            .await,
        "invalid_registration",
    );
    assert_eq!(std::fs::read(fixture.credentials()).unwrap(), before);
    let listed = ok(fixture.call("fido2_list", json!({})).await);
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["credentials"][0]["credential_id"], CREDENTIAL);
    assert_eq!(fixture.fido().list_credentials().unwrap().len(), 1);
    assert_eq!(fixture.succeeded("fido2_register_complete"), 1);
}

#[tokio::test]
async fn fido_corrupt_store_and_invalid_removal_never_emit_success() {
    let mut fixture = Fixture::new(true);
    fixture.enable();
    assert_eq!(
        ok(fixture.call("fido2_list", json!({})).await),
        json!({"count":0,"credentials":[]})
    );
    error(fixture.call("fido2_remove", json!({})).await, "bad_request");
    error(
        fixture
            .call("fido2_remove", json!({"credential_id":"unknown"}))
            .await,
        "not_found",
    );
    std::fs::write(fixture.credentials(), b"corrupt retained credentials").unwrap();
    error(fixture.call("fido2_list", json!({})).await, "internal");
    ok(fixture.call("fido2_register_start", json!({})).await);
    error(
        fixture
            .call(
                "fido2_register_complete",
                json!({"response":registration()}),
            )
            .await,
        "invalid_registration",
    );
    error(
        fixture
            .call("fido2_remove", json!({"credential_id":CREDENTIAL}))
            .await,
        "not_found",
    );
    assert_eq!(
        std::fs::read(fixture.credentials()).unwrap(),
        b"corrupt retained credentials"
    );
    for method in ["fido2_remove", "fido2_register_complete"] {
        assert_eq!(fixture.succeeded(method), 0);
    }
    std::fs::remove_file(fixture.credentials()).unwrap();
    ok(fixture
        .call(
            "fido2_register_complete",
            json!({"response":registration()}),
        )
        .await);
    let prompts = fixture.review.requests.lock().unwrap().len();
    assert_eq!(
        ok(fixture
            .call("fido2_remove", json!({"credential_id":CREDENTIAL}))
            .await)["removed"],
        true
    );
    assert!(fixture.fido().list_credentials().unwrap().is_empty());
    error(
        fixture
            .call("fido2_remove", json!({"credential_id":CREDENTIAL}))
            .await,
        "not_found",
    );
    assert_eq!(fixture.succeeded("fido2_remove"), 1);
    assert_eq!(fixture.review.requests.lock().unwrap().len(), prompts);
}

#[tokio::test]
async fn fido_response_dispatch_verifies_signature_records_counter_and_cleans_pending_round() {
    let mut fixture = Fixture::new(true);
    fixture.enable();
    ok(fixture.call("fido2_register_start", json!({})).await);
    ok(fixture
        .call(
            "fido2_register_complete",
            json!({"response":registration()}),
        )
        .await);
    assert_eq!(
        ok(fixture.call("fido2_pending", json!({})).await)["count"],
        0
    );
    error(
        fixture.call("fido2_respond", json!({})).await,
        "bad_request",
    );
    error(
        fixture
            .call("fido2_respond", json!({"request_id":"unknown"}))
            .await,
        "bad_request",
    );
    error(
        fixture
            .call(
                "fido2_respond",
                json!({"request_id":"unknown","assertion":assertion("unused",1)}),
            )
            .await,
        "invalid_assertion",
    );
    let request = Uuid::new_v4();
    let verifier = Fido2Verifier::new(fixture.state.fido2.as_ref().unwrap().clone());
    let mut pending = verifier.verify(ApprovalContext {
        binding: None,
        approval_id: Uuid::new_v4(),
        request_id: request,
        operation: "fixture.approval".into(),
        client_label: "software fixture".into(),
        description: "Verify software-key protocol only".into(),
    });
    // Poll exactly until the factor waits for a real assertion; no sleeps or
    // task detachment are needed, and dropping the future abandons its round.
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    let rounds = ok(fixture.call("fido2_pending", json!({})).await);
    assert_eq!(rounds["count"], 1);
    assert_eq!(rounds["rounds"][0]["request_id"], request.to_string());
    assert_eq!(
        rounds["rounds"][0]["allowed_credentials"],
        json!([CREDENTIAL])
    );
    let challenge = rounds["rounds"][0]["challenge"].as_str().unwrap();
    let before = std::fs::read(fixture.credentials()).unwrap();
    let mut bad = assertion(challenge, 1);
    bad.signature = URL_SAFE_NO_PAD.encode(b"invalid signature");
    error(
        fixture
            .call(
                "fido2_respond",
                json!({"request_id":request,"assertion":bad}),
            )
            .await,
        "invalid_assertion",
    );
    assert_eq!(std::fs::read(fixture.credentials()).unwrap(), before);
    assert_eq!(
        ok(fixture.call("fido2_pending", json!({})).await)["count"],
        1
    );
    let signed = assertion(challenge, 1);
    let result = ok(fixture
        .call(
            "fido2_respond",
            json!({"request_id":request,"assertion":signed}),
        )
        .await);
    assert_eq!(result, json!({"verified":true}));
    let decision = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(decision.approved);
    assert!(
        decision
            .approver
            .unwrap()
            .principal_id
            .starts_with("fido2:")
    );
    assert_eq!(
        ok(fixture.call("fido2_pending", json!({})).await)["count"],
        0
    );
    error(
        fixture
            .call(
                "fido2_respond",
                json!({"request_id":request,"assertion":signed}),
            )
            .await,
        "invalid_assertion",
    );
    assert_eq!(fixture.fido().list_credentials().unwrap()[0].counter, 1);
    assert_eq!(fixture.succeeded("fido2_respond"), 1);
}
