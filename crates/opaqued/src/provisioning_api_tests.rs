//! RPC integration fixtures, not evidence of a real IdP or hardware ceremony.
//! Native review is a test gate; assertions are genuinely signed with a fixed
//! synthetic P-256 key. Production challenge generation and verification run.

use std::{collections::BTreeSet, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use opaque_core::{
    audit::InMemoryAuditEmitter,
    identity::{PrincipalId, Role, now_unix},
    operation::{ClientIdentity, ClientType},
    proto::{Request, Response},
    tenant::TenantId,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    DaemonState,
    identity::{
        IdentityConfig, IdentityRuntime, PersonaConfig, ServicePrincipalConfig,
        persona::VerifiedPersonaClaims,
        provisioning::{AccessProfile, ProvisioningConfig},
    },
    tenant::{TenantBoundary, TenantConfig},
};
use opaque_approval::fido2::{
    Fido2Assertion, Fido2CredentialStore, Fido2Manager, Fido2RegistrationResponse,
    NoLocalTransport,
};

const ISSUER: &str = "https://idp.example.com";
const RP: &str = "opaque.test";
const CREDENTIAL: &str = "c3ludGhldGljLXRlc3Qta2V5";

fn peer(uid: u32) -> ClientIdentity {
    ClientIdentity {
        uid,
        gid: uid,
        pid: None,
        exe_path: None,
        exe_sha256: None,
        codesign_team_id: None,
    }
}

fn ok(response: Response) -> Value {
    assert!(
        response.error.is_none(),
        "unexpected denial: {:?}",
        response.error
    );
    response.result.expect("successful RPC result")
}

fn denied(response: Response) {
    assert!(
        response.error.is_some(),
        "unexpected authorization: {:?}",
        response.result
    );
    assert!(response.result.is_none());
}

struct Fixture {
    state: DaemonState,
    admin: PrincipalId,
    signing: SigningKey,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(approve: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let tenant = TenantBoundary::open(
            &TenantConfig {
                id: TenantId::parse("provisioning-test").unwrap(),
            },
            directory.path(),
            true,
        )
        .unwrap();
        let persona = PersonaConfig {
            groups_claim: "groups".into(),
            max_age_secs: 300,
        };
        let runtime = IdentityRuntime::initialize(
            IdentityConfig {
                issuer: ISSUER.into(),
                client_id: "opaque-test".into(),
                audience: None,
                redirect_port: None,
                session_ttl_secs: None,
                allowed_email_domains: vec![],
                allowed_subjects: vec!["admin".into(), "recipient".into()],
                required: true,
                persona: Some(persona.clone()),
                service_principals: ["provisioner", "other-service"]
                    .into_iter()
                    .map(|name| ServicePrincipalConfig {
                        name: name.into(),
                        roles: vec!["operator".into()],
                    })
                    .collect(),
            },
            directory.path(),
        )
        .unwrap();
        // Explicit administrator bootstrap is test setup, never a role inferred
        // from a persona. The production login path gives new users no roles.
        let admin = runtime
            .store
            .upsert_human(
                ISSUER,
                "admin",
                None,
                None,
                &BTreeSet::from([Role::Admin, Role::Approver, Role::Operator]),
            )
            .unwrap();
        let recipient = runtime
            .store
            .upsert_human(ISSUER, "recipient", None, None, &BTreeSet::new())
            .unwrap();
        let now = now_unix();
        for (principal, subject, groups) in [
            (&admin, "admin", vec!["Administrators"]),
            (&recipient, "recipient", vec!["Engineering"]),
        ] {
            runtime
                .store
                .record_persona_snapshot(
                    &principal.id,
                    &VerifiedPersonaClaims::test_claims(ISSUER, subject, &persona, &groups, now),
                    now,
                )
                .unwrap();
        }
        runtime
            .store
            .create_human_session(&admin.id, 3600, ISSUER)
            .unwrap();
        let config = ProvisioningConfig {
            profiles: vec![AccessProfile {
                id: "read-metrics".into(),
                revision: 1,
                eligible_group: "Engineering".into(),
                scopes: BTreeSet::from(["metrics:read".into()]),
                max_ttl_secs: 300,
                max_mandate_ttl_secs: 3600,
                max_issuances: 3,
            }],
        };
        runtime.store.sync_profiles(&config).unwrap();
        runtime
            .store
            .sync_provisioning_admission(|p| runtime.principal_permitted(p), now)
            .unwrap();
        let signing = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let fido = Fido2Manager::new(
            Fido2CredentialStore::new(directory.path().join("test-fido2.json"), vec![8u8; 32]),
            Box::new(NoLocalTransport),
            RP.into(),
        );
        fido.validate_and_store_registration(
            &Fido2RegistrationResponse {
                credential_id: CREDENTIAL.into(),
                public_key: URL_SAFE_NO_PAD
                    .encode(signing.verifying_key().to_encoded_point(false).as_bytes()),
                counter: 0,
                authenticator_data: URL_SAFE_NO_PAD.encode(Self::auth_data(0)),
            },
            "synthetic test key",
        )
        .unwrap();
        let mut state =
            crate::tests::build_test_state(Arc::new(InMemoryAuditEmitter::new()), approve);
        state.tenant = Some(tenant);
        state.identity = Some(Arc::new(runtime));
        state.fido2 = Some(Arc::new(opaque_approval::factors::Fido2Approvals::new(
            fido,
            std::time::Duration::from_secs(120),
        )));
        state.config.provisioning = Some(config);
        Self {
            state,
            admin: admin.id,
            signing,
            _directory: directory,
        }
    }

    fn auth_data(counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(RP.as_bytes()).to_vec();
        data.push(0x05); // User presence and verification, asserted by test key.
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    fn assertion(&self, challenge: &str, counter: u32) -> Fido2Assertion {
        let client = serde_json::to_vec(
            &json!({"type":"webauthn.get","challenge":challenge,"origin":format!("https://{RP}"),"crossOrigin":false}),
        )
        .unwrap();
        let auth_data = Self::auth_data(counter);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature: Signature = self.signing.sign(&signed);
        Fido2Assertion {
            credential_id: CREDENTIAL.into(),
            authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
            client_data_json: URL_SAFE_NO_PAD.encode(client),
            signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        }
    }

    async fn call(&self, method: &str, params: Value, session: Option<&str>) -> Response {
        self.call_as(
            method,
            params,
            session,
            501,
            if session.is_some() {
                ClientType::Agent
            } else {
                ClientType::Human
            },
        )
        .await
    }

    async fn call_as(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
        uid: u32,
        kind: ClientType,
    ) -> Response {
        crate::handle_request(
            &self.state,
            Request {
                id: 1,
                method: method.into(),
                params,
            },
            &peer(uid),
            kind,
            session,
        )
        .await
    }

    async fn service(&self, name: &str) -> String {
        let result = ok(self
            .call(
                "agent_session_start",
                json!({"mode":"autonomous","service":name}),
                None,
            )
            .await);
        assert!(
            result["session_token"]
                .as_str()
                .unwrap()
                .starts_with("opqd1.")
        );
        result["session_id"].as_str().unwrap().into()
    }

    async fn bind(&self) {
        let started = ok(self
            .call(
                "identity.provisioning.bind_start",
                json!({"credential_id":CREDENTIAL}),
                None,
            )
            .await);
        let assertion = self.assertion(started["challenge"].as_str().unwrap(), 1);
        let completed = ok(self
            .call(
                "identity.provisioning.bind_complete",
                json!({"challenge_id":started["challenge_id"],"assertion":assertion}),
                None,
            )
            .await);
        assert_eq!(completed["principal_id"], self.admin.as_str());
        assert_eq!(completed["provenance"], "human_fido2_binding");
    }

    async fn mandate(&self) -> String {
        self.bind().await;
        let started = ok(self.call("identity.provisioning.mandate_start", json!({"service":"provisioner","profile_id":"read-metrics","ttl_secs":900,"max_issuances":3}), None).await);
        assert!(started["review"].as_str().unwrap().contains("Engineering"));
        let completed = ok(self.call("identity.provisioning.mandate_complete", json!({"challenge_id":started["challenge_id"],"assertion":self.assertion(started["challenge"].as_str().unwrap(), 2)}), None).await);
        assert_eq!(completed["provenance"], "human_fido2_mandate");
        assert_eq!(completed["mandate"]["issued_count"], 0);
        completed["mandate"]["id"].as_str().unwrap().into()
    }

    fn issue(mandate: &str, request: &str) -> Value {
        json!({"mandate_id":mandate,"recipient_issuer":ISSUER,"recipient_subject":"recipient","ttl_secs":120,"request_id":request})
    }
}

#[tokio::test]
async fn native_denial_never_produces_a_binding_or_mandate_challenge() {
    let fixture = Fixture::new(false);
    let response = fixture
        .call(
            "identity.provisioning.bind_start",
            json!({"credential_id":CREDENTIAL}),
            None,
        )
        .await;
    assert!(
        response
            .error
            .as_ref()
            .unwrap()
            .message
            .contains("out-of-band")
    );
    denied(response);
    assert!(
        fixture
            .state
            .fido2
            .as_ref()
            .unwrap()
            .list_credentials()
            .unwrap()[0]
            .principal_binding
            .is_none()
    );
    let response = fixture.call("identity.provisioning.bind_complete", json!({"challenge_id":uuid::Uuid::new_v4(),"assertion":fixture.assertion("caller-selected",1)}), None).await;
    denied(response);
    let store = &fixture.state.identity.as_ref().unwrap().store;
    assert!(
        store
            .list_mandates(fixture.state.tenant.as_ref().unwrap().binding())
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn reviewed_challenges_are_random_peer_bound_signed_and_single_use() {
    let fixture = Fixture::new(true);
    let first = ok(fixture
        .call(
            "identity.provisioning.bind_start",
            json!({"credential_id":CREDENTIAL}),
            None,
        )
        .await);
    let second = ok(fixture
        .call(
            "identity.provisioning.bind_start",
            json!({"credential_id":CREDENTIAL}),
            None,
        )
        .await);
    assert_ne!(first["challenge"], second["challenge"]);
    assert_ne!(first["challenge_id"], second["challenge_id"]);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(first["challenge"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(first["user_verification"], "required");
    assert_eq!(first["allowed_credentials"], json!([CREDENTIAL]));
    let params = json!({"challenge_id":first["challenge_id"],"assertion":fixture.assertion(first["challenge"].as_str().unwrap(),1)});
    denied(
        fixture
            .call_as(
                "identity.provisioning.bind_complete",
                params.clone(),
                None,
                502,
                ClientType::Human,
            )
            .await,
    );
    ok(fixture
        .call("identity.provisioning.bind_complete", params.clone(), None)
        .await);
    denied(
        fixture
            .call("identity.provisioning.bind_complete", params, None)
            .await,
    );
    // A correctly signed assertion for another challenge is still rejected,
    // consuming only its own review window before cryptographic verification.
    let wrong = json!({"challenge_id":second["challenge_id"],"assertion":fixture.assertion(first["challenge"].as_str().unwrap(),2)});
    denied(
        fixture
            .call("identity.provisioning.bind_complete", wrong, None)
            .await,
    );
    let retry = json!({"challenge_id":second["challenge_id"],"assertion":fixture.assertion(second["challenge"].as_str().unwrap(),2)});
    denied(
        fixture
            .call("identity.provisioning.bind_complete", retry, None)
            .await,
    );
}

#[tokio::test]
async fn only_the_authenticated_mandate_service_can_issue_for_a_verified_recipient() {
    let fixture = Fixture::new(true);
    let mandate = fixture.mandate().await;
    let service = fixture.service("provisioner").await;
    let stranger = fixture.service("other-service").await;
    let params = Fixture::issue(&mandate, &uuid::Uuid::new_v4().to_string());
    denied(
        fixture
            .call("identity.provisioning.issue", params.clone(), None)
            .await,
    );
    denied(
        fixture
            .call_as(
                "identity.provisioning.issue",
                params.clone(),
                None,
                501,
                ClientType::Agent,
            )
            .await,
    );
    denied(
        fixture
            .call(
                "identity.provisioning.issue",
                params.clone(),
                Some(&stranger),
            )
            .await,
    );
    denied(fixture.call("identity.provisioning.mandate_start", json!({"service":"other-service","profile_id":"read-metrics","ttl_secs":900,"max_issuances":1}), Some(&stranger)).await);
    let mut forged = params.clone();
    forged["groups"] = json!(["Engineering"]);
    denied(
        fixture
            .call("identity.provisioning.issue", forged, Some(&service))
            .await,
    );
    let mut outside = params.clone();
    outside["recipient_issuer"] = json!("https://other-idp.example.com");
    denied(
        fixture
            .call("identity.provisioning.issue", outside, Some(&service))
            .await,
    );
    let issued = ok(fixture
        .call("identity.provisioning.issue", params, Some(&service))
        .await);
    assert_eq!(issued["provenance"], "delegated_policy");
    assert_eq!(issued["delegation_id"], service);
    assert_eq!(issued["grant"]["delegation_id"], service);
    assert!(issued["actor"].as_str().unwrap().starts_with("agt_"));
    let store = &fixture.state.identity.as_ref().unwrap().store;
    assert_eq!(
        store
            .get_mandate(fixture.state.tenant.as_ref().unwrap().binding(), &mandate)
            .unwrap()
            .issued_count,
        1
    );
    assert!(
        store
            .get_human_by_subject(ISSUER, "recipient")
            .unwrap()
            .unwrap()
            .roles
            .is_empty()
    );
}

#[tokio::test]
async fn request_reuse_and_issuer_role_removal_cannot_extend_a_mandate() {
    let fixture = Fixture::new(true);
    let mandate = fixture.mandate().await;
    let service = fixture.service("provisioner").await;
    let mut params = Fixture::issue(&mandate, &uuid::Uuid::new_v4().to_string());
    ok(fixture
        .call(
            "identity.provisioning.issue",
            params.clone(),
            Some(&service),
        )
        .await);
    params["ttl_secs"] = json!(240);
    denied(
        fixture
            .call("identity.provisioning.issue", params, Some(&service))
            .await,
    );
    let runtime = fixture.state.identity.as_ref().unwrap();
    let tenant = fixture.state.tenant.as_ref().unwrap().binding();
    assert_eq!(
        runtime
            .store
            .get_mandate(tenant, &mandate)
            .unwrap()
            .issued_count,
        1
    );
    runtime
        .store
        .set_roles(&fixture.admin, &BTreeSet::new())
        .unwrap();
    let next = Fixture::issue(&mandate, &uuid::Uuid::new_v4().to_string());
    denied(
        fixture
            .call("identity.provisioning.issue", next.clone(), Some(&service))
            .await,
    );
    runtime
        .store
        .set_roles(
            &fixture.admin,
            &BTreeSet::from([Role::Admin, Role::Approver, Role::Operator]),
        )
        .unwrap();
    denied(
        fixture
            .call("identity.provisioning.issue", next, Some(&service))
            .await,
    );
    assert_eq!(
        runtime
            .store
            .get_mandate(tenant, &mandate)
            .unwrap()
            .issued_count,
        1
    );
}
