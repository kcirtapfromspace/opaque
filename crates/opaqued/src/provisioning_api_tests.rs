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
};
use opaque_approval::fido2::{
    Fido2Assertion, Fido2CredentialStore, Fido2Manager, Fido2RegistrationResponse, NoLocalTransport,
};
use opaque_tenant::tenant::{TenantBoundary, TenantConfig};

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
        workload: None,
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

fn provisioning_rows(fixture: &Fixture) -> Value {
    let runtime = fixture.state.identity.as_ref().unwrap();
    let binding = fixture.state.tenant.as_ref().unwrap().binding();
    json!({"mandates":runtime.store.list_mandates(binding).unwrap(),"grants":runtime.store.list_access_grants(binding).unwrap()})
}

fn database(fixture: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(fixture._directory.path().join("identity.db")).unwrap()
}

fn denial_message(response: Response) -> String {
    assert!(response.result.is_none());
    let error = response.error.expect("must reject rather than authorize");
    assert_eq!(error.code, "provisioning_denied");
    error.message
}

#[tokio::test]
async fn invalid_mandate_bounds_and_missing_credentials_do_not_create_authority() {
    let fixture = Fixture::new(true);
    let before = provisioning_rows(&fixture);
    for (ttl, count) in [(0, 1), (3601, 1), (900, 0), (900, 4)] {
        let response = fixture.call("identity.provisioning.mandate_start",json!({"service":"provisioner","profile_id":"read-metrics","ttl_secs":ttl,"max_issuances":count}),None).await;
        assert_eq!(
            denial_message(response),
            "mandate exceeds profile lifetime or issuance limit"
        );
        assert_eq!(provisioning_rows(&fixture), before);
    }
    let response=fixture.call("identity.provisioning.mandate_start",json!({"service":"provisioner","profile_id":"read-metrics","ttl_secs":900,"max_issuances":1}),None).await;
    assert_eq!(
        denial_message(response),
        "bind a FIDO2 credential to this administrator first"
    );
    let response = fixture
        .call(
            "identity.provisioning.bind_start",
            json!({"credential_id":"unregistered"}),
            None,
        )
        .await;
    assert_eq!(
        denial_message(response),
        "register the FIDO2 credential before binding it"
    );
    assert_eq!(provisioning_rows(&fixture), before);
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
}

#[tokio::test]
async fn stale_administrator_persona_cannot_start_or_complete_any_ceremony() {
    for remove in [false, true] {
        let fixture = Fixture::new(true);
        let start = ok(fixture
            .call(
                "identity.provisioning.bind_start",
                json!({"credential_id":CREDENTIAL}),
                None,
            )
            .await);
        if remove {
            database(&fixture)
                .execute(
                    "DELETE FROM persona_snapshots WHERE principal_id=?1",
                    [fixture.admin.as_str()],
                )
                .unwrap();
        } else {
            database(&fixture)
                .execute(
                    "UPDATE persona_snapshots SET observed_at=0,issued_at=0,expires_at=0 WHERE principal_id=?1",
                    [fixture.admin.as_str()],
                )
                .unwrap();
        }
        let before = provisioning_rows(&fixture);
        for (method, params) in [
            (
                "identity.provisioning.bind_start",
                json!({"credential_id":CREDENTIAL}),
            ),
            (
                "identity.provisioning.bind_complete",
                json!({"challenge_id":start["challenge_id"],"assertion":fixture.assertion(start["challenge"].as_str().unwrap(),1)}),
            ),
        ] {
            assert_eq!(
                denial_message(fixture.call(method, params, None).await),
                "administrator persona is stale; complete a fresh IdP login"
            );
            assert_eq!(provisioning_rows(&fixture), before);
        }
        // The authentication prerequisite fails before challenge consumption.
        assert!(
            fixture
                .state
                .provisioning_challenges
                .take(start["challenge_id"].as_str().unwrap(), 501)
                .is_ok()
        );
    }
}

#[tokio::test]
async fn completion_rechecks_login_and_review_epoch_before_verifying_fido_assertion() {
    for epoch in [false, true] {
        let fixture = Fixture::new(true);
        let start = ok(fixture
            .call(
                "identity.provisioning.bind_start",
                json!({"credential_id":CREDENTIAL}),
                None,
            )
            .await);
        let runtime = fixture.state.identity.as_ref().unwrap();
        if epoch {
            database(&fixture)
                .execute(
                    "UPDATE provisioning_principal_epochs SET epoch=epoch+1 WHERE principal_id=?1",
                    [fixture.admin.as_str()],
                )
                .unwrap();
        } else {
            runtime.store.revoke_all_human_sessions().unwrap();
            runtime
                .store
                .create_human_session(&fixture.admin, 3600, ISSUER)
                .unwrap();
        }
        let before = provisioning_rows(&fixture);
        let params = json!({"challenge_id":start["challenge_id"],"assertion":fixture.assertion(start["challenge"].as_str().unwrap(),1)});
        assert_eq!(
            denial_message(
                fixture
                    .call("identity.provisioning.bind_complete", params.clone(), None)
                    .await
            ),
            "authority changed since review; request a fresh challenge"
        );
        denied(
            fixture
                .call("identity.provisioning.bind_complete", params, None)
                .await,
        );
        assert_eq!(provisioning_rows(&fixture), before);
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
    }
}

#[tokio::test]
async fn wrong_completion_ceremony_and_credential_consume_only_their_own_review() {
    for wrong_method in [false, true] {
        let fixture = Fixture::new(true);
        let start = ok(fixture
            .call(
                "identity.provisioning.bind_start",
                json!({"credential_id":CREDENTIAL}),
                None,
            )
            .await);
        let untouched = ok(fixture
            .call(
                "identity.provisioning.bind_start",
                json!({"credential_id":CREDENTIAL}),
                None,
            )
            .await);
        let mut assertion = fixture.assertion(start["challenge"].as_str().unwrap(), 1);
        if !wrong_method {
            assertion.credential_id = "foreign-credential".into();
        }
        let params = json!({"challenge_id":start["challenge_id"],"assertion":assertion});
        let method = if wrong_method {
            "identity.provisioning.mandate_complete"
        } else {
            "identity.provisioning.bind_complete"
        };
        assert_eq!(
            denial_message(fixture.call(method, params, None).await),
            if wrong_method {
                "challenge belongs to another ceremony"
            } else {
                "credential differs from human-reviewed binding"
            }
        );
        assert!(
            fixture
                .state
                .provisioning_challenges
                .take(start["challenge_id"].as_str().unwrap(), 501)
                .is_err()
        );
        assert!(
            fixture
                .state
                .provisioning_challenges
                .take(untouched["challenge_id"].as_str().unwrap(), 501)
                .is_ok()
        );
        assert_eq!(
            provisioning_rows(&fixture),
            json!({"mandates":[],"grants":[]})
        );
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
    }
}

#[tokio::test]
async fn administrator_and_owning_service_observe_only_authorized_provisioning_rows() {
    let fixture = Fixture::new(true);
    let mandate = fixture.mandate().await;
    let owner = fixture.service("provisioner").await;
    let foreign = fixture.service("other-service").await;
    let grant = ok(fixture
        .call(
            "identity.provisioning.issue",
            Fixture::issue(&mandate, &uuid::Uuid::new_v4().to_string()),
            Some(&owner),
        )
        .await)["grant"]
        .clone();
    let before = provisioning_rows(&fixture);
    for session in [None, Some(owner.as_str())] {
        let listed = ok(fixture
            .call("identity.provisioning.list", json!({}), session)
            .await);
        assert_eq!(listed, before);
        for (kind, id) in [
            ("mandate", mandate.as_str()),
            ("access", grant["id"].as_str().unwrap()),
        ] {
            let shown = ok(fixture
                .call(
                    "identity.provisioning.show",
                    json!({"kind":kind,"id":id}),
                    session,
                )
                .await);
            assert_eq!(shown["mandate"]["id"], mandate);
            assert_eq!(shown["approved_profile"]["id"], "read-metrics");
            assert_eq!(
                shown["grant"],
                if kind == "access" {
                    grant.clone()
                } else {
                    Value::Null
                }
            );
        }
    }
    assert_eq!(
        ok(fixture
            .call("identity.provisioning.list", json!({}), Some(&foreign))
            .await),
        json!({"mandates":[],"grants":[]})
    );
    for (kind, id) in [
        ("mandate", mandate.as_str()),
        ("access", grant["id"].as_str().unwrap()),
    ] {
        assert_eq!(
            denial_message(
                fixture
                    .call(
                        "identity.provisioning.show",
                        json!({"kind":kind,"id":id}),
                        Some(&foreign)
                    )
                    .await
            ),
            "only an administrator or the owning service may inspect this grant"
        );
        denied(
            fixture
                .call(
                    "identity.provisioning.revoke",
                    json!({"kind":kind,"id":id}),
                    Some(&owner),
                )
                .await,
        );
    }
    assert_eq!(provisioning_rows(&fixture), before);
    for method in ["identity.provisioning.show", "identity.provisioning.revoke"] {
        denied(
            fixture
                .call(method, json!({"kind":"invented","id":mandate}), None)
                .await,
        );
    }
    let revoked = ok(fixture
        .call(
            "identity.provisioning.revoke",
            json!({"kind":"access","id":grant["id"]}),
            None,
        )
        .await);
    assert_eq!(revoked["revoked"], true);
    let rows = provisioning_rows(&fixture);
    assert!(rows["grants"][0]["revoked_at"].is_i64());
    assert_eq!(rows["mandates"][0]["issued_count"], 1);
}

#[tokio::test]
async fn issuance_rejects_foreign_idp_missing_subject_and_nonpositive_or_overflow_ttl() {
    let fixture = Fixture::new(true);
    let mandate = fixture.mandate().await;
    let service = fixture.service("provisioner").await;
    let before = provisioning_rows(&fixture);
    for case in 0..4 {
        let mut params = Fixture::issue(&mandate, &uuid::Uuid::new_v4().to_string());
        match case {
            0 => params["recipient_issuer"] = json!("https://foreign.example"),
            1 => params["recipient_subject"] = json!("not-enrolled"),
            2 => params["ttl_secs"] = json!(0),
            _ => params["ttl_secs"] = json!(u64::MAX),
        }
        let error = denial_message(
            fixture
                .call("identity.provisioning.issue", params, Some(&service))
                .await,
        );
        assert_eq!(
            error,
            match case {
                0 => "recipient issuer is outside this broker's IdP",
                1 => "recipient must complete IdP enrollment first",
                _ => "invalid TTL",
            }
        );
        assert_eq!(provisioning_rows(&fixture), before);
    }
}

fn startup_config(fixture: &Fixture) -> crate::DaemonConfig {
    let mut config = fixture.state.config.clone();
    config.require_seal = true;
    config.enforce_agent_sessions = true;
    config.approval.fido2 = true;
    config.approval.session_factor =
        Some(opaque_core::operation::ApprovalFactor::PairedWorkstation);
    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    config.workstation_approvers = vec![opaque_approval::pairing::WorkstationApproverConfig {
        name: "Registered fixture reviewer".into(),
        public_key_hex: opaque_core::workstation::hex(key.verifying_key().as_bytes()),
        principal_id: Some(fixture.admin.as_str().into()),
    }];
    config.resource_authority=Some(serde_json::from_value(json!({"socket_path":fixture._directory.path().join("resource.sock"),"credential_file":fixture._directory.path().join("resource.key"),"allowed_gateway_uids":[501],"binding":fixture.state.tenant.as_ref().unwrap().binding(),"auth":{"issuer":ISSUER,"resource_audience":"https://metrics.example/mcp","public_key_pem":crate::resource_authority_provisioning_tests::PUBLIC_KEY},"role_scopes":{}})).unwrap());
    config
}

#[test]
fn provisioning_startup_requires_every_custody_identity_and_review_prerequisite() {
    // This exercises the startup prerequisite boundary with the real identity
    // store. It does not start the independent resource ingress or a UI.
    for case in 0..12 {
        let mut fixture = Fixture::new(true);
        let mut config = startup_config(&fixture);
        let binding = fixture.state.tenant.as_ref().unwrap().binding().clone();
        let runtime = Arc::get_mut(fixture.state.identity.as_mut().unwrap()).unwrap();
        let mut bind = Some(&binding);
        match case {
            0 => bind = None,
            1 => runtime.config.required = false,
            2 => config.enforce_agent_sessions = false,
            3 => config.require_seal = false,
            4 => config.approval.fido2 = false,
            5 => runtime.config.persona = None,
            6 => config.resource_authority = None,
            7 => runtime.config.allowed_subjects.clear(),
            8 => {
                config.approval.session_factor =
                    Some(opaque_core::operation::ApprovalFactor::LocalBio)
            }
            9 => config.workstation_approvers.clear(),
            10 => {
                runtime
                    .store
                    .set_roles(&fixture.admin, &BTreeSet::new())
                    .unwrap();
            }
            _ => {}
        }
        let before = runtime.store.provisioning_profile("read-metrics").unwrap();
        let result = crate::provisioning_api::initialize(
            &config,
            if case == 11 { None } else { Some(runtime) },
            bind,
        );
        assert!(result.is_err(), "case {case}");
        assert_eq!(
            runtime.store.provisioning_profile("read-metrics").unwrap(),
            before
        );
        assert!(runtime.store.list_mandates(&binding).unwrap().is_empty());
    }
    let fixture = Fixture::new(true);
    let config = startup_config(&fixture);
    crate::provisioning_api::initialize(
        &config,
        fixture.state.identity.as_deref(),
        Some(fixture.state.tenant.as_ref().unwrap().binding()),
    )
    .unwrap();
}

#[tokio::test]
async fn disabling_provisioning_at_startup_cannot_restore_existing_grants_when_reenabled() {
    let fixture = Fixture::new(true);
    let mandate = fixture.mandate().await;
    let runtime = fixture.state.identity.as_ref().unwrap();
    let binding = fixture.state.tenant.as_ref().unwrap().binding();
    let original = runtime.store.get_mandate(binding, &mandate).unwrap();
    let config = startup_config(&fixture);
    let mut disabled = config.clone();
    disabled.provisioning = None;
    crate::provisioning_api::initialize(&disabled, Some(runtime), Some(binding)).unwrap();
    assert!(
        runtime
            .store
            .get_mandate(binding, &mandate)
            .unwrap()
            .revoked_at
            .is_some()
    );
    crate::provisioning_api::initialize(&config, Some(runtime), Some(binding)).unwrap();
    let retained = runtime.store.get_mandate(binding, &mandate).unwrap();
    assert!(retained.revoked_at.is_some());
    assert_eq!(retained.issued_count, original.issued_count);
    assert!(
        runtime
            .store
            .provisioning_profile("read-metrics")
            .unwrap()
            .1
            > original.profile_epoch
    );
}

#[derive(Debug)]
struct ReviewFence {
    entered: Arc<tokio::sync::Semaphore>,
    released: Arc<tokio::sync::Semaphore>,
}
impl opaque_core::approval_gate::ApprovalGate for ReviewFence {
    fn request_approval(
        &self,
        _: uuid::Uuid,
        request: &opaque_core::operation::OperationRequest,
        factors: &[opaque_core::operation::ApprovalFactor],
        description: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<opaque_core::approval_gate::ApprovalOutcome, String>,
                > + Send
                + '_,
        >,
    > {
        assert_eq!(request.operation, "identity.provisioning.bind_start");
        assert_eq!(factors, [opaque_core::operation::ApprovalFactor::LocalBio]);
        assert!(description.contains(CREDENTIAL));
        Box::pin(async {
            self.entered.add_permits(1);
            self.released.acquire().await.unwrap().forget();
            Ok(opaque_core::approval_gate::ApprovalOutcome::approved_anonymous())
        })
    }
}

#[tokio::test]
async fn login_or_epoch_change_while_review_is_pending_never_publishes_a_challenge() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for changed_epoch in [false, true] {
        let mut fixture = Fixture::new(true);
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let released = Arc::new(tokio::sync::Semaphore::new(0));
        fixture.state.enclave = Arc::new(
            crate::Enclave::builder()
                .approval_gate(Box::new(ReviewFence {
                    entered: entered.clone(),
                    released: released.clone(),
                }))
                .audit(Arc::new(InMemoryAuditEmitter::new()))
                .build()
                .unwrap(),
        );
        let before = provisioning_rows(&fixture);
        let mutated = AtomicBool::new(false);
        let request = fixture.call(
            "identity.provisioning.bind_start",
            json!({"credential_id":CREDENTIAL}),
            None,
        );
        let mutation = async {
            tokio::time::timeout(std::time::Duration::from_secs(5), entered.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            let runtime = fixture.state.identity.as_ref().unwrap();
            if changed_epoch {
                database(&fixture).execute("UPDATE provisioning_principal_epochs SET epoch=epoch+1 WHERE principal_id=?1",[fixture.admin.as_str()]).unwrap();
            } else {
                runtime
                    .store
                    .create_human_session(&fixture.admin, 3600, ISSUER)
                    .unwrap();
            }
            mutated.store(true, Ordering::SeqCst);
            released.add_permits(1);
        };
        let (response, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(request, mutation)
        })
        .await
        .unwrap();
        assert!(mutated.load(Ordering::SeqCst));
        assert_eq!(
            denial_message(response),
            "administrator authority changed; request a new review"
        );
        assert_eq!(provisioning_rows(&fixture), before);
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
    }
}
