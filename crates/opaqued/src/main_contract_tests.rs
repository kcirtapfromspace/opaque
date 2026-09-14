//! Direct daemon configuration and RPC boundary contracts. Identity stores and
//! signatures are real; software attestation is not a hardware posture proof.
use super::*;
use crate::approver_rpc_tests::{Fixture, ISSUER, error, ok};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use opaque_core::identity::Role;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn authority_rows(fixture: &Fixture) -> BTreeMap<String, Vec<Vec<rusqlite::types::Value>>> {
    authority_rows_at(&fixture.directory.path().join("identity.db"))
}

fn authority_rows_at(path: &Path) -> BTreeMap<String, Vec<Vec<rusqlite::types::Value>>> {
    let db = rusqlite::Connection::open(path).unwrap();
    let mut tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .map(|table| {
            let mut statement = db
                .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get(i))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            (table, rows)
        })
        .collect()
}

#[tokio::test]
async fn actual_config_loading_filters_empty_human_entries_and_keeps_invalid_roles_non_authorizing()
{
    let fixture = Fixture::new(true);
    let path = fixture.directory.path().join("config.toml");
    let source = r#"
[[known_human_clients]]
name = "empty entry must not admit all clients"
[[known_human_clients]]
name = "path"
exe_path = "/fixture/bin/tool"
[[known_human_clients]]
name = "hash"
exe_sha256 = "aabb"
[[known_human_clients]]
name = "team"
codesign_team_id = "FIXTURETEAM"
[[rules]]
name = "misspelled role"
operation_pattern = "fixture.invalid"
allow = true
[rules.identity]
roles = ["admin", "admn"]
[[rules]]
name = "valid role control"
operation_pattern = "fixture.valid"
allow = true
[rules.identity]
roles = ["admin"]
"#;
    std::fs::write(&path, source).unwrap();
    let loaded = load_config(&path);
    assert_eq!(
        loaded
            .known_human_clients
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["path", "hash", "team"]
    );
    let mut peer = Fixture::peer();
    assert_eq!(derive_client_type(&peer, &loaded), ClientType::Agent);
    for criterion in ["path", "hash", "team"] {
        peer = Fixture::peer();
        match criterion {
            "path" => peer.exe_path = Some("/fixture/bin/tool".into()),
            "hash" => peer.exe_sha256 = Some("AABB".into()),
            _ => peer.codesign_team_id = Some("FIXTURETEAM".into()),
        }
        assert_eq!(derive_client_type(&peer, &loaded), ClientType::Human);
    }
    // Classification consumes observations; these fixtures make no native
    // executable or code-signing attestation claim.
    let session = ok(fixture
        .call("agent_session_start", json!({"mode":"delegated"}))
        .await);
    let principal = resolve_principal_context(&fixture.state, session["session_id"].as_str())
        .await
        .unwrap();
    let mut request = OperationRequest {
        request_id: Uuid::new_v4(),
        client_identity: Fixture::peer(),
        client_type: ClientType::Agent,
        principal,
        operation: "fixture.invalid".into(),
        target: HashMap::new(),
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: Value::Null,
        workspace: None,
    };
    let policy = PolicyEngine::with_rules(loaded.rules);
    assert!(!policy.evaluate(&request, OperationSafety::Safe).allowed);
    request.operation = "fixture.valid".into();
    assert!(policy.evaluate(&request, OperationSafety::Safe).allowed);
    assert_eq!(std::fs::read_to_string(path).unwrap(), source);
}

#[tokio::test]
async fn direct_attestation_rpc_rejects_invalid_nonces_and_signs_exact_boundary_controls() {
    let mut fixture = Fixture::new(false);
    let signing = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
    let key = signing.verifying_key();
    fixture.state.attestation =
        Arc::new(opaque_federation_runtime::attest::AttestationService::new(
            signing,
            fixture.directory.path().to_owned(),
            fixture.directory.path().join("config.toml"),
            fixture.directory.path().join("audit.db"),
            "direct-rpc-fixture".into(),
            false,
            vec![],
            fixture.state.federation.clone(),
        ));
    let before = authority_rows(&fixture);
    for params in [
        json!({}),
        json!({"nonce":null}),
        json!({"nonce":42}),
        json!({"nonce":"a".repeat(15)}),
        json!({"nonce":"a".repeat(129)}),
        json!({"nonce":format!("{}g", "a".repeat(15))}),
    ] {
        let response = fixture.call("attestation_report", params).await;
        assert!(response.result.is_none());
        let error = response.error.unwrap();
        assert_eq!(error.code, "bad_request");
        assert_eq!(
            error.message,
            "'nonce' must be 16-128 hex characters (caller-chosen, anti-replay)"
        );
        assert_eq!(fixture.succeeded("attestation_report"), 0);
        assert_eq!(authority_rows(&fixture), before);
    }
    for nonce in ["aB01".repeat(4), "Fe02".repeat(32)] {
        let issued = ok(fixture
            .call("attestation_report", json!({"nonce":nonce}))
            .await);
        assert_eq!(
            issued["attestation_key"],
            opaque_core::workstation::hex(key.as_bytes())
        );
        let report = issued["report"].as_str().unwrap();
        let verified =
            opaque_core::attest::verify_report(report, &key, &nonce, now_unix(), 60).unwrap();
        assert_eq!(verified.payload.nonce, nonce);
        assert_eq!(verified.payload.daemon_version, "direct-rpc-fixture");
        assert_eq!(verified.payload.uid, unsafe { libc::geteuid() });
        assert!(!verified.payload.trust_domain.enforce);
        assert!(matches!(
            opaque_core::attest::verify_report(report, &key, &"0".repeat(16), now_unix(), 60),
            Err(opaque_core::attest::AttestError::NonceMismatch { .. })
        ));
        assert_eq!(authority_rows(&fixture), before);
    }
    assert_eq!(fixture.succeeded("attestation_report"), 2);
    assert!(fixture.review.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn delegation_listing_checks_bootstrap_and_current_auditor_authority_without_changing_rows() {
    for actor in [
        "missing-runtime",
        "bootstrap",
        "logged-out",
        "operator",
        "auditor",
        "admin",
    ] {
        let mut fixture = Fixture::new(true);
        let mut session = None;
        if actor == "missing-runtime" {
            fixture.state.identity = None;
        } else if actor == "bootstrap" {
            let original = fixture.state.identity.as_ref().unwrap();
            let path = fixture.directory.path().join("empty-store");
            std::fs::create_dir(&path).unwrap();
            fixture.state.identity = Some(Arc::new(
                identity::IdentityRuntime::initialize(original.config.clone(), &path).unwrap(),
            ));
        } else {
            session = Some(ok(fixture
                .call("agent_session_start", json!({"mode":"delegated"}))
                .await));
            let runtime = fixture.state.identity.as_ref().unwrap();
            if actor == "logged-out" {
                runtime.store.revoke_all_human_sessions().unwrap();
            } else if actor != "admin" {
                let role = if actor == "auditor" {
                    Role::Auditor
                } else {
                    Role::Operator
                };
                let principal = runtime
                    .store
                    .upsert_human(ISSUER, actor, None, None, &BTreeSet::from([role]))
                    .unwrap();
                runtime
                    .store
                    .create_human_session(&principal.id, 3600, ISSUER)
                    .unwrap();
            }
        }
        let selected_database = if actor == "bootstrap" {
            fixture.directory.path().join("empty-store/identity.db")
        } else {
            fixture.directory.path().join("identity.db")
        };
        let before = authority_rows_at(&selected_database);
        let reviews = fixture.review.requests.lock().unwrap().len();
        let response = fixture.call("identity.delegation_list", Value::Null).await;
        match actor {
            "missing-runtime" => error(response, "identity_not_configured"),
            "logged-out" | "operator" => error(response, "not_authorized"),
            "bootstrap" => assert_eq!(ok(response), json!({"delegations":[]})),
            _ => {
                let session = session.unwrap();
                let rows = ok(response);
                let list = rows["delegations"].as_array().unwrap();
                assert_eq!(list.len(), 1);
                assert_eq!(list[0]["jti"], session["session_id"]);
                assert_eq!(list[0]["sub"], fixture.admin.as_str());
                assert_eq!(list[0]["mode"], "delegated");
                let runtime = fixture.state.identity.as_ref().unwrap();
                let row = runtime
                    .store
                    .get_delegation(session["session_id"].as_str().unwrap())
                    .unwrap()
                    .unwrap();
                assert_eq!(list[0]["act"], row.act_principal.as_str());
                assert_eq!(list[0]["human_session_id"], json!(row.human_session_id));
                assert_eq!(list[0]["expires_at"], row.expires_at);
                assert_eq!(list[0]["revoked_at"], json!(row.revoked_at));
                assert!(list[0].get("session_token").is_none());
            }
        }
        assert_eq!(authority_rows_at(&selected_database), before);
        assert_eq!(fixture.review.requests.lock().unwrap().len(), reviews);
    }
}

#[tokio::test]
async fn signed_session_authentication_rejects_a_corrupt_matching_registry_token_before_liveness() {
    let fixture = Fixture::new(true);
    let minted = ok(fixture
        .call("agent_session_start", json!({"mode":"delegated"}))
        .await);
    let token = minted["session_token"].as_str().unwrap();
    let id = minted["session_id"].as_str().unwrap();
    let runtime = fixture.state.identity.as_ref().unwrap();
    let claims =
        verify_delegation_token(token, &runtime.signing.verifying_key(), now_unix()).unwrap();
    assert_eq!(claims.jti, id);
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    let corrupt = parts.join(".");
    assert!(matches!(
        verify_delegation_token(&corrupt, &runtime.signing.verifying_key(), now_unix()),
        Err(opaque_core::identity::TokenError::BadSignature)
    ));
    // Explicit corrupted-registry fault: matching opaque bytes are not enough
    // to authenticate a delegation. No normal mint path creates this state.
    fixture
        .state
        .agent_sessions
        .write()
        .await
        .get_mut(id)
        .unwrap()
        .token = corrupt.clone();
    let before = authority_rows(&fixture);
    let reviews = fixture.review.requests.lock().unwrap().len();
    for client in [ClientType::Agent, ClientType::Human] {
        assert!(
            handshake_session(&fixture.state, Some(&corrupt), client, Fixture::peer().uid)
                .await
                .is_err()
        );
        assert_eq!(authority_rows(&fixture), before);
        let sessions = fixture.state.agent_sessions.read().await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[id].token, corrupt);
    }
    fixture
        .state
        .agent_sessions
        .write()
        .await
        .get_mut(id)
        .unwrap()
        .token = token.into();
    assert_eq!(
        handshake_session(
            &fixture.state,
            Some(token),
            ClientType::Human,
            Fixture::peer().uid
        )
        .await
        .unwrap()
        .as_deref(),
        Some(id)
    );
    assert_eq!(authority_rows(&fixture), before);
    assert_eq!(fixture.review.requests.lock().unwrap().len(), reviews);
}

#[test]
fn daemon_handshake_rejects_reserved_identity_claims_even_when_null_or_nested() {
    let token = "local-daemon-fixture-token";
    let valid = json!({"handshake":"v1","daemon_token":token});
    assert!(validate_handshake(&serde_json::to_vec(&valid).unwrap(), token).is_some());
    for field in [
        "attestor",
        "attestor_id",
        "substrate",
        "strength",
        "attestation_strength",
        "selectors",
        "workload_identity",
        "client_identity",
        "workload",
        "attestation",
    ] {
        for nested in [false, true] {
            let mut forged = valid.clone();
            if nested {
                forged["params"] = json!({field:null});
            } else {
                forged[field] = Value::Null;
            }
            assert!(
                validate_handshake(&serde_json::to_vec(&forged).unwrap(), token).is_none(),
                "{field}, nested={nested}"
            );
        }
    }
    assert!(validate_handshake(&serde_json::to_vec(&valid).unwrap(), token).is_some());
}
