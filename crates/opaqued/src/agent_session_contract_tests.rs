//! Daemon session dispatch with real SQLite/signatures and a scripted reviewer.
//! These tests do not claim a physical approval or socket peer-identity ceremony.
use super::*;
use crate::approver_rpc_tests::{Fixture, ISSUER, error, ok};
use opaque_core::identity::{Role, now_unix, verify_delegation_token};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

fn database(fixture: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(fixture.directory.path().join("identity.db")).unwrap()
}

fn delegation_rows(fixture: &Fixture) -> Vec<Vec<rusqlite::types::Value>> {
    let db = database(fixture);
    let mut rows = db
        .prepare("SELECT * FROM delegations ORDER BY jti")
        .unwrap();
    let columns = rows.column_count();
    rows.query_map([], |row| {
        (0..columns)
            .map(|i| row.get(i))
            .collect::<Result<Vec<_>, _>>()
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

async fn registry(fixture: &Fixture) -> BTreeMap<String, Value> {
    fixture.state.agent_sessions.read().await.iter().map(|(id, session)| {
        let delegation = session.delegation.as_ref().map(|d| json!({"jti":d.jti,"sub":d.sub,
            "act":d.act,"mode":d.mode,"human_session_id":d.human_session_id}));
        (id.clone(), json!({"id":session.session_id,"token":session.token,"uid":session.created_by_uid,
            "expires":system_time_to_unix_ms(session.expires_at),"label":session.label,"delegation":delegation}))
    }).collect()
}

fn issued(fixture: &Fixture) -> usize {
    fixture
        .audit
        .events()
        .iter()
        .filter(|e| e.kind == AuditEventKind::DelegationIssued)
        .count()
}

#[tokio::test]
async fn malformed_session_end_requests_preserve_registry_and_durable_authority() {
    let fixture = Fixture::new(true);
    let started = ok(fixture
        .call("agent_session_start", json!({"label":"retained-owner"}))
        .await);
    let before_registry = registry(&fixture).await;
    let before_rows = delegation_rows(&fixture);
    let before_prompts = fixture.review.requests.lock().unwrap().len();
    for params in [
        json!({}),
        json!({"session_id":null}),
        json!({"session_id":42}),
        json!({"session_id":false}),
        json!({"all":false}),
        json!({"all":"true"}),
    ] {
        let response = fixture.call("agent_session_end", params).await;
        assert!(response.result.is_none());
        let error = response.error.unwrap();
        assert_eq!(error.code, "bad_request");
        assert_eq!(error.message, "missing 'session_id' field");
        assert_eq!(registry(&fixture).await, before_registry);
        assert_eq!(delegation_rows(&fixture), before_rows);
        assert_eq!(
            fixture.review.requests.lock().unwrap().len(),
            before_prompts
        );
        assert_eq!(fixture.succeeded("agent_session_end"), 0);
    }
    let context = resolve_principal_context(&fixture.state, started["session_id"].as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.sub, fixture.admin);
    assert_eq!(issued(&fixture), 1);
}

#[tokio::test]
async fn foreign_agent_cannot_end_owner_session_and_owner_revocation_survives_reopen() {
    let fixture = Fixture::new(true);
    let started = ok(fixture
        .call("agent_session_start", json!({"label":"owner"}))
        .await);
    let id = started["session_id"].as_str().unwrap();
    let before_registry = registry(&fixture).await;
    let before_rows = delegation_rows(&fixture);
    let prompts = fixture.review.requests.lock().unwrap().len();
    let mut foreign = Fixture::peer();
    foreign.uid += 1;
    error(
        handle_request(
            &fixture.state,
            Request {
                id: 2,
                method: "agent_session_end".into(),
                params: json!({"session_id":id}),
            },
            &foreign,
            ClientType::Agent,
            None,
        )
        .await,
        "permission_denied",
    );
    assert_eq!(registry(&fixture).await, before_registry);
    assert_eq!(delegation_rows(&fixture), before_rows);
    assert_eq!(fixture.succeeded("agent_session_end"), 0);
    let owner = Fixture::peer();
    let end = |id: &str| Request {
        id: 3,
        method: "agent_session_end".into(),
        params: json!({"session_id":id}),
    };
    assert_eq!(
        ok(handle_request(&fixture.state, end(id), &owner, ClientType::Agent, None).await),
        json!({"status":"ended","session_id":id,"label":"owner"})
    );
    assert!(registry(&fixture).await.is_empty());
    let reopened =
        identity::store::IdentityStore::open(&fixture.directory.path().join("identity.db"))
            .unwrap();
    let row = reopened.get_delegation(id).unwrap().unwrap();
    assert_eq!(row.sub_principal, fixture.admin);
    assert!(row.revoked_at.is_some());
    let revoked = delegation_rows(&fixture);
    assert_eq!(
        resolve_principal_context(&fixture.state, Some(id))
            .await
            .unwrap_err(),
        "agent session no longer exists"
    );
    for missing in [id, "never-issued-session"] {
        assert_eq!(
            ok(handle_request(
                &fixture.state,
                end(missing),
                &owner,
                ClientType::Agent,
                None
            )
            .await),
            json!({"status":"not_found","session_id":missing,"label":null})
        );
        assert_eq!(delegation_rows(&fixture), revoked);
    }
    assert_eq!(fixture.review.requests.lock().unwrap().len(), prompts);
    assert_eq!(
        fixture
            .audit
            .events()
            .iter()
            .filter(|e| e.kind == AuditEventKind::DelegationRevoked)
            .count(),
        1
    );
}

#[tokio::test]
async fn autonomous_mint_requires_a_string_service_before_requesting_review() {
    let fixture = Fixture::new(true);
    let before = delegation_rows(&fixture);
    for params in [
        json!({"mode":"autonomous"}),
        json!({"mode":"autonomous","service":null}),
        json!({"mode":"autonomous","service":42}),
        json!({"mode":"autonomous","service":true}),
    ] {
        let response = fixture.call("agent_session_start", params).await;
        assert!(response.result.is_none());
        let error = response.error.unwrap();
        assert_eq!(error.code, "invalid_params");
        assert_eq!(
            error.message,
            "autonomous mode requires a 'service' principal name"
        );
        assert!(registry(&fixture).await.is_empty());
        assert_eq!(delegation_rows(&fixture), before);
        assert!(fixture.review.requests.lock().unwrap().is_empty());
        assert_eq!(issued(&fixture), 0);
        assert_eq!(fixture.succeeded("agent_session_start"), 0);
    }
}

#[tokio::test]
async fn mismatched_login_issuer_or_missing_principal_never_reaches_mint_review() {
    for change in ["issuer", "missing-principal"] {
        let fixture = Fixture::new(true);
        let db = database(&fixture);
        match change {
            "issuer" => {
                db.execute(
                    "UPDATE human_sessions SET idp_issuer='https://different.example.invalid'",
                    [],
                )
                .unwrap();
            }
            _ => {
                db.execute(
                    "DELETE FROM principals WHERE id=?1",
                    [fixture.admin.as_str()],
                )
                .unwrap();
            }
        }
        let before = delegation_rows(&fixture);
        let response = fixture
            .call("agent_session_start", json!({"mode":"delegated"}))
            .await;
        assert!(response.result.is_none());
        let error = response.error.unwrap();
        assert_eq!(error.code, "login_required");
        assert_eq!(
            error.message,
            "the logged-in principal is missing or disabled"
        );
        assert!(registry(&fixture).await.is_empty());
        assert_eq!(delegation_rows(&fixture), before);
        assert!(fixture.review.requests.lock().unwrap().is_empty());
        assert_eq!(issued(&fixture), 0);
        assert_eq!(fixture.succeeded("agent_session_start"), 0);
    }
}

#[tokio::test]
async fn login_issuer_subject_or_liveness_changed_during_review_prevents_delegation() {
    for change in ["issuer", "subject", "revoked"] {
        let fixture = Fixture::new(true);
        fixture.review.hold.store(true, Ordering::SeqCst);
        let request = fixture.call("agent_session_start", json!({"mode":"delegated"}));
        let mutation = async {
            fixture.review.entered.acquire().await.unwrap().forget();
            let runtime = fixture.state.identity.as_ref().unwrap();
            match change {
                "issuer" => {
                    database(&fixture).execute("UPDATE human_sessions SET idp_issuer='https://different.example.invalid'", []).unwrap();
                }
                "subject" => {
                    let other = runtime
                        .store
                        .upsert_human(
                            ISSUER,
                            "other",
                            None,
                            None,
                            &BTreeSet::from([Role::Operator]),
                        )
                        .unwrap();
                    runtime
                        .store
                        .create_human_session(&other.id, 3600, ISSUER)
                        .unwrap();
                }
                _ => {
                    runtime.store.revoke_all_human_sessions().unwrap();
                }
            }
            fixture.review.release.add_permits(1);
        };
        let (response, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(request, mutation)
        })
        .await
        .unwrap();
        assert!(response.result.is_none());
        let error = response.error.unwrap();
        assert_eq!(error.code, "login_required", "{change}");
        assert!(
            error
                .message
                .starts_with("the human login session ended before the delegation")
        );
        assert!(registry(&fixture).await.is_empty());
        assert!(delegation_rows(&fixture).is_empty());
        assert_eq!(issued(&fixture), 0);
        assert_eq!(fixture.succeeded("agent_session_start"), 0);
        assert_eq!(fixture.review.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn delegation_insert_failure_after_review_never_exposes_a_token_and_repair_requires_new_review()
 {
    for fault in ["agent-principal", "delegation"] {
        let fixture = Fixture::new(true);
        let db = database(&fixture);
        let (table, condition, expected) = if fault == "agent-principal" {
            (
                "principals",
                "WHEN NEW.kind='agent'",
                "identity store unavailable",
            )
        } else {
            ("delegations", "", "could not record the delegation")
        };
        db.execute_batch(&format!("CREATE TRIGGER refuse_mint BEFORE INSERT ON {table} {condition} BEGIN SELECT RAISE(ABORT,'fixture mint persistence failure'); END;")).unwrap();
        let request = json!({"mode":"delegated","label":"stateful-fixture","ttl_secs":120});
        let response = fixture.call("agent_session_start", request.clone()).await;
        assert!(
            response.result.is_none(),
            "an unrecorded signed token must never escape"
        );
        let error = response.error.unwrap();
        assert_eq!(error.code, "internal");
        assert_eq!(error.message, expected);
        assert!(registry(&fixture).await.is_empty());
        assert!(delegation_rows(&fixture).is_empty());
        assert_eq!(issued(&fixture), 0);
        assert_eq!(fixture.succeeded("agent_session_start"), 0);
        assert_eq!(fixture.review.requests.lock().unwrap().len(), 1);
        let agents: i64 = db
            .query_row(
                "SELECT count(*) FROM principals WHERE kind='agent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(agents, if fault == "delegation" { 1 } else { 0 });
        db.execute_batch("DROP TRIGGER refuse_mint").unwrap();
        let minted = ok(fixture.call("agent_session_start", request).await);
        let runtime = fixture.state.identity.as_ref().unwrap();
        let claims = verify_delegation_token(
            minted["session_token"].as_str().unwrap(),
            &runtime.signing.verifying_key(),
            now_unix(),
        )
        .unwrap();
        assert_eq!(claims.jti, minted["session_id"].as_str().unwrap());
        assert_eq!(claims.sub, fixture.admin);
        assert_eq!(claims.mode, AccessMode::Delegated);
        assert_eq!(claims.exp - claims.iat, 120);
        let row = runtime.store.get_delegation(&claims.jti).unwrap().unwrap();
        assert_eq!(row.sub_principal, claims.sub);
        assert_eq!(row.act_principal, claims.act);
        assert_eq!(row.expires_at, claims.exp);
        assert!(row.revoked_at.is_none());
        assert!(row.human_session_id.is_some());
        assert_eq!(registry(&fixture).await.len(), 1);
        assert_eq!(delegation_rows(&fixture).len(), 1);
        assert_eq!(issued(&fixture), 1);
        assert_eq!(fixture.review.requests.lock().unwrap().len(), 2);
        assert_eq!(
            resolve_principal_context(&fixture.state, Some(&claims.jti))
                .await
                .unwrap()
                .unwrap()
                .sub,
            fixture.admin
        );
    }
}
