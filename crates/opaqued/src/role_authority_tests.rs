//! Daemon role dispatch with actual SQLite authority and held scripted review.
//! No physical biometric or external identity-provider ceremony is claimed.
use super::*;
use crate::approver_rpc_tests::{Fixture, ISSUER, error, ok};
use opaque_core::identity::Role;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

fn snapshot(fixture: &Fixture) -> BTreeMap<String, Vec<Vec<rusqlite::types::Value>>> {
    let db = rusqlite::Connection::open(fixture.directory.path().join("identity.db")).unwrap();
    let mut names = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    names
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .map(|table| {
            let mut rows = db
                .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
                .unwrap();
            let count = rows.column_count();
            let values = rows
                .query_map([], |row| {
                    (0..count)
                        .map(|i| row.get(i))
                        .collect::<Result<Vec<rusqlite::types::Value>, _>>()
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            (table, values)
        })
        .collect()
}
fn add_human(fixture: &Fixture, subject: &str, roles: &[Role]) -> PrincipalId {
    fixture
        .state
        .identity
        .as_ref()
        .unwrap()
        .store
        .upsert_human(
            ISSUER,
            subject,
            None,
            None,
            &roles.iter().copied().collect(),
        )
        .unwrap()
        .id
}
fn roles(fixture: &Fixture, id: &PrincipalId) -> BTreeSet<Role> {
    fixture
        .state
        .identity
        .as_ref()
        .unwrap()
        .store
        .get_principal(id)
        .unwrap()
        .unwrap()
        .roles
}
fn changed_events(fixture: &Fixture) -> usize {
    fixture
        .audit
        .events()
        .iter()
        .filter(|event| event.kind == AuditEventKind::IdentityRoleChanged)
        .count()
}

#[tokio::test]
async fn malformed_role_replacements_preserve_every_authority_row_without_review() {
    let fixture = Fixture::new(true);
    let target = add_human(&fixture, "target", &[Role::Operator]);
    let before = snapshot(&fixture);
    for params in [
        json!({}),
        json!({"principal_id":"invalid","roles":[]}),
        json!({"principal_id":target}),
        json!({"principal_id":target,"roles":"admin"}),
        json!({"principal_id":target,"roles":[42]}),
        json!({"principal_id":target,"roles":["operator",null]}),
        json!({"principal_id":target,"roles":["invented"]}),
    ] {
        error(
            fixture.call("identity.role_set", params).await,
            "invalid_params",
        );
        assert_eq!(snapshot(&fixture), before);
    }
    assert!(fixture.review.requests.lock().unwrap().is_empty());
    assert_eq!(changed_events(&fixture), 0);
}

#[tokio::test]
async fn delegated_nonadmin_cannot_borrow_another_logged_in_administrators_authority() {
    let fixture = Fixture::new(true);
    let runtime = fixture.state.identity.as_ref().unwrap();
    let operator = add_human(&fixture, "delegating-operator", &[Role::Operator]);
    runtime
        .store
        .create_human_session(&operator, 3600, ISSUER)
        .unwrap();
    let session = ok(fixture
        .call("agent_session_start", json!({"mode":"delegated"}))
        .await);
    // A later ambient administrator session must not replace the identity
    // retained by this still-live operator delegation.
    runtime
        .store
        .create_human_session(&fixture.admin, 3600, ISSUER)
        .unwrap();
    let target = add_human(&fixture, "target", &[Role::Operator]);
    let before = snapshot(&fixture);
    let prompts = fixture.review.requests.lock().unwrap().len();
    let response = handle_request(
        &fixture.state,
        Request {
            id: 1,
            method: "identity.role_set".into(),
            params: json!({"principal_id":target,"roles":["admin"]}),
        },
        &Fixture::peer(),
        ClientType::Agent,
        session["session_id"].as_str(),
    )
    .await;
    error(response, "not_authorized");
    assert_eq!(snapshot(&fixture), before);
    assert_eq!(fixture.review.requests.lock().unwrap().len(), prompts);
    assert_eq!(changed_events(&fixture), 0);
}

#[tokio::test]
async fn changed_login_actor_target_or_last_admin_during_review_never_applies_stale_roles() {
    for change in ["login", "actor-role", "target-role", "last-admin"] {
        let fixture = Fixture::new(true);
        let target = if change == "last-admin" {
            fixture.admin.clone()
        } else {
            add_human(&fixture, "target", &[Role::Operator])
        };
        let other = add_human(&fixture, "second-admin", &[Role::Admin]);
        let replacement = if change == "last-admin" {
            json!(["operator"])
        } else {
            json!(["approver", "operator"])
        };
        fixture.review.hold.store(true, Ordering::SeqCst);
        let call = fixture.call(
            "identity.role_set",
            json!({"principal_id":target,"roles":replacement}),
        );
        let mutate = async {
            fixture.review.entered.acquire().await.unwrap().forget();
            let description = fixture
                .review
                .requests
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .1
                .clone();
            assert!(
                description.contains(target.as_str())
                    && description.contains(fixture.admin.as_str())
            );
            assert!(
                description.contains("Previous roles:")
                    && description.contains("Approved replacement roles:")
            );
            let store = &fixture.state.identity.as_ref().unwrap().store;
            match change {
                "login" => {
                    store.create_human_session(&other, 3600, ISSUER).unwrap();
                }
                "actor-role" => store
                    .set_roles(&fixture.admin, &BTreeSet::from([Role::Operator]))
                    .unwrap(),
                "target-role" => store
                    .set_roles(&target, &BTreeSet::from([Role::Auditor]))
                    .unwrap(),
                "last-admin" => store
                    .set_roles(&other, &BTreeSet::from([Role::Operator]))
                    .unwrap(),
                _ => unreachable!(),
            }
            let retained = snapshot(&fixture);
            fixture.review.release.add_permits(1);
            retained
        };
        let (response, retained) =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(call, mutate) })
                .await
                .unwrap();
        error(response, "authority_changed");
        assert_eq!(
            snapshot(&fixture),
            retained,
            "{change}: stale review changed retained state"
        );
        assert_eq!(changed_events(&fixture), 0);
        if change == "last-admin" {
            assert!(roles(&fixture, &fixture.admin).contains(&Role::Admin));
        }
    }
}

#[tokio::test]
async fn revoked_delegation_while_role_review_waits_preserves_target_and_requires_fresh_review() {
    let fixture = Fixture::new(true);
    let session = ok(fixture
        .call("agent_session_start", json!({"mode":"delegated"}))
        .await);
    let session_id = session["session_id"].as_str().unwrap();
    let target = add_human(&fixture, "target", &[Role::Operator]);
    // Discard the start-review notification; the next one is the role review.
    fixture.review.entered.acquire().await.unwrap().forget();
    fixture.review.hold.store(true, Ordering::SeqCst);
    let peer = Fixture::peer();
    let call = handle_request(
        &fixture.state,
        Request {
            id: 1,
            method: "identity.role_set".into(),
            params: json!({"principal_id":target,"roles":["approver"]}),
        },
        &peer,
        ClientType::Agent,
        Some(session_id),
    );
    let mutate = async {
        fixture.review.entered.acquire().await.unwrap().forget();
        let delegation = fixture.state.agent_sessions.read().await[session_id]
            .delegation
            .clone()
            .unwrap();
        fixture
            .state
            .identity
            .as_ref()
            .unwrap()
            .store
            .revoke_delegation(&delegation.jti)
            .unwrap();
        let retained = snapshot(&fixture);
        fixture.review.release.add_permits(1);
        retained
    };
    let (response, retained) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(call, mutate) })
            .await
            .unwrap();
    error(response, "authority_changed");
    assert_eq!(snapshot(&fixture), retained);
    assert_eq!(changed_events(&fixture), 0);
    fixture.review.hold.store(false, Ordering::SeqCst);
    ok(fixture
        .call(
            "identity.role_set",
            json!({"principal_id":target,"roles":["approver"]}),
        )
        .await);
    assert_eq!(roles(&fixture, &target), BTreeSet::from([Role::Approver]));
    assert_eq!(changed_events(&fixture), 1);
}

#[tokio::test]
async fn role_store_write_failure_preserves_exact_authority_and_same_fresh_request_can_succeed() {
    let fixture = Fixture::new(true);
    let target = add_human(&fixture, "target", &[Role::Operator]);
    let db = rusqlite::Connection::open(fixture.directory.path().join("identity.db")).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_role_write BEFORE UPDATE OF roles ON principals BEGIN SELECT RAISE(ABORT,'fixture role write rejected'); END;").unwrap();
    let before = snapshot(&fixture);
    let params = json!({"principal_id":target,"roles":["approver"]});
    error(
        fixture.call("identity.role_set", params.clone()).await,
        "invalid_params",
    );
    assert_eq!(snapshot(&fixture), before);
    assert_eq!(changed_events(&fixture), 0);
    db.execute_batch("DROP TRIGGER refuse_role_write").unwrap();
    ok(fixture.call("identity.role_set", params).await);
    assert_eq!(roles(&fixture, &target), BTreeSet::from([Role::Approver]));
    assert_eq!(changed_events(&fixture), 1);
    assert_eq!(
        fixture.review.requests.lock().unwrap().len(),
        2,
        "retry requires another review"
    );
}
