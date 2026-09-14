//! Startup role synchronization against a disposable, real SQLite store.
//! These cases inject a database write fault, not an identity or policy bypass.

use super::{IdentityConfig, IdentityRuntime};
use opaque_core::identity::Role;
use serde_json::json;
use std::collections::BTreeSet;

fn config(services: serde_json::Value) -> IdentityConfig {
    serde_json::from_value(json!({
        "issuer":"https://service-startup.example",
        "client_id":"service-startup-fixture",
        "required":true,
        "service_principals":services,
    }))
    .unwrap()
}

#[test]
fn service_role_write_fault_aborts_downgrade_and_repaired_restart_has_only_current_roles() {
    failed_downgrade_then_repair(
        "roles",
        "failed to persist roles for service 'ci': fixture_service_write_refused",
    );
}

#[test]
fn service_upsert_write_fault_aborts_downgrade_and_repaired_restart_has_only_current_roles() {
    failed_downgrade_then_repair(
        "last_seen",
        "failed to persist service principal 'ci': fixture_service_write_refused",
    );
}

fn failed_downgrade_then_repair(column: &str, expected_error: &str) {
    let directory = tempfile::tempdir().unwrap();
    let initial = IdentityRuntime::initialize(
        config(json!([{"name":"ci","roles":["admin"]}])),
        directory.path(),
    )
    .unwrap();
    let old = initial.store.get_service_by_name("ci").unwrap().unwrap();
    assert_eq!(old.roles, BTreeSet::from([Role::Admin]));
    assert!(initial.principal_permitted(&old));
    drop(initial);

    let signing_bytes = std::fs::read(directory.path().join("identity.key")).unwrap();
    let database = directory.path().join("identity.db");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER refuse_service_write BEFORE UPDATE OF {column} ON principals
             WHEN OLD.kind='service' AND OLD.service_name='ci'
             BEGIN SELECT RAISE(ABORT, 'fixture_service_write_refused'); END;",
        ))
        .unwrap();
    let desired = config(json!([{"name":"ci","roles":["operator"]}]));
    let error = match IdentityRuntime::initialize(desired.clone(), directory.path()) {
        Err(error) => error,
        Ok(runtime) => {
            let exposed = runtime.store.get_service_by_name("ci").unwrap().unwrap();
            panic!(
                "startup exposed a runtime despite a failed {column} write: permitted={} roles={:?}",
                runtime.principal_permitted(&exposed),
                exposed.roles,
            );
        }
    };
    assert_eq!(error, expected_error);
    // Retaining the old row is expected after the failed SQL statement; it must
    // never be published through a successfully initialized runtime.
    let retained: (String, String, i64, bool) = connection
        .query_row(
            "SELECT id,roles,created_at,disabled FROM principals WHERE service_name='ci'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        retained,
        (
            old.id.as_str().into(),
            "admin".into(),
            old.created_at,
            false
        )
    );
    assert_eq!(
        std::fs::read(directory.path().join("identity.key")).unwrap(),
        signing_bytes
    );
    connection
        .execute_batch("DROP TRIGGER refuse_service_write")
        .unwrap();
    drop(connection);

    // Retry the same configuration and then reopen it again: no recovery step
    // may restore administrator authority from the retained earlier row.
    for _ in 0..2 {
        let runtime = IdentityRuntime::initialize(desired.clone(), directory.path()).unwrap();
        let current = runtime.store.get_service_by_name("ci").unwrap().unwrap();
        assert_eq!(current.id, old.id);
        assert_eq!(current.roles, BTreeSet::from([Role::Operator]));
        assert!(runtime.principal_permitted(&current));
        assert!(!current.has_role(Role::Admin));
        assert_eq!(runtime.store.list_principals().unwrap().len(), 1);
    }
}

#[test]
fn invalid_service_entries_remain_skipped_without_admitting_retained_authority() {
    let directory = tempfile::tempdir().unwrap();
    let initial = IdentityRuntime::initialize(
        config(json!([{"name":"stale","roles":["admin"]}])),
        directory.path(),
    )
    .unwrap();
    let stale = initial.store.get_service_by_name("stale").unwrap().unwrap();
    drop(initial);

    let runtime = IdentityRuntime::initialize(
        config(json!([
            {"name":"stale","roles":["not-a-role"]},
            {"name":"new-invalid-roles","roles":["not-a-role"]},
            {"name":"invalid service name","roles":["admin"]},
            {"name":"ci","roles":["operator"]}
        ])),
        directory.path(),
    )
    .unwrap();
    let retained = runtime.store.get_service_by_name("stale").unwrap().unwrap();
    assert_eq!(retained.id, stale.id);
    assert_eq!(retained.roles, BTreeSet::from([Role::Admin]));
    assert!(!runtime.principal_permitted(&retained));
    for name in ["new-invalid-roles", "invalid service name"] {
        assert!(runtime.store.get_service_by_name(name).unwrap().is_none());
    }
    let current = runtime.store.get_service_by_name("ci").unwrap().unwrap();
    assert_eq!(current.roles, BTreeSet::from([Role::Operator]));
    assert!(runtime.principal_permitted(&current));
    assert!(!current.has_role(Role::Admin));
    assert_eq!(runtime.store.list_principals().unwrap().len(), 2);
}
