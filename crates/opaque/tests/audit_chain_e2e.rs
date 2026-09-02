//! Real-world end-to-end test for the tamper-evident audit log (Phase 0, H8).
//!
//! Scenario: an agent session produces audit records, including a denied
//! attempt. An attacker with local filesystem access then edits or deletes rows
//! to cover the tracks. An operator runs the real `opaque audit verify` binary,
//! which must report the log intact when untouched and detect any tampering.
//!
//! This exercises the production audit sink to write a real chained database and
//! the real compiled `opaque` binary to verify it — no daemon, no keychain.

use std::path::{Path, PathBuf};
use std::process::Command;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};

/// Write a realistic session of audit events to `<home>/.opaque/audit.db`, then
/// flush by dropping the sink (which joins the writer thread). Returns the db path.
fn seed_audit_db(home: &Path) -> PathBuf {
    let db_path = home.join(".opaque").join("audit.db");
    let sink = SqliteAuditSink::new(db_path.clone(), 90).expect("open audit db");

    // An approved, successful operation.
    let req1 = uuid::Uuid::new_v4();
    sink.emit(
        AuditEvent::new(AuditEventKind::RequestReceived)
            .with_request_id(req1)
            .with_operation("github.set_actions_secret")
            .with_outcome("received"),
    );
    sink.emit(
        AuditEvent::new(AuditEventKind::ApprovalGranted)
            .with_request_id(req1)
            .with_operation("github.set_actions_secret")
            .with_outcome("granted"),
    );
    sink.emit(
        AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_request_id(req1)
            .with_operation("github.set_actions_secret")
            .with_outcome("ok"),
    );

    // The incriminating record: the agent attempted an operation policy denied.
    let req2 = uuid::Uuid::new_v4();
    sink.emit(
        AuditEvent::new(AuditEventKind::PolicyDenied)
            .with_request_id(req2)
            .with_operation("secret.reveal")
            .with_outcome("denied")
            .with_detail("denied by policy: REVEAL not permitted"),
    );

    // Further activity after the denied attempt, so the denied record has
    // successors — deleting or editing a record that is not the tail is detectable.
    let req3 = uuid::Uuid::new_v4();
    sink.emit(
        AuditEvent::new(AuditEventKind::RequestReceived)
            .with_request_id(req3)
            .with_operation("github.list_secrets")
            .with_outcome("received"),
    );
    sink.emit(
        AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_request_id(req3)
            .with_operation("github.list_secrets")
            .with_outcome("ok"),
    );

    drop(sink); // flush + join the writer thread
    assert!(db_path.exists(), "audit db should exist after flush");
    db_path
}

/// Run `opaque audit verify --json` with `HOME` pointed at `home`.
/// Returns `(exit_code, parsed_json)`.
fn run_verify(home: &Path) -> (i32, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_opaque"))
        .env("HOME", home)
        .args(["audit", "verify", "--json"])
        .output()
        .expect("run opaque audit verify");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json = serde_json::from_str(stdout.trim()).unwrap_or(serde_json::Value::Null);
    (code, json)
}

#[test]
fn verify_reports_intact_on_untampered_log() {
    let tmp = tempfile::tempdir().unwrap();
    seed_audit_db(tmp.path());

    let (code, json) = run_verify(tmp.path());
    assert_eq!(code, 0, "intact log should exit 0; json={json}");
    assert_eq!(json["ok"], true);
    assert_eq!(json["records_checked"], 6);
}

#[test]
fn verify_detects_deleted_incriminating_record() {
    let tmp = tempfile::tempdir().unwrap();
    let db = seed_audit_db(tmp.path());

    // Attacker deletes the denied-attempt row to cover the tracks.
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        let n = conn
            .execute("DELETE FROM audit_events WHERE outcome = 'denied'", [])
            .unwrap();
        assert_eq!(n, 1, "should have deleted exactly the denied record");
    }

    let (code, json) = run_verify(tmp.path());
    assert_eq!(
        code, 2,
        "a deleted record must fail verification; json={json}"
    );
    assert_eq!(json["ok"], false);
}

#[test]
fn verify_detects_flipped_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let db = seed_audit_db(tmp.path());

    // Attacker rewrites the denial to look successful.
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE audit_events SET outcome = 'ok' WHERE outcome = 'denied'",
            [],
        )
        .unwrap();
    }

    let (code, json) = run_verify(tmp.path());
    assert_eq!(
        code, 2,
        "a rewritten field must fail verification; json={json}"
    );
    assert_eq!(json["ok"], false);
}
