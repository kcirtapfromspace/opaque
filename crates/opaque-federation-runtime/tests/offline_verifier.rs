//! Exercise the independent Python verifier against the real durable sink/export.
//! Synthetic records only; the verifier never receives the audit HMAC key.
use std::path::PathBuf;
use std::process::Command;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};
use opaque_federation_runtime::export::{deliver_spool, read_rows_after};

#[test]
fn standalone_verifier_accepts_production_export_and_detects_truncated_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("audit.db");
    let spool = temp.path().join("audit.jsonl");
    let checkpoint = temp.path().join("checkpoint.json");
    let sink = SqliteAuditSink::new(db.clone(), 90).unwrap();
    for kind in [
        AuditEventKind::RequestReceived,
        AuditEventKind::ApprovalRequired,
        AuditEventKind::ApprovalGranted,
        AuditEventKind::OperationSucceeded,
    ] {
        sink.emit(
            AuditEvent::new(kind)
                .with_operation("test.noop")
                .with_outcome("synthetic")
                .with_detail("offline verifier compatibility ✓"),
        );
    }
    sink.close().unwrap();
    let rows = read_rows_after(&db, 0, 100).unwrap();
    assert_eq!(rows.len(), 4);
    deliver_spool(&spool, &rows).unwrap();
    // Real at-least-once delivery may replay an older batch after the new tail.
    deliver_spool(&spool, &rows[..2]).unwrap();
    let verifier =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/verify_audit_evidence.py");
    let created = Command::new("python3")
        .arg("-B")
        .arg(&verifier)
        .arg("checkpoint")
        .arg(&spool)
        .args(["--source-id", "synthetic-rust-export", "--output"])
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(created.status.success(), "{:?}", created);
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let pin = created["checkpoint_sha256"].as_str().unwrap();
    let verify = || {
        Command::new("python3")
            .arg("-B")
            .arg(&verifier)
            .arg("verify")
            .arg(&spool)
            .arg("--checkpoint")
            .arg(&checkpoint)
            .args(["--trusted-checkpoint-sha256", pin])
            .output()
            .unwrap()
    };
    let verified = verify();
    assert!(verified.status.success(), "{:?}", verified);
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["record_count"], 4);
    assert_eq!(report["duplicate_count"], 2);
    assert_eq!(report["audit_hmac"], "not_verified");
    // Delete a full final delivery: structural framing alone cannot detect it.
    let exported = std::fs::read_to_string(&spool).unwrap();
    let truncated: String = exported
        .lines()
        .take(5)
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(&spool, truncated).unwrap();
    let rejected = verify();
    assert_eq!(rejected.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(report["error"], "checkpoint_export_mismatch");
}

#[test]
fn actual_retained_export_builds_reproducible_independently_checked_package() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("audit.db");
    let initial = SqliteAuditSink::new(db.clone(), 0).unwrap();
    let mut old = AuditEvent::new(AuditEventKind::RequestReceived);
    old.ts_utc_ms = 1;
    initial.emit(old);
    initial.close().unwrap();
    let sink = SqliteAuditSink::new(db.clone(), 1).unwrap(); // authenticated prefix retention
    let request = AuditEvent::new(AuditEventKind::RequestReceived).event_id;
    let approval = AuditEvent::new(AuditEventKind::ApprovalRequired).event_id;
    for kind in [
        AuditEventKind::ApprovalRequired,
        AuditEventKind::OperationSucceeded,
    ] {
        sink.emit(
            AuditEvent::new(kind)
                .with_request_id(request)
                .with_approval_id(approval)
                .with_request_hash("a".repeat(64))
                .with_operation("test.noop"),
        );
    }
    sink.close().unwrap();
    let rows = read_rows_after(&db, 0, 100).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].sequence_number > 0);
    let spool = temp.path().join("audit.jsonl");
    deliver_spool(&spool, &rows).unwrap();
    deliver_spool(&spool, &rows[..1]).unwrap();
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/evidence_package.py");
    let mut outputs = Vec::new();
    for name in ["first", "second"] {
        let directory = temp.path().join(name);
        let result = Command::new("python3")
            .args(["-B"])
            .arg(&script)
            .arg("create")
            .arg(&spool)
            .args(["--source-id", "synthetic-retained-broker", "--output"])
            .arg(&directory)
            .output()
            .unwrap();
        assert!(result.status.success(), "{:?}", result);
        let created: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let verified = Command::new("python3")
            .args(["-B"])
            .arg(&script)
            .arg("verify")
            .arg(&directory)
            .arg("--trusted-manifest-sha256")
            .arg(created["manifest_sha256"].as_str().unwrap())
            .output()
            .unwrap();
        assert!(verified.status.success(), "{:?}", verified);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 8);
        outputs.push(std::fs::read(directory.join("manifest.json")).unwrap());
        let anomalies: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("anomalies.json")).unwrap())
                .unwrap();
        let expected = opaque_federation_runtime::export::Finding::new(
            "approval_missing",
            &rows[1],
            Some(rows[0].sequence_number),
        );
        assert_eq!(
            anomalies["findings"][0],
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(anomalies["input_evidence"]["duplicate_count"], 1);
        assert_eq!(anomalies["coverage"]["global_completeness"], false);
    }
    assert_eq!(outputs[0], outputs[1]);
    // An independently held pin rejects a changed package, including a valid JSON edit.
    let metrics = temp.path().join("first/metrics.json");
    std::fs::write(metrics, b"{}\n").unwrap();
    let rejected = Command::new("python3")
        .args(["-B"])
        .arg(&script)
        .arg("verify")
        .arg(temp.path().join("first"))
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(2));
}
