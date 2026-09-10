//! Real durable sink, persisted detector frontier/outbox and crash/replay paths.
use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};
use opaque_federation_runtime::export::{
    ApprovalDetector, Cursors, ExportConfig, ExportPump, Finding, load_cursors, read_rows_after,
    save_cursors,
};
use std::{path::Path, sync::Arc, time::Duration};

fn pump(path: &Path, audit: Arc<SqliteAuditSink>) -> ExportPump {
    ExportPump::new(
        ExportConfig::default(),
        path.join("audit.db"),
        path.join("cursor.json"),
        audit,
    )
    .unwrap()
}

fn alert_count(path: &Path) -> usize {
    read_rows_after(&path.join("audit.db"), 0, 100)
        .unwrap()
        .iter()
        .filter(|r| r.kind == "audit.alert")
        .count()
}

#[tokio::test]
async fn requirement_survives_restart_and_post_commit_outbox_replay_is_deduplicated() {
    let temp = tempfile::tempdir().unwrap();
    let sink = Arc::new(SqliteAuditSink::new(temp.path().join("audit.db"), 90).unwrap());
    let request = AuditEvent::new(AuditEventKind::RequestReceived).event_id;
    let approval = AuditEvent::new(AuditEventKind::ApprovalRequired).event_id;
    let event = |kind| {
        AuditEvent::new(kind)
            .with_request_id(request)
            .with_approval_id(approval)
            .with_request_hash("a".repeat(64))
    };
    sink.emit(event(AuditEventKind::ApprovalRequired));
    sink.flush(Duration::from_secs(5)).unwrap();
    let mut state = ApprovalDetector::default();
    pump(temp.path(), sink.clone())
        .run_once(&mut state)
        .await
        .unwrap();
    assert_eq!(state.pending_count(), 1);
    let required_sequence = state.last_sequence.unwrap();
    sink.emit(event(AuditEventKind::OperationSucceeded));
    sink.flush(Duration::from_secs(5)).unwrap();
    // New pump and no in-memory pending map model a daemon restart.
    let mut restarted = ApprovalDetector::default();
    pump(temp.path(), sink.clone())
        .run_once(&mut restarted)
        .await
        .unwrap();
    assert_eq!(restarted.pending_count(), 0);
    assert_eq!(alert_count(temp.path()), 1);
    let success = read_rows_after(&temp.path().join("audit.db"), 0, 100)
        .unwrap()
        .into_iter()
        .find(|r| r.kind == "operation.succeeded")
        .unwrap();
    let finding = Finding::new("approval_missing", &success, Some(required_sequence));
    let mut cursor = load_cursors(&temp.path().join("cursor.json")).unwrap();
    // The process may die after the alert committed but before clearing outbox.
    cursor.detector_state.as_mut().unwrap().outbox.push(finding);
    save_cursors(&temp.path().join("cursor.json"), &cursor).unwrap();
    pump(temp.path(), sink.clone())
        .run_once(&mut ApprovalDetector::default())
        .await
        .unwrap();
    assert_eq!(alert_count(temp.path()), 1);
    assert!(
        load_cursors(&temp.path().join("cursor.json"))
            .unwrap()
            .detector_state
            .unwrap()
            .outbox
            .is_empty()
    );
}

#[tokio::test]
async fn outbox_saved_before_emission_is_delivered_after_restart() {
    let temp = tempfile::tempdir().unwrap();
    let sink = Arc::new(SqliteAuditSink::new(temp.path().join("audit.db"), 90).unwrap());
    sink.emit(AuditEvent::new(AuditEventKind::AuditDropped));
    sink.flush(Duration::from_secs(5)).unwrap();
    let rows = read_rows_after(&temp.path().join("audit.db"), 0, 100).unwrap();
    let mut state = ApprovalDetector::default();
    state.outbox = state.observe_findings(&rows[0]);
    let cursors = Cursors {
        detector: rows[0].rowid,
        detector_state: Some(state),
        ..Default::default()
    };
    save_cursors(&temp.path().join("cursor.json"), &cursors).unwrap();
    assert_eq!(alert_count(temp.path()), 0);
    pump(temp.path(), sink.clone())
        .run_once(&mut ApprovalDetector::default())
        .await
        .unwrap();
    assert_eq!(alert_count(temp.path()), 1);
}

#[tokio::test]
async fn legacy_frontier_reports_coverage_gap_instead_of_inventing_violation() {
    let temp = tempfile::tempdir().unwrap();
    let sink = Arc::new(SqliteAuditSink::new(temp.path().join("audit.db"), 90).unwrap());
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    sink.flush(Duration::from_secs(5)).unwrap();
    let first = read_rows_after(&temp.path().join("audit.db"), 0, 100).unwrap()[0].rowid;
    save_cursors(
        &temp.path().join("cursor.json"),
        &Cursors {
            detector: first,
            ..Default::default()
        },
    )
    .unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));
    sink.flush(Duration::from_secs(5)).unwrap();
    let mut state = ApprovalDetector::default();
    pump(temp.path(), sink.clone())
        .run_once(&mut state)
        .await
        .unwrap();
    assert_eq!(state.health["restart_coverage_gap"], 1);
    let alerts: Vec<_> = read_rows_after(&temp.path().join("audit.db"), 0, 100)
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == "audit.alert")
        .collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].outcome.as_deref(), Some("restart_coverage_gap"));
}

#[test]
fn cursor_is_atomic_bounded_regular_and_consistent() {
    let temp = tempfile::tempdir().unwrap();
    let cursor = temp.path().join("cursor");
    save_cursors(&cursor, &Cursors::default()).unwrap();
    let original = std::fs::read(&cursor).unwrap();
    assert_eq!(load_cursors(&cursor).unwrap(), Cursors::default());
    let inconsistent = Cursors {
        detector: 10,
        detector_state: Some(ApprovalDetector::default()),
        ..Default::default()
    };
    save_cursors(&cursor, &inconsistent).unwrap();
    assert!(load_cursors(&cursor).is_err());
    std::fs::write(&cursor, b"{partial").unwrap();
    assert!(load_cursors(&cursor).is_err());
    std::fs::write(&cursor, original).unwrap();
    assert!(load_cursors(temp.path()).is_err());
    let huge = temp.path().join("huge");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(8 * 1024 * 1024 + 1)
        .unwrap();
    assert!(load_cursors(&huge).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let link = temp.path().join("link");
        symlink(&cursor, &link).unwrap();
        assert!(load_cursors(&link).is_err());
        let fifo = temp.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(load_cursors(&fifo).is_err());

        assert_eq!(
            std::fs::metadata(&cursor).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|p| p
                .file_name()
                .to_string_lossy()
                .starts_with(".export-cursor-"))
            .count(),
        0
    );
}

#[tokio::test]
async fn retention_skipping_unprocessed_rows_reports_gap_and_preserves_unknown_coverage() {
    let temp = tempfile::tempdir().unwrap();
    let sink = Arc::new(SqliteAuditSink::new(temp.path().join("audit.db"), 0).unwrap());
    let request = AuditEvent::new(AuditEventKind::RequestReceived).event_id;
    let approval = AuditEvent::new(AuditEventKind::ApprovalRequired).event_id;
    for (kind, timestamp) in [
        (AuditEventKind::ApprovalRequired, 1),
        (AuditEventKind::RequestReceived, 2),
    ] {
        let mut event = AuditEvent::new(kind)
            .with_request_id(request)
            .with_approval_id(approval)
            .with_request_hash("a".repeat(64));
        event.ts_utc_ms = timestamp;
        sink.emit(event);
    }
    sink.flush(Duration::from_secs(5)).unwrap();
    let mut first = pump(temp.path(), sink.clone());
    first.config.batch_size = Some(1);
    let mut state = ApprovalDetector::default();
    first.run_once(&mut state).await.unwrap();
    assert_eq!(state.pending_count(), 1);
    drop(first);
    sink.close().unwrap();
    drop(sink);
    let resumed = Arc::new(SqliteAuditSink::new(temp.path().join("audit.db"), 1).unwrap());
    resumed.emit(
        AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_request_id(request)
            .with_request_hash("a".repeat(64)),
    );
    resumed.flush(Duration::from_secs(5)).unwrap();
    pump(temp.path(), resumed)
        .run_once(&mut state)
        .await
        .unwrap();
    assert_eq!(state.pending_count(), 0);
    assert_eq!(state.health["evidence_gap"], 1);
    assert_eq!(state.health["terminal_without_observed_requirement"], 1);
    let alerts: Vec<_> = read_rows_after(&temp.path().join("audit.db"), 0, 100)
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == "audit.alert")
        .collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].outcome.as_deref(), Some("evidence_gap"));
}

#[tokio::test]
async fn transport_failure_is_one_finding_per_transition_and_does_not_stall_detector() {
    let temp = tempfile::tempdir().unwrap();
    let sink = Arc::new(SqliteAuditSink::new(temp.path().join("audit.db"), 90).unwrap());
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    sink.flush(Duration::from_secs(5)).unwrap();
    let mut exporter = pump(temp.path(), sink.clone());
    exporter.config.spool_path = Some(temp.path().to_path_buf()); // opening directory for append fails
    let mut state = ApprovalDetector::default();
    exporter.run_once(&mut state).await.unwrap();
    assert_eq!(alert_count(temp.path()), 1);
    assert!(state.failed_transports.contains("spool"));
    exporter.run_once(&mut state).await.unwrap();
    assert_eq!(alert_count(temp.path()), 1);
    exporter.config.spool_path = Some(temp.path().join("spool.jsonl"));
    exporter.run_once(&mut state).await.unwrap();
    assert!(state.failed_transports.is_empty());
    assert_eq!(
        load_cursors(&temp.path().join("cursor.json"))
            .unwrap()
            .spool,
        state.last_rowid
    );
}

#[tokio::test]
async fn unacknowledged_finding_with_pruned_source_stays_unknown_and_retained() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("audit.db");
    let sink = SqliteAuditSink::new(db.clone(), 0).unwrap();
    let mut event = AuditEvent::new(AuditEventKind::AuditDropped);
    event.ts_utc_ms = 1;
    sink.emit(event);
    sink.close().unwrap();
    let row = read_rows_after(&db, 0, 100).unwrap().remove(0);
    let mut state = ApprovalDetector::default();
    state.outbox = state.observe_findings(&row);
    let cursor = Cursors {
        detector: row.rowid,
        detector_state: Some(state),
        ..Default::default()
    };
    save_cursors(&temp.path().join("cursor.json"), &cursor).unwrap();
    let sink = Arc::new(SqliteAuditSink::new(db, 1).unwrap());
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    sink.flush(Duration::from_secs(5)).unwrap();
    let error = pump(temp.path(), sink)
        .run_once(&mut ApprovalDetector::default())
        .await
        .unwrap_err();
    assert!(error.contains("delivery unknown"));
    assert_eq!(
        load_cursors(&temp.path().join("cursor.json")).unwrap(),
        cursor
    );
    assert_eq!(alert_count(temp.path()), 0);
}
