//! Storage faults and adversarial maintenance cases exercise the actual writer,
//! SQLite transactions, persisted authenticators and public durability API.
use super::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        Self {
            _directory: directory,
            path,
        }
    }

    fn seed(&self, timestamps: &[i64]) {
        let sink = SqliteAuditSink::new(self.path.clone(), 0).unwrap();
        for &timestamp in timestamps {
            let mut event =
                AuditEvent::new(AuditEventKind::RequestReceived).with_detail("original");
            event.ts_utc_ms = timestamp;
            sink.emit(event);
        }
        sink.close().unwrap();
    }

    fn connection(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.path).unwrap()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn row_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap()
}

fn hashes(conn: &rusqlite::Connection) -> Vec<String> {
    conn.prepare("SELECT record_hash FROM audit_events ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn retention_rejects_corrupted_survivors_before_deleting_expired_evidence() {
    for tamper in [
        "UPDATE audit_events SET detail='corrupted' WHERE sequence_number=1",
        "DELETE FROM audit_events WHERE sequence_number=2",
        "UPDATE audit_events SET ts_utc_ms=0 WHERE sequence_number=1",
        "UPDATE audit_events SET record_hash=NULL WHERE sequence_number=1",
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[1, now(), now()]);
        let mut conn = fixture.connection();
        conn.execute_batch(tamper).unwrap();
        let before = row_count(&conn);
        assert!(!verify_audit_chain(&fixture.path).unwrap().ok);
        assert!(SqliteAuditSink::new(fixture.path.clone(), 1).is_err());
        let key = load_hmac_key(&fixture.path).unwrap();
        assert!(SqliteAuditSink::run_retention_cleanup(&mut conn, 1, &key).is_err());
        assert_eq!(
            row_count(&conn),
            before,
            "failed maintenance must preserve the expired row too"
        );
        assert!(!verify_audit_chain(&fixture.path).unwrap().ok);
        assert!(retention_boundary(&conn, &key).unwrap().is_none());
    }
}

#[test]
fn retention_boundary_and_deletion_roll_back_together() {
    let fixture = Fixture::new();
    fixture.seed(&[1, now()]);
    let mut conn = fixture.connection();
    let before = hashes(&conn);
    conn.execute_batch("CREATE TRIGGER reject_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;").unwrap();
    let key = load_hmac_key(&fixture.path).unwrap();
    assert!(SqliteAuditSink::run_retention_cleanup(&mut conn, 1, &key).is_err());
    assert!(retention_boundary(&conn, &key).unwrap().is_none());
    assert_eq!(hashes(&conn), before);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
    // Startup uses the same atomic maintenance path.
    assert!(SqliteAuditSink::new(fixture.path.clone(), 1).is_err());
    assert!(retention_boundary(&conn, &key).unwrap().is_none());
    assert_eq!(hashes(&conn), before);
    conn.execute_batch("DROP TRIGGER reject_delete;").unwrap();
    assert_eq!(
        SqliteAuditSink::run_retention_cleanup(&mut conn, 1, &key).unwrap(),
        1
    );
    assert_eq!(hashes(&conn), before[1..]);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn retention_boundary_authenticates_the_pruned_predecessor() {
    for tamper in [
        "UPDATE retention_boundary SET previous_hash='forged'",
        "UPDATE retention_boundary SET previous_sequence=99",
        "UPDATE retention_boundary SET sequence_high_watermark=99",
        "UPDATE retention_boundary SET previous_rowid=99",
        "UPDATE retention_boundary SET authenticator='forged'",
        "DELETE FROM retention_boundary",
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[1, now()]);
        SqliteAuditSink::new(fixture.path.clone(), 1)
            .unwrap()
            .close()
            .unwrap();
        let conn = fixture.connection();
        assert!(verify_audit_chain(&fixture.path).unwrap().ok);
        conn.execute_batch(tamper).unwrap();
        assert!(!verify_audit_chain(&fixture.path).unwrap().ok, "{tamper}");
        assert!(SqliteAuditSink::new(fixture.path.clone(), 1).is_err());
    }
}

#[test]
fn fully_pruned_chain_keeps_its_tail_and_next_sequence_across_restarts() {
    let fixture = Fixture::new();
    fixture.seed(&[1, 2]);
    let old_head = hashes(&fixture.connection()).pop().unwrap();
    SqliteAuditSink::new(fixture.path.clone(), 1)
        .unwrap()
        .close()
        .unwrap();
    assert_eq!(row_count(&fixture.connection()), 0);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
    let key = load_hmac_key(&fixture.path).unwrap();
    assert_eq!(
        retention_boundary(&fixture.connection(), &key).unwrap(),
        Some((old_head, 1))
    );
    let reopened = SqliteAuditSink::new(fixture.path.clone(), 1).unwrap();
    reopened.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));
    reopened.close().unwrap();
    let sequence: u64 = fixture
        .connection()
        .query_row("SELECT sequence_number FROM audit_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(sequence, 2);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn retention_does_not_rewrite_the_middle_after_a_clock_regression() {
    let fixture = Fixture::new();
    fixture.seed(&[1, now(), 2]);
    let old_hashes = hashes(&fixture.connection());
    SqliteAuditSink::new(fixture.path.clone(), 1)
        .unwrap()
        .close()
        .unwrap();
    assert_eq!(hashes(&fixture.connection()), old_hashes[1..]);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn excessive_retention_duration_never_wraps_into_a_recent_cutoff() {
    assert_eq!(SqliteAuditSink::retention_cutoff_ms(u64::MAX), 0);
}

#[test]
fn transaction_failures_do_not_advance_the_in_memory_hash() {
    for (schema, trigger) in [
        (
            "",
            "CREATE TRIGGER reject_write BEFORE INSERT ON audit_events WHEN NEW.sequence_number=2 BEGIN SELECT RAISE(ABORT, 'injected second insert failure'); END;",
        ),
        (
            "",
            "CREATE TRIGGER reject_write BEFORE UPDATE ON chain_head BEGIN SELECT RAISE(ABORT, 'injected head failure'); END;",
        ),
        (
            "PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE deferred_failure(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);",
            "CREATE TRIGGER reject_write AFTER UPDATE ON chain_head BEGIN INSERT INTO deferred_failure VALUES(1); END;",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[now()]);
        let conn = fixture.connection();
        conn.execute_batch(schema).unwrap();
        conn.execute_batch(trigger).unwrap();
        let key = load_hmac_key(&fixture.path).unwrap();
        let mut tail = hashes(&conn).pop().unwrap();
        let initial = tail.clone();
        let batch = [
            AuditEvent::new(AuditEventKind::OperationStarted).with_sequence_number(1),
            AuditEvent::new(AuditEventKind::OperationSucceeded).with_sequence_number(2),
        ];
        assert!(SqliteAuditSink::insert_batch(&conn, &batch, &key, &mut tail).is_err());
        assert_eq!(tail, initial, "head must only advance after commit");
        assert_eq!(row_count(&conn), 1);
        assert!(verify_audit_chain(&fixture.path).unwrap().ok);
        conn.execute_batch("DROP TRIGGER reject_write;").unwrap();
        SqliteAuditSink::insert_batch(
            &conn,
            &[AuditEvent::new(AuditEventKind::OperationSucceeded).with_sequence_number(3)],
            &key,
            &mut tail,
        )
        .unwrap();
        assert!(verify_audit_chain(&fixture.path).unwrap().ok);
        assert_eq!(row_count(&conn), 2);
    }
}

#[test]
fn writer_flush_reports_storage_loss_after_later_writes_recover() {
    let fixture = Fixture::new();
    let sink = SqliteAuditSink::new(fixture.path.clone(), 0).unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    sink.flush(Duration::from_secs(3)).unwrap();
    let conn = fixture.connection();
    conn.execute_batch("CREATE TRIGGER reject_write BEFORE UPDATE ON chain_head BEGIN SELECT RAISE(ABORT, 'injected head failure'); END;").unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::OperationStarted));
    assert!(matches!(
        sink.flush(Duration::from_secs(3)),
        Err(AuditFlushError::Storage(_))
    ));
    assert_eq!(row_count(&conn), 1);
    conn.execute_batch("DROP TRIGGER reject_write;").unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));
    assert!(matches!(
        sink.flush(Duration::from_secs(3)),
        Err(AuditFlushError::Storage(_))
    ));
    assert_eq!(
        row_count(&conn),
        2,
        "flush still drains accepted events after an earlier loss"
    );
    assert!(matches!(sink.close(), Err(AuditFlushError::Storage(_))));
    assert!(matches!(
        sink.flush(Duration::ZERO),
        Err(AuditFlushError::Storage(_))
    ));
    assert_eq!(row_count(&conn), 2);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn flush_timeout_does_not_claim_durability_or_permanently_poison_a_healthy_writer() {
    let fixture = Fixture::new();
    let sink = SqliteAuditSink::new(fixture.path.clone(), 0).unwrap();
    sink.pause_writer();
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    assert_eq!(
        sink.flush(Duration::from_millis(20)),
        Err(AuditFlushError::Timeout)
    );
    sink.resume_writer();
    sink.flush(Duration::from_secs(3)).unwrap();
    sink.close().unwrap();
    assert_eq!(row_count(&fixture.connection()), 1);
}

#[test]
fn full_queue_preserves_pending_synthetic_report() {
    // No consumer races the assertion: a paused real writer may still receive
    // one event before parking and legitimately make room for the report.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let progress = Arc::new((
        std::sync::Mutex::new(WriterState {
            sender: Some(sender),
            next_sequence: 0,
            accepted: 0,
            settled: 0,
            failure: None,
            stopped: false,
        }),
        std::sync::Condvar::new(),
    ));
    enqueue_event(&progress, AuditEvent::new(AuditEventKind::RequestReceived)).unwrap();
    let dropped = AtomicU64::new(9);
    SqliteAuditSink::report_drops(&progress, &dropped);
    assert_eq!(dropped.load(Ordering::SeqCst), 9);
    assert_eq!(progress.0.lock().unwrap().accepted, 1);
    assert_eq!(
        receiver.try_recv().unwrap().kind,
        AuditEventKind::RequestReceived
    );

    // A later successful report clears only the pending report count; the
    // accepted count includes that report and the durability loss stays sticky.
    SqliteAuditSink::report_drops(&progress, &dropped);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    let report = receiver.try_recv().unwrap();
    assert_eq!(report.kind, AuditEventKind::AuditDropped);
    assert_eq!(report.sequence_number, 1);
    let state = progress.0.lock().unwrap();
    assert_eq!(state.accepted, 2);
    assert_eq!(state.failure, Some(AuditFlushError::Backpressure));
}

#[test]
fn drops_remain_visible_to_flush_after_synthetic_report() {
    let fixture = Fixture::new();
    let sink = SqliteAuditSink::new_with_capacity(fixture.path.clone(), 0, 1).unwrap();
    sink.pause_writer();
    for _ in 0..10 {
        sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    }
    assert!(sink.dropped_count() > 0);
    sink.flush_dropped_events();
    assert_eq!(sink.flush(Duration::ZERO), Err(AuditFlushError::Timeout));
    sink.resume_writer();
    assert_eq!(
        sink.flush(Duration::from_secs(3)),
        Err(AuditFlushError::Backpressure)
    );
    assert_eq!(sink.close(), Err(AuditFlushError::Backpressure));
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn synthetic_events_cannot_satisfy_an_uncommitted_real_event_flush() {
    let fixture = Fixture::new();
    let sink = SqliteAuditSink::new(fixture.path.clone(), 0).unwrap();
    // Simulate a pending report without losing any real event. The report must
    // receive a sequence and participate in the same queue accounting.
    sink.dropped_count.store(4, Ordering::SeqCst);
    sink.flush_dropped_events();
    sink.flush(Duration::from_secs(3)).unwrap();
    sink.pause_writer();
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    assert_eq!(
        sink.flush(Duration::from_millis(20)),
        Err(AuditFlushError::Timeout)
    );
    sink.resume_writer();
    sink.close().unwrap();
    let sequences: Vec<i64> = fixture
        .connection()
        .prepare("SELECT sequence_number FROM audit_events ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(sequences, [0, 1]);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn close_drains_without_requiring_the_sink_to_be_dropped() {
    let fixture = Fixture::new();
    let sink = Arc::new(SqliteAuditSink::new(fixture.path.clone(), 0).unwrap());
    sink.pause_writer();
    for _ in 0..16 {
        sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = sink.clone();
    let handle = std::thread::spawn(move || {
        sender.send(worker.close()).unwrap();
    });
    receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("close must own shutdown")
        .unwrap();
    handle.join().unwrap();
    sink.close().unwrap();
    sink.flush(Duration::ZERO).unwrap();
    assert_eq!(row_count(&fixture.connection()), 16);
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    assert_eq!(sink.flush(Duration::ZERO), Err(AuditFlushError::Closed));
}

#[test]
fn immediate_close_does_not_miss_the_monitor_stop_notification() {
    let started = Instant::now();
    for _ in 0..8 {
        let fixture = Fixture::new();
        SqliteAuditSink::new(fixture.path.clone(), 0)
            .unwrap()
            .close()
            .unwrap();
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn missing_or_corrupt_keys_are_never_replaced_for_an_existing_chain() {
    for contents in [None, Some(b"short".as_slice())] {
        let fixture = Fixture::new();
        fixture.seed(&[now()]);
        let path = hmac_key_path(&fixture.path);
        std::fs::remove_file(&path).unwrap();
        if let Some(bytes) = contents {
            std::fs::write(&path, bytes).unwrap();
        }
        assert!(verify_audit_chain(&fixture.path).is_err());
        assert!(SqliteAuditSink::new(fixture.path.clone(), 1).is_err());
        assert_eq!(std::fs::read(&path).ok().as_deref(), contents);
    }
}

#[test]
fn verified_reads_remain_consistent_while_transactions_append_and_prune() {
    let fixture = Fixture::new();
    fixture.seed(&[1]);
    let path = fixture.path.clone();
    let writer = std::thread::spawn(move || {
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        let key = load_hmac_key(&path).unwrap();
        let mut tail = hashes(&conn).pop().unwrap();
        for sequence in 1..80 {
            let mut event =
                AuditEvent::new(AuditEventKind::RequestReceived).with_sequence_number(sequence);
            event.ts_utc_ms = 1;
            SqliteAuditSink::insert_batch(&conn, &[event], &key, &mut tail).unwrap();
            SqliteAuditSink::run_retention_cleanup(&mut conn, 1, &key).unwrap();
        }
    });
    for _ in 0..100 {
        let verification = verify_audit_chain(&fixture.path).unwrap();
        assert!(verification.ok, "{:?}", verification.detail);
    }
    writer.join().unwrap();
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn legacy_unchained_schema_gets_one_atomic_baseline() {
    let fixture = Fixture::new();
    let conn = fixture.connection();
    // Match the historical schema: hash and approver columns did not exist.
    conn.execute_batch("CREATE TABLE audit_events (
        event_id TEXT PRIMARY KEY, sequence_number INTEGER NOT NULL, ts_utc_ms INTEGER NOT NULL,
        level TEXT NOT NULL, kind TEXT NOT NULL, request_id TEXT, approval_id TEXT, client_json TEXT,
        operation TEXT, safety TEXT, target_json TEXT, outcome TEXT, latency_ms INTEGER,
        secret_names TEXT, policy_decision TEXT, detail TEXT, workspace_json TEXT, request_hash TEXT
    );").unwrap();
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO audit_events(event_id, sequence_number, ts_utc_ms, level, kind)
        VALUES(?1, 0, ?2, 'info', 'request.received')",
        rusqlite::params![id, now()],
    )
    .unwrap();
    let sink = SqliteAuditSink::new(fixture.path.clone(), 0).unwrap();
    sink.close().unwrap();
    let initial_hashes = hashes(&conn);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
    SqliteAuditSink::new(fixture.path.clone(), 0)
        .unwrap()
        .close()
        .unwrap();
    assert_eq!(hashes(&conn), initial_hashes);
    // Once migrated, a NULL authenticator must not trigger a second baseline.
    conn.execute("UPDATE audit_events SET record_hash=NULL", [])
        .unwrap();
    assert!(SqliteAuditSink::new(fixture.path.clone(), 0).is_err());
    assert!(!verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn missing_tail_row_is_not_mistaken_for_a_legacy_schema() {
    let fixture = Fixture::new();
    fixture.seed(&[now()]);
    let conn = fixture.connection();
    conn.execute("DELETE FROM chain_head", []).unwrap();
    assert!(!verify_audit_chain(&fixture.path).unwrap().ok);
    assert!(SqliteAuditSink::new(fixture.path.clone(), 0).is_err());
}

#[test]
fn multi_sink_flush_propagates_failure_and_still_flushes_other_sinks() {
    #[derive(Debug)]
    struct Probe {
        error: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl AuditSink for Probe {
        fn emit(&self, _: AuditEvent) {}
        fn flush(&self, _: Duration) -> Result<(), AuditFlushError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.error {
                Err(AuditFlushError::Storage("injected".into()))
            } else {
                Ok(())
            }
        }
    }
    let failed = Arc::new(Probe {
        error: true,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let healthy = Arc::new(Probe {
        error: false,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let sink = MultiAuditSink::new(vec![failed.clone(), healthy.clone()]);
    assert!(matches!(
        sink.flush(Duration::from_secs(1)),
        Err(AuditFlushError::Storage(_))
    ));
    assert_eq!(failed.calls.load(Ordering::SeqCst), 1);
    assert_eq!(healthy.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn pruning_legacy_out_of_order_sequences_preserves_the_high_watermark() {
    let fixture = Fixture::new();
    SqliteAuditSink::new(fixture.path.clone(), 0)
        .unwrap()
        .close()
        .unwrap();
    let conn = fixture.connection();
    let key = load_hmac_key(&fixture.path).unwrap();
    let mut tail = CHAIN_GENESIS.to_owned();
    let events: Vec<_> = [1, 0]
        .into_iter()
        .map(|sequence| {
            let mut event =
                AuditEvent::new(AuditEventKind::RequestReceived).with_sequence_number(sequence);
            event.ts_utc_ms = 1;
            event
        })
        .collect();
    SqliteAuditSink::insert_batch(&conn, &events, &key, &mut tail).unwrap();
    let sink = SqliteAuditSink::new(fixture.path.clone(), 1).unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
    sink.close().unwrap();
    assert_eq!(row_count(&conn), 1);
    let sequence: i64 = conn
        .query_row("SELECT sequence_number FROM audit_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(sequence, 2);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn duplicate_event_ids_never_turn_different_content_into_success() {
    let fixture = Fixture::new();
    let sink = SqliteAuditSink::new(fixture.path.clone(), 0).unwrap();
    let event = AuditEvent::new(AuditEventKind::RequestReceived).with_detail("original");
    sink.emit(event.clone());
    sink.flush(Duration::from_secs(3)).unwrap();
    sink.emit(event.with_detail("different"));
    assert!(matches!(
        sink.flush(Duration::from_secs(3)),
        Err(AuditFlushError::Storage(_))
    ));
    assert!(matches!(sink.close(), Err(AuditFlushError::Storage(_))));
    assert_eq!(row_count(&fixture.connection()), 1);
    assert!(verify_audit_chain(&fixture.path).unwrap().ok);
}

#[test]
fn client_hash_summary_never_splits_a_non_ascii_caller_value() {
    let identity = ClientIdentity {
        uid: 501,
        gid: 20,
        pid: None,
        exe_path: None,
        exe_sha256: Some(format!("{}é", "a".repeat(15))),
        codesign_team_id: None,
    };
    let summary = ClientSummary::from((&identity, ClientType::Agent));
    assert_eq!(summary.exe_sha256_prefix, Some("a".repeat(15)));
}
