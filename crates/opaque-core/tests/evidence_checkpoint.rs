use ed25519_dalek::SigningKey;
use opaque_core::audit::checkpoint::{inspect_legacy_export, upgrade_legacy_head};
use opaque_core::audit::{
    AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink, verify_audit_chain,
};
use opaque_core::evidence_checkpoint::*;
use rusqlite::Connection;

fn fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    SigningKey,
    ProducerTrust,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.db");
    let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
    for kind in [
        AuditEventKind::RequestReceived,
        AuditEventKind::ApprovalGranted,
        AuditEventKind::OperationSucceeded,
    ] {
        sink.emit(AuditEvent::new(kind).with_operation("synthetic.noop"));
    }
    sink.close().unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let trust = ProducerTrust {
        schema_version: 1,
        scope: Scope {
            tenant_id: "tenant-a".into(),
            broker_id: "broker-a".into(),
            stream_id: "audit".into(),
            generation: "generation-one".into(),
        },
        key_id: key_id(&key.verifying_key()),
        public_key: hex(key.verifying_key().as_bytes()),
    };
    (directory, path, key, trust)
}

#[test]
fn authenticated_snapshot_exact_bytes_and_independent_scope_key() {
    let (_directory, path, key, trust) = fixture();
    let (checkpoint, export) =
        create_checkpoint(&path, &trust, &key, None, "test-build".into()).unwrap();
    assert_eq!(checkpoint.payload.checkpoint_sequence, 1);
    assert_eq!(checkpoint.payload.record_count, 3);
    let verified = verify_checkpoint(&checkpoint, &trust, &export).unwrap();
    assert_eq!(
        verified.checkpoint_sha256,
        checkpoint_digest(&checkpoint).unwrap()
    );
    let mut altered = export.clone();
    altered.push(b' ');
    assert!(verify_checkpoint(&checkpoint, &trust, &altered).is_err());
    for field in ["tenant", "broker", "stream", "generation", "key"] {
        let mut other = trust.clone();
        match field {
            "tenant" => other.scope.tenant_id = "other".into(),
            "broker" => other.scope.broker_id = "other".into(),
            "stream" => other.scope.stream_id = "other".into(),
            "generation" => other.scope.generation = "other".into(),
            _ => {
                let key = SigningKey::from_bytes(&[43; 32]);
                other.key_id = key_id(&key.verifying_key());
                other.public_key = hex(key.verifying_key().as_bytes());
            }
        }
        assert!(
            verify_checkpoint(&checkpoint, &other, &export).is_err(),
            "{field}"
        );
    }
    let mut changed = checkpoint.clone();
    changed.payload.build_identity = "other-build".into();
    assert!(verify_checkpoint(&changed, &trust, &export).is_err());
    let mut changed = checkpoint.clone();
    changed.payload.record_count = 2;
    assert!(verify_checkpoint(&changed, &trust, &export).is_err());
    let mut changed = checkpoint.clone();
    changed.payload.gaps.push(CoverageGap {
        first_sequence: 1,
        last_sequence: 1,
    });
    assert!(verify_checkpoint(&changed, &trust, &export).is_err());
    let decoded: SignedCheckpoint =
        decode(&serde_json::to_vec_pretty(&checkpoint).unwrap()).unwrap();
    assert_eq!(
        checkpoint_digest(&decoded).unwrap(),
        verified.checkpoint_sha256
    );
}

#[test]
fn successor_link_and_explicit_generation_rotation() {
    let (_directory, path, key, trust) = fixture();
    let (first, _) = create_checkpoint(&path, &trust, &key, None, "build".into()).unwrap();
    let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::OperationFailed));
    sink.close().unwrap();
    let (next, export) =
        create_checkpoint(&path, &trust, &key, Some(&first), "build".into()).unwrap();
    assert_eq!(
        next.payload.previous_checkpoint_sha256,
        Some(checkpoint_digest(&first).unwrap())
    );
    assert_eq!(next.payload.checkpoint_sequence, 2);
    verify_checkpoint(&next, &trust, &export).unwrap();
    let mut tampered = first.clone();
    tampered.signature = "0".repeat(128);
    assert!(create_checkpoint(&path, &trust, &key, Some(&tampered), "build".into()).is_err());
    let rotated = SigningKey::from_bytes(&[44; 32]);
    let mut rotated_trust = trust.clone();
    rotated_trust.key_id = key_id(&rotated.verifying_key());
    rotated_trust.public_key = hex(rotated.verifying_key().as_bytes());
    assert!(
        create_checkpoint(
            &path,
            &rotated_trust,
            &rotated,
            Some(&first),
            "build".into()
        )
        .is_err()
    );
    rotated_trust.scope.generation = "generation-two".into();
    let (rotation, bytes) =
        create_checkpoint(&path, &rotated_trust, &rotated, None, "build".into()).unwrap();
    assert_eq!(rotation.payload.checkpoint_sequence, 1);
    verify_checkpoint(&rotation, &rotated_trust, &bytes).unwrap();
    assert!(verify_checkpoint(&rotation, &trust, &bytes).is_err());
}

#[test]
fn suffix_and_head_rewrite_cannot_reauthenticate_without_key() {
    let (_directory, path, key, trust) = fixture();
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "DELETE FROM audit_events WHERE rowid=(SELECT MAX(rowid) FROM audit_events)",
        [],
    )
    .unwrap();
    assert!(!verify_audit_chain(&path).unwrap().ok);
    conn.execute("UPDATE chain_head SET last_hash=(SELECT record_hash FROM audit_events ORDER BY rowid DESC LIMIT 1),last_sequence=(SELECT sequence_number FROM audit_events ORDER BY rowid DESC LIMIT 1)",[]).unwrap();
    assert!(!verify_audit_chain(&path).unwrap().ok);
    assert!(SqliteAuditSink::new(path.clone(), 0).is_err());
    assert!(create_checkpoint(&path, &trust, &key, None, "build".into()).is_err());
    conn.execute("UPDATE chain_head SET authenticator=last_hash", [])
        .unwrap();
    assert!(!verify_audit_chain(&path).unwrap().ok);
}

#[test]
fn deleting_empty_head_or_downgrading_version_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.db");
    SqliteAuditSink::new(path.clone(), 0)
        .unwrap()
        .close()
        .unwrap();
    assert!(verify_audit_chain(&path).unwrap().ok);
    let conn = Connection::open(&path).unwrap();
    conn.execute("DELETE FROM chain_head", []).unwrap();
    assert!(!verify_audit_chain(&path).unwrap().ok);
    assert!(SqliteAuditSink::new(path.clone(), 0).is_err());
    let (_other, path, _key, _trust) = fixture();
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON; UPDATE chain_head SET format_version=2;",
        )
        .unwrap();
    assert!(!verify_audit_chain(&path).unwrap().ok);
    assert!(SqliteAuditSink::new(path, 0).is_err());
}

fn legacy(path: &std::path::Path) {
    Connection::open(path).unwrap().execute_batch("ALTER TABLE chain_head DROP COLUMN authenticator; ALTER TABLE chain_head DROP COLUMN format_version;").unwrap();
}

#[test]
fn legacy_upgrade_requires_original_pin_preserves_rows_and_refuses_reanchor() {
    let (_directory, path, _key, _trust) = fixture();
    let original = inspect_legacy_export(&path).unwrap();
    let pin = sha256(&original);
    legacy(&path);
    assert!(!verify_audit_chain(&path).unwrap().ok);
    assert!(SqliteAuditSink::new(path.clone(), 0).is_err());
    assert!(upgrade_legacy_head(&path, &"0".repeat(64)).is_err());
    assert!(!verify_audit_chain(&path).unwrap().ok);
    upgrade_legacy_head(&path, &pin).unwrap();
    assert_eq!(inspect_legacy_export(&path).unwrap(), original);
    assert!(verify_audit_chain(&path).unwrap().ok);
    assert!(upgrade_legacy_head(&path, &pin).is_err());
    SqliteAuditSink::new(path.clone(), 0)
        .unwrap()
        .close()
        .unwrap();
}

#[test]
fn original_pin_rejects_corrupted_but_locally_consistent_legacy_prefix() {
    let (_directory, path, _key, _trust) = fixture();
    let pin = sha256(&inspect_legacy_export(&path).unwrap());
    legacy(&path);
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "DELETE FROM audit_events WHERE rowid=(SELECT MAX(rowid) FROM audit_events)",
        [],
    )
    .unwrap();
    conn.execute("UPDATE chain_head SET last_hash=(SELECT record_hash FROM audit_events ORDER BY rowid DESC LIMIT 1),last_sequence=(SELECT sequence_number FROM audit_events ORDER BY rowid DESC LIMIT 1)",[]).unwrap();
    assert!(inspect_legacy_export(&path).is_ok());
    assert!(upgrade_legacy_head(&path, &pin).is_err());
    assert!(SqliteAuditSink::new(path.clone(), 0).is_err());
}

#[test]
fn empty_legacy_pin_cannot_bless_rollback_or_erased_retention_frontier() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.db");
    SqliteAuditSink::new(path.clone(), 0)
        .unwrap()
        .close()
        .unwrap();
    let earlier = directory.path().join("earlier.db");
    std::fs::copy(&path, &earlier).unwrap();
    std::fs::copy(path.with_extension("hmac"), earlier.with_extension("hmac")).unwrap();

    let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
    for _ in 0..3 {
        let mut event =
            AuditEvent::new(AuditEventKind::OperationSucceeded).with_operation("synthetic.expired");
        event.ts_utc_ms = 1;
        sink.emit(event);
    }
    sink.close().unwrap();
    SqliteAuditSink::new(path.clone(), 1)
        .unwrap()
        .close()
        .unwrap();
    let retained_frontier: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT last_sequence FROM chain_head", [], |r| r.get(0))
        .unwrap();
    assert_eq!(retained_frontier, 2);
    legacy(&path);
    legacy(&earlier);
    let erased = directory.path().join("erased.db");
    std::fs::copy(&path, &erased).unwrap();
    std::fs::copy(path.with_extension("hmac"), erased.with_extension("hmac")).unwrap();
    // A storage writer need not forge or read a key to erase these legacy anchors.
    Connection::open(&erased)
        .unwrap()
        .execute_batch("DELETE FROM retention_boundary; DELETE FROM chain_head;")
        .unwrap();
    let archived = inspect_legacy_export(&path).unwrap();
    assert!(archived.is_empty());
    let independent_pin = sha256(&archived);
    for candidate in [&path, &earlier, &erased] {
        assert_eq!(inspect_legacy_export(candidate).unwrap(), archived);
        let before = std::fs::read(candidate).unwrap();
        let key_before = std::fs::read(candidate.with_extension("hmac")).unwrap();
        let error = upgrade_legacy_head(candidate, &independent_pin).unwrap_err();
        assert!(error.to_string().contains("empty legacy export"), "{error}");
        assert_eq!(std::fs::read(candidate).unwrap(), before);
        assert!(std::fs::read(candidate.with_extension("hmac")).unwrap() == key_before);
        let conn = Connection::open(candidate).unwrap();
        assert!(
            conn.prepare("SELECT format_version,authenticator FROM chain_head")
                .is_err(),
            "refusal must not migrate or rewrite the old head"
        );
        drop(conn);
        assert!(SqliteAuditSink::new(candidate.clone(), 0).is_err());
    }
}

#[test]
fn malformed_metadata_refuses_verification_startup_and_upgrade_without_changes() {
    for malformed in [
        "PRAGMA ignore_check_constraints=ON; INSERT INTO retention_boundary VALUES(1,'invalid',0,0,1,'invalid');",
        "PRAGMA ignore_check_constraints=ON; INSERT INTO chain_head VALUES(1,'invalid',0);",
        "CREATE TABLE duplicate_head AS SELECT * FROM chain_head; DROP TABLE chain_head; ALTER TABLE duplicate_head RENAME TO chain_head; INSERT INTO chain_head SELECT * FROM chain_head;",
        "CREATE TRIGGER unexpected_head_trigger AFTER UPDATE ON chain_head BEGIN SELECT 1; END;",
        "CREATE TRIGGER unexpected_boundary_trigger AFTER INSERT ON retention_boundary BEGIN SELECT 1; END;",
        "ALTER TABLE retention_boundary RENAME TO renamed_boundary; ALTER TABLE renamed_boundary RENAME TO RETENTION_BOUNDARY; CREATE TRIGGER unexpected_uppercase_trigger AFTER INSERT ON RETENTION_BOUNDARY BEGIN SELECT 1; END;",
    ] {
        let (_directory, path, _key, _trust) = fixture();
        let pin = sha256(&inspect_legacy_export(&path).unwrap());
        legacy(&path);
        Connection::open(&path)
            .unwrap()
            .execute_batch(malformed)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let checked = verify_audit_chain(&path).unwrap();
        assert!(!checked.ok);
        assert!(checked.detail.unwrap().contains("metadata"));
        assert!(inspect_legacy_export(&path).is_err());
        assert!(upgrade_legacy_head(&path, &pin).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(SqliteAuditSink::new(path.clone(), 0).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn exact_older_snapshot_needs_retained_checkpoint_to_detect_regression() {
    let (directory, path, key, trust) = fixture();
    let old = directory.path().join("old.db");
    // Sink is closed; SQLite has checkpointed its last connection's WAL.
    std::fs::copy(&path, &old).unwrap();
    let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::OperationFailed));
    sink.close().unwrap();
    let (latest, _) = create_checkpoint(&path, &trust, &key, None, "build".into()).unwrap();
    std::fs::copy(&old, &path).unwrap();
    assert!(
        verify_audit_chain(&path).unwrap().ok,
        "local authentic old state is not independent rollback proof"
    );
    assert!(create_checkpoint(&path, &trust, &key, Some(&latest), "build".into()).is_err());
}

#[test]
fn retention_receipt_checks_independent_key_binding_and_deadline() {
    let (_directory, path, producer_key, trust) = fixture();
    let (checkpoint, export) =
        create_checkpoint(&path, &trust, &producer_key, None, "build".into()).unwrap();
    verify_checkpoint(&checkpoint, &trust, &export).unwrap();
    let key = SigningKey::from_bytes(&[99; 32]);
    let custodian = CustodianTrust {
        schema_version: 1,
        key_id: key_id(&key.verifying_key()),
        public_key: hex(key.verifying_key().as_bytes()),
    };
    let receipt = sign_retention_receipt(
        RetentionReceipt {
            schema_version: 1,
            custodian_key_id: custodian.key_id.clone(),
            scope: trust.scope.clone(),
            checkpoint_sha256: checkpoint_digest(&checkpoint).unwrap(),
            export_sha256: checkpoint.payload.export_sha256.clone(),
            first_sequence: checkpoint.payload.first_sequence,
            last_sequence: checkpoint.payload.last_sequence,
            record_count: checkpoint.payload.record_count,
            object_id: "objects/synthetic".into(),
            object_version: "v1".into(),
            previous_receipt_sha256: None,
            received_at_unix_ms: 1000,
            retain_until_unix_ms: 2000,
        },
        &key,
    )
    .unwrap();
    verify_retention_receipt(&receipt, &custodian, &checkpoint, 1500).unwrap();
    // A correctly signed receipt with the producer's own key is insufficient.
    let same_key_trust = CustodianTrust {
        schema_version: 1,
        key_id: trust.key_id.clone(),
        public_key: trust.public_key.clone(),
    };
    let mut same_key_payload = receipt.payload.clone();
    same_key_payload.custodian_key_id = trust.key_id.clone();
    let same_key_receipt = sign_retention_receipt(same_key_payload, &producer_key).unwrap();
    assert_eq!(
        verify_retention_receipt(&same_key_receipt, &same_key_trust, &checkpoint, 1500)
            .unwrap_err()
            .0,
        "producer and custodian signer keys must differ"
    );
    assert!(verify_retention_receipt(&receipt, &custodian, &checkpoint, 2000).is_err());
    assert!(verify_retention_receipt(&receipt, &custodian, &checkpoint, 999).is_err());
    let mut other = checkpoint.clone();
    other.payload.scope.stream_id = "other".into();
    assert!(verify_retention_receipt(&receipt, &custodian, &other, 1500).is_err());
    let mut tampered = receipt.clone();
    tampered.payload.object_version = "v2".into();
    assert!(verify_retention_receipt(&tampered, &custodian, &checkpoint, 1500).is_err());
    let wrong = SigningKey::from_bytes(&[98; 32]);
    let wrong = CustodianTrust {
        schema_version: 1,
        key_id: key_id(&wrong.verifying_key()),
        public_key: hex(wrong.verifying_key().as_bytes()),
    };
    assert!(verify_retention_receipt(&receipt, &wrong, &checkpoint, 1500).is_err());
}

#[test]
fn strict_wire_documents_and_empty_snapshot() {
    assert!(
        decode::<SignedCheckpoint>(b"{\"payload\":{},\"payload\":{},\"signature\":\"\"}").is_err()
    );
    assert!(decode::<SignedCheckpoint>(&vec![b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
    assert!(unhex::<32>(&"A".repeat(64)).is_err());
    let (directory, _path, key, trust) = fixture();
    let empty = directory.path().join("empty.db");
    SqliteAuditSink::new(empty.clone(), 0)
        .unwrap()
        .close()
        .unwrap();
    let (checkpoint, bytes) =
        create_checkpoint(&empty, &trust, &key, None, "build".into()).unwrap();
    assert!(bytes.is_empty());
    assert_eq!(checkpoint.payload.record_count, 0);
    verify_checkpoint(&checkpoint, &trust, &bytes).unwrap();
}
