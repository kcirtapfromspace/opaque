//! Transactional export and explicit legacy-head upgrade. No network or secret export.
use super::{AuditError, CHAIN_GENESIS, load_hmac_key, require_valid_chain, set_chain_head};
use crate::evidence_checkpoint::{CoverageGap, EvidenceError, MAX_EXPORT_BYTES, sha256, unhex};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRecord {
    schema: String,
    rowid: i64,
    event_id: String,
    sequence_number: u64,
    ts_utc_ms: i64,
    level: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safety: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approver_json: Option<String>,
    record_hash: String,
}

pub(crate) struct ExportSummary {
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub record_count: u64,
    pub gaps: Vec<CoverageGap>,
}

pub(crate) struct VerifiedSnapshot {
    pub bytes: Vec<u8>,
    pub summary: ExportSummary,
}

pub(crate) fn inspect_export(bytes: &[u8]) -> Result<ExportSummary, EvidenceError> {
    if bytes.len() > MAX_EXPORT_BYTES || (!bytes.is_empty() && bytes.last() != Some(&b'\n')) {
        return Err(EvidenceError("invalid export framing or size"));
    }
    let mut summary = ExportSummary {
        first_sequence: None,
        last_sequence: None,
        record_count: 0,
        gaps: vec![],
    };
    let mut rowid = 0;
    let mut ids = std::collections::HashSet::new();
    for framed in bytes.split_inclusive(|b| *b == b'\n') {
        let line = &framed[..framed.len() - 1];
        if line.len() > 1024 * 1024 {
            return Err(EvidenceError("export record too large"));
        }
        let row: ExportRecord =
            serde_json::from_slice(line).map_err(|_| EvidenceError("invalid export record"))?;
        if row.schema != "opaque.audit.v1"
            || row.rowid <= rowid
            || row.sequence_number > i64::MAX as u64
            || uuid::Uuid::parse_str(&row.event_id).is_err()
            || !ids.insert(row.event_id)
            || !matches!(row.level.as_str(), "info" | "warn" | "error")
            || row.kind.is_empty()
        {
            return Err(EvidenceError("invalid export record identity"));
        }
        unhex::<32>(&row.record_hash)?;
        if let Some(previous) = summary.last_sequence {
            if row.sequence_number <= previous {
                return Err(EvidenceError("export sequence regressed"));
            }
            if row.sequence_number > previous + 1 {
                if summary.gaps.len() >= 128 {
                    return Err(EvidenceError("too many export gaps"));
                }
                summary.gaps.push(CoverageGap {
                    first_sequence: previous + 1,
                    last_sequence: row.sequence_number - 1,
                });
            }
        }
        summary.first_sequence.get_or_insert(row.sequence_number);
        summary.last_sequence = Some(row.sequence_number);
        summary.record_count += 1;
        if summary.record_count > 100_000 {
            return Err(EvidenceError("too many export records"));
        }
        rowid = row.rowid;
    }
    Ok(summary)
}

fn export_snapshot(conn: &Connection) -> Result<Vec<u8>, AuditError> {
    let approver = if conn
        .prepare("SELECT approver_json FROM audit_events LIMIT 0")
        .is_ok()
    {
        "approver_json"
    } else {
        "NULL AS approver_json"
    };
    let query = format!(
        "SELECT rowid,event_id,sequence_number,ts_utc_ms,level,kind,request_id,approval_id,client_json,operation,safety,target_json,outcome,latency_ms,secret_names,policy_decision,detail,workspace_json,request_hash,{approver},record_hash FROM audit_events ORDER BY rowid LIMIT 100001"
    );
    let mut statement = conn.prepare(&query)?;
    let mut rows = statement.query([])?;
    let mut bytes = Vec::new();
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let record = ExportRecord {
            schema: "opaque.audit.v1".into(),
            rowid: row.get(0)?,
            event_id: row.get(1)?,
            sequence_number: row.get(2)?,
            ts_utc_ms: row.get(3)?,
            level: row.get(4)?,
            kind: row.get(5)?,
            request_id: row.get(6)?,
            approval_id: row.get(7)?,
            client_json: row.get(8)?,
            operation: row.get(9)?,
            safety: row.get(10)?,
            target_json: row.get(11)?,
            outcome: row.get(12)?,
            latency_ms: row.get(13)?,
            secret_names: row.get(14)?,
            policy_decision: row.get(15)?,
            detail: row.get(16)?,
            workspace_json: row.get(17)?,
            request_hash: row.get(18)?,
            approver_json: row.get(19)?,
            record_hash: row.get(20)?,
        };
        serde_json::to_writer(&mut bytes, &record)
            .map_err(|_| AuditError::Other("audit export serialization failed".into()))?;
        bytes.push(b'\n');
        count += 1;
        if bytes.len() > MAX_EXPORT_BYTES || count > 100_000 {
            return Err(AuditError::Other(
                "audit checkpoint export exceeds bounded snapshot; archive before checkpointing"
                    .into(),
            ));
        }
    }
    Ok(bytes)
}

pub(crate) fn verified_snapshot(path: &Path) -> Result<VerifiedSnapshot, EvidenceError> {
    let key = load_hmac_key(path).map_err(|_| EvidenceError("audit key unavailable"))?;
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| EvidenceError("audit database unavailable"))?;
    let tx = conn
        .transaction()
        .map_err(|_| EvidenceError("audit snapshot failed"))?;
    require_valid_chain(&tx, &key, false)
        .map_err(|_| EvidenceError("audit authentication failed"))?;
    let bytes = export_snapshot(&tx).map_err(|_| EvidenceError("audit export failed"))?;
    let summary = inspect_export(&bytes)?;
    Ok(VerifiedSnapshot { bytes, summary })
}

/// Read-only legacy inspection for comparing bytes with an already independently
/// retained export. The digest printed today is not itself a trusted old anchor.
pub fn inspect_legacy_export(path: &Path) -> Result<Vec<u8>, AuditError> {
    let key = load_hmac_key(path)?;
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = conn.transaction()?;
    require_valid_chain(&tx, &key, true)?;
    export_snapshot(&tx)
}

/// Explicit offline upgrade requires the exact previously trusted export digest.
/// Verification and pin comparison precede all changes in one writer transaction.
/// The caller must stop every old writer and independently establish the pin.
pub fn upgrade_legacy_head(path: &Path, trusted_export_sha256: &str) -> Result<(), AuditError> {
    unhex::<32>(trusted_export_sha256)
        .map_err(|_| AuditError::Other("invalid trusted export digest".into()))?;
    let key = load_hmac_key(path)?;
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx
        .prepare("SELECT format_version,authenticator FROM chain_head LIMIT 0")
        .is_ok()
    {
        return Err(AuditError::Other(
            "audit head is already versioned; refusing downgrade/re-anchor".into(),
        ));
    }
    require_valid_chain(&tx, &key, true)?;
    if sha256(&export_snapshot(&tx)?) != trusted_export_sha256 {
        return Err(AuditError::Other(
            "independently trusted export digest does not match; no upgrade performed".into(),
        ));
    }
    // Never migrate an unchained source or silently rehash its records.
    tx.execute_batch("CREATE TABLE IF NOT EXISTS chain_head(id INTEGER PRIMARY KEY CHECK(id=0),last_hash TEXT NOT NULL,last_sequence INTEGER NOT NULL);
        ALTER TABLE chain_head ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1 CHECK(format_version=1);
        ALTER TABLE chain_head ADD COLUMN authenticator TEXT NOT NULL DEFAULT '';")?;
    let head: Option<(String, i64)> = tx
        .query_row(
            "SELECT record_hash,sequence_number FROM audit_events ORDER BY rowid DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (hash, sequence) = match head {
        Some(head) => head,
        None => super::retention_boundary(&tx, &key)?.unwrap_or((CHAIN_GENESIS.into(), -1)),
    };
    set_chain_head(&tx, &key, &hash, sequence)?;
    require_valid_chain(&tx, &key, false)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditEventKind, CHAIN_GENESIS, SqliteAuditSink};
    use crate::evidence_checkpoint::{
        ProducerTrust, Scope, create_checkpoint, hex, key_id, verify_checkpoint,
    };

    #[test]
    fn authenticated_sequence_gaps_are_declared_and_verified_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        SqliteAuditSink::new(path.clone(), 0)
            .unwrap()
            .close()
            .unwrap();
        let key = load_hmac_key(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        let events: Vec<_> = [0, 2, 4]
            .into_iter()
            .map(|sequence| {
                AuditEvent::new(AuditEventKind::RequestReceived).with_sequence_number(sequence)
            })
            .collect();
        SqliteAuditSink::insert_batch(&conn, &events, &key, &mut CHAIN_GENESIS.to_owned()).unwrap();
        drop(conn);
        let signing = ed25519_dalek::SigningKey::from_bytes(&[57; 32]);
        let trust = ProducerTrust {
            schema_version: 1,
            scope: Scope {
                tenant_id: "tenant".into(),
                broker_id: "broker".into(),
                stream_id: "stream".into(),
                generation: "generation".into(),
            },
            key_id: key_id(&signing.verifying_key()),
            public_key: hex(signing.verifying_key().as_bytes()),
        };
        let (mut checkpoint, export) =
            create_checkpoint(&path, &trust, &signing, None, "build".into()).unwrap();
        assert_eq!(
            checkpoint.payload.gaps,
            vec![
                CoverageGap {
                    first_sequence: 1,
                    last_sequence: 1
                },
                CoverageGap {
                    first_sequence: 3,
                    last_sequence: 3
                }
            ]
        );
        assert_eq!(checkpoint.payload.record_count, 3);
        verify_checkpoint(&checkpoint, &trust, &export).unwrap();
        checkpoint.payload.gaps.clear();
        assert!(verify_checkpoint(&checkpoint, &trust, &export).is_err());
    }
}
