use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;

use axum::response::sse::{Event, Sse};
use futures_util::stream::Stream;
use tokio_util::sync::CancellationToken;

/// State for the polling SSE stream.
struct PollState {
    conn: rusqlite::Connection,
    last_seq: i64,
    cancel: CancellationToken,
    /// Buffer of events from the last poll, drained one at a time.
    buffer: Vec<serde_json::Value>,
    at_tail: bool,
}

/// Create an SSE stream that polls the audit SQLite database for new events.
///
/// Drains bounded pages immediately, polling every 500ms only at the tail.
/// The stream ends when the cancellation token is triggered (server shutdown).
pub fn audit_sse_stream(
    db_path: PathBuf,
    cancel: CancellationToken,
    last_seq: Option<i64>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, rusqlite::Error> {
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let max_seq = conn.query_row(
        "SELECT COALESCE(MAX(sequence_number), -1) FROM audit_events",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let initial = PollState {
        conn,
        last_seq: last_seq.unwrap_or(max_seq),
        cancel,
        buffer: vec![],
        at_tail: false,
    };
    let stream =
        futures_util::stream::unfold(Some(initial), |state: Option<PollState>| async move {
            let mut state = state?;
            loop {
                if state.cancel.is_cancelled() {
                    return None;
                }
                if let Some(row) = state.buffer.pop() {
                    if let Some(seq) = row.get("sequence_number").and_then(|v| v.as_i64()) {
                        state.last_seq = seq;
                    }
                    let event = Event::default()
                        .event("audit")
                        .id(state.last_seq.to_string())
                        .data(row.to_string());
                    return Some((Ok(event), Some(state)));
                }
                if state.at_tail {
                    tokio::select! {
                        _ = state.cancel.cancelled() => return None,
                        _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                    }
                }
                let last_seq = state.last_seq;
                // SQLite is synchronous. Keep one bounded query per stream off
                // executor workers; dropping the stream never starts more work.
                let query = tokio::task::spawn_blocking(move || {
                    let rows = query_new_events(&state.conn, last_seq);
                    (state.conn, rows)
                });
                let result = tokio::select! {
                    _ = state.cancel.cancelled() => return None,
                    result = query => result,
                };
                let Ok((conn, rows)) = result else {
                    let event = Event::default()
                        .event("stream_error")
                        .data("Audit query worker stopped. Reconnecting.");
                    return Some((Ok(event), None));
                };
                state.conn = conn;
                match rows {
                    Ok(mut rows) => {
                        state.at_tail = rows.len() < 100;
                        rows.reverse();
                        state.buffer = rows;
                    }
                    Err(error) => {
                        tracing::warn!("audit stream query failed: {error}");
                        let event = Event::default()
                            .event("stream_error")
                            .data("Audit database became unavailable. Reconnecting.");
                        return Some((Ok(event), None));
                    }
                }
            }
        });
    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    ))
}

const NEW_EVENTS_SQL: &str = "SELECT event_id, sequence_number, ts_utc_ms, level, kind,
                request_id, operation, safety, outcome, latency_ms,
                secret_names, detail, target_json
         FROM audit_events
         WHERE sequence_number > ?1
         ORDER BY sequence_number ASC
         LIMIT 100";

/// Query events with sequence_number greater than `last_seq`.
fn query_new_events(
    conn: &rusqlite::Connection,
    last_seq: i64,
) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
    let mut stmt = conn.prepare(NEW_EVENTS_SQL)?;

    let rows = stmt.query_map(rusqlite::params![last_seq], |row| {
        Ok(serde_json::json!({
            "event_id": row.get::<_, Option<String>>("event_id")?,
            "sequence_number": row.get::<_, i64>("sequence_number")?,
            "ts_utc_ms": row.get::<_, i64>("ts_utc_ms")?,
            "level": row.get::<_, Option<String>>("level")?,
            "kind": row.get::<_, Option<String>>("kind")?,
            "request_id": row.get::<_, Option<String>>("request_id")?,
            "operation": row.get::<_, Option<String>>("operation")?,
            "safety": row.get::<_, Option<String>>("safety")?,
            "outcome": row.get::<_, Option<String>>("outcome")?,
            "latency_ms": row.get::<_, Option<i64>>("latency_ms")?,
            "secret_names": row.get::<_, Option<String>>("secret_names")?,
            "detail": row.get::<_, Option<String>>("detail")?,
            "target_json": row.get::<_, Option<String>>("target_json")?,
        }))
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use futures_util::StreamExt;

    struct Database(PathBuf);
    impl Database {
        fn new(count: usize) -> Self {
            let path = std::env::temp_dir().join(format!("opaque-sse-{}.db", uuid::Uuid::new_v4()));
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_events (
                event_id TEXT PRIMARY KEY, sequence_number INTEGER NOT NULL, ts_utc_ms INTEGER,
                level TEXT, kind TEXT, request_id TEXT, operation TEXT, safety TEXT,
                outcome TEXT, latency_ms INTEGER, secret_names TEXT, detail TEXT, target_json TEXT
            );
            CREATE INDEX idx_sequence ON audit_events(sequence_number);",
            )
            .unwrap();
            let transaction = conn.transaction().unwrap();
            for seq in 0..count {
                transaction
                    .execute(
                        "INSERT INTO audit_events(sequence_number, ts_utc_ms) VALUES (?1, 0)",
                        [seq],
                    )
                    .unwrap();
            }
            transaction.commit().unwrap();
            Self(path)
        }
    }

    #[test]
    fn real_audit_schema_supports_indexed_keyset_streaming() {
        use std::os::unix::fs::DirBuilderExt;
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory =
            Directory(std::env::temp_dir().join(format!("opaque-sse-{}", uuid::Uuid::new_v4())));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let path = directory.0.join("audit.db");
        let sink = opaque_core::audit::SqliteAuditSink::new(path.clone(), 0).unwrap();
        sink.close().unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        let plan: Vec<String> = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {NEW_EVENTS_SQL}"))
            .unwrap()
            .query_map([0], |row| row.get(3))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(
            plan.iter()
                .any(|step| step.contains("SEARCH") && step.contains("idx_sequence")),
            "{plan:?}"
        );
        assert!(
            !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "{plan:?}"
        );
        drop(conn);
        drop(sink);
    }
    impl Drop for Database {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[tokio::test]
    async fn resume_drains_full_pages_without_poll_delays_and_cancels_buffered_rows() {
        let db = Database::new(601);
        let cancel = CancellationToken::new();
        let response = audit_sse_stream(db.0.clone(), cancel.clone(), Some(-1))
            .unwrap()
            .into_response();
        let mut body = response.into_body().into_data_stream();
        tokio::time::timeout(Duration::from_secs(2), async {
            for seq in 0..501 {
                let bytes = body.next().await.unwrap().unwrap();
                let frame = std::str::from_utf8(&bytes).unwrap();
                assert!(frame.contains(&format!("id: {seq}\n")), "{frame}");
            }
        })
        .await
        .expect("backlog pages must not sleep 500 ms each");
        // A page still contains buffered rows: shutdown must discard them.
        cancel.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), body.next())
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "explicit local load baseline: 20,000-event backlog plus 1,000 events/sec producer"]
    async fn audit_backlog_load_baseline() {
        const BACKLOG: usize = 20_000;
        const BATCH: usize = 100;
        const BATCHES: usize = 20;
        let db = Database::new(BACKLOG);
        let conn = rusqlite::Connection::open(&db.0).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        drop(conn);
        let path = db.0.clone();
        let producer = tokio::spawn(async move {
            let started = std::time::Instant::now();
            for batch in 0..BATCHES {
                let path = path.clone();
                tokio::task::spawn_blocking(move || {
                    let mut conn = rusqlite::Connection::open(path).unwrap();
                    let tx = conn.transaction().unwrap();
                    for item in 0..BATCH {
                        let seq = BACKLOG + batch * BATCH + item;
                        tx.execute(
                            "INSERT INTO audit_events(sequence_number, ts_utc_ms) VALUES (?1, 0)",
                            [seq],
                        )
                        .unwrap();
                    }
                    tx.commit().unwrap();
                })
                .await
                .unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            started.elapsed()
        });
        let cancel = CancellationToken::new();
        let response = audit_sse_stream(db.0.clone(), cancel.clone(), Some(-1))
            .unwrap()
            .into_response();
        let mut body = response.into_body().into_data_stream();
        let started = std::time::Instant::now();
        let mut backlog_elapsed = Duration::ZERO;
        tokio::time::timeout(Duration::from_secs(10), async {
            for seq in 0..BACKLOG + BATCH * BATCHES {
                let bytes = body.next().await.unwrap().unwrap();
                let frame = std::str::from_utf8(&bytes).unwrap();
                assert!(frame.contains(&format!("id: {seq}\n")), "{frame}");
                if seq + 1 == BACKLOG {
                    backlog_elapsed = started.elapsed();
                }
            }
        })
        .await
        .expect("must drain the backlog and catch the concurrent producer");
        let elapsed = started.elapsed();
        let production_elapsed = producer.await.unwrap();
        let produced_per_second = (BATCH * BATCHES) as f64 / production_elapsed.as_secs_f64();
        assert!(
            produced_per_second > 200.0,
            "producer must exceed the old drain ceiling"
        );
        cancel.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(250), body.next())
                .await
                .unwrap()
                .is_none()
        );
        eprintln!(
            "audit SSE baseline: backlog={BACKLOG}, backlog_ms={}, total_events={}, total_ms={}, producer_events_per_sec={produced_per_second:.1}; exact sequence verified; page buffer <=100; cancellation <250ms",
            backlog_elapsed.as_millis(),
            BACKLOG + BATCH * BATCHES,
            elapsed.as_millis()
        );
    }
}
