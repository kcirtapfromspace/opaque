use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;

use axum::response::sse::{Event, Sse};
use futures_util::stream::Stream;
use opaque_core::audit::AuditNotify;
use tokio_util::sync::CancellationToken;

/// State for the polling SSE stream.
struct PollState {
    conn: rusqlite::Connection,
    last_seq: i64,
    cancel: CancellationToken,
    /// Buffer of events from the last poll, drained one at a time.
    buffer: Vec<serde_json::Value>,
    notify: Option<AuditNotify>,
}

/// Create an SSE stream that polls the audit SQLite database for new events.
///
/// Polls every 500ms (or wakes on push notification) for events with
/// `sequence_number > last_seen`.
/// The stream ends when the cancellation token is triggered (server shutdown).
pub fn audit_sse_stream(
    db_path: PathBuf,
    cancel: CancellationToken,
    notify: Option<AuditNotify>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = futures_util::stream::unfold(None, move |state: Option<PollState>| {
        let db_path = db_path.clone();
        let cancel = cancel.clone();
        let notify = notify.clone();
        async move {
            // Initialize on first call.
            let mut state = match state {
                Some(s) => s,
                None => {
                    let conn = match rusqlite::Connection::open_with_flags(
                        &db_path,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            let event = Event::default()
                                .event("error")
                                .data(format!("failed to open audit db: {e}"));
                            // Return one error event then stop.
                            return Some((Ok(event), None));
                        }
                    };

                    let last_seq: i64 = conn
                        .query_row(
                            "SELECT COALESCE(MAX(sequence_number), -1) FROM audit_events",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap_or(-1);

                    PollState {
                        conn,
                        last_seq,
                        cancel,
                        buffer: vec![],
                        notify,
                    }
                }
            };

            loop {
                // Drain buffered events first.
                if let Some(row) = state.buffer.pop() {
                    if let Some(seq) = row.get("sequence_number").and_then(|v| v.as_i64())
                        && seq > state.last_seq
                    {
                        state.last_seq = seq;
                    }
                    let data = serde_json::to_string(&row).unwrap_or_default();
                    let event = Event::default().event("audit").data(data);
                    return Some((Ok(event), Some(state)));
                }

                // Wait for push notification, poll interval, or cancellation.
                tokio::select! {
                    _ = state.cancel.cancelled() => return None,
                    _ = async {
                        if let Some(ref n) = state.notify {
                            n.wait_or_timeout(Duration::from_millis(500)).await;
                        } else {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    } => {}
                }

                // Poll for new events.
                let mut rows = query_new_events(&state.conn, state.last_seq);
                // Reverse so pop() gives us events in ascending order.
                rows.reverse();
                state.buffer = rows;
            }
        }
    });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

/// Query events with sequence_number greater than `last_seq`.
fn query_new_events(conn: &rusqlite::Connection, last_seq: i64) -> Vec<serde_json::Value> {
    let mut stmt = match conn.prepare(
        "SELECT event_id, sequence_number, ts_utc_ms, level, kind,
                request_id, operation, safety, outcome, latency_ms,
                secret_names, detail, target_json
         FROM audit_events
         WHERE sequence_number > ?1
         ORDER BY sequence_number ASC
         LIMIT 100",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let rows = stmt
        .query_map(rusqlite::params![last_seq], |row| {
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
        })
        .ok();

    match rows {
        Some(r) => r.filter_map(|r| r.ok()).collect(),
        None => vec![],
    }
}
