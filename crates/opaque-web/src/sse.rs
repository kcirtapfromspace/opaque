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
}

/// Create an SSE stream that polls the audit SQLite database for new events.
///
/// Polls every 500ms for events with `sequence_number > last_seen`.
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
    };
    let stream =
        futures_util::stream::unfold(Some(initial), |state: Option<PollState>| async move {
            let mut state = state?;
            loop {
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
                tokio::select! {
                    _ = state.cancel.cancelled() => return None,
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
                match query_new_events(&state.conn, state.last_seq) {
                    Ok(mut rows) => {
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

/// Query events with sequence_number greater than `last_seq`.
fn query_new_events(
    conn: &rusqlite::Connection,
    last_seq: i64,
) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT event_id, sequence_number, ts_utc_ms, level, kind,
                request_id, operation, safety, outcome, latency_ms,
                secret_names, detail, target_json
         FROM audit_events
         WHERE sequence_number > ?1
         ORDER BY sequence_number ASC
         LIMIT 100",
    )?;

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
