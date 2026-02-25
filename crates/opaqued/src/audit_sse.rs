//! Lightweight localhost SSE feed for audit events.
//!
//! This is intentionally simple and request-driven:
//! - no broker-wide event bus
//! - no secrets in payload (only audit-safe fields)
//! - SQLite polling with incremental watermark (`since_ms`)

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::stream;
use opaque_core::audit::{AuditEvent, AuditFilter, query_audit_db};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::warn;

const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_BATCH_LIMIT: usize = 100;
const MAX_BATCH_LIMIT: usize = 1_000;
const MIN_POLL_INTERVAL_MS: u64 = 50;
const MAX_POLL_INTERVAL_MS: u64 = 60_000;

#[derive(Debug, Clone)]
pub struct AuditSseServerConfig {
    pub bind_addr: SocketAddr,
    pub db_path: PathBuf,
    pub poll_interval: Duration,
    pub batch_limit: usize,
}

impl AuditSseServerConfig {
    pub fn new(bind_addr: SocketAddr, db_path: PathBuf) -> Self {
        Self {
            bind_addr,
            db_path,
            poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
            batch_limit: DEFAULT_BATCH_LIMIT,
        }
    }
}

#[derive(Debug, Clone)]
struct AuditSseState {
    db_path: PathBuf,
    poll_interval: Duration,
    batch_limit: usize,
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    since_ms: Option<i64>,
    poll_ms: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
}

#[derive(Debug)]
struct StreamState {
    db_path: PathBuf,
    last_seen_ms: i64,
    poll_interval: Duration,
    batch_limit: usize,
    pending: VecDeque<AuditEvent>,
    fetched_once: bool,
}

pub async fn start_server(
    config: AuditSseServerConfig,
) -> std::io::Result<(JoinHandle<()>, SocketAddr)> {
    let state = Arc::new(AuditSseState {
        db_path: config.db_path,
        poll_interval: config.poll_interval,
        batch_limit: config.batch_limit.clamp(1, MAX_BATCH_LIMIT),
    });
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let local_addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            warn!("audit SSE server failed: {err}");
        }
    });

    Ok((handle, local_addr))
}

fn build_router(state: Arc<AuditSseState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/audit/stream", get(audit_stream_handler))
        .with_state(state)
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

async fn audit_stream_handler(
    State(state): State<Arc<AuditSseState>>,
    Query(query): Query<StreamQuery>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let poll_ms = query
        .poll_ms
        .map(|ms| ms.clamp(MIN_POLL_INTERVAL_MS, MAX_POLL_INTERVAL_MS))
        .unwrap_or_else(|| state.poll_interval.as_millis() as u64);
    let batch_limit = query
        .limit
        .unwrap_or(state.batch_limit)
        .clamp(1, MAX_BATCH_LIMIT);
    let stream_state = StreamState {
        db_path: state.db_path.clone(),
        last_seen_ms: query.since_ms.unwrap_or_else(current_unix_ms),
        poll_interval: Duration::from_millis(poll_ms),
        batch_limit,
        pending: VecDeque::new(),
        fetched_once: false,
    };

    let event_stream = stream::unfold(stream_state, |mut st| async move {
        loop {
            if let Some(event) = st.pending.pop_front() {
                st.last_seen_ms = st.last_seen_ms.max(event.ts_utc_ms);
                let payload = event_payload(&event);
                let encoded = serde_json::to_string(&payload).unwrap_or_else(|err| {
                    serde_json::json!({
                        "error": format!("encode_failed: {err}")
                    })
                    .to_string()
                });
                return Some((Ok(Event::default().event("audit").data(encoded)), st));
            }

            if st.fetched_once {
                tokio::time::sleep(st.poll_interval).await;
            } else {
                st.fetched_once = true;
            }

            let db_path = st.db_path.clone();
            let since_ms = st.last_seen_ms;
            let limit = st.batch_limit;

            let query_result = tokio::task::spawn_blocking(move || {
                let filter = AuditFilter {
                    since_ms: Some(since_ms + 1),
                    limit,
                    ..AuditFilter::default()
                };
                query_audit_db(&db_path, &filter)
            })
            .await;

            match query_result {
                Ok(Ok(mut rows)) => {
                    rows.reverse();
                    st.pending.extend(rows);
                }
                Ok(Err(err)) => {
                    return Some((
                        Ok(Event::default()
                            .event("error")
                            .data(format!("audit_query_failed: {err}"))),
                        st,
                    ));
                }
                Err(err) => {
                    return Some((
                        Ok(Event::default()
                            .event("error")
                            .data(format!("audit_query_task_failed: {err}"))),
                        st,
                    ));
                }
            }
        }
    });

    Sse::new(event_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

fn current_unix_ms() -> i64 {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    duration.as_millis() as i64
}

fn event_payload(event: &AuditEvent) -> serde_json::Value {
    serde_json::json!({
        "event_id": event.event_id.to_string(),
        "ts_utc_ms": event.ts_utc_ms,
        "level": event.level.to_string(),
        "kind": event.kind.to_string(),
        "operation": event.operation,
        "outcome": event.outcome,
        "request_id": event.request_id.map(|u| u.to_string()),
        "target": event.target,
        "client": event.client,
        "workspace": event.workspace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::audit::{AuditEventKind, AuditSink, SqliteAuditSink};
    use tempfile::tempdir;
    use uuid::Uuid;

    #[tokio::test]
    async fn health_endpoint_ok() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let _sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let config = AuditSseServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            db_path,
            poll_interval: Duration::from_millis(100),
            batch_limit: 50,
        };
        let (handle, addr) = start_server(config).await.unwrap();
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body: HealthResponse = resp.json().await.unwrap();
        assert_eq!(body.status, "ok");

        handle.abort();
    }

    #[tokio::test]
    async fn stream_emits_audit_event_frame() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded)
                .with_operation("github.set_actions_secret")
                .with_outcome("allowed")
                .with_request_id(Uuid::new_v4()),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;

        let config = AuditSseServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            db_path,
            poll_interval: Duration::from_millis(50),
            batch_limit: 100,
        };
        let (handle, addr) = start_server(config).await.unwrap();

        let client = reqwest::Client::new();
        let mut resp = client
            .get(format!(
                "http://{addr}/audit/stream?since_ms=0&poll_ms=50&limit=10"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        let found = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let next = resp.chunk().await.unwrap();
                let Some(chunk) = next else {
                    return false;
                };
                let text = String::from_utf8_lossy(&chunk).to_string();
                if text.contains("event: audit")
                    && text.contains("\"kind\":\"operation.succeeded\"")
                    && text.contains("\"operation\":\"github.set_actions_secret\"")
                {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);

        assert!(found, "did not observe expected SSE audit frame");

        handle.abort();
    }
}
