use axum::Json;
use axum::extract::{Query, State};
use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

#[derive(Deserialize, Default)]
pub struct AuditParams {
    pub kind: Option<String>,
    pub operation: Option<String>,
    pub outcome: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
}

pub async fn get_audit(
    State(state): State<AppState>,
    Query(params): Query<AuditParams>,
) -> Json<serde_json::Value> {
    // Try live mode first.
    if state.audit_db_path.exists() {
        let filter = AuditFilter {
            kind: params
                .kind
                .as_deref()
                .and_then(|k| k.parse::<AuditEventKind>().ok()),
            operation: params.operation,
            outcome: params.outcome,
            text_query: params.q,
            limit: params.limit.unwrap_or(50),
            ..Default::default()
        };

        match query_audit_db(&state.audit_db_path, &filter) {
            Ok(events) => {
                let items: Vec<serde_json::Value> = events
                    .iter()
                    .map(|e| serde_json::to_value(e).unwrap_or_default())
                    .collect();
                return Json(json!({ "mode": "live", "events": items }));
            }
            Err(e) => {
                tracing::warn!("failed to query audit db: {e}");
            }
        }
    }

    // Fallback: demo mode.
    let events = crate::demo::demo_audit_events();
    Json(json!({ "mode": "demo", "events": events }))
}

pub async fn get_audit_stream(State(state): State<AppState>) -> axum::response::Response {
    use axum::response::IntoResponse;

    if state.audit_db_path.exists() {
        crate::sse::audit_sse_stream(state.audit_db_path.clone(), state.cancel.clone())
            .into_response()
    } else {
        // In demo mode, return SSE that sends a hint to use frontend-generated events.
        let stream = futures_util::stream::once(async {
            Ok::<_, std::convert::Infallible>(
                axum::response::sse::Event::default()
                    .event("demo")
                    .data(r#"{"mode":"demo"}"#),
            )
        });
        axum::response::sse::Sse::new(stream)
            .keep_alive(
                axum::response::sse::KeepAlive::new()
                    .interval(std::time::Duration::from_secs(15))
                    .text("ping"),
            )
            .into_response()
    }
}
