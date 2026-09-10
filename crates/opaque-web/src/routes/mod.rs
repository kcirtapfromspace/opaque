pub mod audit;
pub mod brand;
pub mod operations;
pub mod policy;
pub mod sessions;
pub mod status;
pub mod tasks;

use axum::Router;
use axum::response::Html;
use axum::routing::{get, post};

use crate::AppState;

static INDEX_HTML: &str = include_str!("../../static/index.html");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(serve_spa))
        .route("/brand/{*path}", get(brand::get_asset))
        .route("/api/status", get(status::get_status))
        .route("/api/fleet", get(fleet_inventory))
        .route("/api/tasks", get(tasks::list_tasks))
        .route("/api/tasks/{id}", get(tasks::get_task))
        .route("/api/tasks/{id}/reconcile", post(tasks::reconcile_task))
        .route("/api/audit", get(audit::get_audit))
        .route("/api/audit/stream", get(audit::get_audit_stream))
        .route("/api/policy", get(policy::get_policy))
        .route("/api/sessions", get(sessions::get_sessions))
        .route("/api/operations", get(operations::get_operations))
}

async fn fleet_inventory(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<serde_json::Value>)>
{
    if state.demo {
        return Ok(axum::Json(
            serde_json::json!({"mode":"demo","configured":false,
            "message":"Fleet evidence requires an enrolled collector. Demo activity does not establish fleet coverage."}),
        ));
    }
    let Some(fleet) = state.fleet else {
        return Ok(axum::Json(serde_json::json!({"configured":false,
            "message":"Connect a tenant fleet collector to view enrolled brokers."})));
    };
    let snapshot = fleet
        .snapshot()
        .await
        .map_err(|error| api_error(axum::http::StatusCode::BAD_GATEWAY, &error))?;
    Ok(axum::Json(
        serde_json::json!({"configured":true,"snapshot":snapshot}),
    ))
}

async fn serve_spa() -> Html<&'static str> {
    Html(INDEX_HTML)
}

pub fn api_error(
    status: axum::http::StatusCode,
    message: &str,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({ "mode": "unavailable", "error": message })),
    )
}
