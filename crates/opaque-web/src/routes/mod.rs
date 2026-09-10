pub mod audit;
pub mod brand;
pub mod operations;
pub mod policy;
pub mod sessions;
pub mod status;
pub mod tasks;

use axum::Router;
use axum::routing::{get, post};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/brand/{*path}", get(brand::get_asset))
        .route("/api/status", get(status::get_status))
        .route("/api/tasks", get(tasks::list_tasks))
        .route("/api/tasks/{id}", get(tasks::get_task))
        .route("/api/tasks/{id}/reconcile", post(tasks::reconcile_task))
        .route("/api/audit", get(audit::get_audit))
        .route("/api/audit/stream", get(audit::get_audit_stream))
        .route("/api/policy", get(policy::get_policy))
        .route("/api/sessions", get(sessions::get_sessions))
        .route("/api/operations", get(operations::get_operations))
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
