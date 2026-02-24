pub mod audit;
pub mod operations;
pub mod policy;
pub mod sessions;
pub mod status;

use axum::Router;
use axum::response::Html;
use axum::routing::get;

use crate::AppState;

static INDEX_HTML: &str = include_str!("../../static/index.html");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(serve_spa))
        .route("/api/status", get(status::get_status))
        .route("/api/audit", get(audit::get_audit))
        .route("/api/audit/stream", get(audit::get_audit_stream))
        .route("/api/policy", get(policy::get_policy))
        .route("/api/sessions", get(sessions::get_sessions))
        .route("/api/operations", get(operations::get_operations))
}

async fn serve_spa() -> Html<&'static str> {
    Html(INDEX_HTML)
}
