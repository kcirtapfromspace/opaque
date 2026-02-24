use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::AppState;

pub async fn get_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    if !state.daemon.is_available() {
        return Json(json!({
            "mode": "demo",
            "daemon_running": false,
        }));
    }

    match state.daemon.try_call("ping", json!({})).await {
        Some(resp) if resp.error.is_none() => {
            let version = resp
                .result
                .as_ref()
                .and_then(|r| r.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Json(json!({
                "mode": "live",
                "daemon_running": true,
                "daemon_version": version,
            }))
        }
        _ => Json(json!({
            "mode": "demo",
            "daemon_running": false,
        })),
    }
}
