use axum::Json;
use axum::extract::State;
use serde_json::json;

use crate::AppState;

pub async fn get_sessions(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Try live mode via IPC.
    if let Some(resp) = state.daemon.try_call("agent_session_list", json!({})).await
        && let Some(result) = resp.result
    {
        return Json(json!({
            "mode": "live",
            "sessions": result,
        }));
    }

    // Fallback: demo mode.
    let sessions = crate::demo::demo_sessions();
    Json(json!({
        "mode": "demo",
        "sessions": sessions,
    }))
}
