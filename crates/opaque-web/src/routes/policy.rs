use axum::Json;
use axum::extract::State;
use serde_json::json;

use crate::AppState;

pub async fn get_policy(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config_path = &state.config_path;

    match crate::config::load_web_config(config_path) {
        Some(config) => {
            let rules: Vec<serde_json::Value> = config
                .rules
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect();

            // Check if config is sealed.
            let seal_path = config_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("config.seal");
            let sealed = seal_path.exists();

            Json(json!({
                "mode": "live",
                "config_path": config_path.display().to_string(),
                "sealed": sealed,
                "enforce_agent_sessions": config.enforce_agent_sessions,
                "agent_session_ttl_secs": config.agent_session_ttl_secs,
                "rules": rules,
            }))
        }
        None => {
            // Demo mode: return sample rules.
            let rules = crate::demo::demo_policy_rules();
            Json(json!({
                "mode": "demo",
                "config_path": config_path.display().to_string(),
                "sealed": false,
                "enforce_agent_sessions": true,
                "agent_session_ttl_secs": 3600,
                "rules": rules,
            }))
        }
    }
}
