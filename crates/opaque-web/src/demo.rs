use serde_json::json;

/// Generate synthetic audit events for demo mode.
pub fn demo_audit_events() -> Vec<serde_json::Value> {
    let base_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    vec![
        json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "sequence_number": 6,
            "ts_utc_ms": base_ts - 500,
            "level": "info",
            "kind": "operation.succeeded",
            "request_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "operation": "github.set_actions_secret",
            "safety": "Safe",
            "outcome": "ok",
            "latency_ms": 342,
            "secret_names": "DATABASE_URL",
            "detail": "repo=acme/api secret=DATABASE_URL",
            "target_json": "{\"repo\":\"acme/api\"}"
        }),
        json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "sequence_number": 5,
            "ts_utc_ms": base_ts - 2000,
            "level": "info",
            "kind": "approval.granted",
            "request_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "operation": "github.set_actions_secret",
            "safety": "Safe",
            "outcome": "ok",
            "latency_ms": 1200,
            "detail": "factor=local_bio"
        }),
        json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "sequence_number": 4,
            "ts_utc_ms": base_ts - 5000,
            "level": "info",
            "kind": "request.received",
            "request_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "operation": "github.set_actions_secret",
            "safety": "Safe",
            "detail": "repo=acme/api secret_name=DATABASE_URL"
        }),
        json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "sequence_number": 3,
            "ts_utc_ms": base_ts - 30_000,
            "level": "warn",
            "kind": "policy.denied",
            "request_id": "f1e2d3c4-b5a6-4978-8069-7a8b9c0d1e2f",
            "operation": "sandbox.exec",
            "safety": "SensitiveOutput",
            "outcome": "denied",
            "detail": "SENSITIVE_OUTPUT operations require explicit agent client allowance"
        }),
        json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "sequence_number": 2,
            "ts_utc_ms": base_ts - 60_000,
            "level": "info",
            "kind": "lease.hit",
            "request_id": "11223344-5566-4778-899a-bbccddeeff00",
            "operation": "github.list_secrets",
            "safety": "Safe",
            "outcome": "ok",
            "detail": "reused existing approval lease"
        }),
        json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "sequence_number": 1,
            "ts_utc_ms": base_ts - 120_000,
            "level": "info",
            "kind": "operation.succeeded",
            "request_id": "aabbccdd-1122-4334-8556-778899001122",
            "operation": "gitlab.set_ci_variable",
            "safety": "Safe",
            "outcome": "ok",
            "latency_ms": 567,
            "secret_names": "DEPLOY_TOKEN",
            "detail": "project=infra/deploy key=DEPLOY_TOKEN",
            "target_json": "{\"project\":\"infra/deploy\"}"
        }),
        json!({
            "event_id": uuid::Uuid::new_v4().to_string(),
            "sequence_number": 0,
            "ts_utc_ms": base_ts - 300_000,
            "level": "error",
            "kind": "operation.failed",
            "request_id": "deadbeef-cafe-4bab-8ead-facade123456",
            "operation": "onepassword.list_vaults",
            "safety": "Safe",
            "outcome": "error",
            "latency_ms": 5012,
            "detail": "1Password CLI not found"
        }),
    ]
}

/// Generate sample policy rules for demo mode.
pub fn demo_policy_rules() -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "allow-github-safe",
            "operation_pattern": "github.*",
            "allow": true,
            "client_types": ["human", "agent"],
            "approval": {
                "require": "first_use",
                "factors": ["local_bio"],
                "lease_ttl": 300
            }
        }),
        json!({
            "name": "allow-gitlab-ci",
            "operation_pattern": "gitlab.set_ci_variable",
            "allow": true,
            "client_types": ["human", "agent"],
            "approval": {
                "require": "always",
                "factors": ["local_bio"]
            }
        }),
        json!({
            "name": "allow-1password-browse",
            "operation_pattern": "onepassword.list_*",
            "allow": true,
            "client_types": ["human", "agent"],
            "approval": {
                "require": "first_use",
                "factors": ["local_bio"],
                "lease_ttl": 600
            }
        }),
        json!({
            "name": "deny-sandbox-agents",
            "operation_pattern": "sandbox.exec",
            "allow": false,
            "client_types": ["agent"]
        }),
        json!({
            "name": "allow-sandbox-humans",
            "operation_pattern": "sandbox.exec",
            "allow": true,
            "client_types": ["human"],
            "approval": {
                "require": "always",
                "factors": ["local_bio"]
            }
        }),
    ]
}

/// Generate sample agent sessions for demo mode.
pub fn demo_sessions() -> Vec<serde_json::Value> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    vec![
        json!({
            "session_id": "sess_a1b2c3d4",
            "label": "claude-code-main",
            "expires_at_utc_ms": now_ms + 1_800_000,
            "ttl_remaining_secs": 1800
        }),
        json!({
            "session_id": "sess_e5f6a7b8",
            "label": "ci-deploy-runner",
            "expires_at_utc_ms": now_ms + 600_000,
            "ttl_remaining_secs": 600
        }),
        json!({
            "session_id": "sess_c9d0e1f2",
            "label": "cursor-workspace",
            "expires_at_utc_ms": now_ms + 3_200_000,
            "ttl_remaining_secs": 3200
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_audit_events_non_empty() {
        let events = demo_audit_events();
        assert!(!events.is_empty());
        for event in &events {
            assert!(event.get("event_id").is_some());
            assert!(event.get("kind").is_some());
            assert!(event.get("ts_utc_ms").is_some());
        }
    }

    #[test]
    fn demo_audit_events_descending_sequence() {
        let events = demo_audit_events();
        let seqs: Vec<i64> = events
            .iter()
            .map(|e| e["sequence_number"].as_i64().unwrap())
            .collect();
        for i in 1..seqs.len() {
            assert!(
                seqs[i - 1] > seqs[i],
                "events should be in descending sequence order"
            );
        }
    }

    #[test]
    fn demo_policy_rules_non_empty() {
        let rules = demo_policy_rules();
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(rule.get("name").is_some());
            assert!(rule.get("operation_pattern").is_some());
        }
    }

    #[test]
    fn demo_sessions_non_empty() {
        let sessions = demo_sessions();
        assert!(!sessions.is_empty());
        for session in &sessions {
            assert!(session.get("session_id").is_some());
            assert!(session.get("ttl_remaining_secs").is_some());
        }
    }

    #[test]
    fn demo_sessions_have_positive_ttl() {
        let sessions = demo_sessions();
        for session in &sessions {
            let ttl = session["ttl_remaining_secs"].as_i64().unwrap();
            assert!(ttl > 0);
        }
    }
}
