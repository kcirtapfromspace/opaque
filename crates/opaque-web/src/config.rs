use std::path::{Path, PathBuf};

use opaque_core::policy::PolicyRule;
use serde::Deserialize;

/// Resolve the opaque home directory (`~/.opaque`).
pub fn opaque_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".opaque")
}

/// Resolve the config path: `$OPAQUE_CONFIG` or `~/.opaque/config.toml`.
pub fn config_path() -> PathBuf {
    std::env::var("OPAQUE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| opaque_home().join("config.toml"))
}

/// Resolve the audit database path: `~/.opaque/audit.db`.
pub fn audit_db_path() -> PathBuf {
    opaque_home().join("audit.db")
}

/// Minimal config struct matching the daemon's `config.toml` format.
#[derive(Debug, Deserialize, Default)]
pub struct WebConfig {
    #[serde(default)]
    pub rules: Vec<PolicyRule>,

    #[serde(default)]
    pub enforce_agent_sessions: bool,

    #[serde(default)]
    pub agent_session_ttl_secs: Option<u64>,
}

/// Load and parse the config file. Returns `None` if the file doesn't exist
/// or fails to parse.
pub fn load_web_config(path: &Path) -> Option<WebConfig> {
    let contents = std::fs::read_to_string(path).ok()?;
    toml_edit::de::from_str(&contents).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_under_opaque_home() {
        let home = opaque_home();
        assert!(home.ends_with(".opaque"));

        let cfg = config_path();
        assert!(cfg.ends_with("config.toml"));

        let db = audit_db_path();
        assert!(db.ends_with("audit.db"));
    }

    #[test]
    fn load_missing_config_returns_none() {
        let result = load_web_config(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_none());
    }

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
enforce_agent_sessions = true
agent_session_ttl_secs = 3600

[[rules]]
name = "allow-all"
operation_pattern = "*"
allow = true
"#;
        let config: WebConfig = toml_edit::de::from_str(toml).unwrap();
        assert!(config.enforce_agent_sessions);
        assert_eq!(config.agent_session_ttl_secs, Some(3600));
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "allow-all");
    }

    #[test]
    fn parse_empty_config() {
        let config: WebConfig = toml_edit::de::from_str("").unwrap();
        assert!(!config.enforce_agent_sessions);
        assert!(config.rules.is_empty());
    }
}
