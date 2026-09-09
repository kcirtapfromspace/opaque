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

pub struct ResolvedPaths {
    pub data_dir: PathBuf,
    pub config: PathBuf,
    pub audit_db: PathBuf,
    pub socket: PathBuf,
}

pub fn resolve_paths(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    socket: Option<PathBuf>,
) -> ResolvedPaths {
    let isolated = data_dir.is_some();
    let data_dir = data_dir.unwrap_or_else(opaque_home);
    let config = config.unwrap_or_else(|| {
        if isolated {
            data_dir.join("config.toml")
        } else {
            config_path()
        }
    });
    let socket = socket.unwrap_or_else(|| {
        if isolated {
            data_dir
                .join("run")
                .join(opaque_core::socket::DEFAULT_SOCKET_FILENAME)
        } else {
            opaque_core::socket::socket_path()
        }
    });
    ResolvedPaths {
        audit_db: data_dir.join("audit.db"),
        data_dir,
        config,
        socket,
    }
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

/// Load the selected file without hiding read or parse failures.
pub fn load_web_config(path: &Path) -> Result<WebConfig, String> {
    let contents = std::fs::read_to_string(path).map_err(|e| format!("Cannot read config: {e}"))?;
    toml_edit::de::from_str(&contents)
        .map_err(|_| "Cannot parse the selected policy config. Check its TOML syntax.".to_string())
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

        let db = resolve_paths(None, None, None).audit_db;
        assert!(db.ends_with("audit.db"));
    }

    #[test]
    fn load_missing_config_returns_error() {
        let result = load_web_config(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_err());
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
