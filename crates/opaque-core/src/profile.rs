//! Execution profile types for sandboxed command execution.
//!
//! Profiles define the sandbox parameters: project directory, network access,
//! secret references, environment variables, and resource limits.
//!
//! Profile files live at `~/.opaque/profiles/<name>.toml` and are loaded
//! by the daemon when processing `sandbox.exec` requests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Profile types
// ---------------------------------------------------------------------------

/// An execution profile that defines sandbox parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecProfile {
    /// Profile name (must match the filename without `.toml`).
    pub name: String,

    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Project directory to bind-mount read-only inside the sandbox.
    pub project_dir: PathBuf,

    /// Additional paths to bind-mount read-only.
    #[serde(default)]
    pub extra_read_paths: Vec<PathBuf>,

    /// Network access configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Secret environment variables: `ENV_NAME -> secret_ref`.
    /// Secret refs use schemes like `env:NAME` or `keychain:service/account`.
    #[serde(default)]
    pub secrets: HashMap<String, String>,

    /// Literal (non-secret) environment variables: `ENV_NAME -> value`.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Resource limits for the sandbox.
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Network access configuration for a sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Allowed egress destinations as `"host:port"` entries.
    /// Empty means no network access (safest default).
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Resource limits for a sandboxed execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum execution time in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Maximum output size in bytes. Default: 10 MB.
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
}

fn default_timeout_secs() -> u64 {
    3600
}

fn default_max_output_bytes() -> usize {
    10 * 1024 * 1024 // 10 MB
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
            max_output_bytes: default_max_output_bytes(),
        }
    }
}

// ---------------------------------------------------------------------------
// Profile TOML wrapper (for deserialization from file)
// ---------------------------------------------------------------------------

/// Wrapper for deserializing a profile from TOML.
///
/// The TOML file format uses `[profile]` as the top-level table:
/// ```toml
/// [profile]
/// name = "dev"
/// project_dir = "/home/user/myproject"
///
/// [secrets]
/// GITHUB_TOKEN = "keychain:opaque/github-token"
///
/// [env]
/// RUST_LOG = "info"
///
/// [network]
/// allow = []
///
/// [limits]
/// timeout_secs = 3600
/// ```
#[derive(Debug, Clone, Deserialize)]
struct ProfileToml {
    profile: ProfileSection,
    #[serde(default)]
    secrets: HashMap<String, String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default)]
    limits: LimitsConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct ProfileSection {
    name: String,
    #[serde(default)]
    description: Option<String>,
    project_dir: PathBuf,
    #[serde(default)]
    extra_read_paths: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Errors from profile validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProfileError {
    #[error("TOML parse error: {0}")]
    ParseError(String),

    #[error("profile name mismatch: file says '{file_name}', expected '{expected}'")]
    NameMismatch { file_name: String, expected: String },

    #[error("path traversal detected in {field}: {path}")]
    PathTraversal { field: String, path: String },

    #[error("invalid secret ref scheme in '{name}': {ref_str} (expected env: or keychain:)")]
    InvalidSecretRef { name: String, ref_str: String },

    #[error("empty profile name")]
    EmptyName,

    #[error("empty project_dir")]
    EmptyProjectDir,

    #[error("secret env name '{0}' contains invalid characters (expected [A-Za-z0-9_])")]
    InvalidSecretEnvName(String),

    #[error("env name '{0}' contains invalid characters (expected [A-Za-z0-9_])")]
    InvalidEnvName(String),

    #[error("timeout_secs must be > 0")]
    ZeroTimeout,

    #[error("max_output_bytes must be > 0")]
    ZeroMaxOutput,
}

/// Allowed secret ref scheme prefixes.
///
/// This is the single canonical list of supported secret ref schemes.
/// All validation code (profile loader, GitHub handler, daemon method handlers)
/// must reference this constant instead of defining local copies.
pub const ALLOWED_REF_SCHEMES: &[&str] = &["env:", "keychain:", "profile:", "onepassword:"];

/// Load and validate an `ExecProfile` from a TOML string.
///
/// If `expected_name` is provided, the profile's `name` field must match.
pub fn load_profile(
    toml_str: &str,
    expected_name: Option<&str>,
) -> Result<ExecProfile, ProfileError> {
    let parsed: ProfileToml =
        toml_edit::de::from_str(toml_str).map_err(|e| ProfileError::ParseError(e.to_string()))?;

    let profile = ExecProfile {
        name: parsed.profile.name,
        description: parsed.profile.description,
        project_dir: parsed.profile.project_dir,
        extra_read_paths: parsed.profile.extra_read_paths,
        network: parsed.network,
        secrets: parsed.secrets,
        env: parsed.env,
        limits: parsed.limits,
    };

    validate_profile(&profile, expected_name)?;
    Ok(profile)
}

/// Validate an `ExecProfile` for correctness and safety.
pub fn validate_profile(
    profile: &ExecProfile,
    expected_name: Option<&str>,
) -> Result<(), ProfileError> {
    // Name must be non-empty.
    if profile.name.is_empty() {
        return Err(ProfileError::EmptyName);
    }

    // Name must match expected (if provided).
    if let Some(expected) = expected_name
        && profile.name != expected
    {
        return Err(ProfileError::NameMismatch {
            file_name: profile.name.clone(),
            expected: expected.to_owned(),
        });
    }

    // Validate profile name characters: [a-zA-Z0-9_-]
    if !profile
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ProfileError::EmptyName);
    }

    // Project dir must be non-empty.
    if profile.project_dir.as_os_str().is_empty() {
        return Err(ProfileError::EmptyProjectDir);
    }

    // Check for path traversal in project_dir.
    check_path_traversal("project_dir", &profile.project_dir)?;

    // Check for path traversal in extra_read_paths.
    for (i, path) in profile.extra_read_paths.iter().enumerate() {
        check_path_traversal(&format!("extra_read_paths[{i}]"), path)?;
    }

    // Validate secret refs.
    for (name, ref_str) in &profile.secrets {
        // Env name must be valid.
        if !is_valid_env_name(name) {
            return Err(ProfileError::InvalidSecretEnvName(name.clone()));
        }

        // Ref must use an allowed scheme.
        if !ALLOWED_REF_SCHEMES.iter().any(|s| ref_str.starts_with(s)) {
            return Err(ProfileError::InvalidSecretRef {
                name: name.clone(),
                ref_str: ref_str.clone(),
            });
        }
    }

    // Validate env names.
    for name in profile.env.keys() {
        if !is_valid_env_name(name) {
            return Err(ProfileError::InvalidEnvName(name.clone()));
        }
    }

    // Validate limits.
    if profile.limits.timeout_secs == 0 {
        return Err(ProfileError::ZeroTimeout);
    }
    if profile.limits.max_output_bytes == 0 {
        return Err(ProfileError::ZeroMaxOutput);
    }

    Ok(())
}

/// Check if a path contains traversal components (`..`).
fn check_path_traversal(field: &str, path: &Path) -> Result<(), ProfileError> {
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(ProfileError::PathTraversal {
                field: field.to_owned(),
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

/// Check if a string is a valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_env_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Return the default profiles directory: `~/.opaque/profiles/`.
pub fn profiles_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".opaque").join("profiles")
}

/// Load a named profile from `~/.opaque/profiles/<name>.toml`.
pub fn load_named_profile(name: &str) -> Result<ExecProfile, ProfileError> {
    // Validate the name to prevent path traversal via the profile name itself.
    if name.is_empty() {
        return Err(ProfileError::EmptyName);
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ProfileError::EmptyName);
    }

    let path = profiles_dir().join(format!("{name}.toml"));
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| ProfileError::ParseError(format!("failed to read {}: {e}", path.display())))?;

    load_profile(&contents, Some(name))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOML: &str = r#"
[profile]
name = "dev"
description = "Development sandbox"
project_dir = "/home/user/src/myproject"
extra_read_paths = ["/usr/share/nodejs"]

[network]
allow = ["registry.npmjs.org:443"]

[secrets]
GITHUB_TOKEN = "keychain:opaque/github-token"
DB_PASSWORD = "env:DB_PASSWORD"

[env]
RUST_LOG = "info"
NODE_ENV = "development"

[limits]
timeout_secs = 1800
max_output_bytes = 5242880
"#;

    #[test]
    fn valid_profile_roundtrip() {
        let profile = load_profile(VALID_TOML, Some("dev")).unwrap();
        assert_eq!(profile.name, "dev");
        assert_eq!(profile.description.as_deref(), Some("Development sandbox"));
        assert_eq!(
            profile.project_dir,
            PathBuf::from("/home/user/src/myproject")
        );
        assert_eq!(profile.extra_read_paths.len(), 1);
        assert_eq!(profile.network.allow.len(), 1);
        assert_eq!(profile.secrets.len(), 2);
        assert_eq!(profile.env.len(), 2);
        assert_eq!(profile.limits.timeout_secs, 1800);
        assert_eq!(profile.limits.max_output_bytes, 5_242_880);
    }

    #[test]
    fn minimal_profile() {
        let toml = r#"
[profile]
name = "minimal"
project_dir = "/tmp/project"
"#;
        let profile = load_profile(toml, Some("minimal")).unwrap();
        assert_eq!(profile.name, "minimal");
        assert!(profile.description.is_none());
        assert!(profile.secrets.is_empty());
        assert!(profile.env.is_empty());
        assert!(profile.network.allow.is_empty());
        assert_eq!(profile.limits.timeout_secs, 3600);
        assert_eq!(profile.limits.max_output_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn name_mismatch_rejected() {
        let result = load_profile(VALID_TOML, Some("wrong-name"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProfileError::NameMismatch { .. }),
            "expected NameMismatch, got: {err}"
        );
    }

    #[test]
    fn empty_name_rejected() {
        let toml = r#"
[profile]
name = ""
project_dir = "/tmp"
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
    }

    #[test]
    fn path_traversal_project_dir() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/home/user/../../../etc"
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProfileError::PathTraversal { .. }),
            "expected PathTraversal, got: {err}"
        );
    }

    #[test]
    fn path_traversal_extra_read_paths() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/tmp"
extra_read_paths = ["/tmp/../etc/shadow"]
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProfileError::PathTraversal { .. }),
            "expected PathTraversal, got: {err}"
        );
    }

    #[test]
    fn invalid_secret_ref_scheme() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/tmp"

[secrets]
TOKEN = "literal:supersecret"
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProfileError::InvalidSecretRef { .. }),
            "expected InvalidSecretRef, got: {err}"
        );
    }

    #[test]
    fn unknown_ref_scheme_rejected() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/tmp"

[secrets]
TOKEN = "vault:secret/data/myapp"
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProfileError::InvalidSecretRef { .. }),
            "expected InvalidSecretRef, got: {err}"
        );
    }

    #[test]
    fn valid_env_ref() {
        let toml = r#"
[profile]
name = "env-test"
project_dir = "/tmp"

[secrets]
MY_SECRET = "env:SOME_VAR"
"#;
        let profile = load_profile(toml, None).unwrap();
        assert_eq!(profile.secrets["MY_SECRET"], "env:SOME_VAR");
    }

    #[test]
    fn valid_keychain_ref() {
        let toml = r#"
[profile]
name = "kc-test"
project_dir = "/tmp"

[secrets]
TOKEN = "keychain:opaque/my-token"
"#;
        let profile = load_profile(toml, None).unwrap();
        assert_eq!(profile.secrets["TOKEN"], "keychain:opaque/my-token");
    }

    #[test]
    fn invalid_secret_env_name() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/tmp"

[secrets]
"my-secret" = "env:FOO"
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProfileError::InvalidSecretEnvName(_)),
            "expected InvalidSecretEnvName, got: {err}"
        );
    }

    #[test]
    fn invalid_env_name() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/tmp"

[env]
"my-env" = "value"
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProfileError::InvalidEnvName(_)),
            "expected InvalidEnvName, got: {err}"
        );
    }

    #[test]
    fn zero_timeout_rejected() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/tmp"

[limits]
timeout_secs = 0
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
    }

    #[test]
    fn zero_max_output_rejected() {
        let toml = r#"
[profile]
name = "bad"
project_dir = "/tmp"

[limits]
max_output_bytes = 0
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
    }

    #[test]
    fn missing_required_fields() {
        let toml = r#"
[profile]
name = "bad"
"#;
        let result = load_profile(toml, None);
        assert!(result.is_err());
    }

    #[test]
    fn default_limits() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.timeout_secs, 3600);
        assert_eq!(limits.max_output_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn is_valid_env_name_cases() {
        assert!(is_valid_env_name("FOO"));
        assert!(is_valid_env_name("_BAR"));
        assert!(is_valid_env_name("MY_VAR_123"));
        assert!(!is_valid_env_name(""));
        assert!(!is_valid_env_name("123"));
        assert!(!is_valid_env_name("my-var"));
        assert!(!is_valid_env_name("my.var"));
    }

    #[test]
    fn profile_error_display() {
        let err = ProfileError::EmptyName;
        assert_eq!(format!("{err}"), "empty profile name");

        let err = ProfileError::PathTraversal {
            field: "project_dir".into(),
            path: "/home/../etc".into(),
        };
        assert!(format!("{err}").contains("path traversal"));

        let err = ProfileError::InvalidSecretRef {
            name: "TOKEN".into(),
            ref_str: "literal:foo".into(),
        };
        assert!(format!("{err}").contains("invalid secret ref scheme"));
    }

    #[test]
    fn network_config_default() {
        let config = NetworkConfig::default();
        assert!(config.allow.is_empty());
    }
}
