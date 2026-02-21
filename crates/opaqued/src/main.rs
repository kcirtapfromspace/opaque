use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use opaque_core::audit::{MultiAuditSink, SqliteAuditSink, TracingAuditEmitter};
use opaque_core::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationDef,
    OperationRegistry, OperationRequest, OperationSafety,
};
use opaque_core::peer::peer_info_from_fd;
use opaque_core::policy::{PolicyEngine, PolicyRule};
use opaque_core::proto::{Request, Response};
use opaque_core::socket::{ensure_socket_parent_dir, socket_path_for_client, validate_path_chain};
use opaque_core::validate::InputValidator;
use serde::Deserialize;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, warn};
use uuid::Uuid;

/// Name of the daemon token file written next to the socket.
const DAEMON_TOKEN_FILENAME: &str = "daemon.token";

mod approval;
mod bitwarden;
mod enclave;
mod github;
mod gitlab;
mod onepassword;
mod sandbox;
pub mod secret;

use std::future::Future;
use std::pin::Pin;

use enclave::{Enclave, NativeApprovalGate, OperationHandler};

// ---------------------------------------------------------------------------
// Daemon configuration
// ---------------------------------------------------------------------------

/// Daemon configuration loaded from `~/.opaque/config.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
struct DaemonConfig {
    /// Known human client executables. If a connecting client matches any
    /// entry, it is classified as `Human`; otherwise it defaults to `Agent`.
    #[serde(default)]
    known_human_clients: Vec<HumanClientEntry>,

    /// Policy rules loaded from config. Deny-all default when empty.
    #[serde(default)]
    rules: Vec<PolicyRule>,

    /// Audit log retention in days. Defaults to 90 if not specified.
    #[serde(default)]
    audit_retention_days: Option<u64>,

    /// When true, clients classified as `Agent` must present a valid
    /// per-session token in the handshake.
    #[serde(default)]
    enforce_agent_sessions: bool,

    /// Default TTL for agent sessions in seconds.
    #[serde(default)]
    agent_session_ttl_secs: Option<u64>,
}

/// A single entry in the known human clients allowlist.
#[derive(Debug, Clone, Deserialize)]
struct HumanClientEntry {
    /// Human-readable label (for logging).
    name: String,

    /// Glob pattern matched against the exe path.
    exe_path: Option<String>,

    /// Exact SHA-256 hex digest of the executable (case-insensitive).
    exe_sha256: Option<String>,

    /// Exact macOS code-signing Team ID.
    codesign_team_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

/// Build a version string that includes the git SHA: `0.1.0+abc1234`.
const fn version_string() -> &'static str {
    concat!(env!("CARGO_PKG_VERSION"), "+", env!("OPAQUE_GIT_SHA"))
}

struct DaemonState {
    enclave: Arc<Enclave>,
    config: DaemonConfig,
    version: &'static str,
    /// Hex-encoded 32-byte CSPRNG token for handshake authentication.
    daemon_token: String,
    /// Active wrapper sessions keyed by session id.
    agent_sessions: Arc<tokio::sync::RwLock<HashMap<String, AgentSession>>>,
    /// Semaphore to limit maximum concurrent connections.
    connection_semaphore: Arc<tokio::sync::Semaphore>,
}

#[derive(Debug, Clone)]
struct AgentSession {
    session_id: String,
    token: String,
    created_by_uid: u32,
    expires_at: SystemTime,
    label: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    init_tracing();

    // Daemon never trusts OPAQUE_SOCK env var.
    let path = socket_path_for_client(false);
    if let Err(e) = run(path).await {
        eprintln!("opaqued: {e}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Load daemon config from `~/.opaque/config.toml` or `$OPAQUE_CONFIG`.
fn load_config() -> DaemonConfig {
    let path = std::env::var("OPAQUE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".opaque").join("config.toml")
        });

    match std::fs::read_to_string(&path) {
        Ok(contents) => match toml_edit::de::from_str::<DaemonConfig>(&contents) {
            Ok(mut config) => {
                // Filter out empty human client entries that would match everything.
                let before = config.known_human_clients.len();
                config.known_human_clients.retain(|entry| {
                    let has_criteria = entry.exe_path.is_some()
                        || entry.exe_sha256.is_some()
                        || entry.codesign_team_id.is_some();
                    if !has_criteria {
                        warn!(
                            "ignoring known_human_clients entry '{}': no matching criteria specified",
                            entry.name
                        );
                    }
                    has_criteria
                });
                let filtered = before - config.known_human_clients.len();
                if filtered > 0 {
                    warn!("{filtered} empty human client entries removed from config");
                }
                info!(
                    "loaded config from {} ({} known human clients, {} policy rules)",
                    path.display(),
                    config.known_human_clients.len(),
                    config.rules.len(),
                );
                config
            }
            Err(e) => {
                warn!("failed to parse config {}: {e}", path.display());
                DaemonConfig::default()
            }
        },
        Err(_) => {
            info!("no config file at {}, using defaults", path.display());
            DaemonConfig::default()
        }
    }
}

/// Verify the config seal on daemon startup.
///
/// - **Verified**: config matches seal — proceed normally.
/// - **Unsealed**: no seal found — warn and continue (backward compatible).
/// - **Tampered**: seal exists but doesn't match — hard stop.
fn verify_config_seal() -> std::io::Result<()> {
    use opaque_core::seal::{self, SealStatus};

    let config_path = std::env::var("OPAQUE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".opaque").join("config.toml")
        });

    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let seal_file = config_dir.join("config.seal");

    // If config doesn't exist, nothing to verify (load_config handles defaults).
    if !config_path.exists() {
        return Ok(());
    }

    let config_bytes = std::fs::read(&config_path)?;

    match seal::verify_seal(&config_bytes, &seal_file) {
        Ok(SealStatus::Verified) => {
            info!("config seal verified");
        }
        Ok(SealStatus::Unsealed) => {
            warn!("config is unsealed — run 'opaque setup --seal' to protect it");
        }
        Ok(SealStatus::Tampered { .. }) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "config seal broken — config.toml was modified after sealing. \
                 Run 'opaque setup --reset' to unseal, then reconfigure.",
            ));
        }
        Err(e) => {
            return Err(std::io::Error::other(format!(
                "config seal check failed: {e}"
            )));
        }
    }

    Ok(())
}

/// Generate a 32-byte CSPRNG hex token for daemon authentication.
fn generate_daemon_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("failed to generate random bytes");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write the daemon token to `<socket_dir>/daemon.token` with mode 0600.
fn write_daemon_token(socket: &Path, token: &str) -> std::io::Result<PathBuf> {
    let token_path = socket
        .parent()
        .expect("socket path should have a parent directory")
        .join(DAEMON_TOKEN_FILENAME);
    std::fs::write(&token_path, token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(token_path)
}

/// Minimal no-op operation handler for end-to-end testing of the enclave pipeline.
#[derive(Debug)]
struct NoopHandler;

impl OperationHandler for NoopHandler {
    fn execute(
        &self,
        _request: &OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + '_>> {
        Box::pin(async { Ok(serde_json::json!({"status": "ok"})) })
    }
}

/// Disable core dumps to prevent secret material from being written to disk.
///
/// Called early in daemon startup, before any secrets are loaded.
fn init_memory_safety() {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if ret == 0 {
            info!("core dumps disabled (PR_SET_DUMPABLE=0)");
        } else {
            warn!("failed to disable core dumps via PR_SET_DUMPABLE");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if ret == 0 {
            info!("core dumps disabled (RLIMIT_CORE=0)");
        } else {
            warn!("failed to disable core dumps via RLIMIT_CORE");
        }
    }
}

async fn run(socket: PathBuf) -> std::io::Result<()> {
    init_memory_safety();
    ensure_socket_parent_dir(&socket)?;

    // Acquire PID file lock before anything else.
    let pid_path = socket
        .parent()
        .expect("socket path should have a parent directory")
        .join("opaqued.pid");
    let _pid_guard = PidFileGuard::acquire(pid_path)?;

    if socket.exists() {
        match UnixStream::connect(&socket).await {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("socket already in use: {}", socket.display()),
                ));
            }
            Err(_) => {
                // Stale socket file.
                tokio::fs::remove_file(&socket).await?;
            }
        }
    }

    // Validate no symlinks in the path chain before binding.
    validate_path_chain(&socket)?;

    let listener = UnixListener::bind(&socket)?;
    lock_down_socket_path(&socket)?;
    let _socket_guard = SocketGuard::new(socket.clone());

    // Generate and write daemon token for handshake authentication.
    let daemon_token = generate_daemon_token();
    let token_path = write_daemon_token(&socket, &daemon_token)?;
    info!("daemon token written to {}", token_path.display());

    info!("listening on {}", socket.display());

    let config = load_config();

    // Verify config seal before proceeding.
    verify_config_seal()?;

    // Build enclave with registered operations and policy from config.
    let mut registry = OperationRegistry::new();
    registry
        .register(OperationDef {
            name: "test.noop".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "No-op test operation".into(),
            params_schema: None,
            allowed_target_keys: vec![],
            secret_ref_param_keys: vec![],
        })
        .expect("failed to register test.noop");

    registry
        .register(OperationDef {
            name: "sandbox.exec".into(),
            safety: OperationSafety::SensitiveOutput,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Execute a command in a sandboxed environment".into(),
            params_schema: None,
            allowed_target_keys: vec!["profile".into(), "command".into()],
            secret_ref_param_keys: vec!["profile".into()],
        })
        .expect("failed to register sandbox.exec");

    registry
        .register(OperationDef {
            name: "github.set_actions_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Actions repository secret".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["repo", "secret_name", "value_ref"],
                "properties": {
                    "repo": {"type": "string"},
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "github_token_ref": {"type": "string"},
                    "environment": {"type": "string"}
                }
            })),
            allowed_target_keys: vec!["repo".into()],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .expect("failed to register github.set_actions_secret");

    registry
        .register(OperationDef {
            name: "github.set_codespaces_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Codespaces secret (user or repo level)".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_name", "value_ref"],
                "properties": {
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "repo": {"type": "string"},
                    "github_token_ref": {"type": "string"},
                    "selected_repository_ids": {"type": "array", "items": {"type": "integer"}}
                }
            })),
            allowed_target_keys: vec!["repo".into()],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .expect("failed to register github.set_codespaces_secret");

    registry
        .register(OperationDef {
            name: "github.set_dependabot_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Dependabot repository secret".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["repo", "secret_name", "value_ref"],
                "properties": {
                    "repo": {"type": "string"},
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "github_token_ref": {"type": "string"}
                }
            })),
            allowed_target_keys: vec!["repo".into()],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .expect("failed to register github.set_dependabot_secret");

    registry
        .register(OperationDef {
            name: "github.set_org_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Actions organization secret".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["org", "secret_name", "value_ref"],
                "properties": {
                    "org": {"type": "string"},
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "github_token_ref": {"type": "string"},
                    "visibility": {"type": "string", "enum": ["all", "private", "selected"]},
                    "selected_repository_ids": {"type": "array", "items": {"type": "integer"}}
                }
            })),
            allowed_target_keys: vec!["org".into()],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .expect("failed to register github.set_org_secret");

    registry
        .register(OperationDef {
            name: "github.list_secrets".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List GitHub secret names for a repository, environment, or org".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["actions", "codespaces", "dependabot", "org"]},
                    "repo": {"type": "string"},
                    "org": {"type": "string"},
                    "environment": {"type": "string"},
                    "github_token_ref": {"type": "string"}
                }
            })),
            allowed_target_keys: vec!["repo".into(), "org".into()],
            secret_ref_param_keys: vec!["github_token_ref".into()],
        })
        .expect("failed to register github.list_secrets");

    registry
        .register(OperationDef {
            name: "github.delete_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Delete a GitHub secret from a repository, environment, or org".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_name"],
                "properties": {
                    "scope": {"type": "string", "enum": ["actions", "codespaces", "dependabot", "org"]},
                    "secret_name": {"type": "string"},
                    "repo": {"type": "string"},
                    "org": {"type": "string"},
                    "environment": {"type": "string"},
                    "github_token_ref": {"type": "string"}
                }
            })),
            allowed_target_keys: vec!["repo".into(), "org".into()],
            secret_ref_param_keys: vec!["github_token_ref".into()],
        })
        .expect("failed to register github.delete_secret");

    registry
        .register(OperationDef {
            name: "gitlab.set_ci_variable".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitLab CI/CD variable for a project".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["project", "key", "value_ref"],
                "properties": {
                    "project": {"type": "string"},
                    "key": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "gitlab_token_ref": {"type": "string"},
                    "environment_scope": {"type": "string"},
                    "protected": {"type": "boolean"},
                    "masked": {"type": "boolean"},
                    "raw": {"type": "boolean"},
                    "variable_type": {"type": "string", "enum": ["env_var", "file"]}
                }
            })),
            allowed_target_keys: vec!["project".into(), "key".into()],
            secret_ref_param_keys: vec!["value_ref".into(), "gitlab_token_ref".into()],
        })
        .expect("failed to register gitlab.set_ci_variable");

    registry
        .register(OperationDef {
            name: "onepassword.list_vaults".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List available 1Password vaults".into(),
            params_schema: None,
            allowed_target_keys: vec![],
            secret_ref_param_keys: vec![],
        })
        .expect("failed to register onepassword.list_vaults");

    registry
        .register(OperationDef {
            name: "onepassword.read_field".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Read a single field value from a 1Password item".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["vault", "item", "field"],
                "properties": {
                    "vault": {"type": "string"},
                    "item": {"type": "string"},
                    "field": {"type": "string"}
                }
            })),
            allowed_target_keys: vec!["vault".into(), "item".into()],
            secret_ref_param_keys: vec!["onepassword:{vault}/{item}/{field}".into()],
        })
        .expect("failed to register onepassword.read_field");

    registry
        .register(OperationDef {
            name: "onepassword.list_items".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List items in a 1Password vault".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["vault"],
                "properties": { "vault": {"type": "string"} }
            })),
            allowed_target_keys: vec!["vault".into()],
            secret_ref_param_keys: vec![],
        })
        .expect("failed to register onepassword.list_items");

    registry
        .register(OperationDef {
            name: "bitwarden.list_projects".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List available Bitwarden Secrets Manager projects".into(),
            params_schema: None,
            allowed_target_keys: vec![],
            secret_ref_param_keys: vec![],
        })
        .expect("failed to register bitwarden.list_projects");

    registry
        .register(OperationDef {
            name: "bitwarden.list_secrets".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List secrets in a Bitwarden Secrets Manager project".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "project": {"type": "string"} }
            })),
            allowed_target_keys: vec!["project".into()],
            secret_ref_param_keys: vec![],
        })
        .expect("failed to register bitwarden.list_secrets");

    registry
        .register(OperationDef {
            name: "bitwarden.read_secret".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Read a secret value from Bitwarden Secrets Manager".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_id"],
                "properties": { "secret_id": {"type": "string"} }
            })),
            allowed_target_keys: vec!["secret_id".into()],
            secret_ref_param_keys: vec!["secret_id".into()],
        })
        .expect("failed to register bitwarden.read_secret");

    let policy = PolicyEngine::with_rules(config.rules.clone());
    info!("policy engine loaded with {} rules", policy.rule_count());

    let tracing_sink = Arc::new(TracingAuditEmitter::new());
    let audit_db_path = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".opaque")
        .join("audit.db");
    let retention_days = config.audit_retention_days.unwrap_or(90);
    let sqlite_sink = Arc::new(
        SqliteAuditSink::new(audit_db_path.clone(), retention_days)
            .expect("failed to open audit database"),
    );
    info!(
        "audit database at {} (retention: {} days)",
        audit_db_path.display(),
        retention_days
    );
    let audit = Arc::new(MultiAuditSink::new(vec![tracing_sink, sqlite_sink]));

    let sandbox_executor = sandbox::SandboxExecutor::new(audit.clone());
    let github_actions_handler = github::GitHubHandler::new(audit.clone());
    let github_codespaces_handler = github::GitHubHandler::new(audit.clone());
    let github_dependabot_handler = github::GitHubHandler::new(audit.clone());
    let github_org_handler = github::GitHubHandler::new(audit.clone());
    let github_list_handler = github::GitHubHandler::new(audit.clone());
    let github_delete_handler = github::GitHubHandler::new(audit.clone());
    let gitlab_handler = gitlab::GitLabHandler::new(audit.clone());

    // 1Password handler: prefer Connect Server URL, fall back to `op` CLI.
    let onepassword_connect_url =
        std::env::var(onepassword::client::CONNECT_URL_ENV).unwrap_or_default();

    let mut enclave_builder = Enclave::builder()
        .registry(registry)
        .policy(policy)
        .handler("test.noop", Box::new(NoopHandler))
        .handler("sandbox.exec", Box::new(sandbox_executor))
        .handler(
            "github.set_actions_secret",
            Box::new(github_actions_handler),
        )
        .handler(
            "github.set_codespaces_secret",
            Box::new(github_codespaces_handler),
        )
        .handler(
            "github.set_dependabot_secret",
            Box::new(github_dependabot_handler),
        )
        .handler("github.set_org_secret", Box::new(github_org_handler))
        .handler("github.list_secrets", Box::new(github_list_handler))
        .handler("github.delete_secret", Box::new(github_delete_handler))
        .handler("gitlab.set_ci_variable", Box::new(gitlab_handler));

    if !onepassword_connect_url.is_empty() {
        // Connect Server backend (self-hosted REST API).
        let op_list_vaults_handler =
            onepassword::OnePasswordHandler::new(audit.clone(), &onepassword_connect_url);
        let op_list_items_handler =
            onepassword::OnePasswordHandler::new(audit.clone(), &onepassword_connect_url);
        let op_read_field_handler =
            onepassword::OnePasswordHandler::new(audit.clone(), &onepassword_connect_url);
        enclave_builder = enclave_builder
            .handler("onepassword.list_vaults", Box::new(op_list_vaults_handler))
            .handler("onepassword.list_items", Box::new(op_list_items_handler))
            .handler("onepassword.read_field", Box::new(op_read_field_handler));
        info!(
            "1Password handler enabled via Connect Server ({})",
            onepassword_connect_url
        );
    } else if let Ok(cli) = onepassword::op_cli::OpCliClient::new() {
        // `op` CLI backend (desktop app + biometric auth).
        let op_list_vaults_handler =
            onepassword::OnePasswordHandler::from_cli(audit.clone(), cli.clone());
        let op_list_items_handler =
            onepassword::OnePasswordHandler::from_cli(audit.clone(), cli.clone());
        let op_read_field_handler = onepassword::OnePasswordHandler::from_cli(audit.clone(), cli);
        enclave_builder = enclave_builder
            .handler("onepassword.list_vaults", Box::new(op_list_vaults_handler))
            .handler("onepassword.list_items", Box::new(op_list_items_handler))
            .handler("onepassword.read_field", Box::new(op_read_field_handler));
        info!("1Password handler enabled via op CLI");
    } else {
        info!("1Password handler disabled (no Connect URL or op CLI found)");
    }

    // Bitwarden handler: use configured URL or default.
    let bitwarden_url = std::env::var(bitwarden::client::BITWARDEN_URL_ENV)
        .unwrap_or_else(|_| bitwarden::client::DEFAULT_BASE_URL.to_owned());
    {
        let bw_list_projects_handler =
            bitwarden::BitwardenHandler::new(audit.clone(), &bitwarden_url);
        let bw_list_secrets_handler =
            bitwarden::BitwardenHandler::new(audit.clone(), &bitwarden_url);
        let bw_read_secret_handler =
            bitwarden::BitwardenHandler::new(audit.clone(), &bitwarden_url);
        enclave_builder = enclave_builder
            .handler(
                "bitwarden.list_projects",
                Box::new(bw_list_projects_handler),
            )
            .handler("bitwarden.list_secrets", Box::new(bw_list_secrets_handler))
            .handler("bitwarden.read_secret", Box::new(bw_read_secret_handler));
        info!("Bitwarden handler enabled ({})", bitwarden_url);
    }

    let enclave = enclave_builder
        .approval_gate(Box::new(NativeApprovalGate))
        .audit(audit)
        .build();

    let state = Arc::new(DaemonState {
        enclave: Arc::new(enclave),
        config,
        version: version_string(),
        daemon_token,
        agent_sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        connection_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
    });

    // Shutdown coordination: watch channel + active connection counter.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let active_connections = Arc::new(AtomicUsize::new(0));

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested (ctrl-c)");
                break;
            }
            _ = sigterm.recv() => {
                info!("shutdown requested (sigterm)");
                break;
            }
            res = listener.accept() => {
                let (stream, _addr) = res?;
                let permit = match state.connection_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("max connections reached (64), rejecting");
                        drop(stream);
                        continue;
                    }
                };
                let state = state.clone();
                let conn_shutdown_rx = shutdown_rx.clone();
                let conn_counter = active_connections.clone();
                conn_counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_conn(state, stream, conn_shutdown_rx).await {
                        warn!("connection error: {e}");
                    }
                    conn_counter.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }

    // Graceful drain: signal all connections to stop accepting new requests.
    let _ = shutdown_tx.send(true);
    let drain_deadline = std::time::Duration::from_secs(5);
    info!("draining active connections (up to 5s)...");
    let drain_start = std::time::Instant::now();
    while active_connections.load(Ordering::SeqCst) > 0 && drain_start.elapsed() < drain_deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let remaining = active_connections.load(Ordering::SeqCst);
    if remaining > 0 {
        warn!("{remaining} connections still active after drain timeout");
    } else {
        info!("all connections drained");
    }

    Ok(())
}

fn lock_down_socket_path(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
}

impl SocketGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// PID file guard (advisory flock)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PidFileGuard {
    _file: std::fs::File, // Keep file open to hold flock
    path: PathBuf,
}

impl PidFileGuard {
    fn acquire(path: PathBuf) -> std::io::Result<Self> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        // Acquire exclusive advisory lock (non-blocking).
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "daemon already running (PID file locked)",
                ));
            }
        }
        write!(file, "{}", std::process::id())?;
        file.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { _file: file, path })
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Per-connection rate limiter
// ---------------------------------------------------------------------------

struct ConnectionRateLimiter {
    timestamps: std::collections::VecDeque<std::time::Instant>,
    burst: usize,
    sustained_per_sec: f64,
}

impl ConnectionRateLimiter {
    fn new(burst: usize, sustained_per_sec: f64) -> Self {
        Self {
            timestamps: std::collections::VecDeque::new(),
            burst,
            sustained_per_sec,
        }
    }

    fn check(&mut self) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(1);
        // Remove timestamps older than 1 second.
        while let Some(&front) = self.timestamps.front() {
            if now.duration_since(front) > window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
        // Check sustained rate (requests in last second).
        if self.timestamps.len() >= self.sustained_per_sec as usize {
            return false;
        }
        // Check burst.
        if self.timestamps.len() >= self.burst {
            return false;
        }
        self.timestamps.push_back(now);
        true
    }
}

// ---------------------------------------------------------------------------
// Client identity & type derivation
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of an executable file (hex-encoded).
fn compute_exe_hash(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&bytes);
    Some(format!("{hash:x}"))
}

/// Derive the client type from the client identity and daemon config.
///
/// The daemon NEVER trusts a self-declared `client_type` from request params.
/// Instead, it matches the verified peer identity against the configured
/// `known_human_clients` allowlist. If no entry matches, the client is
/// classified as `Agent` (safer — more restrictive).
fn derive_client_type(identity: &ClientIdentity, config: &DaemonConfig) -> ClientType {
    for entry in &config.known_human_clients {
        if entry_matches(identity, entry) {
            return ClientType::Human;
        }
    }
    ClientType::Agent
}

/// Check if a client identity matches a human client allowlist entry.
/// All specified fields must match; absent fields are treated as "any".
/// An entry with NO fields specified matches nothing — this prevents a
/// misconfigured empty entry from classifying every client as Human.
fn entry_matches(identity: &ClientIdentity, entry: &HumanClientEntry) -> bool {
    // Reject entries that specify no matching criteria at all.
    if entry.exe_path.is_none() && entry.exe_sha256.is_none() && entry.codesign_team_id.is_none() {
        return false;
    }

    if let Some(ref pattern) = entry.exe_path {
        match &identity.exe_path {
            Some(exe) => {
                let path_str = exe.to_string_lossy();
                if !glob_match::glob_match(pattern, &path_str) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref expected_hash) = entry.exe_sha256 {
        match &identity.exe_sha256 {
            Some(actual) => {
                if !actual.eq_ignore_ascii_case(expected_hash) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref expected_team) = entry.codesign_team_id {
        match &identity.codesign_team_id {
            Some(actual) => {
                if actual != expected_team {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

/// Build a [`ClientIdentity`] from peer credentials obtained via the Unix socket.
fn build_client_identity(peer: Option<&opaque_core::peer::PeerInfo>) -> ClientIdentity {
    match peer {
        Some(info) => {
            let exe_path = info.pid.and_then(exe_path_for_pid);
            let exe_sha256 = exe_path.as_ref().and_then(|p| compute_exe_hash(p));
            ClientIdentity {
                uid: info.uid,
                gid: info.gid,
                pid: info.pid,
                exe_path,
                exe_sha256,
                codesign_team_id: None,
            }
        }
        None => ClientIdentity {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        },
    }
}

/// Resolve the executable path for a given PID.
fn exe_path_for_pid(pid: i32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    }

    #[cfg(target_os = "macos")]
    {
        exe_path_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn exe_path_macos(pid: i32) -> Option<PathBuf> {
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

    unsafe extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_char,
            buffersize: u32,
        ) -> libc::c_int;
    }

    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        proc_pidpath(
            pid,
            buf.as_mut_ptr() as *mut libc::c_char,
            PROC_PIDPATHINFO_MAXSIZE,
        )
    };
    if ret > 0 {
        let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        cstr.to_str().ok().map(PathBuf::from)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Workspace verification
// ---------------------------------------------------------------------------

/// Create a `Command` with a minimal, hardened environment.
///
/// Clears all inherited env vars and sets only a restricted PATH to prevent
/// binary injection. Also prevents git from reading system/user config or
/// prompting for credentials.
fn safe_command(bin: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/usr/local/bin:/bin");
    cmd.env("LC_ALL", "C");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("HOME", "/nonexistent"); // Prevent reading ~/.gitconfig
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd
}

/// Read the current working directory of a process by PID.
fn read_client_cwd(pid: i32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_link(format!("/proc/{pid}/cwd")).ok();
    }

    #[cfg(target_os = "macos")]
    {
        read_client_cwd_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn read_client_cwd_macos(pid: i32) -> Option<PathBuf> {
    // Use lsof to get the cwd of a process on macOS.
    let output = safe_command("lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // lsof output format: "p<pid>\nn<path>"
    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix('n') {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Blocking workspace verification logic.
///
/// Verifies that the claimed workspace context is consistent with the client's
/// actual process state. Runs external `git` commands.
///
/// Checks:
/// - Client's cwd is within the claimed repo_root
/// - `git rev-parse --show-toplevel` in repo_root matches
/// - Claimed remote_url matches actual `git remote get-url origin`
/// - Claimed branch matches actual `git rev-parse --abbrev-ref HEAD`
fn verify_workspace_blocking(
    claimed: &opaque_core::operation::WorkspaceContext,
    client_pid: Option<i32>,
) -> Result<(), String> {
    // Verify client cwd is within claimed repo_root.
    if let Some(pid) = client_pid
        && let Some(cwd) = read_client_cwd(pid)
    {
        let repo_root = claimed
            .repo_root
            .canonicalize()
            .unwrap_or(claimed.repo_root.clone());
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        if !cwd.starts_with(&repo_root) {
            return Err(format!(
                "client cwd {} is not within claimed repo_root {}",
                cwd.display(),
                repo_root.display(),
            ));
        }
    }
    // If we can't read the cwd, we don't fail — best-effort.

    // Verify git toplevel matches.
    let toplevel = safe_command("git")
        .args([
            "-C",
            &claimed.repo_root.to_string_lossy(),
            "rev-parse",
            "--show-toplevel",
        ])
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if !toplevel.status.success() {
        return Err(format!(
            "{} is not a git repository",
            claimed.repo_root.display()
        ));
    }
    let actual_root = String::from_utf8_lossy(&toplevel.stdout).trim().to_string();
    let actual_root = PathBuf::from(&actual_root)
        .canonicalize()
        .unwrap_or(PathBuf::from(&actual_root));
    let claimed_root = claimed
        .repo_root
        .canonicalize()
        .unwrap_or(claimed.repo_root.clone());
    if actual_root != claimed_root {
        return Err(format!(
            "git toplevel {} does not match claimed repo_root {}",
            actual_root.display(),
            claimed_root.display(),
        ));
    }

    // Verify remote URL if claimed.
    if let Some(ref claimed_url) = claimed.remote_url {
        let remote = safe_command("git")
            .args([
                "-C",
                &claimed.repo_root.to_string_lossy(),
                "remote",
                "get-url",
                "origin",
            ])
            .output()
            .map_err(|e| format!("failed to get remote url: {e}"))?;
        if remote.status.success() {
            let actual_url = String::from_utf8_lossy(&remote.stdout).trim().to_string();
            if actual_url != *claimed_url {
                // Sanitize URLs before embedding in error messages to strip
                // embedded credentials (e.g. https://token@host/...).
                let safe_claimed = InputValidator::sanitize_url(claimed_url);
                let safe_actual = InputValidator::sanitize_url(&actual_url);
                return Err(format!(
                    "claimed remote_url '{}' does not match actual '{}'",
                    safe_claimed, safe_actual,
                ));
            }
        }
    }

    // Verify branch if claimed.
    if let Some(ref claimed_branch) = claimed.branch {
        let branch = safe_command("git")
            .args([
                "-C",
                &claimed.repo_root.to_string_lossy(),
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ])
            .output()
            .map_err(|e| format!("failed to get branch: {e}"))?;
        if branch.status.success() {
            let actual_branch = String::from_utf8_lossy(&branch.stdout).trim().to_string();
            if actual_branch != *claimed_branch {
                return Err(format!(
                    "claimed branch '{}' does not match actual '{}'",
                    claimed_branch, actual_branch,
                ));
            }
        }
    }

    Ok(())
}

/// Async wrapper around `verify_workspace_blocking` that offloads the
/// blocking `Command::output()` calls to a Tokio blocking thread.
async fn verify_workspace(
    claimed: &opaque_core::operation::WorkspaceContext,
    client_pid: Option<i32>,
) -> Result<(), String> {
    let claimed = claimed.clone();
    tokio::task::spawn_blocking(move || verify_workspace_blocking(&claimed, client_pid))
        .await
        .map_err(|e| format!("workspace verification task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Verify that the peer UID matches the daemon's own UID.
///
/// Rejects connections from other users, which could be confused-deputy
/// or privilege-escalation attempts in multi-user environments.
fn verify_peer_uid(peer: &opaque_core::peer::PeerInfo) -> bool {
    #[cfg(unix)]
    {
        let my_uid = unsafe { libc::getuid() };
        peer.uid == my_uid
    }
    #[cfg(not(unix))]
    {
        let _ = peer;
        true
    }
}

async fn handle_conn(
    state: Arc<DaemonState>,
    stream: UnixStream,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let peer = peer_info_from_fd(fd).ok();

    // Verify peer UID matches daemon UID. Reject if unavailable or mismatched.
    match &peer {
        None => {
            warn!("peer credentials unavailable, rejecting connection");
            return Ok(());
        }
        Some(info) => {
            if !verify_peer_uid(info) {
                warn!(
                    "peer UID {} does not match daemon UID, rejecting connection",
                    info.uid
                );
                return Ok(());
            }
        }
    }

    let identity = build_client_identity(peer.as_ref());

    // Derive client type once per connection — never from request params.
    let client_type = derive_client_type(&identity, &state.config);

    if let Some(ref peer) = peer {
        info!(
            "client connected uid={} gid={} pid={:?} type={:?}",
            peer.uid, peer.gid, peer.pid, client_type
        );
    } else {
        info!("client connected (peer creds unavailable) type={client_type:?}");
    }

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    // --- Handshake: first frame must be a valid daemon token ---
    let handshake = match framed.next().await {
        Some(Ok(frame)) => validate_handshake(&frame, &state.daemon_token),
        _ => None,
    };

    let Some(handshake) = handshake else {
        // Close silently — no error detail to prevent oracle attacks.
        warn!("handshake failed, closing connection");
        return Ok(());
    };

    let session_id = if state.config.enforce_agent_sessions && client_type == ClientType::Agent {
        match handshake.session_token.as_deref() {
            Some(token) => {
                match validate_agent_session_token(state.as_ref(), token, identity.uid).await {
                    Some(id) => Some(id),
                    None => {
                        warn!("agent session token invalid or expired, closing connection");
                        return Ok(());
                    }
                }
            }
            None => {
                warn!("missing agent session token, closing connection");
                return Ok(());
            }
        }
    } else {
        None
    };

    // Split into read/write halves so we can detect client disconnect during
    // request processing. When the client disconnects, the in-flight request
    // future is dropped, which releases any held resources (including the
    // approval semaphore). This implements the US-009 requirement:
    // "Approval semaphore is released when the requesting client disconnects."
    let (mut sink, mut reader) = framed.split();

    // Per-connection rate limiter: burst of 10, sustained 2 req/s.
    let mut rate_limiter = ConnectionRateLimiter::new(10, 2.0);

    loop {
        // Stop accepting new requests when shutdown is signaled.
        if *shutdown_rx.borrow() {
            info!("shutdown signaled, closing connection");
            break;
        }

        // Idle timeout: disconnect clients that send no frames for 30 seconds.
        let next_frame = tokio::select! {
            frame = tokio::time::timeout(std::time::Duration::from_secs(30), reader.next()) => frame,
            _ = shutdown_rx.changed() => {
                info!("shutdown signaled, closing connection");
                break;
            }
        };

        match next_frame {
            Ok(Some(Ok(frame))) => {
                let req: Request = match serde_json::from_slice(&frame) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("bad JSON from client: {e}");
                        let resp = Response::err(None, "bad_json", "invalid JSON request");
                        let bytes = serde_json::to_vec(&resp)
                            .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                        let _ = sink.send(Bytes::from(bytes)).await;
                        continue;
                    }
                };

                // Per-connection rate limiting.
                if !rate_limiter.check() {
                    warn!("rate limit exceeded for connection");
                    let resp = Response::err(Some(req.id), "rate_limited", "too many requests");
                    let out = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
                    sink.send(Bytes::from(out)).await?;
                    continue;
                }

                // Session TTL enforcement for wrapped agents.
                if state.config.enforce_agent_sessions && client_type == ClientType::Agent {
                    let active = if let Some(ref sid) = session_id {
                        let sessions = state.agent_sessions.read().await;
                        sessions.get(sid).is_some_and(|s| {
                            s.created_by_uid == identity.uid && s.expires_at > SystemTime::now()
                        })
                    } else {
                        false
                    };
                    if !active {
                        warn!("agent session expired or revoked, closing connection");
                        break;
                    }
                }

                // Never log params (may contain secrets due to client bugs).
                // Request timeout: 120 seconds.
                // Race against client disconnect so the approval semaphore is
                // released immediately when the requesting client goes away.
                let req_id = req.id;
                let resp = tokio::select! {
                    r = tokio::time::timeout(
                        std::time::Duration::from_secs(120),
                        handle_request(&state, req, &identity, client_type, session_id.as_deref()),
                    ) => {
                        match r {
                            Ok(r) => r,
                            Err(_) => {
                                warn!("request timed out after 120s");
                                Response::err(Some(req_id), "timeout", "request timed out")
                            }
                        }
                    }
                    _ = reader.next() => {
                        // Client disconnected or sent data during request processing.
                        // Dropping the handle_request future releases the approval
                        // semaphore permit via RAII if one was held.
                        info!("client disconnected during request processing");
                        break;
                    }
                };
                let out = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
                sink.send(Bytes::from(out)).await?;
            }
            Ok(Some(Err(e))) => {
                warn!("bad frame from client: {e}");
                let resp = Response::err(None, "bad_frame", "malformed frame");
                let bytes = serde_json::to_vec(&resp)
                    .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                let _ = sink.send(Bytes::from(bytes)).await;
                return Err(e);
            }
            Ok(None) => break, // Client disconnected
            Err(_) => {
                info!("idle timeout, closing connection");
                break;
            }
        }
    }

    Ok(())
}

/// Validate the handshake frame from a client.
///
/// Expected format: `{"handshake":"v1","daemon_token":"<hex>"}`
#[derive(Debug, Clone)]
struct HandshakePayload {
    session_token: Option<String>,
}

fn validate_handshake(frame: &[u8], expected_token: &str) -> Option<HandshakePayload> {
    #[derive(Deserialize)]
    struct Handshake {
        handshake: String,
        daemon_token: String,
        #[serde(default)]
        session_token: Option<String>,
    }

    let hs: Handshake = match serde_json::from_slice(frame) {
        Ok(h) => h,
        Err(_) => return None,
    };

    if hs.handshake != "v1" {
        return None;
    }

    // Constant-time comparison to prevent timing attacks.
    if !constant_time_eq(hs.daemon_token.as_bytes(), expected_token.as_bytes()) {
        return None;
    }

    Some(HandshakePayload {
        session_token: hs.session_token.filter(|s| !s.trim().is_empty()),
    })
}

/// Constant-time byte comparison (prevents timing side channels).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn system_time_to_unix_ms(ts: SystemTime) -> i64 {
    ts.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn validate_agent_session_token(
    state: &DaemonState,
    token: &str,
    uid: u32,
) -> Option<String> {
    let now = SystemTime::now();
    let mut sessions = state.agent_sessions.write().await;
    // Expire old sessions opportunistically.
    sessions.retain(|_, s| s.expires_at > now);

    sessions.values().find_map(|session| {
        if session.created_by_uid == uid
            && constant_time_eq(session.token.as_bytes(), token.as_bytes())
        {
            Some(session.session_id.clone())
        } else {
            None
        }
    })
}

async fn handle_request(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
) -> Response {
    match req.method.as_str() {
        "ping" => Response::ok(
            req.id,
            serde_json::json!({ "ok": true, "api_version": opaque_core::API_VERSION }),
        ),
        "version" => Response::ok(
            req.id,
            serde_json::json!({ "version": state.version, "api_version": opaque_core::API_VERSION }),
        ),
        "whoami" => {
            // Agent clients get minimal info to prevent reconnaissance.
            // Human clients get the full dump for debugging identity matching.
            let payload = match client_type {
                ClientType::Human => serde_json::json!({
                    "uid": identity.uid,
                    "gid": identity.gid,
                    "pid": identity.pid,
                    "exe_path": identity.exe_path.as_ref().map(|p| p.display().to_string()),
                    "exe_sha256": identity.exe_sha256,
                    "client_type": client_type,
                    "agent_session_id": session_id,
                }),
                ClientType::Agent => serde_json::json!({
                    "uid": identity.uid,
                    "client_type": client_type,
                    "agent_session_id": session_id,
                }),
            };
            Response::ok(req.id, payload)
        }
        "agent_session_start" => {
            if state.config.enforce_agent_sessions && client_type != ClientType::Human {
                return Response::err(
                    Some(req.id),
                    "permission_denied",
                    "only human clients can start agent sessions when enforce_agent_sessions is enabled",
                );
            }

            let default_ttl = state.config.agent_session_ttl_secs.unwrap_or(3600);
            let ttl_secs = req
                .params
                .get("ttl_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(default_ttl)
                .clamp(60, 86_400);
            let label = req
                .params
                .get("label")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned());

            let session_id = Uuid::new_v4().to_string();
            let session_token = generate_daemon_token();
            let expires_at = SystemTime::now()
                .checked_add(std::time::Duration::from_secs(ttl_secs))
                .unwrap_or(SystemTime::now());

            let session = AgentSession {
                session_id: session_id.clone(),
                token: session_token.clone(),
                created_by_uid: identity.uid,
                expires_at,
                label,
            };
            state
                .agent_sessions
                .write()
                .await
                .insert(session_id.clone(), session);

            Response::ok(
                req.id,
                serde_json::json!({
                    "session_id": session_id,
                    "session_token": session_token,
                    "expires_at_utc_ms": system_time_to_unix_ms(expires_at),
                    "ttl_secs": ttl_secs,
                }),
            )
        }
        "agent_session_end" => {
            let Some(session_id) = req.params.get("session_id").and_then(|v| v.as_str()) else {
                return Response::err(Some(req.id), "bad_request", "missing 'session_id' field");
            };

            let mut sessions = state.agent_sessions.write().await;
            let can_delete = if let Some(existing) = sessions.get(session_id) {
                client_type == ClientType::Human || existing.created_by_uid == identity.uid
            } else {
                true
            };
            if !can_delete {
                return Response::err(
                    Some(req.id),
                    "permission_denied",
                    "session belongs to a different uid",
                );
            }

            let removed = sessions.remove(session_id);
            let label = removed.as_ref().and_then(|s| s.label.clone());

            Response::ok(
                req.id,
                serde_json::json!({
                    "status": if removed.is_some() { "ended" } else { "not_found" },
                    "session_id": session_id,
                    "label": label,
                }),
            )
        }
        "leases" => {
            // Only human clients can inspect active leases.
            if client_type != ClientType::Human {
                return Response::err(
                    Some(req.id),
                    "permission_denied",
                    "only human clients can list active leases",
                );
            }
            let leases = state.enclave.active_leases();
            Response::ok(
                req.id,
                serde_json::json!({
                    "count": leases.len(),
                    "leases": leases,
                }),
            )
        }
        "execute" => {
            let operation = req
                .params
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if operation.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'operation' field");
            }

            let target: HashMap<String, String> = req
                .params
                .get("target")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let secret_ref_names: Vec<String> = req
                .params
                .get("secret_ref_names")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            // --- Input validation (P0): sanitize client-controlled strings ---
            let target = match InputValidator::validate_target(&target) {
                Ok(t) => t,
                Err(e) => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid target: {e}"),
                    );
                }
            };

            let secret_ref_names =
                match InputValidator::validate_secret_ref_names(&secret_ref_names) {
                    Ok(n) => n,
                    Err(e) => {
                        return Response::err(
                            Some(req.id),
                            "bad_request",
                            format!("invalid secret_ref_names: {e}"),
                        );
                    }
                };

            // Client type is derived from verified identity — NEVER from params.
            // Any `client_type` field in params is silently ignored.

            let op_params = req
                .params
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            let mut workspace: Option<opaque_core::operation::WorkspaceContext> = req
                .params
                .get("workspace")
                .and_then(|v| serde_json::from_value(v.clone()).ok());

            // Sanitize workspace remote_url to strip embedded credentials.
            if let Some(ref mut ws) = workspace
                && let Some(ref url) = ws.remote_url
            {
                ws.remote_url = Some(InputValidator::sanitize_url(url));
            }

            // Verify claimed workspace against actual process state.
            // verify_workspace is async (offloads blocking git commands to spawn_blocking).
            if let Some(ref ws) = workspace
                && let Err(e) = verify_workspace(ws, identity.pid).await
            {
                warn!("workspace verification failed: {e}");
                return Response::err(
                    Some(req.id),
                    "workspace_verification_failed",
                    "workspace verification failed",
                );
            }

            let op_req = OperationRequest {
                request_id: Uuid::new_v4(),
                client_identity: identity.clone(),
                client_type,
                operation,
                target,
                secret_ref_names,
                created_at: SystemTime::now(),
                expires_at: None,
                params: op_params,
                workspace,
            };

            state
                .enclave
                .execute(op_req)
                .await
                .into_proto_response(req.id)
        }
        "github" => {
            // The github method is a convenience wrapper that builds an "execute"
            // request for the appropriate github.* operation based on the `scope` param.
            //
            // The `action` field determines the operation type:
            // - "list_secrets" → github.list_secrets
            // - "delete_secret" → github.delete_secret
            // - (default) → github.set_* (set secret)
            let action = req
                .params
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("set_secret");

            // Route list_secrets and delete_secret to their own dispatch paths.
            if action == "list_secrets" {
                return handle_github_list_secrets(&req, state, identity, client_type).await;
            }
            if action == "delete_secret" {
                return handle_github_delete_secret(&req, state, identity, client_type).await;
            }

            let scope = req
                .params
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("repo_actions");

            let secret_name = req
                .params
                .get("secret_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if secret_name.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'secret_name' field");
            }

            // Validate secret_name (alphanumeric + underscores).
            if !secret_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "secret_name must be alphanumeric (with underscores)",
                );
            }

            let value_ref = req
                .params
                .get("value_ref")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if value_ref.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'value_ref' field");
            }

            // Validate value_ref starts with a known scheme.
            if !opaque_core::profile::ALLOWED_REF_SCHEMES
                .iter()
                .any(|s| value_ref.starts_with(s))
            {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    format!(
                        "value_ref must start with a known scheme ({:?})",
                        opaque_core::profile::ALLOWED_REF_SCHEMES
                    ),
                );
            }

            // Validate value_ref and github_token_ref for control chars / secret patterns.
            // This prevents prompt injection in the approval UI via crafted ref strings.
            let mut refs_to_validate = vec![value_ref.clone()];
            if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                refs_to_validate.push(tok.to_owned());
            }
            if let Err(e) = InputValidator::validate_secret_ref_names(&refs_to_validate) {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    format!("invalid secret ref: {e}"),
                );
            }

            // Determine operation name and target based on scope.
            let (operation, target, op_params) = match scope {
                "repo_actions" | "env_actions" => {
                    let repo = req
                        .params
                        .get("repo")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    if repo.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'repo' field");
                    }
                    if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
                        return Response::err(
                            Some(req.id),
                            "bad_request",
                            "repo must be in 'owner/repo' format",
                        );
                    }

                    let mut params = serde_json::json!({
                        "repo": repo,
                        "secret_name": secret_name,
                        "value_ref": value_ref,
                    });
                    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                        params["github_token_ref"] = serde_json::Value::String(tok.into());
                    }
                    if let Some(env) = req.params.get("environment").and_then(|v| v.as_str()) {
                        params["environment"] = serde_json::Value::String(env.into());
                    }
                    let mut target = HashMap::from([
                        ("repo".into(), repo),
                        ("secret_name".into(), secret_name.clone()),
                    ]);
                    if let Some(env) = params.get("environment").and_then(|v| v.as_str()) {
                        target.insert("environment".into(), env.to_owned());
                    }
                    ("github.set_actions_secret", target, params)
                }
                "codespaces_user" => {
                    let mut params = serde_json::json!({
                        "secret_name": secret_name,
                        "value_ref": value_ref,
                    });
                    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                        params["github_token_ref"] = serde_json::Value::String(tok.into());
                    }
                    if let Some(ids) = req.params.get("selected_repository_ids") {
                        params["selected_repository_ids"] = ids.clone();
                    }
                    let target = HashMap::from([("secret_name".into(), secret_name.clone())]);
                    ("github.set_codespaces_secret", target, params)
                }
                "codespaces_repo" => {
                    let repo = req
                        .params
                        .get("repo")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    if repo.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'repo' field");
                    }
                    if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
                        return Response::err(
                            Some(req.id),
                            "bad_request",
                            "repo must be in 'owner/repo' format",
                        );
                    }

                    let mut params = serde_json::json!({
                        "repo": repo,
                        "secret_name": secret_name,
                        "value_ref": value_ref,
                    });
                    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                        params["github_token_ref"] = serde_json::Value::String(tok.into());
                    }
                    let target = HashMap::from([
                        ("repo".into(), repo),
                        ("secret_name".into(), secret_name.clone()),
                    ]);
                    ("github.set_codespaces_secret", target, params)
                }
                "dependabot" => {
                    let repo = req
                        .params
                        .get("repo")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    if repo.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'repo' field");
                    }
                    if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
                        return Response::err(
                            Some(req.id),
                            "bad_request",
                            "repo must be in 'owner/repo' format",
                        );
                    }

                    let mut params = serde_json::json!({
                        "repo": repo,
                        "secret_name": secret_name,
                        "value_ref": value_ref,
                    });
                    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                        params["github_token_ref"] = serde_json::Value::String(tok.into());
                    }
                    let target = HashMap::from([
                        ("repo".into(), repo),
                        ("secret_name".into(), secret_name.clone()),
                    ]);
                    ("github.set_dependabot_secret", target, params)
                }
                "org_actions" => {
                    let org = req
                        .params
                        .get("org")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    if org.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'org' field");
                    }

                    let mut params = serde_json::json!({
                        "org": org,
                        "secret_name": secret_name,
                        "value_ref": value_ref,
                    });
                    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                        params["github_token_ref"] = serde_json::Value::String(tok.into());
                    }
                    if let Some(vis) = req.params.get("visibility").and_then(|v| v.as_str()) {
                        params["visibility"] = serde_json::Value::String(vis.into());
                    }
                    if let Some(ids) = req.params.get("selected_repository_ids") {
                        params["selected_repository_ids"] = ids.clone();
                    }
                    let target = HashMap::from([
                        ("org".into(), org),
                        ("secret_name".into(), secret_name.clone()),
                    ]);
                    ("github.set_org_secret", target, params)
                }
                unknown => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!(
                            "unknown scope '{unknown}' (expected: repo_actions, env_actions, codespaces_user, codespaces_repo, dependabot, org_actions)"
                        ),
                    );
                }
            };

            // Validate target before building OperationRequest.
            let target = match InputValidator::validate_target(&target) {
                Ok(t) => t,
                Err(e) => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid target: {e}"),
                    );
                }
            };

            let mut secret_refs = vec![value_ref.clone()];
            if let Some(tok) = op_params.get("github_token_ref").and_then(|v| v.as_str()) {
                secret_refs.push(tok.to_owned());
            }

            let op_req = OperationRequest {
                request_id: Uuid::new_v4(),
                client_identity: identity.clone(),
                client_type,
                operation: operation.into(),
                target,
                secret_ref_names: secret_refs,
                created_at: SystemTime::now(),
                expires_at: None,
                params: op_params,
                workspace: None,
            };

            state
                .enclave
                .execute(op_req)
                .await
                .into_proto_response(req.id)
        }
        "gitlab" => {
            // Convenience wrapper for gitlab.set_ci_variable.
            let action = req
                .params
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("set_ci_variable")
                .to_owned();

            if action != "set_ci_variable" {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    format!("unknown action '{action}' (expected: set_ci_variable)"),
                );
            }

            let project = req
                .params
                .get("project")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if project.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'project' field");
            }

            let key = req
                .params
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if key.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'key' field");
            }
            if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "key must be alphanumeric (with underscores)",
                );
            }

            let value_ref = req
                .params
                .get("value_ref")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if value_ref.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'value_ref' field");
            }
            if !opaque_core::profile::ALLOWED_REF_SCHEMES
                .iter()
                .any(|s| value_ref.starts_with(s))
            {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    format!(
                        "value_ref must start with a known scheme ({:?})",
                        opaque_core::profile::ALLOWED_REF_SCHEMES
                    ),
                );
            }

            let mut refs_to_validate = vec![value_ref.clone()];
            if let Some(tok) = req.params.get("gitlab_token_ref").and_then(|v| v.as_str()) {
                refs_to_validate.push(tok.to_owned());
            }
            if let Err(e) = InputValidator::validate_secret_ref_names(&refs_to_validate) {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    format!("invalid secret ref: {e}"),
                );
            }

            let target = HashMap::from([
                ("project".into(), project.clone()),
                ("key".into(), key.clone()),
            ]);
            let target = match InputValidator::validate_target(&target) {
                Ok(t) => t,
                Err(e) => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid target: {e}"),
                    );
                }
            };

            let mut op_params = serde_json::json!({
                "project": project,
                "key": key,
                "value_ref": value_ref,
            });
            if let Some(tok) = req.params.get("gitlab_token_ref").and_then(|v| v.as_str()) {
                op_params["gitlab_token_ref"] = serde_json::Value::String(tok.to_owned());
            }
            if let Some(scope) = req.params.get("environment_scope").and_then(|v| v.as_str()) {
                op_params["environment_scope"] = serde_json::Value::String(scope.to_owned());
            }
            if req.params.get("protected").is_some() {
                op_params["protected"] = req.params["protected"].clone();
            }
            if req.params.get("masked").is_some() {
                op_params["masked"] = req.params["masked"].clone();
            }
            if req.params.get("raw").is_some() {
                op_params["raw"] = req.params["raw"].clone();
            }
            if let Some(variable_type) = req.params.get("variable_type").and_then(|v| v.as_str()) {
                op_params["variable_type"] = serde_json::Value::String(variable_type.to_owned());
            }

            let op_req = OperationRequest {
                request_id: Uuid::new_v4(),
                client_identity: identity.clone(),
                client_type,
                operation: "gitlab.set_ci_variable".into(),
                target,
                secret_ref_names: vec![],
                created_at: SystemTime::now(),
                expires_at: None,
                params: op_params,
                workspace: None,
            };

            state
                .enclave
                .execute(op_req)
                .await
                .into_proto_response(req.id)
        }
        "onepassword" => {
            // The onepassword method is a convenience wrapper that builds an
            // "execute" request for the appropriate onepassword.* operation.
            let action = req
                .params
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if action.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'action' field");
            }

            let (operation, target, op_params) = match action.as_str() {
                "list_vaults" => (
                    "onepassword.list_vaults",
                    HashMap::new(),
                    serde_json::json!({}),
                ),
                "list_items" => {
                    let vault = req
                        .params
                        .get("vault")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();

                    if vault.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'vault' field");
                    }

                    let target = HashMap::from([("vault".into(), vault.clone())]);
                    (
                        "onepassword.list_items",
                        target,
                        serde_json::json!({ "vault": vault }),
                    )
                }
                "read_field" => {
                    let vault = req
                        .params
                        .get("vault")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let item = req
                        .params
                        .get("item")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let field = req
                        .params
                        .get("field")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();

                    if vault.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'vault' field");
                    }
                    if item.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'item' field");
                    }
                    if field.is_empty() {
                        return Response::err(Some(req.id), "bad_request", "missing 'field' field");
                    }

                    let target = HashMap::from([
                        ("vault".into(), vault.clone()),
                        ("item".into(), item.clone()),
                    ]);
                    (
                        "onepassword.read_field",
                        target,
                        serde_json::json!({ "vault": vault, "item": item, "field": field }),
                    )
                }
                unknown => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!(
                            "unknown action '{unknown}' (expected: list_vaults, list_items, read_field)"
                        ),
                    );
                }
            };

            // Validate target before building OperationRequest.
            let target = match InputValidator::validate_target(&target) {
                Ok(t) => t,
                Err(e) => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid target: {e}"),
                    );
                }
            };

            // Build secret_ref_names from the vault/item/field path for read_field.
            let secret_ref_names = if action == "read_field" {
                let v = op_params
                    .get("vault")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let i = op_params.get("item").and_then(|v| v.as_str()).unwrap_or("");
                let f = op_params
                    .get("field")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let refs = vec![format!("onepassword:{v}/{i}/{f}")];
                if let Err(e) = InputValidator::validate_secret_ref_names(&refs) {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid secret ref: {e}"),
                    );
                }
                refs
            } else {
                vec![]
            };

            let op_req = OperationRequest {
                request_id: Uuid::new_v4(),
                client_identity: identity.clone(),
                client_type,
                operation: operation.into(),
                target,
                secret_ref_names,
                created_at: SystemTime::now(),
                expires_at: None,
                params: op_params,
                workspace: None,
            };

            state
                .enclave
                .execute(op_req)
                .await
                .into_proto_response(req.id)
        }
        "bitwarden" => {
            // The bitwarden method is a convenience wrapper that builds an
            // "execute" request for the appropriate bitwarden.* operation.
            let action = req
                .params
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if action.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'action' field");
            }

            let (operation, target, op_params) = match action.as_str() {
                "list_projects" => (
                    "bitwarden.list_projects",
                    HashMap::new(),
                    serde_json::json!({}),
                ),
                "list_secrets" => {
                    let project = req
                        .params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned());

                    let target = if let Some(ref p) = project {
                        HashMap::from([("project".into(), p.clone())])
                    } else {
                        HashMap::new()
                    };
                    let params = if let Some(ref p) = project {
                        serde_json::json!({ "project": p })
                    } else {
                        serde_json::json!({})
                    };
                    ("bitwarden.list_secrets", target, params)
                }
                "read_secret" => {
                    let secret_id = req
                        .params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();

                    if secret_id.is_empty() {
                        return Response::err(
                            Some(req.id),
                            "bad_request",
                            "missing 'secret_id' field",
                        );
                    }

                    let target = HashMap::from([("secret_id".into(), secret_id.clone())]);
                    (
                        "bitwarden.read_secret",
                        target,
                        serde_json::json!({ "secret_id": secret_id }),
                    )
                }
                unknown => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!(
                            "unknown action '{unknown}' (expected: list_projects, list_secrets, read_secret)"
                        ),
                    );
                }
            };

            // Validate target before building OperationRequest.
            let target = match InputValidator::validate_target(&target) {
                Ok(t) => t,
                Err(e) => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid target: {e}"),
                    );
                }
            };

            // Build secret_ref_names for read_secret.
            let secret_ref_names = if action == "read_secret" {
                let sid = op_params
                    .get("secret_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let refs = vec![format!("bitwarden:{sid}")];
                if let Err(e) = InputValidator::validate_secret_ref_names(&refs) {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid secret ref: {e}"),
                    );
                }
                refs
            } else {
                vec![]
            };

            let op_req = OperationRequest {
                request_id: Uuid::new_v4(),
                client_identity: identity.clone(),
                client_type,
                operation: operation.into(),
                target,
                secret_ref_names,
                created_at: SystemTime::now(),
                expires_at: None,
                params: op_params,
                workspace: None,
            };

            state
                .enclave
                .execute(op_req)
                .await
                .into_proto_response(req.id)
        }
        "exec" => {
            // The exec method is a convenience wrapper that builds an "execute"
            // request for "sandbox.exec" from exec-specific params.
            let profile = req
                .params
                .get("profile")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if profile.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'profile' field");
            }

            let command: Vec<String> = req
                .params
                .get("command")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            if command.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'command' field");
            }

            // Validate profile name (alphanumeric + hyphens + underscores).
            if !profile
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "profile name must be alphanumeric (with hyphens/underscores)",
                );
            }

            // Derive secret_ref_names from the profile's secret declarations.
            let secret_ref_names = opaque_core::profile::load_named_profile(&profile)
                .map(|p| p.secrets.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();

            let op_req = OperationRequest {
                request_id: Uuid::new_v4(),
                client_identity: identity.clone(),
                client_type,
                operation: "sandbox.exec".into(),
                target: HashMap::from([("profile".into(), profile.clone())]),
                secret_ref_names,
                created_at: SystemTime::now(),
                expires_at: None,
                params: serde_json::json!({
                    "profile": profile,
                    "command": command,
                }),
                workspace: None,
            };

            state
                .enclave
                .execute(op_req)
                .await
                .into_proto_response(req.id)
        }
        _ => Response::err(Some(req.id), "unknown_method", "unknown method"),
    }
}

/// Handle `github` method with `action: "list_secrets"`.
///
/// Routes to `github.list_secrets` operation in the enclave.
async fn handle_github_list_secrets(
    req: &opaque_core::proto::Request,
    state: &DaemonState,
    identity: &ClientIdentity,
    client_type: ClientType,
) -> opaque_core::proto::Response {
    let scope = req
        .params
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("actions");

    let mut op_params = serde_json::json!({ "scope": scope });
    let mut target = HashMap::new();

    if let Some(repo) = req.params.get("repo").and_then(|v| v.as_str()) {
        op_params["repo"] = serde_json::Value::String(repo.into());
        target.insert("repo".into(), repo.to_owned());
    }
    if let Some(org) = req.params.get("org").and_then(|v| v.as_str()) {
        op_params["org"] = serde_json::Value::String(org.into());
        target.insert("org".into(), org.to_owned());
    }
    if let Some(env) = req.params.get("environment").and_then(|v| v.as_str()) {
        op_params["environment"] = serde_json::Value::String(env.into());
    }
    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
        op_params["github_token_ref"] = serde_json::Value::String(tok.into());
    }

    // Validate target before building OperationRequest.
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    let op_req = OperationRequest {
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: "github.list_secrets".into(),
        target,
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: op_params,
        workspace: None,
    };

    state
        .enclave
        .execute(op_req)
        .await
        .into_proto_response(req.id)
}

/// Handle `github` method with `action: "delete_secret"`.
///
/// Routes to `github.delete_secret` operation in the enclave.
async fn handle_github_delete_secret(
    req: &opaque_core::proto::Request,
    state: &DaemonState,
    identity: &ClientIdentity,
    client_type: ClientType,
) -> opaque_core::proto::Response {
    let scope = req
        .params
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("actions");

    let secret_name = req
        .params
        .get("secret_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    if secret_name.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'secret_name' field");
    }

    let mut op_params = serde_json::json!({
        "scope": scope,
        "secret_name": secret_name,
    });
    let mut target = HashMap::from([("secret_name".into(), secret_name.clone())]);

    if let Some(repo) = req.params.get("repo").and_then(|v| v.as_str()) {
        op_params["repo"] = serde_json::Value::String(repo.into());
        target.insert("repo".into(), repo.to_owned());
    }
    if let Some(org) = req.params.get("org").and_then(|v| v.as_str()) {
        op_params["org"] = serde_json::Value::String(org.into());
        target.insert("org".into(), org.to_owned());
    }
    if let Some(env) = req.params.get("environment").and_then(|v| v.as_str()) {
        op_params["environment"] = serde_json::Value::String(env.into());
    }
    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
        op_params["github_token_ref"] = serde_json::Value::String(tok.into());
    }

    // Validate target before building OperationRequest.
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    let op_req = OperationRequest {
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: "github.delete_secret".into(),
        target,
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: op_params,
        workspace: None,
    };

    state
        .enclave
        .execute(op_req)
        .await
        .into_proto_response(req.id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    fn test_identity() -> ClientIdentity {
        ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/claude-code".into()),
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
        }
    }

    fn entry_with_path(name: &str, pattern: &str) -> HumanClientEntry {
        HumanClientEntry {
            name: name.into(),
            exe_path: Some(pattern.into()),
            exe_sha256: None,
            codesign_team_id: None,
        }
    }

    #[test]
    fn derive_client_type_matches_by_path() {
        let config = DaemonConfig {
            known_human_clients: vec![entry_with_path("claude", "/usr/bin/claude*")],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Human);
    }

    #[test]
    fn derive_client_type_matches_by_hash() {
        let config = DaemonConfig {
            known_human_clients: vec![HumanClientEntry {
                name: "claude".into(),
                exe_path: None,
                exe_sha256: Some("AABBCCDD".into()), // case-insensitive
                codesign_team_id: None,
            }],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Human);
    }

    #[test]
    fn derive_client_type_defaults_to_agent() {
        let config = DaemonConfig {
            known_human_clients: vec![entry_with_path("vscode", "/usr/bin/code*")],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Agent);
    }

    #[test]
    fn compute_exe_hash_nonexistent_none() {
        assert!(compute_exe_hash(Path::new("/nonexistent/binary")).is_none());
    }

    #[test]
    fn compute_exe_hash_valid_file() {
        // Hash the current test binary — always exists during test execution.
        let exe = std::env::current_exe().expect("current_exe should succeed in tests");
        let hash = compute_exe_hash(&exe);
        assert!(hash.is_some(), "hashing current binary should succeed");
        let h = hash.unwrap();
        // SHA-256 hex digest is always 64 characters.
        assert_eq!(h.len(), 64, "expected 64-char hex digest, got {}", h.len());
        // Should be lowercase hex.
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn config_empty_all_agents() {
        let config = DaemonConfig::default();
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Agent);
    }

    #[test]
    fn entry_matches_codesign_team_id() {
        let entry = HumanClientEntry {
            name: "xcode".into(),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: Some("TEAM123".into()),
        };
        let mut id = test_identity();
        id.codesign_team_id = Some("TEAM123".into());
        assert!(entry_matches(&id, &entry));

        id.codesign_team_id = Some("OTHER".into());
        assert!(!entry_matches(&id, &entry));

        id.codesign_team_id = None;
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn entry_matches_multi_criteria_all_must_match() {
        // When both exe_path and exe_sha256 are specified, both must match.
        let entry = HumanClientEntry {
            name: "strict".into(),
            exe_path: Some("/usr/bin/claude*".into()),
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
        };

        // Both match → ok.
        let id = test_identity();
        assert!(entry_matches(&id, &entry));

        // Path matches, hash doesn't → reject.
        let mut id2 = test_identity();
        id2.exe_sha256 = Some("different".into());
        assert!(!entry_matches(&id2, &entry));

        // Hash matches, path doesn't → reject.
        let mut id3 = test_identity();
        id3.exe_path = Some("/opt/bin/other".into());
        assert!(!entry_matches(&id3, &entry));
    }

    #[test]
    fn entry_matches_empty_entry_rejects_all() {
        let empty = HumanClientEntry {
            name: "empty".into(),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        };
        let id = test_identity();
        assert!(!entry_matches(&id, &empty));
    }

    #[test]
    fn entry_matches_identity_missing_exe_path() {
        let entry = entry_with_path("cli", "/usr/bin/claude*");
        let mut id = test_identity();
        id.exe_path = None;
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn entry_matches_identity_missing_hash() {
        let entry = HumanClientEntry {
            name: "hash-only".into(),
            exe_path: None,
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
        };
        let mut id = test_identity();
        id.exe_sha256 = None;
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn handshake_valid_accepted() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": token,
        }))
        .unwrap();
        assert!(validate_handshake(&frame, token).is_some());
    }

    #[test]
    fn handshake_invalid_token_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": "wrong_token",
        }))
        .unwrap();
        assert!(validate_handshake(&frame, "correct_token").is_none());
    }

    #[test]
    fn handshake_missing_fields_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({"handshake": "v1"})).unwrap();
        assert!(validate_handshake(&frame, "token").is_none());
    }

    #[test]
    fn handshake_wrong_version_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v99",
            "daemon_token": "token",
        }))
        .unwrap();
        assert!(validate_handshake(&frame, "token").is_none());
    }

    #[test]
    fn handshake_garbage_rejected() {
        assert!(validate_handshake(b"not json at all", "token").is_none());
    }

    #[test]
    fn handshake_with_session_token_roundtrip() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": token,
            "session_token": "session_123",
        }))
        .unwrap();
        let hs = validate_handshake(&frame, token).expect("handshake should parse");
        assert_eq!(hs.session_token.as_deref(), Some("session_123"));
    }

    #[test]
    fn generate_daemon_token_is_64_hex_chars() {
        let token = generate_daemon_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_daemon_token_is_unique() {
        let t1 = generate_daemon_token();
        let t2 = generate_daemon_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn write_daemon_token_creates_file() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("opaqued.sock");
        let token = "test_token_hex";
        let token_path = write_daemon_token(&socket_path, token).unwrap();
        assert_eq!(token_path, dir.join(DAEMON_TOKEN_FILENAME));
        let contents = std::fs::read_to_string(&token_path).unwrap();
        assert_eq!(contents, token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = token_path.metadata().unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_peer_uid_same_uid() {
        let my_uid = unsafe { libc::getuid() };
        let peer = opaque_core::peer::PeerInfo {
            uid: my_uid,
            gid: 20,
            pid: Some(1234),
        };
        assert!(verify_peer_uid(&peer));
    }

    #[test]
    fn verify_peer_uid_different_uid() {
        let my_uid = unsafe { libc::getuid() };
        let other_uid = if my_uid == 0 { 1000 } else { my_uid + 1 };
        let peer = opaque_core::peer::PeerInfo {
            uid: other_uid,
            gid: 20,
            pid: Some(1234),
        };
        assert!(!verify_peer_uid(&peer));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    #[test]
    fn safe_command_has_minimal_env() {
        let cmd = safe_command("echo");
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(
            envs.get("PATH").map(|s| s.as_str()),
            Some("/usr/bin:/usr/local/bin:/bin")
        );
        assert_eq!(envs.get("LC_ALL").map(|s| s.as_str()), Some("C"));
        assert_eq!(
            envs.get("GIT_TERMINAL_PROMPT").map(|s| s.as_str()),
            Some("0")
        );
        assert_eq!(
            envs.get("GIT_CONFIG_NOSYSTEM").map(|s| s.as_str()),
            Some("1")
        );
        assert_eq!(envs.get("HOME").map(|s| s.as_str()), Some("/nonexistent"));
        // Should not contain common env vars that would be inherited.
        assert!(!envs.contains_key("USER"));
        assert!(!envs.contains_key("SHELL"));
    }

    #[test]
    fn safe_command_blocks_git_config() {
        let cmd = safe_command("git");
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        // GIT_CONFIG_NOSYSTEM prevents reading /etc/gitconfig.
        assert_eq!(
            envs.get("GIT_CONFIG_NOSYSTEM").map(|s| s.as_str()),
            Some("1")
        );
        // HOME=/nonexistent prevents reading ~/.gitconfig.
        assert_eq!(envs.get("HOME").map(|s| s.as_str()), Some("/nonexistent"));
    }

    #[test]
    fn empty_entry_does_not_match() {
        let entry = HumanClientEntry {
            name: "empty".into(),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        };
        let id = test_identity();
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn config_rejects_empty_human_client_entry() {
        let toml_str = r#"
[[known_human_clients]]
name = "empty-entry"

[[known_human_clients]]
name = "valid-entry"
exe_path = "/usr/bin/claude*"
"#;
        let mut config: DaemonConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(config.known_human_clients.len(), 2);

        // Simulate the filtering that load_config() performs.
        config.known_human_clients.retain(|entry| {
            entry.exe_path.is_some()
                || entry.exe_sha256.is_some()
                || entry.codesign_team_id.is_some()
        });
        assert_eq!(config.known_human_clients.len(), 1);
        assert_eq!(
            config.known_human_clients[0].exe_path.as_deref(),
            Some("/usr/bin/claude*")
        );
    }

    #[test]
    fn config_toml_roundtrip() {
        let toml_str = r#"
[[known_human_clients]]
name = "claude-code"
exe_path = "/usr/bin/claude*"

[[known_human_clients]]
name = "vscode"
exe_sha256 = "deadbeef"
"#;
        let config: DaemonConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(config.known_human_clients.len(), 2);
        assert_eq!(
            config.known_human_clients[0].exe_path.as_deref(),
            Some("/usr/bin/claude*")
        );
        assert_eq!(
            config.known_human_clients[1].exe_sha256.as_deref(),
            Some("deadbeef")
        );
    }

    // -----------------------------------------------------------------------
    // PID file tests
    // -----------------------------------------------------------------------

    #[test]
    fn pid_file_acquire_creates_file_with_pid() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let guard = PidFileGuard::acquire(pid_path.clone()).unwrap();
        let contents = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(contents, format!("{}", std::process::id()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = pid_path.metadata().unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_file_double_acquire_fails() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let _guard1 = PidFileGuard::acquire(pid_path.clone()).unwrap();
        let result = PidFileGuard::acquire(pid_path.clone());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(err.to_string().contains("daemon already running"));

        drop(_guard1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_file_cleaned_up_on_drop() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let guard = PidFileGuard::acquire(pid_path.clone()).unwrap();
        assert!(pid_path.exists());
        drop(guard);
        assert!(!pid_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_file_reacquire_after_drop() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let guard1 = PidFileGuard::acquire(pid_path.clone()).unwrap();
        drop(guard1);
        // Should succeed after first guard is dropped.
        let _guard2 = PidFileGuard::acquire(pid_path.clone()).unwrap();

        drop(_guard2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Rate limiter tests
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_allows_burst() {
        let mut rl = ConnectionRateLimiter::new(5, 10.0);
        for _ in 0..5 {
            assert!(rl.check());
        }
    }

    #[test]
    fn rate_limiter_rejects_above_burst() {
        let mut rl = ConnectionRateLimiter::new(3, 10.0);
        assert!(rl.check());
        assert!(rl.check());
        assert!(rl.check());
        // 4th should be rejected (burst = 3).
        assert!(!rl.check());
    }

    #[test]
    fn rate_limiter_rejects_above_sustained() {
        // sustained_per_sec = 2 means max 2 requests in the 1s window.
        let mut rl = ConnectionRateLimiter::new(10, 2.0);
        assert!(rl.check());
        assert!(rl.check());
        // 3rd should be rejected (sustained = 2).
        assert!(!rl.check());
    }

    // -----------------------------------------------------------------------
    // api_version tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ping_includes_api_version() {
        let state = make_test_state();
        let req = Request {
            id: 1,
            method: "ping".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        let result = resp.result.unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["api_version"], opaque_core::API_VERSION);
    }

    #[tokio::test]
    async fn version_includes_api_version() {
        let state = make_test_state();
        let req = Request {
            id: 2,
            method: "version".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        let result = resp.result.unwrap();
        assert!(result["version"].is_string());
        assert_eq!(result["api_version"], opaque_core::API_VERSION);
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let state = make_test_state();
        let req = Request {
            id: 3,
            method: "nonexistent".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, "unknown_method");
    }

    #[tokio::test]
    async fn agent_session_start_allowed_for_agent_when_not_enforced() {
        let state = make_test_state();
        let req = Request {
            id: 4,
            method: "agent_session_start".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Agent, None).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("result expected");
        assert!(result.get("session_id").and_then(|v| v.as_str()).is_some());
        assert!(
            result
                .get("session_token")
                .and_then(|v| v.as_str())
                .is_some()
        );
    }

    #[tokio::test]
    async fn agent_session_start_denied_for_agent_when_enforced() {
        let mut state = make_test_state();
        state.config.enforce_agent_sessions = true;
        let req = Request {
            id: 5,
            method: "agent_session_start".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Agent, None).await;
        let err = resp.error.expect("expected permission denial");
        assert_eq!(err.code, "permission_denied");
    }

    #[tokio::test]
    async fn validate_agent_session_token_uid_scoped() {
        let state = make_test_state();
        let session = AgentSession {
            session_id: "s1".into(),
            token: "tok1".into(),
            created_by_uid: 501,
            expires_at: SystemTime::now() + std::time::Duration::from_secs(300),
            label: Some("test".into()),
        };
        state
            .agent_sessions
            .write()
            .await
            .insert(session.session_id.clone(), session);

        let ok = validate_agent_session_token(&state, "tok1", 501).await;
        assert_eq!(ok.as_deref(), Some("s1"));

        let wrong_uid = validate_agent_session_token(&state, "tok1", 502).await;
        assert!(wrong_uid.is_none());
    }

    #[tokio::test]
    async fn enforce_agent_sessions_rejects_unwrapped_and_allows_session_token() {
        let mut state = make_test_state();
        state.config.enforce_agent_sessions = true;

        let uid = unsafe { libc::getuid() } as u32;
        state.agent_sessions.write().await.insert(
            "session-1".into(),
            AgentSession {
                session_id: "session-1".into(),
                token: "token-1".into(),
                created_by_uid: uid,
                expires_at: SystemTime::now() + std::time::Duration::from_secs(60),
                label: Some("test".into()),
            },
        );

        let state = Arc::new(state);
        let codec = || {
            LengthDelimitedCodec::builder()
                .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
                .new_codec()
        };

        // Unwrapped agent-style request: handshake has daemon token only.
        let (client_stream, server_stream) = UnixStream::pair().expect("unix pair");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_task = tokio::spawn(handle_conn(state.clone(), server_stream, shutdown_rx));
        let mut client = Framed::new(client_stream, codec());

        let direct_hs = serde_json::json!({
            "handshake": "v1",
            "daemon_token": "test_token",
        });
        client
            .send(Bytes::from(
                serde_json::to_vec(&direct_hs).expect("serialize handshake"),
            ))
            .await
            .expect("send handshake");

        let ping = Request {
            id: 1,
            method: "ping".into(),
            params: serde_json::Value::Null,
        };
        let _ = client
            .send(Bytes::from(
                serde_json::to_vec(&ping).expect("serialize ping"),
            ))
            .await;

        match tokio::time::timeout(std::time::Duration::from_secs(1), client.next()).await {
            Ok(None) | Ok(Some(Err(_))) => {}
            Ok(Some(Ok(frame))) => panic!("unexpected frame on rejected connection: {frame:?}"),
            Err(_) => panic!("timed out waiting for rejected connection to close"),
        }

        drop(client);
        let direct_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .expect("server task timeout")
            .expect("server task join");
        assert!(direct_result.is_ok(), "server error: {direct_result:?}");

        // Wrapped agent-style request: includes valid session token.
        let (client_stream, server_stream) = UnixStream::pair().expect("unix pair");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_task = tokio::spawn(handle_conn(state.clone(), server_stream, shutdown_rx));
        let mut client = Framed::new(client_stream, codec());

        let wrapped_hs = serde_json::json!({
            "handshake": "v1",
            "daemon_token": "test_token",
            "session_token": "token-1",
        });
        client
            .send(Bytes::from(
                serde_json::to_vec(&wrapped_hs).expect("serialize handshake"),
            ))
            .await
            .expect("send handshake");
        client
            .send(Bytes::from(
                serde_json::to_vec(&ping).expect("serialize ping"),
            ))
            .await
            .expect("send ping");

        let frame = tokio::time::timeout(std::time::Duration::from_secs(1), client.next())
            .await
            .expect("timed out waiting for ping response")
            .expect("connection closed unexpectedly")
            .expect("frame read failed");
        let resp: Response = serde_json::from_slice(&frame).expect("response decode");
        assert!(
            resp.error.is_none(),
            "unexpected daemon error: {:?}",
            resp.error
        );
        assert_eq!(
            resp.result
                .as_ref()
                .and_then(|r| r.get("ok"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        drop(client);
        let wrapped_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .expect("server task timeout")
            .expect("server task join");
        assert!(wrapped_result.is_ok(), "server error: {wrapped_result:?}");
    }

    // -----------------------------------------------------------------------
    // Request timeout test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn request_timeout_produces_timeout_response() {
        tokio::time::pause();
        let slow_future = async {
            tokio::time::sleep(std::time::Duration::from_secs(200)).await;
            Response::ok(1, serde_json::json!({"ok": true}))
        };
        let req_id = 42u64;
        let resp =
            match tokio::time::timeout(std::time::Duration::from_secs(120), slow_future).await {
                Ok(r) => r,
                Err(_) => Response::err(Some(req_id), "timeout", "request timed out"),
            };
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, "timeout");
        assert_eq!(resp.id, Some(42));
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_test_state() -> DaemonState {
        let registry = OperationRegistry::new();
        let policy = PolicyEngine::with_rules(vec![]);
        let audit = Arc::new(TracingAuditEmitter::new());
        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .approval_gate(Box::new(NativeApprovalGate))
            .audit(audit)
            .build();
        DaemonState {
            enclave: Arc::new(enclave),
            config: DaemonConfig::default(),
            version: version_string(),
            daemon_token: "test_token".into(),
            agent_sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        }
    }
}
