use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db};
use opaque_core::policy::PolicyRule;
use opaque_core::profile;
use opaque_core::proto::{Request, Response};
use opaque_core::socket::{socket_path, verify_socket_safety};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Name of the daemon token file expected next to the socket.
const DAEMON_TOKEN_FILENAME: &str = "daemon.token";

/// Default sample config embedded in the binary for `opaque init`.
const SAMPLE_CONFIG: &str = r#"# Opaque configuration file
# See https://github.com/anthropics/opaque for documentation.
#
# Rules are evaluated in order; the first matching rule wins.
# Default behavior is deny-all (no rules = nothing is permitted).

# Example: Allow Claude Code to sync GitHub Actions secrets for your org.
# Requires biometric approval on first use, then a 5-minute lease.
#
# [[rules]]
# name = "allow-claude-github-secrets"
# operation_pattern = "github.set_actions_secret"
# allow = true
# client_types = ["agent", "human"]
#
# [rules.client]
# exe_path = "/usr/bin/claude*"
#
# [rules.target]
# fields = { repo = "myorg/*" }
#
# [rules.workspace]
#
# [rules.secret_names]
# patterns = ["GH_*"]
#
# [rules.approval]
# require = "first_use"
# factors = ["local_bio"]
# lease_ttl = 300
"#;

#[derive(Debug, Parser)]
#[command(name = "opaque", version)]
struct Cli {
    /// Override the Unix socket path (otherwise uses OPAQUE_SOCK / XDG_RUNTIME_DIR / ~/.opaque/run).
    #[arg(long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Check daemon liveness.
    Ping,
    /// Read daemon version.
    Version,
    /// Debug client identity (placeholder).
    Whoami,
    /// Execute an operation through the enclave.
    Execute {
        /// Operation name (e.g. "test.noop", "github.set_actions_secret").
        operation: String,

        /// Target key=value pairs (repeatable). E.g. --target repo=org/myrepo
        #[arg(long, short = 't', value_parser = parse_kv)]
        target: Vec<(String, String)>,

        /// Secret ref names (repeatable). E.g. --secret JWT --secret DB_PASSWORD
        #[arg(long, short = 's')]
        secret: Vec<String>,

        /// Attach git workspace context from the current directory.
        #[arg(long, default_value_t = false)]
        workspace: bool,
    },
    /// Manage policy configuration.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Initialize Opaque configuration directory.
    Init {
        /// Overwrite existing config file.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Execute a command in a sandboxed environment.
    Exec {
        /// Profile name (loads ~/.opaque/profiles/<name>.toml).
        #[arg(long)]
        profile: String,

        /// Command and arguments to execute in the sandbox.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Manage execution profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Query the audit log.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyAction {
    /// Validate policy configuration file.
    Check {
        /// Path to config file (default: ~/.opaque/config.toml or $OPAQUE_CONFIG).
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileAction {
    /// List available profiles.
    List,
    /// Show a profile's contents.
    Show {
        /// Profile name.
        name: String,
    },
    /// Validate a profile.
    Validate {
        /// Profile name.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuditAction {
    /// Show recent audit events.
    Tail {
        /// Maximum number of events to display.
        #[arg(long, default_value = "50")]
        limit: usize,

        /// Filter by event kind (e.g. "request.received", "policy.denied").
        #[arg(long)]
        kind: Option<String>,

        /// Filter by operation name.
        #[arg(long)]
        operation: Option<String>,

        /// Show events since duration ago (e.g. "30m", "1h", "7d").
        #[arg(long)]
        since: Option<String>,

        /// Filter by request correlation ID.
        #[arg(long)]
        request_id: Option<String>,
    },
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((k.to_owned(), v.to_owned()))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let cmd = cli.cmd.unwrap_or(Cmd::Ping);

    // Handle commands that don't need a daemon connection.
    match &cmd {
        Cmd::Policy { action } => match action {
            PolicyAction::Check { file } => {
                match policy_check_path(file.as_deref()) {
                    Ok(msg) => {
                        println!("{msg}");
                    }
                    Err(e) => {
                        eprintln!("opaque: {e}");
                        std::process::exit(1);
                    }
                }
                return;
            }
        },
        Cmd::Init { force } => {
            match run_init_at(&default_opaque_dir(), *force) {
                Ok(msg) => {
                    println!("{msg}");
                }
                Err(e) => {
                    eprintln!("opaque: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Profile { action } => {
            match run_profile_action(action) {
                Ok(msg) => {
                    println!("{msg}");
                }
                Err(e) => {
                    eprintln!("opaque: {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Audit { action } => {
            match action {
                AuditAction::Tail {
                    limit,
                    kind,
                    operation,
                    since,
                    request_id,
                } => {
                    match run_audit_tail(
                        *limit,
                        kind.as_deref(),
                        operation.as_deref(),
                        since.as_deref(),
                        request_id.as_deref(),
                    ) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("opaque: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            return;
        }
        _ => {}
    }

    let sock = cli.socket.unwrap_or_else(socket_path);

    let (method, params) = match cmd {
        Cmd::Ping => ("ping", serde_json::Value::Null),
        Cmd::Version => ("version", serde_json::Value::Null),
        Cmd::Whoami => ("whoami", serde_json::Value::Null),
        Cmd::Execute {
            operation,
            target,
            secret,
            workspace: attach_ws,
        } => {
            let target_map: serde_json::Map<String, serde_json::Value> = target
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            let ws = if attach_ws {
                resolve_workspace_context()
            } else {
                None
            };
            let params = serde_json::json!({
                "operation": operation,
                "target": target_map,
                "secret_ref_names": secret,
                "workspace": ws,
            });
            ("execute", params)
        }
        Cmd::Exec { profile, command } => {
            let params = serde_json::json!({
                "profile": profile,
                "command": command,
            });
            ("exec", params)
        }
        // Already handled above; unreachable.
        Cmd::Policy { .. } | Cmd::Init { .. } | Cmd::Audit { .. } | Cmd::Profile { .. } => {
            unreachable!()
        }
    };

    match call(&sock, method, params).await {
        Ok(resp) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string())
            );
        }
        Err(e) => {
            eprintln!("opaque: {e}");
            std::process::exit(1);
        }
    }
}

/// Read the daemon token from `<socket_dir>/daemon.token`.
fn read_daemon_token(sock: &Path) -> std::io::Result<String> {
    let token_path = sock
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "socket path has no parent directory",
            )
        })?
        .join(DAEMON_TOKEN_FILENAME);

    std::fs::read_to_string(&token_path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "failed to read daemon token at {}: {e} (is opaqued running?)",
                token_path.display()
            ),
        )
    })
}

/// Resolve the git workspace context from the current working directory.
///
/// Runs git commands to determine repo root, remote URL, branch, HEAD SHA,
/// and dirty status. Returns `None` if not in a git repository.
fn resolve_workspace_context() -> Option<serde_json::Value> {
    use std::process::Command;

    // Check if we're in a git repo and get the root.
    let repo_root = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

    let remote_url = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let head_sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    Some(serde_json::json!({
        "repo_root": repo_root,
        "remote_url": remote_url,
        "branch": branch,
        "head_sha": head_sha,
        "dirty": dirty,
    }))
}

async fn call(
    sock: &PathBuf,
    method: &str,
    params: serde_json::Value,
) -> std::io::Result<Response> {
    // Verify socket ownership and permissions before connecting.
    verify_socket_safety(sock)?;

    // Read daemon token before connecting.
    let daemon_token = read_daemon_token(sock)?;

    let stream = tokio::time::timeout(Duration::from_secs(30), UnixStream::connect(sock))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connection timed out: {}", sock.display()),
            )
        })?
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "{e} (is opaqued running? expected socket at {})",
                    sock.display()
                ),
            )
        })?;

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    // Send handshake as the first frame.
    let handshake = serde_json::json!({
        "handshake": "v1",
        "daemon_token": daemon_token,
    });
    let hs_bytes = serde_json::to_vec(&handshake).map_err(std::io::Error::other)?;
    framed.send(Bytes::from(hs_bytes)).await?;

    let req = Request {
        id: 1,
        method: method.to_string(),
        params,
    };
    let out = serde_json::to_vec(&req).map_err(std::io::Error::other)?;
    framed.send(Bytes::from(out)).await?;

    let Some(frame) = framed.next().await else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "no response from daemon (handshake may have been rejected)",
        ));
    };
    let frame = frame?;

    let resp: Response = serde_json::from_slice(&frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(resp)
}

// ---------------------------------------------------------------------------
// audit tail
// ---------------------------------------------------------------------------

/// Run the `audit tail` subcommand: query the local SQLite audit DB.
fn run_audit_tail(
    limit: usize,
    kind: Option<&str>,
    operation: Option<&str>,
    since: Option<&str>,
    request_id: Option<&str>,
) -> Result<(), String> {
    let db_path = default_opaque_dir().join("audit.db");
    if !db_path.exists() {
        return Err(format!(
            "audit database not found at {} (is opaqued running?)",
            db_path.display()
        ));
    }

    let kind = match kind {
        Some(s) => Some(
            s.parse::<AuditEventKind>()
                .map_err(|e| format!("invalid --kind: {e}"))?,
        ),
        None => None,
    };

    let since_ms = match since {
        Some(s) => {
            let duration_ms = parse_duration_to_ms(s)?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            Some(now_ms - duration_ms)
        }
        None => None,
    };

    let request_id = match request_id {
        Some(s) => {
            Some(uuid::Uuid::parse_str(s).map_err(|e| format!("invalid --request-id: {e}"))?)
        }
        None => None,
    };

    let filter = AuditFilter {
        kind,
        operation: operation.map(|s| s.to_owned()),
        since_ms,
        limit,
        request_id,
    };

    let events = query_audit_db(&db_path, &filter).map_err(|e| format!("query failed: {e}"))?;

    if events.is_empty() {
        println!("no audit events found");
        return Ok(());
    }

    for event in &events {
        let ts = chrono_format_ms(event.ts_utc_ms);
        let kind = &event.kind;
        let op = event.operation.as_deref().unwrap_or("-");
        let outcome = event.outcome.as_deref().unwrap_or("-");
        let rid = event
            .request_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".into());
        println!("{ts}  {kind:<24}  op={op:<30}  outcome={outcome:<8}  req={rid}");
    }

    Ok(())
}

/// Parse a simple duration string like "30m", "1h", "7d" to milliseconds.
fn parse_duration_to_ms(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".into());
    }

    let (num_str, suffix) = s.split_at(s.len() - 1);
    let num: i64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration: '{s}' (expected e.g. '30m', '1h', '7d')"))?;

    let multiplier = match suffix {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => {
            return Err(format!(
                "unknown duration suffix '{suffix}' (expected s, m, h, or d)"
            ));
        }
    };

    Ok(num * multiplier)
}

/// Format a millisecond timestamp as a human-readable UTC string.
fn chrono_format_ms(ms: i64) -> String {
    let secs = ms / 1000;
    let millis = (ms % 1000) as u32;
    let dt = std::time::UNIX_EPOCH + std::time::Duration::new(secs as u64, millis * 1_000_000);
    let datetime: std::time::SystemTime = dt;
    // Simple formatting without chrono dependency.
    let duration = datetime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = duration.as_secs();
    let days = total_secs / 86400;
    let rem = total_secs % 86400;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let seconds = rem % 60;
    // Approximate date from days since epoch (good enough for display).
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Policy config types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct PolicyConfig {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

// ---------------------------------------------------------------------------
// policy check
// ---------------------------------------------------------------------------

/// Resolve the config path: --file flag > $OPAQUE_CONFIG > ~/.opaque/config.toml.
fn resolve_config_path(file: Option<&Path>) -> PathBuf {
    if let Some(p) = file {
        return p.to_path_buf();
    }
    if let Ok(p) = std::env::var("OPAQUE_CONFIG") {
        return PathBuf::from(p);
    }
    default_opaque_dir().join("config.toml")
}

/// Validate a policy config file. Returns a success message or an error string.
fn policy_check_path(file: Option<&Path>) -> Result<String, String> {
    let path = resolve_config_path(file);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let config: PolicyConfig = toml_edit::de::from_str(&contents)
        .map_err(|e| format!("TOML parse error in {}: {e}", path.display()))?;

    // Additional semantic validation.
    let mut errors: Vec<String> = Vec::new();
    for (i, rule) in config.rules.iter().enumerate() {
        let prefix = format!("rules[{i}] ({:?})", rule.name);
        if rule.name.is_empty() {
            errors.push(format!("{prefix}: name must be non-empty"));
        }
        if rule.operation_pattern.is_empty() {
            errors.push(format!("{prefix}: operation_pattern must be non-empty"));
        }
        if rule.client_types.is_empty() {
            errors.push(format!("{prefix}: client_types must not be empty"));
        }
        if let Some(ttl) = rule.approval.lease_ttl
            && ttl.as_secs() == 0
        {
            errors.push(format!("{prefix}: approval.lease_ttl must be > 0"));
        }
    }

    if !errors.is_empty() {
        return Err(format!(
            "policy validation failed:\n  {}",
            errors.join("\n  ")
        ));
    }

    Ok(format!("policy OK: {} rules loaded", config.rules.len()))
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// Return the default ~/.opaque directory.
fn default_opaque_dir() -> PathBuf {
    dirs_or_home().join(".opaque")
}

/// Best-effort home directory lookup.
fn dirs_or_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Initialize the opaque config directory at the given base path.
fn run_init_at(base: &Path, force: bool) -> Result<String, String> {
    let config_path = base.join("config.toml");
    let run_dir = base.join("run");

    // Check for existing config (unless --force).
    if config_path.exists() && !force {
        return Err(format!(
            "config already exists at {} (use --force to overwrite)",
            config_path.display()
        ));
    }

    let profiles_dir = base.join("profiles");

    // Create directories with mode 0700.
    create_dir_0700(base)?;
    create_dir_0700(&run_dir)?;
    create_dir_0700(&profiles_dir)?;

    // Write config file.
    std::fs::write(&config_path, SAMPLE_CONFIG)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    let mut summary = String::new();
    summary.push_str(&format!("initialized opaque at {}\n", base.display()));
    summary.push_str(&format!("  created {}\n", base.display()));
    summary.push_str(&format!("  created {}\n", run_dir.display()));
    summary.push_str(&format!("  created {}\n", profiles_dir.display()));
    summary.push_str(&format!("  wrote {}", config_path.display()));
    Ok(summary)
}

/// Create a directory with mode 0700 if it does not already exist.
fn create_dir_0700(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Profile management
// ---------------------------------------------------------------------------

/// Handle profile subcommands (list, show, validate).
fn run_profile_action(action: &ProfileAction) -> Result<String, String> {
    let profiles_dir = profile::profiles_dir();

    match action {
        ProfileAction::List => {
            if !profiles_dir.exists() {
                return Ok("no profiles directory found (run `opaque init` first)".into());
            }

            let entries = std::fs::read_dir(&profiles_dir)
                .map_err(|e| format!("failed to read profiles dir: {e}"))?;

            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
                .filter_map(|e| {
                    e.path()
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                })
                .collect();

            names.sort();

            if names.is_empty() {
                return Ok("no profiles found".into());
            }

            let mut output = format!("{} profile(s) found:\n", names.len());
            for name in &names {
                output.push_str(&format!("  {name}\n"));
            }
            Ok(output.trim_end().to_string())
        }

        ProfileAction::Show { name } => {
            let path = profiles_dir.join(format!("{name}.toml"));
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read profile '{name}': {e}"))?;
            Ok(contents)
        }

        ProfileAction::Validate { name } => {
            let path = profiles_dir.join(format!("{name}.toml"));
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read profile '{name}': {e}"))?;

            profile::load_profile(&contents, Some(name))
                .map_err(|e| format!("profile validation failed: {e}"))?;

            Ok(format!("profile '{name}' is valid"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Write a TOML string to a temp file and run policy_check_path on it.
    fn check_toml(content: &str) -> Result<String, String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, content).unwrap();
        policy_check_path(Some(path.as_path()))
    }

    #[test]
    fn valid_toml_with_rules() {
        let toml = r#"
[[rules]]
name = "allow-github"
operation_pattern = "github.*"
allow = true
client_types = ["agent", "human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]

[rules.secret_names]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300
"#;
        let result = check_toml(toml);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert!(result.unwrap().contains("1 rules loaded"));
    }

    #[test]
    fn valid_toml_empty_rules() {
        let toml = "";
        let result = check_toml(toml);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("0 rules loaded"));
    }

    #[test]
    fn invalid_toml_syntax() {
        let toml = "[[rules]\nname = broken";
        let result = check_toml(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TOML parse error"));
    }

    #[test]
    fn validation_error_empty_name() {
        let toml = r#"
[[rules]]
name = ""
operation_pattern = "github.*"
allow = true
client_types = ["agent"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = ["local_bio"]
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("name must be non-empty"), "got: {err}");
    }

    #[test]
    fn validation_error_empty_operation_pattern() {
        let toml = r#"
[[rules]]
name = "test"
operation_pattern = ""
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("operation_pattern must be non-empty"),
            "got: {err}"
        );
    }

    #[test]
    fn validation_error_empty_client_types() {
        let toml = r#"
[[rules]]
name = "test"
operation_pattern = "github.*"
allow = true
client_types = []

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("client_types must not be empty"), "got: {err}");
    }

    #[test]
    fn validation_error_zero_lease_ttl() {
        let toml = r#"
[[rules]]
name = "test"
operation_pattern = "github.*"
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 0
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("lease_ttl must be > 0"), "got: {err}");
    }

    #[test]
    fn missing_file_produces_error() {
        let result = policy_check_path(Some(Path::new("/nonexistent/config.toml")));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn init_creates_directory_structure() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        let result = run_init_at(&base, false);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        assert!(base.exists());
        assert!(base.join("run").exists());
        assert!(base.join("config.toml").exists());

        let content = fs::read_to_string(base.join("config.toml")).unwrap();
        assert!(content.contains("Opaque configuration file"));
    }

    #[test]
    fn init_existing_config_warns() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("config.toml"), "existing").unwrap();

        let result = run_init_at(&base, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn init_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("config.toml"), "old content").unwrap();

        let result = run_init_at(&base, true);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let content = fs::read_to_string(base.join("config.toml")).unwrap();
        assert!(content.contains("Opaque configuration file"));
        assert!(!content.contains("old content"));
    }

    #[test]
    fn toml_with_extra_fields_ignored() {
        let toml = r#"
[daemon]
port = 1234

[[rules]]
name = "test"
operation_pattern = "test.*"
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "never"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert!(result.unwrap().contains("1 rules loaded"));
    }

    #[test]
    fn multiple_validation_errors_reported() {
        let toml = r#"
[[rules]]
name = ""
operation_pattern = ""
allow = true
client_types = []

[rules.client]

[rules.target]
fields = {}

[rules.workspace]
[rules.secret_names]

[rules.approval]
require = "always"
factors = []
"#;
        let result = check_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("name must be non-empty"), "got: {err}");
        assert!(
            err.contains("operation_pattern must be non-empty"),
            "got: {err}"
        );
        assert!(err.contains("client_types must not be empty"), "got: {err}");
    }

    #[test]
    fn init_directory_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join(".opaque");

        run_init_at(&base, false).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&base).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "base dir should be 0700, got {mode:o}");

            let run_mode = fs::metadata(base.join("run")).unwrap().permissions().mode() & 0o777;
            assert_eq!(run_mode, 0o700, "run dir should be 0700, got {run_mode:o}");
        }
    }

    #[test]
    fn sample_config_parses_successfully() {
        // Verify the embedded SAMPLE_CONFIG is valid TOML that deserializes.
        let config: PolicyConfig = toml_edit::de::from_str(SAMPLE_CONFIG).unwrap();
        // All example rules are commented out, so 0 rules.
        assert_eq!(config.rules.len(), 0);
    }
}
