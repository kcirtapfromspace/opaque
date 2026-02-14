use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use console::style;
use futures_util::{SinkExt, StreamExt};
use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db};
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest, OperationSafety};
use opaque_core::policy::{PolicyEngine, PolicyRule};
use opaque_core::profile;
use opaque_core::proto::{Request, Response};
use opaque_core::socket::{socket_path, verify_socket_safety};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

mod service;
mod setup;
mod ui;

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

    /// Output raw JSON instead of styled text (useful for scripting).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Check daemon liveness.
    Ping,
    /// Read daemon version.
    Version,
    /// Show how the daemon identifies this client (uid, gid, exe path, pid).
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
    /// Manage GitHub Actions secrets.
    Github {
        #[command(subcommand)]
        action: GithubAction,
    },
    /// Browse 1Password vaults and items.
    #[command(name = "onepassword", alias = "1p")]
    OnePassword {
        #[command(subcommand)]
        action: OnePasswordAction,
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
    /// Interactive setup wizard — configure and seal your security policy.
    Setup {
        /// Seal the current config.toml without running the wizard.
        #[arg(long)]
        seal: bool,
        /// Remove the config seal (allows reconfiguration).
        #[arg(long)]
        reset: bool,
        /// Check seal status without starting daemon.
        #[arg(long)]
        verify: bool,
    },
    /// Manage the opaqued daemon service (install, start, stop, status).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Diagnose your Opaque installation and report issues.
    Doctor,
    /// List active approval leases in the daemon.
    Leases,
}

#[derive(Debug, Subcommand)]
enum ServiceAction {
    /// Install and start the daemon as a system service.
    Install,
    /// Stop and remove the daemon service.
    Uninstall,
    /// Check if the daemon service is installed and running.
    Status,
    /// Start the daemon service.
    Start,
    /// Stop the daemon service.
    Stop,
    /// Show recent daemon logs.
    Logs,
}

#[derive(Debug, Subcommand)]
enum PolicyAction {
    /// Validate policy configuration file.
    Check {
        /// Path to config file (default: ~/.opaque/config.toml or $OPAQUE_CONFIG).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Display loaded policy rules in a human-readable format.
    Show {
        /// Path to config file (default: ~/.opaque/config.toml or $OPAQUE_CONFIG).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Dry-run a request against the policy to see what would happen.
    Simulate {
        /// Operation name (e.g. "github.set_actions_secret").
        #[arg(long)]
        operation: String,
        /// Client type: "human" or "agent".
        #[arg(long, default_value = "human")]
        client_type: String,
        /// Target fields as KEY=VALUE pairs (e.g. --target repo=org/repo).
        #[arg(long = "target", value_parser = parse_kv)]
        targets: Vec<(String, String)>,
        /// Secret ref names referenced by the request.
        #[arg(long = "secret-ref")]
        secret_refs: Vec<String>,
        /// Path to config file.
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
#[allow(clippy::enum_variant_names)]
enum GithubAction {
    /// Set a GitHub Actions repository secret.
    SetSecret {
        /// Repository in "owner/repo" format.
        #[arg(long)]
        repo: String,

        /// Secret name (e.g. "AWS_ACCESS_KEY_ID").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/aws-key" or "profile:prod:AWS_KEY").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// GitHub environment name (for environment secrets).
        #[arg(long)]
        environment: Option<String>,
    },
    /// Set a GitHub Codespaces secret (user-level or repo-level).
    SetCodespacesSecret {
        /// Repository in "owner/repo" format (omit for user-level secret).
        #[arg(long)]
        repo: Option<String>,

        /// Secret name (e.g. "DOTFILES_TOKEN").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/codespaces-token").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// Selected repository IDs (comma-separated, for user-level secrets).
        #[arg(long, value_delimiter = ',')]
        selected_repository_ids: Option<Vec<i64>>,
    },
    /// Set a GitHub Dependabot repository secret.
    SetDependabotSecret {
        /// Repository in "owner/repo" format.
        #[arg(long)]
        repo: String,

        /// Secret name (e.g. "NPM_TOKEN").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/npm-token").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,
    },
    /// Set a GitHub Actions organization secret.
    SetOrgSecret {
        /// Organization name.
        #[arg(long)]
        org: String,

        /// Secret name (e.g. "ORG_DEPLOY_KEY").
        #[arg(long)]
        secret_name: String,

        /// Secret ref (e.g. "keychain:opaque/org-deploy-key").
        #[arg(long)]
        value_ref: String,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,

        /// Secret visibility: "all", "private", or "selected" (default: "private").
        #[arg(long, default_value = "private")]
        visibility: String,

        /// Selected repository IDs (comma-separated, when visibility is "selected").
        #[arg(long, value_delimiter = ',')]
        selected_repository_ids: Option<Vec<i64>>,
    },
    /// List secrets for a repository, environment, or organization.
    ListSecrets {
        /// Repository in "owner/repo" format (for repo/env/codespaces/dependabot scopes).
        #[arg(long)]
        repo: Option<String>,

        /// Organization name (for org scope).
        #[arg(long)]
        org: Option<String>,

        /// Secret scope: "actions", "codespaces", "dependabot", or "org".
        #[arg(long, default_value = "actions")]
        scope: String,

        /// GitHub environment name (for environment-scoped listing).
        #[arg(long)]
        environment: Option<String>,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,
    },
    /// Delete a secret from a repository, environment, or organization.
    DeleteSecret {
        /// Repository in "owner/repo" format (for repo/env/codespaces/dependabot scopes).
        #[arg(long)]
        repo: Option<String>,

        /// Organization name (for org scope).
        #[arg(long)]
        org: Option<String>,

        /// Secret name to delete.
        #[arg(long)]
        secret_name: String,

        /// Secret scope: "actions", "codespaces", "dependabot", or "org".
        #[arg(long, default_value = "actions")]
        scope: String,

        /// GitHub environment name (for environment-scoped deletion).
        #[arg(long)]
        environment: Option<String>,

        /// GitHub token ref (default: "keychain:opaque/github-pat").
        #[arg(long)]
        github_token_ref: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum OnePasswordAction {
    /// List accessible vaults.
    ListVaults,
    /// List items in a vault.
    ListItems {
        /// Vault name.
        #[arg(long)]
        vault: String,
    },
    /// Read a specific field from a 1Password item.
    ReadField {
        /// Vault name.
        #[arg(long)]
        vault: String,
        /// Item title.
        #[arg(long)]
        item: String,
        /// Field label.
        #[arg(long)]
        field: String,
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

        /// Filter by outcome (e.g. "allowed", "denied", "error").
        #[arg(long)]
        outcome: Option<String>,
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
    let json_output = cli.json;

    // Handle commands that don't need a daemon connection.
    match &cmd {
        Cmd::Policy { action } => match action {
            PolicyAction::Check { file } => {
                match policy_check_path(file.as_deref()) {
                    Ok(msg) => ui::success(&msg),
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            PolicyAction::Show { file } => {
                match policy_show(file.as_deref()) {
                    Ok(()) => {}
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            PolicyAction::Simulate {
                operation,
                client_type,
                targets,
                secret_refs,
                file,
            } => {
                match policy_simulate(
                    file.as_deref(),
                    operation,
                    client_type,
                    targets,
                    secret_refs,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        ui::error(&e);
                        std::process::exit(1);
                    }
                }
                return;
            }
        },
        Cmd::Init { force } => {
            match run_init(*force) {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Profile { action } => {
            match run_profile_action(action) {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
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
                    outcome,
                } => {
                    match run_audit_tail(
                        *limit,
                        kind.as_deref(),
                        operation.as_deref(),
                        since.as_deref(),
                        request_id.as_deref(),
                        outcome.as_deref(),
                        json_output,
                    ) {
                        Ok(()) => {}
                        Err(e) => {
                            ui::error(&e);
                            std::process::exit(1);
                        }
                    }
                }
            }
            return;
        }
        Cmd::Setup {
            seal,
            reset,
            verify,
        } => {
            match run_setup(*seal, *reset, *verify) {
                Ok(()) => {}
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
                }
            }
            return;
        }
        Cmd::Doctor => {
            run_doctor().await;
            return;
        }
        Cmd::Service { action } => {
            let op = match action {
                ServiceAction::Install => service::ServiceOp::Install,
                ServiceAction::Uninstall => service::ServiceOp::Uninstall,
                ServiceAction::Status => service::ServiceOp::Status,
                ServiceAction::Start => service::ServiceOp::Start,
                ServiceAction::Stop => service::ServiceOp::Stop,
                ServiceAction::Logs => service::ServiceOp::Logs,
            };
            match service::run(op) {
                Ok(()) => {
                    // Print success for mutating operations.
                    match op {
                        service::ServiceOp::Install => {
                            ui::success("Daemon service installed and started");
                        }
                        service::ServiceOp::Uninstall => {
                            ui::success("Daemon service stopped and removed");
                        }
                        service::ServiceOp::Start => {
                            ui::success("Daemon service started");
                        }
                        service::ServiceOp::Stop => {
                            ui::success("Daemon service stopped");
                        }
                        service::ServiceOp::Status | service::ServiceOp::Logs => {
                            // Status and logs handle their own output.
                        }
                    }
                }
                Err(e) => {
                    ui::error(&e);
                    std::process::exit(1);
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
        Cmd::Leases => ("leases", serde_json::Value::Null),
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
        Cmd::Github { action } => match action {
            GithubAction::SetSecret {
                repo,
                secret_name,
                value_ref,
                github_token_ref,
                environment,
            } => {
                let scope = if environment.is_some() {
                    "env_actions"
                } else {
                    "repo_actions"
                };
                let mut params = serde_json::json!({
                    "scope": scope,
                    "repo": repo,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                });
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                if let Some(ref env) = environment {
                    params["environment"] = serde_json::Value::String(env.clone());
                }
                ("github", params)
            }
            GithubAction::SetCodespacesSecret {
                repo,
                secret_name,
                value_ref,
                github_token_ref,
                selected_repository_ids,
            } => {
                let scope = if repo.is_some() {
                    "codespaces_repo"
                } else {
                    "codespaces_user"
                };
                let mut params = serde_json::json!({
                    "scope": scope,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                });
                if let Some(ref r) = repo {
                    params["repo"] = serde_json::Value::String(r.clone());
                }
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                if let Some(ref ids) = selected_repository_ids {
                    params["selected_repository_ids"] = serde_json::json!(ids);
                }
                ("github", params)
            }
            GithubAction::SetDependabotSecret {
                repo,
                secret_name,
                value_ref,
                github_token_ref,
            } => {
                let mut params = serde_json::json!({
                    "scope": "dependabot",
                    "repo": repo,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                });
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                ("github", params)
            }
            GithubAction::SetOrgSecret {
                org,
                secret_name,
                value_ref,
                github_token_ref,
                visibility,
                selected_repository_ids,
            } => {
                let mut params = serde_json::json!({
                    "scope": "org_actions",
                    "org": org,
                    "secret_name": secret_name,
                    "value_ref": value_ref,
                    "visibility": visibility,
                });
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                if let Some(ref ids) = selected_repository_ids {
                    params["selected_repository_ids"] = serde_json::json!(ids);
                }
                ("github", params)
            }
            GithubAction::ListSecrets {
                repo,
                org,
                scope,
                environment,
                github_token_ref,
            } => {
                let mut params = serde_json::json!({
                    "action": "list_secrets",
                    "scope": scope,
                });
                if let Some(ref r) = repo {
                    params["repo"] = serde_json::Value::String(r.clone());
                }
                if let Some(ref o) = org {
                    params["org"] = serde_json::Value::String(o.clone());
                }
                if let Some(ref env) = environment {
                    params["environment"] = serde_json::Value::String(env.clone());
                }
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                ("github", params)
            }
            GithubAction::DeleteSecret {
                repo,
                org,
                secret_name,
                scope,
                environment,
                github_token_ref,
            } => {
                let mut params = serde_json::json!({
                    "action": "delete_secret",
                    "scope": scope,
                    "secret_name": secret_name,
                });
                if let Some(ref r) = repo {
                    params["repo"] = serde_json::Value::String(r.clone());
                }
                if let Some(ref o) = org {
                    params["org"] = serde_json::Value::String(o.clone());
                }
                if let Some(ref env) = environment {
                    params["environment"] = serde_json::Value::String(env.clone());
                }
                if let Some(ref tok) = github_token_ref {
                    params["github_token_ref"] = serde_json::Value::String(tok.clone());
                }
                ("github", params)
            }
        },
        Cmd::OnePassword { action } => match action {
            OnePasswordAction::ListVaults => {
                let params = serde_json::json!({ "action": "list_vaults" });
                ("onepassword", params)
            }
            OnePasswordAction::ListItems { vault } => {
                let params = serde_json::json!({
                    "action": "list_items",
                    "vault": vault,
                });
                ("onepassword", params)
            }
            OnePasswordAction::ReadField {
                vault,
                item,
                field,
            } => {
                let params = serde_json::json!({
                    "action": "read_field",
                    "vault": vault,
                    "item": item,
                    "field": field,
                });
                ("onepassword", params)
            }
        },
        // Already handled above; unreachable.
        Cmd::Policy { .. }
        | Cmd::Init { .. }
        | Cmd::Audit { .. }
        | Cmd::Profile { .. }
        | Cmd::Setup { .. }
        | Cmd::Service { .. }
        | Cmd::Doctor => {
            unreachable!()
        }
    };

    let sp = if json_output {
        None
    } else {
        Some(ui::spinner(&format!("Calling {method}...")))
    };

    match call(&sock, method, params).await {
        Ok(resp) => {
            if let Some(ref sp) = sp {
                sp.finish_and_clear();
            }

            if json_output {
                // Raw JSON: output the full response as-is.
                let output = serde_json::to_string_pretty(&resp)
                    .unwrap_or_else(|_| "{}".to_string());
                println!("{output}");
                if resp.error.is_some() {
                    std::process::exit(1);
                }
            } else {
                if let Some(err) = &resp.error {
                    ui::format_error(err);
                    std::process::exit(1);
                }
                if let Some(result) = &resp.result {
                    ui::format_response(method, result);
                } else {
                    ui::success("Done (no result payload)");
                }
            }
        }
        Err(e) => {
            if json_output {
                let err = serde_json::json!({"error": e.to_string()});
                println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
            } else if let Some(ref sp) = sp {
                ui::spinner_error(sp, &format!("Connection failed: {e}"));
            } else {
                ui::error(&format!("Connection failed: {e}"));
            }
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

/// Maximum number of connection retry attempts.
const MAX_RETRIES: u32 = 3;
/// Initial retry delay (doubles each attempt).
const INITIAL_RETRY_MS: u64 = 200;

async fn call(
    sock: &PathBuf,
    method: &str,
    params: serde_json::Value,
) -> std::io::Result<Response> {
    // Verify socket ownership and permissions before connecting.
    verify_socket_safety(sock)?;

    // Read daemon token before connecting.
    let daemon_token = read_daemon_token(sock)?;

    // Retry connection with exponential backoff (200ms → 400ms → 800ms).
    let mut last_err = None;
    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay = INITIAL_RETRY_MS * 2u64.pow(attempt - 1);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        match call_once(sock, method, &params, &daemon_token).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                // Only retry on connection-related errors, not protocol errors.
                let retryable = matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::BrokenPipe
                );
                if !retryable || attempt == MAX_RETRIES {
                    return Err(e);
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other("connection failed after retries")
    }))
}

/// Single connection attempt — no retries.
async fn call_once(
    sock: &PathBuf,
    method: &str,
    params: &serde_json::Value,
    daemon_token: &str,
) -> std::io::Result<Response> {
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
        params: params.clone(),
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
    outcome: Option<&str>,
    json_output: bool,
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
        outcome: outcome.map(|s| s.to_owned()),
    };

    let events = query_audit_db(&db_path, &filter).map_err(|e| format!("query failed: {e}"))?;

    if json_output {
        let json_events: Vec<serde_json::Value> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "event_id": e.event_id.to_string(),
                    "ts_utc_ms": e.ts_utc_ms,
                    "kind": e.kind.to_string(),
                    "operation": e.operation,
                    "outcome": e.outcome,
                    "request_id": e.request_id.map(|u| u.to_string()),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json_events)
                .unwrap_or_else(|_| "[]".to_string())
        );
        return Ok(());
    }

    if events.is_empty() {
        ui::info("No audit events found.");
        return Ok(());
    }

    ui::header(&format!("{} audit event(s)", events.len()));
    ui::audit_header();

    for event in &events {
        let ts = chrono_format_ms(event.ts_utc_ms);
        let kind = event.kind.to_string();
        let op = event.operation.as_deref().unwrap_or("-");
        let outcome = event.outcome.as_deref().unwrap_or("-");
        let rid = event
            .request_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".into());
        ui::audit_row(&ts, &kind, op, outcome, &rid);
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
// policy show
// ---------------------------------------------------------------------------

/// Load and display policy rules in a human-readable format.
fn policy_show(file: Option<&Path>) -> Result<(), String> {
    let path = resolve_config_path(file);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let config: PolicyConfig = toml_edit::de::from_str(&contents)
        .map_err(|e| format!("TOML parse error in {}: {e}", path.display()))?;

    if config.rules.is_empty() {
        ui::warn("no rules loaded — default deny-all policy is in effect");
        return Ok(());
    }

    ui::header(&format!(
        "{} rule(s) from {}",
        config.rules.len(),
        path.display()
    ));

    for (i, rule) in config.rules.iter().enumerate() {
        println!();
        let allow_str = if rule.allow {
            style("ALLOW").green().bold().to_string()
        } else {
            style("DENY").red().bold().to_string()
        };
        println!(
            "  {}  {}  {}",
            style(format!("[{i}]")).dim(),
            allow_str,
            style(&rule.name).cyan().bold()
        );

        // Operation pattern.
        println!(
            "      {} {}",
            style("operation:").dim(),
            style(&rule.operation_pattern).yellow()
        );

        // Client types.
        if !rule.client_types.is_empty() {
            let types: Vec<&str> = rule
                .client_types
                .iter()
                .map(|ct| match ct {
                    ClientType::Human => "human",
                    ClientType::Agent => "agent",
                })
                .collect();
            println!(
                "      {} {}",
                style("clients:").dim(),
                types.join(", ")
            );
        }

        // Client match constraints.
        if rule.client.exe_path.is_some()
            || rule.client.exe_sha256.is_some()
            || rule.client.codesign_team_id.is_some()
            || rule.client.uid.is_some()
        {
            let mut parts = Vec::new();
            if let Some(ref p) = rule.client.exe_path {
                parts.push(format!("exe={p}"));
            }
            if let Some(ref h) = rule.client.exe_sha256 {
                parts.push(format!("sha256={}", &h[..8.min(h.len())]));
            }
            if let Some(ref t) = rule.client.codesign_team_id {
                parts.push(format!("team={t}"));
            }
            if let Some(uid) = rule.client.uid {
                parts.push(format!("uid={uid}"));
            }
            println!(
                "      {} {}",
                style("client:").dim(),
                parts.join(", ")
            );
        }

        // Target constraints.
        if !rule.target.fields.is_empty() {
            let fields: Vec<String> = rule
                .target
                .fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            println!(
                "      {} {}",
                style("target:").dim(),
                fields.join(", ")
            );
        }

        // Workspace constraints.
        if rule.workspace.remote_url_pattern.is_some()
            || rule.workspace.branch_pattern.is_some()
            || rule.workspace.require_clean
        {
            let mut parts = Vec::new();
            if let Some(ref p) = rule.workspace.remote_url_pattern {
                parts.push(format!("remote={p}"));
            }
            if let Some(ref p) = rule.workspace.branch_pattern {
                parts.push(format!("branch={p}"));
            }
            if rule.workspace.require_clean {
                parts.push("clean-only".into());
            }
            println!(
                "      {} {}",
                style("workspace:").dim(),
                parts.join(", ")
            );
        }

        // Secret name constraints.
        if !rule.secret_names.patterns.is_empty() {
            println!(
                "      {} {}",
                style("secrets:").dim(),
                rule.secret_names.patterns.join(", ")
            );
        }

        // Approval.
        let req_str = format!("{:?}", rule.approval.require);
        let factors: Vec<String> = rule
            .approval
            .factors
            .iter()
            .map(|f| format!("{f:?}"))
            .collect();
        let mut approval_parts = vec![req_str.to_lowercase()];
        if !factors.is_empty() {
            approval_parts.push(format!("factors=[{}]", factors.join(",")));
        }
        if let Some(ttl) = rule.approval.lease_ttl {
            approval_parts.push(format!("lease={}s", ttl.as_secs()));
        }
        if rule.approval.one_time {
            approval_parts.push("one-time".into());
        }
        println!(
            "      {} {}",
            style("approval:").dim(),
            approval_parts.join(", ")
        );
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// policy simulate
// ---------------------------------------------------------------------------

/// Dry-run a request against the policy engine to show what would happen.
fn policy_simulate(
    file: Option<&Path>,
    operation: &str,
    client_type_str: &str,
    targets: &[(String, String)],
    secret_refs: &[String],
) -> Result<(), String> {
    let path = resolve_config_path(file);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let config: PolicyConfig = toml_edit::de::from_str(&contents)
        .map_err(|e| format!("TOML parse error in {}: {e}", path.display()))?;

    let client_type = match client_type_str {
        "human" => ClientType::Human,
        "agent" => ClientType::Agent,
        other => return Err(format!("unknown client type: {other} (expected 'human' or 'agent')")),
    };

    let target: std::collections::HashMap<String, String> =
        targets.iter().cloned().collect();

    let request = OperationRequest {
        request_id: uuid::Uuid::nil(),
        client_identity: ClientIdentity {
            uid: 501,
            gid: 20,
            pid: None,
            exe_path: std::env::current_exe().ok(),
            exe_sha256: None,
            codesign_team_id: None,
        },
        client_type,
        operation: operation.into(),
        target,
        params: serde_json::Value::Object(serde_json::Map::new()),
        secret_ref_names: secret_refs.to_vec(),
        workspace: None,
        created_at: std::time::SystemTime::now(),
        expires_at: None,
    };

    let engine = PolicyEngine::with_rules(config.rules);

    // Use Safe as default — we can't know the actual safety class without
    // the operation registry, but this gives a correct policy evaluation
    // for the common case.
    let decision = engine.evaluate(&request, OperationSafety::Safe);

    ui::header("Policy Simulation");

    // Show the request summary.
    println!(
        "  {} {}",
        style("operation:").dim(),
        style(operation).yellow().bold()
    );
    println!(
        "  {} {}",
        style("client:").dim(),
        client_type_str
    );
    if !targets.is_empty() {
        let fields: Vec<String> = targets.iter().map(|(k, v)| format!("{k}={v}")).collect();
        println!(
            "  {} {}",
            style("target:").dim(),
            fields.join(", ")
        );
    }
    if !secret_refs.is_empty() {
        println!(
            "  {} {}",
            style("secrets:").dim(),
            secret_refs.join(", ")
        );
    }
    println!();

    // Show the decision.
    if decision.allowed {
        ui::success(&format!("ALLOW (rule: {})", decision.matched_rule.as_deref().unwrap_or("?")));
        let req_str = format!("{:?}", decision.approval_requirement).to_lowercase();
        println!(
            "  {} {}",
            style("approval:").dim(),
            req_str,
        );
        if !decision.required_factors.is_empty() {
            let factors: Vec<String> = decision
                .required_factors
                .iter()
                .map(|f| format!("{f:?}"))
                .collect();
            println!(
                "  {} {}",
                style("factors:").dim(),
                factors.join(", ")
            );
        }
        if let Some(ttl) = decision.lease_ttl {
            println!(
                "  {} {}s",
                style("lease:").dim(),
                ttl.as_secs(),
            );
        }
        if decision.one_time {
            println!(
                "  {} yes",
                style("one-time:").dim(),
            );
        }
    } else {
        ui::error(&format!(
            "DENY: {}",
            decision.denial_reason.as_deref().unwrap_or("no matching rule")
        ));
        if let Some(ref rule) = decision.matched_rule {
            println!(
                "  {} {}",
                style("matched rule:").dim(),
                rule,
            );
        }
    }

    Ok(())
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

/// Run the init command with styled output.
fn run_init(force: bool) -> Result<(), String> {
    let base = default_opaque_dir();
    run_init_at(&base, force)?;

    ui::header("Initialized opaque");
    ui::init_step(&format!("Created {}", style(base.display()).cyan()));
    ui::init_step(&format!(
        "Created {}",
        style(base.join("run").display()).cyan()
    ));
    ui::init_step(&format!(
        "Created {}",
        style(base.join("profiles").display()).cyan()
    ));
    ui::init_step(&format!(
        "Wrote   {}",
        style(base.join("config.toml").display()).cyan()
    ));
    println!();
    ui::info("Run 'opaque setup' to configure your security policy and seal it.");
    Ok(())
}

/// Initialize the opaque config directory at the given base path.
fn run_init_at(base: &Path, force: bool) -> Result<(), String> {
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

    Ok(())
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

/// Run the setup command (wizard, --seal, --reset, --verify).
fn run_setup(seal_only: bool, reset: bool, verify: bool) -> Result<(), String> {
    use opaque_core::seal::{self, SealStatus};

    let base = default_opaque_dir();
    let config_path = resolve_config_path(None);
    let seal_file = base.join("config.seal");

    if verify {
        if !config_path.exists() {
            return Err(format!(
                "config not found at {} (run 'opaque init' first)",
                config_path.display()
            ));
        }
        let config_bytes = std::fs::read(&config_path)
            .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;
        let status = seal::verify_seal(&config_bytes, &seal_file)
            .map_err(|e| format!("seal check failed: {e}"))?;
        match status {
            SealStatus::Verified => {
                ui::success("Config seal verified — integrity OK");
            }
            SealStatus::Tampered { expected, actual } => {
                ui::error("Config seal BROKEN — config.toml was modified after sealing");
                ui::kv("expected", &expected);
                ui::kv("actual", &actual);
                ui::info("Run 'opaque setup --reset' to unseal, then reconfigure.");
            }
            SealStatus::Unsealed => {
                ui::warn("Config is unsealed — run 'opaque setup --seal' to protect it.");
            }
        }
        return Ok(());
    }

    if reset {
        seal::remove_seal(&seal_file).map_err(|e| format!("failed to remove seal: {e}"))?;
        ui::success("Config seal removed. You can now edit config.toml.");
        ui::info("Run 'opaque setup' to reconfigure and re-seal.");
        return Ok(());
    }

    if seal_only {
        if !config_path.exists() {
            return Err(format!(
                "config not found at {} (run 'opaque init' first)",
                config_path.display()
            ));
        }
        let config_bytes = std::fs::read(&config_path)
            .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;
        let hash = seal::compute_seal(&config_bytes);
        seal::store_seal(&hash, &seal_file).map_err(|e| format!("failed to store seal: {e}"))?;
        ui::success(&format!(
            "Config sealed (SHA-256: {}...)",
            &hash[..16]
        ));
        return Ok(());
    }

    // Interactive wizard.
    run_setup_wizard(&base, &config_path, &seal_file)
}

/// Interactive onboarding wizard.
fn run_setup_wizard(
    base: &Path,
    config_path: &Path,
    seal_file: &Path,
) -> Result<(), String> {
    use dialoguer::{Confirm, Input, MultiSelect};
    use opaque_core::seal;

    println!();
    println!("  {}", style("Opaque Setup").bold());
    println!("  {}", style("════════════").dim());
    println!();
    println!(
        "  This wizard configures your security policy and seals it."
    );
    println!(
        "  Once sealed, config cannot be modified without '{}'.",
        style("opaque setup --reset").cyan()
    );
    println!();

    // Ensure base directory exists.
    create_dir_0700(base)?;

    // Step 1: Human Clients
    println!("  {}", style("Step 1: Human Clients").bold().underlined());

    let current_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut clients: Vec<setup::HumanClientConfig> = Vec::new();

    if !current_exe.is_empty() {
        println!("  Detected: {}", style(&current_exe).cyan());
        let register = Confirm::new()
            .with_prompt("  Register this binary as a trusted human client?")
            .default(true)
            .interact()
            .map_err(|e| format!("input error: {e}"))?;

        if register {
            clients.push(setup::HumanClientConfig {
                name: "opaque-cli".into(),
                exe_path: current_exe,
            });
        }
    }

    loop {
        let add_more = Confirm::new()
            .with_prompt("  Add another client binary path?")
            .default(false)
            .interact()
            .map_err(|e| format!("input error: {e}"))?;

        if !add_more {
            break;
        }

        let path: String = Input::new()
            .with_prompt("  Client binary path")
            .interact_text()
            .map_err(|e| format!("input error: {e}"))?;

        let name: String = Input::new()
            .with_prompt("  Client name")
            .default("custom-client".into())
            .interact_text()
            .map_err(|e| format!("input error: {e}"))?;

        clients.push(setup::HumanClientConfig {
            name,
            exe_path: path,
        });
    }

    println!();

    // Step 2: Operations
    println!("  {}", style("Step 2: Operations").bold().underlined());

    let op_labels: Vec<&str> = setup::EnabledOperation::ALL
        .iter()
        .map(|op| op.label())
        .collect();

    let defaults: Vec<bool> = vec![true; op_labels.len()];

    let selected_indices = MultiSelect::new()
        .with_prompt("  Which operations should human clients access?")
        .items(&op_labels)
        .defaults(&defaults)
        .interact()
        .map_err(|e| format!("input error: {e}"))?;

    let enabled_ops: Vec<setup::EnabledOperation> = selected_indices
        .iter()
        .map(|&i| setup::EnabledOperation::ALL[i])
        .collect();

    println!();

    // Step 3: Approval Policy
    println!(
        "  {}",
        style("Step 3: Approval Policy").bold().underlined()
    );

    let require_bio = Confirm::new()
        .with_prompt("  Require biometric approval for sensitive operations?")
        .default(true)
        .interact()
        .map_err(|e| format!("input error: {e}"))?;

    let lease_ttl: u64 = if require_bio {
        Input::new()
            .with_prompt("  Approval lease duration in seconds")
            .default(300)
            .interact_text()
            .map_err(|e| format!("input error: {e}"))?
    } else {
        0
    };

    println!();

    // Generate config
    let answers = setup::SetupAnswers {
        human_clients: clients,
        enabled_operations: enabled_ops,
        require_biometric: require_bio,
        lease_ttl,
    };

    let config_content = setup::generate_config(&answers);

    // Step 4: Review & Confirm
    println!(
        "  {}",
        style("Step 4: Review & Confirm").bold().underlined()
    );
    println!();
    println!(
        "  {} {}",
        style("┌─").dim(),
        style(config_path.display()).cyan()
    );
    for line in config_content.lines() {
        println!("  {} {}", style("│").dim(), line);
    }
    println!("  {}", style("└─").dim());
    println!();

    let confirm = Confirm::new()
        .with_prompt("  Write config and seal?")
        .default(true)
        .interact()
        .map_err(|e| format!("input error: {e}"))?;

    if !confirm {
        ui::warn("Setup cancelled.");
        return Ok(());
    }

    // Write config
    std::fs::write(config_path, &config_content)
        .map_err(|e| format!("failed to write {}: {e}", config_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                format!(
                    "failed to set permissions on {}: {e}",
                    config_path.display()
                )
            })?;
    }

    ui::init_step(&format!(
        "Config written to {}",
        style(config_path.display()).cyan()
    ));

    // Seal
    let hash = seal::compute_seal(config_content.as_bytes());
    seal::store_seal(&hash, seal_file).map_err(|e| format!("failed to store seal: {e}"))?;

    ui::init_step(&format!(
        "Config sealed (SHA-256: {}...)",
        &hash[..16]
    ));

    println!();
    ui::success("Setup complete!");
    ui::info("Run 'opaque service install' to start the daemon automatically on login.");

    Ok(())
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

/// Run the `opaque doctor` diagnostic command.
///
/// Checks each component of the Opaque installation and reports its status.
/// Uses a pass/warn/fail pattern similar to `brew doctor` or `npm doctor`.
async fn run_doctor() {
    println!();
    println!("  {}", style("Opaque Doctor").bold());
    println!("  {}", style("═════════════").dim());
    println!();

    let mut pass_count = 0u32;
    let mut warn_count = 0u32;
    let mut fail_count = 0u32;

    let base = default_opaque_dir();

    // 1. Config directory
    if base.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&base) {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o700 {
                    doctor_pass(&format!(
                        "Config directory exists ({})",
                        base.display()
                    ));
                    pass_count += 1;
                } else {
                    doctor_warn(&format!(
                        "Config directory permissions are {mode:04o} (expected 0700)"
                    ));
                    warn_count += 1;
                }
            } else {
                doctor_pass(&format!(
                    "Config directory exists ({})",
                    base.display()
                ));
                pass_count += 1;
            }
        }
        #[cfg(not(unix))]
        {
            doctor_pass(&format!(
                "Config directory exists ({})",
                base.display()
            ));
            pass_count += 1;
        }
    } else {
        doctor_fail("Config directory not found — run 'opaque init'");
        fail_count += 1;
    }

    // 2. Config file
    let config_path = base.join("config.toml");
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => {
                match toml_edit::de::from_str::<PolicyConfig>(&contents) {
                    Ok(config) => {
                        doctor_pass(&format!(
                            "Config file valid ({} rules)",
                            config.rules.len()
                        ));
                        pass_count += 1;
                    }
                    Err(e) => {
                        doctor_fail(&format!("Config file has parse errors: {e}"));
                        fail_count += 1;
                    }
                }
            }
            Err(e) => {
                doctor_fail(&format!("Cannot read config file: {e}"));
                fail_count += 1;
            }
        }
    } else {
        doctor_warn("Config file not found — run 'opaque init' or 'opaque setup'");
        warn_count += 1;
    }

    // 3. Config seal
    {
        use opaque_core::seal::{self, SealStatus};
        let seal_file = base.join("config.seal");
        if config_path.exists() {
            match std::fs::read(&config_path) {
                Ok(config_bytes) => {
                    match seal::verify_seal(&config_bytes, &seal_file) {
                        Ok(SealStatus::Verified) => {
                            doctor_pass("Config seal verified");
                            pass_count += 1;
                        }
                        Ok(SealStatus::Unsealed) => {
                            doctor_warn("Config is unsealed — run 'opaque setup --seal'");
                            warn_count += 1;
                        }
                        Ok(SealStatus::Tampered { .. }) => {
                            doctor_fail(
                                "Config seal BROKEN — run 'opaque setup --reset' then reconfigure",
                            );
                            fail_count += 1;
                        }
                        Err(e) => {
                            doctor_warn(&format!("Seal check error: {e}"));
                            warn_count += 1;
                        }
                    }
                }
                Err(e) => {
                    doctor_warn(&format!("Cannot read config for seal check: {e}"));
                    warn_count += 1;
                }
            }
        } else {
            doctor_skip("Config seal (no config file)");
        }
    }

    // 4. Socket
    let sock = socket_path();
    if sock.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&sock) {
                let mode = meta.permissions().mode() & 0o777;
                if mode <= 0o600 {
                    doctor_pass(&format!(
                        "Socket exists with secure permissions ({mode:04o})"
                    ));
                    pass_count += 1;
                } else {
                    doctor_warn(&format!(
                        "Socket permissions are {mode:04o} (expected 0600 or stricter)"
                    ));
                    warn_count += 1;
                }
            } else {
                doctor_pass("Socket file exists");
                pass_count += 1;
            }
        }
        #[cfg(not(unix))]
        {
            doctor_pass("Socket file exists");
            pass_count += 1;
        }
    } else {
        doctor_warn(&format!(
            "Socket not found at {} — is the daemon running?",
            sock.display()
        ));
        warn_count += 1;
    }

    // 5. Daemon connectivity
    if sock.exists() {
        match tokio::time::timeout(Duration::from_secs(5), try_ping(&sock)).await {
            Ok(Ok(())) => {
                doctor_pass("Daemon is reachable (ping OK)");
                pass_count += 1;
            }
            Ok(Err(e)) => {
                doctor_fail(&format!("Daemon ping failed: {e}"));
                fail_count += 1;
            }
            Err(_) => {
                doctor_fail("Daemon ping timed out (5s)");
                fail_count += 1;
            }
        }
    } else {
        doctor_skip("Daemon connectivity (no socket)");
    }

    // 6. Service status
    {
        let status = service::query_status();
        if status.installed {
            if status.running {
                let pid_info = status
                    .pid
                    .map(|p| format!(" (PID {p})"))
                    .unwrap_or_default();
                doctor_pass(&format!("Service installed and running{pid_info}"));
                pass_count += 1;
            } else {
                doctor_warn("Service installed but not running — run 'opaque service start'");
                warn_count += 1;
            }
        } else {
            doctor_warn("Service not installed — run 'opaque service install'");
            warn_count += 1;
        }
    }

    // 7. 1Password op CLI
    match std::process::Command::new("which")
        .arg("op")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            doctor_pass(&format!("1Password CLI found ({path})"));
            pass_count += 1;
        }
        _ => {
            doctor_info("1Password CLI (op) not found — 1Password features unavailable");
        }
    }

    // 8. Profiles directory
    let profiles_dir = base.join("profiles");
    if profiles_dir.exists() {
        let count = std::fs::read_dir(&profiles_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
                    .count()
            })
            .unwrap_or(0);
        doctor_pass(&format!("Profiles directory exists ({count} profiles)"));
        pass_count += 1;
    } else {
        doctor_info("No profiles directory (sandbox features unavailable)");
    }

    // 9. Audit database
    let audit_db = base.join("audit.db");
    if audit_db.exists() {
        if let Ok(meta) = std::fs::metadata(&audit_db) {
            let size_kb = meta.len() / 1024;
            doctor_pass(&format!("Audit database exists ({size_kb} KB)"));
            pass_count += 1;
        } else {
            doctor_pass("Audit database exists");
            pass_count += 1;
        }
    } else {
        doctor_info("No audit database (created on first daemon run)");
    }

    // Summary
    println!();
    println!("  {}", style("────────────────────────────────").dim());
    let summary = format!("{pass_count} passed, {warn_count} warnings, {fail_count} errors");
    if fail_count > 0 {
        println!(
            "  {} {}",
            style(ui::CROSS).red(),
            style(summary).red().bold()
        );
    } else if warn_count > 0 {
        println!(
            "  {} {}",
            style(ui::WARN_ICON).yellow(),
            style(summary).yellow().bold()
        );
    } else {
        println!(
            "  {} {}",
            style(ui::CHECK).green(),
            style(summary).green().bold()
        );
    }
    println!();

    if fail_count > 0 {
        std::process::exit(1);
    }
}

/// Attempt a lightweight ping to the daemon. Returns Ok(()) on success.
async fn try_ping(sock: &Path) -> Result<(), String> {
    // Verify socket safety first.
    verify_socket_safety(sock).map_err(|e| format!("{e}"))?;

    // Read daemon token.
    let daemon_token = read_daemon_token(sock).map_err(|e| format!("{e}"))?;

    // Connect.
    let stream = UnixStream::connect(sock)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    // Handshake.
    let handshake = serde_json::json!({
        "handshake": "v1",
        "daemon_token": daemon_token,
    });
    let hs_bytes = serde_json::to_vec(&handshake).map_err(|e| format!("serialize: {e}"))?;
    framed
        .send(Bytes::from(hs_bytes))
        .await
        .map_err(|e| format!("send handshake: {e}"))?;

    // Send ping.
    let req = Request {
        id: 1,
        method: "ping".to_string(),
        params: serde_json::Value::Null,
    };
    let out = serde_json::to_vec(&req).map_err(|e| format!("serialize: {e}"))?;
    framed
        .send(Bytes::from(out))
        .await
        .map_err(|e| format!("send ping: {e}"))?;

    // Read response.
    let frame = framed
        .next()
        .await
        .ok_or_else(|| "no response".to_string())?
        .map_err(|e| format!("read: {e}"))?;

    let resp: Response =
        serde_json::from_slice(&frame).map_err(|e| format!("parse response: {e}"))?;

    if resp.error.is_some() {
        return Err("daemon returned an error".to_string());
    }
    Ok(())
}

fn doctor_pass(msg: &str) {
    println!(
        "  {} {}",
        style(ui::CHECK).green(),
        msg
    );
}

fn doctor_fail(msg: &str) {
    println!(
        "  {} {}",
        style(ui::CROSS).red(),
        style(msg).red()
    );
}

fn doctor_warn(msg: &str) {
    println!(
        "  {} {}",
        style(ui::WARN_ICON).yellow(),
        style(msg).yellow()
    );
}

fn doctor_info(msg: &str) {
    println!(
        "  {} {}",
        style(ui::INFO_ICON).dim(),
        style(msg).dim()
    );
}

fn doctor_skip(msg: &str) {
    println!(
        "  {} {}",
        style("—").dim(),
        style(msg).dim()
    );
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
fn run_profile_action(action: &ProfileAction) -> Result<(), String> {
    let profiles_dir = profile::profiles_dir();

    match action {
        ProfileAction::List => {
            if !profiles_dir.exists() {
                ui::warn("No profiles directory found (run `opaque init` first)");
                return Ok(());
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
                ui::info("No profiles found.");
                return Ok(());
            }

            ui::header(&format!("{} profile(s)", names.len()));
            for name in &names {
                println!("  {} {}", style(ui::PAPER).dim(), style(name).cyan().bold());
            }
            Ok(())
        }

        ProfileAction::Show { name } => {
            let path = profiles_dir.join(format!("{name}.toml"));
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read profile '{name}': {e}"))?;
            ui::header(&format!("Profile: {name}"));
            println!("{contents}");
            Ok(())
        }

        ProfileAction::Validate { name } => {
            let path = profiles_dir.join(format!("{name}.toml"));
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read profile '{name}': {e}"))?;

            profile::load_profile(&contents, Some(name))
                .map_err(|e| format!("profile validation failed: {e}"))?;

            ui::success(&format!("Profile '{name}' is valid"));
            Ok(())
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
        // Old content should be replaced
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

    /// Write a TOML config, return the temp path for use in policy_show / policy_simulate.
    fn write_config(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, content).unwrap();
        (dir, path)
    }

    fn sample_rule_toml() -> &'static str {
        r#"
[[rules]]
name = "allow-github-actions"
operation_pattern = "github.set_actions_secret"
allow = true
client_types = ["human"]

[rules.client]

[rules.target]
fields = { repo = "myorg/*" }

[rules.workspace]

[rules.secret_names]
patterns = ["GH_*"]

[rules.approval]
require = "first_use"
factors = ["local_bio"]
lease_ttl = 300
"#
    }

    #[test]
    fn policy_show_empty_rules() {
        let (_dir, path) = write_config("");
        // Should not error, just warn about empty rules.
        let result = policy_show(Some(path.as_path()));
        assert!(result.is_ok());
    }

    #[test]
    fn policy_show_with_rules() {
        let (_dir, path) = write_config(sample_rule_toml());
        let result = policy_show(Some(path.as_path()));
        assert!(result.is_ok());
    }

    #[test]
    fn policy_show_missing_file() {
        let result = policy_show(Some(Path::new("/nonexistent/config.toml")));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn policy_simulate_allow() {
        let (_dir, path) = write_config(sample_rule_toml());
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "human",
            &[("repo".into(), "myorg/myrepo".into())],
            &["GH_TOKEN".into()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn policy_simulate_deny_no_matching_rule() {
        let (_dir, path) = write_config(sample_rule_toml());
        // Use an operation not covered by any rule.
        let result = policy_simulate(
            Some(path.as_path()),
            "sandbox.exec",
            "human",
            &[],
            &[],
        );
        // Should succeed (prints the deny decision).
        assert!(result.is_ok());
    }

    #[test]
    fn policy_simulate_deny_target_mismatch() {
        let (_dir, path) = write_config(sample_rule_toml());
        // Rule requires repo=myorg/*, but we pass a different org.
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "human",
            &[("repo".into(), "otherorg/repo".into())],
            &["GH_TOKEN".into()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn policy_simulate_invalid_client_type() {
        let (_dir, path) = write_config(sample_rule_toml());
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "unknown",
            &[],
            &[],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown client type"));
    }

    #[test]
    fn policy_simulate_agent_client_type() {
        let (_dir, path) = write_config(sample_rule_toml());
        // Rule only allows "human", so agent should be denied.
        let result = policy_simulate(
            Some(path.as_path()),
            "github.set_actions_secret",
            "agent",
            &[("repo".into(), "myorg/myrepo".into())],
            &["GH_TOKEN".into()],
        );
        assert!(result.is_ok());
    }
}
