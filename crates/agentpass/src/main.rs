use std::path::{Path, PathBuf};
use std::time::Duration;

use agentpass_core::proto::{Request, Response};
use agentpass_core::socket::{socket_path, verify_socket_safety};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Name of the daemon token file expected next to the socket.
const DAEMON_TOKEN_FILENAME: &str = "daemon.token";

#[derive(Debug, Parser)]
#[command(name = "agentpass", version)]
struct Cli {
    /// Override the Unix socket path (otherwise uses AGENTPASS_SOCK / XDG_RUNTIME_DIR / ~/.agentpass/run).
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
    let sock = cli.socket.unwrap_or_else(socket_path);

    let cmd = cli.cmd.unwrap_or(Cmd::Ping);
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
    };

    match call(&sock, method, params).await {
        Ok(resp) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string())
            );
        }
        Err(e) => {
            eprintln!("agentpass: {e}");
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
                "failed to read daemon token at {}: {e} (is agentpassd running?)",
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
                    "{e} (is agentpassd running? expected socket at {})",
                    sock.display()
                ),
            )
        })?;

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(1024 * 1024)
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
