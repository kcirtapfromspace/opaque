use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentpass_core::peer::peer_info_from_fd;
use agentpass_core::proto::{Request, Response};
use agentpass_core::socket::{ensure_socket_parent_dir, socket_path};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, warn};

mod approval;
mod enclave;

struct AppState {
    version: &'static str,
    approval_gate: tokio::sync::Semaphore,
}

#[tokio::main]
async fn main() {
    init_tracing();

    let path = socket_path();
    if let Err(e) = run(path).await {
        eprintln!("agentpassd: {e}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn run(socket: PathBuf) -> std::io::Result<()> {
    ensure_socket_parent_dir(&socket)?;

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

    let listener = UnixListener::bind(&socket)?;
    lock_down_socket_path(&socket)?;
    let _socket_guard = SocketGuard::new(socket.clone());

    info!("listening on {}", socket.display());

    let state = Arc::new(AppState {
        version: env!("CARGO_PKG_VERSION"),
        approval_gate: tokio::sync::Semaphore::new(1),
    });

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
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(state, stream).await {
                        warn!("connection error: {e}");
                    }
                });
            }
        }
    }

    Ok(())
}

fn lock_down_socket_path(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Only allow the owning user to connect.
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

async fn handle_conn(state: Arc<AppState>, stream: UnixStream) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let peer = peer_info_from_fd(fd).ok();

    if let Some(peer) = peer {
        info!(
            "client connected uid={} gid={} pid={:?}",
            peer.uid, peer.gid, peer.pid
        );
    } else {
        info!("client connected (peer creds unavailable)");
    }

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(1024 * 1024)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    while let Some(frame) = framed.next().await {
        let frame = match frame {
            Ok(b) => b,
            Err(e) => {
                let resp = Response::err(None, "bad_frame", e.to_string());
                let bytes = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                let _ = framed.send(Bytes::from(bytes)).await;
                return Err(e);
            }
        };

        let req: Request = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(None, "bad_json", e.to_string());
                let bytes = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                let _ = framed.send(Bytes::from(bytes)).await;
                continue;
            }
        };

        // Never log params (may contain secrets due to client bugs).
        let resp = handle_request(state.as_ref(), req).await;
        let out = serde_json::to_vec(&resp).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        framed.send(Bytes::from(out)).await?;
    }

    Ok(())
}

async fn handle_request(state: &AppState, req: Request) -> Response {
    match req.method.as_str() {
        "ping" => Response::ok(req.id, serde_json::json!({ "ok": true })),
        "version" => Response::ok(req.id, serde_json::json!({ "version": state.version })),
        "approval.prompt" => {
            let reason = req
                .params
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let Ok(_permit) = state.approval_gate.acquire().await else {
                return Response::err(Some(req.id), "internal", "approval gate closed");
            };

            match approval::prompt(reason).await {
                Ok(approved) => Response::ok(req.id, serde_json::json!({ "approved": approved })),
                Err(e) => Response::err(Some(req.id), "approval_failed", e.to_string()),
            }
        }
        "whoami" => {
            // Placeholder. In v1, this should return the server-observed client identity (uid/pid/exe hash).
            Response::ok(req.id, serde_json::json!({ "note": "not implemented" }))
        }
        _ => Response::err(Some(req.id), "unknown_method", "unknown method"),
    }
}

// tokio::net::UnixStream implements AsRawFd on unix platforms.
use std::os::unix::io::AsRawFd;
