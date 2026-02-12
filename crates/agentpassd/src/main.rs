use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use agentpass_core::audit::TracingAuditEmitter;
use agentpass_core::operation::{ClientIdentity, ClientType, OperationRegistry, OperationRequest};
use agentpass_core::peer::peer_info_from_fd;
use agentpass_core::policy::PolicyEngine;
use agentpass_core::proto::{Request, Response};
use agentpass_core::socket::{ensure_socket_parent_dir, socket_path};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, warn};
use uuid::Uuid;

mod approval;
mod enclave;

use enclave::{Enclave, NativeApprovalGate};

struct DaemonState {
    enclave: Arc<Enclave>,
    version: &'static str,
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

    // Build enclave with deny-all defaults.
    // Operations are registered as provider integrations are built.
    let registry = OperationRegistry::new();
    let policy = PolicyEngine::new();
    let audit = Arc::new(TracingAuditEmitter);

    let enclave = Enclave::builder()
        .registry(registry)
        .policy(policy)
        .approval_gate(Box::new(NativeApprovalGate))
        .audit(audit)
        .build();

    let state = Arc::new(DaemonState {
        enclave: Arc::new(enclave),
        version: env!("CARGO_PKG_VERSION"),
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

/// Build a [`ClientIdentity`] from peer credentials obtained via the Unix socket.
fn build_client_identity(peer: Option<&agentpass_core::peer::PeerInfo>) -> ClientIdentity {
    match peer {
        Some(info) => {
            let exe_path = info.pid.and_then(exe_path_for_pid);
            ClientIdentity {
                uid: info.uid,
                gid: info.gid,
                pid: info.pid,
                exe_path,
                exe_sha256: None,
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

async fn handle_conn(state: Arc<DaemonState>, stream: UnixStream) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let peer = peer_info_from_fd(fd).ok();
    let identity = build_client_identity(peer.as_ref());

    if let Some(ref peer) = peer {
        info!(
            "client connected uid={} gid={} pid={:?}",
            peer.uid, peer.gid, peer.pid
        );
    } else {
        info!("client connected (peer creds unavailable)");
    }

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(128 * 1024) // 128KB max frame
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    while let Some(frame) = framed.next().await {
        let frame = match frame {
            Ok(b) => b,
            Err(e) => {
                let resp = Response::err(None, "bad_frame", e.to_string());
                let bytes = serde_json::to_vec(&resp)
                    .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                let _ = framed.send(Bytes::from(bytes)).await;
                return Err(e);
            }
        };

        let req: Request = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(None, "bad_json", e.to_string());
                let bytes = serde_json::to_vec(&resp)
                    .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                let _ = framed.send(Bytes::from(bytes)).await;
                continue;
            }
        };

        // Never log params (may contain secrets due to client bugs).
        let resp = handle_request(&state, req, &identity).await;
        let out = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
        framed.send(Bytes::from(out)).await?;
    }

    Ok(())
}

async fn handle_request(state: &DaemonState, req: Request, identity: &ClientIdentity) -> Response {
    match req.method.as_str() {
        "ping" => Response::ok(req.id, serde_json::json!({ "ok": true })),
        "version" => Response::ok(req.id, serde_json::json!({ "version": state.version })),
        "whoami" => Response::ok(
            req.id,
            serde_json::json!({
                "uid": identity.uid,
                "gid": identity.gid,
                "pid": identity.pid,
                "exe_path": identity.exe_path.as_ref().map(|p| p.display().to_string()),
            }),
        ),
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

            // Default to Agent (safer — more restrictive).
            let client_type = match req.params.get("client_type").and_then(|v| v.as_str()) {
                Some("human") => ClientType::Human,
                _ => ClientType::Agent,
            };

            let op_params = req
                .params
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

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
