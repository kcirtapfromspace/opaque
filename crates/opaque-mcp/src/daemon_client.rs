use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use opaque_core::proto::{Request, Response};
use opaque_core::socket::{socket_path, verify_socket_safety};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::debug;

const DAEMON_TOKEN_FILENAME: &str = "daemon.token";

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

/// A client for communicating with the opaqued daemon over Unix socket IPC.
#[derive(Clone)]
pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    /// Create a new daemon client using the default or env-overridden socket path.
    pub fn new(socket_override: Option<PathBuf>) -> Self {
        let socket_path = socket_override.unwrap_or_else(socket_path);
        Self { socket_path }
    }

    /// Send once. A missing response after dispatch is an unknown outcome,
    /// never evidence that retrying an operation would be safe.
    pub async fn call(&self, method: &str, params: serde_json::Value) -> std::io::Result<Response> {
        let deadline = match method {
            "exec" | "execute" => Duration::from_secs(300),
            "task_run" => Duration::from_secs(3660),
            "mcp_catalog"
            | "mcp_get"
            | "mcp_revoke"
            | "ping"
            | "operations"
            | "version"
            | "whoami"
            | "leases"
            | "task_get"
            | "task_list"
            | "identity.login_status"
            | "identity.principal_list"
            | "identity.delegation_list"
            | "identity.provisioning.list"
            | "identity.provisioning.show"
            | "fido2_list"
            | "fido2_pending"
            | "device_list"
            | "agent_session_list"
            | "attestation_report" => Duration::from_secs(30),
            _ => Duration::from_secs(300),
        };
        self.call_with_timeout(method, params, deadline).await
    }

    async fn call_with_timeout(
        &self,
        method: &str,
        params: serde_json::Value,
        deadline: Duration,
    ) -> std::io::Result<Response> {
        verify_socket_safety(&self.socket_path)?;
        let daemon_token = read_daemon_token(&self.socket_path)?;
        let mut dispatched = false;
        let exchange = async {
            let stream = tokio::time::timeout(
                Duration::from_secs(30),
                UnixStream::connect(&self.socket_path),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out")
            })??;
            let req = Request {
                id: 1,
                method: method.to_string(),
                params,
            };
            let out = serde_json::to_vec(&req).map_err(std::io::Error::other)?;
            if out.len() > opaque_core::MAX_FRAME_LENGTH {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "request exceeds the IPC frame limit",
                ));
            }
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
                .new_codec();
            let mut framed = Framed::new(stream, codec);
            let mut handshake =
                serde_json::json!({ "handshake": "v1", "daemon_token": daemon_token.trim() });
            if let Ok(session_token) = std::env::var("OPAQUE_SESSION_TOKEN")
                && !session_token.trim().is_empty()
            {
                handshake["session_token"] = serde_json::Value::String(session_token);
            }
            let hs_bytes = serde_json::to_vec(&handshake).map_err(std::io::Error::other)?;
            framed.send(Bytes::from(hs_bytes)).await?;
            debug!(method, "sending IPC request to daemon");
            // A cancelled or failed write may already have reached the daemon.
            dispatched = true;
            framed.send(Bytes::from(out)).await?;
            let frame = framed.next().await.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "daemon closed without a response",
                )
            })??;
            opaque_core::proto::decode_response(&frame, req.id)
        };
        let result = tokio::time::timeout(deadline, exchange)
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("request timed out after {} seconds", deadline.as_secs()),
                ))
            });
        result.map_err(|error| {
            if dispatched {
                std::io::Error::new(error.kind(), format!(
                    "{error}; outcome unknown: the request may have executed. It was not retried. Inspect the task receipt or operation audit before taking further action"
                ))
            } else {
                error
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn entire_exchange_deadline_closes_a_stalled_response_without_replay() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(directory.path().join("daemon.token"), "fixture-token").unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let daemon = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            framed.next().await.unwrap().unwrap();
            let request: Request =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(request.method, "task_run");
            assert!(framed.next().await.is_none());
            assert!(
                tokio::time::timeout(Duration::from_millis(200), listener.accept())
                    .await
                    .is_err()
            );
        });
        let client = DaemonClient::new(Some(socket));
        let error = client
            .call_with_timeout(
                "task_run",
                serde_json::json!({"task_id":"fixture"}),
                Duration::from_millis(100),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("outcome unknown"));
        assert!(error.to_string().contains("not retried"));
        tokio::time::timeout(Duration::from_secs(2), daemon)
            .await
            .unwrap()
            .unwrap();
    }
}
