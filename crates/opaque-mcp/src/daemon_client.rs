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
pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    /// Create a new daemon client using the default or env-overridden socket path.
    pub fn new(socket_override: Option<PathBuf>) -> Self {
        let socket_path = socket_override.unwrap_or_else(socket_path);
        Self { socket_path }
    }

    /// Send a request to the daemon and return the response.
    pub async fn call(&self, method: &str, params: serde_json::Value) -> std::io::Result<Response> {
        verify_socket_safety(&self.socket_path)?;
        let daemon_token = read_daemon_token(&self.socket_path)?;

        let stream = tokio::time::timeout(
            Duration::from_secs(30),
            UnixStream::connect(&self.socket_path),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connection timed out: {}", self.socket_path.display()),
            )
        })?
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "{e} (is opaqued running? expected socket at {})",
                    self.socket_path.display()
                ),
            )
        })?;

        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
            .new_codec();
        let mut framed = Framed::new(stream, codec);

        // Send handshake as the first frame.
        let mut handshake = serde_json::json!({
            "handshake": "v1",
            "daemon_token": daemon_token.trim(),
        });
        if let Ok(session_token) = std::env::var("OPAQUE_SESSION_TOKEN")
            && !session_token.trim().is_empty()
        {
            handshake["session_token"] = serde_json::Value::String(session_token);
        }
        let hs_bytes = serde_json::to_vec(&handshake).map_err(std::io::Error::other)?;
        framed.send(Bytes::from(hs_bytes)).await?;

        // Send request.
        let req = Request {
            id: 1,
            method: method.to_string(),
            params,
        };
        debug!(method, "sending IPC request to daemon");
        let out = serde_json::to_vec(&req).map_err(std::io::Error::other)?;
        framed.send(Bytes::from(out)).await?;

        // Receive response.
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
}
