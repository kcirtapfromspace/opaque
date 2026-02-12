use std::path::PathBuf;

use agentpass_core::proto::{Request, Response};
use agentpass_core::socket::socket_path;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

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
    /// Request a native OS approval prompt (debug).
    Approve {
        /// Text shown in the OS authentication prompt.
        #[arg(long)]
        reason: String,
    },
    /// Debug client identity (placeholder).
    Whoami,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let sock = cli.socket.unwrap_or_else(socket_path);

    let cmd = cli.cmd.unwrap_or(Cmd::Ping);
    let (method, params) = match cmd {
        Cmd::Ping => ("ping", serde_json::Value::Null),
        Cmd::Version => ("version", serde_json::Value::Null),
        Cmd::Approve { reason } => (
            "approval.prompt",
            serde_json::json!({
                "reason": reason,
            }),
        ),
        Cmd::Whoami => ("whoami", serde_json::Value::Null),
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

async fn call(
    sock: &PathBuf,
    method: &str,
    params: serde_json::Value,
) -> std::io::Result<Response> {
    let stream = UnixStream::connect(sock).await.map_err(|e| {
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
            "no response from daemon",
        ));
    };
    let frame = frame?;

    let resp: Response = serde_json::from_slice(&frame)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(resp)
}
