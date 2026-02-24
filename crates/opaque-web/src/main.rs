use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};

mod config;
mod daemon_client;
mod demo;
mod routes;
mod sse;

#[derive(Parser)]
#[command(name = "opaque-web", about = "Opaque live dashboard & demo explorer")]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value = "7380")]
    port: u16,

    /// Open the dashboard in the default browser on startup.
    #[arg(long)]
    open: bool,
}

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub daemon: daemon_client::DaemonClient,
    pub config_path: PathBuf,
    pub audit_db_path: PathBuf,
    pub cancel: CancellationToken,
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();
    let cancel = CancellationToken::new();

    let state = AppState {
        daemon: daemon_client::DaemonClient::new(None),
        config_path: config::config_path(),
        audit_db_path: config::audit_db_path(),
        cancel: cancel.clone(),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = routes::router().layer(cors).with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    tracing::info!("opaque-web listening on http://{addr}");

    if args.open {
        let url = format!("http://127.0.0.1:{}", args.port);
        if let Err(e) = open_browser(&url) {
            tracing::warn!("failed to open browser: {e}");
        }
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(cancel))
    .await
    .expect("server error");
}

async fn shutdown_signal(cancel: CancellationToken) {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }
    cancel.cancel();
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}
