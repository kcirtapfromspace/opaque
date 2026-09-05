use clap::Parser;
use opaque_metrics::server::{App, GatewayConfig, router};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Tenant-scoped OAuth MCP metrics gateway")]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("opaque_metrics=info")
        .init();
    let args = Args::parse();
    let config: GatewayConfig = serde_json::from_slice(&std::fs::read(args.config)?)?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let app = App::new(config)?;
    tracing::info!("metrics gateway listening on {}", listener.local_addr()?);
    axum::serve(listener, router(app)).await?;
    Ok(())
}
