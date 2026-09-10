use clap::Parser;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    opaque_web::run_dashboard(
        opaque_web::DashboardOptions::parse(),
        opaque_web::DashboardExtension::default(),
    )
    .await
}
