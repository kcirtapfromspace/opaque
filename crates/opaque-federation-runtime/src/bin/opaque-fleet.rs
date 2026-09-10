//! Operator-owned enrolled broker inventory collector. No remote mutation API.
use clap::{Parser, Subcommand};
use opaque_federation_runtime::fleet::{
    CollectorConfig, Enrollment, FleetStore, read_private_file, serve,
};
use std::{path::PathBuf, sync::Arc};
#[derive(Parser)]
#[command(
    name = "opaque-fleet",
    about = "Enrolled broker inventory and authenticated software posture collector"
)]
struct Cli {
    #[arg(long)]
    store: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Serve tenant-scoped read and report APIs behind a trusted TLS ingress.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Pin an exact tenant/broker/public-key enrollment from a private JSON file.
    Enroll {
        #[arg(long)]
        enrollment: PathBuf,
    },
    /// Rotate an active broker to a previously unused key; old reports stop working.
    Rotate {
        #[arg(long)]
        enrollment: PathBuf,
    },
    /// Permanently revoke a tenant/broker enrollment. Use a new broker identity to reenroll.
    Revoke {
        #[arg(long)]
        binding: PathBuf,
    },
    /// Inspect one tenant's enrolled coverage locally.
    Inventory {
        #[arg(long)]
        tenant: String,
        #[arg(long, default_value_t = 120)]
        fresh_secs: u64,
        #[arg(long, default_value_t = 600)]
        offline_secs: u64,
    },
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let store = Arc::new(FleetStore::open(&cli.store)?);
    let now = opaque_core::identity::now_unix();
    match cli.command {
        Command::Serve { config } => {
            let config: CollectorConfig =
                serde_json::from_slice(&read_private_file(&config, 128 * 1024)?)?;
            serve(store, config).await?;
        }
        Command::Enroll { enrollment } => {
            enroll(&store, enrollment, false, now)?;
        }
        Command::Rotate { enrollment } => {
            enroll(&store, enrollment, true, now)?;
        }
        Command::Revoke { binding } => {
            let binding = serde_json::from_slice(&read_private_file(&binding, 16 * 1024)?)?;
            store.revoke(&binding, now)?;
            println!("{}", serde_json::json!({"revoked":true,"binding":binding}));
        }
        Command::Inventory {
            tenant,
            fresh_secs,
            offline_secs,
        } => println!(
            "{}",
            serde_json::to_string_pretty(&store.inventory(
                &tenant,
                now,
                fresh_secs,
                offline_secs
            )?)?
        ),
    }
    Ok(())
}

fn enroll(
    store: &FleetStore,
    path: PathBuf,
    rotate: bool,
    now: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let enrollment: Enrollment = serde_json::from_slice(&read_private_file(&path, 16 * 1024)?)?;
    let epoch = store.enroll(&enrollment, rotate, now)?;
    println!(
        "{}",
        serde_json::json!({"binding":enrollment.binding,"enrollment_epoch":epoch})
    );
    Ok(())
}
