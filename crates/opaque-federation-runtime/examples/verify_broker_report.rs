//! Verify an exported report against a key and binding pinned by the consumer.
//! Run: cargo run -p opaque-federation-runtime --example verify_broker_report --
//!      heartbeat.json binding.json LOWERCASE_HEX_PUBLIC_KEY
//! This offline example does not enroll a broker or provide replay protection.
use opaque_core::tenant::TenantBinding;
use opaque_federation_runtime::fleet::{Heartbeat, verify_heartbeat};
use std::io::Read;

fn bounded_json<T: serde::de::DeserializeOwned>(
    path: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 256 * 1024 {
        return Err("input exceeds 256 KiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: verify_broker_report heartbeat.json binding.json PINNED_PUBLIC_KEY_HEX".into(),
        );
    }
    let heartbeat: Heartbeat = bounded_json(&args[0])?;
    let binding: TenantBinding = bounded_json(&args[1])?;
    let key = opaque_core::bundle::parse_anchor(&args[2])?;
    let report = verify_heartbeat(
        &heartbeat,
        &binding,
        &key,
        opaque_core::identity::now_unix(),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
