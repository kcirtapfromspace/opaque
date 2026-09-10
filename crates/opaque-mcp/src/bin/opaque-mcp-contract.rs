//! Offline registry lint/preparation. Never connects to a daemon or upstream.

use std::io::Read;
use std::path::Path;

use opaque_mcp::gateway_contract::{
    MAX_CALL_BYTES, MAX_REGISTRY_BYTES, PREPARED_CONTRACT_VERSION, Registry,
};
use serde_json::json;

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    // This is a developer tool, not a registry custody/provenance check. Refuse
    // ordinary directories, links and special files before attempting a read.
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "cannot inspect contract file")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("contract file must be a bounded regular file");
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open contract file")?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read contract file")?;
    if bytes.len() > limit {
        return Err("contract file exceeds its byte limit");
    }
    Ok(bytes)
}

fn run(args: &[String]) -> Result<(), String> {
    if args == ["--help"] || args == ["-h"] {
        println!("Usage: opaque-mcp-contract validate REGISTRY.json");
        println!("       opaque-mcp-contract prepare REGISTRY.json CALL.json");
        println!("Offline contract checks only; no network, authorization or execution.");
        return Ok(());
    }
    let (command, registry_path, call_path) = match args {
        [command, registry] if command == "validate" => (command, registry, None),
        [command, registry, call] if command == "prepare" => (command, registry, Some(call)),
        _ => {
            return Err(
                "expected validate REGISTRY.json or prepare REGISTRY.json CALL.json".into(),
            );
        }
    };
    let registry =
        Registry::from_json(&read_bounded(Path::new(registry_path), MAX_REGISTRY_BYTES)?)
            .map_err(|error| error.to_string())?;
    let output = if command == "validate" {
        json!({"mode":"offline_contract", "registry_valid":true,
            "route_count":registry.route_count(), "runtime_gateway_enabled":false})
    } else {
        let bytes = read_bounded(
            Path::new(call_path.expect("prepare includes call")),
            MAX_CALL_BYTES,
        )?;
        let call = registry
            .prepare_json(&bytes)
            .map_err(|error| error.to_string())?;
        json!({"mode":"offline_contract", "status":"prepared_not_authorized",
            "runtime_gateway_enabled":false, "route":call.route().alias,
            "prepared_contract_version":PREPARED_CONTRACT_VERSION, "action_digest":call.action_digest(), "output_policy":call.route().output_policy})
    };
    println!("{output}");
    Ok(())
}

fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
