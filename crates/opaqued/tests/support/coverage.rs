//! Coverage-only collection for real fixture subprocesses. Normal test and
//! production binaries never compile this module or inherit these settings.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn directory() -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os("OPAQUE_COVERAGE_PROFILE_DIR")
            .expect("coverage fixtures require a collector-owned profile directory"),
    );
    assert!(
        path.is_absolute() && path.is_dir(),
        "coverage profile directory must be an existing absolute directory"
    );
    path
}

/// Restore only collection settings after a fixture clears its environment.
/// The collector gives each job a separate directory writable by its fixture
/// UIDs. PID and module identifiers keep restarts and peer binaries distinct;
/// continuous mode retains counters even when the scenario kills a process.
pub fn subprocess(command: &mut Command, role: &str) {
    assert!(matches!(role, "daemon" | "adapter" | "peer"));
    let directory = directory();
    command
        .env(
            "LLVM_PROFILE_FILE",
            directory.join(format!("{role}-%p-%m-%c.profraw")),
        )
        .env("OPAQUE_COVERAGE_PROFILE_DIR", directory);
}

/// A bare rustc fixture must use the collector's exact compiler and flags.
/// Cargo does not instrument ad-hoc rustc invocations automatically. Retain
/// the resulting mapping object before the fixture's temporary tree is gone.
#[allow(dead_code)] // Only subprocess-peer fixtures compile a separate binary.
pub fn compile_peer(source: &Path, output: &Path) {
    let compiler = PathBuf::from(
        std::env::var_os("OPAQUE_COVERAGE_RUSTC")
            .expect("coverage peer requires the collector's pinned compiler"),
    );
    assert!(compiler.is_absolute() && compiler.is_file());
    let flags: Vec<String> = serde_json::from_str(
        &std::env::var("OPAQUE_COVERAGE_RUSTFLAGS")
            .expect("coverage peer requires the collector's encoded compiler flags"),
    )
    .expect("coverage compiler flags must be a JSON string array");
    assert!(!flags.is_empty(), "coverage compiler flags cannot be empty");
    let compiled = Command::new(compiler)
        .args(flags)
        .arg("--edition=2024")
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("compile instrumented peer");
    assert!(
        compiled.status.success(),
        "instrumented peer compilation failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    std::fs::copy(
        output,
        directory().join(format!("peer-binary-{}", uuid::Uuid::new_v4())),
    )
    .expect("retain instrumented peer mapping object");
}
