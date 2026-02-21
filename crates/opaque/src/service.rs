//! Daemon service management (launchd on macOS, systemd on Linux).
//!
//! Provides install/uninstall/start/stop/status/logs operations for
//! managing the opaqued daemon as a system service.

use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which operations the `opaque service` subcommand supports.
#[derive(Debug, Clone, Copy)]
pub enum ServiceOp {
    Install,
    Uninstall,
    Status,
    Start,
    Stop,
    Logs,
}

/// Result of a service status check.
#[derive(Debug)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub pid: Option<u32>,
    pub service_file: PathBuf,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run a service management operation.
pub fn run(op: ServiceOp) -> Result<(), String> {
    match op {
        ServiceOp::Install => install(),
        ServiceOp::Uninstall => uninstall(),
        ServiceOp::Status => status(),
        ServiceOp::Start => start(),
        ServiceOp::Stop => stop(),
        ServiceOp::Logs => logs(),
    }
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

fn install() -> Result<(), String> {
    let opaqued = find_opaqued()?;
    let service_file = service_file_path();

    if service_file.exists() {
        return Err(format!(
            "service already installed at {} (run 'opaque service uninstall' first)",
            service_file.display()
        ));
    }

    // Ensure parent directory exists.
    if let Some(parent) = service_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }

    let content = generate_service_file(&opaqued);
    std::fs::write(&service_file, &content)
        .map_err(|e| format!("failed to write {}: {e}", service_file.display()))?;

    load_service(&service_file)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

fn uninstall() -> Result<(), String> {
    let service_file = service_file_path();

    if !service_file.exists() {
        return Err("service is not installed".into());
    }

    unload_service(&service_file)?;

    std::fs::remove_file(&service_file)
        .map_err(|e| format!("failed to remove {}: {e}", service_file.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn status() -> Result<(), String> {
    let st = query_status();
    // Caller (main.rs) handles formatting via ui helpers.
    // We print structured output here.
    crate::ui::header("Daemon Service");
    crate::ui::kv("service file", &st.service_file.display().to_string());
    crate::ui::kv("installed", if st.installed { "yes" } else { "no" });
    crate::ui::kv("running", if st.running { "yes" } else { "no" });
    if let Some(pid) = st.pid {
        crate::ui::kv("pid", &pid.to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Start / Stop
// ---------------------------------------------------------------------------

fn start() -> Result<(), String> {
    let service_file = service_file_path();
    if !service_file.exists() {
        return Err("service is not installed (run 'opaque service install' first)".into());
    }
    start_service()?;
    Ok(())
}

fn stop() -> Result<(), String> {
    let service_file = service_file_path();
    if !service_file.exists() {
        return Err("service is not installed".into());
    }
    stop_service()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

fn logs() -> Result<(), String> {
    show_logs()
}

// ---------------------------------------------------------------------------
// Platform: macOS (launchd)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const LABEL: &str = "com.opaque.daemon";

#[cfg(target_os = "macos")]
fn service_file_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join("com.opaque.daemon.plist")
}

#[cfg(target_os = "macos")]
fn generate_service_file(opaqued_path: &Path) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let log_dir = PathBuf::from(&home).join(".opaque").join("logs");
    // Ensure log directory exists.
    let _ = std::fs::create_dir_all(&log_dir);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>{}</string></array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict><key>SuccessfulExit</key><false/></dict>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>StandardOutPath</key>
    <string>{}/opaqued.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{}/opaqued.stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
"#,
        opaqued_path.display(),
        log_dir.display(),
        log_dir.display(),
    )
}

#[cfg(target_os = "macos")]
fn load_service(plist: &Path) -> Result<(), String> {
    let output = Command::new("launchctl")
        .args(["load", "-w"])
        .arg(plist)
        .output()
        .map_err(|e| format!("failed to run launchctl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("launchctl load failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn unload_service(plist: &Path) -> Result<(), String> {
    let output = Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(plist)
        .output()
        .map_err(|e| format!("failed to run launchctl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "not loaded" errors during uninstall — idempotent.
        if !stderr.contains("Could not find specified service") {
            return Err(format!("launchctl unload failed: {}", stderr.trim()));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn start_service() -> Result<(), String> {
    let output = Command::new("launchctl")
        .args(["start", LABEL])
        .output()
        .map_err(|e| format!("failed to run launchctl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("launchctl start failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn stop_service() -> Result<(), String> {
    let output = Command::new("launchctl")
        .args(["stop", LABEL])
        .output()
        .map_err(|e| format!("failed to run launchctl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("launchctl stop failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn query_status() -> ServiceStatus {
    let service_file = service_file_path();
    let installed = service_file.exists();

    let mut running = false;
    let mut pid = None;

    if installed
        && let Ok(output) = Command::new("launchctl").args(["list", LABEL]).output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Output format: "PID\tStatus\tLabel" or similar.
        // First line after header often starts with the PID or "-".
        for line in stdout.lines() {
            if line.contains(LABEL) {
                let parts: Vec<&str> = line.split('\t').collect();
                if let Some(pid_str) = parts.first()
                    && let Ok(p) = pid_str.trim().parse::<u32>()
                {
                    pid = Some(p);
                    running = true;
                }
                break;
            }
        }
        // If we got success but no PID line, it's loaded (may be running).
        if pid.is_none() {
            // Parse the dict format from `launchctl list <label>`.
            if let Some(pid_line) = stdout.lines().find(|l| l.contains("\"PID\"")) {
                let num: String = pid_line.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(p) = num.parse::<u32>() {
                    pid = Some(p);
                    running = true;
                }
            }
        }
    }

    ServiceStatus {
        installed,
        running,
        pid,
        service_file,
    }
}

#[cfg(target_os = "macos")]
fn show_logs() -> Result<(), String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let log_dir = PathBuf::from(&home).join(".opaque").join("logs");
    let stderr_log = log_dir.join("opaqued.stderr.log");

    if !stderr_log.exists() {
        return Err(format!(
            "no log file found at {} (is the service installed?)",
            stderr_log.display()
        ));
    }

    // Show last 50 lines.
    let output = Command::new("tail")
        .args(["-50"])
        .arg(&stderr_log)
        .output()
        .map_err(|e| format!("failed to read logs: {e}"))?;

    let content = String::from_utf8_lossy(&output.stdout);
    if content.is_empty() {
        crate::ui::info("Log file is empty.");
    } else {
        crate::ui::header("Recent daemon logs");
        print!("{content}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Platform: Linux (systemd --user)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const UNIT_NAME: &str = "opaqued.service";

#[cfg(target_os = "linux")]
fn service_file_path() -> PathBuf {
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".config")
        });
    config_dir.join("systemd").join("user").join(UNIT_NAME)
}

#[cfg(target_os = "linux")]
fn generate_service_file(opaqued_path: &Path) -> String {
    format!(
        r#"[Unit]
Description=Opaque Daemon
Documentation=https://github.com/kcirtapfromspace/opaque
After=graphical-session.target

[Service]
Type=simple
ExecStart={}
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"#,
        opaqued_path.display()
    )
}

#[cfg(target_os = "linux")]
fn load_service(_unit_path: &Path) -> Result<(), String> {
    // Reload systemd to pick up the new unit file.
    let reload = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output()
        .map_err(|e| format!("failed to run systemctl: {e}"))?;
    if !reload.status.success() {
        let stderr = String::from_utf8_lossy(&reload.stderr);
        return Err(format!("systemctl daemon-reload failed: {}", stderr.trim()));
    }

    // Enable and start.
    let enable = Command::new("systemctl")
        .args(["--user", "enable", "--now", UNIT_NAME])
        .output()
        .map_err(|e| format!("failed to run systemctl: {e}"))?;
    if !enable.status.success() {
        let stderr = String::from_utf8_lossy(&enable.stderr);
        return Err(format!("systemctl enable failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unload_service(_unit_path: &Path) -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(["--user", "disable", "--now", UNIT_NAME])
        .output()
        .map_err(|e| format!("failed to run systemctl: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "not loaded" errors — idempotent.
        if !stderr.contains("not loaded") && !stderr.contains("not found") {
            return Err(format!("systemctl disable failed: {}", stderr.trim()));
        }
    }

    // Reload so systemd forgets the unit.
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    Ok(())
}

#[cfg(target_os = "linux")]
fn start_service() -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(["--user", "start", UNIT_NAME])
        .output()
        .map_err(|e| format!("failed to run systemctl: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("systemctl start failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn stop_service() -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(["--user", "stop", UNIT_NAME])
        .output()
        .map_err(|e| format!("failed to run systemctl: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("systemctl stop failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn query_status() -> ServiceStatus {
    let service_file = service_file_path();
    let installed = service_file.exists();

    let mut running = false;
    let mut pid = None;

    if installed {
        if let Ok(output) = Command::new("systemctl")
            .args([
                "--user",
                "show",
                UNIT_NAME,
                "--property=ActiveState,MainPID",
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(state) = line.strip_prefix("ActiveState=") {
                        running = state == "active";
                    }
                    if let Some(pid_str) = line.strip_prefix("MainPID=") {
                        if let Ok(p) = pid_str.parse::<u32>() {
                            if p > 0 {
                                pid = Some(p);
                            }
                        }
                    }
                }
            }
        }
    }

    ServiceStatus {
        installed,
        running,
        pid,
        service_file,
    }
}

#[cfg(target_os = "linux")]
fn show_logs() -> Result<(), String> {
    let output = Command::new("journalctl")
        .args(["--user", "-u", UNIT_NAME, "-n", "50", "--no-pager"])
        .output()
        .map_err(|e| format!("failed to run journalctl: {e}"))?;

    let content = String::from_utf8_lossy(&output.stdout);
    if content.is_empty() {
        crate::ui::info("No log entries found.");
    } else {
        crate::ui::header("Recent daemon logs");
        print!("{content}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unsupported platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn service_file_path() -> PathBuf {
    PathBuf::from("unsupported")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn generate_service_file(_opaqued_path: &Path) -> String {
    String::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn load_service(_path: &Path) -> Result<(), String> {
    Err("service management is not supported on this platform".into())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unload_service(_path: &Path) -> Result<(), String> {
    Err("service management is not supported on this platform".into())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn start_service() -> Result<(), String> {
    Err("service management is not supported on this platform".into())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn stop_service() -> Result<(), String> {
    Err("service management is not supported on this platform".into())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn query_status() -> ServiceStatus {
    ServiceStatus {
        installed: false,
        running: false,
        pid: None,
        service_file: PathBuf::from("unsupported"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn show_logs() -> Result<(), String> {
    Err("service management is not supported on this platform".into())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the `opaqued` binary. Checks:
/// 1. Same directory as the current executable (cargo build layout)
/// 2. `which opaqued` on PATH
fn find_opaqued() -> Result<PathBuf, String> {
    // Check next to the current executable first.
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        let sibling = dir.join("opaqued");
        if sibling.exists() {
            return Ok(sibling.canonicalize().unwrap_or(sibling));
        }
    }

    // Fall back to PATH lookup.
    if let Ok(output) = Command::new("which").arg("opaqued").output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            let p = PathBuf::from(&path);
            return Ok(p.canonicalize().unwrap_or(p));
        }
    }

    Err(
        "could not find opaqued binary (not in PATH or next to opaque CLI). \
         Build with 'cargo build --workspace' first."
            .into(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_file_path_is_in_home() {
        let path = service_file_path();
        let path_str = path.display().to_string();

        #[cfg(target_os = "macos")]
        assert!(
            path_str.contains("LaunchAgents"),
            "expected LaunchAgents in path, got: {path_str}"
        );

        #[cfg(target_os = "linux")]
        assert!(
            path_str.contains("systemd/user"),
            "expected systemd/user in path, got: {path_str}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generate_plist_contains_binary_path() {
        let content = generate_service_file(Path::new("/usr/local/bin/opaqued"));
        assert!(content.contains("/usr/local/bin/opaqued"));
        assert!(content.contains(LABEL));
        assert!(content.contains("RunAtLoad"));
        assert!(content.contains("KeepAlive"));
        assert!(content.contains("RUST_LOG"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generate_unit_contains_binary_path() {
        let content = generate_service_file(Path::new("/usr/local/bin/opaqued"));
        assert!(content.contains("ExecStart=/usr/local/bin/opaqued"));
        assert!(content.contains("Restart=on-failure"));
        assert!(content.contains("RUST_LOG=info"));
    }

    #[test]
    fn find_opaqued_from_sibling_dir() {
        // This test checks that find_opaqued works when opaqued is next to
        // the current exe. In test context, this may or may not find it
        // depending on the build state. We just verify it doesn't panic.
        let _ = find_opaqued();
    }

    #[test]
    fn query_status_does_not_panic() {
        // Just verify the status query doesn't panic, even if the service
        // is not installed.
        let st = query_status();
        // service_file should always have a path.
        assert!(!st.service_file.as_os_str().is_empty());
    }
}
