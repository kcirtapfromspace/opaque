//! macOS sandbox using sandbox-exec (Seatbelt).
//!
//! Generates a Seatbelt profile dynamically from the `ExecProfile` and runs
//! the command via `sandbox-exec -f <profile> -- <command>`.
//!
//! **Documented limitations:**
//! - `sandbox-exec` is deprecated by Apple but still functional through macOS 15+
//! - Determined attackers can bypass Seatbelt restrictions
//! - Network filtering is host-level, not as granular as Linux netns
//! - Labeled "best-effort containment" in approval UI and docs

use std::collections::HashMap;
use std::path::PathBuf;

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use opaque_core::proto::{ExecFrame, ExecStream};

/// Maximum output chunk size sent per frame (16 KB).
const OUTPUT_CHUNK_SIZE: usize = 16 * 1024;

/// Errors from macOS sandbox execution.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox setup failed: {0}")]
    Setup(String),

    #[error("child process failed to spawn: {0}")]
    Spawn(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("seatbelt profile generation failed: {0}")]
    ProfileGeneration(String),
}

/// Configuration for a macOS sandbox execution.
pub struct MacOSSandboxConfig {
    /// Command to execute (first element is the binary).
    pub command: Vec<String>,
    /// Environment variables to inject (secrets + literal env).
    pub env: HashMap<String, String>,
    /// Project directory (allowed read-only).
    pub project_dir: PathBuf,
    /// Extra paths to allow read-only access.
    pub extra_read_paths: Vec<PathBuf>,
    /// Network host:port entries to allow (empty = no network).
    pub network_allow: Vec<String>,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum output bytes to capture.
    pub max_output_bytes: usize,
}

/// Generate a Seatbelt profile (Scheme syntax) from the sandbox configuration.
pub fn generate_seatbelt_profile(config: &MacOSSandboxConfig) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".into());
    let mut profile = String::new();

    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n\n");

    // Allow reading system directories.
    profile.push_str("; System read access\n");
    profile.push_str("(allow file-read*\n");
    profile.push_str("  (subpath \"/usr\")\n");
    profile.push_str("  (subpath \"/bin\")\n");
    profile.push_str("  (subpath \"/sbin\")\n");
    profile.push_str("  (subpath \"/Library/Frameworks\")\n");
    profile.push_str("  (subpath \"/System\")\n");
    profile.push_str("  (subpath \"/private/var/db/dyld\")\n");
    profile.push_str("  (subpath \"/private/etc\")\n");
    profile.push_str("  (subpath \"/dev\")\n");
    profile.push_str("  (subpath \"/var/folders\")\n");
    profile.push_str(")\n\n");

    // Allow reading the project directory.
    profile.push_str("; Project directory (read-only)\n");
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{}\"))\n",
        escape_seatbelt_string(&config.project_dir.to_string_lossy())
    ));

    // Extra read paths.
    for path in &config.extra_read_paths {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            escape_seatbelt_string(&path.to_string_lossy())
        ));
    }
    profile.push('\n');

    // Temp directory: read + write.
    profile.push_str("; Temp directory access\n");
    profile.push_str("(allow file-read* file-write* (subpath \"/private/tmp\"))\n");
    profile.push_str("(allow file-read* file-write* (subpath \"/tmp\"))\n");
    profile.push_str("(allow file-read* file-write* (subpath \"/var/folders\"))\n\n");

    // Deny sensitive directories explicitly (before broader allows).
    profile.push_str("; Deny access to sensitive directories\n");
    profile.push_str(&format!(
        "(deny file-read* (subpath \"{}/.opaque\"))\n",
        escape_seatbelt_string(&home)
    ));
    profile.push_str(&format!(
        "(deny file-read* (subpath \"{}/.ssh\"))\n",
        escape_seatbelt_string(&home)
    ));
    profile.push_str(&format!(
        "(deny file-read* (subpath \"{}/.gnupg\"))\n",
        escape_seatbelt_string(&home)
    ));
    profile.push_str(&format!(
        "(deny file-read* (subpath \"{}/Library/Keychains\"))\n\n",
        escape_seatbelt_string(&home)
    ));

    // Network access.
    if config.network_allow.is_empty() {
        profile.push_str("; No network access\n");
        profile.push_str("(deny network*)\n\n");
    } else {
        profile.push_str("; Network egress allowlist\n");
        for entry in &config.network_allow {
            profile.push_str(&format!(
                "(allow network-outbound (remote tcp \"{}\"))\n",
                escape_seatbelt_string(entry)
            ));
        }
        profile.push('\n');
    }

    // Process execution.
    profile.push_str("; Process control\n");
    profile.push_str("(allow process-exec)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow signal (target self))\n\n");

    // Deny process inspection (prevents reading other process memory/info).
    profile.push_str("; Deny process inspection\n");
    profile.push_str("(deny process-info-pidinfo)\n\n");

    // System basics.
    profile.push_str("; System basics\n");
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow mach-lookup)\n");

    profile
}

/// Escape a string for Seatbelt profile (Scheme syntax).
fn escape_seatbelt_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Execute a command inside a macOS sandbox.
///
/// Sends streaming `ExecFrame` messages through the provided channel.
/// Returns the child's exit code.
pub async fn execute(
    config: MacOSSandboxConfig,
    tx: mpsc::Sender<ExecFrame>,
) -> Result<i32, SandboxError> {
    if config.command.is_empty() {
        return Err(SandboxError::Setup("empty command".into()));
    }

    // Generate and write the Seatbelt profile to a temp file.
    let profile_content = generate_seatbelt_profile(&config);
    let profile_path = write_temp_profile(&profile_content)?;

    // Build the sandbox-exec command.
    let mut cmd = tokio::process::Command::new("sandbox-exec");
    cmd.args(["-f", &profile_path.to_string_lossy()]);
    cmd.arg("--");
    for arg in &config.command {
        cmd.arg(arg);
    }

    // Clear all environment and inject only allowed vars.
    cmd.env_clear();
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    cmd.env("HOME", "/tmp");

    // Inherit TERM for proper terminal handling.
    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", term);
    }

    // Inject profile environment variables.
    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // Do NOT set OPAQUE_SOCK.

    // Set working directory to the project dir.
    cmd.current_dir(&config.project_dir);

    // Capture stdout/stderr.
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());

    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Spawn(e.to_string()))?;

    let pid = child.id().unwrap_or(0);
    let _ = tx.send(ExecFrame::ExecStarted { pid }).await;

    let start = std::time::Instant::now();

    // Stream stdout and stderr concurrently.
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let tx_out = tx.clone();
    let tx_err = tx.clone();
    let max_bytes = config.max_output_bytes;

    let stdout_task = tokio::spawn(stream_output(stdout, tx_out, ExecStream::Stdout, max_bytes));
    let stderr_task = tokio::spawn(stream_output(stderr, tx_err, ExecStream::Stderr, max_bytes));

    // Wait for child with timeout.
    let timeout = std::time::Duration::from_secs(config.timeout_secs);
    let exit_status = tokio::select! {
        result = child.wait() => {
            result.map_err(SandboxError::Io)?
        }
        _ = tokio::time::sleep(timeout) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let duration_ms = start.elapsed().as_millis() as u64;
            let _ = tx.send(ExecFrame::ExecCompleted {
                exit_code: -1,
                duration_ms,
            }).await;
            // Clean up temp profile.
            let _ = std::fs::remove_file(&profile_path);
            return Ok(-1);
        }
    };

    // Wait for output streaming to complete.
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    let exit_code = exit_status.code().unwrap_or(-1);
    let duration_ms = start.elapsed().as_millis() as u64;

    let _ = tx
        .send(ExecFrame::ExecCompleted {
            exit_code,
            duration_ms,
        })
        .await;

    // Clean up temp profile file.
    let _ = std::fs::remove_file(&profile_path);

    Ok(exit_code)
}

/// Write the Seatbelt profile to a temporary file.
fn write_temp_profile(content: &str) -> Result<PathBuf, SandboxError> {
    let dir = std::env::temp_dir();
    let filename = format!("opaque-sandbox-{}.sb", std::process::id());
    let path = dir.join(filename);
    std::fs::write(&path, content)
        .map_err(|e| SandboxError::ProfileGeneration(format!("failed to write profile: {e}")))?;
    Ok(path)
}

/// Stream output from an async reader to the frame channel.
async fn stream_output(
    mut reader: impl AsyncReadExt + Unpin,
    tx: mpsc::Sender<ExecFrame>,
    stream: ExecStream,
    max_bytes: usize,
) {
    let mut buf = vec![0u8; OUTPUT_CHUNK_SIZE];
    let mut total = 0usize;

    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > max_bytes {
                    let allowed = n.saturating_sub(total - max_bytes);
                    if allowed > 0 {
                        let data = String::from_utf8_lossy(&buf[..allowed]).into_owned();
                        let _ = tx.send(ExecFrame::Output { stream, data }).await;
                    }
                    break;
                }
                let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                let _ = tx.send(ExecFrame::Output { stream, data }).await;
            }
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seatbelt_profile_contains_deny_default() {
        let config = MacOSSandboxConfig {
            command: vec!["echo".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/project"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 60,
            max_output_bytes: 1024,
        };
        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(version 1)"));
    }

    #[test]
    fn seatbelt_profile_includes_project_dir() {
        let config = MacOSSandboxConfig {
            command: vec!["ls".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/home/user/myproject"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 60,
            max_output_bytes: 1024,
        };
        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("/home/user/myproject"));
    }

    #[test]
    fn seatbelt_profile_denies_sensitive_dirs() {
        let config = MacOSSandboxConfig {
            command: vec!["ls".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 60,
            max_output_bytes: 1024,
        };
        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains(".opaque"));
        assert!(profile.contains(".ssh"));
        assert!(profile.contains(".gnupg"));
        assert!(profile.contains("Library/Keychains"));
    }

    #[test]
    fn seatbelt_profile_no_network_by_default() {
        let config = MacOSSandboxConfig {
            command: vec!["ls".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 60,
            max_output_bytes: 1024,
        };
        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn seatbelt_profile_with_network_allow() {
        let config = MacOSSandboxConfig {
            command: vec!["curl".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network_allow: vec!["api.github.com:443".into()],
            timeout_secs: 60,
            max_output_bytes: 1024,
        };
        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("api.github.com:443"));
        assert!(!profile.contains("(deny network*)"));
    }

    #[test]
    fn seatbelt_profile_extra_read_paths() {
        let config = MacOSSandboxConfig {
            command: vec!["cat".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![PathBuf::from("/opt/shared-libs")],
            network_allow: vec![],
            timeout_secs: 60,
            max_output_bytes: 1024,
        };
        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("/opt/shared-libs"));
    }

    #[test]
    fn escape_seatbelt_quotes() {
        assert_eq!(
            escape_seatbelt_string(r#"path"with"quotes"#),
            r#"path\"with\"quotes"#
        );
    }

    #[test]
    fn escape_seatbelt_backslash() {
        assert_eq!(
            escape_seatbelt_string(r"path\with\slashes"),
            r"path\\with\\slashes"
        );
    }

    #[test]
    fn sandbox_error_display() {
        let err = SandboxError::Setup("test".into());
        assert!(format!("{err}").contains("sandbox setup failed"));

        let err = SandboxError::Spawn("test".into());
        assert!(format!("{err}").contains("child process failed to spawn"));

        let err = SandboxError::ProfileGeneration("test".into());
        assert!(format!("{err}").contains("seatbelt profile generation failed"));
    }

    #[tokio::test]
    async fn empty_command_rejected() {
        let (tx, _rx) = mpsc::channel(16);
        let config = MacOSSandboxConfig {
            command: vec![],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 10,
            max_output_bytes: 1024,
        };
        let result = execute(config, tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty command"));
    }
}
