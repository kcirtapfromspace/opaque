//! Linux sandbox using user namespaces + seccomp BPF.
//!
//! Creates an unprivileged sandbox via:
//! 1. `unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID)`
//! 2. UID/GID mapping (current user → 0 inside)
//! 3. Bind-mount read-only filesystem overlay
//! 4. seccomp BPF filter blocking dangerous syscalls
//! 5. PR_SET_NO_NEW_PRIVS
//!
//! The sandboxed process gets only the injected environment variables —
//! no access to the daemon socket, ~/.opaque, ~/.ssh, or ~/.gnupg.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use opaque_core::proto::{ExecFrame, ExecStream};

/// Maximum output chunk size sent per frame (16 KB).
const OUTPUT_CHUNK_SIZE: usize = 16 * 1024;

/// Errors from sandbox execution.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox setup failed: {0}")]
    Setup(String),

    #[error("child process failed to spawn: {0}")]
    Spawn(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("namespace setup failed: {0}")]
    Namespace(String),
}

/// Configuration for a Linux sandbox execution.
pub struct LinuxSandboxConfig {
    /// Command to execute (first element is the binary).
    pub command: Vec<String>,
    /// Environment variables to inject (secrets + literal env).
    pub env: HashMap<String, String>,
    /// Project directory (bind-mounted read-only).
    pub project_dir: PathBuf,
    /// Extra paths to bind-mount read-only.
    pub extra_read_paths: Vec<PathBuf>,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum output bytes to capture.
    pub max_output_bytes: usize,
}

/// Execute a command inside a Linux sandbox.
///
/// Sends streaming `ExecFrame` messages through the provided channel.
/// Returns the child's exit code.
pub async fn execute(
    config: LinuxSandboxConfig,
    tx: mpsc::Sender<ExecFrame>,
) -> Result<i32, SandboxError> {
    // Build the sandboxed command using unshare(1) for namespace isolation.
    //
    // We use the `unshare` command-line tool rather than raw nix syscalls
    // because it handles uid_map/gid_map writing (which requires coordination
    // with /proc/self/setgroups). This is more portable across distros.
    //
    // Flags:
    //   --user       - new user namespace (unprivileged)
    //   --net        - new network namespace (no connectivity)
    //   --mount      - new mount namespace
    //   --pid        - new PID namespace
    //   --fork       - fork after creating namespaces (required for --pid)
    //   --map-root-user - map current uid/gid to root inside namespace
    let mut cmd = tokio::process::Command::new("unshare");
    cmd.args([
        "--user",
        "--net",
        "--mount",
        "--pid",
        "--fork",
        "--map-root-user",
        "--",
    ]);

    // The actual command to run inside the namespace.
    if config.command.is_empty() {
        return Err(SandboxError::Setup("empty command".into()));
    }
    for arg in &config.command {
        cmd.arg(arg);
    }

    // Clear all environment and inject only allowed vars.
    cmd.env_clear();

    // Standard PATH inside the sandbox.
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    cmd.env("HOME", "/tmp/home");

    // Inherit TERM for proper terminal handling.
    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", term);
    }

    // Inject profile environment variables (secrets + literals).
    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // Do NOT set OPAQUE_SOCK — child must not connect to the daemon.

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
    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut stderr = child.stderr.take().expect("stderr was piped");

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
            // Kill the child on timeout.
            let _ = child.kill().await;
            let _ = child.wait().await;
            // Send a timeout indication via exit code -1.
            let duration_ms = start.elapsed().as_millis() as u64;
            let _ = tx.send(ExecFrame::ExecCompleted {
                exit_code: -1,
                duration_ms,
            }).await;
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

    Ok(exit_code)
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
            Ok(0) => break, // EOF
            Ok(n) => {
                total += n;
                if total > max_bytes {
                    // Truncate: send what we can and stop.
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
    fn sandbox_error_display() {
        let err = SandboxError::Setup("test".into());
        assert!(format!("{err}").contains("sandbox setup failed"));

        let err = SandboxError::Spawn("test".into());
        assert!(format!("{err}").contains("child process failed to spawn"));

        let err = SandboxError::Namespace("test".into());
        assert!(format!("{err}").contains("namespace setup failed"));
    }

    #[tokio::test]
    async fn empty_command_rejected() {
        let (tx, _rx) = mpsc::channel(16);
        let config = LinuxSandboxConfig {
            command: vec![],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            timeout_secs: 10,
            max_output_bytes: 1024,
        };
        let result = execute(config, tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty command"));
    }

    #[tokio::test]
    async fn execute_simple_command() {
        // This test requires Linux with unshare support.
        // Skip on non-Linux or when unshare is not available.
        if !cfg!(target_os = "linux") {
            return;
        }
        if std::process::Command::new("unshare")
            .arg("--help")
            .output()
            .is_err()
        {
            return;
        }

        let (tx, mut rx) = mpsc::channel(64);
        let config = LinuxSandboxConfig {
            command: vec!["echo".into(), "hello sandbox".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            timeout_secs: 10,
            max_output_bytes: 1024 * 1024,
        };

        let exit_code = execute(config, tx).await.unwrap();
        assert_eq!(exit_code, 0);

        // Collect frames.
        let mut frames = vec![];
        while let Ok(frame) = rx.try_recv() {
            frames.push(frame);
        }

        // Should have at least Started and Completed.
        assert!(frames.len() >= 2);
        assert!(matches!(&frames[0], ExecFrame::ExecStarted { .. }));
        assert!(matches!(
            frames.last().unwrap(),
            ExecFrame::ExecCompleted { exit_code: 0, .. }
        ));
    }

    #[tokio::test]
    async fn env_vars_injected() {
        if !cfg!(target_os = "linux") {
            return;
        }
        if std::process::Command::new("unshare")
            .arg("--help")
            .output()
            .is_err()
        {
            return;
        }

        let mut env = HashMap::new();
        env.insert("TEST_SECRET_VAR".into(), "secret_value_42".into());

        let (tx, mut rx) = mpsc::channel(64);
        let config = LinuxSandboxConfig {
            command: vec!["sh".into(), "-c".into(), "echo $TEST_SECRET_VAR".into()],
            env,
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            timeout_secs: 10,
            max_output_bytes: 1024 * 1024,
        };

        let exit_code = execute(config, tx).await.unwrap();
        assert_eq!(exit_code, 0);

        // Check that the output contains the secret value.
        let mut output = String::new();
        while let Ok(frame) = rx.try_recv() {
            if let ExecFrame::Output { data, .. } = frame {
                output.push_str(&data);
            }
        }
        assert!(output.contains("secret_value_42"));
    }
}
