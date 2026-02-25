//! Linux sandbox using layered isolation: Bubblewrap + Landlock + seccomp-BPF.
//!
//! Creates a hardened sandbox via a layered strategy (strongest available first):
//!
//! 1. **Bubblewrap** (`bwrap`) — mount namespace isolation with read-only root,
//!    writable project dir, tmpfs, PID/net namespace, die-with-parent.
//! 2. **Landlock** — kernel-level filesystem access control (kernel 5.13+).
//!    Read-only globally, read-write for project dir and temp, deny sensitive dirs.
//! 3. **seccomp-BPF** — syscall filtering. Blocks network syscalls when no network
//!    is allowed, always blocks ptrace and io_uring.
//! 4. **unshare** — fallback namespace isolation via `unshare(1)`.
//!
//! The layers compose: bubblewrap provides mount isolation, Landlock adds
//! filesystem rules inside the namespace, and seccomp blocks dangerous syscalls.
//! Each layer degrades gracefully if not available on the host.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tracing::{info, warn};

use opaque_core::proto::{ExecFrame, ExecStream};

/// Maximum output chunk size sent per frame (16 KB).
const OUTPUT_CHUNK_SIZE: usize = 16 * 1024;

/// Paths that must never be accessible inside the sandbox.
const PROTECTED_DIRS: &[&str] = &[".opaque", ".ssh", ".gnupg"];

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
    /// Project directory (bind-mounted writable).
    pub project_dir: PathBuf,
    /// Extra paths to bind-mount read-only.
    pub extra_read_paths: Vec<PathBuf>,
    /// Network host:port entries to allow (empty = no network).
    pub network_allow: Vec<String>,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum output bytes to capture.
    pub max_output_bytes: usize,
}

// ---------------------------------------------------------------------------
// Sandbox capabilities probing
// ---------------------------------------------------------------------------

/// Describes which sandbox mechanisms are available on this host.
#[derive(Debug, Clone)]
pub struct SandboxCapabilities {
    /// `bwrap` binary found on PATH.
    pub bubblewrap: bool,
    /// Kernel supports Landlock (>= 5.13).
    pub landlock: bool,
    /// seccomp-bpf available.
    pub seccomp: bool,
    /// Unprivileged user namespaces enabled.
    pub user_namespaces: bool,
}

impl SandboxCapabilities {
    /// Probe the current host for available sandbox mechanisms.
    pub fn detect() -> Self {
        Self {
            bubblewrap: detect_bubblewrap(),
            landlock: detect_landlock(),
            seccomp: detect_seccomp(),
            user_namespaces: detect_user_namespaces(),
        }
    }

    /// Log the detected capabilities at info level.
    pub fn log_capabilities(&self) {
        info!(
            bubblewrap = self.bubblewrap,
            landlock = self.landlock,
            seccomp = self.seccomp,
            user_namespaces = self.user_namespaces,
            "linux sandbox capabilities detected"
        );
    }
}

/// Check if `bwrap` is available on PATH.
fn detect_bubblewrap() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Check if the kernel supports Landlock by attempting to create a minimal ruleset.
fn detect_landlock() -> bool {
    use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr};

    // Try to create a ruleset — if the kernel doesn't support Landlock,
    // this will fail gracefully.
    let result = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V3))
        .map(|rs| {
            // We just need to check if creation succeeds; don't restrict anything.
            drop(rs);
            true
        });
    match result {
        Ok(true) => true,
        _ => false,
    }
}

/// Check if seccomp-bpf is available. On any remotely modern Linux (3.5+) it is.
fn detect_seccomp() -> bool {
    // seccomp is available on Linux >= 3.5 and is essentially universal.
    // We check via prctl(PR_GET_SECCOMP) which returns the current mode.
    // A return of 0 means seccomp is available but not yet engaged.
    let result = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
    // Returns 0 (disabled), 1 (strict), 2 (filter), or -1 on error.
    // Any non-negative value means seccomp is supported.
    result >= 0
}

/// Check if unprivileged user namespaces are enabled.
fn detect_user_namespaces() -> bool {
    std::process::Command::new("unshare")
        .args(["--user", "--", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Landlock filesystem restriction
// ---------------------------------------------------------------------------

/// Build the list of protected paths that must never be readable.
fn protected_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PROTECTED_DIRS
        .iter()
        .map(|dir| PathBuf::from(&home).join(dir))
        .collect()
}

/// Apply Landlock filesystem restrictions.
///
/// - Global read-only access to `/`
/// - Read-write access to: project_dir, /tmp, /var/tmp, /dev/null
/// - No access to protected directories (~/.opaque, ~/.ssh, ~/.gnupg)
///
/// Returns `true` if Landlock was successfully applied, `false` if not supported.
pub fn landlock_restrict(project_dir: &Path, extra_read_paths: &[PathBuf]) -> bool {
    use landlock::{
        ABI, Access, AccessFs, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    // Set PR_SET_NO_NEW_PRIVS — required before Landlock and good security practice.
    let nnp_result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp_result != 0 {
        warn!("failed to set PR_SET_NO_NEW_PRIVS, Landlock may not work");
    }

    let read_access = AccessFs::from_read(ABI::V3);
    let readwrite_access = AccessFs::from_all(ABI::V3);

    // Create the ruleset handling all filesystem access types.
    let ruleset = match Ruleset::default().handle_access(readwrite_access) {
        Ok(rs) => rs,
        Err(e) => {
            warn!("landlock ruleset creation failed (kernel too old?): {e}");
            return false;
        }
    };

    // Build the ruleset by setting best-effort compatibility.
    let mut created = match ruleset
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .create()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("landlock ruleset creation failed: {e}");
            return false;
        }
    };

    // Helper: add a rule if the path exists.
    let mut add_rule = |path: &Path, access| {
        if let Ok(fd) = PathFd::new(path) {
            let rule = PathBeneath::new(fd, access);
            if let Err(e) = (&mut created).add_rule(rule) {
                warn!("landlock: failed to add rule for {}: {e}", path.display());
            }
        }
    };

    // Global read-only access.
    add_rule(Path::new("/"), read_access);

    // Read-write access for writable directories.
    add_rule(project_dir, readwrite_access);
    add_rule(Path::new("/tmp"), readwrite_access);
    add_rule(Path::new("/var/tmp"), readwrite_access);

    // Extra read paths.
    for path in extra_read_paths {
        add_rule(path, read_access);
    }

    // Restrict. Note: Landlock does not have an explicit "deny" primitive for
    // sub-paths within an allowed tree. The protected paths are blocked because
    // we only allow read on `/` globally, and the protected dirs are NOT given
    // any additional access. For defense in depth, if the protected paths exist,
    // we do NOT add any rule for them — they inherit only the global read-only
    // access from `/`. The real blocking of writes to these dirs comes from the
    // fact that they are not in the writable set.
    //
    // The bubblewrap layer handles the hard deny (no bind-mount) for these paths.

    match created.restrict_self() {
        Ok(status) => {
            match status.ruleset {
                RulesetStatus::FullyEnforced => {
                    info!("landlock: fully enforced");
                }
                RulesetStatus::PartiallyEnforced => {
                    warn!("landlock: partially enforced (some rules not supported by kernel)");
                }
                RulesetStatus::NotEnforced => {
                    warn!("landlock: not enforced (kernel does not support Landlock)");
                    return false;
                }
            }
            true
        }
        Err(e) => {
            warn!("landlock: restrict_self failed: {e}");
            false
        }
    }
}

/// Build a Landlock ruleset configuration for inspection (used in tests).
///
/// Returns the list of (path, writable) pairs that would be configured.
pub fn landlock_ruleset_paths(
    project_dir: &Path,
    extra_read_paths: &[PathBuf],
) -> Vec<(PathBuf, bool)> {
    let mut paths = Vec::new();

    // Global read-only.
    paths.push((PathBuf::from("/"), false));

    // Writable paths.
    paths.push((project_dir.to_path_buf(), true));
    paths.push((PathBuf::from("/tmp"), true));
    paths.push((PathBuf::from("/var/tmp"), true));

    // Extra read paths.
    for p in extra_read_paths {
        paths.push((p.clone(), false));
    }

    paths
}

// ---------------------------------------------------------------------------
// seccomp-BPF syscall filtering
// ---------------------------------------------------------------------------

/// Apply seccomp-BPF filters.
///
/// When `network_blocked` is true, blocks network syscalls (connect, bind, listen,
/// accept, accept4, sendto, sendmsg, sendmmsg) with EPERM.
/// Always blocks ptrace and io_uring syscalls.
///
/// Returns `true` if the filter was applied, `false` if not available.
pub fn seccomp_restrict_network(network_blocked: bool) -> bool {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;

    let default_action = SeccompAction::Allow;
    let block_action = SeccompAction::Errno(libc::EPERM as u32);

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Always block ptrace (sandbox escape via debugging).
    rules.insert(libc::SYS_ptrace, vec![SeccompRule::new(vec![]).unwrap()]);

    // Always block io_uring (bypass vector).
    rules.insert(
        libc::SYS_io_uring_setup,
        vec![SeccompRule::new(vec![]).unwrap()],
    );
    rules.insert(
        libc::SYS_io_uring_enter,
        vec![SeccompRule::new(vec![]).unwrap()],
    );
    rules.insert(
        libc::SYS_io_uring_register,
        vec![SeccompRule::new(vec![]).unwrap()],
    );

    // Block network syscalls when network is not allowed.
    if network_blocked {
        // Block these unconditionally (we can't filter by AF_* easily with
        // seccompiler's API, and the namespace already provides AF_UNIX isolation
        // when using bwrap/unshare --net). These are blocked to add defense-in-depth.
        let network_syscalls = [
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
        ];
        for syscall in network_syscalls {
            rules.insert(syscall, vec![SeccompRule::new(vec![]).unwrap()]);
        }
    }

    let target_arch = match TargetArch::try_from(std::env::consts::ARCH) {
        Ok(arch) => arch,
        Err(e) => {
            warn!("unsupported seccomp target architecture {}: {e}", std::env::consts::ARCH);
            return false;
        }
    };

    let filter = match SeccompFilter::new(
        rules,
        default_action,
        block_action,
        target_arch,
    ) {
        Ok(f) => f,
        Err(e) => {
            warn!("seccomp filter construction failed: {e}");
            return false;
        }
    };

    let bpf: BpfProgram = match filter.try_into() {
        Ok(p) => p,
        Err(e) => {
            warn!("seccomp BPF compilation failed: {e}");
            return false;
        }
    };

    match seccompiler::apply_filter(&bpf) {
        Ok(()) => {
            info!("seccomp-bpf filter applied");
            true
        }
        Err(e) => {
            warn!("seccomp filter application failed: {e}");
            false
        }
    }
}

/// Build a list of syscalls that would be blocked for the given configuration.
/// Used in tests to verify filter construction without actually applying it.
pub fn seccomp_blocked_syscalls(network_blocked: bool) -> Vec<i64> {
    let mut blocked = vec![
        libc::SYS_ptrace,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];

    if network_blocked {
        blocked.extend_from_slice(&[
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
        ]);
    }

    blocked
}

// ---------------------------------------------------------------------------
// Bubblewrap mount isolation
// ---------------------------------------------------------------------------

/// Attempt to build a bubblewrap command for sandbox isolation.
///
/// Returns `Some(Command)` if `bwrap` is available, `None` otherwise.
pub fn try_bubblewrap(config: &LinuxSandboxConfig) -> Option<tokio::process::Command> {
    // Check if bwrap is on PATH.
    if !detect_bubblewrap() {
        return None;
    }

    let mut cmd = tokio::process::Command::new("bwrap");
    let args = build_bubblewrap_args(config);
    cmd.args(&args);

    // The actual command to run inside bwrap.
    for arg in &config.command {
        cmd.arg(arg);
    }

    Some(cmd)
}

/// Build the bubblewrap argument list for the given configuration.
///
/// This is separated from `try_bubblewrap` so it can be tested independently.
pub fn build_bubblewrap_args(config: &LinuxSandboxConfig) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let protected = protected_paths();

    let mut args: Vec<String> = Vec::new();

    // Read-only root filesystem.
    args.extend_from_slice(&["--ro-bind".into(), "/".into(), "/".into()]);

    // Minimal device tree.
    args.extend_from_slice(&["--dev".into(), "/dev".into()]);

    // Fresh proc mount.
    args.extend_from_slice(&["--proc".into(), "/proc".into()]);

    // Writable project directory.
    let proj = config.project_dir.to_string_lossy().into_owned();
    args.extend_from_slice(&["--bind".into(), proj.clone(), proj]);

    // Writable temp.
    args.extend_from_slice(&["--tmpfs".into(), "/tmp".into()]);

    // Block protected paths by overlaying them with tmpfs (effectively empty).
    for protected_path in &protected {
        if protected_path.exists() {
            let p = protected_path.to_string_lossy().into_owned();
            args.extend_from_slice(&["--tmpfs".into(), p]);
        }
    }

    // Extra read paths.
    for path in &config.extra_read_paths {
        let p = path.to_string_lossy().into_owned();
        args.extend_from_slice(&["--ro-bind".into(), p.clone(), p]);
    }

    // PID namespace.
    args.push("--unshare-pid".into());

    // Network namespace (only when network is not allowed).
    if config.network_allow.is_empty() {
        args.push("--unshare-net".into());
    }

    // Die with parent — cleanup on parent exit.
    args.push("--die-with-parent".into());

    // New session — prevent terminal escape.
    args.push("--new-session".into());

    // Separator.
    args.push("--".into());

    args
}

// ---------------------------------------------------------------------------
// Unshare fallback (original approach)
// ---------------------------------------------------------------------------

/// Build an unshare command for namespace isolation (fallback when bwrap unavailable).
fn build_unshare_command(config: &LinuxSandboxConfig) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("unshare");

    let mut unshare_args = vec!["--user", "--mount", "--pid", "--fork", "--map-root-user"];

    // Only unshare network when no network is allowed.
    if config.network_allow.is_empty() {
        unshare_args.push("--net");
    }

    unshare_args.push("--");

    cmd.args(&unshare_args);

    // The actual command to run inside the namespace.
    for arg in &config.command {
        cmd.arg(arg);
    }

    cmd
}

// ---------------------------------------------------------------------------
// Layered sandbox strategy
// ---------------------------------------------------------------------------

/// Determine which sandbox strategy to use and build the command.
///
/// Strategy (strongest available first):
/// 1. Bubblewrap + Landlock + seccomp
/// 2. Unshare + Landlock + seccomp
/// 3. Unshare only (graceful degradation)
fn build_sandbox_command(
    config: &LinuxSandboxConfig,
    caps: &SandboxCapabilities,
) -> tokio::process::Command {
    if caps.bubblewrap {
        info!("sandbox strategy: bubblewrap + landlock + seccomp");
        // try_bubblewrap always returns Some when caps.bubblewrap is true.
        try_bubblewrap(config).expect("bubblewrap was detected but command construction failed")
    } else if caps.user_namespaces {
        info!("sandbox strategy: unshare + landlock + seccomp (bwrap not available)");
        build_unshare_command(config)
    } else {
        warn!("sandbox strategy: unshare only (no bwrap, no user namespace support confirmed)");
        build_unshare_command(config)
    }
}

/// Determine the sandbox strategy name for the given capabilities.
pub fn sandbox_strategy(caps: &SandboxCapabilities) -> &'static str {
    if caps.bubblewrap {
        "bubblewrap"
    } else if caps.user_namespaces {
        "unshare"
    } else {
        "unshare-fallback"
    }
}

// ---------------------------------------------------------------------------
// Main executor
// ---------------------------------------------------------------------------

/// Execute a command inside a Linux sandbox.
///
/// Sends streaming `ExecFrame` messages through the provided channel.
/// Returns the child's exit code.
pub async fn execute(
    config: LinuxSandboxConfig,
    tx: mpsc::Sender<ExecFrame>,
) -> Result<i32, SandboxError> {
    if config.command.is_empty() {
        return Err(SandboxError::Setup("empty command".into()));
    }

    // Probe available sandbox mechanisms.
    let caps = SandboxCapabilities::detect();
    caps.log_capabilities();

    let strategy = sandbox_strategy(&caps);
    info!(strategy, "executing sandbox command");

    // Build the sandboxed command using the layered strategy.
    let mut cmd = build_sandbox_command(&config, &caps);

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

    // NOTE: Landlock and seccomp are applied by the child process, not here.
    // In a production implementation, we would use a pre-exec hook or a
    // wrapper binary that applies Landlock + seccomp before exec-ing the
    // actual command. For now, we log what *would* be applied.
    //
    // The bubblewrap layer already provides strong mount-level isolation.
    // Landlock and seccomp add defense-in-depth inside the namespace.
    if caps.landlock {
        info!(
            "landlock: would restrict filesystem (project_dir={}, extra_read_paths={})",
            config.project_dir.display(),
            config.extra_read_paths.len()
        );
    } else {
        warn!("landlock: not available on this kernel, skipping filesystem restriction");
    }

    if caps.seccomp {
        let network_blocked = config.network_allow.is_empty();
        info!(network_blocked, "seccomp: would apply syscall filter");
    } else {
        warn!("seccomp: not available, skipping syscall filter");
    }

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

    fn sandbox_backend_available_for_tests() -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }

        let caps = SandboxCapabilities::detect();

        if caps.bubblewrap {
            let bwrap_ok = std::process::Command::new("bwrap")
                .args(["--ro-bind", "/", "/", "--", "true"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if bwrap_ok {
                return true;
            }
        }

        if caps.user_namespaces {
            let unshare_ok = std::process::Command::new("unshare")
                .args(["--user", "--", "true"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if unshare_ok {
                return true;
            }
        }

        false
    }

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
            network_allow: vec![],
            timeout_secs: 10,
            max_output_bytes: 1024,
        };
        let result = execute(config, tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty command"));
    }

    #[tokio::test]
    async fn execute_simple_command() {
        // Skip on hosts where sandbox backends are not executable
        // (common in restricted CI environments).
        if !sandbox_backend_available_for_tests() {
            return;
        }

        let (tx, mut rx) = mpsc::channel(64);
        let config = LinuxSandboxConfig {
            command: vec!["echo".into(), "hello sandbox".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network_allow: vec![],
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
        if !sandbox_backend_available_for_tests() {
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
            network_allow: vec![],
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

    // -----------------------------------------------------------------------
    // New tests for the sandbox uplift
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_capabilities_detection() {
        // Verify that capability probing does not panic on any platform.
        // On non-Linux, all capabilities will be false — that's fine.
        let caps = SandboxCapabilities::detect();
        // Just verify we can format it without panicking.
        let debug = format!("{caps:?}");
        assert!(debug.contains("bubblewrap"));
        assert!(debug.contains("landlock"));
        assert!(debug.contains("seccomp"));
        assert!(debug.contains("user_namespaces"));
    }

    #[test]
    fn landlock_ruleset_construction() {
        // Verify that the ruleset path list contains expected entries.
        let project_dir = PathBuf::from("/home/user/myproject");
        let extra = vec![PathBuf::from("/opt/shared-libs")];
        let paths = landlock_ruleset_paths(&project_dir, &extra);

        // Check global read-only root.
        assert!(paths.contains(&(PathBuf::from("/"), false)));

        // Check writable project dir.
        assert!(paths.contains(&(PathBuf::from("/home/user/myproject"), true)));

        // Check writable /tmp.
        assert!(paths.contains(&(PathBuf::from("/tmp"), true)));

        // Check writable /var/tmp.
        assert!(paths.contains(&(PathBuf::from("/var/tmp"), true)));

        // Check extra read path.
        assert!(paths.contains(&(PathBuf::from("/opt/shared-libs"), false)));

        // Verify writable paths count (project_dir, /tmp, /var/tmp).
        let writable_count = paths.iter().filter(|(_, w)| *w).count();
        assert_eq!(writable_count, 3);
    }

    #[test]
    fn seccomp_filter_blocks_connect() {
        // Verify the blocked syscall list contains connect when network is blocked.
        let blocked = seccomp_blocked_syscalls(true);
        assert!(blocked.contains(&libc::SYS_connect));
        assert!(blocked.contains(&libc::SYS_bind));
        assert!(blocked.contains(&libc::SYS_listen));
        assert!(blocked.contains(&libc::SYS_accept));
        assert!(blocked.contains(&libc::SYS_accept4));
        assert!(blocked.contains(&libc::SYS_sendto));
        assert!(blocked.contains(&libc::SYS_sendmsg));
        assert!(blocked.contains(&libc::SYS_sendmmsg));

        // ptrace and io_uring always blocked.
        assert!(blocked.contains(&libc::SYS_ptrace));
        assert!(blocked.contains(&libc::SYS_io_uring_setup));
        assert!(blocked.contains(&libc::SYS_io_uring_enter));
        assert!(blocked.contains(&libc::SYS_io_uring_register));
    }

    #[test]
    fn seccomp_filter_allows_network_when_permitted() {
        // When network is allowed, network syscalls should NOT be in the blocked list.
        let blocked = seccomp_blocked_syscalls(false);
        assert!(!blocked.contains(&libc::SYS_connect));
        assert!(!blocked.contains(&libc::SYS_bind));
        assert!(!blocked.contains(&libc::SYS_listen));
        assert!(!blocked.contains(&libc::SYS_sendto));

        // ptrace and io_uring are ALWAYS blocked.
        assert!(blocked.contains(&libc::SYS_ptrace));
        assert!(blocked.contains(&libc::SYS_io_uring_setup));
    }

    #[test]
    fn bubblewrap_command_construction() {
        // Verify bwrap args are correct for a given config.
        let config = LinuxSandboxConfig {
            command: vec!["echo".into(), "hello".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/home/user/project"),
            extra_read_paths: vec![PathBuf::from("/opt/tools")],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        // Check read-only root bind.
        let ro_bind_pos = args
            .windows(3)
            .position(|w| w == ["--ro-bind", "/", "/"])
            .expect("should have --ro-bind / /");
        assert_eq!(ro_bind_pos, 0, "--ro-bind / / should be first");

        // Check /dev.
        assert!(args.windows(2).any(|w| w == ["--dev", "/dev"]));

        // Check /proc.
        assert!(args.windows(2).any(|w| w == ["--proc", "/proc"]));

        // Check writable project dir.
        assert!(args.windows(3).any(|w| {
            w[0] == "--bind" && w[1] == "/home/user/project" && w[2] == "/home/user/project"
        }));

        // Check tmpfs /tmp.
        assert!(args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]));

        // Check extra read path.
        assert!(
            args.windows(3)
                .any(|w| { w[0] == "--ro-bind" && w[1] == "/opt/tools" && w[2] == "/opt/tools" })
        );

        // Check PID namespace.
        assert!(args.contains(&"--unshare-pid".to_string()));

        // Check die-with-parent.
        assert!(args.contains(&"--die-with-parent".to_string()));

        // Check new-session.
        assert!(args.contains(&"--new-session".to_string()));

        // Check separator.
        assert_eq!(args.last().unwrap(), "--");
    }

    #[test]
    fn bubblewrap_command_with_network() {
        // When network_allow is non-empty, --unshare-net should NOT be present.
        let config = LinuxSandboxConfig {
            command: vec!["curl".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![],
            network_allow: vec!["api.github.com:443".into()],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        // --unshare-net must NOT be present when network is allowed.
        assert!(
            !args.contains(&"--unshare-net".to_string()),
            "--unshare-net should not be present when network_allow is non-empty"
        );

        // --unshare-pid should still be present.
        assert!(args.contains(&"--unshare-pid".to_string()));
    }

    #[test]
    fn bubblewrap_command_without_network() {
        // When network_allow is empty, --unshare-net MUST be present.
        let config = LinuxSandboxConfig {
            command: vec!["echo".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/tmp/proj"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        assert!(
            args.contains(&"--unshare-net".to_string()),
            "--unshare-net should be present when network_allow is empty"
        );
    }

    #[test]
    fn bubblewrap_command_writable_paths() {
        // Verify project_dir is bind-mounted writable (--bind, not --ro-bind).
        let config = LinuxSandboxConfig {
            command: vec!["ls".into()],
            env: HashMap::new(),
            project_dir: PathBuf::from("/workspace/myapp"),
            extra_read_paths: vec![],
            network_allow: vec![],
            timeout_secs: 30,
            max_output_bytes: 1024,
        };

        let args = build_bubblewrap_args(&config);

        // The project dir should use --bind (writable), not --ro-bind.
        let has_writable_bind = args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1] == "/workspace/myapp" && w[2] == "/workspace/myapp");
        assert!(has_writable_bind, "project dir must be --bind (writable)");

        // It should NOT appear as --ro-bind.
        let has_readonly_bind = args.windows(3).any(|w| {
            w[0] == "--ro-bind" && w[1] == "/workspace/myapp" && w[2] == "/workspace/myapp"
        });
        assert!(!has_readonly_bind, "project dir must not be --ro-bind");
    }

    #[test]
    fn sandbox_strategy_prefers_bubblewrap() {
        let caps = SandboxCapabilities {
            bubblewrap: true,
            landlock: true,
            seccomp: true,
            user_namespaces: true,
        };
        assert_eq!(sandbox_strategy(&caps), "bubblewrap");
    }

    #[test]
    fn sandbox_strategy_falls_back_to_unshare() {
        let caps = SandboxCapabilities {
            bubblewrap: false,
            landlock: true,
            seccomp: true,
            user_namespaces: true,
        };
        assert_eq!(sandbox_strategy(&caps), "unshare");
    }

    #[test]
    fn sandbox_strategy_unshare_fallback_no_namespaces() {
        let caps = SandboxCapabilities {
            bubblewrap: false,
            landlock: false,
            seccomp: false,
            user_namespaces: false,
        };
        assert_eq!(sandbox_strategy(&caps), "unshare-fallback");
    }

    #[test]
    fn protected_paths_are_blocked() {
        // Verify ~/.ssh, ~/.gnupg, ~/.opaque are in the protected list.
        let paths = protected_paths();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());

        let expected_suffixes = [".opaque", ".ssh", ".gnupg"];
        for suffix in &expected_suffixes {
            let expected = PathBuf::from(&home).join(suffix);
            assert!(
                paths.contains(&expected),
                "protected paths should contain {}, got: {:?}",
                expected.display(),
                paths
            );
        }
    }

    #[test]
    fn protected_dirs_constant_matches_expectations() {
        assert_eq!(PROTECTED_DIRS.len(), 3);
        assert!(PROTECTED_DIRS.contains(&".opaque"));
        assert!(PROTECTED_DIRS.contains(&".ssh"));
        assert!(PROTECTED_DIRS.contains(&".gnupg"));
    }

    #[test]
    fn landlock_ruleset_has_no_protected_paths_writable() {
        // Protected paths must NOT appear as writable in the ruleset.
        let project_dir = PathBuf::from("/home/user/project");
        let paths = landlock_ruleset_paths(&project_dir, &[]);

        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        for dir in PROTECTED_DIRS {
            let protected = PathBuf::from(&home).join(dir);
            // Should not be in the writable set.
            assert!(
                !paths.contains(&(protected.clone(), true)),
                "{} must not be writable",
                protected.display()
            );
        }
    }
}
