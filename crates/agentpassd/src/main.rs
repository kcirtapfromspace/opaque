use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use agentpass_core::audit::TracingAuditEmitter;
use agentpass_core::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationDef,
    OperationRegistry, OperationRequest, OperationSafety,
};
use agentpass_core::peer::peer_info_from_fd;
use agentpass_core::policy::{PolicyEngine, PolicyRule};
use agentpass_core::proto::{Request, Response};
use agentpass_core::socket::{
    ensure_socket_parent_dir, socket_path_for_client, validate_path_chain,
};
use agentpass_core::validate::InputValidator;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, warn};
use uuid::Uuid;

/// Name of the daemon token file written next to the socket.
const DAEMON_TOKEN_FILENAME: &str = "daemon.token";

mod approval;
mod enclave;

use std::future::Future;
use std::pin::Pin;

use enclave::{Enclave, NativeApprovalGate, OperationHandler};

// ---------------------------------------------------------------------------
// Daemon configuration
// ---------------------------------------------------------------------------

/// Daemon configuration loaded from `~/.agentpass/config.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
struct DaemonConfig {
    /// Known human client executables. If a connecting client matches any
    /// entry, it is classified as `Human`; otherwise it defaults to `Agent`.
    #[serde(default)]
    known_human_clients: Vec<HumanClientEntry>,

    /// Policy rules loaded from config. Deny-all default when empty.
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

/// A single entry in the known human clients allowlist.
#[derive(Debug, Clone, Deserialize)]
struct HumanClientEntry {
    /// Human-readable label (for logging).
    #[allow(dead_code)]
    name: String,

    /// Glob pattern matched against the exe path.
    exe_path: Option<String>,

    /// Exact SHA-256 hex digest of the executable (case-insensitive).
    exe_sha256: Option<String>,

    /// Exact macOS code-signing Team ID.
    codesign_team_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

struct DaemonState {
    enclave: Arc<Enclave>,
    config: DaemonConfig,
    version: &'static str,
    /// Hex-encoded 32-byte CSPRNG token for handshake authentication.
    daemon_token: String,
    /// Semaphore to limit maximum concurrent connections.
    connection_semaphore: Arc<tokio::sync::Semaphore>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    init_tracing();

    // Daemon never trusts AGENTPASS_SOCK env var.
    let path = socket_path_for_client(false);
    if let Err(e) = run(path).await {
        eprintln!("agentpassd: {e}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Load daemon config from `~/.agentpass/config.toml` or `$AGENTPASS_CONFIG`.
fn load_config() -> DaemonConfig {
    let path = std::env::var("AGENTPASS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".agentpass").join("config.toml")
        });

    match std::fs::read_to_string(&path) {
        Ok(contents) => match toml_edit::de::from_str::<DaemonConfig>(&contents) {
            Ok(config) => {
                info!(
                    "loaded config from {} ({} known human clients, {} policy rules)",
                    path.display(),
                    config.known_human_clients.len(),
                    config.rules.len(),
                );
                config
            }
            Err(e) => {
                warn!("failed to parse config {}: {e}", path.display());
                DaemonConfig::default()
            }
        },
        Err(_) => {
            info!("no config file at {}, using defaults", path.display());
            DaemonConfig::default()
        }
    }
}

/// Generate a 32-byte CSPRNG hex token for daemon authentication.
fn generate_daemon_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("failed to generate random bytes");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write the daemon token to `<socket_dir>/daemon.token` with mode 0600.
fn write_daemon_token(socket: &Path, token: &str) -> std::io::Result<PathBuf> {
    let token_path = socket
        .parent()
        .expect("socket path should have a parent directory")
        .join(DAEMON_TOKEN_FILENAME);
    std::fs::write(&token_path, token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(token_path)
}

/// Minimal no-op operation handler for end-to-end testing of the enclave pipeline.
#[derive(Debug)]
struct NoopHandler;

impl OperationHandler for NoopHandler {
    fn execute(
        &self,
        _request: &OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + '_>> {
        Box::pin(async { Ok(serde_json::json!({"status": "ok"})) })
    }
}

async fn run(socket: PathBuf) -> std::io::Result<()> {
    ensure_socket_parent_dir(&socket)?;

    if socket.exists() {
        match UnixStream::connect(&socket).await {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("socket already in use: {}", socket.display()),
                ));
            }
            Err(_) => {
                // Stale socket file.
                tokio::fs::remove_file(&socket).await?;
            }
        }
    }

    // Validate no symlinks in the path chain before binding.
    validate_path_chain(&socket)?;

    let listener = UnixListener::bind(&socket)?;
    lock_down_socket_path(&socket)?;
    let _socket_guard = SocketGuard::new(socket.clone());

    // Generate and write daemon token for handshake authentication.
    let daemon_token = generate_daemon_token();
    let token_path = write_daemon_token(&socket, &daemon_token)?;
    info!("daemon token written to {}", token_path.display());

    info!("listening on {}", socket.display());

    let config = load_config();

    // Build enclave with registered operations and policy from config.
    let mut registry = OperationRegistry::new();
    registry
        .register(OperationDef {
            name: "test.noop".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "No-op test operation".into(),
            params_schema: None,
            allowed_target_keys: vec![],
        })
        .expect("failed to register test.noop");

    let policy = PolicyEngine::with_rules(config.rules.clone());
    info!("policy engine loaded with {} rules", policy.rule_count());

    let audit = Arc::new(TracingAuditEmitter::new());

    let enclave = Enclave::builder()
        .registry(registry)
        .policy(policy)
        .handler("test.noop", Box::new(NoopHandler))
        .approval_gate(Box::new(NativeApprovalGate))
        .audit(audit)
        .build();

    let state = Arc::new(DaemonState {
        enclave: Arc::new(enclave),
        config,
        version: env!("CARGO_PKG_VERSION"),
        daemon_token,
        connection_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
    });

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested (ctrl-c)");
                break;
            }
            _ = sigterm.recv() => {
                info!("shutdown requested (sigterm)");
                break;
            }
            res = listener.accept() => {
                let (stream, _addr) = res?;
                let permit = match state.connection_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("max connections reached (64), rejecting");
                        drop(stream);
                        continue;
                    }
                };
                let state = state.clone();
                tokio::spawn(async move {
                    // Hold the permit for the connection lifetime.
                    let _permit = permit;
                    if let Err(e) = handle_conn(state, stream).await {
                        warn!("connection error: {e}");
                    }
                });
            }
        }
    }

    Ok(())
}

fn lock_down_socket_path(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
}

impl SocketGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Client identity & type derivation
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of an executable file (hex-encoded).
fn compute_exe_hash(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&bytes);
    Some(format!("{hash:x}"))
}

/// Derive the client type from the client identity and daemon config.
///
/// The daemon NEVER trusts a self-declared `client_type` from request params.
/// Instead, it matches the verified peer identity against the configured
/// `known_human_clients` allowlist. If no entry matches, the client is
/// classified as `Agent` (safer — more restrictive).
fn derive_client_type(identity: &ClientIdentity, config: &DaemonConfig) -> ClientType {
    for entry in &config.known_human_clients {
        if entry_matches(identity, entry) {
            return ClientType::Human;
        }
    }
    ClientType::Agent
}

/// Check if a client identity matches a human client allowlist entry.
/// All specified fields must match; absent fields are treated as "any".
fn entry_matches(identity: &ClientIdentity, entry: &HumanClientEntry) -> bool {
    if let Some(ref pattern) = entry.exe_path {
        match &identity.exe_path {
            Some(exe) => {
                let path_str = exe.to_string_lossy();
                if !glob_match::glob_match(pattern, &path_str) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref expected_hash) = entry.exe_sha256 {
        match &identity.exe_sha256 {
            Some(actual) => {
                if !actual.eq_ignore_ascii_case(expected_hash) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref expected_team) = entry.codesign_team_id {
        match &identity.codesign_team_id {
            Some(actual) => {
                if actual != expected_team {
                    return false;
                }
            }
            None => return false,
        }
    }

    // An entry with no fields specified would match everything — but that's
    // a config error. We still return true for backward-compat.
    true
}

/// Build a [`ClientIdentity`] from peer credentials obtained via the Unix socket.
fn build_client_identity(peer: Option<&agentpass_core::peer::PeerInfo>) -> ClientIdentity {
    match peer {
        Some(info) => {
            let exe_path = info.pid.and_then(exe_path_for_pid);
            let exe_sha256 = exe_path.as_ref().and_then(|p| compute_exe_hash(p));
            ClientIdentity {
                uid: info.uid,
                gid: info.gid,
                pid: info.pid,
                exe_path,
                exe_sha256,
                codesign_team_id: None,
            }
        }
        None => ClientIdentity {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        },
    }
}

/// Resolve the executable path for a given PID.
fn exe_path_for_pid(pid: i32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    }

    #[cfg(target_os = "macos")]
    {
        exe_path_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn exe_path_macos(pid: i32) -> Option<PathBuf> {
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

    unsafe extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_char,
            buffersize: u32,
        ) -> libc::c_int;
    }

    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        proc_pidpath(
            pid,
            buf.as_mut_ptr() as *mut libc::c_char,
            PROC_PIDPATHINFO_MAXSIZE,
        )
    };
    if ret > 0 {
        let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        cstr.to_str().ok().map(PathBuf::from)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Workspace verification
// ---------------------------------------------------------------------------

/// Create a `Command` with a minimal, hardened environment.
///
/// Clears all inherited env vars and sets only a restricted PATH to prevent
/// binary injection. Also prevents git from reading system/user config or
/// prompting for credentials.
fn safe_command(bin: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/usr/local/bin:/bin");
    cmd.env("LC_ALL", "C");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("HOME", "/nonexistent"); // Prevent reading ~/.gitconfig
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd
}

/// Read the current working directory of a process by PID.
fn read_client_cwd(pid: i32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_link(format!("/proc/{pid}/cwd")).ok();
    }

    #[cfg(target_os = "macos")]
    {
        read_client_cwd_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn read_client_cwd_macos(pid: i32) -> Option<PathBuf> {
    // Use lsof to get the cwd of a process on macOS.
    let output = safe_command("lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // lsof output format: "p<pid>\nn<path>"
    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix('n') {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Blocking workspace verification logic.
///
/// Verifies that the claimed workspace context is consistent with the client's
/// actual process state. Runs external `git` commands.
///
/// Checks:
/// - Client's cwd is within the claimed repo_root
/// - `git rev-parse --show-toplevel` in repo_root matches
/// - Claimed remote_url matches actual `git remote get-url origin`
/// - Claimed branch matches actual `git rev-parse --abbrev-ref HEAD`
fn verify_workspace_blocking(
    claimed: &agentpass_core::operation::WorkspaceContext,
    client_pid: Option<i32>,
) -> Result<(), String> {
    // Verify client cwd is within claimed repo_root.
    if let Some(pid) = client_pid
        && let Some(cwd) = read_client_cwd(pid)
    {
        let repo_root = claimed
            .repo_root
            .canonicalize()
            .unwrap_or(claimed.repo_root.clone());
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        if !cwd.starts_with(&repo_root) {
            return Err(format!(
                "client cwd {} is not within claimed repo_root {}",
                cwd.display(),
                repo_root.display(),
            ));
        }
    }
    // If we can't read the cwd, we don't fail — best-effort.

    // Verify git toplevel matches.
    let toplevel = safe_command("git")
        .args([
            "-C",
            &claimed.repo_root.to_string_lossy(),
            "rev-parse",
            "--show-toplevel",
        ])
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if !toplevel.status.success() {
        return Err(format!(
            "{} is not a git repository",
            claimed.repo_root.display()
        ));
    }
    let actual_root = String::from_utf8_lossy(&toplevel.stdout).trim().to_string();
    let actual_root = PathBuf::from(&actual_root)
        .canonicalize()
        .unwrap_or(PathBuf::from(&actual_root));
    let claimed_root = claimed
        .repo_root
        .canonicalize()
        .unwrap_or(claimed.repo_root.clone());
    if actual_root != claimed_root {
        return Err(format!(
            "git toplevel {} does not match claimed repo_root {}",
            actual_root.display(),
            claimed_root.display(),
        ));
    }

    // Verify remote URL if claimed.
    if let Some(ref claimed_url) = claimed.remote_url {
        let remote = safe_command("git")
            .args([
                "-C",
                &claimed.repo_root.to_string_lossy(),
                "remote",
                "get-url",
                "origin",
            ])
            .output()
            .map_err(|e| format!("failed to get remote url: {e}"))?;
        if remote.status.success() {
            let actual_url = String::from_utf8_lossy(&remote.stdout).trim().to_string();
            if actual_url != *claimed_url {
                return Err(format!(
                    "claimed remote_url '{}' does not match actual '{}'",
                    claimed_url, actual_url,
                ));
            }
        }
    }

    // Verify branch if claimed.
    if let Some(ref claimed_branch) = claimed.branch {
        let branch = safe_command("git")
            .args([
                "-C",
                &claimed.repo_root.to_string_lossy(),
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ])
            .output()
            .map_err(|e| format!("failed to get branch: {e}"))?;
        if branch.status.success() {
            let actual_branch = String::from_utf8_lossy(&branch.stdout).trim().to_string();
            if actual_branch != *claimed_branch {
                return Err(format!(
                    "claimed branch '{}' does not match actual '{}'",
                    claimed_branch, actual_branch,
                ));
            }
        }
    }

    Ok(())
}

/// Async wrapper around `verify_workspace_blocking` that offloads the
/// blocking `Command::output()` calls to a Tokio blocking thread.
async fn verify_workspace(
    claimed: &agentpass_core::operation::WorkspaceContext,
    client_pid: Option<i32>,
) -> Result<(), String> {
    let claimed = claimed.clone();
    tokio::task::spawn_blocking(move || verify_workspace_blocking(&claimed, client_pid))
        .await
        .map_err(|e| format!("workspace verification task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Verify that the peer UID matches the daemon's own UID.
///
/// Rejects connections from other users, which could be confused-deputy
/// or privilege-escalation attempts in multi-user environments.
fn verify_peer_uid(peer: &agentpass_core::peer::PeerInfo) -> bool {
    #[cfg(unix)]
    {
        let my_uid = unsafe { libc::getuid() };
        peer.uid == my_uid
    }
    #[cfg(not(unix))]
    {
        let _ = peer;
        true
    }
}

async fn handle_conn(state: Arc<DaemonState>, stream: UnixStream) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let peer = peer_info_from_fd(fd).ok();

    // Verify peer UID matches daemon UID. Reject if unavailable or mismatched.
    match &peer {
        None => {
            warn!("peer credentials unavailable, rejecting connection");
            return Ok(());
        }
        Some(info) => {
            if !verify_peer_uid(info) {
                warn!(
                    "peer UID {} does not match daemon UID, rejecting connection",
                    info.uid
                );
                return Ok(());
            }
        }
    }

    let identity = build_client_identity(peer.as_ref());

    // Derive client type once per connection — never from request params.
    let client_type = derive_client_type(&identity, &state.config);

    if let Some(ref peer) = peer {
        info!(
            "client connected uid={} gid={} pid={:?} type={:?}",
            peer.uid, peer.gid, peer.pid, client_type
        );
    } else {
        info!("client connected (peer creds unavailable) type={client_type:?}");
    }

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(128 * 1024) // 128KB max frame
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    // --- Handshake: first frame must be a valid daemon token ---
    let handshake_ok = match framed.next().await {
        Some(Ok(frame)) => validate_handshake(&frame, &state.daemon_token),
        _ => false,
    };

    if !handshake_ok {
        // Close silently — no error detail to prevent oracle attacks.
        warn!("handshake failed, closing connection");
        return Ok(());
    }

    loop {
        // Idle timeout: disconnect clients that send no frames for 30 seconds.
        let next_frame =
            tokio::time::timeout(std::time::Duration::from_secs(30), framed.next()).await;

        match next_frame {
            Ok(Some(Ok(frame))) => {
                let req: Request = match serde_json::from_slice(&frame) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("bad JSON from client: {e}");
                        let resp = Response::err(None, "bad_json", "invalid JSON request");
                        let bytes = serde_json::to_vec(&resp)
                            .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                        let _ = framed.send(Bytes::from(bytes)).await;
                        continue;
                    }
                };

                // Never log params (may contain secrets due to client bugs).
                let resp = handle_request(&state, req, &identity, client_type).await;
                let out = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
                framed.send(Bytes::from(out)).await?;
            }
            Ok(Some(Err(e))) => {
                warn!("bad frame from client: {e}");
                let resp = Response::err(None, "bad_frame", "malformed frame");
                let bytes = serde_json::to_vec(&resp)
                    .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                let _ = framed.send(Bytes::from(bytes)).await;
                return Err(e);
            }
            Ok(None) => break, // Client disconnected
            Err(_) => {
                info!("idle timeout, closing connection");
                break;
            }
        }
    }

    Ok(())
}

/// Validate the handshake frame from a client.
///
/// Expected format: `{"handshake":"v1","daemon_token":"<hex>"}`
fn validate_handshake(frame: &[u8], expected_token: &str) -> bool {
    #[derive(Deserialize)]
    struct Handshake {
        handshake: String,
        daemon_token: String,
    }

    let hs: Handshake = match serde_json::from_slice(frame) {
        Ok(h) => h,
        Err(_) => return false,
    };

    if hs.handshake != "v1" {
        return false;
    }

    // Constant-time comparison to prevent timing attacks.
    constant_time_eq(hs.daemon_token.as_bytes(), expected_token.as_bytes())
}

/// Constant-time byte comparison (prevents timing side channels).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn handle_request(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
) -> Response {
    match req.method.as_str() {
        "ping" => Response::ok(req.id, serde_json::json!({ "ok": true })),
        "version" => Response::ok(req.id, serde_json::json!({ "version": state.version })),
        "whoami" => {
            // Agent clients get minimal info to prevent reconnaissance.
            // Human clients get the full dump.
            let payload = match client_type {
                ClientType::Human => serde_json::json!({
                    "uid": identity.uid,
                    "gid": identity.gid,
                    "pid": identity.pid,
                    "exe_path": identity.exe_path.as_ref().map(|p| p.display().to_string()),
                    "client_type": client_type,
                }),
                ClientType::Agent => serde_json::json!({
                    "uid": identity.uid,
                    "client_type": client_type,
                }),
            };
            Response::ok(req.id, payload)
        }
        "execute" => {
            let operation = req
                .params
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if operation.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'operation' field");
            }

            let target: HashMap<String, String> = req
                .params
                .get("target")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let secret_ref_names: Vec<String> = req
                .params
                .get("secret_ref_names")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            // --- Input validation (P0): sanitize client-controlled strings ---
            let target = match InputValidator::validate_target(&target) {
                Ok(t) => t,
                Err(e) => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        format!("invalid target: {e}"),
                    );
                }
            };

            let secret_ref_names =
                match InputValidator::validate_secret_ref_names(&secret_ref_names) {
                    Ok(n) => n,
                    Err(e) => {
                        return Response::err(
                            Some(req.id),
                            "bad_request",
                            format!("invalid secret_ref_names: {e}"),
                        );
                    }
                };

            // Client type is derived from verified identity — NEVER from params.
            // Any `client_type` field in params is silently ignored.

            let op_params = req
                .params
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            let mut workspace: Option<agentpass_core::operation::WorkspaceContext> = req
                .params
                .get("workspace")
                .and_then(|v| serde_json::from_value(v.clone()).ok());

            // Sanitize workspace remote_url to strip embedded credentials.
            if let Some(ref mut ws) = workspace
                && let Some(ref url) = ws.remote_url
            {
                ws.remote_url = Some(InputValidator::sanitize_url(url));
            }

            // Verify claimed workspace against actual process state.
            // verify_workspace is async (offloads blocking git commands to spawn_blocking).
            if let Some(ref ws) = workspace
                && let Err(e) = verify_workspace(ws, identity.pid).await
            {
                warn!("workspace verification failed: {e}");
                return Response::err(
                    Some(req.id),
                    "workspace_verification_failed",
                    "workspace verification failed",
                );
            }

            let op_req = OperationRequest {
                request_id: Uuid::new_v4(),
                client_identity: identity.clone(),
                client_type,
                operation,
                target,
                secret_ref_names,
                created_at: SystemTime::now(),
                expires_at: None,
                params: op_params,
                workspace,
            };

            state
                .enclave
                .execute(op_req)
                .await
                .into_proto_response(req.id)
        }
        _ => Response::err(Some(req.id), "unknown_method", "unknown method"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> ClientIdentity {
        ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/claude-code".into()),
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
        }
    }

    fn entry_with_path(name: &str, pattern: &str) -> HumanClientEntry {
        HumanClientEntry {
            name: name.into(),
            exe_path: Some(pattern.into()),
            exe_sha256: None,
            codesign_team_id: None,
        }
    }

    #[test]
    fn derive_client_type_matches_by_path() {
        let config = DaemonConfig {
            known_human_clients: vec![entry_with_path("claude", "/usr/bin/claude*")],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Human);
    }

    #[test]
    fn derive_client_type_matches_by_hash() {
        let config = DaemonConfig {
            known_human_clients: vec![HumanClientEntry {
                name: "claude".into(),
                exe_path: None,
                exe_sha256: Some("AABBCCDD".into()), // case-insensitive
                codesign_team_id: None,
            }],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Human);
    }

    #[test]
    fn derive_client_type_defaults_to_agent() {
        let config = DaemonConfig {
            known_human_clients: vec![entry_with_path("vscode", "/usr/bin/code*")],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Agent);
    }

    #[test]
    fn compute_exe_hash_nonexistent_none() {
        assert!(compute_exe_hash(Path::new("/nonexistent/binary")).is_none());
    }

    #[test]
    fn config_empty_all_agents() {
        let config = DaemonConfig::default();
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Agent);
    }

    #[test]
    fn entry_matches_codesign_team_id() {
        let entry = HumanClientEntry {
            name: "xcode".into(),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: Some("TEAM123".into()),
        };
        let mut id = test_identity();
        id.codesign_team_id = Some("TEAM123".into());
        assert!(entry_matches(&id, &entry));

        id.codesign_team_id = Some("OTHER".into());
        assert!(!entry_matches(&id, &entry));

        id.codesign_team_id = None;
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn handshake_valid_accepted() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": token,
        }))
        .unwrap();
        assert!(validate_handshake(&frame, token));
    }

    #[test]
    fn handshake_invalid_token_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": "wrong_token",
        }))
        .unwrap();
        assert!(!validate_handshake(&frame, "correct_token"));
    }

    #[test]
    fn handshake_missing_fields_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({"handshake": "v1"})).unwrap();
        assert!(!validate_handshake(&frame, "token"));
    }

    #[test]
    fn handshake_wrong_version_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v99",
            "daemon_token": "token",
        }))
        .unwrap();
        assert!(!validate_handshake(&frame, "token"));
    }

    #[test]
    fn handshake_garbage_rejected() {
        assert!(!validate_handshake(b"not json at all", "token"));
    }

    #[test]
    fn generate_daemon_token_is_64_hex_chars() {
        let token = generate_daemon_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_daemon_token_is_unique() {
        let t1 = generate_daemon_token();
        let t2 = generate_daemon_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn write_daemon_token_creates_file() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("agentpass-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("agentpassd.sock");
        let token = "test_token_hex";
        let token_path = write_daemon_token(&socket_path, token).unwrap();
        assert_eq!(token_path, dir.join(DAEMON_TOKEN_FILENAME));
        let contents = std::fs::read_to_string(&token_path).unwrap();
        assert_eq!(contents, token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = token_path.metadata().unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_peer_uid_same_uid() {
        let my_uid = unsafe { libc::getuid() };
        let peer = agentpass_core::peer::PeerInfo {
            uid: my_uid,
            gid: 20,
            pid: Some(1234),
        };
        assert!(verify_peer_uid(&peer));
    }

    #[test]
    fn verify_peer_uid_different_uid() {
        let my_uid = unsafe { libc::getuid() };
        let other_uid = if my_uid == 0 { 1000 } else { my_uid + 1 };
        let peer = agentpass_core::peer::PeerInfo {
            uid: other_uid,
            gid: 20,
            pid: Some(1234),
        };
        assert!(!verify_peer_uid(&peer));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    #[test]
    fn safe_command_has_minimal_env() {
        let cmd = safe_command("echo");
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(
            envs.get("PATH").map(|s| s.as_str()),
            Some("/usr/bin:/usr/local/bin:/bin")
        );
        assert_eq!(envs.get("LC_ALL").map(|s| s.as_str()), Some("C"));
        assert_eq!(
            envs.get("GIT_TERMINAL_PROMPT").map(|s| s.as_str()),
            Some("0")
        );
        assert_eq!(
            envs.get("GIT_CONFIG_NOSYSTEM").map(|s| s.as_str()),
            Some("1")
        );
        assert_eq!(envs.get("HOME").map(|s| s.as_str()), Some("/nonexistent"));
        // Should not contain common env vars that would be inherited.
        assert!(!envs.contains_key("USER"));
        assert!(!envs.contains_key("SHELL"));
    }

    #[test]
    fn safe_command_blocks_git_config() {
        let cmd = safe_command("git");
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        // GIT_CONFIG_NOSYSTEM prevents reading /etc/gitconfig.
        assert_eq!(
            envs.get("GIT_CONFIG_NOSYSTEM").map(|s| s.as_str()),
            Some("1")
        );
        // HOME=/nonexistent prevents reading ~/.gitconfig.
        assert_eq!(envs.get("HOME").map(|s| s.as_str()), Some("/nonexistent"));
    }

    #[test]
    fn config_toml_roundtrip() {
        let toml_str = r#"
[[known_human_clients]]
name = "claude-code"
exe_path = "/usr/bin/claude*"

[[known_human_clients]]
name = "vscode"
exe_sha256 = "deadbeef"
"#;
        let config: DaemonConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(config.known_human_clients.len(), 2);
        assert_eq!(
            config.known_human_clients[0].exe_path.as_deref(),
            Some("/usr/bin/claude*")
        );
        assert_eq!(
            config.known_human_clients[1].exe_sha256.as_deref(),
            Some("deadbeef")
        );
    }
}
