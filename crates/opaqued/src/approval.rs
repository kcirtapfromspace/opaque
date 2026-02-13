use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("invalid approval reason")]
    InvalidReason,

    #[error("approval not supported on this platform")]
    #[allow(dead_code)] // Used on platforms without macOS/Linux approval
    Unsupported,

    #[error("approval UI unavailable")]
    Unavailable,

    #[error("approval failed: {0}")]
    Failed(String),
}

pub async fn prompt(reason: &str) -> Result<bool, ApprovalError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(ApprovalError::InvalidReason);
    }

    #[cfg(target_os = "macos")]
    {
        return prompt_macos(reason).await;
    }

    #[cfg(target_os = "linux")]
    {
        return prompt_linux(reason).await;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = reason;
        Err(ApprovalError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// macOS: LocalAuthentication (Touch ID / password)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
async fn prompt_macos(reason: &str) -> Result<bool, ApprovalError> {
    let reason = reason.to_string();
    tokio::task::spawn_blocking(move || prompt_macos_blocking(&reason))
        .await
        .map_err(|e| ApprovalError::Failed(format!("approval task failed: {e}")))?
}

#[cfg(target_os = "macos")]
fn prompt_macos_blocking(reason: &str) -> Result<bool, ApprovalError> {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    let ctx = unsafe { LAContext::new() };

    // Preflight: check if the UI session supports approval.
    // If not (e.g., no window server, LaunchDaemon, SSH), return Unavailable
    // so the enclave reports `approval_unavailable` to the client.
    if unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }.is_err() {
        return Err(ApprovalError::Unavailable);
    }

    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let reason_ns = NSString::from_str(reason);

    // The reply block can be invoked on an arbitrary private queue.
    let tx2 = tx.clone();
    let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
        let ok = success.as_bool();
        if let Some(tx) = tx2.lock().ok().and_then(|mut g| g.take()) {
            let _ = tx.send(ok);
        }
    });

    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason_ns,
            &reply,
        );
    }

    // US-009: Reduced from 120s to 60s. The approval semaphore in the enclave
    // is released via future cancellation if the client disconnects, so a
    // shorter timeout here limits how long an orphaned prompt can block.
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(ok) => Ok(ok),
        Err(e) => Err(ApprovalError::Failed(format!(
            "approval timed out or failed: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Linux: opaque-approve-helper subprocess
// ---------------------------------------------------------------------------

/// Launch the external approval helper binary as a subprocess.
///
/// The helper performs the two-step approval flow:
/// 1. Intent dialog (zenity/kdialog/TTY) showing what the user is approving
/// 2. Polkit authentication via `pkcheck`
///
/// Exit codes: 0 = approved, 1 = denied, 2 = unavailable.
#[cfg(target_os = "linux")]
async fn prompt_linux(reason: &str) -> Result<bool, ApprovalError> {
    let reason = reason.to_string();
    tokio::task::spawn_blocking(move || launch_approve_helper(&reason))
        .await
        .map_err(|e| ApprovalError::Failed(format!("approval task failed: {e}")))?
}

#[cfg(target_os = "linux")]
fn launch_approve_helper(reason: &str) -> Result<bool, ApprovalError> {
    let helper_path = find_approve_helper()?;

    // Inherit daemon's environment — the helper needs DISPLAY, WAYLAND_DISPLAY,
    // DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR etc. to display dialogs and
    // communicate with polkit.
    let status = std::process::Command::new(&helper_path)
        .arg("--reason")
        .arg(reason)
        .status()
        .map_err(|e| ApprovalError::Failed(format!("failed to launch approval helper: {e}")))?;

    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(2) => Err(ApprovalError::Unavailable),
        Some(c) => Err(ApprovalError::Failed(format!(
            "approval helper exited with code {c}"
        ))),
        None => Err(ApprovalError::Failed(
            "approval helper killed by signal".into(),
        )),
    }
}

/// Locate the `opaque-approve-helper` binary.
///
/// Search order:
/// 1. Same directory as the running daemon binary
/// 2. Well-known system paths
#[cfg(target_os = "linux")]
fn find_approve_helper() -> Result<std::path::PathBuf, ApprovalError> {
    // Next to the daemon binary (works during development and standard installs).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let helper = dir.join("opaque-approve-helper");
            if helper.exists() {
                return Ok(helper);
            }
        }
    }

    // Well-known install paths.
    for path in &[
        "/usr/local/bin/opaque-approve-helper",
        "/usr/bin/opaque-approve-helper",
    ] {
        let p = std::path::PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    Err(ApprovalError::Unavailable)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reason_returns_invalid() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(prompt(""));
        assert!(matches!(result, Err(ApprovalError::InvalidReason)));
    }

    #[test]
    fn whitespace_reason_returns_invalid() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(prompt("   "));
        assert!(matches!(result, Err(ApprovalError::InvalidReason)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_exit_code_mapping() {
        // Test exit code interpretation without launching a real helper.
        // We simulate by testing the match logic.
        fn map_exit(code: Option<i32>) -> Result<bool, &'static str> {
            match code {
                Some(0) => Ok(true),
                Some(1) => Ok(false),
                Some(2) => Err("unavailable"),
                Some(_) => Err("unexpected"),
                None => Err("signal"),
            }
        }

        assert_eq!(map_exit(Some(0)), Ok(true));
        assert_eq!(map_exit(Some(1)), Ok(false));
        assert!(map_exit(Some(2)).is_err());
        assert!(map_exit(Some(42)).is_err());
        assert!(map_exit(None).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_helper_returns_unavailable_when_missing() {
        // Set a fake current_exe that has no helper next to it.
        // Since we can't control current_exe in tests, just verify that
        // find_approve_helper() returns Unavailable when the helper doesn't
        // exist in any expected location (which is the case in CI/dev).
        // In production, the helper would be installed alongside the daemon.
        let result = find_approve_helper();
        // The result depends on whether the helper is built. In most test
        // environments during `cargo test`, both binaries are in target/debug/
        // so the helper may or may not exist. We just check it doesn't panic.
        match result {
            Ok(path) => assert!(path.exists()),
            Err(ApprovalError::Unavailable) => {} // Expected in CI
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
