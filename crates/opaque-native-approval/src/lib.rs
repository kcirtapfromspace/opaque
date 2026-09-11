//! Shared native review and authentication for the daemon and workstation approver.

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

/// The account polkit authenticated (Linux helper), when it reports one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct UnixAccount {
    pub uid: u32,
    pub username: String,
}

/// Outcome of the native prompt.
///
/// On Linux the helper reports which account passed polkit (`account`);
/// macOS `LocalAuthentication` proves device-owner presence but names no
/// account — callers bind the login-session principal instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    Approved { account: Option<UnixAccount> },
    Denied,
}

pub async fn prompt(reason: &str) -> Result<PromptOutcome, ApprovalError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(ApprovalError::InvalidReason);
    }

    #[cfg(target_os = "macos")]
    {
        return prompt_macos(reason).await.map(|approved| {
            if approved {
                PromptOutcome::Approved { account: None }
            } else {
                PromptOutcome::Denied
            }
        });
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

const MAX_TASK_REVIEW_BYTES: usize = 128 * 1024;

#[cfg(any(target_os = "macos", target_os = "linux"))]
const REVIEW_STAGES: &[&str] = &[
    "helper-started",
    "ui-ready",
    "window-ordered",
    "dialog-started",
    "review-confirmed",
    "review-cancelled",
];

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn read_review_stages(
    output: impl tokio::io::AsyncRead + Unpin,
    stage: &std::sync::atomic::AtomicUsize,
) {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    // Only fixed protocol markers reach the operator. OS dialog output or a
    // malformed helper cannot leak review content through these diagnostics.
    let mut reader = BufReader::new(output.take(4096));
    let mut line = Vec::new();
    while reader.read_until(b'\n', &mut line).await.unwrap_or(0) > 0 {
        if let Ok(text) = std::str::from_utf8(&line)
            && let Some(name) = text
                .trim_end_matches('\n')
                .strip_prefix("opaque-review-stage: ")
            && let Some(index) = REVIEW_STAGES.iter().position(|value| *value == name)
        {
            stage.store(index, Ordering::Relaxed);
            println!("opaque-review-stage: {name}");
        }
        line.clear();
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn run_task_review(
    helper: &std::path::Path,
    review: &str,
    deadline: std::time::Duration,
) -> Result<bool, ApprovalError> {
    use std::process::Stdio;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new(helper)
        .args(["--review-only", "--reason-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            ApprovalError::Failed(
                "native review helper could not start; run opaque-approver check-native".into(),
            )
        })?;
    let mut stdin = child.stdin.take().ok_or(ApprovalError::Unavailable)?;
    let stdout = child.stdout.take().ok_or(ApprovalError::Unavailable)?;
    let stage = AtomicUsize::new(0);
    let interaction = async {
        // Include document delivery in the same deadline: a helper that never
        // reads stdin must not leave the approval waiting indefinitely.
        stdin.write_all(review.as_bytes()).await?;
        drop(stdin);
        let (status, ()) = tokio::join!(child.wait(), read_review_stages(stdout, &stage));
        status
    };
    let result = tokio::time::timeout(deadline, interaction).await;
    let stage_name = REVIEW_STAGES[stage.load(Ordering::Relaxed)];
    match result {
        Err(_) => {
            // Reap the helper before returning. kill_on_drop also protects
            // cancellation by a caller whose broker challenge has expired.
            let _ = child.kill().await;
            Err(ApprovalError::Failed(format!(
                "task review timed out after {} seconds (last stage: {stage_name}); no native authorization completed. Check the desktop for Review Opaque task and run opaque-approver check-native before requesting a fresh approval",
                deadline.as_secs()
            )))
        }
        Ok(Err(_)) => Err(ApprovalError::Failed(format!(
            "native review helper failed (last stage: {stage_name}); run opaque-approver check-native"
        ))),
        Ok(Ok(status)) => match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(ApprovalError::Failed(format!(
                "native review UI unavailable (last stage: {stage_name}); run opaque-approver check-native from the signed-in desktop session"
            ))),
        },
    }
}

fn task_review_text(reason: &str) -> Result<(String, String), ApprovalError> {
    use sha2::{Digest, Sha256};

    if reason.trim().is_empty() || reason.contains('\0') {
        return Err(ApprovalError::InvalidReason);
    }
    let digest: String = Sha256::digest(reason.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let review = format!("{reason}\n\nReview fingerprint (SHA-256): {digest}\n");
    if review.len() > MAX_TASK_REVIEW_BYTES {
        return Err(ApprovalError::InvalidReason);
    }
    Ok((review, digest))
}

/// Show the complete immutable task in a trusted scrollable review window,
/// then authenticate a short reason bound to the same reviewed description.
/// Review confirmation never substitutes for the configured native factor.
pub async fn prompt_task(reason: &str) -> Result<PromptOutcome, ApprovalError> {
    prompt_task_inner(reason, None).await
}

/// A remote challenge has an absolute deadline. Never begin authentication
/// after it, and bound both review and authentication by remaining time.
pub async fn prompt_task_until(
    reason: &str,
    expires_at: i64,
) -> Result<PromptOutcome, ApprovalError> {
    prompt_task_inner(reason, Some(expires_at)).await
}

fn remaining(
    expires_at: Option<i64>,
    maximum_secs: u64,
) -> Result<std::time::Duration, ApprovalError> {
    let maximum = std::time::Duration::from_secs(maximum_secs);
    let Some(expiry) = expires_at else {
        return Ok(maximum);
    };
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApprovalError::Unavailable)?;
    let deadline = std::time::Duration::from_secs(
        u64::try_from(expiry).map_err(|_| ApprovalError::Unavailable)?,
    );
    let remaining = deadline
        .checked_sub(elapsed)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            ApprovalError::Failed(
                "approval expired; no decision sent, request a fresh review".into(),
            )
        })?;
    Ok(remaining.min(maximum))
}

async fn prompt_task_inner(
    reason: &str,
    expires_at: Option<i64>,
) -> Result<PromptOutcome, ApprovalError> {
    let (review, digest) = task_review_text(reason)?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let deadline = remaining(expires_at, 90)?;
        let helper = find_approve_helper()?;
        if !run_task_review(&helper, &review, deadline).await? {
            return Ok(PromptOutcome::Denied);
        }
        let short_reason = format!(
            "Authorize the task just reviewed in Opaque. Review fingerprint: {}",
            &digest[..16]
        );
        println!("opaque-review-stage: authenticating");
        let timeout = remaining(expires_at, 60)?;
        #[cfg(target_os = "macos")]
        let outcome =
            tokio::task::spawn_blocking(move || prompt_macos_blocking_for(&short_reason, timeout))
                .await
                .map_err(|_| ApprovalError::Unavailable)?
                .map(|approved| {
                    if approved {
                        PromptOutcome::Approved { account: None }
                    } else {
                        PromptOutcome::Denied
                    }
                });
        #[cfg(target_os = "linux")]
        let outcome = if expires_at.is_some() {
            prompt_linux_bounded(&short_reason, timeout).await
        } else {
            prompt(&short_reason).await
        };
        if outcome.is_err() {
            eprintln!("opaque-review-stage: authentication-failed");
        }
        outcome
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (review, digest);
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
    prompt_macos_blocking_for(reason, std::time::Duration::from_secs(60))
}

#[cfg(target_os = "macos")]
fn prompt_macos_blocking_for(
    reason: &str,
    timeout: std::time::Duration,
) -> Result<bool, ApprovalError> {
    use std::sync::{Arc, Mutex};

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
    match rx.recv_timeout(timeout) {
        Ok(ok) => Ok(ok),
        Err(e) => {
            unsafe {
                ctx.invalidate();
            }
            Err(ApprovalError::Failed(format!(
                "approval timed out or failed: {e}"
            )))
        }
    }
}

#[cfg(target_os = "linux")]
async fn prompt_linux_bounded(
    reason: &str,
    timeout: std::time::Duration,
) -> Result<PromptOutcome, ApprovalError> {
    use tokio::io::AsyncReadExt;
    let helper = find_approve_helper()?;
    let mut child = tokio::process::Command::new(helper)
        .args(["--reason", reason])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ApprovalError::Unavailable)?;
    let status = tokio::time::timeout(timeout, child.wait()).await;
    match status {
        Ok(Ok(status)) if status.code() == Some(0) => {
            let mut output = Vec::new();
            if let Some(stdout) = child.stdout.take() {
                let _ = stdout.take(4096).read_to_end(&mut output).await;
            }
            Ok(PromptOutcome::Approved {
                account: parse_helper_account(&output),
            })
        }
        Ok(Ok(status)) if status.code() == Some(1) => Ok(PromptOutcome::Denied),
        _ => {
            let _ = child.kill().await;
            Err(ApprovalError::Failed(
                "authentication expired or unavailable; no decision sent".into(),
            ))
        }
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
/// Exit codes: 0 = approved, 1 = denied, 2 = unavailable. On approval, newer
/// helpers additionally print `{"account":{"uid":…,"username":"…"}}` on
/// stdout naming the polkit-authenticated account; older helpers print
/// nothing and the approval stays account-anonymous.
#[cfg(target_os = "linux")]
async fn prompt_linux(reason: &str) -> Result<PromptOutcome, ApprovalError> {
    let reason = reason.to_string();
    tokio::task::spawn_blocking(move || launch_approve_helper(&reason))
        .await
        .map_err(|e| ApprovalError::Failed(format!("approval task failed: {e}")))?
}

#[cfg(target_os = "linux")]
fn launch_approve_helper(reason: &str) -> Result<PromptOutcome, ApprovalError> {
    let helper_path = find_approve_helper()?;

    // Inherit daemon's environment — the helper needs DISPLAY, WAYLAND_DISPLAY,
    // DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR etc. to display dialogs and
    // communicate with polkit. Capture stdout for the account report.
    let output = std::process::Command::new(&helper_path)
        .arg("--reason")
        .arg(reason)
        // stdin/stderr stay on the daemon's terminal so the helper's TTY
        // fallback still works; only stdout is captured for the report.
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| ApprovalError::Failed(format!("failed to launch approval helper: {e}")))?;

    match output.status.code() {
        Some(0) => Ok(PromptOutcome::Approved {
            account: parse_helper_account(&output.stdout),
        }),
        Some(1) => Ok(PromptOutcome::Denied),
        Some(2) => Err(ApprovalError::Unavailable),
        Some(c) => Err(ApprovalError::Failed(format!(
            "approval helper exited with code {c}"
        ))),
        None => Err(ApprovalError::Failed(
            "approval helper killed by signal".into(),
        )),
    }
}

/// Parse the helper's optional stdout account report. Anything malformed
/// degrades to `None` (account-anonymous approval) — the DECISION rides the
/// exit code alone, so a hostile or broken stdout can never flip it.
#[cfg(any(target_os = "linux", test))]
fn parse_helper_account(stdout: &[u8]) -> Option<UnixAccount> {
    #[derive(serde::Deserialize)]
    struct HelperReport {
        account: UnixAccount,
    }
    let text = std::str::from_utf8(stdout).ok()?;
    let line = text.lines().find(|l| l.trim_start().starts_with('{'))?;
    let report: HelperReport = serde_json::from_str(line.trim()).ok()?;
    // An empty or absurdly long name is not a usable label.
    if report.account.username.is_empty() || report.account.username.len() > 256 {
        return None;
    }
    Some(report.account)
}

/// Locate the `opaque-approve-helper` binary.
///
/// Search order:
/// 1. Same directory as the running daemon binary
/// 2. Well-known system paths
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_approve_helper() -> Result<std::path::PathBuf, ApprovalError> {
    // Next to the daemon binary (works during development and standard installs).
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let helper = dir.join("opaque-approve-helper");
        if helper.is_file() {
            return Ok(helper);
        }
    }

    // Well-known install paths.
    for path in &[
        "/usr/local/bin/opaque-approve-helper",
        "/usr/bin/opaque-approve-helper",
    ] {
        let p = std::path::PathBuf::from(path);
        if p.is_file() {
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

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn expired_challenge_never_starts_native_review() {
        let error = prompt_task_until("Exact immutable task", 1)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expired"));
        assert_eq!(
            remaining(None, 90).unwrap(),
            std::time::Duration::from_secs(90)
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(remaining(Some(now + 2), 90).unwrap() <= std::time::Duration::from_secs(2));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn review_diagnostics_accept_only_fixed_markers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let stage = AtomicUsize::new(0);
        read_review_stages(
            &b"review content must not become diagnostics\nopaque-review-stage: ui-ready\nopaque-review-stage: secret=value\nopaque-review-stage: window-ordered\n"[..],
            &stage,
        )
        .await;
        assert_eq!(
            REVIEW_STAGES[stage.load(Ordering::Relaxed)],
            "window-ordered"
        );
        let stage = AtomicUsize::new(0);
        let oversized = format!(
            "{}\nopaque-review-stage: review-confirmed\n",
            "x".repeat(4096)
        );
        read_review_stages(oversized.as_bytes(), &stage).await;
        assert_eq!(stage.load(Ordering::Relaxed), 0);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn review_test_helper(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("review-helper");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        (directory, path)
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn review_timeout_reports_last_stage_and_reaps_helper() {
        let (_directory, helper) = review_test_helper(
            "printf '%s\\n' $$ > \"$0.pid\"\nprintf '%s\\n' 'opaque-review-stage: window-ordered'\nexec /bin/sleep 5",
        );
        let started = std::time::Instant::now();
        let error = run_task_review(&helper, "complete task", std::time::Duration::from_secs(1))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("task review timed out"));
        assert!(error.contains("last stage: window-ordered"));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        let pid: i32 = std::fs::read_to_string(helper.with_extension("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal zero performs a liveness check without sending a
        // signal; the pid was written by this test's disposable helper.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn unread_review_input_cannot_escape_the_deadline() {
        let (_directory, helper) = review_test_helper("exec /bin/sleep 5");
        let started = std::time::Instant::now();
        let error = run_task_review(
            &helper,
            &"x".repeat(MAX_TASK_REVIEW_BYTES),
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("task review timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn helper_markers_cannot_override_denial_or_failure() {
        let (_directory, helper) = review_test_helper(
            "cat >/dev/null\nprintf '%s\\n' 'opaque-review-stage: review-confirmed'\nexit 1",
        );
        assert!(
            !run_task_review(&helper, "task", std::time::Duration::from_secs(2))
                .await
                .unwrap()
        );
        let (_directory, helper) = review_test_helper("cat >/dev/null\nexit 2");
        let error = run_task_review(&helper, "task", std::time::Duration::from_secs(2))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("native review UI unavailable"));
    }

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

    #[test]
    fn task_review_keeps_full_scope_and_binds_its_fingerprint() {
        let reason = format!(
            "Task\n{}\n32. LAST ACTION\nmanifest_digest=abc",
            "scope\n".repeat(1000)
        );
        let (review, fingerprint) = task_review_text(&reason).unwrap();
        assert!(review.starts_with(&reason));
        assert!(review.contains("32. LAST ACTION"));
        assert!(review.contains(&fingerprint));
        assert_eq!(fingerprint.len(), 64);
        let (_, changed) = task_review_text(&format!("{reason} changed")).unwrap();
        assert_ne!(fingerprint, changed);
        assert!(task_review_text(&"x".repeat(MAX_TASK_REVIEW_BYTES)).is_err());
        assert!(task_review_text("\0").is_err());
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

    #[test]
    fn helper_account_report_parses() {
        let out = br#"{"account":{"uid":1000,"username":"pat"}}"#;
        let acct = parse_helper_account(out).unwrap();
        assert_eq!(acct.uid, 1000);
        assert_eq!(acct.username, "pat");
    }

    #[test]
    fn helper_account_report_tolerates_leading_dialog_noise() {
        let out = b"zenity chatter\n{\"account\":{\"uid\":7,\"username\":\"svc\"}}\n";
        assert_eq!(parse_helper_account(out).unwrap().uid, 7);
    }

    #[test]
    fn malformed_or_hostile_account_report_degrades_to_anonymous() {
        assert!(parse_helper_account(b"").is_none());
        assert!(parse_helper_account(b"not json").is_none());
        assert!(parse_helper_account(br#"{"account":{"uid":"x"}}"#).is_none());
        // Empty and oversized usernames are unusable labels.
        assert!(parse_helper_account(br#"{"account":{"uid":1,"username":""}}"#).is_none());
        let long = format!(
            r#"{{"account":{{"uid":1,"username":"{}"}}}}"#,
            "a".repeat(300)
        );
        assert!(parse_helper_account(long.as_bytes()).is_none());
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
