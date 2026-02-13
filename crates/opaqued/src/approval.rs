use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("invalid approval reason")]
    InvalidReason,

    #[error("approval not supported on this platform")]
    #[allow(dead_code)] // Used on platforms without macOS/Linux approval
    Unsupported,

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
    // Preflight so we can return a reasonable error instead of failing silently.
    if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) } {
        return Err(ApprovalError::Failed(format!(
            "LocalAuthentication unavailable: {}",
            e.localizedDescription()
        )));
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

    // Avoid hanging forever if LocalAuthentication never calls back.
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(ok) => Ok(ok),
        Err(e) => Err(ApprovalError::Failed(format!(
            "approval timed out or failed: {e}"
        ))),
    }
}

#[cfg(target_os = "linux")]
async fn prompt_linux(reason: &str) -> Result<bool, ApprovalError> {
    // Step 1: Show intent dialog with operation details before authentication.
    // This prevents blind polkit approvals where the user authenticates without
    // knowing what operation they are approving.
    let intent_confirmed = show_intent_dialog(reason).await?;
    if !intent_confirmed {
        return Ok(false);
    }

    // Step 2: Polkit authentication (unchanged).
    polkit_authenticate(reason).await
}

/// Show an intent dialog displaying operation details before polkit authentication.
///
/// Tries GUI dialogs first (zenity, kdialog), falls back to terminal if available.
/// If no UI is available, fails closed (returns error, not false).
#[cfg(target_os = "linux")]
async fn show_intent_dialog(reason: &str) -> Result<bool, ApprovalError> {
    let reason = reason.to_string();
    tokio::task::spawn_blocking(move || show_intent_dialog_blocking(&reason))
        .await
        .map_err(|e| ApprovalError::Failed(format!("intent dialog task failed: {e}")))?
}

/// Blocking implementation of the intent dialog.
#[cfg(target_os = "linux")]
fn show_intent_dialog_blocking(reason: &str) -> Result<bool, ApprovalError> {
    use std::process::Command;

    let dialog_text = format!("Opaque Approval Request\n\n{reason}\n\nDo you want to proceed?");

    // Try zenity (GNOME/GTK).
    if let Ok(status) = Command::new("zenity")
        .args([
            "--question",
            "--title=Opaque Approval",
            &format!("--text={dialog_text}"),
            "--width=400",
        ])
        .status()
    {
        return Ok(status.success());
    }

    // Try kdialog (KDE).
    if let Ok(status) = Command::new("kdialog")
        .args(["--yesno", &dialog_text, "--title", "Opaque Approval"])
        .status()
    {
        return Ok(status.success());
    }

    // Try terminal fallback if stdin is a TTY.
    if atty_is_tty() {
        eprint!("{}\n\nApprove? [y/N] ", dialog_text);
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let answer = input.trim().to_lowercase();
            return Ok(answer == "y" || answer == "yes");
        }
    }

    // No UI available — fail closed.
    Err(ApprovalError::Failed(
        "no approval UI available (no zenity, kdialog, or TTY)".into(),
    ))
}

/// Check if stdin is a terminal (TTY).
#[cfg(target_os = "linux")]
fn atty_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
}

/// Polkit authentication step.
#[cfg(target_os = "linux")]
async fn polkit_authenticate(reason: &str) -> Result<bool, ApprovalError> {
    use std::collections::HashMap;

    use zbus::Connection;
    use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

    let connection = Connection::system()
        .await
        .map_err(|e| ApprovalError::Failed(format!("polkit connect failed: {e}")))?;
    let proxy = AuthorityProxy::new(&connection)
        .await
        .map_err(|e| ApprovalError::Failed(format!("polkit proxy failed: {e}")))?;

    let pid = std::process::id();
    let subject = Subject::new_for_owner(pid, None, None)
        .map_err(|e| ApprovalError::Failed(format!("polkit subject failed: {e}")))?;

    let action_id = "com.opaque.approve";

    let mut details = HashMap::new();
    details.insert("reason".to_string(), reason.to_string());

    let result = proxy
        .check_authorization(
            &subject,
            action_id,
            &details,
            CheckAuthorizationFlags::AllowUserInteraction.into(),
            "",
        )
        .await
        .map_err(|e| ApprovalError::Failed(format!("polkit check failed: {e}")))?;

    Ok(result.is_authorized)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn atty_is_tty_does_not_panic() {
        // Just verify the function doesn't panic in any environment.
        let _ = super::atty_is_tty();
    }
}
