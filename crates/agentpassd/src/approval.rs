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

    // This requires installing a matching polkit policy action on the system.
    // In v1, we ship a sample policy file and installation instructions.
    let action_id = "com.agentpass.approve";

    // Details can be shown in some auth agents.
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
