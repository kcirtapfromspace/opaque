//! Interactive trusted-workstation application; deliberately no autoapprove.
use clap::{Parser, Subcommand};
use ed25519_dalek::Signer;
use opaque_approver::{
    client::BrokerClient,
    custody::{self, BrokerEnrollment},
};
use opaque_core::workstation::{
    EnrollmentChallenge, EnrollmentRequest, EnrollmentResponse, WorkstationChallenge,
    WorkstationDecision, WorkstationResponse, WorkstationReview, enrollment_bytes, hex,
    workstation_decision_bytes,
};
use std::path::PathBuf;

// One shared native implementation preserves the daemon's full-review and
// native-authentication requirements without a weaker workstation fallback.
#[path = "../../opaqued/src/approval.rs"]
mod native;

#[derive(Parser)]
#[command(
    name = "opaque-approver",
    version,
    about = "Trusted paired-workstation approvals for Opaque"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check local review and authentication capability without opening a prompt.
    CheckNative,
    /// Generate a dedicated workstation identity; prints public enrollment data only.
    Init {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Prove possession of a key already allowlisted in trusted broker configuration.
    Enroll {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        broker: String,
        #[arg(long)]
        broker_id: String,
        #[arg(long)]
        tls_fingerprint: String,
    },
    /// List pending approval metadata over the pinned connection.
    List {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Fetch and review the complete document, authenticate natively, then sign.
    Review {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        approval_id: String,
    },
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!("opaque-approver: {error}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    // This application must run in trusted custody, not inside an agent's
    // delegated execution session. This check complements account isolation;
    // environment absence alone is not proof that a process is trusted.
    if std::env::var_os("OPAQUE_SESSION_TOKEN").is_some() {
        return Err(
            "run the approver outside delegated agent sessions on the trusted workstation".into(),
        );
    }
    match args.command {
        Command::CheckNative => check_native().await?,
        Command::Init { state_dir, name } => {
            let state = custody::initialize(&state_dir, &name)?;
            println!(
                "{}",
                serde_json::json!({"name":state.name,"public_key_hex":state.public_key_hex,
                "key_fingerprint":opaque_core::workstation::review_hash(&state.public_key_hex),
                "next":"Install this public key in the broker's trusted workstation_approvers configuration; keep workstation.key private."})
            );
        }
        Command::Enroll {
            state_dir,
            broker,
            broker_id,
            tls_fingerprint,
        } => {
            let (mut state, key) = custody::load(&state_dir)?;
            if let Some(existing) = &state.enrollment
                && (existing.endpoint != broker.trim_end_matches('/')
                    || existing.broker_id != broker_id
                    || !existing
                        .tls_fingerprint
                        .eq_ignore_ascii_case(&tls_fingerprint))
            {
                return Err("this identity is already pinned to a different broker; use separate workstation custody".into());
            }
            let client = BrokerClient::new(&broker, &tls_fingerprint)?;
            let challenge: EnrollmentChallenge = client
                .request(
                    reqwest::Method::POST,
                    "/workstation/enrollment/challenge",
                    Some(serde_json::json!({"public_key_hex":state.public_key_hex})),
                    None,
                )
                .await?;
            challenge
                .validate(&broker_id, &state.public_key_hex, now())
                .map_err(|error| error.to_string())?;
            let request = EnrollmentRequest {
                public_key_hex: state.public_key_hex.clone(),
                nonce: challenge.nonce.clone(),
                signature: hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes()),
            };
            let response: EnrollmentResponse = client
                .request(
                    reqwest::Method::POST,
                    "/workstation/enrollment/complete",
                    Some(serde_json::to_value(request).map_err(|_| "enrollment encoding failed")?),
                    None,
                )
                .await?;
            if response.server_id != broker_id || response.token.len() != 64 {
                return Err("broker enrollment identity mismatch".into());
            }
            state.enrollment = Some(BrokerEnrollment {
                endpoint: broker.trim_end_matches('/').into(),
                broker_id: broker_id.clone(),
                tls_fingerprint: tls_fingerprint.to_ascii_lowercase(),
                device_id: response.device_id.clone(),
                token: response.token,
            });
            custody::save(&state_dir, &state)?;
            println!(
                "Enrolled workstation {} with broker {broker_id}.",
                response.device_id
            );
        }
        Command::List { state_dir } => {
            let (state, _) = custody::load(&state_dir)?;
            let enrollment = state.enrollment.ok_or("workstation is not enrolled")?;
            let client = BrokerClient::new(&enrollment.endpoint, &enrollment.tls_fingerprint)?;
            #[derive(serde::Deserialize)]
            struct Pending {
                approvals: Vec<WorkstationChallenge>,
            }
            let pending: Pending = client
                .request(
                    reqwest::Method::GET,
                    "/workstation/approvals/pending",
                    None,
                    Some((&enrollment.device_id, &enrollment.token)),
                )
                .await?;
            for challenge in &pending.approvals {
                challenge
                    .validate(&enrollment.broker_id, now())
                    .map_err(|error| error.to_string())?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&pending.approvals)
                    .map_err(|_| "pending metadata encoding failed")?
            );
        }
        Command::Review {
            state_dir,
            approval_id,
        } => {
            if uuid_like(&approval_id).is_none() {
                return Err("approval_id must be a broker-issued UUID".into());
            }
            let (state, key) = custody::load(&state_dir)?;
            let enrollment = state.enrollment.ok_or("workstation is not enrolled")?;
            let client = BrokerClient::new(&enrollment.endpoint, &enrollment.tls_fingerprint)?;
            let route = format!("/workstation/approvals/{approval_id}");
            let review: WorkstationReview = client
                .request(
                    reqwest::Method::GET,
                    &route,
                    None,
                    Some((&enrollment.device_id, &enrollment.token)),
                )
                .await?;
            review
                .validate(&enrollment.broker_id, now())
                .map_err(|error| error.to_string())?;
            if review.challenge.approval_id != approval_id {
                return Err("broker returned a different approval round".into());
            }
            let reason = format!(
                "Trusted broker: {}\nApproval: {}\nRequest: {}\nOperation: {}\nChallenge expires: {}\nReview content SHA256: {}\n\n{}",
                review.challenge.broker_id,
                approval_id,
                review.challenge.request_id,
                review.challenge.operation,
                review.challenge.expires_at,
                review.challenge.content_hash,
                review.review_text
            );
            let approved = matches!(
                native::prompt_task(&reason)
                    .await
                    .map_err(|error| error.to_string())?,
                native::PromptOutcome::Approved { .. }
            );
            // Revalidate after user interaction. Expired or replaced challenges
            // cannot be made useful by keeping a review window open.
            review
                .validate(&enrollment.broker_id, now())
                .map_err(|error| error.to_string())?;
            let latest: WorkstationReview = client
                .request(
                    reqwest::Method::GET,
                    &route,
                    None,
                    Some((&enrollment.device_id, &enrollment.token)),
                )
                .await?;
            if latest != review {
                return Err("approval round changed after review; no signature sent".into());
            }
            let response = WorkstationResponse {
                device_id: enrollment.device_id.clone(),
                decision: if approved {
                    WorkstationDecision::Approve
                } else {
                    WorkstationDecision::Reject
                },
                signature: hex(&key
                    .sign(&workstation_decision_bytes(&review.challenge, approved))
                    .to_bytes()),
            };
            let _: serde_json::Value = client
                .request(
                    reqwest::Method::POST,
                    &format!("{route}/respond"),
                    Some(serde_json::to_value(response).map_err(|_| "decision encoding failed")?),
                    Some((&enrollment.device_id, &enrollment.token)),
                )
                .await?;
            println!(
                "{} request {} on {}.",
                if approved { "Approved" } else { "Rejected" },
                review.challenge.request_id,
                enrollment.broker_id
            );
        }
    }
    Ok(())
}

async fn check_native() -> Result<(), String> {
    use std::process::Stdio;
    use std::time::Duration;

    let helper = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("opaque-approve-helper")))
        .filter(|path| path.is_file())
        .or_else(|| {
            [
                "/usr/local/bin/opaque-approve-helper",
                "/usr/bin/opaque-approve-helper",
            ]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        })
        .ok_or("native review helper missing; build or install it beside opaque-approver")?;
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(helper)
            .arg("--check-ui")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "native review capability check timed out; inspect the desktop session")?
    .map_err(|_| "native review helper could not start; check its installation and permissions")?;
    if !output.status.success() {
        // A fixed diagnostic avoids forwarding arbitrary OS/helper output.
        return Err("native review UI unavailable; run opaque-approve-helper --check-ui from the signed-in desktop session for details".into());
    }
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "native review helper returned an invalid capability report; rebuild both host binaries")?;
    if result["check"] != "native_review_ui"
        || result["ready"] != true
        || result["visibility_verified"] != false
    {
        return Err("native review helper capability mismatch; rebuild both host binaries".into());
    }
    check_authentication()?;
    println!(
        "{}",
        serde_json::json!({
            "check": "native_review",
            "ready": true,
            "visibility_verified": false,
            "authentication_available": true,
        })
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn check_authentication() -> Result<(), String> {
    use objc2_local_authentication::{LAContext, LAPolicy};
    // This capability query does not evaluate policy, display UI or accept a
    // decision. A successful result is not evidence of native authentication.
    let context = unsafe { LAContext::new() };
    unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }
        .map_err(|_| "native authentication unavailable in this macOS session".into())
}

#[cfg(target_os = "linux")]
fn check_authentication() -> Result<(), String> {
    use std::process::{Command, Stdio};
    let status = Command::new("pkcheck")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "pkcheck is required for native authentication")?;
    if !status.success() {
        return Err("polkit authentication tools are unavailable".into());
    }
    // Inspect the daemon's registered action without checking or granting an
    // authorization. Tool installation alone does not prove polkit is ready.
    let action = Command::new("pkaction")
        .args(["--action-id", "com.opaque.approve"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "pkaction is required to inspect native authentication readiness")?;
    if !action.status.success()
        || std::str::from_utf8(&action.stdout).map(str::trim) != Ok("com.opaque.approve")
    {
        return Err("polkit approval action unavailable; install the Opaque policy and verify the polkit service".into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn check_authentication() -> Result<(), String> {
    Err("native authentication is unsupported on this platform".into())
}

fn uuid_like(value: &str) -> Option<()> {
    (value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }))
    .then_some(())
}
