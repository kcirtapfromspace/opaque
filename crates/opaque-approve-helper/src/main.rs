//! Opaque Approval Helper
//!
//! A small standalone binary launched by the Opaque daemon to display an
//! approval dialog and perform polkit authentication on Linux.
//!
//! The two-step flow:
//! 1. **Intent dialog** — shows what operation the user is approving
//!    (zenity -> kdialog -> terminal fallback)
//! 2. **Polkit authentication** — verifies user identity via `pkcheck`
//!
//! Exit codes:
//! - 0: approved (user confirmed intent + polkit auth succeeded)
//! - 1: denied (user declined in dialog or polkit denied)
//! - 2: unavailable (no display, no dialog tool, no pkcheck)

use std::io::IsTerminal;
use std::process::{Command, ExitCode};

const EXIT_APPROVED: u8 = 0;
const EXIT_DENIED: u8 = 1;
const EXIT_UNAVAILABLE: u8 = 2;

fn main() -> ExitCode {
    let reason = match parse_reason() {
        Some(r) => r,
        None => {
            eprintln!("usage: opaque-approve-helper --reason <description>");
            return ExitCode::from(EXIT_UNAVAILABLE);
        }
    };

    // Step 1: Show intent dialog so the user sees what they are approving.
    match show_intent_dialog(&reason) {
        Ok(true) => {} // User confirmed intent, proceed to authentication.
        Ok(false) => return ExitCode::from(EXIT_DENIED),
        Err(e) => {
            eprintln!("opaque-approve-helper: intent dialog failed: {e}");
            return ExitCode::from(EXIT_UNAVAILABLE);
        }
    }

    // Step 2: Polkit authentication (password / biometric).
    match polkit_authenticate() {
        Ok(true) => ExitCode::from(EXIT_APPROVED),
        Ok(false) => ExitCode::from(EXIT_DENIED),
        Err(e) => {
            eprintln!("opaque-approve-helper: polkit auth failed: {e}");
            ExitCode::from(EXIT_UNAVAILABLE)
        }
    }
}

/// Parse `--reason <text>` from command-line arguments.
fn parse_reason() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--reason" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

/// Display an intent dialog showing the operation details.
///
/// Tries zenity (GNOME/GTK) -> kdialog (KDE/Qt) -> terminal fallback.
/// Returns `Ok(true)` if the user confirms, `Ok(false)` if denied,
/// `Err` if no UI is available.
fn show_intent_dialog(reason: &str) -> Result<bool, String> {
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

    // Try kdialog (KDE/Qt).
    if let Ok(status) = Command::new("kdialog")
        .args(["--yesno", &dialog_text, "--title", "Opaque Approval"])
        .status()
    {
        return Ok(status.success());
    }

    // Terminal fallback if stdin is a TTY.
    if std::io::stdin().is_terminal() {
        eprint!("{dialog_text}\n\nApprove? [y/N] ");
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let answer = input.trim().to_lowercase();
            return Ok(answer == "y" || answer == "yes");
        }
    }

    // No UI available — fail closed.
    Err("no approval UI available (no zenity, kdialog, or TTY)".into())
}

/// Authenticate the user via polkit using `pkcheck`.
///
/// Uses the helper's own PID as the polkit subject. The `--allow-user-interaction`
/// flag triggers the polkit agent dialog for interactive authentication.
fn polkit_authenticate() -> Result<bool, String> {
    let pid = std::process::id();
    let status = Command::new("pkcheck")
        .args([
            "--process",
            &pid.to_string(),
            "--action-id",
            "com.opaque.approve",
            "--allow-user-interaction",
        ])
        .status()
        .map_err(|e| format!("failed to run pkcheck: {e}"))?;

    match status.code() {
        Some(0) => Ok(true),
        Some(1) | Some(2) => Ok(false),
        Some(c) => Err(format!("pkcheck exited with unexpected code {c}")),
        None => Err("pkcheck killed by signal".into()),
    }
}
