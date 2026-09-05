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

use std::io::{IsTerminal, Read};
use std::process::{Command, ExitCode};

const EXIT_APPROVED: u8 = 0;
const EXIT_DENIED: u8 = 1;
const EXIT_UNAVAILABLE: u8 = 2;
const MAX_REVIEW_BYTES: usize = 128 * 1024;

mod review;

#[derive(Debug, PartialEq, Eq)]
enum HelperRequest {
    Legacy(String),
    ReviewStdin,
}

fn main() -> ExitCode {
    let request = match parse_request(std::env::args().skip(1).collect()) {
        Ok(request) => request,
        Err(()) => {
            eprintln!(
                "usage: opaque-approve-helper --reason <description> | --review-only --reason-stdin"
            );
            return ExitCode::from(EXIT_UNAVAILABLE);
        }
    };
    let reason = match request {
        HelperRequest::Legacy(reason) => reason,
        HelperRequest::ReviewStdin => {
            let reason = match read_review(std::io::stdin().lock()) {
                Ok(reason) => reason,
                Err(()) => return ExitCode::from(EXIT_UNAVAILABLE),
            };
            return ExitCode::from(match review::show(&reason) {
                Ok(true) => EXIT_APPROVED,
                Ok(false) => EXIT_DENIED,
                Err(()) => EXIT_UNAVAILABLE,
            });
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
        Ok(true) => {
            report_account();
            ExitCode::from(EXIT_APPROVED)
        }
        Ok(false) => ExitCode::from(EXIT_DENIED),
        Err(e) => {
            eprintln!("opaque-approve-helper: polkit auth failed: {e}");
            ExitCode::from(EXIT_UNAVAILABLE)
        }
    }
}

/// Report the polkit-authenticated account to the daemon on stdout, so the
/// approval is attributed to a named account instead of an anonymous pass.
/// The decision itself rides the exit code alone — this line is attribution
/// only, and the daemon ignores it if malformed. Usernames outside the safe
/// charset are skipped rather than escaped (no injection surface at all).
fn report_account() {
    // std-only uid lookup (this crate deliberately has no dependencies):
    // the second field of the Uid: line is the effective uid.
    let Some(uid) = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse::<u32>().ok())
        })
    else {
        return;
    };
    let username = std::env::var("USER").unwrap_or_default();
    if username.is_empty()
        || username.len() > 256
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return;
    }
    println!("{{\"account\":{{\"uid\":{uid},\"username\":\"{username}\"}}}}");
}

/// Parse `--reason <text>` from command-line arguments.
fn parse_request(args: Vec<String>) -> Result<HelperRequest, ()> {
    if args.len() == 2 && args[0] == "--reason" && !args[1].trim().is_empty() {
        return Ok(HelperRequest::Legacy(args[1].clone()));
    }
    if args.len() == 2
        && args.contains(&"--review-only".to_owned())
        && args.contains(&"--reason-stdin".to_owned())
    {
        return Ok(HelperRequest::ReviewStdin);
    }
    Err(())
}

/// Read one exact UTF-8 document, never silently truncate the approved scope.
fn read_review(input: impl Read) -> Result<String, ()> {
    let mut bytes = Vec::new();
    input
        .take(MAX_REVIEW_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > MAX_REVIEW_BYTES {
        return Err(());
    }
    let reason = String::from_utf8(bytes).map_err(|_| ())?;
    if reason.trim().is_empty() || reason.contains('\0') {
        return Err(());
    }
    Ok(reason)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_mode_requires_both_explicit_flags_and_no_inline_content() {
        let args = |values: &[&str]| values.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            parse_request(args(&["--review-only", "--reason-stdin"])),
            Ok(HelperRequest::ReviewStdin)
        );
        assert_eq!(
            parse_request(args(&["--reason-stdin", "--review-only"])),
            Ok(HelperRequest::ReviewStdin)
        );
        assert_eq!(
            parse_request(args(&["--reason", "legacy description"])),
            Ok(HelperRequest::Legacy("legacy description".into()))
        );
        for invalid in [
            vec!["--review-only"],
            vec!["--reason-stdin"],
            vec!["--reason", ""],
            vec!["--review-only", "--reason", "hidden"],
            vec!["--review-only", "--reason-stdin", "extra"],
        ] {
            assert!(parse_request(args(&invalid)).is_err());
        }
    }

    #[test]
    fn review_input_preserves_every_byte_and_fails_closed_at_limit() {
        let text = "\nExact task\n32. final action\nSHA-256: abc\n";
        assert_eq!(read_review(text.as_bytes()).unwrap(), text);
        assert!(read_review(vec![b'x'; MAX_REVIEW_BYTES].as_slice()).is_ok());
        assert!(read_review(vec![b'x'; MAX_REVIEW_BYTES + 1].as_slice()).is_err());
        assert!(read_review(&[0xff][..]).is_err());
        assert!(read_review(&b"text\0hidden"[..]).is_err());
        assert!(read_review(&b" \n\t"[..]).is_err());
    }
}
