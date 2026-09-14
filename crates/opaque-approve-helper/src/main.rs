#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

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

#[cfg(target_os = "linux")]
mod process;
mod review;

#[derive(Debug, PartialEq, Eq)]
enum HelperRequest {
    Legacy(String),
    ReviewStdin,
    CheckUi,
}

fn main() -> ExitCode {
    let request = match parse_request(std::env::args().skip(1).collect()) {
        Ok(request) => request,
        Err(()) => {
            eprintln!(
                "usage: opaque-approve-helper --reason <description> | --review-only --reason-stdin | --check-ui"
            );
            return ExitCode::from(EXIT_UNAVAILABLE);
        }
    };
    let reason = match request {
        HelperRequest::CheckUi => {
            return match review::check_ui() {
                Ok(()) => {
                    println!(
                        "{{\"check\":\"native_review_ui\",\"ready\":true,\"visibility_verified\":false}}"
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("opaque-approve-helper: {error}");
                    ExitCode::from(EXIT_UNAVAILABLE)
                }
            };
        }
        HelperRequest::Legacy(reason) => reason,
        HelperRequest::ReviewStdin => {
            let reason = match read_review(std::io::stdin().lock()) {
                Ok(reason) => reason,
                Err(()) => return ExitCode::from(EXIT_UNAVAILABLE),
            };
            return ExitCode::from(match review::show(&reason) {
                Ok(true) => EXIT_APPROVED,
                Ok(false) => EXIT_DENIED,
                Err(error) => {
                    eprintln!("opaque-approve-helper: {error}");
                    EXIT_UNAVAILABLE
                }
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
    let Some(status) = std::fs::read_to_string("/proc/self/status").ok() else {
        return;
    };
    let username = std::env::var("USER").unwrap_or_default();
    if let Some(report) = account_report(&status, &username) {
        println!("{report}");
    }
}

/// Derive attribution from the actual process status and safe display label.
/// This is not the authentication decision, which is carried by exit status.
fn account_report(status: &str, username: &str) -> Option<String> {
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .nth(2)?
        .parse::<u32>()
        .ok()?;
    if username.is_empty()
        || username.len() > 256
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return None;
    }
    Some(format!(
        "{{\"account\":{{\"uid\":{uid},\"username\":\"{username}\"}}}}"
    ))
}

/// Parse `--reason <text>` from command-line arguments.
fn parse_request(args: Vec<String>) -> Result<HelperRequest, ()> {
    if args == ["--check-ui"] {
        return Ok(HelperRequest::CheckUi);
    }
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
        assert_eq!(
            parse_request(args(&["--check-ui"])),
            Ok(HelperRequest::CheckUi)
        );
        for invalid in [
            vec!["--review-only"],
            vec!["--reason-stdin"],
            vec!["--reason", ""],
            vec!["--review-only", "--reason", "hidden"],
            vec!["--review-only", "--reason-stdin", "extra"],
            vec!["--check-ui", "--review-only", "--reason-stdin"],
            vec!["--check-ui", "--reason", "hidden"],
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

    #[cfg(target_os = "macos")]
    #[test]
    fn appkit_observation_guards_fail_closed_and_never_activate_without_need() {
        // Injected OS observations verify the decision contract, not a GUI ceremony.
        assert!(review::require_console_user(0, 0).is_err());
        assert!(review::require_console_user(501, 502).is_err());
        assert_eq!(review::require_console_user(501, 501), Ok(()));
        assert!(review::require_screen(false).is_err());
        assert_eq!(review::require_screen(true), Ok(()));
        assert!(review::require_ordered_window(false).is_err());
        assert_eq!(review::require_ordered_window(true), Ok(()));
        assert_eq!(
            review::prepare_activation(false, || panic!(
                "already active application must not change policy"
            )),
            Ok(())
        );
        let calls = std::cell::Cell::new(0);
        assert!(
            review::prepare_activation(true, || {
                calls.set(calls.get() + 1);
                false
            })
            .is_err()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            review::prepare_activation(true, || {
                calls.set(calls.get() + 1);
                true
            }),
            Ok(())
        );
        assert_eq!(calls.get(), 2);
        assert!(review::record_review_decision(true));
        assert!(!review::record_review_decision(false));
    }

    #[test]
    fn review_input_io_failure_and_duplicate_flags_never_produce_a_document() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fixture input unavailable"))
            }
        }
        assert!(read_review(Broken).is_err());
        assert!(parse_request(vec!["--review-only".into(), "--review-only".into()]).is_err());
    }

    #[test]
    fn account_attribution_uses_effective_uid_and_rejects_unusable_labels() {
        let status = "Name: helper\nUid:\t100\t200\t300\t400\n";
        assert_eq!(
            account_report(status, "fixture.user_-9").unwrap(),
            r#"{"account":{"uid":200,"username":"fixture.user_-9"}}"#
        );
        for name in [
            "".to_owned(),
            "x".repeat(257),
            "newline\nvalue".into(),
            "é".into(),
            "quote\"".into(),
        ] {
            assert!(account_report(status, &name).is_none());
        }
        for status in ["", "Uid:", "Uid: 100 invalid", "Uid: 100 4294967296"] {
            assert!(account_report(status, "fixture").is_none());
        }
        assert!(account_report(status, &"x".repeat(256)).is_some());
    }
}
