//! Actual helper subprocesses with private, scripted desktop command boundaries.
//! Success here establishes command sequencing, never physical authentication.
use std::{
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};
struct Desktop {
    path: PathBuf,
}
impl Desktop {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "opaque-helper-command-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }
    fn tool(&self, name: &str, result: &str) {
        std::os::unix::fs::symlink(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dialog-tool.sh"),
            self.path.join(name),
        )
        .unwrap();
        std::fs::write(
            self.path.join(format!("{name}.result")),
            format!("{result}\n"),
        )
        .unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_opaque-approve-helper"))
            .args(args)
            .env("PATH", &self.path)
            .env("HOME", &self.path)
            .env("USER", "fixture-reviewer")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

#[test]
fn helper_declined_dialog_never_invokes_authentication() {
    for dialog in ["zenity", "kdialog"] {
        let desktop = Desktop::new();
        desktop.tool(dialog, "1");
        desktop.tool("pkcheck", "0");
        let output = desktop.run(&["--reason", "Exact disposable operation"]);
        assert_eq!(output.status.code(), Some(1));
        let args =
            std::fs::read_to_string(desktop.path.join(format!("{dialog}.arguments"))).unwrap();
        assert!(args.contains("Exact disposable operation"));
        assert!(!desktop.path.join("pkcheck.arguments").exists());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn helper_authentication_codes_preserve_denial_unavailable_and_subject_binding() {
    for (result, expected) in [("0", 0), ("1", 1), ("2", 1), ("3", 2), ("signal", 2)] {
        let desktop = Desktop::new();
        desktop.tool("zenity", "0");
        desktop.tool("pkcheck", result);
        let child = Command::new(env!("CARGO_BIN_EXE_opaque-approve-helper"))
            .args(["--reason", "Exact disposable operation"])
            .env("PATH", &desktop.path)
            .env("USER", "fixture-reviewer")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let args = std::fs::read_to_string(desktop.path.join("pkcheck.arguments")).unwrap();
        assert_eq!(
            args,
            format!(
                "--process\n{pid}\n--action-id\ncom.opaque.approve\n--allow-user-interaction\n"
            )
        );
        if expected != 0 {
            assert!(output.stdout.is_empty());
        }
        #[cfg(target_os = "linux")]
        if expected == 0 {
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("\"username\":\"fixture-reviewer\"")
            );
        }
    }
}

#[test]
fn helper_fallback_and_missing_commands_fail_closed_without_a_terminal() {
    let desktop = Desktop::new();
    let output = desktop.run(&["--reason", "Exact disposable operation"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no approval UI available"));
    desktop.tool("kdialog", "0");
    let output = desktop.run(&["--reason", "Exact disposable operation"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to run pkcheck"));
    assert!(desktop.path.join("kdialog.arguments").is_file());
}

#[test]
fn helper_cli_rejects_empty_review_and_ambiguous_flags_before_any_ui() {
    let desktop = Desktop::new();
    for args in [
        &["--review-only", "--review-only"][..],
        &["--review-only", "--reason-stdin"][..],
        &["--reason", "  "][..],
        &[][..],
    ] {
        let output = desktop.run(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn terminal_fallback_reads_exact_confirmation_before_invoking_polkit_boundary() {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    for (answer, approved) in [("y\n", true), ("YES\n", true), ("no\n", false)] {
        let desktop = Desktop::new();
        desktop.tool("pkcheck", "0");
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: both output pointers are valid and optional attributes null;
        // returned descriptors are immediately transferred into owned files.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = OwnedChild(
            Command::new(env!("CARGO_BIN_EXE_opaque-approve-helper"))
                .args(["--reason", "Exact terminal scope"])
                .env("PATH", &desktop.path)
                .env("HOME", &desktop.path)
                .env("USER", "fixture-reviewer")
                .stdin(slave)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        master.write_all(answer.as_bytes()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "private terminal helper did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(if approved { 0 } else { 1 }));
        assert_eq!(desktop.path.join("pkcheck.arguments").exists(), approved);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_full_review_requires_display_capability_and_exact_document_delivery() {
    use std::io::Write;
    let desktop = Desktop::new();
    let unavailable = desktop.run(&["--check-ui"]);
    assert_eq!(unavailable.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("no Linux display"));
    let check = || {
        Command::new(env!("CARGO_BIN_EXE_opaque-approve-helper"))
            .arg("--check-ui")
            .env("PATH", &desktop.path)
            .env("DISPLAY", ":fixture")
            .env_remove("WAYLAND_DISPLAY")
            .output()
            .unwrap()
    };
    assert!(String::from_utf8_lossy(&check().stderr).contains("zenity is required"));
    desktop.tool("zenity", "0");
    std::fs::write(desktop.path.join("zenity.version"), "3\n").unwrap();
    assert!(String::from_utf8_lossy(&check().stderr).contains("zenity is unavailable"));
    std::fs::write(desktop.path.join("zenity.version"), "0\n").unwrap();
    let available = check();
    assert_eq!(available.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(available.stdout).unwrap().trim(),
        r#"{"check":"native_review_ui","ready":true,"visibility_verified":false}"#
    );
    for (result, expected) in [("0", 0), ("1", 1), ("3", 2), ("signal", 2)] {
        std::fs::write(desktop.path.join("zenity.result"), format!("{result}\n")).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_opaque-approve-helper"))
            .args(["--review-only", "--reason-stdin"])
            .env("PATH", &desktop.path)
            .env("DISPLAY", ":fixture")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let document = "Exact target\n  unchanged whitespace\nlast allowance=1\n";
        child
            .stdin
            .take()
            .unwrap()
            .write_all(document.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(desktop.path.join("zenity.review")).unwrap(),
            document
        );
        assert!(!desktop.path.join("pkcheck.arguments").exists());
        assert!(
            std::fs::read_to_string(desktop.path.join("zenity.arguments"))
                .unwrap()
                .contains("--checkbox=I reviewed every action and limit")
        );
    }
}
