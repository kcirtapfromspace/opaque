//! Actual controlling-terminal processes with a synthetic framed broker peer.
//! The helper owns a separate session; no user terminal or process group is used.
#![cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/agent-terminal.py"
);

struct Supervisor<'a> {
    child: Child,
    directory: &'a Path,
    reaped: bool,
    master: Option<std::fs::File>,
}
impl Drop for Supervisor<'_> {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Retain this unreaped session-leader PID until all recorded groups have
        // been checked. Matching getsid cannot then select a reused foreign SID.
        unsafe {
            let group = self
                .master
                .as_ref()
                .map_or(-1, |master| libc::tcgetpgrp(master.as_raw_fd()));
            if group > 1
                && group != self.child.id() as i32
                && libc::getsid(group) == self.child.id() as i32
                && libc::getpgid(group) == group
            {
                // The master also discovers a child stopped before it could
                // publish its test identity. The retained SID fences reuse.
                libc::kill(-group, libc::SIGKILL);
            }
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let cleanup = Command::new("/usr/bin/python3")
            .args([HELPER, "cleanup"])
            .arg(self.directory)
            .arg(self.child.id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut cleanup) = cleanup {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if matches!(cleanup.try_wait(), Ok(Some(_))) {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = cleanup.kill();
                    let _ = cleanup.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        // Darwin can retain an exiting tty session leader until the last
        // master closes. First capture/fence groups above, then release it.
        self.master.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn terminal_case(case: &str) {
    let base = std::fs::canonicalize("/tmp").unwrap();
    let directory = tempfile::Builder::new()
        .prefix("oq-term-")
        .tempdir_in(base)
        .unwrap();
    // Allocate descriptors with CLOEXEC atomically: parallel tests must not
    // inherit one another's PTY masters and hold an unrelated session open.
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    assert!(master_fd >= 0, "{}", std::io::Error::last_os_error());
    let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    assert_eq!(unsafe { libc::grantpt(master_fd) }, 0);
    assert_eq!(unsafe { libc::unlockpt(master_fd) }, 0);
    // POSIX ptsname may reuse a static buffer. Only copying that name needs
    // serialization; every supervisor and scenario continues independently.
    static PTY_NAME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let slave_name = {
        let _guard = PTY_NAME.lock().unwrap();
        let name = unsafe { libc::ptsname(master_fd) };
        assert!(!name.is_null());
        unsafe { std::ffi::CStr::from_ptr(name) }
            .to_str()
            .unwrap()
            .to_owned()
    };
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(slave_name)
        .unwrap();
    let mut command = Command::new("/usr/bin/python3");
    command
        .args([HELPER, case])
        .arg(directory.path())
        .arg(env!("CARGO_BIN_EXE_opaque"))
        .arg(master_fd.to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", directory.path())
        .stdin(Stdio::from(slave))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    #[cfg(coverage_nightly)]
    command.env(
        "OPAQUE_COVERAGE_PROFILE_DIR",
        std::env::var_os("OPAQUE_COVERAGE_PROFILE_DIR").expect("coverage directory"),
    );
    // SAFETY: only async-signal-safe setsid/fcntl run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(master_fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut supervisor = Supervisor {
        child: command.spawn().unwrap(),
        directory: directory.path(),
        reaped: false,
        master: Some(master),
    };
    let result_path = directory.path().join("result.json");
    let deadline = Instant::now() + Duration::from_secs(45);
    // Do not try_wait: retaining the unreaped PID makes outer-failure cleanup's
    // session identity check safe even if the supervisor has already crashed.
    while !result_path.is_file() {
        assert!(
            Instant::now() < deadline,
            "terminal supervisor deadline: {case}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(result_path).unwrap()).unwrap();
    assert_eq!(result["status"], "passed", "{case}: {result}");
    assert_eq!(result["cleanup_forced"], false, "{case}: {result}");
    supervisor.master.take();
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = supervisor.child.try_wait().unwrap() {
            supervisor.reaped = true;
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < exit_deadline, "supervisor did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn terminal_ctrl_c_reaches_child_once_and_preserves_foreground_stdin() {
    terminal_case("ctrl_c");
}
#[test]
fn terminal_direct_wrapper_sigint_forwards_once_and_restores_foreground() {
    terminal_case("direct_int");
}
#[test]
fn terminal_direct_wrapper_sigterm_forwards_once_and_restores_foreground() {
    terminal_case("direct_term");
}
#[test]
fn terminal_normal_exit_restores_foreground_before_revocation_ack() {
    terminal_case("normal");
}
#[test]
fn terminal_spawn_failure_restores_foreground_without_running_child() {
    terminal_case("spawn_failure");
}
#[test]
fn terminal_pending_grant_cancellation_revokes_without_running_child() {
    terminal_case("pending_cancel");
}
#[test]
fn terminal_stop_and_foreground_resume_do_not_steal_background_terminal() {
    terminal_case("stop_resume");
}

#[test]
fn terminal_cleanup_preserves_foreign_foreground_owner_and_modes() {
    terminal_case("foreign_owner");
}

#[test]
fn terminal_keyboard_handler_can_continue_beyond_wrapper_cancellation_grace() {
    terminal_case("keyboard_continue");
}
