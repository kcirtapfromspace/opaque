//! Bounded subprocess collection for workspace verification only.
//!
//! Git parses attacker-owned files even when its executable configuration is
//! isolated. Nonblocking pipes and a process-group deadline prevent a stalled
//! config FIFO or unlimited output from retaining a verifier indefinitely.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(5);
const STDOUT_LIMIT: usize = 16 * 1024 * 1024;
const STDERR_LIMIT: usize = 128 * 1024;

pub(crate) trait WorkspaceCommandExt {
    fn workspace_output(&mut self) -> io::Result<Output>;
    fn workspace_output_with_limit(&mut self, stdout_limit: usize) -> io::Result<Output>;
}

impl WorkspaceCommandExt for Command {
    fn workspace_output(&mut self) -> io::Result<Output> {
        self.workspace_output_with_limit(STDOUT_LIMIT)
    }

    fn workspace_output_with_limit(&mut self, stdout_limit: usize) -> io::Result<Output> {
        output_with_deadline(self, stdout_limit, STDERR_LIMIT, DEADLINE)
    }
}

struct ChildGuard {
    child: Child,
    complete: bool,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.complete {
            // process_group(0) makes the spawned child's PID its group ID.
            // Terminate inherited-pipe descendants as well as the Git child.
            // SAFETY: the negative ID addresses the group created for this
            // child; SIGKILL requires no pointer arguments.
            unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is an owned, live child-output pipe; these fcntl operations
    // read/set descriptor status flags without pointer arguments.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read at most one chunk per turn, ensuring floods cannot starve the other
/// pipe, the output checks, or the deadline. No background readers are created.
fn read_chunk(
    reader: &mut impl Read,
    bytes: &mut Vec<u8>,
    limit: usize,
) -> io::Result<(bool, bool)> {
    let mut chunk = [0; 8192];
    match reader.read(&mut chunk) {
        Ok(0) => Ok((true, false)),
        Ok(count) => {
            if count > limit.saturating_sub(bytes.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "workspace subprocess output limit exceeded",
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
            Ok((false, true))
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok((false, false))
        }
        Err(error) => Err(error),
    }
}

fn output_with_deadline(
    command: &mut Command,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> io::Result<Output> {
    // The command builder supplies null stdin; an explicitly supplied private
    // input file must survive here for check-attr and update-index.
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let started = Instant::now();
    let mut guard = ChildGuard {
        child: command.spawn()?,
        complete: false,
    };
    let mut stdout = guard
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing workspace stdout"))?;
    let mut stderr = guard
        .child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing workspace stderr"))?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    loop {
        if started.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "workspace subprocess deadline exceeded",
            ));
        }
        let mut progress = false;
        if !stdout_eof {
            let (eof, read) = read_chunk(&mut stdout, &mut output, stdout_limit)?;
            stdout_eof = eof;
            progress |= read;
        }
        if !stderr_eof {
            let (eof, read) = read_chunk(&mut stderr, &mut errors, stderr_limit)?;
            stderr_eof = eof;
            progress |= read;
        }
        // Defer reaping until both pipes close. A descendant retaining a pipe
        // keeps the original group identity live until its deadline cleanup.
        if stdout_eof
            && stderr_eof
            && let Some(status) = guard.child.try_wait()?
        {
            guard.complete = true;
            return Ok(Output {
                status,
                stdout: output,
                stderr: errors,
            });
        }
        if !progress {
            std::thread::sleep(
                Duration::from_millis(20).min(timeout.saturating_sub(started.elapsed())),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn workspace_process_preserves_file_stdin_and_exit_status() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        std::fs::write(&input, b"one\0two\n").unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "cat; printf diagnostic >&2; exit 7"])
            .stdin(std::fs::File::open(input).unwrap());
        let result = command.workspace_output().unwrap();
        assert_eq!(result.stdout, b"one\0two\n");
        assert_eq!(result.stderr, b"diagnostic");
        assert_eq!(result.status.code(), Some(7));
    }

    #[test]
    fn workspace_process_config_fifo_has_a_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let init = crate::workspace_git_read_command()
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .workspace_output()
            .unwrap();
        assert!(init.status.success());
        let fifo = root.join("config-fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: path names an owned temporary FIFO, created with private mode.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        std::fs::write(
            root.join(".git/config"),
            format!("[include]\npath = {}\n", fifo.display()),
        )
        .unwrap();
        let started = Instant::now();
        let result = output_with_deadline(
            crate::workspace_git_read_command()
                .arg("-C")
                .arg(&root)
                .args(["rev-parse", "--show-toplevel"]),
            1024,
            1024,
            Duration::from_millis(100),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn workspace_process_caps_each_output_pipe() {
        for script in [
            "while :; do printf 0123456789; done",
            "while :; do printf 0123456789 >&2; done",
        ] {
            let started = Instant::now();
            let result = output_with_deadline(
                Command::new("/bin/sh")
                    .args(["-c", script])
                    .stdin(Stdio::null()),
                1024,
                1024,
                Duration::from_secs(1),
            );
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    #[test]
    fn workspace_process_timeout_kills_group_and_reaps_parent() {
        let directory = tempfile::tempdir().unwrap();
        let pid = directory.path().join("pid");
        let marker = directory.path().join("escaped");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "echo $$ > \"$1\"; (sleep 0.5; touch \"$2\") & wait",
                "test",
            ])
            .arg(&pid)
            .arg(&marker)
            .stdin(Stdio::null());
        let result = output_with_deadline(&mut command, 1024, 1024, Duration::from_millis(100));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let child_id: libc::pid_t = std::fs::read_to_string(pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal 0 observes whether the recorded child still exists.
        assert_eq!(
            unsafe { libc::kill(child_id, 0) },
            -1,
            "direct child must be reaped"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        std::thread::sleep(Duration::from_millis(600));
        assert!(
            !marker.exists(),
            "descendants must not survive the deadline"
        );
    }
}
