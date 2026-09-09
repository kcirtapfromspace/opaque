//! Keep the Linux review window within the helper's lifetime.

use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn bind_to_parent(command: &mut Command) {
    let parent_pid = std::process::id() as libc::pid_t;
    // SAFETY: the child hook uses only async-signal-safe libc calls and
    // constructs OS errors without allocating. No Rust lock is acquired after
    // fork. PR_SET_PDEATHSIG is local to this child and survives exec.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Close the race where the helper exits between fork and prctl.
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    struct TestProcess(Child);
    impl Drop for TestProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn parent_death_fixture() {
        if std::env::var_os("OPAQUE_PARENT_DEATH_TEST").is_none() {
            return;
        }
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        bind_to_parent(&mut command);
        let child = TestProcess(command.spawn().unwrap());
        println!("review-child-pid: {}", child.0.id());
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn review_child_stops_when_the_helper_is_killed() {
        let mut parent = TestProcess(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process::tests::parent_death_fixture",
                    "--nocapture",
                ])
                .env("OPAQUE_PARENT_DEATH_TEST", "1")
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let output = std::io::BufReader::new(parent.0.stdout.take().unwrap());
        let pid: u32 = output
            .lines()
            .map(Result::unwrap)
            .find_map(|line| {
                line.strip_prefix("review-child-pid: ")
                    .map(|pid| pid.parse().unwrap())
            })
            .expect("fixture started its disposable child");
        parent.0.kill().unwrap();
        parent.0.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // A container's init may defer reaping orphans. A zombie is no
            // longer executing and cannot retain a live dialog.
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            if stat.is_err() || stat.as_ref().is_ok_and(|line| line.contains(") Z ")) {
                break;
            }
            if Instant::now() >= deadline {
                // SAFETY: terminate only the disposable child whose pid was
                // returned by this test; never leave its sleep process alive.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
                panic!("review child survived helper termination");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
