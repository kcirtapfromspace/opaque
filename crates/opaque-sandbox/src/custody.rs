//! Cancellation owns the process group and every spawned pipe reader.
use opaque_core::proto::ExecFrame;
use std::{io, process::ExitStatus};
use tokio::{process::Child, sync::mpsc, time::Instant};

pub(super) struct ProcessCustody {
    pid: u32,
    armed: bool,
    readers: Vec<tokio::task::AbortHandle>,
}
impl ProcessCustody {
    /// Commands must use process_group(0), kill_on_drop(true), and this wait API.
    pub(super) fn new(pid: u32) -> Self {
        Self {
            pid,
            armed: pid != 0,
            readers: Vec::new(),
        }
    }
    pub(super) fn reader<T>(&mut self, task: &tokio::task::JoinHandle<T>) {
        self.readers.push(task.abort_handle());
    }
    pub(super) fn kill_group(&mut self) {
        if self.armed {
            // SAFETY: the leader has not been reaped, so its PID cannot have
            // been recycled. This group was created by process_group(0).
            unsafe {
                libc::kill(-(self.pid as libc::pid_t), libc::SIGKILL);
            }
            self.armed = false;
        }
    }
    /// Observe exit without reaping. Kill inherited-pipe descendants before
    /// reaping the leader, avoiding later signals to a recycled numeric PGID.
    pub(super) async fn wait(&mut self, child: &mut Child) -> io::Result<ExitStatus> {
        // Register before checking status, so exit between waitid and recv is
        // retained by the signal stream rather than lost.
        let mut exits = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())?;
        loop {
            // SAFETY: waitid initializes this owned siginfo and WNOWAIT retains
            // the child as a zombie until the explicit Child::wait below.
            let exited = {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        self.armed = false;
                    }
                    return Err(error);
                }
                (unsafe { info.si_pid() }) != 0
            };
            if exited {
                break;
            }
            exits.recv().await;
        }
        self.kill_group();
        child.wait().await
    }
}
impl Drop for ProcessCustody {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
        self.kill_group();
    }
}

pub(super) async fn send_frame(
    tx: &mpsc::Sender<ExecFrame>,
    frame: ExecFrame,
    deadline: Instant,
) -> io::Result<()> {
    tokio::time::timeout_at(deadline, tx.send(frame))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "execution frame delivery timed out",
            )
        })?
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "execution consumer disconnected"))
}

pub(super) fn completion_deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(5)
}
