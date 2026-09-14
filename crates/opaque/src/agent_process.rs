//! Own the agent's process group and temporarily lend it our controlling tty.
//!
//! Keyboard signals go directly to the foreground agent. Its exit status is
//! authoritative, including a handler that continues or exits successfully.
//! Signals explicitly sent to the wrapper cancel the entire owned group with
//! a five-second grace period. Neither operation signals the caller's group.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::signal::unix::Signal;

fn check(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// All operations here are synchronous. The calling thread's mask is restored
// before returning; it is never carried across an async suspension point.
fn foreground(fd: libc::c_int, group: libc::pid_t) -> io::Result<()> {
    unsafe {
        let mut blocked = std::mem::zeroed();
        let mut previous = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        let error = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        let result = check(libc::tcsetpgrp(fd, group));
        let error = libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        result?;
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        Ok(())
    }
}

fn modes(fd: libc::c_int) -> io::Result<libc::termios> {
    unsafe {
        let mut value = std::mem::zeroed();
        check(libc::tcgetattr(fd, &mut value))?;
        Ok(value)
    }
}

struct Terminal {
    file: File,
    wrapper_group: libc::pid_t,
    child_group: Option<libc::pid_t>,
    original_modes: Option<libc::termios>,
    suspended_modes: Option<libc::termios>,
}

impl Terminal {
    fn open() -> io::Result<Option<Self>> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
            .open("/dev/tty")
        {
            Ok(file) => file,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENXIO | libc::ENODEV | libc::ENOENT | libc::ENOTTY)
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let wrapper_group = unsafe { libc::getpgrp() };
        let current = unsafe { libc::tcgetpgrp(file.as_raw_fd()) };
        check(current)?;
        let original_modes = if current == wrapper_group {
            Some(modes(file.as_raw_fd())?)
        } else {
            None
        };
        Ok(Some(Self {
            file,
            wrapper_group,
            child_group: None,
            original_modes,
            suspended_modes: None,
        }))
    }

    fn restore(&mut self, suspended: bool) -> io::Result<()> {
        let Some(group) = self.child_group else {
            return Ok(());
        };
        let fd = self.file.as_raw_fd();
        let current = unsafe { libc::tcgetpgrp(fd) };
        check(current)?;
        // A shell may already have foregrounded another job. Never steal it.
        if current != group {
            return Ok(());
        }
        if suspended {
            self.suspended_modes = Some(modes(fd)?);
        }
        foreground(fd, self.wrapper_group)?;
        if let Some(original) = &self.original_modes {
            check(unsafe { libc::tcsetattr(fd, libc::TCSANOW, original) })?;
        }
        Ok(())
    }

    fn resume(&mut self, group: libc::pid_t) -> io::Result<()> {
        let fd = self.file.as_raw_fd();
        let current = unsafe { libc::tcgetpgrp(fd) };
        check(current)?;
        // `bg` resumes execution without transferring the terminal. A later
        // terminal read may stop the job again with the normal SIGTTIN action.
        if current != self.wrapper_group {
            return Ok(());
        }
        if self.original_modes.is_none() {
            self.original_modes = Some(modes(fd)?);
        }
        if let Some(suspended) = &self.suspended_modes {
            check(unsafe { libc::tcsetattr(fd, libc::TCSANOW, suspended) })?;
        }
        foreground(fd, group)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // Explicit restoration reports errors. This additionally covers an
        // unwinding caller without ever taking a foreign foreground group.
        let _ = self.restore(false);
    }
}

#[cfg(target_os = "macos")]
fn group_has_only_zombies(group: libc::pid_t) -> bool {
    // Darwin killpg returns EPERM when all group members are zombies. Preserve
    // the unreaped leader's identity and prove every remaining member is dead;
    // a live member, partial inventory, or denied inspection stays fail-closed.
    const PROC_PGRP_ONLY: u32 = 2; // Darwin sys/proc_info.h
    let needed =
        unsafe { libc::proc_listpids(PROC_PGRP_ONLY, group as u32, std::ptr::null_mut(), 0) };
    if needed <= 0 || needed > 1024 * 1024 {
        return false;
    }
    let mut pids = vec![0i32; needed as usize / std::mem::size_of::<libc::pid_t>() + 32];
    let capacity = std::mem::size_of_val(pids.as_slice()) as i32;
    let received = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            group as u32,
            pids.as_mut_ptr().cast(),
            capacity,
        )
    };
    if received <= 0
        || received >= capacity
        || !(received as usize).is_multiple_of(std::mem::size_of::<libc::pid_t>())
    {
        return false;
    }
    pids.truncate(received as usize / std::mem::size_of::<libc::pid_t>());
    if !pids.contains(&group) {
        return false;
    }
    pids.into_iter().all(|pid| unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let size = std::mem::size_of_val(&info) as i32;
        // arg=1 explicitly includes zombie records in PROC_PIDTBSDINFO.
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            1,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        ) == size
            && info.pbi_pid == pid as u32
            && info.pbi_pgid == group as u32
            && info.pbi_status == libc::SZOMB
    })
}

fn signal_group(group: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    if group <= 0 || group == unsafe { libc::getpgrp() } {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    completed_group_signal(group, check(unsafe { libc::kill(-group, signal) }))
}

fn completed_group_signal(_group: libc::pid_t, result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        #[cfg(target_os = "macos")]
        Err(error)
            if error.raw_os_error() == Some(libc::EPERM) && group_has_only_zombies(_group) =>
        {
            Ok(())
        }
        result => result,
    }
}

fn child_stopped(pid: libc::pid_t) -> io::Result<bool> {
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let result = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WSTOPPED | libc::WCONTINUED | libc::WNOHANG,
        );
        if result == -1 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::EINTR | libc::ECHILD)) {
                return Ok(false);
            }
            return Err(error);
        }
        // WEXITED is deliberately absent: Tokio alone reaps the child exit.
        Ok(info.si_code == libc::CLD_STOPPED)
    }
}

// An unreaped leader reserves the process-group identifier. Disarm this guard
// before reaping so cleanup can never target a newly reused PID/process group.
struct OwnedGroup {
    id: libc::pid_t,
    active: bool,
}

impl OwnedGroup {
    fn signal(&self, signal: i32) -> io::Result<()> {
        if self.active {
            signal_group(self.id, signal)
        } else {
            Ok(())
        }
    }

    async fn finish(&mut self, child: &mut Child) -> io::Result<std::process::ExitStatus> {
        let reap_timeout = || {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "agent child did not exit after forced termination",
            )
        };
        if !self.active {
            // A failed cleanup may be reported again by the caller. Its group
            // was already signalled before reaping; never extend the deadline.
            return child.try_wait()?.ok_or_else(reap_timeout);
        }
        let group_killed = self.signal(libc::SIGKILL);
        // The direct child may have moved to another process group. Target its
        // retained Child identity as well; never signal that foreign group.
        let child_killed = match child.start_kill() {
            Err(_) if child_exited(self.id).unwrap_or(false) => Ok(()),
            result => result,
        };
        // Both kill attempts precede any reap. No later group signal may reuse
        // this identifier, including when the bounded wait below times out.
        self.active = false;
        let status = tokio::time::timeout(Duration::from_secs(1), child.wait())
            .await
            .map_err(|_| reap_timeout())
            .and_then(|result| result);
        group_killed.and(child_killed).and(status)
    }
}

impl Drop for OwnedGroup {
    fn drop(&mut self) {
        // The guard is declared after Child, so its group cleanup also precedes
        // Tokio's direct-child kill/reap when this future is dropped or unwinds.
        let _ = self.signal(libc::SIGKILL);
    }
}

fn child_exited(pid: libc::pid_t) -> io::Result<bool> {
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let observed = check(libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        ));
        if let Err(error) = observed {
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(matches!(
            info.si_code,
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
        ))
    }
}

async fn cancel(child: &mut Child, group: &mut OwnedGroup, signal: i32) -> io::Result<()> {
    if !group.active {
        return Ok(());
    }
    let sent = group.signal(signal);
    // A stopped agent cannot handle a pending termination until continued.
    let continued = group.signal(libc::SIGCONT);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let observed = loop {
        match child_exited(group.id) {
            Ok(true) => break Ok(()),
            Err(error) if error.kind() != io::ErrorKind::Interrupted => break Err(error),
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            break Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // Kill remaining descendants while the unreaped leader still reserves its
    // PID, then reap. Even a successful handler can leave stubborn descendants.
    // Darwin can reject SIGCONT while the terminated child is still moving
    // into its zombie record. Recheck those errors against the complete group
    // after waiting, while the unreaped leader still reserves the group ID.
    // Live members, incomplete inspection and all other errors still fail.
    let sent = completed_group_signal(group.id, sent);
    let continued = completed_group_signal(group.id, continued);
    let finished = group.finish(child).await.map(|_| ());
    sent.and(continued).and(observed).and(finished)
}

async fn supervise(
    child: &mut Child,
    group: &mut OwnedGroup,
    terminal: &mut Option<Terminal>,
    interrupt: &mut Signal,
    terminate: &mut Signal,
) -> Result<i32, String> {
    let mut ticks = tokio::time::interval(Duration::from_millis(20));
    let mut resumed = false;
    loop {
        let signal = tokio::select! {
            biased;
            _ = interrupt.recv() => Some(libc::SIGINT),
            _ = terminate.recv() => Some(libc::SIGTERM),
            _ = ticks.tick() => None,
        };
        if let Some(signal) = signal {
            cancel(child, group, signal)
                .await
                .map_err(|error| format!("agent cancellation cleanup failed: {error}"))?;
            return Ok(128 + signal);
        }
        if resumed {
            if let Some(terminal) = terminal {
                terminal
                    .resume(group.id)
                    .map_err(|error| format!("cannot resume agent terminal: {error}"))?;
            }
            group
                .signal(libc::SIGCONT)
                .map_err(|error| format!("cannot resume agent group: {error}"))?;
            resumed = false;
        }
        if child_exited(group.id).map_err(|error| format!("cannot inspect agent exit: {error}"))? {
            let status = group
                .finish(child)
                .await
                .map_err(|error| format!("agent descendant cleanup failed: {error}"))?;
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
        }
        if child_stopped(group.id)
            .map_err(|error| format!("cannot inspect agent job status: {error}"))?
        {
            group
                .signal(libc::SIGSTOP)
                .map_err(|error| format!("cannot suspend agent group: {error}"))?;
            if let Some(terminal) = terminal {
                terminal
                    .restore(true)
                    .map_err(|error| format!("cannot restore suspended terminal: {error}"))?;
            }
            // Stop this wrapper only, so the invoking shell observes a stopped
            // job. SIGCONT returns here; pending cancellation is checked first.
            check(unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) })
                .map_err(|error| format!("cannot suspend agent wrapper: {error}"))?;
            resumed = true;
        }
    }
}

pub async fn run(
    mut command: Command,
    interrupt: &mut Signal,
    terminate: &mut Signal,
) -> Result<i32, String> {
    let mut terminal =
        Terminal::open().map_err(|error| format!("cannot inspect agent terminal: {error}"))?;
    let handoff = terminal
        .as_ref()
        .filter(|tty| tty.original_modes.is_some())
        .map(|tty| (tty.file.as_raw_fd(), tty.wrapper_group));
    let (mut reader, writer) =
        UnixStream::pair().map_err(|error| format!("cannot prepare agent process: {error}"))?;
    reader
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("cannot bound agent process setup: {error}"))?;
    command.kill_on_drop(true);
    // SAFETY: only fixed-size stack data and async-signal-safe libc calls run
    // after fork. No allocation, environment lookup, locks, or async work.
    unsafe {
        command.pre_exec(move || {
            check(libc::setpgid(0, 0))?;
            let group = libc::getpid();
            let bytes = group.to_ne_bytes();
            let mut written = 0;
            while written < bytes.len() {
                let count = libc::write(
                    writer.as_raw_fd(),
                    bytes[written..].as_ptr().cast(),
                    bytes.len() - written,
                );
                if count < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(error);
                }
                if count == 0 {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                written += count as usize;
            }
            if let Some((fd, original_group)) = handoff {
                if libc::tcgetpgrp(fd) != original_group {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                // Caught wrapper handlers must not run in the child between
                // foreground handoff and exec. Exec would reset them anyway.
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut action.sa_mask);
                check(libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()))?;
                check(libc::sigaction(
                    libc::SIGTERM,
                    &action,
                    std::ptr::null_mut(),
                ))?;
                let mut blocked = std::mem::zeroed();
                let mut previous = std::mem::zeroed();
                libc::sigemptyset(&mut blocked);
                libc::sigaddset(&mut blocked, libc::SIGTTOU);
                // This post-fork child has only one thread. sigprocmask is
                // async-signal-safe; the parent uses pthread_sigmask instead.
                check(libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous))?;
                let transferred = check(libc::tcsetpgrp(fd, group));
                let restored = check(libc::sigprocmask(
                    libc::SIG_SETMASK,
                    &previous,
                    std::ptr::null_mut(),
                ));
                transferred.and(restored)?;
            }
            Ok(())
        });
    }
    let spawned = command.spawn();
    drop(command); // Close the parent's copy of the child-owned CLOEXEC writer.
    let mut bytes = [0u8; std::mem::size_of::<libc::pid_t>()];
    let identified = reader.read_exact(&mut bytes);
    let group = identified
        .as_ref()
        .ok()
        .map(|_| libc::pid_t::from_ne_bytes(bytes));
    if let Some(terminal) = &mut terminal {
        terminal.child_group = group.or_else(|| {
            spawned
                .as_ref()
                .ok()
                .and_then(Child::id)
                .map(|id| id as libc::pid_t)
        });
    }
    let outcome = match spawned {
        Err(error) => Err(format!("failed to spawn agent command: {error}")),
        Ok(mut child) => {
            let actual = child.id().expect("newly spawned child has a PID") as libc::pid_t;
            let mut owned = OwnedGroup {
                id: actual,
                active: true,
            };
            let outcome = if let Err(error) = identified {
                Err(format!(
                    "agent process-group setup was not acknowledged: {error}"
                ))
            } else if group != Some(actual) {
                Err("agent process-group setup identity mismatch".to_owned())
            } else {
                supervise(&mut child, &mut owned, &mut terminal, interrupt, terminate).await
            };
            if let Err(error) = outcome {
                // A failed supervisor cannot safely keep the agent running.
                // Force cleanup once; do not add a second cancellation grace.
                match owned.finish(&mut child).await {
                    Ok(_) => Err(error),
                    Err(cleanup) => {
                        Err(format!("{error}; agent process cleanup failed: {cleanup}"))
                    }
                }
            } else {
                outcome
            }
        }
    };
    let restored = terminal
        .as_mut()
        .map(|tty| tty.restore(false))
        .transpose()
        .map_err(|error| format!("agent terminal restoration failed: {error}"));
    match (outcome, restored) {
        (Ok(code), Ok(_)) => Ok(code),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(restore)) => Err(format!("{error}; {restore}")),
    }
}

#[cfg(all(test, target_os = "macos"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::time::Instant;

    #[tokio::test]
    async fn rapid_cancellation_reaps_every_owned_child_without_false_permission_failure() {
        for attempt in 0..128 {
            let mut child = Command::new("/bin/sleep")
                .arg("60")
                .process_group(0)
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let pid = child.id().unwrap() as libc::pid_t;
            let mut group = OwnedGroup {
                id: pid,
                active: true,
            };
            let outcome = cancel(&mut child, &mut group, libc::SIGTERM).await;
            assert!(
                child.try_wait().unwrap().is_some(),
                "child was not reaped on attempt {attempt}"
            );
            assert!(!group.active, "group must be disarmed before PID reuse");
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
            assert!(outcome.is_ok(), "cancellation {attempt}: {outcome:?}");
        }
    }

    #[test]
    fn darwin_group_inspection_distinguishes_live_stopped_and_unreaped_zombie() {
        struct Fixture(std::process::Child);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Fixture(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id() as libc::pid_t;
        assert!(!group_has_only_zombies(pid));
        assert_eq!(
            completed_group_signal(pid, Err(io::Error::from_raw_os_error(libc::EPERM)))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        signal_group(pid, libc::SIGSTOP).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !child_stopped(pid).unwrap() {
            assert!(Instant::now() < deadline, "owned child did not stop");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!group_has_only_zombies(pid));
        signal_group(pid, libc::SIGKILL).unwrap();
        while !child_exited(pid).unwrap() {
            assert!(Instant::now() < deadline, "owned child did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(group_has_only_zombies(pid));
        // Native Darwin killpg returns EPERM for this zombie-only group. The
        // guarded operation succeeds, while retaining the PID until Drop reaps.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGKILL) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        signal_group(pid, libc::SIGKILL).unwrap();
        // Reconciliation may clear the native zombie-group EPERM while this
        // identity is retained, but cannot turn another error into success.
        completed_group_signal(pid, Err(io::Error::from_raw_os_error(libc::EPERM))).unwrap();
        assert_eq!(
            completed_group_signal(pid, Err(io::Error::from_raw_os_error(libc::EINVAL)))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }
}
