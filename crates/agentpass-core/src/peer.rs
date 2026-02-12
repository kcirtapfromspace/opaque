use std::io;
use std::os::unix::io::RawFd;

#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub pid: Option<i32>,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_info_from_fd(fd: RawFd) -> io::Result<PeerInfo> {
    #[cfg(target_os = "linux")]
    {
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(PeerInfo {
            pid: Some(ucred.pid),
            uid: ucred.uid,
            gid: ucred.gid,
        });
    }

    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        // LOCAL_PEERPID is available on macOS, but not always exposed by libc crate.
        // Fallback to pid=None if we can't retrieve it.
        let pid = local_peer_pid(fd).ok();

        return Ok(PeerInfo {
            pid,
            uid: uid as u32,
            gid: gid as u32,
        });
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer credential lookup not supported on this platform",
        ))
    }
}

#[cfg(target_os = "macos")]
fn local_peer_pid(fd: RawFd) -> io::Result<i32> {
    // sys/un.h: LOCAL_PEERPID
    const LOCAL_PEERPID: libc::c_int = 0x002; // value is stable on macOS
    const SOL_LOCAL: libc::c_int = 0; // sys/socket.h: SOL_LOCAL == 0

    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid as i32)
}

