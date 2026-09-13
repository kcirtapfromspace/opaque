use std::io;
use std::os::unix::io::RawFd;

#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub pid: Option<i32>,
    pub uid: u32,
    pub gid: u32,
    /// Kernel-issued macOS audit token, including the process incarnation.
    /// Never constructed from a transport request or a PID lookup.
    pub audit_token: Option<[u32; 8]>,
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
        Ok(PeerInfo {
            pid: Some(ucred.pid),
            uid: ucred.uid,
            gid: ucred.gid,
            audit_token: None,
        })
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

        Ok(PeerInfo {
            pid,
            uid: uid as u32,
            gid: gid as u32,
            audit_token: local_peer_audit_token(fd).ok(),
        })
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
fn local_peer_audit_token(fd: RawFd) -> io::Result<[u32; 8]> {
    // sys/un.h: LOCAL_PEERTOKEN. The token binds code-signing lookup to the
    // connected process incarnation; a later process reusing its PID cannot win.
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    let mut token = [0u32; 8];
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
    let rc =
        unsafe { libc::getsockopt(fd, 0, LOCAL_PEERTOKEN, token.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of_val(&token) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer audit token size",
        ));
    }
    Ok(token)
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
