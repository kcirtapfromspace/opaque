use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const DEFAULT_SOCKET_FILENAME: &str = "opaqued.sock";

/// Resolve the socket path, optionally allowing the `OPAQUE_SOCK` env override.
///
/// The daemon should call `socket_path_for_client(false)` to ignore the env
/// var (prevents an attacker from redirecting via environment). The CLI uses
/// `socket_path()` which delegates to `socket_path_for_client(true)`.
/// System socket location used by split (service-account) deployments.
pub const SYSTEM_SOCKET_PATH: &str = "/run/opaque/opaqued.sock";

pub fn socket_path_for_client(allow_env_override: bool) -> PathBuf {
    if allow_env_override && let Ok(p) = std::env::var("OPAQUE_SOCK") {
        return PathBuf::from(p);
    }

    let user_candidate = if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        let dir_path = Path::new(&dir);
        // Reject non-absolute or paths with `..` components.
        if dir_path.is_absolute()
            && !dir_path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            Some(dir_path.join("opaque").join(DEFAULT_SOCKET_FILENAME))
        } else {
            None
        }
    } else {
        None
    };

    let user_candidate = user_candidate.unwrap_or_else(|| {
        let home = std::env::var_os("HOME").unwrap_or_else(|| OsString::from("."));
        PathBuf::from(home)
            .join(".opaque")
            .join("run")
            .join(DEFAULT_SOCKET_FILENAME)
    });

    // Clients discover a system daemon (trust-domain split deployment) when no
    // per-user daemon socket exists. The daemon itself never probes: where it
    // *binds* must not depend on what files happen to exist (its split-mode
    // path comes from the sealed config instead).
    if allow_env_override && !user_candidate.exists() {
        let system = PathBuf::from(SYSTEM_SOCKET_PATH);
        if system.exists() {
            return system;
        }
    }

    user_candidate
}

/// Resolve the socket path (client-side, allows env override).
pub fn socket_path() -> PathBuf {
    socket_path_for_client(true)
}

pub fn ensure_socket_parent_dir(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    std::fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Ensure only the user can access the runtime dir.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

/// Ownership + mode facts about the socket and its parent directory, fed to
/// the pure [`check_socket_facts`] so both trust models are unit-testable
/// (a foreign-uid daemon socket cannot be fabricated in a same-uid test).
#[derive(Debug, Clone, Copy)]
pub struct SocketFacts {
    pub uid: u32,
    pub mode: u32,
    pub is_symlink: bool,
}

/// Decide whether a socket is safe to connect to.
///
/// Two trust models, selected by ownership:
///
/// - **Same-uid daemon** (developer mode): the socket belongs to *us* — it and
///   its directory must be exactly private (0600 / 0700, no exceptions).
/// - **System daemon** (trust-domain split): the socket belongs to a service
///   account. We cannot demand our own uid; instead we demand the split's
///   shape: no world access anywhere, no group *write* on the directory
///   (a group-writable dir would let any group member replace the socket),
///   and directory custody by the daemon account or root. Group *connect*
///   access on the socket itself (0660) is the mechanism that admits clients.
///
/// The caller guards against symlinked path components separately via
/// [`validate_path_chain`]; symlinks at either endpoint fail here too.
pub fn check_socket_facts(
    socket: SocketFacts,
    parent: Option<SocketFacts>,
    my_uid: u32,
) -> Result<(), String> {
    if socket.is_symlink {
        return Err("socket path is a symlink".into());
    }
    if let Some(dir) = &parent
        && dir.is_symlink
    {
        return Err("socket parent directory is a symlink".into());
    }

    if socket.uid == my_uid {
        // Same-uid daemon: exact private modes. A group- or world-accessible
        // socket we ourselves own is not a deployment shape the daemon ever
        // creates in this mode — treat it as tampering. (This also refuses
        // connecting *as* the service account of a split daemon: nothing
        // legitimate drives the CLI from inside the daemon's own trust
        // domain, and the daemon would refuse that peer anyway.)
        let mode = socket.mode & 0o777;
        if mode != 0o600 {
            return Err(format!("socket has mode {mode:o}, expected 0600"));
        }
        if let Some(dir) = parent {
            if dir.uid != my_uid {
                return Err(format!(
                    "parent dir owned by uid {} but expected {my_uid}",
                    dir.uid
                ));
            }
            let dir_mode = dir.mode & 0o777;
            if dir_mode != 0o700 {
                return Err(format!("parent dir has mode {dir_mode:o}, expected 0700"));
            }
        }
        return Ok(());
    }

    // System daemon under another uid: verify the split's shape.
    if socket.mode & 0o007 != 0 {
        return Err(format!(
            "system daemon socket is world-accessible (mode {:o}) — a split deployment \
             must gate connect access by group membership (0660)",
            socket.mode & 0o777
        ));
    }
    let Some(dir) = parent else {
        return Err("system daemon socket has no parent directory to verify".into());
    };
    if dir.uid != socket.uid && dir.uid != 0 {
        return Err(format!(
            "system daemon socket owned by uid {} but its directory by uid {} — \
             the socket directory must belong to the daemon account or root",
            socket.uid, dir.uid
        ));
    }
    if dir.mode & 0o022 != 0 {
        return Err(format!(
            "system daemon socket directory is group- or world-writable (mode {:o}) — \
             a writable directory lets others replace the socket",
            dir.mode & 0o777
        ));
    }
    Ok(())
}

/// Verify that a socket path is safe to connect to (see [`check_socket_facts`]).
#[cfg(unix)]
pub fn verify_socket_safety(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let facts_of = |p: &Path| -> std::io::Result<SocketFacts> {
        let meta = p.symlink_metadata().map_err(|e| {
            std::io::Error::new(e.kind(), format!("cannot stat {}: {e}", p.display()))
        })?;
        Ok(SocketFacts {
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
            is_symlink: meta.file_type().is_symlink(),
        })
    };

    let socket_facts = facts_of(path)?;
    let parent_facts = match path.parent() {
        Some(parent) => Some(facts_of(parent)?),
        None => None,
    };

    let my_uid = unsafe { libc::getuid() };
    check_socket_facts(socket_facts, parent_facts, my_uid).map_err(|msg| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{msg} (socket {})", path.display()),
        )
    })
}

/// Walk each component of a path and verify none are symlinks.
///
/// This prevents TOCTOU symlink attacks on the socket path chain.
#[cfg(unix)]
pub fn validate_path_chain(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        // Skip the root "/" component — it's always a directory, not a symlink.
        if current.as_os_str() == "/" {
            continue;
        }
        // If the component doesn't exist yet (e.g. the socket file before bind),
        // that's fine — we only check existing components.
        match current.symlink_metadata() {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("path component is a symlink: {}", current.display()),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Component doesn't exist yet — acceptable for trailing components.
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env var tests are combined into one function to avoid parallel test races.
    #[test]
    fn socket_path_env_overrides() {
        // When allow_env_override is false, OPAQUE_SOCK should be ignored.
        {
            let _guard = EnvGuard::set("OPAQUE_SOCK", "/tmp/evil.sock");
            let path = socket_path_for_client(false);
            assert_ne!(path, PathBuf::from("/tmp/evil.sock"));
        }

        // When allow_env_override is true, OPAQUE_SOCK should be used.
        {
            let _guard = EnvGuard::set("OPAQUE_SOCK", "/tmp/test.sock");
            let path = socket_path_for_client(true);
            assert_eq!(path, PathBuf::from("/tmp/test.sock"));
        }

        // Relative XDG_RUNTIME_DIR should be rejected.
        {
            let _sock_guard = EnvGuard::remove("OPAQUE_SOCK");
            let _xdg_guard = EnvGuard::set("XDG_RUNTIME_DIR", "relative/path");
            let path = socket_path_for_client(false);
            assert!(!path.starts_with("relative"));
        }

        // XDG_RUNTIME_DIR with parent traversal should be rejected.
        {
            let _sock_guard = EnvGuard::remove("OPAQUE_SOCK");
            let _xdg_guard = EnvGuard::set("XDG_RUNTIME_DIR", "/run/../etc");
            let path = socket_path_for_client(false);
            assert!(!path.starts_with("/run/../etc"));
        }
    }

    fn facts(uid: u32, mode: u32) -> SocketFacts {
        SocketFacts {
            uid,
            mode,
            is_symlink: false,
        }
    }

    const ME: u32 = 1000;
    const DAEMON: u32 = 500;

    #[test]
    fn same_uid_model_requires_exact_private_modes() {
        // Exactly 0600 socket in a 0700 dir: fine.
        assert!(check_socket_facts(facts(ME, 0o600), Some(facts(ME, 0o700)), ME).is_ok());
        // Anything looser on either endpoint is tampering.
        assert!(check_socket_facts(facts(ME, 0o660), Some(facts(ME, 0o700)), ME).is_err());
        assert!(check_socket_facts(facts(ME, 0o600), Some(facts(ME, 0o750)), ME).is_err());
        // Dir owned by someone else while the socket is ours: rejected.
        assert!(check_socket_facts(facts(ME, 0o600), Some(facts(DAEMON, 0o700)), ME).is_err());
    }

    #[test]
    fn system_daemon_model_accepts_the_split_shape() {
        // Daemon-owned socket 0660 in a daemon-owned 0750 dir.
        assert!(check_socket_facts(facts(DAEMON, 0o660), Some(facts(DAEMON, 0o750)), ME).is_ok());
        // Root-owned runtime dir (pre-created /run/opaque) is also fine.
        assert!(check_socket_facts(facts(DAEMON, 0o660), Some(facts(0, 0o755)), ME).is_ok());
    }

    #[test]
    fn system_daemon_model_rejects_world_access_and_writable_dirs() {
        // World-connectable socket: the group gate is missing.
        assert!(check_socket_facts(facts(DAEMON, 0o666), Some(facts(DAEMON, 0o750)), ME).is_err());
        assert!(check_socket_facts(facts(DAEMON, 0o662), Some(facts(DAEMON, 0o750)), ME).is_err());
        // Group- or world-writable dir: anyone could swap the socket out.
        assert!(check_socket_facts(facts(DAEMON, 0o660), Some(facts(DAEMON, 0o770)), ME).is_err());
        assert!(check_socket_facts(facts(DAEMON, 0o660), Some(facts(DAEMON, 0o757)), ME).is_err());
        // Dir owned by a third uid (neither daemon nor root): custody unclear.
        assert!(check_socket_facts(facts(DAEMON, 0o660), Some(facts(1234, 0o750)), ME).is_err());
        // No parent at all for a foreign socket: nothing vouches for it.
        assert!(check_socket_facts(facts(DAEMON, 0o660), None, ME).is_err());
    }

    #[test]
    fn symlinks_fail_both_models() {
        let link = SocketFacts {
            uid: ME,
            mode: 0o600,
            is_symlink: true,
        };
        assert!(check_socket_facts(link, Some(facts(ME, 0o700)), ME).is_err());
        let dir_link = SocketFacts {
            uid: DAEMON,
            mode: 0o750,
            is_symlink: true,
        };
        assert!(check_socket_facts(facts(DAEMON, 0o660), Some(dir_link), ME).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn verify_socket_safety_rejects_symlink() {
        use std::os::unix::fs;
        let dir = tempdir();
        let real_file = dir.join("real.sock");
        std::fs::write(&real_file, b"").unwrap();
        let link = dir.join("link.sock");
        fs::symlink(&real_file, &link).unwrap();
        let result = verify_socket_safety(&link);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn verify_socket_safety_rejects_wrong_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let sock = dir.join("test.sock");
        std::fs::write(&sock, b"").unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = verify_socket_safety(&sock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mode"));
    }

    #[cfg(unix)]
    #[test]
    fn verify_socket_safety_rejects_0755() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let sock = dir.join("test755.sock");
        std::fs::write(&sock, b"").unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = verify_socket_safety(&sock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mode"));
    }

    #[cfg(unix)]
    #[test]
    fn verify_socket_safety_rejects_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let sock = dir.join("test700.sock");
        std::fs::write(&sock, b"").unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = verify_socket_safety(&sock);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mode"));
    }

    #[cfg(unix)]
    #[test]
    fn verify_socket_safety_accepts_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let sock = dir.join("test600.sock");
        std::fs::write(&sock, b"").unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = verify_socket_safety(&sock);
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn validate_path_chain_rejects_symlink() {
        use std::os::unix::fs;
        let dir = tempdir();
        let real_dir = dir.join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link_dir = dir.join("link");
        fs::symlink(&real_dir, &link_dir).unwrap();
        let sock_path = link_dir.join("opaqued.sock");
        let result = validate_path_chain(&sock_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_path_chain_accepts_normal_path() {
        let dir = tempdir();
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let result = validate_path_chain(&sub);
        assert!(result.is_ok());
    }

    // -- Test helpers --

    /// RAII guard for temporarily setting/unsetting an env var.
    struct EnvGuard {
        key: String,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: Tests are run single-threaded for env var tests.
            unsafe { std::env::set_var(key, value) };
            Self {
                key: key.to_string(),
                prev,
            }
        }

        fn remove(key: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: Tests are run single-threaded for env var tests.
            unsafe { std::env::remove_var(key) };
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                // SAFETY: Tests are run single-threaded for env var tests.
                Some(v) => unsafe { std::env::set_var(&self.key, v) },
                None => unsafe { std::env::remove_var(&self.key) },
            }
        }
    }

    /// Create a temporary directory that is cleaned up on drop.
    /// Uses canonicalize to resolve symlinks (e.g. macOS /var -> /private/var).
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base.join(format!("opaque-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }
}
