use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const DEFAULT_SOCKET_FILENAME: &str = "agentpassd.sock";

/// Resolve the socket path, optionally allowing the `AGENTPASS_SOCK` env override.
///
/// The daemon should call `socket_path_for_client(false)` to ignore the env
/// var (prevents an attacker from redirecting via environment). The CLI uses
/// `socket_path()` which delegates to `socket_path_for_client(true)`.
pub fn socket_path_for_client(allow_env_override: bool) -> PathBuf {
    if allow_env_override && let Ok(p) = std::env::var("AGENTPASS_SOCK") {
        return PathBuf::from(p);
    }

    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        let dir_path = Path::new(&dir);
        // Reject non-absolute or paths with `..` components.
        if dir_path.is_absolute()
            && !dir_path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return dir_path.join("agentpass").join(DEFAULT_SOCKET_FILENAME);
        }
    }

    let home = std::env::var_os("HOME").unwrap_or_else(|| OsString::from("."));
    PathBuf::from(home)
        .join(".agentpass")
        .join("run")
        .join(DEFAULT_SOCKET_FILENAME)
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

/// Verify that a socket path is safe to connect to.
///
/// Checks:
/// - The socket file exists and is not a symlink
/// - The socket file is owned by the current user with mode 0600
/// - The parent directory is not a symlink and is owned by the current user with mode 0700
#[cfg(unix)]
pub fn verify_socket_safety(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let my_uid = unsafe { libc::getuid() };

    // lstat the socket file — reject symlinks.
    let meta = path.symlink_metadata().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("cannot stat socket {}: {e}", path.display()),
        )
    })?;

    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("socket path is a symlink: {}", path.display()),
        ));
    }

    if meta.uid() != my_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("socket owned by uid {} but expected {}", meta.uid(), my_uid),
        ));
    }

    let mode = meta.mode() & 0o777;
    if mode != 0o600 && mode != 0o755 && mode != 0o700 {
        // Allow common socket modes: 0600 is preferred, also accept 0755/0700
        // since some systems set different modes on socket files.
        // Be strict: only accept 0600.
        if mode != 0o600 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("socket has mode {:o}, expected 0600", mode),
            ));
        }
    }

    // Check parent directory.
    if let Some(parent) = path.parent() {
        let parent_meta = parent.symlink_metadata().map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("cannot stat parent dir {}: {e}", parent.display()),
            )
        })?;

        if parent_meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("parent directory is a symlink: {}", parent.display()),
            ));
        }

        if parent_meta.uid() != my_uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "parent dir owned by uid {} but expected {}",
                    parent_meta.uid(),
                    my_uid
                ),
            ));
        }

        let parent_mode = parent_meta.mode() & 0o777;
        if parent_mode != 0o700 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("parent dir has mode {:o}, expected 0700", parent_mode),
            ));
        }
    }

    Ok(())
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
        // When allow_env_override is false, AGENTPASS_SOCK should be ignored.
        {
            let _guard = EnvGuard::set("AGENTPASS_SOCK", "/tmp/evil.sock");
            let path = socket_path_for_client(false);
            assert_ne!(path, PathBuf::from("/tmp/evil.sock"));
        }

        // When allow_env_override is true, AGENTPASS_SOCK should be used.
        {
            let _guard = EnvGuard::set("AGENTPASS_SOCK", "/tmp/test.sock");
            let path = socket_path_for_client(true);
            assert_eq!(path, PathBuf::from("/tmp/test.sock"));
        }

        // Relative XDG_RUNTIME_DIR should be rejected.
        {
            let _sock_guard = EnvGuard::remove("AGENTPASS_SOCK");
            let _xdg_guard = EnvGuard::set("XDG_RUNTIME_DIR", "relative/path");
            let path = socket_path_for_client(false);
            assert!(!path.starts_with("relative"));
        }

        // XDG_RUNTIME_DIR with parent traversal should be rejected.
        {
            let _sock_guard = EnvGuard::remove("AGENTPASS_SOCK");
            let _xdg_guard = EnvGuard::set("XDG_RUNTIME_DIR", "/run/../etc");
            let path = socket_path_for_client(false);
            assert!(!path.starts_with("/run/../etc"));
        }
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
    fn validate_path_chain_rejects_symlink() {
        use std::os::unix::fs;
        let dir = tempdir();
        let real_dir = dir.join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link_dir = dir.join("link");
        fs::symlink(&real_dir, &link_dir).unwrap();
        let sock_path = link_dir.join("agentpassd.sock");
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
        let dir = base.join(format!("agentpass-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }
}
