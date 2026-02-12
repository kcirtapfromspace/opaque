use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const DEFAULT_SOCKET_FILENAME: &str = "agentpassd.sock";

pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENTPASS_SOCK") {
        return PathBuf::from(p);
    }

    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir)
            .join("agentpass")
            .join(DEFAULT_SOCKET_FILENAME);
    }

    let home = std::env::var_os("HOME").unwrap_or_else(|| OsString::from("."));
    PathBuf::from(home)
        .join(".agentpass")
        .join("run")
        .join(DEFAULT_SOCKET_FILENAME)
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
