//! A held descriptor serializes native ceremonies within one trusted custody.
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

pub struct ReviewLock(File);
impl ReviewLock {
    pub fn acquire(directory: &Path) -> Result<Self, String> {
        let directory = crate::custody::validate_directory(directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("review.lock"))
            .map_err(|_| "review lock unavailable")?;
        let m = file.metadata().map_err(|_| "review lock unavailable")?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err("review lock requires an owned private regular file".into());
        }
        // The descriptor remains alive through display, authentication and receipt recovery.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                "a review is already active for this enrollment; return to its window".into(),
            );
        }
        Ok(Self(file))
    }
}
impl Drop for ReviewLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_one_ceremony_and_symlinks_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        crate::custody::initialize(&state, "Fixture").unwrap();
        let first = ReviewLock::acquire(&state).unwrap();
        assert!(ReviewLock::acquire(&state).is_err());
        drop(first);
        assert!(ReviewLock::acquire(&state).is_ok());
        std::fs::remove_file(state.join("review.lock")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("other"), state.join("review.lock")).unwrap();
        assert!(ReviewLock::acquire(&state).is_err());
    }
}
