//! Opaque notifications for independently implemented transports.
//! Neither this feed nor its dedicated read credential can fetch review text,
//! submit a decision, or authorize work. Polling is idempotent and does not
//! consume an approval or track transport delivery; adapters own that state.
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalNotice {
    pub approval_id: String,
    pub broker_id: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingNoticeFeed {
    pub schema_version: u32,
    pub broker_id: String,
    pub notices: Vec<ApprovalNotice>,
}

pub(crate) fn token_hash(path: &Path) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha256};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "notice credential unavailable")?;
    let meta = file
        .metadata()
        .map_err(|_| "notice credential unavailable")?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() > 128
    {
        return Err("notice credential requires a bounded owned private regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| "notice credential unavailable")?;
    if !(32..=128).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(byte))
    {
        return Err("notice credential must contain 32..128 URL-safe bytes".into());
    }
    Ok(Sha256::digest(bytes).into())
}
