pub mod audit;
pub mod operation;
pub mod peer;
pub mod policy;
pub mod proto;
pub mod sanitize;
pub mod socket;
pub mod validate;

pub const API_VERSION: u32 = 1;

/// Maximum IPC frame size in bytes (128 KB).
///
/// Both daemon and CLI must agree on this limit. Using a shared constant
/// prevents frame-size mismatches that could cause silent truncation or
/// connection resets.
pub const MAX_FRAME_LENGTH: usize = 128 * 1024;
