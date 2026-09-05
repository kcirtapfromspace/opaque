pub mod attest;
pub mod audit;
pub mod bundle;
pub mod execve_map;
pub mod identity;
pub mod inference;
pub mod keyfile;
pub mod operation;
pub mod peer;
pub mod policy;
pub mod profile;
pub mod proto;
pub mod release;
pub mod sanitize;
pub mod seal;
pub mod socket;
pub mod task;
pub mod tenant;
pub mod trust_domain;
pub mod validate;
pub mod workstation;

pub const API_VERSION: u32 = 1;

/// Maximum IPC frame size in bytes (128 KB).
///
/// Both daemon and CLI must agree on this limit. Using a shared constant
/// prevents frame-size mismatches that could cause silent truncation or
/// connection resets.
pub const MAX_FRAME_LENGTH: usize = 128 * 1024;
