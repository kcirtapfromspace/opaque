//! First listener-bound workload attestor, alongside the legacy Unix identity.
//!
//! The Unix listener installs this binding after privilege drop. Neither the
//! binding nor its inputs are selected from a request. Policy selectors,
//! strength floors and selector-based lease fingerprints are separate work;
//! this adapter deliberately preserves the legacy client construction path.

use std::path::PathBuf;

use opaque_core::operation::ClientIdentity;
use opaque_core::peer::PeerInfo;
use opaque_core::workload::{AttestationStrength, AttestorId, Selector, WorkloadIdentity};

/// Compute the SHA-256 hash of an executable file (hex-encoded).
fn compute_exe_hash(path: &std::path::Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let hash = Sha256::digest(&bytes);
    Some(format!("{hash:x}"))
}

/// Build a [`ClientIdentity`] from peer credentials obtained via the Unix socket.
fn build_client_identity(peer: Option<&PeerInfo>) -> ClientIdentity {
    match peer {
        Some(info) => {
            let exe_path = info.pid.and_then(exe_path_for_pid);
            let exe_sha256 = exe_path.as_ref().and_then(|p| compute_exe_hash(p));
            ClientIdentity {
                uid: info.uid,
                gid: info.gid,
                pid: info.pid,
                exe_path,
                exe_sha256,
                codesign_team_id: None,
            }
        }
        None => ClientIdentity {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        },
    }
}

/// Resolve the executable path for a given PID.
fn exe_path_for_pid(pid: i32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    #[cfg(target_os = "macos")]
    {
        exe_path_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn exe_path_macos(pid: i32) -> Option<PathBuf> {
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

    unsafe extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_char,
            buffersize: u32,
        ) -> libc::c_int;
    }

    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        proc_pidpath(
            pid,
            buf.as_mut_ptr() as *mut libc::c_char,
            PROC_PIDPATHINFO_MAXSIZE,
        )
    };
    if ret > 0 {
        let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        cstr.to_str().ok().map(PathBuf::from)
    } else {
        None
    }
}

/// Server-observed credentials. Construction is private to the listener adapter.
struct ConnectionContext {
    client: ClientIdentity,
}

#[derive(Debug, thiserror::Error)]
enum AttestError {
    #[error("peer credentials unavailable")]
    Unavailable,
    #[error("invalid peer credential observation")]
    InvalidObservation,
}

trait WorkloadAttestor: Send + Sync {
    fn id(&self) -> AttestorId;
    fn attest(&self, conn: &ConnectionContext) -> Result<WorkloadIdentity, AttestError>;
}

struct PeercredAttestor {
    daemon_effective_uid: u32,
}

impl WorkloadAttestor for PeercredAttestor {
    fn id(&self) -> AttestorId {
        "peercred"
            .to_owned()
            .try_into()
            .expect("static attestor id")
    }

    fn attest(&self, conn: &ConnectionContext) -> Result<WorkloadIdentity, AttestError> {
        let client = &conn.client;
        if client.uid == u32::MAX || client.gid == u32::MAX {
            return Err(AttestError::Unavailable);
        }
        let mut selectors = std::collections::BTreeSet::new();
        let mut observe = |key, value: &str| -> Result<(), AttestError> {
            let selector = Selector::new("peercred", key, value)
                .map_err(|_| AttestError::InvalidObservation)?;
            selectors.insert(selector);
            Ok(())
        };
        observe("uid", &client.uid.to_string())?;
        observe("gid", &client.gid.to_string())?;
        if let Some(path) = &client.exe_path {
            observe("exe_path", &path.to_string_lossy())?;
        }
        if let Some(hash) = &client.exe_sha256 {
            observe("exe_sha256", hash)?;
        }
        Ok(WorkloadIdentity {
            selectors,
            strength: if client.uid == self.daemon_effective_uid {
                AttestationStrength::Weak
            } else {
                AttestationStrength::Medium
            },
            source: self.id(),
        })
    }
}

/// Immutable attestor choice for the daemon's single Unix listener.
/// A multi-listener registry is intentionally not introduced in this slice.
pub struct ListenerAttestor {
    daemon_effective_uid: u32,
    attestor: Box<dyn WorkloadAttestor>,
}

impl ListenerAttestor {
    pub fn unix_listener() -> Self {
        // Resolved once at startup, after run_as has dropped privileges.
        let daemon_effective_uid = unsafe { libc::geteuid() };
        Self {
            daemon_effective_uid,
            attestor: Box::new(PeercredAttestor {
                daemon_effective_uid,
            }),
        }
    }

    pub fn daemon_effective_uid(&self) -> u32 {
        self.daemon_effective_uid
    }

    pub fn attest(&self, peer: Option<&PeerInfo>) -> (ClientIdentity, WorkloadIdentity) {
        let conn = ConnectionContext {
            client: build_client_identity(peer),
        };
        match self.attestor.attest(&conn) {
            Ok(identity) if identity.is_attested() => (conn.client, identity),
            // No partial canonical or legacy identity survives an error.
            _ => (
                build_client_identity(None),
                WorkloadIdentity::unavailable(self.attestor.id()),
            ),
        }
    }
}

/// Identity claims are reserved in transport and method envelopes. Presence
/// is rejected even when null; none of their values are ever audited.
pub fn has_identity_claim(value: &serde_json::Value) -> bool {
    const RESERVED: &[&str] = &[
        "attestor",
        "attestor_id",
        "substrate",
        "strength",
        "attestation_strength",
        "selectors",
        "workload_identity",
        "client_identity",
        "workload",
        "attestation",
    ];
    let has_reserved = |value: &serde_json::Value| {
        value
            .as_object()
            .is_some_and(|object| RESERVED.iter().any(|name| object.contains_key(*name)))
    };
    has_reserved(value) || value.get("params").is_some_and(has_reserved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(uid: u32) -> ClientIdentity {
        ClientIdentity {
            uid,
            gid: 20,
            pid: Some(42),
            exe_path: Some("/opt/client:stable".into()),
            exe_sha256: Some("a1b2".into()),
            codesign_team_id: None,
        }
    }

    #[test]
    fn peercred_emits_observed_selectors_and_uid_dependent_strength() {
        let attestor = PeercredAttestor {
            daemon_effective_uid: 501,
        };
        for (uid, expected) in [
            (501, AttestationStrength::Weak),
            (502, AttestationStrength::Medium),
        ] {
            let identity = attestor
                .attest(&ConnectionContext {
                    client: client(uid),
                })
                .unwrap();
            assert_eq!(identity.source.as_str(), "peercred");
            assert_eq!(identity.strength, expected);
            assert_eq!(identity.selectors.len(), 4);
            for selector in [
                format!("peercred:uid:{uid}"),
                "peercred:gid:20".into(),
                "peercred:exe_path:/opt/client:stable".into(),
                "peercred:exe_sha256:a1b2".into(),
            ] {
                assert!(identity.selectors.contains(&selector.parse().unwrap()));
            }
            assert!(identity.selectors.iter().all(|s| s.key() != "pid"));
        }
    }

    #[test]
    fn missing_executable_does_not_invent_selectors_or_strength() {
        let attestor = PeercredAttestor {
            daemon_effective_uid: 501,
        };
        let mut legacy = client(501);
        legacy.exe_path = None;
        legacy.exe_sha256 = None;
        let identity = attestor
            .attest(&ConnectionContext { client: legacy })
            .unwrap();
        assert_eq!(identity.selectors.len(), 2);
        assert_eq!(identity.strength, AttestationStrength::Weak);
    }

    #[test]
    fn listener_failure_drops_every_observation() {
        let listener = ListenerAttestor::unix_listener();
        let (legacy, identity) = listener.attest(None);
        assert_eq!(legacy.uid, u32::MAX);
        assert!(legacy.exe_path.is_none());
        assert_eq!(identity.strength, AttestationStrength::None);
        assert!(identity.selectors.is_empty());
        assert!(!identity.is_attested());
        let peer = PeerInfo {
            uid: 501,
            gid: u32::MAX,
            pid: None,
        };
        let (legacy, identity) = listener.attest(Some(&peer));
        assert_eq!(legacy.uid, u32::MAX);
        assert_eq!(identity.strength, AttestationStrength::None);
        assert!(identity.selectors.is_empty());
    }

    #[test]
    fn production_adapter_retains_legacy_matching() {
        let listener = ListenerAttestor::unix_listener();
        let peer = PeerInfo {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            pid: Some(std::process::id() as i32),
        };
        let before = super::build_client_identity(Some(&peer));
        let (after, identity) = listener.attest(Some(&peer));
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        assert_eq!(identity.strength, AttestationStrength::Weak);
        for pattern in ["*", "/opt/*", "/Applications/Claude Code*", "**/deps/*"] {
            let matcher = opaque_core::policy::ClientMatch {
                exe_path: Some(pattern.into()),
                ..Default::default()
            };
            assert_eq!(matcher.matches(&before), matcher.matches(&after));
        }
        assert!(after.codesign_team_id.is_none());
    }

    #[test]
    fn identity_claims_cannot_select_or_strengthen_an_attestor() {
        for field in [
            "attestor",
            "attestor_id",
            "substrate",
            "strength",
            "attestation_strength",
            "selectors",
            "workload_identity",
            "client_identity",
            "workload",
            "attestation",
        ] {
            assert!(has_identity_claim(&serde_json::json!({field: null})));
            assert!(has_identity_claim(
                &serde_json::json!({"params": {field: "strong"}})
            ));
        }
        assert!(!has_identity_claim(
            &serde_json::json!({"id": 1, "method": "ping", "params": null})
        ));
    }

    #[test]
    fn compute_exe_hash_nonexistent_none() {
        assert!(compute_exe_hash(std::path::Path::new("/nonexistent/binary")).is_none());
    }

    #[test]
    fn compute_exe_hash_valid_file() {
        // Hash the current test binary — always exists during test execution.
        let exe = std::env::current_exe().expect("current_exe should succeed in tests");
        let hash = compute_exe_hash(&exe);
        assert!(hash.is_some(), "hashing current binary should succeed");
        let h = hash.unwrap();
        // SHA-256 hex digest is always 64 characters.
        assert_eq!(h.len(), 64, "expected 64-char hex digest, got {}", h.len());
        // Should be lowercase hex.
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
