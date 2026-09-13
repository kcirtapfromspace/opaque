//! First listener-bound workload attestor, alongside the legacy Unix identity.
//!
//! The Unix listener installs this binding after privilege drop. Neither the
//! binding nor its inputs are selected from a request. The trusted workload
//! context travels with the client into policy and approval bindings. macOS
//! signing teams are validated against the connected process's audit token;
//! this software identity does not imply hardware attestation.

use std::path::PathBuf;

use opaque_core::operation::ClientIdentity;
use opaque_core::peer::PeerInfo;
use opaque_core::workload::{AttestationStrength, AttestorId, Selector, WorkloadIdentity};

#[cfg(target_os = "macos")]
#[path = "workload_attest_macos.rs"]
mod macos;

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
                codesign_team_id: signing_team_for_peer(info),
                workload: None,
            }
        }
        None => ClientIdentity {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        },
    }
}

fn signing_team_for_peer(peer: &PeerInfo) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        // audit_token_t layout from bsm/libbsm.h: euid, egid and pid are
        // fields 1, 2 and 5. Reject inconsistent observations before native API.
        let token = peer.audit_token.as_ref()?;
        if token[1] != peer.uid || token[2] != peer.gid || peer.pid != Some(token[5] as i32) {
            return None;
        }
        macos::validated_team_id(token)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = peer;
        None
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
        if let Some(team) = &client.codesign_team_id {
            observe("codesign_team_id", team)?;
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
        let mut conn = ConnectionContext {
            client: build_client_identity(peer),
        };
        match self.attestor.attest(&conn) {
            Ok(identity) if identity.is_attested() => {
                conn.client.workload = Some(identity.clone());
                (conn.client, identity)
            }
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
            workload: None,
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
            audit_token: None,
        };
        let (legacy, identity) = listener.attest(Some(&peer));
        assert_eq!(legacy.uid, u32::MAX);
        assert_eq!(identity.strength, AttestationStrength::None);
        assert!(identity.selectors.is_empty());
    }

    #[test]
    fn native_listener_observations_survive_cloning_into_policy() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::{UnixListener, UnixStream};
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("attestation.sock");
        let server = UnixListener::bind(&socket).unwrap();
        let _client = UnixStream::connect(&socket).unwrap();
        let (connection, _) = server.accept().unwrap();
        let peer = opaque_core::peer::peer_info_from_fd(connection.as_raw_fd()).unwrap();
        assert_eq!(peer.uid, unsafe { libc::geteuid() });
        #[cfg(target_os = "macos")]
        {
            let token = peer.audit_token.expect("kernel audit token");
            assert_eq!(token[1], peer.uid);
            assert_eq!(token[2], peer.gid);
            assert_eq!(Some(token[5] as i32), peer.pid);
        }
        let (client, workload) = ListenerAttestor::unix_listener().attest(Some(&peer));
        assert_eq!(client.workload.as_ref(), Some(&workload));
        let cloned = client.clone();
        let policy: opaque_core::policy::ClientMatch = serde_json::from_value(serde_json::json!({
            "attestor": "peercred",
            "min_attestation": "weak",
            "selectors": [format!("peercred:uid:{}", peer.uid)]
        }))
        .unwrap();
        assert!(policy.matches(&cloned));
    }

    #[test]
    fn validated_software_team_is_a_selector_without_strength_promotion() {
        let attestor = PeercredAttestor {
            daemon_effective_uid: 501,
        };
        let mut legacy = client(501);
        legacy.codesign_team_id = Some("TEAM123".into());
        let workload = attestor
            .attest(&ConnectionContext { client: legacy })
            .unwrap();
        assert!(
            workload
                .selectors
                .contains(&"peercred:codesign_team_id:TEAM123".parse().unwrap())
        );
        assert_eq!(workload.strength, AttestationStrength::Weak);
    }

    #[test]
    fn missing_or_mismatched_audit_token_never_yields_a_signing_team() {
        let mut peer = PeerInfo {
            uid: 501,
            gid: 20,
            pid: Some(std::process::id() as i32),
            audit_token: None,
        };
        assert!(signing_team_for_peer(&peer).is_none());
        peer.audit_token = Some([u32::MAX; 8]);
        assert!(signing_team_for_peer(&peer).is_none());
    }

    /// Uses installed runtimes only; never signs code or launches a GUI app.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires explicit signed and ad-hoc Node executables and expected Team ID"]
    fn live_signed_and_adhoc_child_socket_attestation() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixListener;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let signed = std::env::var("OPAQUE_TEST_SIGNED_NODE")
            .expect("set OPAQUE_TEST_SIGNED_NODE to a trusted signed Node executable");
        let adhoc = std::env::var("OPAQUE_TEST_ADHOC_NODE")
            .expect("set OPAQUE_TEST_ADHOC_NODE to an ad-hoc Node executable");
        let expected_team = std::env::var("OPAQUE_TEST_SIGNED_TEAM_ID")
            .expect("set OPAQUE_TEST_SIGNED_TEAM_ID to the independently verified Team ID");
        assert!(!expected_team.is_empty());
        let script = "const s=require('net').createConnection(process.argv[1]); s.on('error',()=>process.exit(2)); setTimeout(()=>process.exit(3),15000).unref();";
        for (runtime, team) in [(signed, Some(expected_team)), (adhoc, None)] {
            assert!(std::path::Path::new(&runtime).is_absolute());
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("child.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut child = ChildGuard(
                Command::new(runtime)
                    .args(["-e", script])
                    .arg(&socket)
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("could not start configured Node runtime"),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            let connection = loop {
                match listener.accept() {
                    Ok((connection, _)) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            child.0.try_wait().unwrap().is_none(),
                            "child exited before connecting"
                        );
                        assert!(Instant::now() < deadline, "child connection timed out");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("child connection failed: {error}"),
                }
            };
            let peer = opaque_core::peer::peer_info_from_fd(connection.as_raw_fd()).unwrap();
            assert_eq!(peer.pid, Some(child.0.id() as i32));
            let (client, workload) = ListenerAttestor::unix_listener().attest(Some(&peer));
            assert_eq!(client.codesign_team_id, team);
            assert_eq!(workload.strength, AttestationStrength::Weak);
            assert_eq!(client.workload.as_ref(), Some(&workload));
            if let Some(team) = team {
                let policy = opaque_core::policy::ClientMatch {
                    codesign_team_id: Some(team.clone()),
                    selectors: vec![Selector::new("peercred", "codesign_team_id", &team).unwrap()],
                    min_attestation: Some(AttestationStrength::Weak),
                    ..Default::default()
                };
                assert!(policy.matches(&client));
                let mut wrong_incarnation = peer.audit_token.expect("kernel audit token");
                wrong_incarnation[7] = wrong_incarnation[7].wrapping_add(1);
                assert!(macos::validated_team_id(&wrong_incarnation).is_none());
            } else {
                assert!(
                    !workload
                        .selectors
                        .iter()
                        .any(|selector| selector.key() == "codesign_team_id")
                );
            }
        }
    }

    #[test]
    fn production_adapter_retains_legacy_matching() {
        let listener = ListenerAttestor::unix_listener();
        let peer = PeerInfo {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            pid: Some(std::process::id() as i32),
            audit_token: None,
        };
        let before = super::build_client_identity(Some(&peer));
        let (after, identity) = listener.attest(Some(&peer));
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        assert_eq!(identity.strength, AttestationStrength::Weak);
        assert_eq!(after.workload.as_ref(), Some(&identity));
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
