//! First listener-bound workload attestor, alongside the legacy Unix identity.
//!
//! The Unix listener installs this binding after privilege drop. Neither the
//! binding nor its inputs are selected from a request. Policy selectors,
//! strength floors and selector-based lease fingerprints are separate work;
//! this adapter deliberately preserves the legacy client construction path.

use opaque_core::operation::ClientIdentity;
use opaque_core::peer::PeerInfo;
use opaque_core::workload::{AttestationStrength, AttestorId, Selector, WorkloadIdentity};

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
pub(super) struct ListenerAttestor {
    daemon_effective_uid: u32,
    attestor: Box<dyn WorkloadAttestor>,
}

impl ListenerAttestor {
    pub(super) fn unix_listener() -> Self {
        // Resolved once at startup, after run_as has dropped privileges.
        let daemon_effective_uid = unsafe { libc::geteuid() };
        Self {
            daemon_effective_uid,
            attestor: Box::new(PeercredAttestor {
                daemon_effective_uid,
            }),
        }
    }

    pub(super) fn daemon_effective_uid(&self) -> u32 {
        self.daemon_effective_uid
    }

    pub(super) fn attest(&self, peer: Option<&PeerInfo>) -> (ClientIdentity, WorkloadIdentity) {
        let conn = ConnectionContext {
            client: super::build_client_identity(peer),
        };
        match self.attestor.attest(&conn) {
            Ok(identity) if identity.is_attested() => (conn.client, identity),
            // No partial canonical or legacy identity survives an error.
            _ => (
                super::build_client_identity(None),
                WorkloadIdentity::unavailable(self.attestor.id()),
            ),
        }
    }
}

/// Identity claims are reserved in transport and method envelopes. Presence
/// is rejected even when null; none of their values are ever audited.
pub(super) fn has_identity_claim(value: &serde_json::Value) -> bool {
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
        let before = super::super::build_client_identity(Some(&peer));
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
}
