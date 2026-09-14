//! Existing provider-neutral reporter against synthetic loopback protocol peers.
//! These tests use real SQLite metadata and signed software attestations; no enterprise collector.
use std::{os::unix::fs::PermissionsExt, sync::Arc};

use ed25519_dalek::SigningKey;
use opaque_core::{
    audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink},
    tenant::{TenantBinding, TenantId},
};
use opaque_federation_runtime::{
    attest::AttestationService,
    federation::FederationStatus,
    fleet::{
        Acknowledgment, Challenge, ExportEntry, Heartbeat, MAX_EXPORT_BATCH,
        reporter::{Reporter, ReporterConfig},
        verify_heartbeat,
    },
};
use sha2::{Digest, Sha256};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const TOKEN: &str = "fixture_reporter_token_01234567890123456789";

struct Rig {
    home: tempfile::TempDir,
    binding: TenantBinding,
    attestor: Arc<AttestationService>,
    key: SigningKey,
}
impl Rig {
    fn new(events: usize) -> Self {
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join(".opaque");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, value) in [("config.toml", ""), ("reporter.token", TOKEN)] {
            std::fs::write(state.join(name), value).unwrap();
            std::fs::set_permissions(state.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let sink = SqliteAuditSink::new(state.join("audit.db"), 90).unwrap();
        for _ in 0..events {
            sink.emit(
                AuditEvent::new(AuditEventKind::RequestReceived)
                    .with_operation("private-operation-must-not-be-exported"),
            );
        }
        drop(sink);
        let key = SigningKey::from_bytes(&[61; 32]);
        let attestor = Arc::new(AttestationService::new(
            key.clone(),
            home.path().to_owned(),
            state.join("config.toml"),
            state.join("audit.db"),
            "reporter-protocol-fixture".into(),
            true,
            vec![],
            Arc::new(FederationStatus::default()),
        ));
        let binding = TenantBinding::new(
            TenantId::parse("fixture").unwrap(),
            "00000000-0000-4000-8000-000000000061".parse().unwrap(),
        )
        .unwrap();
        Self {
            home,
            binding,
            attestor,
            key,
        }
    }
    fn state(&self) -> std::path::PathBuf {
        self.home.path().join(".opaque")
    }
    fn config(&self, url: &str) -> ReporterConfig {
        ReporterConfig {
            collector_url: url.into(),
            token_file: self.state().join("reporter.token"),
            interval_secs: 1,
        }
    }
    fn reporter(&self, url: &str) -> Reporter {
        Reporter::new(
            self.config(url),
            self.binding.clone(),
            self.attestor.clone(),
            &self.state(),
        )
        .unwrap()
    }
    fn challenge(&self, after: Option<u64>) -> Challenge {
        Challenge {
            binding: self.binding.clone(),
            epoch: 7,
            nonce: "a".repeat(32),
            expires_at: opaque_core::identity::now_unix() + 60,
            acknowledged_sequence: after,
        }
    }
    fn route(&self, suffix: &str) -> String {
        format!(
            "/v1/tenants/{}/brokers/{}/{suffix}",
            self.binding.tenant_id, self.binding.broker_id
        )
    }
    fn entries(&self, after: u64) -> Vec<ExportEntry> {
        let db = rusqlite::Connection::open(self.state().join("audit.db")).unwrap();
        let mut query = db
            .prepare("SELECT sequence_number,event_id,record_hash FROM audit_events ORDER BY rowid")
            .unwrap();
        query
            .query_map([], |row| {
                Ok(ExportEntry {
                    sequence: row.get(0)?,
                    event_id: row.get(1)?,
                    record_hash: row.get(2)?,
                })
            })
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.sequence > after)
            .take(MAX_EXPORT_BATCH)
            .collect()
    }
    async fn mount_challenge(&self, server: &MockServer, challenge: &Challenge) {
        Mock::given(method("POST"))
            .and(path(self.route("challenge")))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(challenge))
            .expect(1)
            .mount(server)
            .await;
    }
    fn ack(&self, challenge: &Challenge, entries: &[ExportEntry], health: &str) -> Acknowledgment {
        Acknowledgment {
            binding: self.binding.clone(),
            epoch: challenge.epoch,
            received_at: opaque_core::identity::now_unix(),
            acknowledged_sequence: if health == "ok" {
                entries
                    .last()
                    .map(|e| e.sequence)
                    .or(challenge.acknowledged_sequence)
            } else {
                challenge.acknowledged_sequence
            },
            receipt_digest: Some(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(entries).unwrap())
            )),
            evidence_health: health.into(),
        }
    }
}

#[test]
fn reporter_configuration_rejects_each_endpoint_and_credential_authority_mutation() {
    let rig = Rig::new(0);
    for url in [
        "not-a-url",
        "ftp://127.0.0.1/",
        "http://remote.example/",
        "https://user@collector.example/",
        "https://:pass@collector.example/",
        "https://collector.example/?query",
        "https://collector.example/#fragment",
        "https://collector.example/nested",
    ] {
        assert!(
            Reporter::new(
                rig.config(url),
                rig.binding.clone(),
                rig.attestor.clone(),
                &rig.state()
            )
            .is_err(),
            "{url}"
        );
    }
    for interval_secs in [0, 3601] {
        let mut config = rig.config("https://collector.example/");
        config.interval_secs = interval_secs;
        assert_eq!(
            Reporter::new(
                config,
                rig.binding.clone(),
                rig.attestor.clone(),
                &rig.state()
            )
            .err()
            .unwrap(),
            "collector requires HTTPS root URL, or explicit loopback HTTP, and interval 1..3600"
        );
    }
    let mut config = rig.config("https://collector.example/");
    config.token_file = rig.home.path().join("foreign.token");
    assert_eq!(
        Reporter::new(
            config,
            rig.binding.clone(),
            rig.attestor.clone(),
            &rig.state()
        )
        .err()
        .unwrap(),
        "fleet reporting credential must be directly inside broker custody"
    );
    for token in [
        vec![b'a'; 31],
        vec![b'a'; 129],
        vec![b'!'; 32],
        vec![255; 32],
    ] {
        std::fs::write(rig.state().join("reporter.token"), token).unwrap();
        assert_eq!(
            Reporter::new(
                rig.config("https://collector.example/"),
                rig.binding.clone(),
                rig.attestor.clone(),
                &rig.state()
            )
            .err()
            .unwrap(),
            "invalid reporter credential"
        );
    }
    for len in [32, 128] {
        std::fs::write(
            rig.state().join("reporter.token"),
            &"a_-0Z".repeat(26).as_bytes()[..len],
        )
        .unwrap();
        assert!(
            Reporter::new(
                rig.config("https://collector.example/"),
                rig.binding.clone(),
                rig.attestor.clone(),
                &rig.state()
            )
            .is_ok()
        );
    }
}

#[test]
fn reporter_credentials_require_bounded_private_regular_files_without_following_links() {
    let rig = Rig::new(0);
    let token = rig.state().join("reporter.token");
    for mode in [0o640, 0o4600] {
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            Reporter::new(
                rig.config("https://collector.example/"),
                rig.binding.clone(),
                rig.attestor.clone(),
                &rig.state()
            )
            .err()
            .unwrap(),
            "file must be a bounded, owned private regular file"
        );
    }
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&token, vec![b'a'; 257]).unwrap();
    assert_eq!(
        Reporter::new(
            rig.config("https://collector.example/"),
            rig.binding.clone(),
            rig.attestor.clone(),
            &rig.state()
        )
        .err()
        .unwrap(),
        "file must be a bounded, owned private regular file"
    );
    std::fs::remove_file(&token).unwrap();
    std::os::unix::fs::symlink("missing-credential", &token).unwrap();
    assert_eq!(
        Reporter::new(
            rig.config("https://collector.example/"),
            rig.binding.clone(),
            rig.attestor.clone(),
            &rig.state()
        )
        .err()
        .unwrap(),
        "private file unavailable"
    );
    std::fs::remove_file(&token).unwrap();
    std::fs::create_dir(&token).unwrap();
    assert_eq!(
        Reporter::new(
            rig.config("https://collector.example/"),
            rig.binding.clone(),
            rig.attestor.clone(),
            &rig.state()
        )
        .err()
        .unwrap(),
        "file must be a bounded, owned private regular file"
    );
}

#[tokio::test]
async fn reporter_signs_exact_bounded_audit_metadata_and_requires_its_acknowledgment() {
    let rig = Rig::new(MAX_EXPORT_BATCH + 4);
    for (after, health) in [
        (Some(0), "ok"),
        (Some(500), "ok"),
        (None, "unknown"),
        (Some(1), "unavailable"),
        (Some(1), "regressed"),
        (Some(1), "gap"),
    ] {
        let server = MockServer::start().await;
        let challenge = rig.challenge(after);
        rig.mount_challenge(&server, &challenge).await;
        let entries = rig.entries(after.unwrap_or(0));
        let expected = rig.ack(&challenge, &entries, health);
        Mock::given(method("POST"))
            .and(path(rig.route("heartbeat")))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&expected))
            .expect(1)
            .mount(&server)
            .await;
        let acknowledgment = rig.reporter(&server.uri()).run_once().await.unwrap();
        assert_eq!(
            serde_json::to_value(acknowledgment).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let heartbeat: Heartbeat = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(heartbeat.challenge, challenge);
        assert_eq!(
            serde_json::to_value(&heartbeat.evidence.export_entries).unwrap(),
            serde_json::to_value(&entries).unwrap()
        );
        assert!(heartbeat.evidence.export_entries.len() <= MAX_EXPORT_BATCH);
        let payload = verify_heartbeat(
            &heartbeat,
            &rig.binding,
            &rig.key.verifying_key(),
            opaque_core::identity::now_unix(),
        )
        .unwrap();
        assert_eq!(payload.daemon_version, "reporter-protocol-fixture");
        assert!(payload.audit.chain_ok);
        assert!(
            !String::from_utf8_lossy(&requests[1].body)
                .contains("private-operation-must-not-be-exported")
        );
    }
}

#[tokio::test]
async fn invalid_challenge_never_sends_a_heartbeat_or_retries_the_challenge() {
    let rig = Rig::new(1);
    for field in 0..6 {
        let server = MockServer::start().await;
        let mut challenge = rig.challenge(None);
        match field {
            0 => challenge.binding.tenant_id = TenantId::parse("foreign").unwrap(),
            1 => challenge.epoch = 0,
            2 => challenge.expires_at = 0,
            3 => challenge.expires_at += 120,
            4 => challenge.nonce = "a".repeat(31),
            _ => challenge.nonce = "g".repeat(32),
        }
        rig.mount_challenge(&server, &challenge).await;
        assert_eq!(
            rig.reporter(&server.uri()).run_once().await.unwrap_err(),
            "collector returned invalid challenge binding"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn acknowledgment_mutations_cannot_advance_the_authenticated_evidence_frontier() {
    let rig = Rig::new(3);
    let before = serde_json::to_value(rig.entries(0)).unwrap();
    for field in 0..8 {
        let server = MockServer::start().await;
        let challenge = rig.challenge(Some(0));
        rig.mount_challenge(&server, &challenge).await;
        let mut ack = rig.ack(&challenge, &rig.entries(0), "ok");
        let expected = match field {
            0 => {
                ack.evidence_health = "invented".into();
                "unknown evidence health"
            }
            1 => {
                ack.binding.tenant_id = TenantId::parse("foreign").unwrap();
                "collector acknowledgment binding invalid"
            }
            2 => {
                ack.epoch += 1;
                "collector acknowledgment binding invalid"
            }
            3 => {
                ack.acknowledged_sequence = Some(999);
                "collector acknowledgment binding invalid"
            }
            4 => {
                ack.received_at = 0;
                "collector acknowledgment binding invalid"
            }
            5 => {
                ack.received_at += 120;
                "collector acknowledgment binding invalid"
            }
            6 => {
                ack.receipt_digest = None;
                "collector acknowledgment digest invalid"
            }
            _ => {
                ack.receipt_digest = Some("0".repeat(64));
                "collector acknowledgment digest invalid"
            }
        };
        Mock::given(method("POST"))
            .and(path(rig.route("heartbeat")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ack))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            rig.reporter(&server.uri()).run_once().await.unwrap_err(),
            expected
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        assert_eq!(
            serde_json::to_value(rig.entries(0)).unwrap(),
            before,
            "reporting never mutates retained audit metadata"
        );
    }
}

#[tokio::test]
async fn malformed_refused_and_redirected_transport_responses_are_bounded_and_not_replayed() {
    let rig = Rig::new(1);
    for heartbeat_phase in [false, true] {
        for (response, expected) in [
            (
                ResponseTemplate::new(401),
                "collector refused report: HTTP 401",
            ),
            (
                ResponseTemplate::new(503),
                "collector refused report: HTTP 503",
            ),
            (
                ResponseTemplate::new(200).set_body_string("not json"),
                "invalid collector response",
            ),
            (
                ResponseTemplate::new(200).set_body_string("x".repeat(256 * 1024 + 1)),
                "collector response exceeds bound",
            ),
            (
                ResponseTemplate::new(302).insert_header("location", "/redirect"),
                "collector refused report: HTTP 302",
            ),
        ] {
            let server = MockServer::start().await;
            if heartbeat_phase {
                rig.mount_challenge(&server, &rig.challenge(None)).await;
            }
            Mock::given(method("POST"))
                .and(path(rig.route(if heartbeat_phase {
                    "heartbeat"
                } else {
                    "challenge"
                })))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                rig.reporter(&server.uri()).run_once().await.unwrap_err(),
                expected
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), if heartbeat_phase { 2 } else { 1 });
            assert!(requests.iter().all(|r| r.url.path() != "/redirect"));
        }
    }
}

#[tokio::test]
async fn absent_or_corrupt_audit_storage_stops_before_report_submission() {
    for corrupt in [false, true] {
        let rig = Rig::new(1);
        let server = MockServer::start().await;
        rig.mount_challenge(&server, &rig.challenge(None)).await;
        std::fs::remove_file(rig.state().join("audit.db")).unwrap();
        if corrupt {
            std::fs::write(rig.state().join("audit.db"), "invalid sqlite").unwrap();
        }
        assert_eq!(
            rig.reporter(&server.uri()).run_once().await.unwrap_err(),
            "audit metadata unavailable"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn periodic_reporter_continues_after_failure_and_success_until_explicit_cancellation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for succeed in [false, true] {
        let rig = Rig::new(0);
        let server = MockServer::start().await;
        let challenge = rig.challenge(None);
        let ack = rig.ack(&challenge, &[], "ok");
        let calls = Arc::new(AtomicUsize::new(0));
        let next_cycle = Arc::new(tokio::sync::Notify::new());
        let observed = calls.clone();
        let ready = next_cycle.clone();
        Mock::given(method("POST"))
            .and(path(rig.route("challenge")))
            .respond_with(move |_: &wiremock::Request| {
                if observed.fetch_add(1, Ordering::SeqCst) == 1 {
                    ready.notify_one();
                }
                if succeed {
                    ResponseTemplate::new(200).set_body_json(&challenge)
                } else {
                    ResponseTemplate::new(503)
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(rig.route("heartbeat")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ack))
            .mount(&server)
            .await;
        let task = tokio::spawn(rig.reporter(&server.uri()).run());
        tokio::time::timeout(std::time::Duration::from_secs(4), next_cycle.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(calls.load(Ordering::SeqCst) >= 2);
        let requests = server.received_requests().await.unwrap();
        let heartbeat_count = requests
            .iter()
            .filter(|r| r.url.path().ends_with("/heartbeat"))
            .count();
        if succeed {
            assert!(heartbeat_count >= 1);
        } else {
            assert_eq!(heartbeat_count, 0);
        }
    }
}
