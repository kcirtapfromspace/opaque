//! Enrolled coverage fixtures: real collector HTTP and isolated broker state.
//! Synthetic keys/tenants; no endpoint discovery or vendor pilot is claimed.
use ed25519_dalek::SigningKey;
use opaque_core::{
    attest::{AuditPosture, FederationPosture, ReportPayload, TrustDomainPosture, sign_report},
    tenant::{TenantBinding, TenantId},
};
use opaque_federation_runtime::{
    attest::AttestationService,
    federation::FederationStatus,
    fleet::{
        reporter::{Reporter, ReporterConfig},
        *,
    },
};
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeMap, path::Path, sync::Arc};

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<FleetStore>,
    a: TenantBinding,
    b: TenantBinding,
    ka: SigningKey,
    kb: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Arc::new(FleetStore::open(dir.path()).unwrap());
        let a = binding("tenant-a");
        let b = binding("tenant-b");
        let ka = SigningKey::from_bytes(&[31; 32]);
        let kb = SigningKey::from_bytes(&[32; 32]);
        for (binding, key) in [(&a, &ka), (&b, &kb)] {
            store.enroll(&enrollment(binding, key), false, 100).unwrap();
        }
        Self {
            dir,
            store,
            a,
            b,
            ka,
            kb,
        }
    }
    fn view(&self, tenant: &str, now: i64) -> Value {
        self.store.inventory(tenant, now, 120, 600).unwrap()
    }
}
fn binding(tenant: &str) -> TenantBinding {
    TenantBinding::new(TenantId::parse(tenant).unwrap(), uuid::Uuid::new_v4()).unwrap()
}
fn enrollment(binding: &TenantBinding, key: &SigningKey) -> Enrollment {
    Enrollment {
        binding: binding.clone(),
        public_key: key
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        expected_policy_version: Some(2),
        expected_policy_digest: Some("a".repeat(64)),
    }
}
fn heartbeat(
    challenge: Challenge,
    key: &SigningKey,
    now: i64,
    entries: Vec<ExportEntry>,
    head: Option<u64>,
) -> Heartbeat {
    let evidence = Evidence {
        audit_head: head,
        export_entries: entries,
    };
    let report = sign_report(
        &ReportPayload {
            nonce: Heartbeat::nonce_for(&challenge, &evidence).unwrap(),
            issued_at: now,
            daemon_version: "test-build".into(),
            uid: 7001,
            trust_domain: TrustDomainPosture {
                enforce: true,
                custody_ok: true,
                custody_violations: vec![],
            },
            audit: AuditPosture {
                chain_ok: true,
                records: head.unwrap_or(0),
                detail: None,
            },
            federation: Some(FederationPosture {
                org: "fixture".into(),
                version: 2,
                digest: "a".repeat(64),
            }),
            factors: vec!["paired_workstation".into()],
        },
        key,
    )
    .unwrap();
    Heartbeat {
        schema_version: 1,
        challenge,
        evidence,
        report,
    }
}
fn entries(start: u64, count: u64) -> Vec<ExportEntry> {
    (start..start + count)
        .map(|sequence| ExportEntry {
            sequence,
            event_id: uuid::Uuid::new_v4().to_string(),
            record_hash: format!("{sequence:064x}"),
        })
        .collect()
}
#[test]
fn two_tenants_enrollment_nonce_replay_freshness_and_revocation_survive_restart() {
    let f = Fixture::new();
    assert_eq!(f.view("tenant-a", 100)["brokers"][0]["status"], "unknown");
    assert_eq!(
        f.view("tenant-a", 100)["brokers"][0]["policy_status"],
        "unknown"
    );
    let h = heartbeat(
        f.store.challenge(&f.a, 100).unwrap(),
        &f.ka,
        100,
        entries(1, 2),
        Some(5),
    );
    let ack = f.store.accept(&f.a, &h, 101).unwrap();
    assert_eq!(ack.acknowledged_sequence, Some(2));
    assert!(ack.receipt_digest.is_some());
    assert!(f.store.accept(&f.a, &h, 102).is_err());
    let b = heartbeat(
        f.store.challenge(&f.b, 100).unwrap(),
        &f.kb,
        100,
        vec![],
        None,
    );
    f.store.accept(&f.b, &b, 101).unwrap();
    let view = f.view("tenant-a", 102);
    assert_eq!(view["brokers"].as_array().unwrap().len(), 1);
    assert_eq!(view["brokers"][0]["broker_id"], f.a.broker_id.to_string());
    assert_eq!(view["brokers"][0]["evidence_export_lag_records"], 3);
    assert_eq!(view["brokers"][0]["policy_status"], "matches");
    assert!(view["brokers"][0]["full_audit_export_lag"].is_null());
    assert_eq!(f.view("tenant-a", 222)["brokers"][0]["status"], "stale");
    assert!(f.view("tenant-a", 222)["brokers"][0]["current_posture"].is_null());
    assert_eq!(f.view("tenant-a", 701)["brokers"][0]["status"], "offline");
    assert_eq!(f.view("tenant-a", 90)["brokers"][0]["status"], "unknown");
    let pending = heartbeat(
        f.store.challenge(&f.a, 105).unwrap(),
        &f.ka,
        105,
        entries(3, 1),
        Some(5),
    );
    f.store.revoke(&f.a, 106).unwrap();
    assert!(f.store.accept(&f.a, &pending, 107).is_err());
    let reopened = FleetStore::open(f.dir.path()).unwrap();
    assert_eq!(
        reopened.inventory("tenant-a", 110, 120, 600).unwrap()["brokers"][0]["status"],
        "revoked"
    );
    assert!(reopened.challenge(&f.a, 110).is_err());
    assert!(
        reopened
            .enroll(
                &enrollment(&f.a, &SigningKey::from_bytes(&[33; 32])),
                true,
                111
            )
            .is_err()
    );
}
#[test]
fn signed_binding_evidence_and_clock_cannot_be_substituted() {
    let f = Fixture::new();
    let c = f.store.challenge(&f.a, 100).unwrap();
    let h = heartbeat(c.clone(), &f.ka, 100, entries(1, 2), Some(2));
    assert!(f.store.accept(&f.b, &h, 100).is_err());
    let mut altered = h.clone();
    altered.evidence.audit_head = Some(1000);
    assert!(f.store.accept(&f.a, &altered, 100).is_err());
    let wrong = heartbeat(c.clone(), &f.kb, 100, vec![], None);
    assert!(f.store.accept(&f.a, &wrong, 100).is_err());
    let future = heartbeat(c.clone(), &f.ka, 101, vec![], None);
    assert!(f.store.accept(&f.a, &future, 100).is_err());
    let old = heartbeat(c.clone(), &f.ka, 99, vec![], None);
    assert!(f.store.accept(&f.a, &old, 100).is_err());
    assert!(f.store.accept(&f.a, &h, 160).is_err());
    let new = f.store.challenge(&f.a, 160).unwrap();
    assert_ne!(new.nonce, c.nonce);
    assert!(f.store.accept(&f.a, &h, 160).is_err());
}
#[test]
fn rotation_invalidates_prior_proof_and_key_cannot_move_between_tenants() {
    let f = Fixture::new();
    let old = heartbeat(
        f.store.challenge(&f.a, 100).unwrap(),
        &f.ka,
        100,
        vec![],
        None,
    );
    assert!(
        f.store
            .enroll(&enrollment(&binding("tenant-c"), &f.ka), false, 100)
            .is_err()
    );
    let new_key = SigningKey::from_bytes(&[90; 32]);
    assert_eq!(
        f.store
            .enroll(&enrollment(&f.a, &new_key), true, 101)
            .unwrap(),
        2
    );
    assert!(f.store.accept(&f.a, &old, 101).is_err());
    let challenge = f.store.challenge(&f.a, 102).unwrap();
    assert_eq!(challenge.epoch, 2);
    let wrong = heartbeat(challenge.clone(), &f.ka, 102, vec![], None);
    assert!(f.store.accept(&f.a, &wrong, 102).is_err());
    f.store
        .accept(
            &f.a,
            &heartbeat(challenge, &new_key, 102, vec![], None),
            102,
        )
        .unwrap();
}
#[test]
fn collector_acknowledges_only_received_contiguous_signed_evidence() {
    let f = Fixture::new();
    let h = heartbeat(
        f.store.challenge(&f.a, 100).unwrap(),
        &f.ka,
        100,
        entries(20, 2),
        Some(30),
    );
    f.store.accept(&f.a, &h, 100).unwrap();
    let view = f.view("tenant-a", 100);
    assert_eq!(view["brokers"][0]["evidence_coverage_start"], 20);
    assert_eq!(view["brokers"][0]["evidence_export_lag_records"], 9);

    let c = f.store.challenge(&f.a, 101).unwrap();
    let gap = heartbeat(c, &f.ka, 101, entries(23, 1), Some(30));
    let ack = f.store.accept(&f.a, &gap, 101).unwrap();
    assert_eq!(ack.acknowledged_sequence, Some(21));
    assert_eq!(ack.evidence_health, "gap");
    let view = f.view("tenant-a", 101);
    assert_eq!(view["brokers"][0]["status"], "fresh");
    assert_eq!(view["brokers"][0]["evidence_health"], "gap");
    assert!(view["brokers"][0]["evidence_export_lag_records"].is_null());
    let c = f.store.challenge(&f.a, 102).unwrap();
    let regressed = heartbeat(c, &f.ka, 102, vec![], Some(25));
    let ack = f.store.accept(&f.a, &regressed, 102).unwrap();
    assert_eq!(ack.evidence_health, "regressed");
    let view = f.view("tenant-a", 102);
    assert_eq!(view["brokers"][0]["last_known_audit_head"], 30);
    assert_eq!(view["brokers"][0]["audit_head"], 25);
    assert!(view["brokers"][0]["evidence_export_lag_records"].is_null());
    let c = f.store.challenge(&f.a, 103).unwrap();
    let unknown = heartbeat(c, &f.ka, 103, vec![], None);
    assert_eq!(
        f.store.accept(&f.a, &unknown, 103).unwrap().evidence_health,
        "unavailable"
    );
    let c = f.store.challenge(&f.a, 104).unwrap();
    let next = heartbeat(c, &f.ka, 104, entries(22, 2), Some(30));
    assert_eq!(
        f.store
            .accept(&f.a, &next, 104)
            .unwrap()
            .acknowledged_sequence,
        Some(23)
    );
}
fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn broker(directory: &Path, key: SigningKey, token: &str) -> Arc<AttestationService> {
    let state = directory.join(".opaque");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    private(&state.join("fleet.token"), token.as_bytes());
    private(&directory.join("config.toml"), b"fixture=true\n");
    // Real audit sink schema/chain. No business payloads enter the metadata export.
    let sink = opaque_core::audit::SqliteAuditSink::new(state.join("audit.db"), 90).unwrap();
    drop(sink);
    Arc::new(AttestationService::new(
        key,
        directory.into(),
        directory.join("config.toml"),
        state.join("audit.db"),
        "fixture-version".into(),
        true,
        vec![],
        Arc::new(FederationStatus::default()),
    ))
}
#[tokio::test]
async fn real_http_two_isolated_reporters_and_reader_scope() {
    let f = Fixture::new();
    let secrets = tempfile::tempdir().unwrap();
    let mut credentials = BTreeMap::new();
    for tenant in ["tenant-a", "tenant-b"] {
        let reader = secrets.path().join(format!("{tenant}-reader"));
        let writer = secrets.path().join(format!("{tenant}-writer"));
        private(
            &reader,
            format!("{tenant}_reader_fixture_random_material_1234567890").as_bytes(),
        );
        private(
            &writer,
            format!("{tenant}_writer_fixture_random_material_1234567890").as_bytes(),
        );
        credentials.insert(
            tenant.to_owned(),
            TenantCredentials {
                read_token_file: reader,
                report_token_file: writer,
            },
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}/");
    let config = CollectorConfig {
        listen: address,
        tenants: credentials,
        fresh_secs: 120,
        offline_secs: 600,
    };
    let store = f.store.clone();
    let task = tokio::spawn(async move { serve_listener(store, config, listener).await.unwrap() });
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    for (binding, key, directory, tenant) in [
        (&f.a, f.ka.clone(), da.path(), "tenant-a"),
        (&f.b, f.kb.clone(), db.path(), "tenant-b"),
    ] {
        let token = format!("{tenant}_writer_fixture_random_material_1234567890");
        let attestor = broker(directory, key, &token);
        let state = directory.join(".opaque");
        let reporter = Reporter::new(
            ReporterConfig {
                collector_url: url.clone(),
                token_file: state.join("fleet.token"),
                interval_secs: 30,
            },
            binding.clone(),
            attestor,
            &state,
        )
        .unwrap();
        reporter.run_once().await.unwrap();
    }
    let client = reqwest::Client::new();
    let a_url = format!("{url}v1/tenants/tenant-a/brokers");
    assert_eq!(client.get(&a_url).send().await.unwrap().status(), 401);
    assert_eq!(
        client
            .get(&a_url)
            .bearer_auth("tenant-a_writer_fixture_random_material_1234567890")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(&a_url)
            .bearer_auth("tenant-b_reader_fixture_random_material_1234567890")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let response = client
        .get(&a_url)
        .bearer_auth("tenant-a_reader_fixture_random_material_1234567890")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let view: Value = response.json().await.unwrap();
    assert_eq!(view["brokers"].as_array().unwrap().len(), 1);
    assert_eq!(view["brokers"][0]["status"], "fresh");
    assert_eq!(view["brokers"][0]["daemon_version"], "fixture-version");
    // Stopping reports never fabricates a healthy current posture.
    let later = f
        .store
        .inventory(
            "tenant-a",
            opaque_core::identity::now_unix() + 601,
            120,
            600,
        )
        .unwrap();
    assert_eq!(later["brokers"][0]["status"], "offline");
    assert!(later["brokers"][0]["current_posture"].is_null());
    task.abort();
}

#[test]
fn extreme_signed_time_does_not_poison_other_tenant_collection() {
    let f = Fixture::new();
    for issued_at in [i64::MIN, i64::MAX] {
        let c = f.store.challenge(&f.a, 100).unwrap();
        let extreme = heartbeat(c, &f.ka, issued_at, vec![], None);
        assert!(f.store.accept(&f.a, &extreme, 100).is_err());
    }
    let c = f.store.challenge(&f.b, 100).unwrap();
    let valid = heartbeat(c, &f.kb, 100, vec![], None);
    f.store.accept(&f.b, &valid, 100).unwrap();
    assert_eq!(f.view("tenant-b", 100)["brokers"][0]["status"], "fresh");
}
