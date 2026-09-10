//! Public contract fixtures use no enterprise collector or management database.
use ed25519_dalek::SigningKey;
use opaque_core::{
    attest::{AuditPosture, ReportPayload, TrustDomainPosture, sign_report},
    tenant::{TenantBinding, TenantId},
};
use opaque_federation_runtime::fleet::{
    Challenge, Evidence, ExportEntry, Heartbeat, MAX_EXPORT_BATCH, verify_heartbeat,
};

fn fixture(issued_at: i64) -> (Heartbeat, SigningKey) {
    let key = SigningKey::from_bytes(&[31; 32]);
    let challenge = Challenge {
        binding: TenantBinding::new(
            TenantId::parse("example-team").unwrap(),
            "00000000-0000-4000-8000-000000000001".parse().unwrap(),
        )
        .unwrap(),
        epoch: 1,
        nonce: "0".repeat(32),
        expires_at: 160,
        acknowledged_sequence: Some(4),
    };
    let evidence = Evidence {
        audit_head: Some(5),
        export_entries: vec![ExportEntry {
            sequence: 5,
            event_id: "00000000-0000-4000-8000-000000000002".into(),
            record_hash: "a".repeat(64),
        }],
    };
    let report = sign_report(
        &ReportPayload {
            nonce: Heartbeat::nonce_for(&challenge, &evidence).unwrap(),
            issued_at,
            daemon_version: "third-party-application".into(),
            uid: 1000,
            trust_domain: TrustDomainPosture {
                enforce: true,
                custody_ok: true,
                custody_violations: vec![],
            },
            audit: AuditPosture {
                chain_ok: true,
                records: 5,
                detail: None,
            },
            federation: None,
            factors: vec![],
        },
        &key,
    )
    .unwrap();
    (
        Heartbeat {
            schema_version: 1,
            challenge,
            evidence,
            report,
        },
        key,
    )
}

#[test]
fn independent_consumer_verifies_v1_without_management_service() {
    let (heartbeat, key) = fixture(100);
    let encoded = serde_json::to_vec(&heartbeat).unwrap();
    let decoded: Heartbeat = serde_json::from_slice(&encoded).unwrap();
    let payload = verify_heartbeat(
        &decoded,
        &heartbeat.challenge.binding,
        &key.verifying_key(),
        101,
    )
    .unwrap();
    assert_eq!(payload.daemon_version, "third-party-application");
    assert!(payload.integrity_ok());
    // Contract verification is intentionally stateless. The embedding consumer
    // must atomically compare/consume outstanding challenges to reject replay.
    assert!(
        verify_heartbeat(
            &decoded,
            &heartbeat.challenge.binding,
            &key.verifying_key(),
            101
        )
        .is_ok()
    );
}

#[test]
fn every_challenge_and_evidence_field_is_signed() {
    let (heartbeat, key) = fixture(100);
    let mut mutations = Vec::new();
    let mut changed = heartbeat.clone();
    changed.challenge.epoch += 1;
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.challenge.nonce = "1".repeat(32);
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.challenge.expires_at += 1;
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.challenge.acknowledged_sequence = None;
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.evidence.audit_head = Some(10);
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.evidence.export_entries[0].record_hash = "b".repeat(64);
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.evidence.export_entries[0].sequence += 1;
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.evidence.export_entries[0].event_id = "00000000-0000-4000-8000-000000000003".into();
    mutations.push(changed);
    let mut changed = heartbeat.clone();
    changed.challenge.binding = TenantBinding::new(
        TenantId::parse("different-team").unwrap(),
        heartbeat.challenge.binding.broker_id,
    )
    .unwrap();
    mutations.push(changed);
    for changed in mutations {
        assert!(
            verify_heartbeat(
                &changed,
                &heartbeat.challenge.binding,
                &key.verifying_key(),
                101
            )
            .is_err()
        );
    }
    let wrong = SigningKey::from_bytes(&[32; 32]);
    assert!(
        verify_heartbeat(
            &heartbeat,
            &heartbeat.challenge.binding,
            &wrong.verifying_key(),
            101
        )
        .is_err()
    );
}

#[test]
fn freshness_and_extreme_signed_times_fail_closed() {
    let (heartbeat, key) = fixture(100);
    for now in [-1, 99, 160, i64::MAX] {
        assert!(
            verify_heartbeat(
                &heartbeat,
                &heartbeat.challenge.binding,
                &key.verifying_key(),
                now
            )
            .is_err()
        );
    }
    for issued_at in [99, 102, i64::MIN, i64::MAX] {
        let (heartbeat, key) = fixture(issued_at);
        assert!(
            verify_heartbeat(
                &heartbeat,
                &heartbeat.challenge.binding,
                &key.verifying_key(),
                101
            )
            .is_err()
        );
    }
}

#[test]
fn unversioned_overlarge_and_unknown_field_envelopes_are_rejected() {
    let (heartbeat, key) = fixture(100);
    let mut bad = heartbeat.clone();
    bad.schema_version = 2;
    assert!(
        verify_heartbeat(
            &bad,
            &heartbeat.challenge.binding,
            &key.verifying_key(),
            101
        )
        .is_err()
    );
    let mut bad = heartbeat.clone();
    bad.evidence.export_entries =
        vec![bad.evidence.export_entries[0].clone(); MAX_EXPORT_BATCH + 1];
    assert!(
        verify_heartbeat(
            &bad,
            &heartbeat.challenge.binding,
            &key.verifying_key(),
            101
        )
        .is_err()
    );
    let mut bad = serde_json::to_value(heartbeat).unwrap();
    bad["implicit_enrollment"] = true.into();
    assert!(serde_json::from_value::<Heartbeat>(bad).is_err());
}
