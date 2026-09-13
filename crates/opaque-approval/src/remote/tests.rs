use super::*;
use crate::pairing::{WorkstationApproverConfig, store::DeviceStore};
use ed25519_dalek::{Signer, SigningKey};
use opaque_core::workstation::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

struct Rig {
    dir: tempfile::TempDir,
    tenant: TenantBinding,
    pairing: Arc<PairingManager>,
    device: PairedDevice,
    key: SigningKey,
    epoch: Arc<AtomicU64>,
    config: RemoteApprovalConfig,
}
impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = SigningKey::from_bytes(&[19; 32]);
        let pairing = Arc::new(PairingManager::new(
            "opq-remote-test".into(),
            SigningKey::from_bytes(&[17; 32]),
            0,
            DeviceStore::new(dir.path().join("devices.json"), vec![18; 32]),
        ));
        let device = pairing
            .enroll_workstation(&WorkstationApproverConfig {
                public_key_hex: hex(key.verifying_key().as_bytes()),
                name: "Fixture reviewer".into(),
                principal_id: Some("hum_11111111111111111111111111111111".into()),
            })
            .unwrap();
        let tenant = TenantBinding::new(
            opaque_core::tenant::TenantId::parse("fixture").unwrap(),
            uuid::Uuid::new_v4(),
        )
        .unwrap();
        let config = RemoteApprovalConfig {
            reviewer_public_key_hex: device.public_key_hex.clone(),
            required_role: "operator".into(),
            notice_token_file: None,
        };
        Self {
            dir,
            tenant,
            pairing,
            device,
            key,
            epoch: Arc::new(AtomicU64::new(1)),
            config,
        }
    }
    fn open(&self) -> Arc<RemoteApprovals> {
        let epoch = self.epoch.clone();
        let resolver: ReviewerResolver = Arc::new(move |principal, role| {
            if principal != "hum_11111111111111111111111111111111" || role != "operator" {
                return Err("wrong reviewer".into());
            }
            let epoch = epoch.load(Ordering::SeqCst);
            if epoch == 0 {
                Err("reviewer disabled".into())
            } else {
                Ok(epoch)
            }
        });
        let guard_resolver = resolver.clone();
        let guard: ReviewerAuthorityGuard =
            Arc::new(move |_, principal, role, epoch, authorize| {
                if guard_resolver(principal, role)? != epoch {
                    return Err("reviewer authority changed".into());
                }
                authorize()
            });
        RemoteApprovals::open(
            self.config.clone(),
            &self.dir.path().join("remote.db"),
            self.tenant.clone(),
            self.pairing.clone(),
            resolver,
            guard,
        )
        .unwrap()
    }
    fn review(&self, remote: &RemoteApprovals) -> WorkstationReview {
        let text = "Release the exact fixture manifest. No live credentials.";
        let mut review = WorkstationReview {
            challenge: WorkstationChallenge {
                schema_version: 1,
                authority: None,
                broker_id: self.pairing.server_id().into(),
                approval_id: uuid::Uuid::new_v4().to_string(),
                request_id: uuid::Uuid::new_v4().to_string(),
                operation: "github.release_manifest".into(),
                content_hash: review_hash(text),
                nonce: "aa".repeat(32),
                created_at: now(),
                expires_at: now() + 120,
            },
            review_text: text.into(),
        };
        remote
            .bind(
                &mut review,
                ApprovalBinding {
                    tenant: self.tenant.clone(),
                    task_id: uuid::Uuid::new_v4().to_string(),
                    manifest_digest: "bb".repeat(32),
                    request_hash: "cc".repeat(32),
                    policy_digest: "dd".repeat(32),
                    requester: "svc_22222222222222222222222222222222".into(),
                },
            )
            .unwrap();
        review
    }
    fn response(&self, review: &WorkstationReview, approve: bool) -> WorkstationResponse {
        WorkstationResponse {
            device_id: self.device.device_id.clone(),
            decision: if approve {
                WorkstationDecision::Approve
            } else {
                WorkstationDecision::Reject
            },
            signature: hex(&self
                .key
                .sign(&workstation_decision_bytes(&review.challenge, approve))
                .to_bytes()),
        }
    }
}

#[test]
fn signed_receipt_survives_restart_but_unfinished_round_does_not() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    let receipt = remote
        .accept(&review, rig.response(&review, true), &rig.device)
        .unwrap();
    receipt.verify().unwrap();
    remote.revalidate(&receipt).unwrap();
    assert!(
        remote
            .accept(&review, rig.response(&review, true), &rig.device)
            .is_err()
    );
    let pending = rig.review(&remote);
    remote.enqueue(&pending).unwrap();
    drop(remote);
    let restarted = rig.open();
    assert_eq!(
        restarted
            .store
            .receipt(&review.challenge.approval_id)
            .unwrap(),
        Some(receipt.clone())
    );
    restarted.revalidate(&receipt).unwrap();
    assert!(
        restarted
            .accept(&pending, rig.response(&pending, true), &rig.device)
            .is_err()
    );
    assert!(
        restarted
            .store
            .receipt(&pending.challenge.approval_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn every_new_signed_binding_is_tamper_evident() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    let receipt = remote
        .accept(&review, rig.response(&review, true), &rig.device)
        .unwrap();
    let mutations: [fn(&mut WorkstationAuthority); 9] = [
        |a| a.binding.tenant.broker_id = uuid::Uuid::new_v4(),
        |a| a.binding.tenant.tenant_id = opaque_core::tenant::TenantId::parse("other").unwrap(),
        |a| a.binding.task_id = uuid::Uuid::new_v4().to_string(),
        |a| a.binding.manifest_digest = "ee".repeat(32),
        |a| a.binding.request_hash = "ee".repeat(32),
        |a| a.binding.policy_digest = "ee".repeat(32),
        |a| a.binding.requester = "other".into(),
        |a| a.principal_id = "other".into(),
        |a| a.authority_epoch += 1,
    ];
    for mutate in mutations {
        let mut forged = receipt.clone();
        mutate(forged.review.challenge.authority.as_mut().unwrap());
        assert!(forged.verify().is_err());
    }
    let mut forged = receipt.clone();
    forged.response.decision = WorkstationDecision::Reject;
    assert!(forged.verify().is_err());
}

#[test]
fn disable_role_regrant_device_revocation_and_cancel_fail_closed() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    rig.epoch.store(0, Ordering::SeqCst);
    assert!(
        remote
            .accept(&review, rig.response(&review, true), &rig.device)
            .is_err()
    );
    rig.epoch.store(2, Ordering::SeqCst);
    assert!(
        remote
            .accept(&review, rig.response(&review, true), &rig.device)
            .is_err()
    );
    let fresh = rig.review(&remote);
    remote.enqueue(&fresh).unwrap();
    let receipt = remote
        .accept(&fresh, rig.response(&fresh, true), &rig.device)
        .unwrap();
    rig.epoch.store(3, Ordering::SeqCst);
    assert!(remote.revalidate(&receipt).is_err());
    let cancelled = rig.review(&remote);
    remote.enqueue(&cancelled).unwrap();
    remote
        .store
        .cancel(&cancelled.challenge.approval_id)
        .unwrap();
    assert!(
        remote
            .accept(&cancelled, rig.response(&cancelled, true), &rig.device)
            .is_err()
    );
    rig.pairing.revoke_device(&rig.device.device_id).unwrap();
    assert!(remote.revalidate(&receipt).is_err());
}

#[test]
fn rejection_is_durable_but_never_dispatch_authority() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    let receipt = remote
        .accept(&review, rig.response(&review, false), &rig.device)
        .unwrap();
    receipt.verify().unwrap();
    assert!(remote.revalidate(&receipt).is_err());
    assert_eq!(
        remote.store.receipt(&review.challenge.approval_id).unwrap(),
        Some(receipt)
    );
}

#[test]
fn private_ledger_refuses_second_writer_wrong_tenant_and_symlink() {
    let rig = Rig::new();
    let remote = rig.open();
    assert!(
        RemoteStore::open(
            &rig.dir.path().join("remote.db"),
            rig.tenant.clone(),
            rig.pairing.server_id().into()
        )
        .is_err()
    );
    drop(remote);
    let mut other = rig.tenant.clone();
    other.broker_id = uuid::Uuid::new_v4();
    assert!(
        RemoteStore::open(
            &rig.dir.path().join("remote.db"),
            other,
            rig.pairing.server_id().into()
        )
        .is_err()
    );
    std::os::unix::fs::symlink(
        rig.dir.path().join("remote.db"),
        rig.dir.path().join("linked.db"),
    )
    .unwrap();
    assert!(
        RemoteStore::open(
            &rig.dir.path().join("linked.db"),
            rig.tenant.clone(),
            rig.pairing.server_id().into()
        )
        .is_err()
    );
}

#[test]
fn notice_cannot_supply_transport_authority() {
    let id = uuid::Uuid::new_v4().to_string();
    let link = notice_link("opq-enrolled", &id).unwrap();
    assert_eq!(resolve_notice(&link, "opq-enrolled").unwrap(), id);
    for wrong in [
        format!("{link}?endpoint=https://evil.test"),
        format!("{link}#token"),
        format!("{link}/extra"),
        link.replace("opq-enrolled", "opq-other"),
        format!("https://evil.test/{id}"),
    ] {
        assert!(resolve_notice(&wrong, "opq-enrolled").is_err());
    }
}

#[tokio::test]
async fn real_pinned_https_review_persists_signature_before_acknowledgment() {
    use crate::approval_server::{ApprovalServer, ApprovalServerConfig, generate_self_signed_cert};
    use opaque_approver::client::{BrokerClient, certificate_fingerprint};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rig = Rig::new();
    let challenge = rig
        .pairing
        .begin_workstation_enrollment(&rig.device.public_key_hex)
        .unwrap();
    let enrollment = rig
        .pairing
        .complete_workstation_enrollment(&EnrollmentRequest {
            public_key_hex: rig.device.public_key_hex.clone(),
            nonce: challenge.nonce.clone(),
            signature: hex(&rig.key.sign(&enrollment_bytes(&challenge)).to_bytes()),
        })
        .unwrap();
    let remote = rig.open();
    let review = rig.review(&remote);
    let tls = generate_self_signed_cert().unwrap();
    let fingerprint = certificate_fingerprint(&tls.cert_der);
    let server = ApprovalServer::new(
        ApprovalServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            tls_cert_der: tls.cert_der,
            tls_key_der: tls.key_der,
            timeout_secs: 60,
        },
        rig.pairing.clone(),
    )
    .unwrap()
    .with_remote(remote.clone());
    let handle = server.handle();
    let (server_task, address) = server.start().await.unwrap();
    let issued = review.clone();
    let waiting = tokio::spawn(async move { handle.await_workstation_review(issued).await });
    let client = BrokerClient::new(&format!("https://{address}"), &fingerprint).unwrap();
    let auth = Some((enrollment.device_id.as_str(), enrollment.token.as_str()));
    let route = format!("/workstation/approvals/{}", review.challenge.approval_id);
    let fetched: WorkstationReview =
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(review) = client
                    .request(reqwest::Method::GET, &route, None, auth)
                    .await
                {
                    break review;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    assert_eq!(fetched, review);
    rig.epoch.store(0, Ordering::SeqCst);
    assert!(
        client
            .request::<WorkstationReview>(reqwest::Method::GET, &route, None, auth)
            .await
            .is_err()
    );
    let hidden: serde_json::Value = client
        .request(
            reqwest::Method::GET,
            "/workstation/approvals/pending",
            None,
            auth,
        )
        .await
        .unwrap();
    assert_eq!(hidden["approvals"], serde_json::json!([]));
    rig.epoch.store(1, Ordering::SeqCst);
    let response = rig.response(&review, true);
    let _: serde_json::Value = client
        .request(
            reqwest::Method::POST,
            &format!("{route}/respond"),
            Some(serde_json::to_value(&response).unwrap()),
            auth,
        )
        .await
        .unwrap();
    let retained = remote
        .store
        .receipt(&review.challenge.approval_id)
        .unwrap()
        .expect("receipt committed before HTTP 200");
    assert_eq!(retained.response, response);
    let verified = waiting.await.unwrap().unwrap();
    assert_eq!(verified.workstation_receipt, Some(retained.clone()));
    let downloaded: SignedWorkstationReceipt = client
        .request(
            reqwest::Method::GET,
            &format!("/workstation/receipts/{}", review.challenge.approval_id),
            None,
            auth,
        )
        .await
        .unwrap();
    assert_eq!(downloaded, retained);
    rig.epoch.store(0, Ordering::SeqCst);
    assert!(
        client
            .request::<SignedWorkstationReceipt>(
                reqwest::Method::GET,
                &format!("/workstation/receipts/{}", review.challenge.approval_id),
                None,
                auth
            )
            .await
            .is_err()
    );
    assert!(
        client
            .request::<serde_json::Value>(
                reqwest::Method::POST,
                &format!("{route}/respond"),
                Some(serde_json::to_value(&response).unwrap()),
                auth
            )
            .await
            .is_err()
    );
    server_task.abort();
    let _ = server_task.await;
}
#[test]
fn notice_credential_is_scoped_and_old_transport_config_fails_closed() {
    use axum::http::{HeaderMap, HeaderValue};
    let mut rig = Rig::new();
    let token = "fixture_notice_token_012345678901234567890123456789";
    let path = rig.dir.path().join("notice.token");
    std::fs::write(&path, token).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    rig.config.notice_token_file = Some(path);
    let remote = rig.open();
    let mut headers = HeaderMap::new();
    assert!(!remote.authorize_notice_feed(&headers));
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    assert!(remote.authorize_notice_feed(&headers));
    headers.insert("origin", HeaderValue::from_static("https://example.test"));
    assert!(!remote.authorize_notice_feed(&headers));
    headers.remove("origin");
    headers.append(
        "authorization",
        HeaderValue::from_static("Bearer second_value"),
    );
    assert!(!remote.authorize_notice_feed(&headers));
    let mut old = serde_json::to_value(&rig.config).unwrap();
    old["slack"] = serde_json::json!({"channel_id":"C12345","token_file":"/private/token"});
    assert!(serde_json::from_value::<RemoteApprovalConfig>(old).is_err());
}

#[test]
fn historical_notice_columns_do_not_resume_delivery_or_pending_authority() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    let db = rusqlite::Connection::open(rig.dir.path().join("remote.db")).unwrap();
    let notice: String = db
        .query_row("SELECT notice FROM rounds", [], |row| row.get(0))
        .unwrap();
    assert_eq!(notice, "disabled");
    db.execute(
        "UPDATE rounds SET notice='sending',attempts=2,retry_at=100",
        [],
    )
    .unwrap();
    drop(db);
    drop(remote);
    let reopened = rig.open();
    assert!(
        reopened
            .store
            .receipt(&review.challenge.approval_id)
            .unwrap()
            .is_none()
    );
    let db = rusqlite::Connection::open(rig.dir.path().join("remote.db")).unwrap();
    let (state, notice): (String, String) = db
        .query_row("SELECT state,notice FROM rounds", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(state, "cancelled_restart");
    assert_eq!(notice, "cancelled");
}

fn reviewed_requester() -> opaque_core::identity::PrincipalContext {
    use opaque_core::identity::{AccessMode, PrincipalContext, PrincipalId};
    PrincipalContext {
        sub: PrincipalId::parse("svc_22222222222222222222222222222222").unwrap(),
        sub_label: "fixture requester".into(),
        sub_roles: Default::default(),
        sub_teams: vec![],
        act: PrincipalId::parse("agt_33333333333333333333333333333333").unwrap(),
        act_label: "fixture agent".into(),
        mode: AccessMode::Autonomous,
        jti: "fixture-delegation".into(),
        human_session_id: None,
    }
}

#[test]
fn durable_receipt_requires_the_reviewed_requester_before_and_after_restart() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    let receipt = remote
        .accept(&review, rig.response(&review, true), &rig.device)
        .unwrap();
    receipt.verify().unwrap();
    let requester = reviewed_requester();
    let mut other = requester.clone();
    other.sub =
        opaque_core::identity::PrincipalId::parse("svc_44444444444444444444444444444444").unwrap();
    let mut current = remote;
    for restart in [false, true] {
        if restart {
            drop(current);
            current = rig.open();
        }
        for context in [None, Some(&other)] {
            let mut effects = 0;
            assert_eq!(
                current
                    .authorize(context, &receipt, &mut || {
                        effects += 1;
                        Ok(())
                    })
                    .unwrap_err(),
                "remote dispatch requires the reviewed requester"
            );
            assert_eq!(effects, 0);
            assert_eq!(
                current
                    .store
                    .receipt(&review.challenge.approval_id)
                    .unwrap(),
                Some(receipt.clone())
            );
        }
        let mut effects = 0;
        current
            .authorize(Some(&requester), &receipt, &mut || {
                effects += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            effects, 1,
            "the matching receipt remains usable by the caller's ledger gate"
        );
    }
}

#[test]
fn independently_signed_reviewer_bindings_fail_current_and_locked_authority_checks() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    for mutation in ["key", "principal", "role"] {
        let mut changed = review.clone();
        let mut key = rig.key.clone();
        let authority = changed.challenge.authority.as_mut().unwrap();
        match mutation {
            "key" => {
                key = SigningKey::from_bytes(&[57; 32]);
                authority.public_key_hex = hex(key.verifying_key().as_bytes());
            }
            "principal" => authority.principal_id = "hum_55555555555555555555555555555555".into(),
            "role" => authority.required_role = "approver".into(),
            _ => unreachable!(),
        }
        let response = WorkstationResponse {
            device_id: rig.device.device_id.clone(),
            decision: WorkstationDecision::Approve,
            signature: hex(&key
                .sign(&workstation_decision_bytes(&changed.challenge, true))
                .to_bytes()),
        };
        let candidate = SignedWorkstationReceipt {
            schema_version: 1,
            review: changed.clone(),
            response: response.clone(),
            accepted_at: now(),
        };
        candidate.verify().unwrap();
        assert_eq!(
            remote.accept(&changed, response, &rig.device).unwrap_err(),
            "remote reviewer authority changed",
            "{mutation}"
        );
        let mut effects = 0;
        assert_eq!(
            remote
                .with_authority(Some(&reviewed_requester()), &candidate, &mut || {
                    effects += 1;
                    Ok(())
                })
                .unwrap_err(),
            "remote reviewer enrollment changed",
            "{mutation}"
        );
        assert_eq!(effects, 0, "{mutation}");
        assert_eq!(
            remote
                .can_read_receipt(&candidate, &rig.device.device_id)
                .unwrap_err(),
            "receipt belongs to another reviewer",
            "{mutation}"
        );
        assert!(
            remote
                .store
                .receipt(&review.challenge.approval_id)
                .unwrap()
                .is_none()
        );
    }
    let receipt = remote
        .accept(&review, rig.response(&review, true), &rig.device)
        .unwrap();
    remote.revalidate(&receipt).unwrap();
}

#[test]
fn valid_signatures_do_not_replace_authenticated_device_or_durable_acceptance() {
    let rig = Rig::new();
    let remote = rig.open();
    let review = rig.review(&remote);
    remote.enqueue(&review).unwrap();
    let mut candidate = SignedWorkstationReceipt {
        schema_version: 1,
        review: review.clone(),
        response: rig.response(&review, true),
        accepted_at: now(),
    };
    candidate.verify().unwrap();
    assert_eq!(
        remote.revalidate(&candidate).unwrap_err(),
        "remote decision is not durably accepted"
    );
    candidate.response.device_id = uuid::Uuid::new_v4().to_string();
    candidate.verify().unwrap();
    assert_eq!(
        remote
            .accept(&review, candidate.response.clone(), &rig.device)
            .unwrap_err(),
        "wrong reviewer device"
    );
    assert_eq!(
        remote
            .can_read_receipt(&candidate, &rig.device.device_id)
            .unwrap_err(),
        "receipt belongs to another reviewer"
    );
    assert!(
        remote
            .store
            .receipt(&review.challenge.approval_id)
            .unwrap()
            .is_none()
    );
    let other_key = SigningKey::from_bytes(&[58; 32]);
    let other = rig
        .pairing
        .enroll_workstation(&WorkstationApproverConfig {
            public_key_hex: hex(other_key.verifying_key().as_bytes()),
            name: "Other enrolled reviewer".into(),
            principal_id: Some("hum_66666666666666666666666666666666".into()),
        })
        .unwrap();
    assert_eq!(
        remote.check_current(&review, Some(&other)).unwrap_err(),
        "remote reviewer authority changed"
    );
    let accepted = remote
        .accept(&review, rig.response(&review, true), &rig.device)
        .unwrap();
    assert_eq!(
        remote
            .can_read_receipt(&accepted, &other.device_id)
            .unwrap_err(),
        "receipt belongs to another reviewer"
    );
    remote.revalidate(&accepted).unwrap();
}
