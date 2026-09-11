//! Actual TLS, disposable enrollment, no native UI and no provider operation.
use ed25519_dalek::Signer;
use opaque_approver::{
    client::{BrokerClient, certificate_fingerprint},
    custody::{self, BrokerEnrollment},
    review,
};
use opaque_core::workstation::{
    SignedWorkstationReceipt, WorkstationDecision, WorkstationResponse, WorkstationReview, hex,
    review_hash, workstation_decision_bytes,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn lost_ack(retain_receipt: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("workstation");
    let mut state = custody::initialize(&directory, "Synthetic reviewer").unwrap();
    let (_, key) = custody::load(&directory).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let id = "00000000-0000-4000-8000-000000000001";
    let body = "One exact synthetic action. No provider credentials.";
    let review: WorkstationReview = serde_json::from_value(serde_json::json!({
        "challenge": { "schema_version": 2, "broker_id": "opq-fixture", "approval_id": id,
            "request_id": "00000000-0000-4000-8000-000000000002", "operation": "github.release_manifest",
            "content_hash": review_hash(body), "nonce": "aa".repeat(32), "created_at": now, "expires_at": now + 60,
            "authority": {"binding": {"tenant": {"schema_version": 1, "tenant_id": "fixture", "broker_id": "00000000-0000-4000-8000-000000000003"},
                "task_id": "00000000-0000-4000-8000-000000000004", "manifest_digest": "bb".repeat(32), "request_hash": "cc".repeat(32), "policy_digest": "dd".repeat(32), "requester": "svc-fixture"},
                "principal_id": "human-fixture", "public_key_hex": state.public_key_hex, "required_role": "operator", "authority_epoch": 1}},
        "review_text": body
    })).unwrap();
    let response = WorkstationResponse {
        device_id: "00000000-0000-4000-8000-000000000005".into(),
        decision: WorkstationDecision::Approve,
        signature: hex(&key
            .sign(&workstation_decision_bytes(&review.challenge, true))
            .to_bytes()),
    };
    let receipt = SignedWorkstationReceipt {
        schema_version: 1,
        review: review.clone(),
        response: response.clone(),
        accepted_at: now,
    };
    receipt.verify().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pin = certificate_fingerprint(certificate.cert.der());
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let enrollment = BrokerEnrollment {
        endpoint: format!("https://{address}"),
        broker_id: "opq-fixture".into(),
        tls_fingerprint: pin.clone(),
        device_id: response.device_id.clone(),
        token: "fixture-only-credential".into(),
    };
    state.enrollment = Some(enrollment.clone());
    let payload = serde_json::to_vec(&receipt).unwrap();
    let server = tokio::spawn(async move {
        let mut methods = Vec::new();
        for index in 0..2 {
            let (socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut stream = acceptor.accept(socket).await.unwrap();
            let mut data = Vec::new();
            loop {
                let mut bytes = [0u8; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                assert!(count > 0 && data.len() + count < 256 * 1024);
                data.extend_from_slice(&bytes[..count]);
                if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = std::str::from_utf8(&data[..end]).unwrap();
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|n| n.parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if data.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let first_line = std::str::from_utf8(&data).unwrap().lines().next().unwrap();
            if index == 0 {
                assert!(first_line.starts_with("POST /workstation/approvals/"));
                methods.push("POST");
                // The synthetic server retained the decision, then lost its acknowledgment.
                drop(stream);
            } else {
                assert!(first_line.starts_with("GET /workstation/receipts/"));
                methods.push("GET");
                let (status, response_body) = if retain_receipt {
                    ("200 OK", payload.as_slice())
                } else {
                    ("404 Not Found", b"{}".as_slice())
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response_body.len()).as_bytes()).await.unwrap();
                stream.write_all(response_body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        }
        methods
    });
    let client = BrokerClient::new(&enrollment.endpoint, &pin).unwrap();
    let report = review::submit(&client, &enrollment, &state, &review, response)
        .await
        .unwrap();
    assert_eq!(server.await.unwrap(), vec!["POST", "GET"]);
    assert_eq!(
        report.decision_status,
        if retain_receipt {
            "accepted"
        } else {
            "unknown"
        }
    );
    assert_eq!(report.recovered_via_receipt, retain_receipt);
    assert_eq!(report.execution_status, "not_observed");
    let mut wrong = receipt.clone();
    wrong.response.device_id = "00000000-0000-4000-8000-000000000099".into();
    assert!(review::validate_receipt(&wrong, &enrollment, &state, id).is_err());
}

#[tokio::test]
async fn lost_ack_recovers_only_the_exact_retained_decision() {
    lost_ack(true).await;
}

#[tokio::test]
async fn missing_receipt_stays_unknown_without_post_retry() {
    lost_ack(false).await;
}
