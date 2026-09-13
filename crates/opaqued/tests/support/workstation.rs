//! Scripted test ceremony using the production pinned-TLS workstation client.
//! This never calls the native UI or claims human presence. The daemon must
//! enable explicit workstation_test_mode while retaining all real checks.
use ed25519_dalek::{Signer, SigningKey};
use opaque_approver::{
    client::{BrokerClient, certificate_fingerprint},
    custody::{self, BrokerEnrollment, WorkstationState},
    review,
};
use opaque_core::workstation::{
    EnrollmentChallenge, EnrollmentRequest, EnrollmentResponse, SignedWorkstationReceipt,
    WorkstationChallenge, WorkstationDecision, WorkstationResponse, WorkstationReview,
    enrollment_bytes, hex, workstation_decision_bytes,
};
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
pub struct ScriptedWorkstation {
    pub state: WorkstationState,
    key: SigningKey,
    client: Option<BrokerClient>,
}
impl ScriptedWorkstation {
    pub fn new(directory: &Path) -> Self {
        let state = custody::initialize(directory, "Synthetic CI reviewer").unwrap();
        let (_, key) = custody::load(directory).unwrap();
        Self {
            state,
            key,
            client: None,
        }
    }
    pub async fn enroll(&mut self, endpoint: &str, certificate: &[u8]) {
        let fingerprint = certificate_fingerprint(certificate);
        let client = BrokerClient::new(endpoint, &fingerprint).unwrap();
        // Negative pin control: fixture credentials never leave custody when
        // the live server certificate does not match its configured pin.
        assert!(
            BrokerClient::new(endpoint, &"00".repeat(32))
                .unwrap()
                .request::<Value>(
                    reqwest::Method::POST,
                    "/workstation/enrollment/challenge",
                    Some(json!({"public_key_hex":self.state.public_key_hex})),
                    None
                )
                .await
                .is_err()
        );
        let challenge: EnrollmentChallenge = client
            .request(
                reqwest::Method::POST,
                "/workstation/enrollment/challenge",
                Some(json!({"public_key_hex":self.state.public_key_hex})),
                None,
            )
            .await
            .unwrap();
        challenge
            .validate(&challenge.broker_id, &self.state.public_key_hex, now())
            .unwrap();
        let request = EnrollmentRequest {
            public_key_hex: self.state.public_key_hex.clone(),
            nonce: challenge.nonce.clone(),
            signature: hex(&self.key.sign(&enrollment_bytes(&challenge)).to_bytes()),
        };
        let response: EnrollmentResponse = client
            .request(
                reqwest::Method::POST,
                "/workstation/enrollment/complete",
                Some(serde_json::to_value(request).unwrap()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.server_id, challenge.broker_id);
        assert_eq!(response.token.len(), 64);
        self.state.enrollment = Some(BrokerEnrollment {
            endpoint: endpoint.into(),
            broker_id: response.server_id,
            tls_fingerprint: fingerprint,
            device_id: response.device_id,
            token: response.token,
        });
        self.client = Some(client);
    }
    pub fn reconnect(&mut self, certificate: &[u8]) {
        let enrollment = self.state.enrollment.as_ref().unwrap();
        assert_eq!(
            certificate_fingerprint(certificate),
            enrollment.tls_fingerprint,
            "restart changed pinned TLS identity"
        );
        self.client =
            Some(BrokerClient::new(&enrollment.endpoint, &enrollment.tls_fingerprint).unwrap());
    }
    pub async fn pending(&self) -> Vec<WorkstationChallenge> {
        #[derive(serde::Deserialize)]
        struct Pending {
            approvals: Vec<WorkstationChallenge>,
        }
        let e = self.state.enrollment.as_ref().unwrap();
        let pending: Pending = self
            .client
            .as_ref()
            .unwrap()
            .request(
                reqwest::Method::GET,
                "/workstation/approvals/pending",
                None,
                Some((&e.device_id, &e.token)),
            )
            .await
            .unwrap();
        for item in &pending.approvals {
            item.validate(&e.broker_id, now()).unwrap();
        }
        pending.approvals
    }
    pub async fn wait_review(&self, operation: &str) -> WorkstationReview {
        let end = Instant::now() + Duration::from_secs(8);
        loop {
            let pending = self.pending().await;
            assert!(
                pending.len() <= 1,
                "fixture created competing review rounds"
            );
            if let Some(challenge) = pending.first() {
                assert_eq!(challenge.operation, operation);
                let e = self.state.enrollment.as_ref().unwrap();
                let review: WorkstationReview = self
                    .client
                    .as_ref()
                    .unwrap()
                    .request(
                        reqwest::Method::GET,
                        &format!("/workstation/approvals/{}", challenge.approval_id),
                        None,
                        Some((&e.device_id, &e.token)),
                    )
                    .await
                    .unwrap();
                review.validate(&e.broker_id, now()).unwrap();
                assert_eq!(&review.challenge, challenge);
                return review;
            }
            assert!(Instant::now() < end, "expected review never became pending");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    pub async fn respond(
        &self,
        review: &WorkstationReview,
        approve: bool,
    ) -> Result<Value, String> {
        let e = self.state.enrollment.as_ref().unwrap();
        let response = WorkstationResponse {
            device_id: e.device_id.clone(),
            decision: if approve {
                WorkstationDecision::Approve
            } else {
                WorkstationDecision::Reject
            },
            signature: hex(&self
                .key
                .sign(&workstation_decision_bytes(&review.challenge, approve))
                .to_bytes()),
        };
        self.client
            .as_ref()
            .unwrap()
            .request(
                reqwest::Method::POST,
                &format!(
                    "/workstation/approvals/{}/respond",
                    review.challenge.approval_id
                ),
                Some(serde_json::to_value(response).unwrap()),
                Some((&e.device_id, &e.token)),
            )
            .await
    }
    pub async fn receipt(&self, id: &str) -> SignedWorkstationReceipt {
        let e = self.state.enrollment.as_ref().unwrap();
        let receipt = review::receipt(self.client.as_ref().unwrap(), e, &self.state, id)
            .await
            .unwrap();
        // Independently verify the retained response with the enrolled key,
        // beyond trusting either the daemon's acknowledgment or task status.
        let signature = ed25519_dalek::Signature::from_bytes(
            &opaque_core::workstation::decode_hex::<64>(&receipt.response.signature).unwrap(),
        );
        self.key
            .verifying_key()
            .verify_strict(
                &workstation_decision_bytes(
                    &receipt.review.challenge,
                    receipt.response.decision == WorkstationDecision::Approve,
                ),
                &signature,
            )
            .unwrap();
        receipt
    }
}
