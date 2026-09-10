//! Dedicated full-review capability. Legacy mobile clients cannot access it.
use super::*;
use opaque_core::workstation::{
    EnrollmentChallenge, EnrollmentRequest, EnrollmentResponse, WorkstationDecision,
    WorkstationResponse, WorkstationReview,
};

#[derive(Debug)]
pub(super) struct PendingWorkstation {
    review: WorkstationReview,
    response_tx: oneshot::Sender<VerifiedDeviceDecision>,
    created_at: Instant,
    timeout: Duration,
}

struct CancelRound {
    state: Arc<ServerState>,
    approval_id: String,
}

impl Drop for CancelRound {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.state.workstation_pending.lock() {
            pending.remove(&self.approval_id);
            if let Some(remote) = &self.state.remote {
                let _ = remote.store.cancel(&self.approval_id);
            }
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl ApprovalServerHandle {
    pub fn authorize_receipt(
        &self,
        requester: Option<&opaque_core::identity::PrincipalContext>,
        receipt: &opaque_core::workstation::SignedWorkstationReceipt,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.state
            .remote
            .as_ref()
            .ok_or("remote authority unavailable")?
            .authorize(requester, receipt, authorize)
    }
    pub fn bind_remote_review(
        &self,
        review: &mut WorkstationReview,
        binding: opaque_core::workstation::ApprovalBinding,
    ) -> Result<(), String> {
        if let Some(remote) = &self.state.remote {
            remote.bind(review, binding)?;
        }
        Ok(())
    }

    pub fn revalidate_receipt(
        &self,
        receipt: &opaque_core::workstation::SignedWorkstationReceipt,
    ) -> Result<(), String> {
        self.state
            .remote
            .as_ref()
            .ok_or("remote approval store unavailable")?
            .revalidate(receipt)
    }
    /// Cancelling this future synchronously removes the issued round. A
    /// disconnected agent cannot leave an actionable workstation prompt.
    pub async fn await_workstation_review(
        &self,
        review: WorkstationReview,
    ) -> Result<VerifiedDeviceDecision, String> {
        review
            .validate(self.state.pairing.server_id(), now())
            .map_err(|_| "invalid full workstation review")?;
        let approval_id = review.challenge.approval_id.clone();
        let timeout = self.timeout().min(Duration::from_secs(
            (review.challenge.expires_at - now()).max(0) as u64,
        ));
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut pending = self
                .state
                .workstation_pending
                .lock()
                .map_err(|_| "workstation approval lock failed")?;
            pending.retain(|_, entry| {
                entry.created_at.elapsed() < entry.timeout
                    && entry.review.challenge.expires_at > now()
            });
            if pending.len() >= 64 || pending.contains_key(&approval_id) {
                return Err("workstation approval capacity unavailable".into());
            }
            if review.challenge.authority.is_some() {
                self.state
                    .remote
                    .as_ref()
                    .ok_or("remote approval store unavailable")?
                    .enqueue(&review)?;
            }
            pending.insert(
                approval_id.clone(),
                PendingWorkstation {
                    review,
                    response_tx,
                    created_at: Instant::now(),
                    timeout,
                },
            );
        }
        let _cancel = CancelRound {
            state: self.state.clone(),
            approval_id,
        };
        tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| "workstation approval timed out".to_owned())?
            .map_err(|_| "workstation approval was cancelled".to_owned())
    }
}

pub(super) fn routes() -> Router<Arc<ServerState>> {
    Router::new()
        .route(
            "/workstation/enrollment/challenge",
            post(enrollment_challenge),
        )
        .route(
            "/workstation/enrollment/complete",
            post(enrollment_complete),
        )
        .route("/workstation/approvals/pending", get(pending))
        .route("/workstation/approvals/{approval_id}", get(review))
        .route("/workstation/receipts/{approval_id}", get(receipt))
        .route(
            "/workstation/approvals/{approval_id}/respond",
            post(respond),
        )
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentStart {
    public_key_hex: String,
}

async fn enrollment_challenge(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<EnrollmentStart>,
) -> Result<Json<EnrollmentChallenge>, StatusCode> {
    state
        .pairing
        .begin_workstation_enrollment(&body.public_key_hex)
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}

async fn enrollment_complete(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, StatusCode> {
    state
        .pairing
        .complete_workstation_enrollment(&body)
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}

fn auth(state: &ServerState, headers: &HeaderMap) -> Result<String, StatusCode> {
    let device = validate_auth(state, headers)?;
    state
        .pairing
        .workstation_device(&device)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(device)
}

async fn pending(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device_id = auth(&state, &headers)?;
    let device = state
        .pairing
        .workstation_device(&device_id)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let mut pending = state
        .workstation_pending
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    pending.retain(|_, entry| {
        entry.created_at.elapsed() < entry.timeout && entry.review.challenge.expires_at > now()
    });
    let mut approvals: Vec<_> = pending
        .values()
        .filter(|entry| {
            entry.review.challenge.authority.is_none()
                || state.remote.as_ref().is_some_and(|remote| {
                    remote.check_current(&entry.review, Some(&device)).is_ok()
                })
        })
        .filter(|entry| {
            entry
                .review
                .challenge
                .authority
                .as_ref()
                .is_none_or(|authority| {
                    authority.public_key_hex == device.public_key_hex
                        && device.paired_by.as_deref() == Some(authority.principal_id.as_str())
                })
        })
        .map(|entry| entry.review.challenge.clone())
        .collect();
    approvals.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then(a.approval_id.cmp(&b.approval_id))
    });
    Ok(Json(serde_json::json!({"approvals": approvals})))
}

async fn review(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<WorkstationReview>, StatusCode> {
    let device_id = auth(&state, &headers)?;
    let device = state
        .pairing
        .workstation_device(&device_id)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let pending = state
        .workstation_pending
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let entry = pending.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    if entry.review.challenge.authority.is_some()
        && state
            .remote
            .as_ref()
            .is_none_or(|remote| remote.check_current(&entry.review, Some(&device)).is_err())
    {
        return Err(StatusCode::NOT_FOUND);
    }
    if entry
        .review
        .challenge
        .authority
        .as_ref()
        .is_some_and(|authority| {
            authority.public_key_hex != device.public_key_hex
                || device.paired_by.as_deref() != Some(authority.principal_id.as_str())
        })
    {
        return Err(StatusCode::NOT_FOUND);
    }
    if entry.created_at.elapsed() >= entry.timeout || entry.review.challenge.expires_at <= now() {
        return Err(StatusCode::GONE);
    }
    Ok(Json(entry.review.clone()))
}

async fn respond(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<WorkstationResponse>,
) -> Result<StatusCode, StatusCode> {
    let authenticated = auth(&state, &headers)?;
    if authenticated != body.device_id {
        return Err(StatusCode::FORBIDDEN);
    }
    // One serialized verification/consume boundary: bad signatures leave the
    // round available; concurrent valid replies can produce only one decision.
    let mut pending = state
        .workstation_pending
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let entry = pending.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    if entry.created_at.elapsed() >= entry.timeout || entry.review.challenge.expires_at <= now() {
        return Err(StatusCode::GONE);
    }
    let approve = body.decision == WorkstationDecision::Approve;
    let device = state
        .pairing
        .verify_workstation_decision(
            &entry.review.challenge,
            &body.signature,
            &body.device_id,
            approve,
        )
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let workstation_receipt = if entry.review.challenge.authority.is_some() {
        Some(
            state
                .remote
                .as_ref()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                .accept(&entry.review, body, &device)
                .map_err(|_| StatusCode::FORBIDDEN)?,
        )
    } else {
        None
    };
    let entry = pending.remove(&id).ok_or(StatusCode::NOT_FOUND)?;
    entry
        .response_tx
        .send(VerifiedDeviceDecision {
            approve,
            device,
            workstation_receipt,
        })
        .map_err(|_| StatusCode::GONE)?;
    Ok(StatusCode::OK)
}

async fn receipt(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<opaque_core::workstation::SignedWorkstationReceipt>, StatusCode> {
    let device = auth(&state, &headers)?;
    let receipt = state
        .remote
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?
        .store
        .receipt(&id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if state
        .remote
        .as_ref()
        .is_none_or(|remote| remote.can_read_receipt(&receipt, &device).is_err())
    {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::{WorkstationApproverConfig, store::DeviceStore};
    use ed25519_dalek::{Signer, SigningKey};
    use opaque_approver::client::{BrokerClient, certificate_fingerprint};
    use opaque_core::workstation::{
        WorkstationChallenge, enrollment_bytes, hex, review_hash, workstation_decision_bytes,
    };

    struct Rig {
        _directory: tempfile::TempDir,
        manager: Arc<PairingManager>,
        server: ApprovalServer,
        key: SigningKey,
        device: EnrollmentResponse,
        certificate: Vec<u8>,
    }

    fn rig() -> Rig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let manager = Arc::new(PairingManager::new(
            "opq-workstation-test".into(),
            SigningKey::from_bytes(&[41; 32]),
            0,
            DeviceStore::new(directory.path().join("devices.json"), vec![42; 32]),
        ));
        let key = SigningKey::from_bytes(&[43; 32]);
        let public_key_hex = hex(key.verifying_key().as_bytes());
        manager
            .enroll_workstation(&WorkstationApproverConfig {
                public_key_hex: public_key_hex.clone(),
                name: "Isolated test signer".into(),
                principal_id: Some("test-human".into()),
            })
            .unwrap();
        let challenge = manager
            .begin_workstation_enrollment(&public_key_hex)
            .unwrap();
        let device = manager
            .complete_workstation_enrollment(&EnrollmentRequest {
                public_key_hex,
                nonce: challenge.nonce.clone(),
                signature: hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes()),
            })
            .unwrap();
        let identity = generate_self_signed_cert().unwrap();
        let certificate = identity.cert_der.clone();
        let server = ApprovalServer::new(
            ApprovalServerConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                tls_cert_der: identity.cert_der,
                tls_key_der: identity.key_der,
                timeout_secs: 60,
            },
            manager.clone(),
        )
        .unwrap();
        Rig {
            _directory: directory,
            manager,
            server,
            key,
            device,
            certificate,
        }
    }

    fn headers(device: &EnrollmentResponse) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", device.token).parse().unwrap(),
        );
        headers.insert("X-Opaque-Device", device.device_id.parse().unwrap());
        headers
    }

    fn document() -> WorkstationReview {
        let text = "Release exact commit 0123456789abcdef\nRepository: owner/repo (repository ID: 123)\nWorkflow: staging.yml\nEnvironment: staging\nSource: vault:kv/data/demo?version=7#VALUE\nBudget: one dispatch";
        WorkstationReview {
            challenge: WorkstationChallenge {
                schema_version: 1,
                authority: None,
                broker_id: "opq-workstation-test".into(),
                approval_id: uuid::Uuid::new_v4().to_string(),
                request_id: uuid::Uuid::new_v4().to_string(),
                operation: "github.release_manifest".into(),
                content_hash: review_hash(text),
                nonce: "09".repeat(32),
                created_at: now(),
                expires_at: now() + 60,
            },
            review_text: text.into(),
        }
    }

    fn signature(rig: &Rig, document: &WorkstationReview, approve: bool) -> WorkstationResponse {
        WorkstationResponse {
            device_id: rig.device.device_id.clone(),
            decision: if approve {
                WorkstationDecision::Approve
            } else {
                WorkstationDecision::Reject
            },
            signature: hex(&rig
                .key
                .sign(&workstation_decision_bytes(&document.challenge, approve))
                .to_bytes()),
        }
    }

    async fn issue(
        handle: &ApprovalServerHandle,
        document: &WorkstationReview,
    ) -> JoinHandle<Result<VerifiedDeviceDecision, String>> {
        let handle_for_task = handle.clone();
        let document = document.clone();
        let id = document.challenge.approval_id.clone();
        let task =
            tokio::spawn(async move { handle_for_task.await_workstation_review(document).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !handle
                .state
                .workstation_pending
                .lock()
                .unwrap()
                .contains_key(&id)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task
    }

    #[tokio::test]
    async fn workstation_rejects_unsigned_changed_and_duplicate_decisions_without_consuming_valid_round()
     {
        let rig = rig();
        let handle = rig.server.handle();
        let document = document();
        let waiting = issue(&handle, &document).await;
        let id = document.challenge.approval_id.clone();
        assert_eq!(
            review(
                State(handle.state.clone()),
                HeaderMap::new(),
                AxumPath(id.clone())
            )
            .await
            .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        let fetched = review(
            State(handle.state.clone()),
            headers(&rig.device),
            AxumPath(id.clone()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(fetched, document);
        let mut wrong_token = headers(&rig.device);
        wrong_token.insert("Authorization", "Bearer incorrect".parse().unwrap());
        assert_eq!(
            pending(State(handle.state.clone()), wrong_token)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        for field in 0..6 {
            let mut changed = document.clone();
            match field {
                0 => changed.challenge.broker_id.push_str("-other"),
                1 => changed.challenge.content_hash = "03".repeat(32),
                2 => changed.challenge.nonce = "04".repeat(32),
                3 => changed.challenge.request_id = uuid::Uuid::new_v4().to_string(),
                4 => changed.challenge.expires_at += 1,
                _ => changed.challenge.approval_id = uuid::Uuid::new_v4().to_string(),
            }
            assert_eq!(
                respond(
                    State(handle.state.clone()),
                    headers(&rig.device),
                    AxumPath(id.clone()),
                    Json(signature(&rig, &changed, true))
                )
                .await
                .unwrap_err(),
                StatusCode::FORBIDDEN
            );
        }
        let mut unsigned = signature(&rig, &document, true);
        unsigned.signature = "00".repeat(64);
        assert_eq!(
            respond(
                State(handle.state.clone()),
                headers(&rig.device),
                AxumPath(id.clone()),
                Json(unsigned)
            )
            .await
            .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        let mut changed_decision = signature(&rig, &document, true);
        changed_decision.decision = WorkstationDecision::Reject;
        assert_eq!(
            respond(
                State(handle.state.clone()),
                headers(&rig.device),
                AxumPath(id.clone()),
                Json(changed_decision)
            )
            .await
            .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        let response = signature(&rig, &document, true);
        let (first, second) = tokio::join!(
            respond(
                State(handle.state.clone()),
                headers(&rig.device),
                AxumPath(id.clone()),
                Json(response.clone())
            ),
            respond(
                State(handle.state.clone()),
                headers(&rig.device),
                AxumPath(id),
                Json(response)
            )
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(waiting.await.unwrap().unwrap().approve);
        assert!(handle.state.workstation_pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn workstation_revocation_and_legacy_kind_deny_access_and_signing() {
        let rig = rig();
        let handle = rig.server.handle();
        let document = document();
        let waiting = issue(&handle, &document).await;
        let (_, nonce) = rig.manager.generate_qr_payload(None);
        let legacy_key = SigningKey::from_bytes(&[51; 32]);
        let (legacy, token) = rig
            .manager
            .complete_pairing(
                &nonce,
                legacy_key.verifying_key().as_bytes(),
                "Legacy phone",
            )
            .unwrap();
        rig.manager.confirm_device(&legacy.device_id).unwrap();
        let legacy = EnrollmentResponse {
            device_id: legacy.device_id,
            token,
            server_id: rig.manager.server_id().into(),
        };
        assert_eq!(
            pending(State(handle.state.clone()), headers(&legacy))
                .await
                .unwrap_err(),
            StatusCode::FORBIDDEN
        );
        assert!(
            rig.manager
                .verify_workstation_decision(
                    &document.challenge,
                    &hex(&legacy_key
                        .sign(&workstation_decision_bytes(&document.challenge, true))
                        .to_bytes()),
                    &legacy.device_id,
                    true
                )
                .is_err()
        );
        rig.manager.revoke_device(&rig.device.device_id).unwrap();
        assert_eq!(
            respond(
                State(handle.state.clone()),
                headers(&rig.device),
                AxumPath(document.challenge.approval_id.clone()),
                Json(signature(&rig, &document, true))
            )
            .await
            .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert!(handle.state.workstation_pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn workstation_cancellation_and_exact_expiry_remove_authority() {
        let rig = rig();
        let handle = rig.server.handle();
        let mut expired = document();
        expired.challenge.created_at = now() - 60;
        expired.challenge.expires_at = now();
        assert!(handle.await_workstation_review(expired).await.is_err());
        let document = document();
        let waiting = issue(&handle, &document).await;
        assert!(
            handle
                .await_workstation_review(document.clone())
                .await
                .is_err()
        );
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert_eq!(
            respond(
                State(handle.state.clone()),
                headers(&rig.device),
                AxumPath(document.challenge.approval_id.clone()),
                Json(signature(&rig, &document, true))
            )
            .await
            .unwrap_err(),
            StatusCode::NOT_FOUND
        );
        let waiting = issue(&handle, &document).await;
        {
            let mut rounds = handle.state.workstation_pending.lock().unwrap();
            rounds
                .get_mut(&document.challenge.approval_id)
                .unwrap()
                .review
                .challenge
                .expires_at = now();
        }
        assert_eq!(
            respond(
                State(handle.state.clone()),
                headers(&rig.device),
                AxumPath(document.challenge.approval_id.clone()),
                Json(signature(&rig, &document, true))
            )
            .await
            .unwrap_err(),
            StatusCode::GONE
        );
        waiting.abort();
        let _ = waiting.await;
    }

    #[tokio::test]
    async fn workstation_real_tls_pins_enrollment_full_review_and_signed_rejection() {
        let rig = rig();
        let handle = rig.server.handle();
        let document = document();
        let waiting = issue(&handle, &document).await;
        let Rig {
            server,
            certificate,
            manager,
            key,
            _directory,
            ..
        } = rig;
        let (server_task, address) = server.start().await.unwrap();
        // A separate peer that never starts TLS cannot hold up the reviewer.
        let _stalled_handshake = tokio::net::TcpStream::connect(address).await.unwrap();
        let endpoint = format!("https://{address}");
        let wrong_pin = BrokerClient::new(&endpoint, &"00".repeat(32)).unwrap();
        assert!(
            wrong_pin
                .request::<serde_json::Value>(
                    reqwest::Method::GET,
                    "/workstation/approvals/pending",
                    None,
                    None
                )
                .await
                .is_err()
        );
        let client = BrokerClient::new(&endpoint, &certificate_fingerprint(&certificate)).unwrap();
        let public_key = hex(key.verifying_key().as_bytes());
        let challenge: EnrollmentChallenge = client
            .request(
                reqwest::Method::POST,
                "/workstation/enrollment/challenge",
                Some(serde_json::json!({"public_key_hex": public_key})),
                None,
            )
            .await
            .unwrap();
        challenge
            .validate(manager.server_id(), &public_key, now())
            .unwrap();
        let enrollment: EnrollmentResponse = client
            .request(
                reqwest::Method::POST,
                "/workstation/enrollment/complete",
                Some(
                    serde_json::to_value(EnrollmentRequest {
                        public_key_hex: public_key,
                        nonce: challenge.nonce.clone(),
                        signature: hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes()),
                    })
                    .unwrap(),
                ),
                None,
            )
            .await
            .unwrap();
        let credentials = Some((enrollment.device_id.as_str(), enrollment.token.as_str()));
        let listing: serde_json::Value = client
            .request(
                reqwest::Method::GET,
                "/workstation/approvals/pending",
                None,
                credentials,
            )
            .await
            .unwrap();
        assert_eq!(
            listing["approvals"][0]["approval_id"],
            document.challenge.approval_id
        );
        assert!(listing["approvals"][0].get("review_text").is_none());
        let route = format!("/workstation/approvals/{}", document.challenge.approval_id);
        let fetched: WorkstationReview = client
            .request(reqwest::Method::GET, &route, None, credentials)
            .await
            .unwrap();
        fetched.validate(manager.server_id(), now()).unwrap();
        assert_eq!(fetched, document);
        let response = WorkstationResponse {
            device_id: enrollment.device_id.clone(),
            decision: WorkstationDecision::Reject,
            signature: hex(&key
                .sign(&workstation_decision_bytes(&fetched.challenge, false))
                .to_bytes()),
        };
        let _: serde_json::Value = client
            .request(
                reqwest::Method::POST,
                &format!("{route}/respond"),
                Some(serde_json::to_value(response).unwrap()),
                credentials,
            )
            .await
            .unwrap();
        assert!(!waiting.await.unwrap().unwrap().approve);
        server_task.abort();
    }
}
