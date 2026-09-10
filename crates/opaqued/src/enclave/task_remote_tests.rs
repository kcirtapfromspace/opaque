//! Remote signed decisions through the real task ledger and provider dispatch.
//! Only the human signing ceremony is automated. Identity, pairing, durable
//! acceptance, final authority guards and loopback HTTP effects are production code.
use super::*;
use crate::identity::{IdentityConfig, IdentityRuntime, store::DelegationRecord};
use ed25519_dalek::{Signer, SigningKey};
use opaque_approval::{
    pairing::{PairingManager, WorkstationApproverConfig, store::DeviceStore},
    remote::{RemoteApprovalConfig, RemoteApprovals, ReviewerAuthorityGuard, ReviewerResolver},
};
use opaque_core::{
    audit::InMemoryAuditEmitter,
    identity::{AccessMode, PrincipalId, Role},
    task::TaskState,
    tenant::{TenantBinding, TenantId},
    workstation::{
        ApprovalBinding, EnrollmentRequest, SignedWorkstationReceipt, WorkstationChallenge,
        WorkstationDecision, WorkstationResponse, WorkstationReview, enrollment_bytes, hex,
        review_hash, workstation_decision_bytes,
    },
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt,
    sync::{Mutex, atomic::AtomicUsize},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct ReceiptGate {
    remote: Arc<RemoteApprovals>,
    pairing: Arc<PairingManager>,
    key: SigningKey,
    device_id: String,
    receipt: Arc<Mutex<Option<SignedWorkstationReceipt>>>,
    authorized_dispatches: Arc<AtomicUsize>,
    prompts: Arc<AtomicUsize>,
}
impl std::fmt::Debug for ReceiptGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntheticRemoteCeremony")
            .finish_non_exhaustive()
    }
}
impl ApprovalGate for ReceiptGate {
    fn request_approval(
        &self,
        _: Uuid,
        _: &OperationRequest,
        _: &[ApprovalFactor],
        _: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalOutcome, String>> + Send + '_>> {
        Box::pin(async { Err("remote test requires a fully bound task".into()) })
    }
    fn request_bound_approval(
        &self,
        approval_id: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        description: &str,
        binding: Option<ApprovalBinding>,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalOutcome, String>> + Send + '_>> {
        assert_eq!(factors, [ApprovalFactor::PairedWorkstation]);
        let request_id = request.request_id;
        let operation = request.operation.clone();
        let text = description.to_owned();
        Box::pin(async move {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            let mut review = WorkstationReview {
                challenge: WorkstationChallenge {
                    schema_version: 1,
                    authority: None,
                    broker_id: self.pairing.server_id().into(),
                    approval_id: approval_id.to_string(),
                    request_id: request_id.to_string(),
                    operation,
                    content_hash: review_hash(&text),
                    nonce: "73".repeat(32),
                    created_at: now_unix(),
                    expires_at: now_unix() + 120,
                },
                review_text: text,
            };
            self.remote
                .bind(&mut review, binding.ok_or("missing task binding")?)?;
            self.remote.enqueue(&review)?;
            let response = WorkstationResponse {
                device_id: self.device_id.clone(),
                decision: WorkstationDecision::Approve,
                signature: hex(&self
                    .key
                    .sign(&workstation_decision_bytes(&review.challenge, true))
                    .to_bytes()),
            };
            let device = self
                .pairing
                .workstation_device(&self.device_id)
                .map_err(|e| e.to_string())?;
            let receipt = self.remote.accept(&review, response, &device)?;
            *self.receipt.lock().unwrap() = Some(receipt.clone());
            Ok(ApprovalOutcome {
                approved: true,
                approver: None,
                workstation_receipt: Some(receipt),
            })
        })
    }
    fn revalidate_receipt(&self, receipt: &SignedWorkstationReceipt) -> Result<(), String> {
        self.remote.revalidate(receipt)
    }
    fn authorize_receipt(
        &self,
        requester: Option<&PrincipalContext>,
        receipt: &SignedWorkstationReceipt,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.remote.authorize(requester, receipt, &mut || {
            // Increment only after the real task ledger authorizes this slot.
            authorize()?;
            self.authorized_dispatches.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Mutation {
    None,
    RequesterDisabled,
    DelegationRevoked,
    ReviewerDisabled,
    ReviewerRoleRemoved,
    ReviewerRoleRegranted,
    DeviceRevoked,
}

struct Fixture {
    _directory: tempfile::TempDir,
    provider: MockServer,
    identity: Arc<IdentityRuntime>,
    reviewer: PrincipalId,
    context: PrincipalContext,
    pairing: Arc<PairingManager>,
    remote: Arc<RemoteApprovals>,
    device_id: String,
    enclave: Enclave,
    store: TaskStore,
    task: TaskRecord,
    owner: String,
    receipt: Arc<Mutex<Option<SignedWorkstationReceipt>>>,
    authorized_dispatches: Arc<AtomicUsize>,
    prompts: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = Arc::new(
            IdentityRuntime::initialize(
                IdentityConfig {
                    issuer: "https://remote-test-idp.example".into(),
                    client_id: "fixture".into(),
                    audience: None,
                    redirect_port: None,
                    session_ttl_secs: None,
                    allowed_email_domains: vec![],
                    allowed_subjects: vec!["requester".into(), "reviewer".into()],
                    required: true,
                    persona: None,
                    service_principals: vec![],
                },
                directory.path(),
            )
            .unwrap(),
        );
        let roles = BTreeSet::from([Role::Operator]);
        let requester = identity
            .store
            .upsert_human(&identity.config.issuer, "requester", None, None, &roles)
            .unwrap();
        let reviewer = identity
            .store
            .upsert_human(&identity.config.issuer, "reviewer", None, None, &roles)
            .unwrap();
        let actor = identity.store.upsert_agent("remote-fixture-agent").unwrap();
        let session = identity
            .store
            .create_human_session(&requester.id, 600, &identity.config.issuer)
            .unwrap();
        let context = PrincipalContext {
            sub: requester.id,
            sub_label: "Fixture requester".into(),
            sub_roles: roles,
            sub_teams: vec![],
            act: actor.id,
            act_label: "Fixture agent".into(),
            mode: AccessMode::Delegated,
            jti: Uuid::new_v4().to_string(),
            human_session_id: Some(session.id),
        };
        identity
            .store
            .record_delegation(&DelegationRecord {
                jti: context.jti.clone(),
                sub_principal: context.sub.clone(),
                act_principal: context.act.clone(),
                mode: context.mode,
                human_session_id: context.human_session_id.clone(),
                approved_by: Some(context.sub.clone()),
                created_at: now_unix(),
                expires_at: now_unix() + 600,
                revoked_at: None,
            })
            .unwrap();
        let tenant = TenantBinding::new(
            TenantId::parse("remote-task-fixture").unwrap(),
            Uuid::new_v4(),
        )
        .unwrap();
        let pairing = Arc::new(PairingManager::new(
            "remote-task-broker".into(),
            SigningKey::from_bytes(&[81; 32]),
            0,
            DeviceStore::new(directory.path().join("devices.json"), vec![82; 32]),
        ));
        let key = SigningKey::from_bytes(&[83; 32]);
        let public_key = hex(key.verifying_key().as_bytes());
        let device = pairing
            .enroll_workstation(&WorkstationApproverConfig {
                public_key_hex: public_key.clone(),
                name: "Fixture reviewer".into(),
                principal_id: Some(reviewer.id.to_string()),
            })
            .unwrap();
        let enrollment = pairing.begin_workstation_enrollment(&public_key).unwrap();
        pairing
            .complete_workstation_enrollment(&EnrollmentRequest {
                public_key_hex: public_key.clone(),
                nonce: enrollment.nonce.clone(),
                signature: hex(&key.sign(&enrollment_bytes(&enrollment)).to_bytes()),
            })
            .unwrap();
        let resolver_identity = identity.clone();
        let resolver: ReviewerResolver = Arc::new(move |principal, role| {
            resolver_identity.reviewer_eligibility(
                &PrincipalId::parse(principal).map_err(|e| e.to_string())?,
                role.parse().map_err(|_| "invalid role")?,
            )
        });
        let guard_identity = identity.clone();
        let guard: ReviewerAuthorityGuard =
            Arc::new(move |requester, principal, role, epoch, authorize| {
                let principal = PrincipalId::parse(principal).map_err(|e| e.to_string())?;
                guard_identity.with_dispatch_authority(
                    requester,
                    Some((&principal, role.parse().map_err(|_| "invalid role")?, epoch)),
                    authorize,
                )
            });
        let remote = RemoteApprovals::open(
            RemoteApprovalConfig {
                reviewer_public_key_hex: public_key,
                required_role: "operator".into(),
                notice_token_file: None,
            },
            &directory.path().join("remote.db"),
            tenant.clone(),
            pairing.clone(),
            resolver,
            guard,
        )
        .unwrap();

        // The compiled public inference fixture needs no token, environment
        // change, keychain access, model download or external network.
        let provider = MockServer::start().await;
        let profile = opaque_bounded_work::inference::InferenceProfileConfig {
            profile_id: "remote-fixture".into(),
            api_url: provider.uri(),
            model_id: "fixture-model.gguf".into(),
            model_path: "/models/fixture-model.gguf".into(),
            model_artifact_sha256: "a".repeat(64),
            chat_template_sha256: review_hash("fixed-template-v1"),
            server_build: "remote-fixture-v1".into(),
            service_uid: Uuid::new_v4(),
            source_id: opaque_bounded_work::inference::DEMO_SOURCE_ID.into(),
            source_snapshot_sha256: opaque_bounded_work::inference::demo_source_snapshot_sha256(),
            credential_ref: None,
            allow_loopback_http: true,
        }
        .bind(&tenant)
        .unwrap();
        for (verb, endpoint, body) in [
            ("GET", "/health", json!({"status":"ok"})),
            (
                "GET",
                "/props",
                json!({"model_path":profile.model_path,"build_info":profile.server_build,"chat_template":"fixed-template-v1","total_slots":1,"default_generation_settings":{"n_ctx":2048}}),
            ),
            (
                "GET",
                "/v1/models",
                json!({"data":[{"id":profile.model_id}]}),
            ),
            (
                "POST",
                "/apply-template",
                json!({"prompt":"formatted public fixture"}),
            ),
            ("POST", "/tokenize", json!({"tokens":[10,11,12]})),
            (
                "POST",
                "/completion",
                json!({"content":"Artifact smoke passed. Service health was not observed.","model":profile.model_id,"stop":true,"truncated":false,"stop_type":"eos","tokens_evaluated":3,"tokens_predicted":8,"tokens":[1,2,3,4,5,6,7,8],"generation_settings":{"n_predict":96}}),
            ),
        ] {
            Mock::given(method(verb))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&provider)
                .await;
        }
        let manifest = opaque_bounded_work::inference::public_demo_manifest(
            &profile,
            "Three signed public fixture completions".into(),
            300,
        )
        .unwrap();
        let store =
            TaskStore::open_for_tenant(&directory.path().join("tasks.db"), Some(tenant.clone()))
                .unwrap();
        let owner = tenant.owner_key(501, Some(&context.sub));
        let task = store.create(&owner, manifest, now_unix()).unwrap();
        let mut registry = OperationRegistry::new();
        for operation in inference_task_operations() {
            registry.register(operation).unwrap();
        }
        let rules = ["inference.fixed_manifest", "inference.fixed_completion"].into_iter().map(|operation| {
            serde_json::from_value(json!({"name":operation,"operation_pattern":operation,"allow":true,"client_types":["agent"],"approval":{"require":"always","factors":["paired_workstation"]}})).unwrap()
        }).collect();
        let receipt = Arc::new(Mutex::new(None));
        let authorized_dispatches = Arc::new(AtomicUsize::new(0));
        let prompts = Arc::new(AtomicUsize::new(0));
        let enclave = Enclave::builder()
            .registry(registry)
            .policy(PolicyEngine::with_rules(rules))
            .inference_profile(Some(profile))
            .approval_gate(Box::new(ReceiptGate {
                remote: remote.clone(),
                pairing: pairing.clone(),
                key,
                device_id: device.device_id.clone(),
                receipt: receipt.clone(),
                authorized_dispatches: authorized_dispatches.clone(),
                prompts: prompts.clone(),
            }))
            .audit(Arc::new(InMemoryAuditEmitter::new()))
            .build()
            .unwrap();
        Self {
            _directory: directory,
            provider,
            identity,
            reviewer: reviewer.id,
            context,
            pairing,
            remote,
            device_id: device.device_id,
            enclave,
            store,
            task,
            owner,
            receipt,
            authorized_dispatches,
            prompts,
        }
    }

    fn request(&self) -> OperationRequest {
        OperationRequest {
            principal: Some(self.context.clone()),
            request_id: Uuid::new_v4(),
            client_type: ClientType::Agent,
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(4242),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            operation: "inference.fixed_manifest".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::Value::Null,
            workspace: None,
        }
    }
    fn mutate(&self, mutation: Mutation) {
        match mutation {
            Mutation::None => {}
            Mutation::RequesterDisabled => self
                .identity
                .store
                .set_disabled(&self.context.sub, true)
                .unwrap(),
            Mutation::DelegationRevoked => {
                assert!(
                    self.identity
                        .store
                        .revoke_delegation(&self.context.jti)
                        .unwrap()
                );
            }
            Mutation::ReviewerDisabled => self
                .identity
                .store
                .set_disabled(&self.reviewer, true)
                .unwrap(),
            Mutation::ReviewerRoleRemoved => self
                .identity
                .store
                .set_roles(&self.reviewer, &BTreeSet::new())
                .unwrap(),
            Mutation::ReviewerRoleRegranted => {
                self.identity
                    .store
                    .set_roles(&self.reviewer, &BTreeSet::new())
                    .unwrap();
                self.identity
                    .store
                    .set_roles(&self.reviewer, &BTreeSet::from([Role::Operator]))
                    .unwrap();
            }
            Mutation::DeviceRevoked => self.pairing.revoke_device(&self.device_id).unwrap(),
        }
    }
    async fn run(&self, mutation: Mutation) -> Result<TaskRecord, String> {
        let checks = AtomicUsize::new(0);
        tokio::time::timeout(
            Duration::from_secs(10),
            self.enclave.execute_task(
                &self.store,
                &self.owner,
                &self.task.id,
                self.request(),
                TaskApprovalMode::Native,
                || {
                    // Deliberately return the old asynchronous snapshot. The second
                    // check occurs after reservation and HTTP preparation, directly
                    // before the actual remote+identity+task dispatch fence.
                    if checks.fetch_add(1, Ordering::SeqCst) == 1 {
                        self.mutate(mutation);
                    }
                    let context = self.context.clone();
                    async move { Ok(Some(context)) }
                },
            ),
        )
        .await
        .expect("bounded remote task fixture timed out")
    }
    async fn effects(&self) -> Vec<wiremock::Request> {
        self.provider
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == "/completion")
            .collect()
    }
}

#[tokio::test]
async fn signed_remote_receipt_drives_real_bounded_effects_once_and_survives_restart() {
    let f = Fixture::new().await;
    let completed = f.run(Mutation::None).await.unwrap();
    assert_eq!(completed.state, TaskState::Completed);
    assert_eq!(
        completed.approval_mode,
        Some(TaskApprovalMode::PairedWorkstation)
    );
    assert_eq!(f.authorized_dispatches.load(Ordering::SeqCst), 3);
    let effects = f.effects().await;
    assert_eq!(effects.len(), 3);
    for effect in effects {
        assert!(!effect.headers.contains_key("authorization"));
        let body: serde_json::Value = serde_json::from_slice(&effect.body).unwrap();
        assert_eq!(body["model"], "fixture-model.gguf");
        assert_eq!(body["prompt"], json!([10, 11, 12]));
        assert_eq!(body["n_predict"], 96);
    }
    let receipt = f.receipt.lock().unwrap().clone().unwrap();
    receipt.verify().unwrap();
    let reference = completed.workstation_receipt.as_ref().unwrap();
    assert_eq!(reference.approval_id, receipt.review.challenge.approval_id);
    assert_eq!(
        reference.sha256,
        review_hash(&serde_json::to_string(&receipt).unwrap())
    );
    assert_eq!(
        f.remote.store.receipt(&reference.approval_id).unwrap(),
        Some(receipt.clone())
    );
    let device = f.pairing.workstation_device(&f.device_id).unwrap();
    assert!(
        f.remote
            .accept(&receipt.review, receipt.response.clone(), &device)
            .is_err()
    );
    assert!(f.run(Mutation::None).await.is_err());
    assert_eq!(f.prompts.load(Ordering::SeqCst), 1);
    assert_eq!(f.effects().await.len(), 3);

    let path = f._directory.path().join("tasks.db");
    let tenant = completed.tenant.clone();
    let owner = f.owner.clone();
    let id = completed.id.clone();
    let Fixture {
        _directory: directory,
        store,
        enclave,
        remote,
        ..
    } = f;
    drop(enclave);
    drop(remote);
    drop(store);
    let reopened = TaskStore::open_for_tenant(&path, tenant.clone()).unwrap();
    let recovered = reopened.get(&id, &owner, now_unix()).unwrap();
    assert_eq!(recovered.state, TaskState::Completed);
    assert_eq!(recovered.workstation_receipt, completed.workstation_receipt);
    assert!(reopened.claim(&id, &owner, now_unix()).is_err());
    let decisions = opaque_approval::remote::store::RemoteStore::open(
        &directory.path().join("remote.db"),
        tenant.unwrap(),
        receipt.review.challenge.broker_id.clone(),
    )
    .unwrap();
    assert_eq!(
        decisions
            .receipt(&receipt.review.challenge.approval_id)
            .unwrap(),
        Some(receipt)
    );
}

#[tokio::test]
async fn requester_reviewer_and_device_revocation_at_real_dispatch_fence_block_all_effects() {
    for mutation in [
        Mutation::RequesterDisabled,
        Mutation::DelegationRevoked,
        Mutation::ReviewerDisabled,
        Mutation::ReviewerRoleRemoved,
        Mutation::ReviewerRoleRegranted,
        Mutation::DeviceRevoked,
    ] {
        let f = Fixture::new().await;
        let result = f.run(mutation).await.unwrap();
        assert_eq!(result.state, TaskState::Partial, "{mutation:?}");
        assert!(
            result.approved_at.is_some(),
            "mutation must occur after signed approval"
        );
        assert!(result.workstation_receipt.is_some());
        assert!(
            result.slots[0].reserved_at.is_some(),
            "mutation must reach the final dispatch check"
        );
        assert_eq!(result.slots[0].state, SlotState::Rejected, "{mutation:?}");
        assert_eq!(
            result.slots[0].outcome.as_ref().unwrap().code,
            "reviewer_or_task_authority_changed",
            "{mutation:?}"
        );
        assert!(
            result.slots[1..]
                .iter()
                .all(|slot| slot.reserved_at.is_none())
        );
        assert_eq!(
            f.authorized_dispatches.load(Ordering::SeqCst),
            0,
            "{mutation:?}"
        );
        assert!(f.effects().await.is_empty(), "{mutation:?}");
        let receipt = f.receipt.lock().unwrap().clone().unwrap();
        assert_eq!(
            f.remote
                .store
                .receipt(&receipt.review.challenge.approval_id)
                .unwrap(),
            Some(receipt)
        );
        assert!(f.run(Mutation::None).await.is_err());
        assert!(f.effects().await.is_empty());
        assert_eq!(f.prompts.load(Ordering::SeqCst), 1);
    }
}
