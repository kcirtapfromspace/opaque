//! Real listener/peer-credential regressions for guards before RPC dispatch.
//! The prepared test operation appends and syncs a fixture-owned file. It is
//! deliberately effectful so a silently successful forbidden dispatch fails.

use super::*;
use futures_util::SinkExt;
use opaque_core::approval_gate::ApprovalOutcome;
use opaque_core::audit::InMemoryAuditEmitter;
use opaque_core::operation_handler::PreparedOperation;
use serde_json::{Value, json};
use std::io::Write;
use std::time::Duration;

const OPERATION: &str = "test.connection_effect";
const SESSION: &str = "connection-flow-session";
const TOKEN: &str = "connection-flow-token";
const BOUND: Duration = Duration::from_secs(1);
// Match the existing real daemon identity RPC fixture: a response includes
// freshly hashing the actual caller executable before the handshake. The
// one-second handler shutdown bound stays separate from that setup cost.
const RESPONSE_BOUND: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct UnexpectedApproval;

impl ApprovalGate for UnexpectedApproval {
    fn request_approval(
        &self,
        _: Uuid,
        _: &OperationRequest,
        _: &[ApprovalFactor],
        _: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalOutcome, String>> + Send + '_>> {
        Box::pin(async { panic!("the explicitly ungated test effect must not request approval") })
    }
}

#[derive(Debug)]
struct DurableEffect {
    path: PathBuf,
    prepared: Arc<AtomicUsize>,
}

impl OperationHandler for DurableEffect {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        assert_eq!(request.operation, OPERATION);
        self.prepared.fetch_add(1, Ordering::SeqCst);
        PreparedOperation::new(
            json!({"action":"connection-effect.v1"}),
            HashMap::new(),
            vec![],
            |_| async {
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&self.path)
                    .map_err(|e| e.to_string())?;
                file.write_all(b"effect\n").map_err(|e| e.to_string())?;
                file.sync_all().map_err(|e| e.to_string())?;
                Ok(json!({"committed":true}))
            },
        )
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    state: Arc<DaemonState>,
    audit: Arc<InMemoryAuditEmitter>,
    prepared: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new(enforce_uid_split: bool, enforce_sessions: bool) -> Self {
        // Unix socket paths must fit sockaddr_un even on macOS.
        let directory = tempfile::Builder::new()
            .prefix("opq-conn-")
            .tempdir_in("/tmp")
            .unwrap();
        let path = directory.path().join("effects");
        std::fs::File::create(&path).unwrap().sync_all().unwrap();
        let prepared = Arc::new(AtomicUsize::new(0));
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mut state = crate::tests::build_test_state(audit.clone(), false);
        state.config.trust_domain.enforce = enforce_uid_split;
        state.config.enforce_agent_sessions = enforce_sessions;
        let mut registry = OperationRegistry::new();
        registry
            .register(OperationDef {
                name: OPERATION.into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Never,
                default_factors: vec![],
                description: "Append one durable test effect".into(),
                params_schema: None,
                allowed_target_keys: vec![],
                secret_ref_param_keys: vec![],
            })
            .unwrap();
        let rule = serde_json::from_value::<PolicyRule>(json!({
            "name":"connection-effect", "operation_pattern":OPERATION, "allow":true,
            "approval":{"require":"never"}
        }))
        .unwrap();
        state.enclave = Arc::new(
            Enclave::builder()
                .registry(registry)
                .policy(PolicyEngine::with_rules(vec![rule]))
                .handler(
                    OPERATION,
                    Box::new(DurableEffect {
                        path,
                        prepared: prepared.clone(),
                    }),
                )
                .approval_gate(Box::new(UnexpectedApproval))
                .audit(audit.clone())
                .build()
                .unwrap(),
        );
        if enforce_sessions {
            state.agent_sessions.write().await.insert(
                SESSION.into(),
                AgentSession {
                    session_id: SESSION.into(),
                    token: TOKEN.into(),
                    created_by_uid: unsafe { libc::geteuid() },
                    expires_at: SystemTime::now() + Duration::from_secs(300),
                    label: Some("connection-flow".into()),
                    delegation: None,
                },
            );
        }
        Self {
            directory,
            state: Arc::new(state),
            audit,
            prepared,
        }
    }

    async fn connect(&self) -> Connection {
        let path = self
            .directory
            .path()
            .join(format!("{}.sock", Uuid::new_v4()));
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let peer = peer_info_from_fd(server.as_raw_fd()).expect("kernel peer credentials");
        assert_eq!(peer.uid, unsafe { libc::geteuid() });
        assert_eq!(peer.pid, Some(std::process::id() as i32));
        drop(listener);
        std::fs::remove_file(path).unwrap();
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let state = self.state.clone();
        let task = tokio::spawn(handle_conn(state, server, rx));
        Connection {
            client: Framed::new(
                client,
                LengthDelimitedCodec::builder()
                    .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
                    .new_codec(),
            ),
            task,
            _shutdown: shutdown,
        }
    }

    fn assert_effects(&self, count: usize) {
        for event in self.audit.events_of_kind(AuditEventKind::WorkloadAttested) {
            let client = event
                .client
                .expect("listener-established identity is audited");
            assert_eq!(client.uid, unsafe { libc::geteuid() });
            assert_eq!(client.pid, Some(std::process::id() as i32));
            assert_eq!(client.client_type, ClientType::Agent);
            assert!(client.exe_sha256_prefix.is_some_and(
                |hash| hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            ));
        }
        assert_eq!(self.prepared.load(Ordering::SeqCst), count);
        assert_eq!(
            std::fs::read(self.directory.path().join("effects")).unwrap(),
            b"effect\n".repeat(count)
        );
        for kind in [
            AuditEventKind::OperationStarted,
            AuditEventKind::OperationSucceeded,
        ] {
            assert_eq!(
                self.audit
                    .events_of_kind(kind)
                    .iter()
                    .filter(|event| event.operation.as_deref() == Some(OPERATION))
                    .count(),
                count
            );
        }
    }
}

struct Connection {
    client: Framed<UnixStream, LengthDelimitedCodec>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        // A failed assertion must not leave an owned connection task behind.
        // Successful paths explicitly join and assert its result below.
        self.task.abort();
    }
}

impl Connection {
    async fn send(&mut self, value: Value) {
        self.client
            .send(Bytes::from(serde_json::to_vec(&value).unwrap()))
            .await
            .unwrap();
    }

    async fn handshake(&mut self, token: Option<&str>) {
        let mut handshake = json!({"handshake":"v1", "daemon_token":"test_token"});
        if let Some(token) = token {
            handshake["session_token"] = json!(token);
        }
        self.send(handshake).await;
    }

    async fn response(&mut self, id: u64) -> Response {
        let frame = tokio::time::timeout(RESPONSE_BOUND, self.client.next())
            .await
            .expect("response deadline")
            .expect("connection unexpectedly closed")
            .unwrap();
        let response: Response = serde_json::from_slice(&frame).unwrap();
        assert_eq!(response.id, Some(id));
        response
    }

    async fn ping(&mut self, id: u64) {
        self.send(json!({"id":id,"method":"ping","params":null}))
            .await;
        let response = self.response(id).await;
        assert!(response.error.is_none(), "{:?}", response.error);
        assert_eq!(response.result.unwrap()["ok"], true);
    }

    async fn effect(&mut self, id: u64) {
        self.send(effect_request(id)).await;
        let response = self.response(id).await;
        assert!(response.error.is_none(), "{:?}", response.error);
    }

    async fn closed(&mut self) {
        match tokio::time::timeout(RESPONSE_BOUND, self.client.next())
            .await
            .expect("close deadline")
        {
            None | Some(Err(_)) => {}
            Some(Ok(frame)) => panic!("denied connection returned a frame: {frame:?}"),
        }
        tokio::time::timeout(BOUND, &mut self.task)
            .await
            .expect("handler exit deadline")
            .expect("handler panicked")
            .expect("handler failed");
    }

    async fn stop(&mut self) {
        self._shutdown.send(true).unwrap();
        self.closed().await;
    }
}

fn effect_request(id: u64) -> Value {
    json!({"id":id,"method":"execute","params":{"operation":OPERATION}})
}

#[tokio::test]
async fn enforced_listener_rejects_actual_service_uid_before_attestation_or_effect() {
    let allowed = Fixture::new(false, false).await;
    let mut client = allowed.connect().await;
    client.handshake(None).await;
    client.effect(1).await;
    client.stop().await;
    allowed.assert_effects(1);

    let denied = Fixture::new(true, false).await;
    let mut client = denied.connect().await;
    // Queue a complete, otherwise valid request before the handler runs. The
    // real kernel UID matches the service UID, forbidden in enforced mode.
    client.handshake(None).await;
    client.send(effect_request(1)).await;
    client.closed().await;
    denied.assert_effects(0);
    assert!(
        denied.audit.events().is_empty(),
        "UID rejection must precede attestation"
    );
    assert!(denied.state.agent_sessions.read().await.is_empty());
}

#[tokio::test]
async fn listener_rate_limit_counts_claim_denials_and_recovers_without_queued_effects() {
    let fixture = Fixture::new(false, false).await;
    let mut client = fixture.connect().await;
    client.handshake(None).await;
    // These reject before async request dispatch, so batching them does not
    // invoke the protocol's disconnect-on-concurrent-request cancellation.
    for id in [1, 2] {
        let mut request = effect_request(id);
        request["workload_identity"] = json!("caller-supplied");
        client.send(request).await;
    }
    client.send(effect_request(3)).await;
    for id in [1, 2] {
        assert_eq!(
            client.response(id).await.error.unwrap().code,
            "identity_claim_forbidden"
        );
    }
    assert_eq!(client.response(3).await.error.unwrap().code, "rate_limited");
    fixture.assert_effects(0);
    assert_eq!(
        fixture
            .audit
            .events_of_kind(AuditEventKind::WorkloadAttestationDenied)
            .len(),
        2
    );

    // The production limiter has a one-second window. Its recorded arrivals
    // precede the observed refusal, so this contractual deadline expires all
    // entries without a guessed scheduling delay or enlarged rate limit.
    tokio::time::sleep_until(tokio::time::Instant::now() + Duration::from_secs(1)).await;
    fixture.assert_effects(0);
    client.effect(4).await;
    client.stop().await;
    fixture.assert_effects(1);
}

#[tokio::test]
async fn revoked_session_closes_established_socket_and_rejects_token_replay() {
    let fixture = Fixture::new(false, true).await;
    let mut established = fixture.connect().await;
    established.handshake(Some(TOKEN)).await;
    established.ping(1).await;

    let mut revoker = fixture.connect().await;
    revoker.handshake(Some(TOKEN)).await;
    revoker
        .send(json!({"id":2,"method":"agent_session_end","params":{"session_id":SESSION}}))
        .await;
    let response = revoker.response(2).await;
    assert!(response.error.is_none(), "{:?}", response.error);
    assert_eq!(
        response.result.unwrap(),
        json!({"status":"ended","session_id":SESSION,"label":"connection-flow"})
    );
    assert!(fixture.state.agent_sessions.read().await.is_empty());
    revoker.stop().await;

    established.send(effect_request(3)).await;
    established.closed().await;
    let mut replay = fixture.connect().await;
    replay.handshake(Some(TOKEN)).await;
    replay.send(effect_request(4)).await;
    replay.closed().await;
    fixture.assert_effects(0);
    let ended = fixture
        .audit
        .events_of_kind(AuditEventKind::OperationSucceeded);
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].operation.as_deref(), Some("agent_session_end"));
    assert_eq!(ended[0].outcome.as_deref(), Some("ended"));

    // A separate, freshly authorized installation executes the same action.
    let control = Fixture::new(false, true).await;
    let mut client = control.connect().await;
    client.handshake(Some(TOKEN)).await;
    client.effect(5).await;
    client.stop().await;
    control.assert_effects(1);
}

#[tokio::test]
async fn expired_session_closes_established_socket_and_sweeps_token_on_replay() {
    let fixture = Fixture::new(false, true).await;
    let mut established = fixture.connect().await;
    established.handshake(Some(TOKEN)).await;
    established.ping(1).await;
    // Change only the fixture's deadline after the successful handshake. The
    // production per-request check reads real SystemTime; no clock bypass or
    // minute-long minimum session-TTL wait is involved.
    fixture
        .state
        .agent_sessions
        .write()
        .await
        .get_mut(SESSION)
        .unwrap()
        .expires_at = SystemTime::UNIX_EPOCH;
    established.send(effect_request(2)).await;
    established.closed().await;
    assert_eq!(fixture.state.agent_sessions.read().await.len(), 1);
    let mut replay = fixture.connect().await;
    replay.handshake(Some(TOKEN)).await;
    replay.send(effect_request(3)).await;
    replay.closed().await;
    assert!(fixture.state.agent_sessions.read().await.is_empty());
    fixture.assert_effects(0);

    let control = Fixture::new(false, true).await;
    let mut client = control.connect().await;
    client.handshake(Some(TOKEN)).await;
    client.effect(4).await;
    client.stop().await;
    control.assert_effects(1);
}

#[tokio::test]
async fn session_end_reports_sqlite_revoke_failure_and_keeps_local_access_closed() {
    sqlite_revoke_failure(false).await;
}

#[tokio::test]
async fn session_end_all_reports_partial_sqlite_failure_and_attempts_every_revocation() {
    sqlite_revoke_failure(true).await;
}

async fn sqlite_revoke_failure(end_all: bool) {
    use opaque_core::identity::{DelegationClaims, sign_delegation_token};
    let mut fixture = Fixture::new(false, true).await;
    let config = serde_json::from_value(json!({
        "issuer":"https://connection-fixture.example", "client_id":"fixture",
        "required":true, "service_principals":[{"name":"ci","roles":["operator"]}]
    }))
    .unwrap();
    let runtime =
        Arc::new(identity::IdentityRuntime::initialize(config, fixture.directory.path()).unwrap());
    let subject = runtime.store.get_service_by_name("ci").unwrap().unwrap();
    let actor = runtime.store.upsert_agent("connection-fixture").unwrap();
    let state = Arc::get_mut(&mut fixture.state).unwrap();
    state.identity = Some(runtime.clone());
    let mut credentials = Vec::new();
    for id in if end_all {
        vec![SESSION, "other-session"]
    } else {
        vec![SESSION]
    } {
        let context = PrincipalContext {
            sub: subject.id.clone(),
            sub_label: "ci".into(),
            sub_roles: subject.roles.clone(),
            sub_teams: vec![],
            act: actor.id.clone(),
            act_label: "connection-fixture".into(),
            mode: AccessMode::Autonomous,
            jti: id.into(),
            human_session_id: None,
        };
        let claims = DelegationClaims {
            jti: id.into(),
            sub: subject.id.clone(),
            act: actor.id.clone(),
            mode: AccessMode::Autonomous,
            iat: now_unix(),
            exp: now_unix() + 300,
        };
        let token = sign_delegation_token(&claims, &runtime.signing).unwrap();
        runtime
            .store
            .record_delegation(&identity::store::DelegationRecord {
                jti: id.into(),
                sub_principal: subject.id.clone(),
                act_principal: actor.id.clone(),
                mode: AccessMode::Autonomous,
                human_session_id: None,
                approved_by: None,
                created_at: claims.iat,
                expires_at: claims.exp,
                revoked_at: None,
            })
            .unwrap();
        state.agent_sessions.write().await.insert(
            id.into(),
            AgentSession {
                session_id: id.into(),
                token: token.clone(),
                created_by_uid: unsafe { libc::geteuid() },
                expires_at: SystemTime::now() + Duration::from_secs(300),
                label: None,
                delegation: Some(SessionDelegation {
                    jti: id.into(),
                    sub: subject.id.clone(),
                    act: actor.id.clone(),
                    mode: AccessMode::Autonomous,
                    human_session_id: None,
                }),
            },
        );
        credentials.push((id, token, context));
    }
    let (_, token, stale_context) = &credentials[0];
    let mut established = fixture.connect().await;
    established.handshake(Some(token)).await;
    established.effect(1).await;
    fixture.assert_effects(1);
    runtime
        .with_dispatch_authority(Some(stale_context), None, &mut || Ok(()))
        .unwrap();

    // A real SQLite trigger rejects only this row's UPDATE. Reads, and the
    // other session's UPDATE in end-all, remain functional.
    let fault = rusqlite::Connection::open(fixture.directory.path().join("identity.db")).unwrap();
    fault.execute_batch("CREATE TRIGGER refuse_revoke BEFORE UPDATE OF revoked_at ON delegations WHEN OLD.jti='connection-flow-session' BEGIN SELECT RAISE(FAIL, 'fixture revoke write failed'); END;").unwrap();
    let mut revoker = fixture.connect().await;
    revoker.handshake(Some(token)).await;
    revoker
        .send(json!({"id":2,"method":"agent_session_end","params":
            if end_all {json!({"all":true})} else {json!({"session_id":SESSION})}
        }))
        .await;
    let response = revoker.response(2).await;
    assert!(response.result.is_none());
    let error = response.error.unwrap();
    assert_eq!(error.code, "revocation_failed");
    assert!(
        !error.message.contains("fixture revoke write failed"),
        "raw storage error must not escape"
    );
    assert!(fixture.state.agent_sessions.read().await.is_empty());
    assert!(
        runtime
            .store
            .get_delegation(SESSION)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    let mut forbidden_dispatches = 0;
    assert!(
        runtime
            .with_dispatch_authority(Some(stale_context), None, &mut || {
                forbidden_dispatches += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(forbidden_dispatches, 0);
    if end_all {
        assert!(
            runtime
                .store
                .get_delegation("other-session")
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some(),
            "one failed write must not skip revoking another ended session"
        );
    }
    revoker.stop().await;
    established.send(effect_request(3)).await;
    established.closed().await;
    for (_, token, _) in &credentials {
        let mut replay = fixture.connect().await;
        replay.handshake(Some(token)).await;
        replay.send(effect_request(4)).await;
        replay.closed().await;
    }
    fixture.assert_effects(1);
    let successes = fixture
        .audit
        .events_of_kind(AuditEventKind::OperationSucceeded);
    assert!(
        successes
            .iter()
            .all(|event| event.operation.as_deref() != Some("agent_session_end"))
    );
    let failures = fixture
        .audit
        .events_of_kind(AuditEventKind::OperationFailed);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].operation.as_deref(), Some("agent_session_end"));
    assert_eq!(failures[0].outcome.as_deref(), Some("revocation_failed"));
    assert_eq!(
        fixture
            .audit
            .events_of_kind(AuditEventKind::DelegationRevoked)
            .len(),
        usize::from(end_all)
    );

    // Recovery can persist the revocation, but must never re-enable either
    // the stale context or the removed session token.
    fault.execute_batch("DROP TRIGGER refuse_revoke").unwrap();
    assert!(runtime.store.revoke_delegation(SESSION).unwrap());
    assert!(
        runtime
            .store
            .get_delegation(SESSION)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert!(
        runtime
            .with_dispatch_authority(Some(stale_context), None, &mut || {
                forbidden_dispatches += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(forbidden_dispatches, 0);
    assert!(
        validate_agent_session_token(&fixture.state, token, unsafe { libc::geteuid() })
            .await
            .is_none()
    );
}
