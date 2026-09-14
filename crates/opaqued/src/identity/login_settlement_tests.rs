// Actual loopback HTTP callbacks and signed local IdP responses exercise login
// settlement. Software signing and injected SQLite faults do not represent a
// human browser or hardware authentication ceremony.

struct SettlementFixture {
    runtime: Arc<IdentityRuntime>,
    audit: Arc<opaque_core::audit::InMemoryAuditEmitter>,
    directory: tempfile::TempDir,
}
impl SettlementFixture {
    fn new(config: IdentityConfig) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(opaque_core::audit::InMemoryAuditEmitter::new());
        let runtime = Arc::new(
            IdentityRuntime::initialize(config, directory.path())
                .unwrap()
                .with_audit(audit.clone()),
        );
        Self {
            runtime,
            audit,
            directory,
        }
    }
    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.directory.path().join("identity.db")).unwrap()
    }
    fn sessions(&self) -> Vec<Vec<rusqlite::types::Value>> {
        let db = self.db();
        let mut statement = db
            .prepare("SELECT * FROM human_sessions ORDER BY rowid")
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
    fn audit_counts(&self) -> (usize, usize) {
        use opaque_core::audit::AuditEventKind;
        let events = self.audit.events();
        (
            events
                .iter()
                .filter(|e| e.kind == AuditEventKind::IdentityLoginSucceeded)
                .count(),
            events
                .iter()
                .filter(|e| e.kind == AuditEventKind::IdentityLoginFailed)
                .count(),
        )
    }
    async fn settled(&self, login: &StartedLogin) -> AttemptOutcome {
        let mut task = self
            .runtime
            .attempts
            .lock()
            .get_mut(&login.attempt_id)
            .unwrap()
            .listener_task
            .take()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
        if result.is_err() {
            task.abort();
            let _ = task.await;
            panic!("owned callback listener failed to settle within its test bound");
        }
        result.unwrap().unwrap();
        self.runtime.login_status(&login.attempt_id).unwrap()
    }
}
impl Drop for SettlementFixture {
    fn drop(&mut self) {
        for attempt in self.runtime.attempts.lock().values_mut() {
            if let Some(task) = attempt.listener_task.take() {
                task.abort();
            }
        }
    }
}

fn failed_as(outcome: AttemptOutcome, expected: &str) {
    match outcome {
        AttemptOutcome::Failed { reason } => assert_eq!(reason, expected),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

async fn raw_callback(login: &StartedLogin, bytes: &[u8]) -> String {
    let uri = reqwest::Url::parse(&query_param(&login.auth_url, "redirect_uri").unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", uri.port().unwrap()))
            .await
            .unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    })
    .await
    .unwrap()
}

async fn provider_history(server: &MockServer) -> Vec<(String, String)> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| (r.method.to_string(), r.url.path().to_owned()))
        .collect()
}

#[tokio::test]
async fn malformed_callbacks_exhaust_exact_stray_allowance_without_exchanging_or_logging_in() {
    let server = MockServer::start().await;
    mount_discovery(&server, &server.uri()).await;
    let fixture = SettlementFixture::new(test_config(&server.uri(), vec![]));
    let login = fixture.runtime.login_start().await.unwrap();
    let requests: &[(&[u8], u16)] = &[
        (b"POST /callback HTTP/1.1\r\n\r\n", 400),
        (b"GET /favicon.ico HTTP/1.1\r\n\r\n", 404),
        (b"GET /callback?state=%XX HTTP/1.1\r\n\r\n", 400),
        (b"GET /callback?state=wrong HTTP/1.1\r\n\r\n", 400),
        (b"GET /callback HTTP/2\r\n\r\n", 400),
        (b"GET\r\n\r\n", 400),
        (b"GET /callback\r\n\r\n", 400),
        (b"GET /\xff HTTP/1.1\r\n\r\n", 400),
    ];
    for index in 0..32 {
        let (request, status) = requests[index % requests.len()];
        let response = raw_callback(&login, request).await;
        assert!(response.starts_with(&format!("HTTP/1.1 {status} ")));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert_eq!(fixture.runtime.store.count_humans().unwrap(), 0);
        assert!(fixture.sessions().is_empty());
        if index < 31 {
            assert!(matches!(
                fixture.runtime.login_status(&login.attempt_id),
                Some(AttemptOutcome::Pending)
            ));
            assert_eq!(fixture.audit_counts(), (0, 0));
        }
    }
    failed_as(
        fixture.settled(&login).await,
        "too many stray requests on the callback listener",
    );
    assert_eq!(fixture.audit_counts(), (0, 1));
    assert_eq!(
        provider_history(&server).await,
        [("GET".into(), "/.well-known/openid-configuration".into())]
    );
}

#[tokio::test]
async fn valid_state_provider_errors_and_missing_code_settle_once_without_echo_or_exchange() {
    for provider_error in [true, false] {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let fixture = SettlementFixture::new(test_config(&server.uri(), vec![]));
        let login = fixture.runtime.login_start().await.unwrap();
        let state = query_param(&login.auth_url, "state").unwrap();
        let suffix = if provider_error {
            "&error=access_denied%3Cscript%3E%0D%0A"
        } else {
            ""
        };
        let response = raw_callback(
            &login,
            format!("GET /callback?state={state}{suffix} HTTP/1.1\r\n\r\n").as_bytes(),
        )
        .await;
        assert!(response.starts_with(if provider_error {
            "HTTP/1.1 200 "
        } else {
            "HTTP/1.1 400 "
        }));
        assert!(response.ends_with(ERROR_PAGE));
        assert!(!response.contains(&state));
        assert!(!response.contains("access_denied"));
        failed_as(
            fixture.settled(&login).await,
            if provider_error {
                "identity provider reported: access_deniedscript"
            } else {
                "callback missing authorization code"
            },
        );
        assert_eq!(fixture.audit_counts(), (0, 1));
        assert!(fixture.sessions().is_empty());
        assert_eq!(fixture.runtime.store.count_humans().unwrap(), 0);
        assert_eq!(
            provider_history(&server).await,
            [("GET".into(), "/.well-known/openid-configuration".into())]
        );
    }
}

async fn signed_callback(
    server: &MockServer,
    fixture: &SettlementFixture,
    code: &str,
    email: Option<&str>,
) -> StartedLogin {
    let login = fixture.runtime.login_start().await.unwrap();
    let nonce = query_param(&login.auth_url, "nonce").unwrap();
    let mut claims = base_claims(&server.uri(), &nonce);
    if let Some(email) = email {
        claims["email"] = email.into();
    } else {
        claims.as_object_mut().unwrap().remove("email");
    }
    if fixture.runtime.config.persona.is_some() {
        claims["groups"] = serde_json::json!(["Engineering"]);
        claims["auth_time"] = claims["iat"].clone();
    }
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(format!("code={code}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id_token": sign_id_token(claims, "test-key-1")
        })))
        .mount(server)
        .await;
    assert_eq!(
        drive_callback(
            &login.auth_url,
            code,
            &query_param(&login.auth_url, "state").unwrap()
        )
        .await,
        200
    );
    login
}

#[tokio::test]
async fn signed_login_write_faults_never_replace_live_session_and_fresh_retry_can_settle() {
    for (table, reason) in [
        ("principals", "failed to persist principal"),
        (
            "persona_snapshots",
            "fresh identity persona could not be persisted",
        ),
        ("human_sessions", "failed to create login session"),
    ] {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let mut config = test_config(&server.uri(), vec![]);
        if table == "persona_snapshots" {
            config.persona = Some(crate::identity::PersonaConfig {
                groups_claim: "groups".into(),
                max_age_secs: 60,
            });
        }
        let fixture = SettlementFixture::new(config);
        let prior = fixture
            .runtime
            .store
            .upsert_human(
                &server.uri(),
                "existing",
                None,
                None,
                &BTreeSet::from([Role::Admin]),
            )
            .unwrap();
        fixture
            .runtime
            .store
            .create_human_session(&prior.id, 3600, &server.uri())
            .unwrap();
        let previous_sessions = fixture.sessions();
        let db = fixture.db();
        db.execute_batch(&format!("CREATE TRIGGER reject_login_write BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'private fixture persistence fault'); END;")).unwrap();
        let failed = signed_callback(&server, &fixture, "fail", Some("dev@example.com")).await;
        failed_as(fixture.settled(&failed).await, reason);
        assert_eq!(fixture.sessions(), previous_sessions);
        assert_eq!(
            fixture.runtime.current_human_principal().unwrap().id,
            prior.id
        );
        assert_eq!(fixture.audit_counts(), (0, 1));
        assert_eq!(
            fixture.runtime.store.count_humans().unwrap(),
            if table == "principals" { 1 } else { 2 }
        );
        let snapshot_count: u64 = db
            .query_row("SELECT count(*) FROM persona_snapshots", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(snapshot_count, 0);
        assert_eq!(
            provider_history(&server).await,
            [
                ("GET".into(), "/.well-known/openid-configuration".into()),
                ("POST".into(), "/token".into()),
                ("GET".into(), "/jwks".into()),
            ]
        );
        db.execute_batch("DROP TRIGGER reject_login_write").unwrap();
        let retried = signed_callback(&server, &fixture, "retry", Some("dev@example.com")).await;
        let AttemptOutcome::Done { session_id } = fixture.settled(&retried).await else {
            panic!("fresh login must settle")
        };
        assert_eq!(fixture.sessions().len(), 2);
        assert_eq!(fixture.sessions()[0], previous_sessions[0]);
        let session = fixture
            .runtime
            .store
            .get_human_session(&session_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            fixture.runtime.current_human_principal().unwrap().id,
            session.principal_id
        );
        assert_ne!(session.principal_id, prior.id);
        let principal = fixture
            .runtime
            .store
            .get_principal(&session.principal_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            principal.roles,
            if table == "persona_snapshots" {
                BTreeSet::new()
            } else {
                BTreeSet::from([Role::Operator])
            }
        );
        assert_eq!(fixture.audit_counts(), (1, 1));
        failed_as(
            fixture.runtime.login_status(&failed.attempt_id).unwrap(),
            reason,
        );
        assert_eq!(
            provider_history(&server).await.last(),
            Some(&("POST".into(), "/token".into()))
        );
        assert_eq!(provider_history(&server).await.len(), 4);
    }
}

#[tokio::test]
async fn signed_disabled_identity_and_missing_email_never_create_login_authority() {
    for case in [
        "disabled",
        "missing-email",
        "malformed-email",
        "uppercase-allowed",
    ] {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let fixture = SettlementFixture::new(test_config(
            &server.uri(),
            if case == "disabled" {
                vec![]
            } else {
                vec!["example.com".into()]
            },
        ));
        if case == "disabled" {
            let principal = fixture
                .runtime
                .store
                .upsert_human(
                    &server.uri(),
                    "user-123",
                    None,
                    None,
                    &BTreeSet::from([Role::Operator]),
                )
                .unwrap();
            fixture
                .runtime
                .store
                .set_disabled(&principal.id, true)
                .unwrap();
        }
        let login = signed_callback(
            &server,
            &fixture,
            "valid",
            match case {
                "missing-email" => None,
                "malformed-email" => Some("missing-at-sign"),
                _ => Some("dev@EXAMPLE.COM"),
            },
        )
        .await;
        let result = fixture.settled(&login).await;
        if case == "uppercase-allowed" {
            assert!(matches!(result, AttemptOutcome::Done { .. }));
            assert_eq!(fixture.sessions().len(), 1);
            assert_eq!(fixture.audit_counts(), (1, 0));
        } else {
            failed_as(
                result,
                if case == "disabled" {
                    "this identity has been disabled"
                } else {
                    "email domain not permitted by daemon policy"
                },
            );
            assert!(fixture.sessions().is_empty());
            assert_eq!(fixture.audit_counts(), (0, 1));
            assert_eq!(fixture.runtime.store.count_humans().unwrap(), 0);
            let humans: u64 = fixture
                .db()
                .query_row(
                    "SELECT count(*) FROM principals WHERE kind='human'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(humans, u64::from(case == "disabled"));
            if case == "disabled" {
                let retained = fixture
                    .runtime
                    .store
                    .list_principals()
                    .unwrap()
                    .into_iter()
                    .find(|p| p.disabled)
                    .unwrap();
                assert_eq!(retained.roles, BTreeSet::from([Role::Operator]));
            }
            assert!(fixture.runtime.current_human_principal().is_none());
        }
        assert_eq!(
            provider_history(&server).await,
            [
                ("GET".into(), "/.well-known/openid-configuration".into()),
                ("POST".into(), "/token".into()),
                ("GET".into(), "/jwks".into()),
            ]
        );
    }
}

#[tokio::test]
async fn callback_reader_handles_fragmentation_eof_and_size_limit_on_actual_tcp() {
    // A direct production-parser check uses real TCP to exercise fragmentation
    // without a helper HTTP parser. No wall-clock delay selects the boundary.
    for oversize in [false, true] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        client
            .write_all(b"GET /callback?state=fragment HTTP/1.1\r\nX-Fill: ")
            .await
            .unwrap();
        server.readable().await.unwrap();
        let parse = read_request_target(&mut server);
        tokio::pin!(parse);
        assert!(futures_util::poll!(&mut parse).is_pending());
        if oversize {
            client
                .write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1])
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(5), &mut parse)
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            client.write_all(b"complete\r\n\r\n").await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), &mut parse)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("/callback?state=fragment")
            );
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    client.write_all(b"GET /unfinished").await.unwrap();
    client.shutdown().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), read_request_target(&mut server))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn callback_attempt_deadline_settles_failure_and_closes_owned_listener() {
    let server = MockServer::start().await;
    mount_discovery(&server, &server.uri()).await;
    let fixture = SettlementFixture::new(test_config(&server.uri(), vec![]));
    let login = fixture.runtime.login_start().await.unwrap();
    let uri = reqwest::Url::parse(&query_param(&login.auth_url, "redirect_uri").unwrap()).unwrap();
    // A real stray-request response proves the listener task and its timeout
    // were polled before advancing Tokio's test clock. This checks timeout
    // handling, not the passage of five real minutes.
    assert!(
        raw_callback(&login, b"GET /favicon.ico HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 404 ")
    );
    tokio::time::pause();
    tokio::time::advance(ATTEMPT_TTL + Duration::from_secs(1)).await;
    failed_as(fixture.settled(&login).await, "login timed out");
    tokio::time::resume();
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", uri.port().unwrap()))
            .await
            .is_err()
    );
    assert_eq!(fixture.audit_counts(), (0, 1));
    assert!(fixture.sessions().is_empty());
    assert_eq!(
        provider_history(&server).await,
        [("GET".into(), "/.well-known/openid-configuration".into())]
    );
}

#[tokio::test]
async fn status_expiry_and_garbage_collection_retire_pending_and_settled_attempts() {
    let server = MockServer::start().await;
    mount_discovery(&server, &server.uri()).await;
    let fixture = SettlementFixture::new(test_config(&server.uri(), vec![]));
    let first = fixture.runtime.login_start().await.unwrap();
    let uri = reqwest::Url::parse(&query_param(&first.auth_url, "redirect_uri").unwrap()).unwrap();
    // Select std::time-based retention boundaries explicitly. The native
    // listener remains real and its cancellation must finish before return.
    let abort = {
        let mut attempts = fixture.runtime.attempts.lock();
        let attempt = attempts.get_mut(&first.attempt_id).unwrap();
        attempt.created = Instant::now() - ATTEMPT_TTL - Duration::from_secs(1);
        attempt.listener_task.as_ref().unwrap().abort_handle()
    };
    failed_as(
        fixture.runtime.login_status(&first.attempt_id).unwrap(),
        "login timed out",
    );
    assert_eq!(
        fixture.audit_counts(),
        (0, 0),
        "status is a read, not terminal settlement"
    );
    fixture
        .runtime
        .attempts
        .lock()
        .get_mut(&first.attempt_id)
        .unwrap()
        .created = Instant::now() - ATTEMPT_TTL * 2 - Duration::from_secs(1);
    assert!(fixture.runtime.login_status(&first.attempt_id).is_none());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !abort.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", uri.port().unwrap()))
            .await
            .is_err()
    );
    let next = fixture.runtime.login_start().await.unwrap();
    let state = query_param(&next.auth_url, "state").unwrap();
    raw_callback(
        &next,
        format!("GET /callback?state={state} HTTP/1.1\r\n\r\n").as_bytes(),
    )
    .await;
    failed_as(
        fixture.settled(&next).await,
        "callback missing authorization code",
    );
    fixture
        .runtime
        .attempts
        .lock()
        .get_mut(&next.attempt_id)
        .unwrap()
        .created = Instant::now() - ATTEMPT_TTL * 2 - Duration::from_secs(1);
    assert!(fixture.runtime.login_status(&next.attempt_id).is_none());
    assert_eq!(fixture.audit_counts(), (0, 1));
    assert!(fixture.sessions().is_empty());
    assert_eq!(
        provider_history(&server).await,
        [("GET".into(), "/.well-known/openid-configuration".into())]
    );
}
