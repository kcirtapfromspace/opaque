//! Real-world end-to-end tests for the Phase 1 identity substrate.
//!
//! Unlike the unit tests, these spawn the ACTUAL `opaqued` binary with an
//! isolated HOME + runtime dir, run a wiremock OIDC IdP, and drive the real
//! socket protocol (length-delimited JSON frames, handshake and all) — the
//! same path a human's CLI takes. The mock IdP signs RS256 ID tokens with the
//! repo's test RSA fixture; the daemon verifies them via the JWKS endpoint.
//!
//! Socket paths must stay short (macOS `SUN_LEN` limit), so the runtime dir
//! lives directly under /tmp rather than in a nested tempdir.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde_json::{Value, json};
#[path = "support/oidc.rs"]
mod oidc;
use oidc::{Counts, MockOidc, TestIdentity};
#[cfg(coverage_nightly)]
#[path = "support/coverage.rs"]
mod coverage;
const CLIENT_ID: &str = "opaque-e2e";

/// Each test spawns a real daemon + a wiremock IdP + reqwest clients; running
/// several concurrently causes resource contention (JWKS fetch timeouts →
/// spurious "token failed verification"). Serialize them so cargo's default
/// parallel test scheduling can't overlap them. tokio::test uses a
/// current-thread runtime, so holding this std guard across awaits is sound.
static E2E_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    E2E_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn query_param(url: &str, name: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

// ---------------------------------------------------------------------------
// Daemon harness
// ---------------------------------------------------------------------------

struct TestDaemon {
    child: Child,
    home: Option<tempfile::TempDir>,
    runtime_dir: PathBuf,
    sock: PathBuf,
    daemon_token: String,
}

impl TestDaemon {
    /// Spawn the real opaqued binary with an isolated HOME, a short runtime
    /// dir, and the given config. Waits until the socket + handshake token
    /// exist.
    fn spawn(config_toml: &str) -> Self {
        Self::spawn_with_env(config_toml, &[])
    }

    fn spawn_with_env(config_toml: &str, extra_env: &[(&str, &str)]) -> Self {
        let home = tempfile::tempdir().expect("home tempdir");
        // SHORT socket dir (SUN_LEN limit on macOS), canonicalized because
        // the daemon's socket hygiene rejects symlinked path components
        // (/tmp -> /private/tmp on macOS).
        let tmp_base = Path::new("/tmp")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let runtime_dir = tmp_base.join(format!("oq{}-{:08x}", std::process::id(), rand_u32()));
        std::fs::create_dir_all(&runtime_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let config_path = home.path().join("config.toml");
        std::fs::write(&config_path, config_toml).unwrap();

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_opaqued"));
        cmd.env("HOME", home.path())
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            .env("OPAQUE_CONFIG", &config_path)
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        #[cfg(coverage_nightly)]
        coverage::subprocess(&mut cmd, "daemon");
        let child = cmd.spawn().expect("spawn opaqued");

        let sock = runtime_dir.join("opaque").join("opaqued.sock");
        let token_path = runtime_dir.join("opaque").join("daemon.token");
        let deadline = Instant::now() + Duration::from_secs(15);
        while (!sock.exists() || !token_path.exists()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            sock.exists() && token_path.exists(),
            "daemon did not come up (socket/token missing)"
        );
        let daemon_token = std::fs::read_to_string(&token_path)
            .expect("read daemon token")
            .trim()
            .to_owned();

        Self {
            child,
            home: Some(home),
            runtime_dir,
            sock,
            daemon_token,
        }
    }

    fn audit_db(&self) -> PathBuf {
        self.home
            .as_ref()
            .unwrap()
            .path()
            .join(".opaque")
            .join("audit.db")
    }

    /// One request over a fresh connection, exactly like the CLI: handshake
    /// frame (optionally carrying a session token), request frame, response
    /// frame (length-delimited JSON). `Err` = the daemon closed the
    /// connection or the frame failed — how handshake rejection presents.
    async fn raw_call(
        &self,
        method: &str,
        params: Value,
        session_token: Option<&str>,
    ) -> Result<Value, String> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let stream = tokio::net::UnixStream::connect(&self.sock)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
            .new_codec();
        let mut framed = Framed::new(stream, codec);

        let mut handshake = json!({"handshake": "v1", "daemon_token": self.daemon_token});
        if let Some(t) = session_token {
            handshake["session_token"] = json!(t);
        }
        framed
            .send(serde_json::to_vec(&handshake).unwrap().into())
            .await
            .map_err(|e| format!("send handshake: {e}"))?;
        framed
            .send(
                serde_json::to_vec(&json!({"id": 1, "method": method, "params": params}))
                    .unwrap()
                    .into(),
            )
            .await
            .map_err(|e| format!("send request: {e}"))?;
        match tokio::time::timeout(Duration::from_secs(10), framed.next()).await {
            Err(_) => Err("response timeout".into()),
            Ok(None) => Err("connection closed before response".into()),
            Ok(Some(Err(e))) => Err(format!("frame error: {e}")),
            Ok(Some(Ok(frame))) => {
                serde_json::from_slice(&frame).map_err(|e| format!("bad response json: {e}"))
            }
        }
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        self.raw_call(method, params, None)
            .await
            .unwrap_or_else(|e| panic!("{method} failed: {e}"))
    }

    /// Call and unwrap `result`, panicking with the error if the daemon
    /// returned one.
    async fn call_ok(&self, method: &str, params: Value) -> Value {
        let resp = self.call(method, params).await;
        assert!(
            resp.get("error").is_none_or(Value::is_null),
            "{method} returned error: {resp}"
        );
        resp.get("result").cloned().unwrap_or(Value::Null)
    }

    /// Graceful shutdown (SIGTERM) so the audit sink flushes, then reap.
    fn shutdown(mut self) -> (PathBuf, tempfile::TempDir) {
        let pid = self.child.id();
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        let db = self.audit_db();
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
        (db, self.home.take().unwrap())
    }
}

fn rand_u32() -> u32 {
    // Enough entropy for a unique test dir name; not security-relevant.
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        ^ std::process::id().rotate_left(16)
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        // A failed assertion must not leave a test broker running after its
        // temporary custody directory has been removed.
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

fn identity_config(issuer: &str) -> String {
    identity_config_with(issuer, "")
}

/// Build a daemon config. `top_level` holds extra top-level DaemonConfig keys
/// (e.g. `enforce_agent_sessions`, `approval_backend`). They are emitted at
/// the very TOP, before any table header — in TOML, bare keys after
/// `[[known_human_clients]]` or `[identity]` would be captured by that table.
fn identity_config_with(issuer: &str, top_level: &str) -> String {
    // The test binary itself is the "human" client (exe allowlist) so whoami
    // exercises the full human-classified response shape.
    // The kernel reports a canonical executable path. A Cargo target under
    // macOS /tmp otherwise allowlists an alias of /private/tmp and classifies
    // this intended human test client as an agent.
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    format!(
        r#"{top_level}

[[known_human_clients]]
name = "e2e-test"
exe_path = "{exe}"

[identity]
issuer = "{issuer}"
client_id = "{CLIENT_ID}"
session_ttl_secs = 3600
"#,
        exe = exe.display(),
    )
}

struct LoginAttempt {
    id: String,
    auth_url: String,
    state: String,
    redirect: String,
}

async fn begin_login(daemon: &TestDaemon, idp: &MockOidc) -> LoginAttempt {
    let start = daemon.call_ok("identity.login_start", Value::Null).await;
    let auth_url = start["auth_url"].as_str().expect("auth_url").to_owned();
    let redirect = query_param(&auth_url, "redirect_uri").expect("redirect_uri");
    // Dynamic loopback ports are explicitly registered before the request;
    // changing an authorization URL cannot silently change registration.
    idp.register_redirect(&redirect);
    LoginAttempt {
        id: start["attempt_id"].as_str().unwrap().into(),
        state: query_param(&auth_url, "state").unwrap(),
        auth_url,
        redirect,
    }
}

async fn request_code(
    idp: &MockOidc,
    auth_url: &str,
    email: &str,
    forge_nonce: Option<&str>,
) -> String {
    idp.select_identity(
        &query_param(auth_url, "state").unwrap(),
        TestIdentity {
            subject: "e2e-user-1".into(),
            email: email.into(),
            token_nonce_override: forge_nonce.map(str::to_owned),
        },
    );
    let response = idp.authorize(auth_url).await;
    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    let callback = response.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(
        query_param(&callback, "state"),
        query_param(auth_url, "state")
    );
    callback
}

async fn finish_login(daemon: &TestDaemon, attempt: &LoginAttempt, callback: &str) -> Value {
    let resp = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
        .get(callback)
        .send()
        .await
        .expect("callback reachable");
    assert!(resp.status().is_success() || resp.status().is_client_error());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = daemon
            .call_ok("identity.login_status", json!({"attempt_id": attempt.id}))
            .await;
        if status["status"] != "pending" {
            return status;
        }
        assert!(Instant::now() < deadline, "login never became terminal");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Drive the actual authorization request and callback. The IdP verifies the
/// daemon's real verifier against its issued code's S256 challenge at /token.
async fn drive_login(
    daemon: &TestDaemon,
    idp: &MockOidc,
    email: &str,
    forge_nonce: Option<&str>,
) -> Value {
    let attempt = begin_login(daemon, idp).await;
    let callback = request_code(idp, &attempt.auth_url, email, forge_nonce).await;
    finish_login(daemon, &attempt, &callback).await
}

async fn assert_no_session_and_sanitized_failure(
    daemon: TestDaemon,
    status: &Value,
    code: &str,
    prior_logins: u64,
) {
    assert_eq!(status["status"], "failed");
    assert!(!status.to_string().contains(code));
    assert!(daemon.call_ok("whoami", Value::Null).await["identity"].is_null());
    assert_eq!(
        daemon.call_ok("agent_session_list", Value::Null).await["count"],
        0
    );
    let (db, _home) = daemon.shutdown();
    assert!(opaque_core::audit::verify_audit_chain(&db).unwrap().ok);
    let events =
        opaque_core::audit::query_audit_db(&db, &opaque_core::audit::AuditFilter::default())
            .unwrap();
    assert!(!serde_json::to_string(&events).unwrap().contains(code));
    // Read the isolated stopped daemon's durable records as well as the public
    // API: a failed flow must not leave an orphan principal or hidden session.
    let identity = rusqlite::Connection::open_with_flags(
        db.with_file_name("identity.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let count = |query: &str| {
        identity
            .query_row(query, [], |row| row.get::<_, u64>(0))
            .unwrap()
    };
    assert_eq!(
        count("SELECT COUNT(*) FROM principals WHERE kind = 'human'"),
        prior_logins
    );
    assert_eq!(count("SELECT COUNT(*) FROM human_sessions"), prior_logins);
    assert_eq!(
        count("SELECT COUNT(*) FROM human_sessions WHERE revoked_at IS NULL"),
        0
    );
    assert_eq!(count("SELECT COUNT(*) FROM delegations"), 0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Drive the actual listener error path with bounded framing violations. More
/// than one semaphore's capacity of rejected peers must not exhaust the daemon.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn malformed_peer_frames_release_listener_capacity_and_preserve_healthy_dispatch() {
    use futures_util::{SinkExt, StreamExt};
    use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db, verify_audit_chain};
    use tokio::io::AsyncWriteExt;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    let _serial = serial_guard();
    // Expected framing failures must not fill the harness's unread log pipe.
    let mut daemon = TestDaemon::spawn_with_env(
        "[attestation]\ninterval_secs = 0\n",
        &[("RUST_LOG", "error")],
    );
    let expected = json!({"ok":true,"api_version":opaque_core::API_VERSION});
    assert_eq!(daemon.call_ok("ping", Value::Null).await, expected);
    let oversized = u32::try_from(opaque_core::MAX_FRAME_LENGTH + 1)
        .unwrap()
        .to_be_bytes();
    for authenticated in [false, true] {
        // This is one test with 130 connection scenarios, not 130 distinct tests.
        for attempt in 0..65 {
            let stream = tokio::net::UnixStream::connect(&daemon.sock).await.unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            if authenticated {
                framed
                    .send(
                        serde_json::to_vec(
                            &json!({"handshake":"v1","daemon_token":daemon.daemon_token}),
                        )
                        .unwrap()
                        .into(),
                    )
                    .await
                    .unwrap();
            }
            // Bypass only the fixture's encoder: the daemon receives a real
            // over-limit length prefix, without allocating its claimed body.
            framed.get_mut().write_all(&oversized).await.unwrap();
            if authenticated {
                let frame = tokio::time::timeout(Duration::from_secs(5), framed.next())
                    .await
                    .expect("malformed peer response deadline")
                    .expect("missing bad_frame response")
                    .unwrap();
                let response: Value = serde_json::from_slice(&frame).unwrap();
                assert!(response["id"].is_null());
                assert_eq!(
                    response["error"]["code"], "bad_frame",
                    "scenario {attempt}: {response}"
                );
                assert!(response.get("result").is_none_or(Value::is_null));
            }
            assert!(
                matches!(
                    tokio::time::timeout(Duration::from_secs(5), framed.next()).await,
                    Ok(None) | Ok(Some(Err(_)))
                ),
                "malformed peer was not disconnected: authenticated={authenticated}, attempt={attempt}"
            );
        }
        assert_eq!(daemon.call_ok("ping", Value::Null).await, expected);
        assert!(daemon.child.try_wait().unwrap().is_none());
    }
    // Require a successful native shutdown before checking the flushed audit.
    assert_eq!(
        unsafe { libc::kill(daemon.child.id() as i32, libc::SIGTERM) },
        0
    );
    let status = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("daemon failed to drain rejected connections");
    assert_eq!(status.code(), Some(0));
    let db = daemon.audit_db();
    assert!(verify_audit_chain(&db).unwrap().ok);
    let events = query_audit_db(&db, &AuditFilter::default()).unwrap();
    let dispatched = events
        .iter()
        .filter(|e| e.kind == AuditEventKind::WorkloadAttested)
        .collect::<Vec<_>>();
    assert_eq!(dispatched.len(), 3);
    assert!(
        dispatched
            .iter()
            .all(|e| e.operation.as_deref() == Some("ping"))
    );
    let runtime = daemon.runtime_dir.clone();
    drop(daemon);
    assert!(!runtime.exists());
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // same serialized real-daemon path as identity tests
async fn workload_attestor_uses_listener_evidence_and_refuses_claims() {
    use futures_util::{SinkExt, StreamExt};
    use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db, verify_audit_chain};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    let _serial = serial_guard();
    let daemon = TestDaemon::spawn("[attestation]\ninterval_secs = 0\n");
    daemon.call_ok("ping", Value::Null).await;

    // A normal method envelope cannot upgrade the shared-uid observation.
    let denied = daemon.call("ping", json!({"strength": "strong"})).await;
    assert_eq!(denied["error"]["code"], "identity_claim_forbidden");

    // Top-level fields must be checked before Request deserialization could
    // silently discard them. The attempted attestor does not select a plugin.
    let stream = tokio::net::UnixStream::connect(&daemon.sock).await.unwrap();
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
    framed
        .send(
            serde_json::to_vec(&json!({
                "handshake": "v1", "daemon_token": daemon.daemon_token,
            }))
            .unwrap()
            .into(),
        )
        .await
        .unwrap();
    framed
        .send(
            serde_json::to_vec(&json!({
                "id": 8, "method": "ping", "params": null, "attestor": "caller-secret-marker",
            }))
            .unwrap()
            .into(),
        )
        .await
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(10), framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let denied: Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(denied["id"], 8);
    assert_eq!(denied["error"]["code"], "identity_claim_forbidden");
    // Duplicate envelopes must retain their original parse-error behavior;
    // a later params object cannot erase an earlier identity claim.
    framed
        .send(
            br#"{"id":9,"method":"ping","params":{"strength":"strong"},"params":null}"#
                .to_vec()
                .into(),
        )
        .await
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(10), framed.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let denied: Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(denied["error"]["code"], "bad_json");
    drop(framed);

    // Identity claims in a handshake close the connection before dispatch.
    let stream = tokio::net::UnixStream::connect(&daemon.sock).await.unwrap();
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
    framed
        .send(
            serde_json::to_vec(&json!({
                "handshake": "v1", "daemon_token": daemon.daemon_token,
                "workload_identity": {"strength": "strong", "source": "caller-secret-marker"},
            }))
            .unwrap()
            .into(),
        )
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), framed.next()).await,
        Ok(None) | Ok(Some(Err(_)))
    ));
    drop(framed);

    let (db, _home) = daemon.shutdown();
    assert!(verify_audit_chain(&db).unwrap().ok);
    let events = query_audit_db(&db, &AuditFilter::default()).unwrap();
    let attested: Vec<_> = events
        .iter()
        .filter(|e| e.kind == AuditEventKind::WorkloadAttested)
        .collect();
    assert_eq!(
        attested.len(),
        1,
        "forged identities must never reach dispatch"
    );
    assert_eq!(attested[0].operation.as_deref(), Some("ping"));
    let client = attested[0].client.as_ref().unwrap();
    assert_eq!(client.uid, unsafe { libc::geteuid() });
    assert_eq!(client.pid, Some(std::process::id() as i32));
    let detail: Value = serde_json::from_str(attested[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["attestor"], "peercred");
    assert_eq!(detail["strength"], "weak");
    assert_eq!(
        detail["selector_count"], 4,
        "real executable observations are required"
    );
    let denied: Vec<_> = events
        .iter()
        .filter(|e| e.kind == AuditEventKind::WorkloadAttestationDenied)
        .collect();
    assert_eq!(denied.len(), 3);
    assert!(
        denied
            .iter()
            .all(|e| e.outcome.as_deref() == Some("identity_claim_forbidden"))
    );
    assert!(events.iter().all(|e| {
        !e.detail
            .as_deref()
            .unwrap_or("")
            .contains("caller-secret-marker")
    }));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize heavy e2e daemons (current-thread runtime)
async fn login_end_to_end_against_real_daemon() {
    let _serial = serial_guard();
    let idp = MockOidc::start(CLIENT_ID).await;

    let daemon = TestDaemon::spawn(&identity_config(&idp.uri()));

    // Sanity: daemon is up and identity-aware.
    let pong = daemon.call_ok("ping", Value::Null).await;
    assert_eq!(pong["ok"], true);

    let status = drive_login(&daemon, &idp, "dev@example.com", None).await;
    assert_eq!(status["status"], "complete", "login failed: {status}");
    assert_eq!(
        idp.counts(),
        Counts {
            codes_issued: 1,
            token_requests: 1,
            tokens_issued: 1,
            token_rejections: 0
        }
    );
    let identity = &status["identity"];
    assert_eq!(identity["label"], "dev@example.com");
    let roles: Vec<String> = identity["roles"]
        .as_array()
        .expect("roles array")
        .iter()
        .map(|r| r.as_str().unwrap().to_owned())
        .collect();
    assert!(
        roles.contains(&"admin".to_string()),
        "first human bootstraps as admin, got {roles:?}"
    );

    // whoami (human-classified via exe allowlist) reports the principal.
    let who = daemon.call_ok("whoami", Value::Null).await;
    assert_eq!(who["identity"]["label"], "dev@example.com");

    // principal_list shows the bootstrapped human with admin role.
    let principals = daemon.call_ok("identity.principal_list", Value::Null).await;
    let humans: Vec<&Value> = principals["principals"]
        .as_array()
        .expect("principals")
        .iter()
        .filter(|p| p["kind"] == "human")
        .collect();
    assert_eq!(humans.len(), 1);
    assert_eq!(humans[0]["label"], "dev@example.com");

    // Logout revokes the session; whoami goes anonymous.
    let out = daemon.call_ok("identity.logout", Value::Null).await;
    assert!(out["revoked"].as_u64().unwrap() >= 1);
    let who = daemon.call_ok("whoami", Value::Null).await;
    assert!(who["identity"].is_null(), "identity after logout: {who}");

    // Graceful shutdown, then the tamper-evident chain must verify.
    let (db, _home) = daemon.shutdown();
    assert!(db.exists(), "audit db missing");
    let v = opaque_core::audit::verify_audit_chain(&db).expect("verify runs");
    assert!(
        v.ok,
        "audit chain broken after identity flow: {:?}",
        v.detail
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize heavy e2e daemons (current-thread runtime)
async fn delegation_lifecycle_end_to_end() {
    let _serial = serial_guard();
    let idp = MockOidc::start(CLIENT_ID).await;

    // Identity + session enforcement + the LOUDLY-GUARDED auto-approve test
    // backend (config value AND env var both required — see Stage D). These
    // are top-level keys, so they must precede the [identity] table.
    let config = identity_config_with(
        &idp.uri(),
        "enforce_agent_sessions = true\napproval_backend = \"insecure_auto_approve\"",
    );
    let daemon = TestDaemon::spawn_with_env(&config, &[("OPAQUE_INSECURE_AUTO_APPROVE", "1")]);

    let status = drive_login(&daemon, &idp, "dev@example.com", None).await;
    assert_eq!(status["status"], "complete", "login failed: {status}");
    assert_eq!(
        idp.counts(),
        Counts {
            codes_issued: 1,
            token_requests: 1,
            tokens_issued: 1,
            token_rejections: 0
        }
    );

    // Mint a delegated agent session. Approval is satisfied by the insecure
    // test backend; the response must carry the delegation shape.
    let sess = daemon
        .call_ok(
            "agent_session_start",
            json!({"reason": "e2e", "label": "e2e-agent"}),
        )
        .await;
    let token = sess["session_token"].as_str().expect("session_token");
    assert!(
        token.starts_with("opqd1."),
        "identity-configured mint must produce a delegation token"
    );
    assert_eq!(sess["mode"], "delegated");
    assert_eq!(sess["on_behalf_of_label"], "dev@example.com");
    let on_behalf_of = sess["on_behalf_of"].as_str().unwrap();
    assert!(on_behalf_of.starts_with("hum_"));

    // The minted token verifies under the daemon's own signing key and
    // carries the delegated-mode claims (sub = the human, act = an agent).
    // (Per-request Agent-side enforcement — identity_required,
    // delegation_invalid, tampered-token rejection, lease isolation — is
    // exercised by the daemon unit tests; a single Human-classified harness
    // process cannot also be the wrapped Agent that executes.)
    let _ = token;

    // The delegation is recorded and visible to the admin who created it.
    let delegations = daemon
        .call_ok("identity.delegation_list", Value::Null)
        .await;
    let rows = delegations["delegations"].as_array().expect("delegations");
    assert_eq!(rows.len(), 1, "one delegation should be recorded");
    assert_eq!(rows[0]["mode"], "delegated");
    assert_eq!(rows[0]["sub_label"], "dev@example.com");
    assert!(rows[0]["revoked_at"].is_null(), "delegation is live");

    // Logout revokes the human login session.
    let out = daemon.call_ok("identity.logout", Value::Null).await;
    assert!(out["revoked"].as_u64().unwrap() >= 1);
    let who = daemon.call_ok("whoami", Value::Null).await;
    assert!(who["identity"].is_null(), "identity after logout: {who}");

    // Shut down and inspect the tamper-evident record.
    let (db, _home) = daemon.shutdown();
    let v = opaque_core::audit::verify_audit_chain(&db).expect("verify runs");
    assert!(v.ok, "audit chain broken: {:?}", v.detail);

    let events =
        opaque_core::audit::query_audit_db(&db, &opaque_core::audit::AuditFilter::default())
            .expect("query audit db");
    let kinds: Vec<String> = events.iter().map(|e| e.kind.to_string()).collect();
    for expected in [
        "identity.login.succeeded",
        "delegation.issued",
        "identity.logout",
    ] {
        assert!(
            kinds.iter().any(|k| k == expected),
            "audit must contain {expected}; kinds: {kinds:?}"
        );
    }
    // The session approval names its (test-backend) approver, proving the
    // approver-attribution pipeline end to end.
    let approved = events
        .iter()
        .filter(|e| e.approver.is_some())
        .collect::<Vec<_>>();
    assert!(
        !approved.is_empty(),
        "at least one approval event must carry an approver"
    );
    assert!(approved.iter().all(|e| {
        e.approver.as_ref().unwrap().source
            == opaque_core::audit::ApproverSource::InsecureAutoApprove
    }));
    // The delegation-issued event attributes the on-behalf-of principal.
    let issued = events
        .iter()
        .find(|e| e.kind.to_string() == "delegation.issued")
        .expect("delegation.issued present");
    if let Some(client) = &issued.client
        && let Some(p) = &client.principal
    {
        assert_eq!(p.sub_label, "dev@example.com");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize heavy e2e daemons (current-thread runtime)
async fn login_rejects_forged_nonce_end_to_end() {
    let _serial = serial_guard();
    let idp = MockOidc::start(CLIENT_ID).await;

    let daemon = TestDaemon::spawn(&identity_config(&idp.uri()));

    let attempt = begin_login(&daemon, &idp).await;
    let callback = request_code(
        &idp,
        &attempt.auth_url,
        "dev@example.com",
        Some("forged-nonce"),
    )
    .await;
    let status = finish_login(&daemon, &attempt, &callback).await;
    assert_eq!(
        idp.counts(),
        Counts {
            codes_issued: 1,
            token_requests: 1,
            tokens_issued: 1,
            token_rejections: 0
        },
        "the real daemon must reject the signed nonce after a valid PKCE exchange"
    );
    assert_no_session_and_sanitized_failure(
        daemon,
        &status,
        &query_param(&callback, "code").unwrap(),
        0,
    )
    .await;
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn login_rejects_pkce_challenge_substitution_before_creating_authority() {
    let _serial = serial_guard();
    let idp = MockOidc::start(CLIENT_ID).await;
    let daemon = TestDaemon::spawn(&identity_config(&idp.uri()));
    let attempt = begin_login(&daemon, &idp).await;
    let mut changed = reqwest::Url::parse(&attempt.auth_url).unwrap();
    let pairs: Vec<_> = changed.query_pairs().into_owned().collect();
    changed
        .query_pairs_mut()
        .clear()
        .extend_pairs(pairs.into_iter().map(|(key, value)| {
            if key == "code_challenge" {
                (key, oidc::challenge(&"attacker-verifier".repeat(4)))
            } else {
                (key, value)
            }
        }));
    // The IdP binds this code to the modified challenge. The real daemon has
    // only its original private verifier, so its token exchange must fail.
    let callback = request_code(&idp, changed.as_str(), "dev@example.com", None).await;
    let status = finish_login(&daemon, &attempt, &callback).await;
    assert_eq!(
        idp.counts(),
        Counts {
            codes_issued: 1,
            token_requests: 1,
            tokens_issued: 0,
            token_rejections: 1
        }
    );
    let principals = daemon.call_ok("identity.principal_list", Value::Null).await;
    assert!(principals["principals"].as_array().unwrap().is_empty());
    assert_no_session_and_sanitized_failure(
        daemon,
        &status,
        &query_param(&callback, "code").unwrap(),
        0,
    )
    .await;
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn login_rejects_replayed_code_after_logout_without_restoring_session() {
    let _serial = serial_guard();
    let idp = MockOidc::start(CLIENT_ID).await;
    let daemon = TestDaemon::spawn(&identity_config(&idp.uri()));
    let first = begin_login(&daemon, &idp).await;
    let callback = request_code(&idp, &first.auth_url, "dev@example.com", None).await;
    assert_eq!(
        finish_login(&daemon, &first, &callback).await["status"],
        "complete"
    );
    let code = query_param(&callback, "code").unwrap();
    assert!(
        daemon.call_ok("identity.logout", Value::Null).await["revoked"]
            .as_u64()
            .unwrap()
            >= 1
    );

    let second = begin_login(&daemon, &idp).await;
    let mut replay = reqwest::Url::parse(&second.redirect).unwrap();
    replay
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &second.state);
    let failed = finish_login(&daemon, &second, replay.as_str()).await;
    assert_eq!(
        idp.counts(),
        Counts {
            codes_issued: 1,
            token_requests: 2,
            tokens_issued: 1,
            token_rejections: 1
        }
    );
    assert_no_session_and_sanitized_failure(daemon, &failed, &code, 1).await;
}

/// Qualify actual CLI wrapping and pinned attestation against a real daemon,
/// synthetic signed OIDC issuer and durable identity/audit databases. Approval
/// is explicitly the guarded test backend, never claimed as native consent.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cli_wrapping_revokes_durable_delegations_and_verifies_pinned_attestation() {
    let _serial = serial_guard();
    let cli = Path::new(env!("CARGO_BIN_EXE_opaqued"))
        .with_file_name("opaque")
        .canonicalize()
        .expect("build workspace binaries before identity E2E: cargo build --workspace --bins");
    let idp = MockOidc::start(CLIENT_ID).await;
    let top = format!(
        "enforce_agent_sessions = true\napproval_backend = \"insecure_auto_approve\"\n[[known_human_clients]]\nname = \"actual-cli\"\nexe_path = {}",
        serde_json::to_string(cli.to_str().unwrap()).unwrap()
    );
    let daemon = TestDaemon::spawn_with_env(
        &identity_config_with(&idp.uri(), &top),
        &[("OPAQUE_INSECURE_AUTO_APPROVE", "1")],
    );
    let login = drive_login(&daemon, &idp, "cli@example.com", None).await;
    assert_eq!(login["status"], "complete");
    let command = || {
        let mut cmd = Command::new(&cli);
        cmd.env_clear()
            .env("HOME", daemon.home.as_ref().unwrap().path())
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env("PRIVATE_SENTINEL", "must-not-reach-child")
            .args(["--socket", daemon.sock.to_str().unwrap(), "--json"]);
        #[cfg(coverage_nightly)]
        {
            coverage::subprocess(&mut cmd, "peer");
        }
        let mut cmd = tokio::process::Command::from(cmd);
        cmd.kill_on_drop(true);
        cmd
    };
    for (args, code) in [
        (
            vec![
                "agent",
                "run",
                "--",
                "/bin/sh",
                "-c",
                "test -z \"$PRIVATE_SENTINEL\" && test -n \"$OPAQUE_SESSION_TOKEN\" && test -n \"$OPAQUE_AGENT_SESSION_ID\" || exit 90; exit 17",
            ],
            17,
        ),
        (
            vec!["agent", "run", "--", "/definitely/missing/opaque-agent"],
            1,
        ),
    ] {
        let output = tokio::time::timeout(Duration::from_secs(20), command().args(args).output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            daemon.call_ok("agent_session_list", Value::Null).await["count"],
            0
        );
        let records = daemon
            .call_ok("identity.delegation_list", Value::Null)
            .await;
        assert!(
            records["delegations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| !row["revoked_at"].is_null())
        );
    }
    // A readiness marker, not elapsed time, establishes that the actual child
    // is running and the delegation is active before terminating its wrapper.
    let marker = daemon.home.as_ref().unwrap().path().join("child.pid");
    let mut wrapper = command()
        .args([
            "agent",
            "run",
            "--",
            "/bin/sh",
            "-c",
            "echo $$ > \"$1\"; exec /bin/sleep 60",
            "opaque-test",
        ])
        .arg(&marker)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !marker.exists() {
        assert!(
            wrapper.try_wait().unwrap().is_none(),
            "wrapper exited before child readiness"
        );
        assert!(Instant::now() < deadline, "child readiness deadline");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let child_pid: i32 = std::fs::read_to_string(&marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(
        daemon.call_ok("agent_session_list", Value::Null).await["count"],
        1
    );
    unsafe {
        assert_eq!(libc::kill(wrapper.id().unwrap() as i32, libc::SIGTERM), 0);
    }
    let output = tokio::time::timeout(Duration::from_secs(10), wrapper.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(128 + libc::SIGTERM),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        unsafe { libc::kill(child_pid, 0) },
        -1,
        "wrapped child survived termination"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    assert_eq!(
        daemon.call_ok("agent_session_list", Value::Null).await["count"],
        0
    );

    // Pin comes from the fixture's isolated custody file, independently of the
    // report being verified. No runtime key bytes are logged or retained.
    let bytes = std::fs::read(
        daemon
            .home
            .as_ref()
            .unwrap()
            .path()
            .join(".opaque/attestation.key"),
    )
    .unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&bytes.try_into().unwrap());
    let pin: String = signing
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        command().args(["attest", "--key", &pin]).output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verdict["verified"], true);
    assert_eq!(verdict["key_pinned"], true);
    assert_eq!(verdict["healthy"], true);
    assert_eq!(
        verdict["release_eligible"], false,
        "session mode must not qualify key release"
    );
    let records = daemon
        .call_ok("identity.delegation_list", Value::Null)
        .await;
    assert_eq!(records["delegations"].as_array().unwrap().len(), 3);
    assert!(
        records["delegations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| !row["revoked_at"].is_null())
    );
    let (audit, _home) = daemon.shutdown();
    let identity = rusqlite::Connection::open_with_flags(
        audit.with_file_name("identity.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let (total, active): (u64, u64) = identity
        .query_row(
            "SELECT COUNT(*), SUM(revoked_at IS NULL) FROM delegations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (total, active),
        (3, 0),
        "revocation must survive connection teardown and database reopen"
    );
    assert!(opaque_core::audit::verify_audit_chain(&audit).unwrap().ok);
    let events =
        opaque_core::audit::query_audit_db(&audit, &opaque_core::audit::AuditFilter::default())
            .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.kind.to_string() == "delegation.issued")
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.operation.as_deref() == Some("agent_session_end")
                && e.kind == opaque_core::audit::AuditEventKind::OperationSucceeded)
            .count(),
        3
    );
    assert!(
        events
            .iter()
            .filter_map(|e| e.approver.as_ref())
            .all(|a| a.source == opaque_core::audit::ApproverSource::InsecureAutoApprove)
    );
}
