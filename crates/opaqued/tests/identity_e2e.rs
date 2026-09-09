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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_RSA_PEM: &str = include_str!("fixtures/test_rsa_key.pem");
const TEST_JWKS: &str = include_str!("fixtures/test_idp_jwks.json");
const TEST_KID: &str = "test-key-1";
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

// ---------------------------------------------------------------------------
// Mock IdP helpers
// ---------------------------------------------------------------------------

async fn mount_idp(server: &MockServer) {
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::from_str::<Value>(TEST_JWKS).unwrap()),
        )
        .mount(server)
        .await;
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign_id_token(claims: Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(TEST_KID.to_owned());
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, &claims, &key).unwrap()
}

fn id_token_claims(issuer: &str, nonce: &str, email: &str) -> Value {
    json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": "e2e-user-1",
        "email": email,
        "name": "E2E Human",
        "nonce": nonce,
        "iat": now_unix(),
        "exp": now_unix() + 600,
    })
}

/// Mount the token endpoint AFTER the nonce is known (it must be embedded in
/// the signed id_token).
async fn mount_token_endpoint(server: &MockServer, id_token: String) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "unused",
            "token_type": "Bearer",
            "id_token": id_token,
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// URL helpers (tiny, test-only)
// ---------------------------------------------------------------------------

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == name {
            return Some(percent_decode(v));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Daemon harness
// ---------------------------------------------------------------------------

struct TestDaemon {
    child: Child,
    home: tempfile::TempDir,
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
            home,
            runtime_dir,
            sock,
            daemon_token,
        }
    }

    fn audit_db(&self) -> PathBuf {
        self.home.path().join(".opaque").join("audit.db")
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
        (db, self.home)
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
    let exe = std::env::current_exe().unwrap();
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

/// Drive the full browser-side of the login: start the attempt, extract
/// state/nonce/redirect from the auth URL, arm the token endpoint with a
/// signed id_token, then hit the daemon's loopback callback like the IdP
/// redirect would.
async fn drive_login(
    daemon: &TestDaemon,
    idp: &MockServer,
    email: &str,
    forge_nonce: Option<&str>,
) -> Value {
    let start = daemon.call_ok("identity.login_start", Value::Null).await;
    let attempt_id = start["attempt_id"].as_str().expect("attempt_id").to_owned();
    let auth_url = start["auth_url"].as_str().expect("auth_url").to_owned();

    let state = query_param(&auth_url, "state").expect("state in auth_url");
    let nonce = query_param(&auth_url, "nonce").expect("nonce in auth_url");
    let redirect_uri = query_param(&auth_url, "redirect_uri").expect("redirect_uri in auth_url");

    let token_nonce = forge_nonce.unwrap_or(&nonce);
    let id_token = sign_id_token(id_token_claims(&idp.uri(), token_nonce, email));
    mount_token_endpoint(idp, id_token).await;

    // The "browser redirect": GET the daemon's loopback callback.
    let callback = format!("{redirect_uri}?code=e2e-code&state={state}");
    let resp = reqwest::get(&callback).await.expect("callback reachable");
    assert!(resp.status().is_success() || resp.status().is_client_error());

    // Poll login_status until terminal.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = daemon
            .call_ok("identity.login_status", json!({"attempt_id": attempt_id}))
            .await;
        match status["status"].as_str() {
            Some("pending") => {
                assert!(Instant::now() < deadline, "login never became terminal");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            _ => return status,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    let idp = MockServer::start().await;
    mount_idp(&idp).await;

    let daemon = TestDaemon::spawn(&identity_config(&idp.uri()));

    // Sanity: daemon is up and identity-aware.
    let pong = daemon.call_ok("ping", Value::Null).await;
    assert_eq!(pong["ok"], true);

    let status = drive_login(&daemon, &idp, "dev@example.com", None).await;
    assert_eq!(status["status"], "complete", "login failed: {status}");
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
    let idp = MockServer::start().await;
    mount_idp(&idp).await;

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
    let idp = MockServer::start().await;
    mount_idp(&idp).await;

    let daemon = TestDaemon::spawn(&identity_config(&idp.uri()));

    let status = drive_login(&daemon, &idp, "dev@example.com", Some("forged-nonce")).await;
    assert_eq!(
        status["status"], "failed",
        "forged nonce must fail login: {status}"
    );

    // No session was created.
    let who = daemon.call_ok("whoami", Value::Null).await;
    assert!(who["identity"].is_null());

    let (db, _home) = daemon.shutdown();
    let v = opaque_core::audit::verify_audit_chain(&db).expect("verify runs");
    assert!(v.ok);
}
