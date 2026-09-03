//! End-to-end proof that the provider RPC surface actually works against the
//! REAL `opaqued` binary: the flagship `github.set_actions_secret` path, from
//! client request through ref validation, target-key validation, policy,
//! approval, secret resolution, sealed-box encryption, the GitHub API call,
//! and response sanitization.
//!
//! Why this exists: two independent regressions had made every GitHub write
//! impossible, and every unit test still passed, because nothing drove a
//! provider request through a live daemon.
//!
//!   1. `validate_secret_ref_names` forbade ':' — the scheme separator the
//!      daemon itself REQUIRES on a `value_ref` — so every well-formed ref
//!      was rejected as `bad_request`.
//!   2. The github handlers put `secret_name` (and `environment`) in the
//!      operation target so rules can constrain on them, but the operation
//!      registry's `allowed_target_keys` listed only `repo`, so the enclave
//!      rejected the request as an unexpected target key.
//!
//! Both were invisible to unit tests and immediately fatal in production.
//!
//! Socket paths stay short (macOS `SUN_LEN`), so the runtime dir lives
//! directly under /tmp rather than a nested tempdir.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// These spawn real daemons; running several at once causes socket and
/// resource contention. Serialize them. `tokio::test` without a flavor is a
/// CURRENT-THREAD runtime, so the future never migrates between threads and
/// holding a std guard across awaits is sound (same pattern as federation_e2e).
static E2E_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    E2E_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).unwrap();
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

const TEST_PAT: &str = "ghp_e2e_placeholder_not_a_real_token";
const TEST_VALUE: &str = "tutorial-value-plaintext";

struct Fixture {
    home: tempfile::TempDir,
    runtime_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // Custody refuses a runtime path that traverses a symlink, and on
        // macOS /tmp is one — canonicalize before the daemon sees it.
        let tmp_base = Path::new("/tmp")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let runtime_dir = tmp_base.join(format!("oqprov{}-{}", std::process::id(), rand_hex(4)));
        std::fs::create_dir_all(&runtime_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            home: tempfile::tempdir().unwrap(),
            runtime_dir,
        }
    }

    /// A policy that allows the GitHub write and nothing else — the same
    /// shape the `github-secrets` preset ships.
    fn write_config(&self) -> PathBuf {
        let config_path = self.home.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
# The enclave clamps approval to each operation's floor, and this operation's
# floor is Always — so an unattended e2e needs the test approval backend
# (which additionally demands OPAQUE_INSECURE_AUTO_APPROVE=1 in the env).
approval_backend = "insecure_auto_approve"

[[rules]]
name = "allow-github-actions-secret"
operation_pattern = "github.set_actions_secret"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]
"#,
        )
        .unwrap();
        config_path
    }

    fn spawn(&self, config_path: &Path, github_api: &str) -> Daemon {
        let sock = self.runtime_dir.join("opaque").join("opaqued.sock");
        let token_path = self.runtime_dir.join("opaque").join("daemon.token");
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(&token_path);

        let log = self.home.path().join(format!("daemon-{}.log", rand_hex(3)));
        let log_file = std::fs::File::create(&log).unwrap();
        // The daemon's tracing subscriber writes to STDOUT; capture both
        // streams or the log looks mysteriously empty.
        let log_stdout = log_file.try_clone().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_opaqued"))
            .env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("OPAQUE_CONFIG", config_path)
            .env("RUST_LOG", "info")
            .env("OPAQUE_INSECURE_AUTO_APPROVE", "1")
            .env("OPAQUE_GITHUB_API_URL", github_api)
            // Resolved by the daemon's own EnvResolver — `env:` refs keep the
            // test off the OS keychain (which would prompt).
            .env("OPAQUE_E2E_PAT", TEST_PAT)
            .env("OPAQUE_E2E_VALUE", TEST_VALUE)
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::from(log_stdout))
            .stderr(log_file)
            .spawn()
            .expect("spawn opaqued");

        let mut daemon = Daemon {
            child_pid: child.id(),
            child,
            sock,
            token: String::new(),
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while (!daemon.sock.exists() || !token_path.exists()) && Instant::now() < deadline {
            if let Ok(Some(status)) = daemon.child.try_wait() {
                panic!(
                    "daemon exited early ({status}):\n{}",
                    std::fs::read_to_string(&daemon.log).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            daemon.sock.exists() && token_path.exists(),
            "daemon did not come up:\n{}",
            std::fs::read_to_string(&daemon.log).unwrap_or_default()
        );
        daemon.token = std::fs::read_to_string(&token_path)
            .expect("daemon token")
            .trim()
            .to_owned();
        daemon
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

struct Daemon {
    child_pid: u32,
    child: Child,
    sock: PathBuf,
    token: String,
    log: PathBuf,
}

impl Daemon {
    async fn call(&self, method: &str, params: Value) -> Value {
        use futures_util::{SinkExt, StreamExt};
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let stream = tokio::net::UnixStream::connect(&self.sock)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "connect: {e}\ndaemon log:\n{}",
                    std::fs::read_to_string(&self.log).unwrap_or_default()
                )
            });
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
            .new_codec();
        let mut framed = Framed::new(stream, codec);

        let handshake = json!({"handshake": "v1", "daemon_token": self.token});
        framed
            .send(serde_json::to_vec(&handshake).unwrap().into())
            .await
            .expect("send handshake");
        framed
            .send(
                serde_json::to_vec(&json!({"id": 1, "method": method, "params": params}))
                    .unwrap()
                    .into(),
            )
            .await
            .expect("send request");
        match tokio::time::timeout(Duration::from_secs(20), framed.next()).await {
            Ok(Some(Ok(frame))) => serde_json::from_slice(&frame).expect("response json"),
            other => {
                std::thread::sleep(Duration::from_millis(300));
                panic!(
                    "{method} failed: {other:?}\ndaemon alive: {}\ndaemon log:\n{}",
                    std::process::Command::new("kill")
                        .args(["-0", &self.child_pid.to_string()])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false),
                    std::fs::read_to_string(&self.log).unwrap_or_default()
                )
            }
        }
    }

    fn shutdown(mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
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
    }
}

/// Stand in for the GitHub API: hand out a real Curve25519 public key, then
/// accept the sealed secret.
async fn mock_github() -> MockServer {
    let server = MockServer::start().await;
    let public_key: [u8; 32] = {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).unwrap();
        buf
    };
    use base64::Engine as _;
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/actions/secrets/public-key"))
        .and(header("authorization", format!("Bearer {TEST_PAT}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"key_id": "568250167", "key": key_b64})),
        )
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/repos/acme/widgets/actions/secrets/TUTORIAL_KEY"))
        .and(header("authorization", format!("Bearer {TEST_PAT}")))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;

    server
}

/// The tutorial's flagship step, end to end: an agent-shaped request sets a
/// GitHub Actions secret it never sees.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize real daemons (current-thread runtime)
async fn github_set_actions_secret_succeeds_end_to_end() {
    let _serial = serial_guard();
    let github = mock_github().await;
    let fixture = Fixture::new();
    let config_path = fixture.write_config();
    let daemon = fixture.spawn(&config_path, &github.uri());

    let resp = daemon
        .call(
            "github",
            json!({
                "scope": "repo_actions",
                "repo": "acme/widgets",
                "secret_name": "TUTORIAL_KEY",
                // Scheme-prefixed refs are the ONLY shape the daemon accepts.
                "value_ref": "env:OPAQUE_E2E_VALUE",
                "github_token_ref": "env:OPAQUE_E2E_PAT",
            }),
        )
        .await;

    assert!(
        resp.get("error").is_none_or(Value::is_null),
        "github set-secret failed — a well-formed provider request must reach \
         the enclave, not die in validation: {resp}"
    );
    let result = resp.get("result").expect("result");
    let status = result.get("status").and_then(Value::as_str).unwrap_or("");
    assert!(
        matches!(status, "created" | "updated"),
        "unexpected status in {result}"
    );
    assert_eq!(
        result.get("secret_name").and_then(Value::as_str),
        Some("TUTORIAL_KEY")
    );

    // The response an agent would see carries no secret material — not the
    // plaintext, and not the token used to deliver it.
    let rendered = serde_json::to_string(&resp).unwrap();
    assert!(
        !rendered.contains(TEST_VALUE),
        "secret value leaked into the response: {rendered}"
    );
    assert!(
        !rendered.contains(TEST_PAT),
        "GitHub token leaked into the response: {rendered}"
    );

    // The API actually received the write (the daemon did not silently no-op).
    let requests = github.received_requests().await.unwrap_or_default();
    assert!(
        requests.iter().any(|r| r.method.as_str() == "PUT"),
        "no PUT reached the GitHub API; requests: {:?}",
        requests.iter().map(|r| r.url.path()).collect::<Vec<_>>()
    );

    daemon.shutdown();
}

/// An operation no rule names dies at the policy engine — not at input
/// validation, and not at the provider. Deny-by-default has to be the reason
/// a request fails, or the guarantee is an accident of validation order.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn unlisted_provider_operation_is_policy_denied() {
    let _serial = serial_guard();
    let github = mock_github().await;
    let fixture = Fixture::new();
    let config_path = fixture.write_config();
    let daemon = fixture.spawn(&config_path, &github.uri());

    let resp = daemon
        .call(
            "gitlab",
            json!({
                "action": "set_ci_variable",
                "project": "acme/widgets",
                "key": "TUTORIAL_KEY",
                "value_ref": "env:OPAQUE_E2E_VALUE",
                "gitlab_token_ref": "env:OPAQUE_E2E_PAT",
            }),
        )
        .await;

    let code = resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert_eq!(
        code, "policy_denied",
        "expected a policy denial, got: {resp}"
    );

    daemon.shutdown();
}
