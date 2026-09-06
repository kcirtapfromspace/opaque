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

    /// Like [`Fixture::write_config`] but with a caller-supplied `[[rules]]`
    /// body instead of the fixed GitHub-only rule, for exercising other
    /// providers' operations. An empty `rules_toml` yields deny-by-default
    /// (no rule matches anything) — useful for proving a request reaches (or
    /// is rejected before reaching) the policy engine.
    fn write_config_with_rules(&self, rules_toml: &str) -> PathBuf {
        let config_path = self.home.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("approval_backend = \"insecure_auto_approve\"\n\n{rules_toml}\n"),
        )
        .unwrap();
        config_path
    }

    fn spawn(&self, config_path: &Path, github_api: &str) -> Daemon {
        self.spawn_with_env(config_path, github_api, &[])
    }

    /// Like [`Fixture::spawn`] but with additional provider-specific env vars
    /// (mock endpoint URLs, `env:`-scheme credential ref overrides, etc.).
    fn spawn_with_env(
        &self,
        config_path: &Path,
        github_api: &str,
        extra_env: &[(&str, &str)],
    ) -> Daemon {
        let sock = self.runtime_dir.join("opaque").join("opaqued.sock");
        let token_path = self.runtime_dir.join("opaque").join("daemon.token");
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(&token_path);

        let log = self.home.path().join(format!("daemon-{}.log", rand_hex(3)));
        let log_file = std::fs::File::create(&log).unwrap();
        // The daemon's tracing subscriber writes to STDOUT; capture both
        // streams or the log looks mysteriously empty.
        let log_stdout = log_file.try_clone().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_opaqued"));
        cmd.env("HOME", self.home.path())
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
            .stderr(log_file);
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        let child = cmd.spawn().expect("spawn opaqued");

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

// ---------------------------------------------------------------------------
// opaque-providers extraction: one e2e smoke test per provider that had zero
// e2e coverage before the crate split (aws, azure, gcp, onepassword,
// bitwarden, doppler, infisical, vault). Each drives the real daemon binary
// over its real RPC socket, the same way the two tests above do.
//
// aws/onepassword/bitwarden/vault reach a real (mocked) HTTP backend and
// assert a full success round-trip. azure/gcp/doppler/infisical are not
// wired into `main.rs`'s `Enclave::builder()`/operation registry at all
// today (dormant, compiled-but-unused — true before this extraction too;
// verified by grepping `main.rs` for their operation names, which are
// nowhere registered) — the most meaningful, honest test available for
// those four is that the daemon rejects their operations as
// `unknown_operation` rather than crashing, hanging, or silently
// mis-dispatching. None of the four's own client/resolver code runs in
// this build, so this specifically does NOT exercise it — see each test's
// doc comment for exact coverage.
// ---------------------------------------------------------------------------

/// AWS has no dedicated RPC method (unlike github/gitlab/onepassword/
/// bitwarden) — it is reachable only through the generic `execute` method
/// with a client-supplied `operation` string. Production AWS transport is
/// permanently disabled pending SigV4; the only AWS path that can ever run
/// is the explicit loopback mock (`OPAQUE_AWS_ALLOW_INSECURE=1` +
/// `OPAQUE_AWS_MOCK_URL`), so that is what this test drives end to end:
/// ref resolution (access/secret key via `env:` refs), policy, approval,
/// the mocked STS `GetCallerIdentity` call, and the response shape. Does
/// NOT cover real (signed) AWS transport, which does not exist yet.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn aws_get_caller_identity_succeeds_end_to_end() {
    let _serial = serial_guard();
    let aws = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header(
            "x-amz-target",
            "AWSSecurityTokenServiceV20110615.GetCallerIdentity",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/e2e-test",
            "UserId": "AIDAE2ETEST",
        })))
        .mount(&aws)
        .await;

    let fixture = Fixture::new();
    let config_path = fixture.write_config_with_rules(
        r#"
[[rules]]
name = "allow-aws-caller-identity"
operation_pattern = "aws.get_caller_identity"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]
"#,
    );
    let aws_uri = aws.uri();
    let daemon = fixture.spawn_with_env(
        &config_path,
        "https://api.github.com",
        &[
            ("OPAQUE_AWS_ALLOW_INSECURE", "1"),
            ("OPAQUE_AWS_MOCK_URL", aws_uri.as_str()),
            ("OPAQUE_AWS_ACCESS_KEY_REF", "env:OPAQUE_E2E_AWS_AK"),
            ("OPAQUE_AWS_SECRET_KEY_REF", "env:OPAQUE_E2E_AWS_SK"),
            ("OPAQUE_E2E_AWS_AK", "test-access-key"),
            ("OPAQUE_E2E_AWS_SK", "test-secret-key"),
        ],
    );

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "aws.get_caller_identity",
                "target": {},
                "params": {},
            }),
        )
        .await;

    assert!(
        resp.get("error").is_none_or(Value::is_null),
        "aws.get_caller_identity failed — a well-formed mock-configured AWS \
         request must reach the enclave and the mocked STS endpoint: {resp}"
    );
    let result = resp.get("result").expect("result");
    assert_eq!(
        result.get("account").and_then(Value::as_str),
        Some("123456789012"),
        "unexpected result: {result}"
    );

    let requests = aws.received_requests().await.unwrap_or_default();
    assert!(
        !requests.is_empty(),
        "no request reached the mocked AWS STS endpoint"
    );

    daemon.shutdown();
}

/// 1Password has its own bespoke RPC method for setting secrets, but
/// `onepassword.list_vaults` (used here) is only reachable through the
/// generic `execute` method. Drives the Connect Server backend (the
/// self-hosted REST API path, selected whenever
/// `OPAQUE_1PASSWORD_CONNECT_URL` is set) end to end against a mocked
/// Connect server: token resolution via an `env:` ref, policy, approval,
/// the mocked `GET /v1/vaults` call, and the sanitized response shape
/// (names only, no vault IDs). Does NOT cover the `op` CLI backend path
/// (`OnePasswordHandler::from_cli`), which shells out to a local binary
/// this test environment does not have.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn onepassword_list_vaults_succeeds_end_to_end() {
    let _serial = serial_guard();
    let op_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .and(header("authorization", "Bearer test-op-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "vault123", "name": "Engineering", "description": "Eng team vault"}
        ])))
        .mount(&op_server)
        .await;

    let fixture = Fixture::new();
    let config_path = fixture.write_config_with_rules(
        r#"
[[rules]]
name = "allow-onepassword-list-vaults"
operation_pattern = "onepassword.list_vaults"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]
"#,
    );
    let op_uri = op_server.uri();
    let daemon = fixture.spawn_with_env(
        &config_path,
        "https://api.github.com",
        &[
            ("OPAQUE_1PASSWORD_CONNECT_URL", op_uri.as_str()),
            ("OPAQUE_1PASSWORD_TOKEN_REF", "env:OPAQUE_E2E_OP_TOKEN"),
            ("OPAQUE_E2E_OP_TOKEN", "test-op-token"),
        ],
    );

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "onepassword.list_vaults",
                "target": {},
                "params": {},
            }),
        )
        .await;

    assert!(
        resp.get("error").is_none_or(Value::is_null),
        "onepassword.list_vaults failed: {resp}"
    );
    let result = resp.get("result").expect("result");
    let vaults = result.get("vaults").and_then(Value::as_array).expect("vaults array");
    assert!(
        vaults
            .iter()
            .any(|v| v.get("name").and_then(Value::as_str) == Some("Engineering")),
        "expected vault 'Engineering' in sanitized response: {result}"
    );
    // Sanitized: no vault IDs leak into the response an agent sees.
    let rendered = serde_json::to_string(&resp).unwrap();
    assert!(
        !rendered.contains("vault123"),
        "vault id leaked into the response: {rendered}"
    );

    daemon.shutdown();
}

/// Bitwarden's handler is always registered (unlike 1Password, it has no
/// "is this even configured" gate — it defaults to the real Bitwarden URL
/// unless overridden), so this only needs to override the URL and token ref
/// to redirect it at a mock. Drives `bitwarden.list_projects` end to end:
/// token resolution via an `env:` ref, policy, approval, the mocked
/// `GET /api/projects` call, and the sanitized (names-only) response shape.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bitwarden_list_projects_succeeds_end_to_end() {
    let _serial = serial_guard();
    let bw_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/projects"))
        .and(header("authorization", "Bearer test-bw-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "proj123", "name": "backend-secrets"}
        ])))
        .mount(&bw_server)
        .await;

    let fixture = Fixture::new();
    let config_path = fixture.write_config_with_rules(
        r#"
[[rules]]
name = "allow-bitwarden-list-projects"
operation_pattern = "bitwarden.list_projects"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]
"#,
    );
    let bw_uri = bw_server.uri();
    let daemon = fixture.spawn_with_env(
        &config_path,
        "https://api.github.com",
        &[
            ("OPAQUE_BITWARDEN_URL", bw_uri.as_str()),
            ("OPAQUE_BITWARDEN_TOKEN_REF", "env:OPAQUE_E2E_BW_TOKEN"),
            ("OPAQUE_E2E_BW_TOKEN", "test-bw-token"),
        ],
    );

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "bitwarden.list_projects",
                "target": {},
                "params": {},
            }),
        )
        .await;

    assert!(
        resp.get("error").is_none_or(Value::is_null),
        "bitwarden.list_projects failed: {resp}"
    );
    let result = resp.get("result").expect("result");
    let projects = result
        .get("projects")
        .and_then(Value::as_array)
        .expect("projects array");
    assert!(
        projects
            .iter()
            .any(|p| p.get("name").and_then(Value::as_str) == Some("backend-secrets")),
        "expected project 'backend-secrets' in sanitized response: {result}"
    );
    let rendered = serde_json::to_string(&resp).unwrap();
    assert!(
        !rendered.contains("proj123"),
        "project id leaked into the response: {rendered}"
    );

    daemon.shutdown();
}

/// Vault exposes no `OperationHandler` of its own — no `vault.*` operation
/// is ever registered (it is resolver-only: it just teaches `value_ref`/
/// `github_token_ref`-style params how to resolve a `vault:` scheme). The
/// only way to exercise its real HTTP client end to end through the daemon
/// is via another provider's ref resolution, so this drives
/// `github.set_actions_secret` with a `value_ref` in the `vault:` scheme.
///
/// Routed through the generic `execute` method rather than the ad-hoc
/// `"github"` RPC method deliberately: the ad-hoc wrapper's
/// `InputValidator::validate_secret_ref_names` charset-allowlists ref
/// bodies to `[A-Za-z0-9_./:-]` — it does not include `#`, which every
/// `vault:<path>#<field>` ref requires — so a `vault:`-scheme `value_ref`
/// can never pass that specific gate (a pre-existing constraint, not
/// something this extraction introduced or could fix in scope). The
/// generic `execute` method validates only the client-declared
/// `secret_ref_names` array up front (trivially empty here); the enclave
/// re-derives the real `secret_ref_names` from `params` server-side
/// (`derive_secret_ref_names`, which performs no charset check) before
/// dispatch, so the same `github.set_actions_secret` operation and handler
/// run either way. Confirms: Vault client construction from
/// `OPAQUE_VAULT_URL`, KV v2 field extraction, `env:`-ref token
/// resolution, and the resolved value actually reaching the sealed-box
/// GitHub write — all through the real RPC boundary, previously only
/// covered by in-process unit tests. Does NOT cover the ad-hoc `"github"`
/// RPC wrapper with a vault-scheme ref (rejected by input validation, as
/// above) or Vault lease renewal/caching (covered by
/// `vault::resolve`'s inline unit tests, unaffected by this move).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn github_set_actions_secret_resolves_vault_value_ref_end_to_end() {
    let _serial = serial_guard();
    let github = mock_github().await;
    let vault = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/app"))
        .and(header("x-vault-token", "test-vault-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "TOKEN": TEST_VALUE } }
        })))
        .mount(&vault)
        .await;

    let fixture = Fixture::new();
    let config_path = fixture.write_config();
    let vault_uri = vault.uri();
    let daemon = fixture.spawn_with_env(
        &config_path,
        &github.uri(),
        &[
            ("OPAQUE_VAULT_URL", vault_uri.as_str()),
            ("OPAQUE_VAULT_TOKEN_REF", "env:OPAQUE_E2E_VAULT_TOKEN"),
            ("OPAQUE_E2E_VAULT_TOKEN", "test-vault-token"),
        ],
    );

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "github.set_actions_secret",
                "target": {"repo": "acme/widgets", "secret_name": "TUTORIAL_KEY"},
                "params": {
                    "repo": "acme/widgets",
                    "secret_name": "TUTORIAL_KEY",
                    "value_ref": "vault:secret/data/app#TOKEN",
                    "github_token_ref": "env:OPAQUE_E2E_PAT",
                },
            }),
        )
        .await;

    assert!(
        resp.get("error").is_none_or(Value::is_null),
        "github.set_actions_secret with a vault: value_ref failed: {resp}"
    );
    let result = resp.get("result").expect("result");
    let status = result.get("status").and_then(Value::as_str).unwrap_or("");
    assert!(
        matches!(status, "created" | "updated"),
        "unexpected status in {result}"
    );

    let vault_requests = vault.received_requests().await.unwrap_or_default();
    assert!(
        vault_requests
            .iter()
            .any(|r| r.url.path() == "/v1/secret/data/app"),
        "no read reached the mocked Vault server; requests: {:?}",
        vault_requests
            .iter()
            .map(|r| r.url.path())
            .collect::<Vec<_>>()
    );
    let github_requests = github.received_requests().await.unwrap_or_default();
    assert!(
        github_requests.iter().any(|r| r.method.as_str() == "PUT"),
        "no PUT reached the mocked GitHub API"
    );

    daemon.shutdown();
}

/// Azure is not wired into `main.rs`'s `default_secret_resolvers()` or
/// `Enclave::builder()` at all (dormant — `#[allow(dead_code)]` on its
/// module, same before and after this extraction; confirmed no
/// `azure.*` operation is registered anywhere in `main.rs`). This proves
/// the honest current behavior — a syntactically well-formed request for a
/// real azure operation name is rejected as `unknown_operation` at the
/// registry, before policy or any handler — rather than crashing, hanging,
/// or silently mis-dispatching to another provider. Does NOT exercise
/// `opaque_providers::azure`'s own client/resolver code, which this build
/// never wires up; that is covered by its inline unit tests only. Wiring
/// azure in (and giving it this test's stronger, mocked round-trip
/// coverage) is future feature-gating work, not part of this extraction.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn azure_operation_is_unknown_end_to_end() {
    let _serial = serial_guard();
    let fixture = Fixture::new();
    let config_path = fixture.write_config_with_rules("");
    let daemon = fixture.spawn(&config_path, "https://api.github.com");

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "azure.list_secrets",
                "target": {},
                "params": {},
            }),
        )
        .await;

    let code = resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert_eq!(
        code, "unknown_operation",
        "expected azure.list_secrets to be unregistered (dormant provider), got: {resp}"
    );

    daemon.shutdown();
}

/// GCP is not wired into `main.rs` at all today (dormant, same as azure
/// above — no `gcp.*` operation is registered). See
/// `azure_operation_is_unknown_end_to_end` for the full rationale; this is
/// the same shape for GCP. Does NOT exercise
/// `opaque_providers::gcp`'s own client/resolver code (inline-unit-tested
/// only).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn gcp_operation_is_unknown_end_to_end() {
    let _serial = serial_guard();
    let fixture = Fixture::new();
    let config_path = fixture.write_config_with_rules("");
    let daemon = fixture.spawn(&config_path, "https://api.github.com");

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "gcp.list_secrets",
                "target": {},
                "params": {},
            }),
        )
        .await;

    let code = resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert_eq!(
        code, "unknown_operation",
        "expected gcp.list_secrets to be unregistered (dormant provider), got: {resp}"
    );

    daemon.shutdown();
}

/// Doppler is not wired into `main.rs` at all today (dormant, same as azure
/// above — no `doppler.*` operation is registered). See
/// `azure_operation_is_unknown_end_to_end` for the full rationale; this is
/// the same shape for Doppler. Does NOT exercise
/// `opaque_providers::doppler`'s own client/resolver code (inline-unit-tested
/// only).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn doppler_operation_is_unknown_end_to_end() {
    let _serial = serial_guard();
    let fixture = Fixture::new();
    let config_path = fixture.write_config_with_rules("");
    let daemon = fixture.spawn(&config_path, "https://api.github.com");

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "doppler.list_secrets",
                "target": {},
                "params": {},
            }),
        )
        .await;

    let code = resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert_eq!(
        code, "unknown_operation",
        "expected doppler.list_secrets to be unregistered (dormant provider), got: {resp}"
    );

    daemon.shutdown();
}

/// Infisical is not wired into `main.rs` at all today (dormant, same as
/// azure above — no `infisical.*` operation is registered). See
/// `azure_operation_is_unknown_end_to_end` for the full rationale; this is
/// the same shape for Infisical. Does NOT exercise
/// `opaque_providers::infisical`'s own client/resolver code
/// (inline-unit-tested only).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn infisical_operation_is_unknown_end_to_end() {
    let _serial = serial_guard();
    let fixture = Fixture::new();
    let config_path = fixture.write_config_with_rules("");
    let daemon = fixture.spawn(&config_path, "https://api.github.com");

    let resp = daemon
        .call(
            "execute",
            json!({
                "operation": "infisical.list_secrets",
                "target": {},
                "params": {},
            }),
        )
        .await;

    let code = resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    assert_eq!(
        code, "unknown_operation",
        "expected infisical.list_secrets to be unregistered (dormant provider), got: {resp}"
    );

    daemon.shutdown();
}
