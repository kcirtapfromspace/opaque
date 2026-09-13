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

// A failed assertion must not leave a fixture daemon or its socket alive.
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
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
/// with a client-supplied `operation` string. This drives the signed AWS
/// transport against an explicit loopback fixture using public synthetic
/// credentials: ref resolution, policy, approval, the real STS Query/XML
/// protocol and sanitized response. Live AWS/IAM qualification is separate.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn aws_get_caller_identity_succeeds_end_to_end() {
    let _serial = serial_guard();
    let aws = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(wiremock::matchers::body_string("Action=GetCallerIdentity&Version=2011-06-15"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/e2e-test</Arn><UserId>AIDAE2ETEST</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>",
            "text/xml",
        ))
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
            ("OPAQUE_E2E_AWS_AK", "AKIAIOSFODNN7EXAMPLE"),
            (
                "OPAQUE_E2E_AWS_SK",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
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

    let authorization = requests[0]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 "));
    assert!(authorization.contains("/us-east-1/sts/aws4_request"));
    assert!(!requests[0].headers.contains_key("x-amz-secret-key"));
    assert!(!requests[0].headers.contains_key("x-amz-access-key"));

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
    let vaults = result
        .get("vaults")
        .and_then(Value::as_array)
        .expect("vaults array");
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

/// Explicit test fixture for the official `bws` subprocess contract. Production
/// uses an installed official executable; this file exists only inside the test.
#[cfg(unix)]
fn bitwarden_cli_fixture(fixture: &Fixture) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let executable = fixture.home.path().join("bws-fixture");
    std::fs::write(
        &executable,
        r#"#!/bin/sh
set -eu
[ -n "$0" ] && : > "$0.invoked"
[ "${BWS_ACCESS_TOKEN-}" = 'test-bw-token' ] || exit 9
[ "$1" = '--config-file' ] && [ -f "$2" ] || exit 10
[ "$3 $4 $5 $6 $7 $8" = '--profile opaque --output json --color no' ] || exit 11
case "$9 ${10}" in
  'project list') printf '%s' '[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","name":"backend-secrets"}]' ;;
  'secret get')
    [ "${11}" = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' ] || exit 12
    printf '%s' '{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","key":"TUTORIAL_KEY","value":"tutorial-value-plaintext","note":"private fixture note"}' ;;
  *) exit 13 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    executable
}

/// Daemon policy, approval, environment-ref token resolution, official CLI
/// command shape, and sanitized project browsing. This is a subprocess fixture
/// test; the ignored provider acceptance test separately exercises a live account.
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bitwarden_list_projects_succeeds_end_to_end() {
    let _serial = serial_guard();
    let fixture = Fixture::new();
    let executable = bitwarden_cli_fixture(&fixture);
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
    let daemon = fixture.spawn_with_env(
        &config_path,
        "https://api.github.com",
        &[
            ("OPAQUE_BITWARDEN_URL", "https://api.bitwarden.com"),
            (
                "OPAQUE_BITWARDEN_IDENTITY_URL",
                "https://identity.bitwarden.com",
            ),
            ("OPAQUE_BITWARDEN_CLI_PATH", executable.to_str().unwrap()),
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
    assert_eq!(result, &json!({"projects":[{"name":"backend-secrets"}]}));
    let rendered = serde_json::to_string(&resp).unwrap();
    assert!(!rendered.contains("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
    assert!(!rendered.contains("test-bw-token"));
    daemon.shutdown();
}

/// A decrypted BWS fixture value reaches the real GitHub sealed-box path through
/// the daemon's composite resolver without leaking into the RPC response or log.
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn bitwarden_value_ref_reaches_github_end_to_end() {
    use base64::Engine as _;
    let _serial = serial_guard();
    let github = mock_github().await;
    let key = crypto_box::SecretKey::from([42u8; 32]);
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/actions/secrets/public-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key_id":"568250167",
            "key":base64::engine::general_purpose::STANDARD.encode(key.public_key().as_bytes())
        })))
        .with_priority(1)
        .mount(&github)
        .await;
    let fixture = Fixture::new();
    let executable = bitwarden_cli_fixture(&fixture);
    let config_path = fixture.write_config();
    let daemon = fixture.spawn_with_env(
        &config_path,
        &github.uri(),
        &[
            ("OPAQUE_BITWARDEN_URL", "https://api.bitwarden.com"),
            (
                "OPAQUE_BITWARDEN_IDENTITY_URL",
                "https://identity.bitwarden.com",
            ),
            ("OPAQUE_BITWARDEN_CLI_PATH", executable.to_str().unwrap()),
            ("OPAQUE_BITWARDEN_TOKEN_REF", "env:OPAQUE_E2E_BW_TOKEN"),
            ("OPAQUE_E2E_BW_TOKEN", "test-bw-token"),
        ],
    );
    let response = daemon
        .call(
            "github",
            json!({
                "scope":"repo_actions", "repo":"acme/widgets", "secret_name":"TUTORIAL_KEY",
                "value_ref":"bitwarden:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "github_token_ref":"env:OPAQUE_E2E_PAT"
            }),
        )
        .await;
    assert!(
        response.get("error").is_none_or(Value::is_null),
        "BWS value ref failed: {response}"
    );
    let requests = github.received_requests().await.unwrap();
    let write = requests
        .iter()
        .find(|r| r.method.as_str() == "PUT")
        .expect("sealed GitHub write");
    let body: Value = serde_json::from_slice(&write.body).unwrap();
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(body["encrypted_value"].as_str().unwrap())
        .unwrap();
    assert_eq!(key.unseal(&ciphertext).unwrap(), TEST_VALUE.as_bytes());
    let rendered = format!(
        "{response} {}",
        std::fs::read_to_string(&daemon.log).unwrap()
    );
    for sensitive in [TEST_VALUE, "test-bw-token", "private fixture note"] {
        assert!(!rendered.contains(sensitive));
        assert!(!String::from_utf8_lossy(&write.body).contains(sensitive));
    }
    daemon.shutdown();
}

/// Vault exposes no `OperationHandler` of its own — no `vault.*` operation
/// is ever registered (it is resolver-only: it just teaches `value_ref`/
/// `github_token_ref`-style params how to resolve a `vault:` scheme). The
/// only way to exercise its real HTTP client end to end through the daemon
/// is via another provider's ref resolution, so this drives
/// `github.set_actions_secret` with a `value_ref` in the `vault:` scheme.
///
/// Uses generic execution with a complete prepared Vault source reference.
/// Confirms Vault KV v2 extraction and environment-token resolution reach the
/// actual sealed GitHub write. The wrapper now shares the same typed preparer;
/// ref syntax is provider-owned. Lease renewal/caching has separate unit tests.
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

/// Production cloud endpoints stay fixed. These daemon checks deliberately
/// stop before authentication: missing credentials prove preparation and policy
/// do not silently resolve secrets or perform an OAuth/API request.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn azure_registration_and_policy_fail_closed_end_to_end() {
    let _serial = serial_guard();
    for configured in [false, true] {
        let fixture = Fixture::new();
        let config_path = fixture.write_config_with_rules("");
        let daemon = fixture.spawn_with_env(
            &config_path,
            "https://api.github.com",
            &[
                (
                    "OPAQUE_AZURE_VAULT_URL",
                    if configured {
                        "https://opaque-e2e.vault.azure.net"
                    } else {
                        ""
                    },
                ),
                (
                    "OPAQUE_AZURE_TENANT_ID",
                    "00000000-0000-0000-0000-000000000001",
                ),
                (
                    "OPAQUE_AZURE_CLIENT_ID",
                    "00000000-0000-0000-0000-000000000002",
                ),
                (
                    "OPAQUE_AZURE_CLIENT_SECRET_REF",
                    "env:OPAQUE_E2E_INTENTIONALLY_ABSENT_CLOUD_SECRET",
                ),
            ],
        );
        let catalog = daemon.call("operations", json!({})).await;
        let operations = catalog["result"]["operations"].as_array().unwrap();
        let cloud: Vec<_> = operations
            .iter()
            .filter(|row| row["provider"] == "azure")
            .collect();
        assert_eq!(cloud.len(), 5, "{catalog}");
        for row in cloud {
            assert_eq!(
                row["availability"],
                if configured { "enabled" } else { "disabled" }
            );
            assert_eq!(
                row["execution_paths"],
                if configured {
                    json!(["operation"])
                } else {
                    json!([])
                }
            );
        }
        let response = daemon
            .call(
                "execute",
                json!({
                    "operation": "azure.list_secrets", "target": {}, "params": {},
                    "secret_ref_names": [],
                }),
            )
            .await;
        assert_error(
            &response,
            if configured {
                "policy_denied"
            } else {
                "bad_request"
            },
        );
        if configured {
            let invalid = daemon
                .call(
                    "execute",
                    json!({
                        "operation": "azure.get_secret", "params": {"name": "../escape"},
                    }),
                )
                .await;
            assert_error(&invalid, "invalid_params");
            let mismatch = daemon
                .call(
                    "execute",
                    json!({
                        "operation": "azure.list_secrets", "params": {},
                        "target": {"azure_vault_url": "https://other-vault.vault.azure.net"},
                    }),
                )
                .await;
            assert_error(&mismatch, "bad_request");
        }
        daemon.shutdown();
        let events = audit_events(&fixture);
        assert_no_approval_or_execution(&events);
        if configured {
            let received = events
                .iter()
                .find(|event| {
                    event.operation.as_deref() == Some("azure.list_secrets")
                        && event.kind == opaque_core::audit::AuditEventKind::RequestReceived
                })
                .unwrap();
            assert_eq!(
                received.secret_names,
                ["env:OPAQUE_E2E_INTENTIONALLY_ABSENT_CLOUD_SECRET"]
            );
        }
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn gcp_registration_and_policy_fail_closed_end_to_end() {
    let _serial = serial_guard();
    for configured in [false, true] {
        let fixture = Fixture::new();
        let config_path = fixture.write_config_with_rules("");
        let daemon = fixture.spawn_with_env(
            &config_path,
            "https://api.github.com",
            &[
                (
                    "OPAQUE_GCP_SM_URL",
                    "https://secretmanager.googleapis.com/v1",
                ),
                (
                    "OPAQUE_GCP_TOKEN_REF",
                    if configured {
                        "env:OPAQUE_E2E_INTENTIONALLY_ABSENT_CLOUD_TOKEN"
                    } else {
                        ""
                    },
                ),
                ("OPAQUE_GCP_SERVICE_ACCOUNT_REF", ""),
                ("OPAQUE_GCP_SERVICE_ACCOUNT_KEY", ""),
                ("OPAQUE_GCP_ACCESS_TOKEN", ""),
            ],
        );
        let catalog = daemon.call("operations", json!({})).await;
        let operations = catalog["result"]["operations"].as_array().unwrap();
        let cloud: Vec<_> = operations
            .iter()
            .filter(|row| row["provider"] == "gcp")
            .collect();
        assert_eq!(cloud.len(), 4, "{catalog}");
        for row in cloud {
            assert_eq!(
                row["availability"],
                if configured { "enabled" } else { "disabled" }
            );
            assert_eq!(
                row["execution_paths"],
                if configured {
                    json!(["operation"])
                } else {
                    json!([])
                }
            );
        }
        let response = daemon.call("execute", json!({
            "operation": "gcp.list_secrets", "target": {}, "params": {"project":"123456789012"},
            "secret_ref_names": [],
        })).await;
        assert_error(
            &response,
            if configured {
                "policy_denied"
            } else {
                "bad_request"
            },
        );
        if configured {
            let invalid = daemon
                .call(
                    "execute",
                    json!({
                        "operation": "gcp.list_secrets", "params": {"project": "../escape"},
                    }),
                )
                .await;
            assert_error(&invalid, "invalid_params");
            let mismatch = daemon
                .call(
                    "execute",
                    json!({
                        "operation": "gcp.list_secrets", "params": {"project":"123456789012"},
                        "target": {"project": "987654321098"},
                    }),
                )
                .await;
            assert_error(&mismatch, "bad_request");
        }
        daemon.shutdown();
        let events = audit_events(&fixture);
        assert_no_approval_or_execution(&events);
        if configured {
            let received = events
                .iter()
                .find(|event| {
                    event.operation.as_deref() == Some("gcp.list_secrets")
                        && event.kind == opaque_core::audit::AuditEventKind::RequestReceived
                })
                .unwrap();
            assert_eq!(
                received.secret_names,
                ["env:OPAQUE_E2E_INTENTIONALLY_ABSENT_CLOUD_TOKEN"]
            );
        }
    }
}

/// Doppler remains unregistered. Its standalone client unit tests are not
/// daemon integration evidence.
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

// ---------------------------------------------------------------------------
// Canonical actions: real socket -> policy/review/audit -> actual provider effects.
// ---------------------------------------------------------------------------

fn github_action_params(repo: &str) -> Value {
    json!({
        "repo":repo, "secret_name":"TUTORIAL_KEY",
        "value_ref":"env:OPAQUE_E2E_VALUE", "github_token_ref":"env:OPAQUE_E2E_PAT",
    })
}

fn assert_error(response: &Value, expected: &str) {
    assert_eq!(
        response["error"]["code"], expected,
        "unexpected response: {response}"
    );
    assert!(response.get("result").is_none_or(Value::is_null));
}

fn audit_events(fixture: &Fixture) -> Vec<opaque_core::audit::AuditEvent> {
    opaque_core::audit::query_audit_db(
        &fixture.home.path().join(".opaque/audit.db"),
        &opaque_core::audit::AuditFilter {
            limit: 1000,
            ..Default::default()
        },
    )
    .unwrap()
}

fn assert_no_approval_or_execution(events: &[opaque_core::audit::AuditEvent]) {
    use opaque_core::audit::AuditEventKind;
    assert!(
        !events
            .iter()
            .filter(|event| event.operation.as_deref() != Some("daemon_startup"))
            .any(|event| matches!(
                event.kind,
                AuditEventKind::ApprovalRequired
                    | AuditEventKind::ApprovalPresented
                    | AuditEventKind::ApprovalGranted
                    | AuditEventKind::OperationStarted
                    | AuditEventKind::SecretResolved
                    | AuditEventKind::ProviderFetchStarted
                    | AuditEventKind::OperationSucceeded
            )),
        "rejection reached approval, credentials or execution: {events:?}"
    );
}

const REPOSITORY_POLICY: &str = r#"
[[rules]]
name = "only-approved-repository"
operation_pattern = "github.set_actions_secret"
allow = true
[rules.target.fields]
repo = "acme/widgets"
scope = "actions"
scope_kind = "repository"
[rules.approval]
require = "always"
factors = ["local_bio"]
"#;

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn canonical_action_rejects_target_substitution_before_approval_and_provider_io() {
    let _serial = serial_guard();
    let github = mock_github().await;
    let fixture = Fixture::new();
    let config = fixture.write_config_with_rules(REPOSITORY_POLICY);
    let daemon = fixture.spawn(&config, &github.uri());
    let response = daemon
        .call(
            "execute",
            json!({
                "operation":"github.set_actions_secret",
                "target":{"repo":"acme/widgets"},
                "params":github_action_params("acme/unapproved"),
            }),
        )
        .await;
    assert_error(&response, "bad_request");
    assert!(github.received_requests().await.unwrap().is_empty());
    daemon.shutdown();
    let events = audit_events(&fixture);
    assert_no_approval_or_execution(&events);
    let rejected: Vec<_> = events
        .iter()
        .filter(|event| event.detail.as_deref() == Some("action_preparation_rejected"))
        .collect();
    assert_eq!(rejected.len(), 1);
    assert!(rejected[0].target.is_none());
    assert!(rejected[0].operation.is_none());
    assert!(rejected[0].secret_names.is_empty());
    assert!(
        !events
            .iter()
            .any(|event| event.kind == opaque_core::audit::AuditEventKind::RequestReceived)
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn canonical_action_derives_omitted_targets_for_policy_and_equivalent_dispatch() {
    use opaque_core::audit::AuditEventKind;
    let _serial = serial_guard();
    let github = mock_github().await;
    let fixture = Fixture::new();
    let config = fixture.write_config_with_rules(REPOSITORY_POLICY);
    let daemon = fixture.spawn(&config, &github.uri());
    let denied = daemon.call("execute", json!({
        "operation":"github.set_actions_secret", "params":github_action_params("acme/unapproved"),
    })).await;
    assert_error(&denied, "policy_denied");
    assert!(github.received_requests().await.unwrap().is_empty());
    let raw = daemon.call("execute", json!({
        "operation":"github.set_actions_secret", "params":github_action_params("acme/widgets"),
    })).await;
    assert_eq!(raw["result"]["status"], "created", "{raw}");
    let mut wrapped = github_action_params("acme/widgets");
    wrapped["scope"] = "repo_actions".into();
    let wrapped = daemon.call("github", wrapped).await;
    assert_eq!(wrapped["result"]["status"], "created", "{wrapped}");
    let requests = github.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method.as_str() == "PUT")
            .count(),
        2
    );
    assert!(
        requests
            .iter()
            .all(|request| request.url.path().starts_with("/repos/acme/widgets/"))
    );
    daemon.shutdown();
    let events = audit_events(&fixture);
    let received: Vec<_> = events
        .iter()
        .filter(|event| event.kind == AuditEventKind::RequestReceived)
        .collect();
    assert_eq!(received.len(), 3);
    let approved: Vec<_> = received
        .iter()
        .filter(|event| event.target.as_ref().unwrap().fields["repo"] == "acme/widgets")
        .collect();
    assert_eq!(approved.len(), 2);
    assert!(approved[0].request_hash.is_some());
    assert_eq!(
        approved[0].request_hash, approved[1].request_hash,
        "raw and wrapper must bind the same prepared action"
    );
    for event in approved {
        let target = &event.target.as_ref().unwrap().fields;
        assert_eq!(target["scope"], "actions");
        assert_eq!(target["scope_kind"], "repository");
        assert_eq!(
            event.secret_names,
            ["env:OPAQUE_E2E_PAT", "env:OPAQUE_E2E_VALUE"]
        );
    }
    let denied_event = events
        .iter()
        .find(|event| event.kind == AuditEventKind::PolicyDenied)
        .unwrap();
    assert_eq!(
        denied_event.target.as_ref().unwrap().fields["repo"],
        "acme/unapproved"
    );
    let denied_id = denied_event.request_id;
    assert_no_approval_or_execution(
        &events
            .iter()
            .filter(|event| event.request_id == denied_id)
            .cloned()
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn canonical_action_rejects_malformed_targets_and_unknown_provider_fields() {
    let _serial = serial_guard();
    let github = mock_github().await;
    let fixture = Fixture::new();
    let executable = bitwarden_cli_fixture(&fixture);
    let config = fixture.write_config();
    let daemon = fixture.spawn_with_env(
        &config,
        &github.uri(),
        &[
            ("OPAQUE_1PASSWORD_CONNECT_URL", &github.uri()),
            ("OPAQUE_1PASSWORD_TOKEN_REF", "env:OPAQUE_E2E_PAT"),
            ("OPAQUE_BITWARDEN_URL", "https://api.bitwarden.com"),
            (
                "OPAQUE_BITWARDEN_IDENTITY_URL",
                "https://identity.bitwarden.com",
            ),
            ("OPAQUE_BITWARDEN_CLI_PATH", executable.to_str().unwrap()),
            (
                "OPAQUE_BITWARDEN_TOKEN_REF",
                "env:OPAQUE_E2E_MISSING_BW_TOKEN",
            ),
        ],
    );
    for target in [
        Value::Null,
        json!([]),
        json!("acme/widgets"),
        json!({"repo":42}),
        json!({"unrecognized":"x"}),
    ] {
        let response = daemon
            .call(
                "execute",
                json!({
                    "operation":"github.set_actions_secret", "target":target,
                    "params":github_action_params("acme/widgets"),
                }),
            )
            .await;
        assert_error(&response, "bad_request");
    }
    for (field, value) in [
        ("unexpected", json!(true)),
        ("environment", json!(false)),
        ("org", json!("competing")),
    ] {
        let mut params = github_action_params("acme/widgets");
        params[field] = value;
        let raw = daemon
            .call(
                "execute",
                json!({"operation":"github.set_actions_secret", "params":params.clone()}),
            )
            .await;
        assert_error(&raw, "invalid_params");
        params["scope"] = "repo_actions".into();
        let wrapped = daemon.call("github", params).await;
        assert_error(&wrapped, "invalid_params");
    }
    let malformed_project = daemon
        .call(
            "bitwarden",
            json!({"action":"list_secrets", "project":false}),
        )
        .await;
    assert_error(&malformed_project, "invalid_params");
    assert!(!executable.with_extension("invoked").exists());
    let unknown_option = daemon
        .call(
            "onepassword",
            json!({"action":"list_items", "vault":"Engineering", "unrecognized":true}),
        )
        .await;
    assert_error(&unknown_option, "invalid_params");
    assert!(github.received_requests().await.unwrap().is_empty());
    daemon.shutdown();
    assert_no_approval_or_execution(&audit_events(&fixture));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn canonical_action_policy_includes_implicit_token_refs_and_ignores_forged_ref_lists() {
    use opaque_core::audit::AuditEventKind;
    let _serial = serial_guard();
    let github = mock_github().await;
    for allow_token in [false, true] {
        let fixture = Fixture::new();
        let patterns = if allow_token {
            r#"["env:OPAQUE_E2E_VALUE", "env:OPAQUE_E2E_PAT"]"#
        } else {
            r#"["env:OPAQUE_E2E_VALUE"]"#
        };
        let config = fixture.write_config_with_rules(&format!(
            r#"
[[rules]]
name = "only-enrolled-secret-references"
operation_pattern = "github.set_actions_secret"
allow = true
[rules.secret_names]
patterns = {patterns}
[rules.approval]
require = "always"
factors = ["local_bio"]
"#
        ));
        let daemon = fixture.spawn_with_env(
            &config,
            &github.uri(),
            &[("OPAQUE_GITHUB_TOKEN_REF", "env:OPAQUE_E2E_PAT")],
        );
        let mut params = github_action_params("acme/widgets");
        params.as_object_mut().unwrap().remove("github_token_ref");
        let response = daemon
            .call(
                "execute",
                json!({
                    "operation":"github.set_actions_secret", "params":params,
                    // A caller cannot hide the implicitly selected provider credential.
                    "secret_ref_names":["env:OPAQUE_E2E_VALUE"],
                }),
            )
            .await;
        if allow_token {
            assert_eq!(response["result"]["status"], "created", "{response}");
        } else {
            assert_error(&response, "policy_denied");
            assert!(github.received_requests().await.unwrap().is_empty());
        }
        daemon.shutdown();
        let events = audit_events(&fixture);
        let received = events
            .iter()
            .find(|event| event.kind == AuditEventKind::RequestReceived)
            .unwrap();
        assert_eq!(
            received.secret_names,
            ["env:OPAQUE_E2E_PAT", "env:OPAQUE_E2E_VALUE"]
        );
        if !allow_token {
            assert_no_approval_or_execution(&events);
        }
    }
    assert_eq!(github.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn canonical_action_policy_constrains_actual_secret_scope_and_environment() {
    use opaque_core::audit::AuditEventKind;
    let _serial = serial_guard();
    let github = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/environments/staging/secrets"))
        .and(header("authorization", format!("Bearer {TEST_PAT}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"total_count":0,"secrets":[]})),
        )
        .expect(1)
        .mount(&github)
        .await;
    let fixture = Fixture::new();
    let config = fixture.write_config_with_rules(
        r#"
[[rules]]
name = "only-staging-actions"
operation_pattern = "github.list_secrets"
allow = true
[rules.target.fields]
repo = "acme/widgets"
scope = "actions"
environment = "staging"
[rules.approval]
require = "always"
factors = ["local_bio"]
"#,
    );
    let daemon = fixture.spawn(&config, &github.uri());
    for params in [
        json!({"repo":"acme/widgets","environment":"production"}),
        json!({"repo":"acme/widgets","scope":"dependabot"}),
        json!({"scope":"org","org":"acme"}),
    ] {
        let mut params = params;
        params["github_token_ref"] = "env:OPAQUE_E2E_PAT".into();
        let response = daemon
            .call(
                "execute",
                json!({"operation":"github.list_secrets","params":params}),
            )
            .await;
        assert_error(&response, "policy_denied");
    }
    assert!(github.received_requests().await.unwrap().is_empty());
    let response = daemon
        .call(
            "github",
            json!({
                "action":"list_secrets","repo":"acme/widgets","environment":"staging",
                "github_token_ref":"env:OPAQUE_E2E_PAT",
            }),
        )
        .await;
    assert_eq!(response["result"]["total_count"], 0, "{response}");
    assert_eq!(github.received_requests().await.unwrap().len(), 1);
    daemon.shutdown();
    let events = audit_events(&fixture);
    let denied: Vec<_> = events
        .iter()
        .filter(|event| event.kind == AuditEventKind::PolicyDenied)
        .collect();
    assert_eq!(denied.len(), 3);
    for event in denied {
        assert_no_approval_or_execution(
            &events
                .iter()
                .filter(|other| other.request_id == event.request_id)
                .cloned()
                .collect::<Vec<_>>(),
        );
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn canonical_action_rejects_task_only_operations_under_allow_all_policy() {
    let _serial = serial_guard();
    let github = MockServer::start().await;
    let fixture = Fixture::new();
    let config = fixture.write_config_with_rules(
        r#"
[[rules]]
name = "allow-all-for-route-regression"
operation_pattern = "*"
allow = true
[rules.approval]
require = "always"
factors = ["local_bio"]
"#,
    );
    let daemon = fixture.spawn(&config, &github.uri());
    for operation in [
        "github.publish_manifest",
        "github.release_manifest",
        "github.dispatch_staging_workflow",
        "github.observe_staging_workflow",
        "inference.fixed_manifest",
        "inference.fixed_completion",
        "ssh.health_manifest",
        "ssh.service_health",
    ] {
        let response = daemon
            .call("execute", json!({"operation":operation,"params":{}}))
            .await;
        assert_error(&response, "bad_request");
    }
    assert!(github.received_requests().await.unwrap().is_empty());
    daemon.shutdown();
    let events = audit_events(&fixture);
    assert_no_approval_or_execution(&events);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.detail.as_deref() == Some("action_preparation_rejected"))
            .count(),
        8
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn canonical_reference_metadata_rejects_secret_bytes_before_audit_or_review() {
    let _serial = serial_guard();
    let github = mock_github().await;
    let fixture = Fixture::new();
    let config = fixture.write_config();
    let daemon = fixture.spawn(&config, &github.uri());
    let sentinel = format!("ghp_{}", "z".repeat(36));
    for reference in [
        format!("env:{sentinel}"),
        "env:forged\nrecord".into(),
        "env:hidden\u{202e}".into(),
    ] {
        for field in ["value_ref", "github_token_ref"] {
            let mut params = github_action_params("acme/widgets");
            params[field] = reference.clone().into();
            let raw = daemon
                .call(
                    "execute",
                    json!({
                        "operation":"github.set_actions_secret", "params":params.clone(),
                    }),
                )
                .await;
            assert_error(&raw, "invalid_params");
            params["scope"] = "repo_actions".into();
            let wrapped = daemon.call("github", params).await;
            assert!(wrapped.get("error").is_some(), "{wrapped}");
            assert!(!wrapped.to_string().contains(&sentinel));
        }
    }
    assert!(github.received_requests().await.unwrap().is_empty());
    daemon.shutdown();
    let events = audit_events(&fixture);
    assert_no_approval_or_execution(&events);
    let encoded = serde_json::to_string(&events).unwrap();
    for marker in [&sentinel, "forged", "hidden"] {
        assert!(!encoded.contains(marker));
    }
}
