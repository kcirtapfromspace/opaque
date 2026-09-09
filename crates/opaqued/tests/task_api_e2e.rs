//! End-to-end proof that the fixed-manifest task ledger RPC surface
//! (`task_plan`/`task_run`/`task_get`/`task_list`/`task_revoke`) actually
//! works against the REAL `opaqued` binary.
//!
//! Why this exists: `task_api.rs` had zero tests of any kind — inline unit
//! tests or e2e — anywhere in the crate before the `opaque-bounded-work`
//! extraction, despite being live dispatch for the entire bounded-work/SSH
//! surface. This project's own hard-won lesson (see `provider_e2e.rs`'s doc
//! comment) is that real production bugs live at the RPC boundary, invisible
//! to inline unit tests — which this file had none of either. Follows the
//! same real-daemon-over-the-real-socket pattern as `provider_e2e.rs` and
//! `resource_authority_e2e.rs`.
//!
//! Exercises the plain (non-SSH, non-inference) `github.publish_manifest`
//! task shape end to end — planning (with a mocked GitHub repository-id
//! lookup and a pinned Vault secret ref), listing, fetching, running
//! (mocked GitHub public-key + secret PUT), and revoking a second,
//! never-run task. This is also the first exercise of this extraction's new
//! `opaque_bounded_work::task_facade::BoundedWorkFacade` trait and the
//! `EnclaveFacade::verify_workspace` addition through a real `execute_task`
//! dispatch, not just a build check.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Same rationale as `provider_e2e.rs`: several real daemons at once causes
/// socket and resource contention. `tokio::test` without a flavor is a
/// CURRENT-THREAD runtime, so the future never migrates between threads and
/// holding a std guard across awaits is sound.
static E2E_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    E2E_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).unwrap();
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

const TEST_PAT: &str = "ghp_task_e2e_placeholder_not_a_real_token";
const TEST_VAULT_TOKEN: &str = "task-e2e-vault-token";
const TEST_SECRET_VALUE: &str = "task-e2e-secret-plaintext";

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
        let runtime_dir = tmp_base.join(format!("oqtask{}-{}", std::process::id(), rand_hex(4)));
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

    /// Fixed-manifest tasks enabled, auto-approved, and policy rules
    /// allowing the plain (non-SSH, non-inference) task shape's two
    /// policy-evaluated operation names: `enclave::task::task_decision`
    /// evaluates the top-level manifest as `github.publish_manifest`, AND
    /// (via `action_request`) each `PublishSecret` action individually as
    /// `github.set_actions_secret` — both must be allowed, with identical
    /// approval factors (the enclave rejects a task whose per-action
    /// factors differ from its top-level factors).
    fn write_config(&self) -> PathBuf {
        let config_path = self.home.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
enable_task_grants = true
approval_backend = "insecure_auto_approve"

[[rules]]
name = "allow-task-publish-manifest"
operation_pattern = "github.publish_manifest"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"
factors = ["local_bio"]

[[rules]]
name = "allow-task-publish-secret-action"
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

    fn spawn(&self, config_path: &Path, github_api: &str, vault_api: &str) -> Daemon {
        let sock = self.runtime_dir.join("opaque").join("opaqued.sock");
        let token_path = self.runtime_dir.join("opaque").join("daemon.token");
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(&token_path);

        let log = self.home.path().join(format!("daemon-{}.log", rand_hex(3)));
        let log_file = std::fs::File::create(&log).unwrap();
        let log_stdout = log_file.try_clone().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_opaqued"));
        cmd.env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("OPAQUE_CONFIG", config_path)
            .env("RUST_LOG", "info")
            .env("OPAQUE_INSECURE_AUTO_APPROVE", "1")
            .env("OPAQUE_GITHUB_API_URL", github_api)
            .env("OPAQUE_VAULT_URL", vault_api)
            // Mocked endpoints are plain loopback HTTP, not HTTPS.
            .env("OPAQUE_DOGFOOD_LOOPBACK", "1")
            .env("OPAQUE_VAULT_TOKEN_REF", "env:OPAQUE_TASK_E2E_VAULT_TOKEN")
            .env("OPAQUE_TASK_E2E_VAULT_TOKEN", TEST_VAULT_TOKEN)
            // Resolved by the daemon's own EnvResolver — `env:` refs keep the
            // test off the OS keychain (which would prompt).
            .env("OPAQUE_TASK_E2E_PAT", TEST_PAT)
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::from(log_stdout))
            .stderr(log_file);
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

/// Stand in for the GitHub API: repository identity lookup (planning time),
/// a real Curve25519 public key, then acceptance of the sealed secret
/// (execution time).
async fn mock_github() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/acme/task-widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 918_273, "full_name": "acme/task-widgets"
        })))
        .mount(&server)
        .await;

    let public_key: [u8; 32] = {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).unwrap();
        buf
    };
    use base64::Engine as _;
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    Mock::given(method("GET"))
        .and(path("/repos/acme/task-widgets/actions/secrets/public-key"))
        .and(header("authorization", format!("Bearer {TEST_PAT}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"key_id": "568250167", "key": key_b64})),
        )
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/repos/acme/task-widgets/actions/secrets/TASK_SECRET"))
        .and(header("authorization", format!("Bearer {TEST_PAT}")))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;

    server
}

async fn mock_vault() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/task-app"))
        .and(header("x-vault-token", TEST_VAULT_TOKEN))
        // A pinned (`?version=N`) read additionally requires the KV v2
        // `metadata` envelope (version/destroyed/deletion_time) — the plain
        // `{"data": {"data": {...}}}` shape used by an unpinned read (see
        // `provider_e2e.rs`'s vault mock) is not enough here.
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": { "TOKEN": TEST_SECRET_VALUE },
                "metadata": { "version": 1, "destroyed": false, "deletion_time": "" }
            }
        })))
        .mount(&server)
        .await;
    server
}

fn manifest(title: &str) -> Value {
    json!({
        "schema_version": 1,
        "title": title,
        "expires_in_secs": 300,
        "actions": [{
            "repo": "acme/task-widgets",
            "secret_name": "TASK_SECRET",
            "value_ref": "vault:secret/data/task-app?version=1#TOKEN",
            "github_token_ref": "env:OPAQUE_TASK_E2E_PAT",
        }]
    })
}

fn ok(resp: &Value, context: &str) {
    assert!(
        resp.get("error").is_none_or(Value::is_null),
        "{context} returned an error: {resp}"
    );
}

/// Full lifecycle: plan two tasks, list and fetch the first, run it to
/// completion against mocked GitHub/Vault, then revoke the second (never
/// run) task.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize real daemons (current-thread runtime)
async fn task_plan_run_get_list_revoke_end_to_end() {
    let _serial = serial_guard();
    let github = mock_github().await;
    let vault = mock_vault().await;
    let fixture = Fixture::new();
    let config_path = fixture.write_config();
    let daemon = fixture.spawn(&config_path, &github.uri(), &vault.uri());

    // task_plan: create the task that will actually run.
    let planned = daemon
        .call(
            "task_plan",
            json!({"manifest": manifest("publish task secret")}),
        )
        .await;
    ok(&planned, "task_plan");
    let task = &planned["result"]["task"];
    assert_eq!(task["state"], "planned", "unexpected state in {task}");
    let task_id = task["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no task id in {task}"))
        .to_string();

    // A second, independent task that will be revoked without ever running.
    let planned2 = daemon
        .call(
            "task_plan",
            json!({"manifest": manifest("publish task secret (revoked)")}),
        )
        .await;
    ok(&planned2, "task_plan (second)");
    let task_id2 = planned2["result"]["task"]["id"]
        .as_str()
        .expect("second task id")
        .to_string();
    assert_ne!(
        task_id, task_id2,
        "each task_plan call must mint a fresh id"
    );

    // task_list: both planned tasks are visible.
    let listed = daemon.call("task_list", json!({})).await;
    ok(&listed, "task_list");
    let tasks = listed["result"]["tasks"].as_array().expect("tasks array");
    let ids: Vec<&str> = tasks.iter().filter_map(|t| t["id"].as_str()).collect();
    assert!(
        ids.contains(&task_id.as_str()),
        "task_list missing first task: {ids:?}"
    );
    assert!(
        ids.contains(&task_id2.as_str()),
        "task_list missing second task: {ids:?}"
    );

    // task_get: fetch the first task by id.
    let got = daemon.call("task_get", json!({"task_id": task_id})).await;
    ok(&got, "task_get");
    assert_eq!(got["result"]["task"]["id"], task_id);
    assert_eq!(got["result"]["task"]["state"], "planned");

    // task_run: claim and execute the first task against mocked GitHub/Vault.
    let ran = daemon.call("task_run", json!({"task_id": task_id})).await;
    ok(&ran, "task_run");
    let ran_task = &ran["result"]["task"];
    assert_eq!(
        ran_task["state"],
        "completed",
        "unexpected post-run state in {ran_task}\ndaemon log:\n{}",
        std::fs::read_to_string(&daemon.log).unwrap_or_default()
    );
    let slots = ran_task["slots"].as_array().expect("slots array");
    assert_eq!(slots.len(), 1);
    assert_eq!(
        slots[0]["outcome"]["state"], "api_accepted",
        "unexpected slot outcome in {:?}",
        slots[0]
    );

    let vault_requests = vault.received_requests().await.unwrap_or_default();
    assert!(
        vault_requests
            .iter()
            .any(|r| r.url.path() == "/v1/secret/data/task-app"),
        "no read reached the mocked Vault server; requests: {:?}",
        vault_requests
            .iter()
            .map(|r| r.url.path())
            .collect::<Vec<_>>()
    );
    let github_requests = github.received_requests().await.unwrap_or_default();
    assert!(
        github_requests.iter().any(|r| r.method.as_str() == "PUT"),
        "no PUT reached the mocked GitHub API; requests: {:?}",
        github_requests
            .iter()
            .map(|r| (r.method.as_str().to_owned(), r.url.path().to_owned()))
            .collect::<Vec<_>>()
    );

    // task_get again: the run is durably reflected.
    let got_again = daemon.call("task_get", json!({"task_id": task_id})).await;
    assert_eq!(got_again["result"]["task"]["state"], "completed");

    // task_revoke: the second task, never run, moves to revoked and can no
    // longer be run.
    let revoked = daemon
        .call("task_revoke", json!({"task_id": task_id2}))
        .await;
    ok(&revoked, "task_revoke");
    assert_eq!(revoked["result"]["task"]["state"], "revoked");
    let run_after_revoke = daemon.call("task_run", json!({"task_id": task_id2})).await;
    assert!(
        run_after_revoke.get("error").is_some_and(|e| !e.is_null()),
        "running a revoked task must fail: {run_after_revoke}"
    );

    daemon.shutdown();
}
