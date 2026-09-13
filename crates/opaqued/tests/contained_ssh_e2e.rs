//! Real Vault/OpenSSH/systemd composition with an explicit scripted reviewer.
//! Run through tests/contained-ssh/run.py. Root and service prerequisites fail
//! closed; these tests never claim native human presence or vendor credentials.
#![cfg(target_os = "linux")]
#[path = "support/oidc.rs"]
mod oidc;
#[path = "support/split_daemon.rs"]
mod split_daemon;
#[path = "support/workstation.rs"]
mod workstation;

use opaque_core::workstation::{SignedWorkstationReceipt, WorkstationReview};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use split_daemon::{Daemon, Layout, Peer};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use workstation::ScriptedWorkstation;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const CLIENT: &str = "opaque-contained-ssh";

struct Services;
impl Services {
    fn call(action: &str, args: &[&Path]) -> Value {
        let script =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/contained-ssh/fixture.py");
        let mut command = Command::new("python3");
        command.arg("-B").arg(script).arg(action);
        let options: &[&str] = match action {
            "prepare" => &["--output", "--grant-key"],
            "configure" | "replay-host" => &["--task"],
            _ => &[],
        };
        assert_eq!(options.len(), args.len());
        for (option, argument) in options.iter().zip(args) {
            command.arg(option).arg(argument);
        }
        let result = command.stdin(Stdio::null()).output().unwrap();
        assert!(
            result.status.success(),
            "contained fixture {action} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        if result.stdout.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&result.stdout).expect("bounded fixture snapshot")
        }
    }
}
impl Drop for Services {
    fn drop(&mut self) {
        // Container teardown is an additional outer bound if the Rust process
        // aborts or a failed prerequisite prevents this normal cleanup.
        let result = Command::new("python3")
            .arg("-B")
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/contained-ssh/fixture.py"),
            )
            .arg("cleanup")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !std::thread::panicking() {
            assert!(
                result.is_ok_and(|status| status.success()),
                "contained services cleanup failed"
            );
        }
    }
}

fn config(
    layout: &Layout,
    issuer: &str,
    port: u16,
    profile: &Value,
    reviewer: Option<(&str, &str)>,
    inference: Option<&Value>,
) -> String {
    let mapping = reviewer.map(|(principal, key)| format!(
        "workstation_approvers = [{{public_key_hex = \"{key}\", name = \"Synthetic CI reviewer\", principal_id = \"{principal}\"}}]\n"
    )).unwrap_or_default();
    let mut value = format!(
        r#"data_dir = "{}"
enable_task_grants = true
require_seal = true
enforce_agent_sessions = true
approval_backend = "native"
workstation_test_mode = true
{mapping}
[[known_human_clients]]
name = "Synthetic human RPC peer"
exe_path = "{}"
[tenant]
id = "contained-ssh-fixture"
[trust_domain]
enforce = true
socket_group = "{}"
socket_path = "{}"
[approval]
server_bind = "127.0.0.1:{port}"
timeout_secs = 8
session_factor = "paired_workstation"
[identity]
issuer = "{issuer}"
client_id = "{CLIENT}"
required = true
session_ttl_secs = 600
allowed_subjects = ["reviewer", "requester"]
[attestation]
interval_secs = 0
"#,
        layout.state.display(),
        layout.human_binary.display(),
        split_daemon::SOCKET_GID,
        layout.socket.display()
    );
    if let Some((_, key)) = reviewer {
        value += &format!(
            "\n[remote_approvals]\nreviewer_public_key_hex = \"{key}\"\nrequired_role = \"approver\"\n"
        );
    }
    for operation in [
        "ssh.health_manifest",
        "ssh.service_health",
        "inference.fixed_manifest",
        "inference.fixed_completion",
    ] {
        value += &format!(
            r#"
[[rules]]
name = "contained-{operation}"
operation_pattern = "{operation}"
allow = true
client_types = ["agent", "human"]
[rules.approval]
require = "always"
factors = ["paired_workstation"]
lease_ttl = 0
[rules.identity]
require_principal = true
roles = ["operator"]
"#
        );
    }
    if let Some(profile) = inference {
        value += "\n[inference]\n";
        for (key, field) in profile.as_object().unwrap() {
            value += &format!("{key} = {field}\n");
        }
    }
    value += "\n[ssh]\n";
    for (key, field) in profile.as_object().unwrap() {
        if key != "health_contract" {
            value += &format!("{key} = {field}\n");
        }
    }
    value += "[ssh.health_contract]\n";
    for (key, field) in profile["health_contract"].as_object().unwrap() {
        value += &format!("{key} = {field}\n");
    }
    value
}

async fn login(peer: &Peer, idp: &oidc::MockOidc, subject: &str) -> Value {
    let start = peer.ok("identity.login_start", Value::Null, None).await;
    let url = reqwest::Url::parse(start["auth_url"].as_str().unwrap()).unwrap();
    let parameter = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .unwrap()
            .1
            .into_owned()
    };
    idp.register_redirect(&parameter("redirect_uri"));
    idp.select_identity(
        &parameter("state"),
        oidc::TestIdentity {
            subject: subject.into(),
            email: format!("{subject}@example.invalid"),
            token_nonce_override: None,
        },
    );
    let authorization = idp.authorize(url.as_str()).await;
    assert_eq!(authorization.status(), reqwest::StatusCode::FOUND);
    assert!(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
            .get(authorization.headers()["location"].to_str().unwrap())
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let result = peer
            .ok(
                "identity.login_status",
                json!({"attempt_id":start["attempt_id"]}),
                None,
            )
            .await;
        if result["status"] == "complete" {
            return result["identity"].clone();
        }
        assert_eq!(result["status"], "pending");
        assert!(Instant::now() < deadline, "signed OIDC login deadline");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct Fixture {
    daemon: Daemon,
    workstation: ScriptedWorkstation,
    layout: Layout,
    _idp: oidc::MockOidc,
    _services: Services,
    signer: String,
    reviewer: String,
    requester: String,
    session: String,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_inference(None).await
    }
    async fn with_inference(inference: Option<&Value>) -> Self {
        let layout = Layout::new();
        Services::call(
            "prepare",
            &[layout.base.path(), &layout.home.join("ssh-signing.key")],
        );
        let services = Services;
        let profile: Value = serde_json::from_slice(
            &std::fs::read(layout.base.path().join("profile.json")).unwrap(),
        )
        .unwrap();
        let signer = std::fs::read_to_string(layout.base.path().join("signer-token")).unwrap();
        let idp = oidc::MockOidc::start(CLIENT).await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut workstation = ScriptedWorkstation::new(&layout.base.path().join("workstation"));
        layout.seal(&config(
            &layout,
            &idp.uri(),
            port,
            &profile,
            None,
            inference,
        ));
        let mut bootstrap = layout.start(&[("OPAQUE_CONTAINED_VAULT_TOKEN", &signer)]);
        let identity = login(&bootstrap.human(), &idp, "reviewer").await;
        assert!(
            identity["roles"]
                .as_array()
                .unwrap()
                .contains(&json!("approver"))
        );
        let reviewer = identity["principal_id"].as_str().unwrap().to_owned();
        bootstrap.stop();
        drop(bootstrap);
        layout.seal(&config(
            &layout,
            &idp.uri(),
            port,
            &profile,
            Some((&reviewer, &workstation.state.public_key_hex)),
            inference,
        ));
        let daemon = layout.start(&[("OPAQUE_CONTAINED_VAULT_TOKEN", &signer)]);
        let version = daemon.human().ok("version", Value::Null, None).await;
        assert_eq!(version["approval_backend"], "native");
        assert_eq!(version["workstation_test_mode"], true);
        assert_eq!(version["trust_domain_enforced"], true);
        workstation
            .enroll(
                &format!("https://127.0.0.1:{port}"),
                &std::fs::read(layout.state.join("approval_server.cert")).unwrap(),
            )
            .await;
        let identity = login(&daemon.human(), &idp, "requester").await;
        assert_eq!(identity["roles"], json!(["operator"]));
        let requester = identity["principal_id"].as_str().unwrap().to_owned();
        assert_ne!(requester, reviewer);
        let mut fixture = Self {
            daemon,
            workstation,
            layout,
            _idp: idp,
            _services: services,
            signer,
            reviewer,
            requester,
            session: String::new(),
        };
        fixture.session = fixture.delegate().await;
        let who = fixture
            .daemon
            .agent()
            .ok("whoami", Value::Null, Some(&fixture.session))
            .await;
        assert_eq!(who["uid"], split_daemon::CLIENT_UID);
        assert_eq!(who["client_type"], "agent");
        assert!(who["agent_session_id"].is_string());
        let human = fixture.daemon.human().ok("whoami", Value::Null, None).await;
        assert_eq!(human["uid"], split_daemon::CLIENT_UID);
        assert!(human["pid"].as_u64().unwrap() > 0);
        assert_eq!(
            human["exe_path"],
            fixture.layout.human_binary.to_str().unwrap()
        );
        assert_eq!(
            human["exe_sha256"],
            opaque_core::workstation::hex(&Sha256::digest(
                std::fs::read(&fixture.layout.human_binary).unwrap()
            ))
        );
        fixture
    }
    async fn delegate(&self) -> String {
        let peer = self.daemon.human();
        let pending = tokio::spawn(async move {
            peer.ok(
                "agent_session_start",
                json!({"label":"contained-agent",
                "reason":"unattended contained acceptance", "ttl_secs":300}),
                None,
            )
            .await
        });
        let review = self.workstation.wait_review("agent_session_start").await;
        self.workstation.respond(&review, true).await.unwrap();
        let delegated = pending.await.unwrap();
        assert_eq!(delegated["on_behalf_of"], self.requester);
        delegated["session_token"].as_str().unwrap().to_owned()
    }
    async fn plan(&self) -> Value {
        let task = self
            .daemon
            .agent()
            .ok(
                "task_plan_ssh",
                json!({
                    "title":"Contained real SSH health", "expires_in_secs":120
                }),
                Some(&self.session),
            )
            .await["task"]
            .clone();
        assert_eq!(
            task["manifest"]["actions"][0]["workload_uid"],
            split_daemon::CLIENT_UID
        );
        assert_eq!(
            task["manifest"]["actions"][0]["workload_exe_sha256"],
            opaque_core::workstation::hex(&Sha256::digest(
                std::fs::read(&self.layout.human_binary).unwrap()
            ))
        );
        let file = self.layout.base.path().join("planned-task.json");
        std::fs::write(&file, serde_json::to_vec(&task).unwrap()).unwrap();
        Services::call("configure", &[&file]);
        assert_eq!(Services::call("snapshot", &[])["reads"], 0);
        assert_eq!(Services::call("snapshot", &[])["vault_sign_requests"], 0);
        task
    }
    fn run(&self, task: &Value) -> tokio::task::JoinHandle<Result<Value, String>> {
        let peer = self.daemon.agent();
        let session = self.session.clone();
        let id = task["id"].clone();
        tokio::spawn(async move {
            peer.call("task_run", json!({"task_id":id}), Some(&session))
                .await
        })
    }
    fn verify_review(&self, review: &WorkstationReview, task: &Value) {
        assert_eq!(review.challenge.schema_version, 2);
        let authority = review.challenge.authority.as_ref().unwrap();
        assert_eq!(authority.principal_id, self.reviewer);
        assert_eq!(authority.binding.requester, self.requester);
        assert_eq!(authority.binding.task_id, task["id"].as_str().unwrap());
        assert_eq!(
            authority.binding.manifest_digest,
            task["manifest_digest"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_value(&authority.binding.tenant).unwrap(),
            task["tenant"]
        );
        assert_eq!(authority.required_role, "approver");
        assert_eq!(
            authority.public_key_hex,
            self.workstation.state.public_key_hex
        );
        let text: &[&str] = if task["manifest"]["schema_version"] == 4 {
            &[
                "contained-health",
                "127.0.0.1",
                "OPAQUE_CONTAINED_VAULT_TOKEN",
            ]
        } else {
            &[
                "inference-rpc-fixture",
                "fixture-model.gguf",
                "opaque-public-receipts-v1",
            ]
        };
        for text in text {
            assert!(
                review.review_text.contains(*text),
                "SSH review omitted scope"
            );
        }
        assert!(!review.review_text.contains(&self.signer));
    }
    fn assert_unapproved_host(&self) {
        let state = Services::call("snapshot", &[]);
        assert_eq!(state["reads"], 0);
        assert_eq!(state["vault_sign_requests"], 0);
        assert!(state["grants"].as_array().unwrap().is_empty());
    }
    async fn get(&self, task: &Value) -> Value {
        self.daemon
            .agent()
            .ok(
                "task_get",
                json!({"task_id":task["id"]}),
                Some(&self.session),
            )
            .await["task"]
            .clone()
    }
    async fn receipt(&self, task: &Value) -> SignedWorkstationReceipt {
        let reference = &task["workstation_receipt"];
        let receipt = self
            .workstation
            .receipt(reference["approval_id"].as_str().unwrap())
            .await;
        assert_eq!(
            opaque_core::workstation::hex(&Sha256::digest(serde_json::to_vec(&receipt).unwrap())),
            reference["sha256"].as_str().unwrap()
        );
        self.verify_review(&receipt.review, task);
        assert_eq!(task["approval_mode"], "insecure_test");
        assert!(!task.to_string().contains(&self.signer));
        receipt
    }
    async fn restart(&mut self, task: &Value) {
        let old_session = self.session.clone();
        let identity_counts = self._idp.counts();
        self.daemon.stop();
        self.daemon = self
            .layout
            .start(&[("OPAQUE_CONTAINED_VAULT_TOKEN", &self.signer)]);
        self.workstation
            .reconnect(&std::fs::read(self.layout.state.join("approval_server.cert")).unwrap());
        assert!(
            self.daemon
                .agent()
                .call(
                    "task_get",
                    json!({"task_id":task["id"]}),
                    Some(&old_session)
                )
                .await
                .is_err()
        );
        self.session = self.delegate().await;
        assert_ne!(self.session, old_session);
        assert_eq!(self._idp.counts(), identity_counts);
    }
    async fn no_replay(&self, task: &Value) {
        assert!(self.run(task).await.unwrap().unwrap()["error"].is_object());
        assert!(self.workstation.pending().await.is_empty());
        assert_eq!(Services::call("snapshot", &[])["reads"], 1);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.daemon.stop();
    }
}

#[tokio::test]
#[ignore = "requires disposable Vault/OpenSSH/systemd container and Linux root with SYS_PTRACE"]
#[allow(clippy::await_holding_lock)]
async fn contained_signed_ssh_runs_one_probe_and_rejects_replay_after_restart() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut fixture = Fixture::new().await;
    let task = fixture.plan().await;
    let pending = fixture.run(&task);
    let review = fixture.workstation.wait_review("ssh.health_manifest").await;
    fixture.verify_review(&review, &task);
    fixture.assert_unapproved_host();
    fixture.workstation.respond(&review, true).await.unwrap();
    let result = pending.await.unwrap().unwrap();
    assert!(result["error"].is_null(), "approved SSH task was rejected");
    let completed = &result["result"]["task"];
    assert_eq!(completed["state"], "completed");
    assert_eq!(completed["slots"][0]["state"], "api_accepted");
    let host_receipt = &completed["slots"][0]["outcome"]["ssh_receipt"];
    assert_eq!(host_receipt["code"], "health_observed");
    assert_eq!(
        host_receipt["grant_id"],
        task["manifest"]["actions"][0]["grant_id"]
    );
    assert_eq!(
        host_receipt["signed_receipt_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        serde_json::from_str::<Value>(host_receipt["output_text"].as_str().unwrap()).unwrap(),
        json!({"service":"contained-api", "status":"ok", "version":"1"})
    );
    Services::call(
        "replay-host",
        &[&fixture.layout.base.path().join("planned-task.json")],
    );
    let evidence = Services::call("snapshot", &[]);
    assert_eq!(evidence["reads"], 1);
    assert_eq!(evidence["vault_sign_requests"], 1);
    assert_eq!(evidence["grants"].as_array().unwrap().len(), 1);
    assert_eq!(evidence["grants"][0]["state"], "completed");
    assert_eq!(evidence["grants"][0]["revoked"], 1);
    assert!(evidence["probe_pids"].as_array().unwrap().is_empty());
    let receipt = fixture.receipt(completed).await;
    fixture.no_replay(&task).await;
    fixture.restart(&task).await;
    assert_eq!(fixture.get(&task).await, *completed);
    assert_eq!(fixture.receipt(completed).await, receipt);
    fixture.no_replay(&task).await;
}

#[tokio::test]
#[ignore = "requires disposable Vault/OpenSSH/systemd container and Linux root with SYS_PTRACE"]
#[allow(clippy::await_holding_lock)]
async fn contained_guard_crash_preserves_unknown_and_kills_probe_without_replay() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut fixture = Fixture::new().await;
    let task = fixture.plan().await;
    Services::call("stall", &[]);
    let pending = fixture.run(&task);
    let review = fixture.workstation.wait_review("ssh.health_manifest").await;
    fixture.verify_review(&review, &task);
    fixture.assert_unapproved_host();
    fixture.workstation.respond(&review, true).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Services::call("snapshot", &[])["reads"] == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "real SSH probe did not enter health service"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Services::call("crash-guard", &[]);
    let result = pending.await.unwrap().unwrap();
    assert!(result["error"].is_null());
    let task_state = &result["result"]["task"];
    assert_eq!(task_state["slots"][0]["state"], "unknown");
    assert_eq!(
        task_state["slots"][0]["outcome"]["code"],
        "transport_unknown"
    );
    assert!(task_state["slots"][0]["outcome"]["ssh_receipt"].is_null());
    fixture.receipt(task_state).await;
    let snapshot = Services::call("snapshot", &[]);
    assert_eq!(snapshot["reads"], 1);
    assert_eq!(snapshot["vault_sign_requests"], 1);
    assert_eq!(snapshot["grants"][0]["state"], "unknown");
    assert_eq!(snapshot["grants"][0]["revoked"], 1);
    assert!(snapshot["probe_pids"].as_array().unwrap().is_empty());
    assert!(
        snapshot["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|receipt| receipt["status"] == "unknown"
                && receipt["result_code"] == "restart_unknown")
    );
    assert_eq!(fixture.get(&task).await, *task_state);
    fixture.no_replay(&task).await;
    fixture.restart(&task).await;
    assert_eq!(fixture.get(&task).await, *task_state);
    fixture.receipt(task_state).await;
    fixture.no_replay(&task).await;
}

/// A controlled HTTP protocol peer, not a model or model-quality assertion.
/// Its metadata barrier makes authority mutation deterministic while the real
/// broker is awaiting I/O, without replacing its policy/ledger dispatch fence.
struct InferencePeer {
    profile: Value,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    entered: std::sync::Arc<tokio::sync::Notify>,
    released: std::sync::Arc<tokio::sync::Notify>,
    completions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}
impl InferencePeer {
    async fn new() -> Self {
        use axum::{
            Json, Router,
            routing::{get, post},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let profile = json!({
            "profile_id":"inference-rpc-fixture", "api_url":format!("http://{}/", listener.local_addr().unwrap()),
            "model_id":"fixture-model.gguf", "model_path":"/models/fixture-model.gguf",
            "model_artifact_sha256":"a".repeat(64),
            "chat_template_sha256":opaque_core::inference::sha256(b"fixed-template-v1"),
            "server_build":"b1-fixture", "service_uid":uuid::Uuid::new_v4(),
            "source_id":opaque_bounded_work::inference::DEMO_SOURCE_ID,
            "source_snapshot_sha256":opaque_bounded_work::inference::demo_source_snapshot_sha256(),
            "allow_loopback_http":true
        });
        let armed = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(tokio::sync::Notify::new());
        let completions = Arc::new(AtomicUsize::new(0));
        let (a, e, r) = (armed.clone(), entered.clone(), released.clone());
        let observed = completions.clone();
        let routes = Router::new()
            .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
            .route("/props", get(move || {
                let (a, e, r) = (a.clone(), e.clone(), r.clone());
                async move {
                    if a.swap(false, Ordering::SeqCst) {
                        e.notify_one();
                        r.notified().await;
                    }
                    Json(json!({"model_path":"/models/fixture-model.gguf", "build_info":"b1-fixture",
                        "chat_template":"fixed-template-v1", "total_slots":1,
                        "default_generation_settings":{"n_ctx":2048}}))
                }
            }))
            .route("/v1/models", get(|| async { Json(json!({"data":[{"id":"fixture-model.gguf"}]})) }))
            .route("/apply-template", post(|| async { Json(json!({"prompt":"formatted public fixture"})) }))
            .route("/tokenize", post(|| async { Json(json!({"tokens":[10,11,12]})) }))
            .route("/completion", post(move |Json(request): Json<Value>| {
                let observed = observed.clone();
                async move {
                    assert_eq!(request["model"], "fixture-model.gguf");
                    assert_eq!(request["prompt"], json!([10,11,12]));
                    assert_eq!(request["n_predict"], 96);
                    observed.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"content":"Controlled protocol completion.", "model":"fixture-model.gguf",
                        "stop":true,"truncated":false,"stop_type":"eos", "tokens_evaluated":3,
                        "tokens_predicted":3,"tokens":[1,2,3],"generation_settings":{"n_predict":96}}))
                }
            }));
        let server = tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        Self {
            profile,
            armed,
            entered,
            released,
            completions,
            server,
        }
    }
    fn arm(&self) {
        assert!(!self.armed.swap(true, std::sync::atomic::Ordering::SeqCst));
    }
    async fn wait_metadata(&self) {
        tokio::time::timeout(Duration::from_secs(15), self.entered.notified())
            .await
            .expect("live metadata barrier");
    }
    fn release(&self) {
        self.released.notify_one();
    }
    fn count(&self) -> usize {
        self.completions.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl Drop for InferencePeer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
#[ignore = "requires disposable marked Linux systemd fixture and root with SYS_PTRACE"]
#[allow(clippy::await_holding_lock)]
async fn contained_inference_rpc_rechecks_authority_after_metadata_without_refunding() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let model = InferencePeer::new().await;
    let mut fixture = Fixture::with_inference(Some(&model.profile)).await;
    let plan_args =
        json!({"title":"Controlled inference protocol acceptance", "expires_in_secs":300});

    // Revoking delegation during planning's actual metadata GET must not
    // create a durable task under the authority observed before that await.
    model.arm();
    let peer = fixture.daemon.agent();
    let session = fixture.session.clone();
    let args = plan_args.clone();
    let planning =
        tokio::spawn(async move { peer.call("task_plan_inference", args, Some(&session)).await });
    model.wait_metadata().await;
    fixture
        .daemon
        .human()
        .ok("agent_session_end", json!({"all":true}), None)
        .await;
    model.release();
    let denied = planning.await.unwrap();
    assert!(denied.is_err() || denied.unwrap()["error"].is_object());
    fixture.session = fixture.delegate().await;
    let listing = fixture
        .daemon
        .agent()
        .ok("task_list", json!({}), Some(&fixture.session))
        .await;
    assert!(listing["tasks"].as_array().unwrap().is_empty());
    assert_eq!(model.count(), 0);

    // The successful RPC path uses the real HTTP adapter and typed receipts.
    // The returned strings are controlled protocol data, not model evidence.
    let task = fixture
        .daemon
        .agent()
        .ok(
            "task_plan_inference",
            plan_args.clone(),
            Some(&fixture.session),
        )
        .await["task"]
        .clone();
    assert_eq!(task["manifest"]["schema_version"], 3);
    assert_eq!(task["slots"].as_array().unwrap().len(), 3);
    let running = fixture.run(&task);
    let review = fixture
        .workstation
        .wait_review("inference.fixed_manifest")
        .await;
    fixture.verify_review(&review, &task);
    assert_eq!(model.count(), 0);
    fixture.workstation.respond(&review, true).await.unwrap();
    let response = running.await.unwrap().unwrap();
    assert!(response["error"].is_null());
    let completed = &response["result"]["task"];
    assert_eq!(completed["state"], "completed");
    for slot in completed["slots"].as_array().unwrap() {
        assert_eq!(slot["state"], "api_accepted");
        assert_eq!(
            slot["outcome"]["inference_receipt"]["code"],
            "completion_observed"
        );
        assert_eq!(
            slot["outcome"]["inference_receipt"]["reserved_output_tokens"],
            96
        );
        assert_eq!(
            slot["outcome"]["inference_receipt"]["observed_output_tokens"],
            3
        );
    }
    assert_eq!(model.count(), 3);
    fixture.receipt(completed).await;

    // After approval/reservation, mutate live task authority while execution
    // is awaiting metadata. The final dispatch fence must prevent completion
    // and retain the charged first slot; subsequent slots stay untouched.
    let task = fixture
        .daemon
        .agent()
        .ok("task_plan_inference", plan_args, Some(&fixture.session))
        .await["task"]
        .clone();
    model.arm();
    let running = fixture.run(&task);
    let review = fixture
        .workstation
        .wait_review("inference.fixed_manifest")
        .await;
    fixture.verify_review(&review, &task);
    fixture.workstation.respond(&review, true).await.unwrap();
    model.wait_metadata().await;
    let reserved = fixture.get(&task).await;
    assert_eq!(reserved["slots"][0]["state"], "reserved");
    assert!(reserved["slots"][0]["reserved_at"].is_number());
    fixture
        .daemon
        .agent()
        .ok(
            "task_revoke",
            json!({"task_id":task["id"]}),
            Some(&fixture.session),
        )
        .await;
    model.release();
    let response = running.await.unwrap().unwrap();
    assert!(response["error"].is_null());
    let revoked = &response["result"]["task"];
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(revoked["slots"][0]["state"], "rejected");
    assert_eq!(
        revoked["slots"][0]["outcome"]["code"],
        "reviewer_or_task_authority_changed"
    );
    assert_eq!(
        revoked["slots"][0]["reserved_at"],
        reserved["slots"][0]["reserved_at"]
    );
    assert!(revoked["slots"][0]["outcome"]["inference_receipt"].is_null());
    for slot in revoked["slots"].as_array().unwrap().iter().skip(1) {
        assert_eq!(slot["state"], "pending");
        assert!(slot["reserved_at"].is_null());
    }
    fixture.receipt(revoked).await;
    assert_eq!(model.count(), 3);
    assert!(fixture.run(&task).await.unwrap().unwrap()["error"].is_object());
    fixture.restart(&task).await;
    assert_eq!(fixture.get(&task).await, *revoked);
    assert!(fixture.run(&task).await.unwrap().unwrap()["error"].is_object());
    assert_eq!(model.count(), 3);
    assert!(fixture.workstation.pending().await.is_empty());
}
