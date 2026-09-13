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
        let text: Vec<&str> = if task["manifest"]["schema_version"] == 4 {
            vec![
                "contained-health",
                "127.0.0.1",
                "OPAQUE_CONTAINED_VAULT_TOKEN",
            ]
        } else {
            ["profile_id", "model_id", "source_id"]
                .into_iter()
                .map(|key| task["manifest"]["actions"][0][key].as_str().unwrap())
                .collect()
        };
        for text in text {
            assert!(
                review.review_text.contains(text),
                "trusted review omitted manifest scope"
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
    fn task_rows(&self) -> Vec<(String, String, String)> {
        let database = rusqlite::Connection::open_with_flags(
            self.layout.state.join("tasks.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        database.busy_timeout(Duration::from_secs(2)).unwrap();
        database
            .prepare("SELECT id, owner_key, record FROM bounded_tasks ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
    async fn wait_probe(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let observed = Services::call("snapshot", &[]);
            if observed["reads"] == 1 {
                assert_eq!(observed["vault_sign_requests"], 1);
                assert_eq!(observed["grants"].as_array().unwrap().len(), 1);
                assert_eq!(observed["grants"][0]["state"], "reserved");
                assert_eq!(observed["probe_observations"].as_array().unwrap().len(), 1);
                assert_eq!(observed["guard_idle"], false);
                return observed;
            }
            assert!(
                Instant::now() < deadline,
                "real SSH probe observation deadline"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn wait_guard_idle(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let observed = Services::call("snapshot", &[]);
            if observed["guard_idle"] == true {
                return observed;
            }
            assert!(
                Instant::now() < deadline,
                "observed probe identities survived cancellation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
        let before = Services::call("snapshot", &[]);
        let persisted = self.get(task).await;
        assert!(self.run(task).await.unwrap().unwrap()["error"].is_object());
        assert!(self.workstation.pending().await.is_empty());
        assert_eq!(self.get(task).await, persisted);
        assert_eq!(Services::call("snapshot", &[]), before);
        assert_eq!(before["reads"], 1);
        assert_eq!(before["vault_sign_requests"], 1);
        assert_eq!(before["grants"].as_array().unwrap().len(), 1);
        assert_eq!(before["probe_observations"].as_array().unwrap().len(), 1);
        assert_eq!(before["guard_idle"], true);
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
async fn contained_ssh_rpc_rejects_absent_and_disabled_principals_without_effects() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut fixture = Fixture::new().await;
    let task = fixture.plan().await;
    let before = fixture.task_rows();
    let host_before = Services::call("snapshot", &[]);

    // This is an independently verified human executable in a valid tenant.
    // A human login exists, but the RPC has no delegated principal context;
    // neither OS identity nor a previous login substitutes for that binding.
    let denied = fixture
        .daemon
        .human()
        .call(
            "task_plan_ssh",
            json!({"title":"Missing delegated principal", "expires_in_secs":120}),
            None,
        )
        .await
        .unwrap();
    assert_eq!(denied["error"]["code"], "task_unavailable");
    assert_eq!(
        denied["error"]["message"],
        "tenant tasks require an authenticated tenant principal and live delegation"
    );
    assert!(denied["result"].is_null());
    assert_eq!(fixture.task_rows(), before);

    // Disable only the delegating principal in this disposable identity DB.
    // Production SQLite triggers retire its delegations and human sessions
    // atomically; this exercises those real RPC consequences independently
    // of subject admission, tenant binding, and the signed OIDC response.
    let identity = rusqlite::Connection::open(fixture.layout.state.join("identity.db")).unwrap();
    identity.busy_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        identity
            .execute(
                "UPDATE principals SET disabled=1 WHERE id=?1 AND disabled=0",
                [&fixture.requester],
            )
            .unwrap(),
        1
    );
    for (method, params) in [
        (
            "task_plan_ssh",
            json!({"title":"Disabled delegated principal", "expires_in_secs":120}),
        ),
        ("task_run", json!({"task_id":task["id"]})),
        ("task_revoke", json!({"task_id":task["id"]})),
    ] {
        let denied = fixture
            .daemon
            .agent()
            .call(method, params, Some(&fixture.session))
            .await
            .unwrap();
        assert_eq!(denied["error"]["code"], "delegation_invalid", "{method}");
        assert!(denied["result"].is_null());
        assert_eq!(
            fixture.task_rows(),
            before,
            "{method} changed durable authority"
        );
        assert_eq!(Services::call("snapshot", &[]), host_before);
        assert!(fixture.workstation.pending().await.is_empty());
    }
    let old_delegation = task["manifest"]["actions"][0]["delegation_id"]
        .as_str()
        .unwrap();
    let revoked_at: i64 = identity
        .query_row(
            "SELECT revoked_at FROM delegations WHERE jti=?1",
            [old_delegation],
            |row| row.get(0),
        )
        .unwrap();
    // Re-enabling the fixture principal must not resurrect its old authority.
    assert_eq!(
        identity
            .execute(
                "UPDATE principals SET disabled=0 WHERE id=?1 AND disabled=1",
                [&fixture.requester],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        identity
            .query_row(
                "SELECT revoked_at FROM delegations WHERE jti=?1",
                [old_delegation],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        revoked_at
    );
    let old_session = fixture.session.clone();
    let still_denied = fixture
        .daemon
        .agent()
        .call(
            "task_get",
            json!({"task_id":task["id"]}),
            Some(&old_session),
        )
        .await
        .unwrap();
    assert_eq!(still_denied["error"]["code"], "delegation_invalid");
    assert!(still_denied["result"].is_null());
    drop(identity);
    let fresh_identity = login(&fixture.daemon.human(), &fixture._idp, "requester").await;
    assert_eq!(fresh_identity["principal_id"], fixture.requester);
    fixture.session = fixture.delegate().await;
    assert_ne!(fixture.session, old_session);
    assert_eq!(fixture.get(&task).await, task);
    fixture.restart(&task).await;
    assert_eq!(fixture.get(&task).await, task);
    assert_eq!(fixture.task_rows(), before);
    assert_eq!(Services::call("snapshot", &[]), host_before);
}

#[tokio::test]
#[ignore = "requires disposable Vault/OpenSSH/systemd container and Linux root with SYS_PTRACE"]
#[allow(clippy::await_holding_lock)]
async fn contained_ssh_rpc_rejects_foreign_tenant_and_broker_bindings_without_effects() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut fixture = Fixture::new().await;
    let task = fixture.plan().await;
    let before = fixture.task_rows();
    let host_before = Services::call("snapshot", &[]);
    for (field, foreign) in [
        ("tenant_id", json!("another-admitted-tenant")),
        ("broker_id", json!(uuid::Uuid::new_v4())),
    ] {
        let mut manifest = task["manifest"].clone();
        manifest["actions"][0]["tenant"][field] = foreign;
        // A well-formed manifest with exactly one different authority field
        // must reach the trusted profile binding check, not JSON rejection.
        let parsed: opaque_core::task::TaskManifest =
            serde_json::from_value(manifest.clone()).unwrap();
        parsed.validate().unwrap();
        let denied = fixture
            .daemon
            .agent()
            .call(
                "task_plan",
                json!({"manifest":manifest}),
                Some(&fixture.session),
            )
            .await
            .unwrap();
        assert_eq!(denied["error"]["code"], "task_unavailable", "{field}");
        assert_eq!(
            denied["error"]["message"], "SSH profile or authenticated host evidence unavailable",
            "{field}"
        );
        assert!(denied["result"].is_null());
        assert_eq!(fixture.task_rows(), before);
        assert_eq!(Services::call("snapshot", &[]), host_before);
        assert!(fixture.workstation.pending().await.is_empty());
    }
    assert_eq!(fixture.get(&task).await, task);
    fixture.restart(&task).await;
    assert_eq!(fixture.task_rows(), before);
    assert_eq!(fixture.get(&task).await, task);
    assert_eq!(Services::call("snapshot", &[]), host_before);
}

#[tokio::test]
#[ignore = "requires disposable Vault/OpenSSH/systemd container and Linux root with SYS_PTRACE"]
#[allow(clippy::await_holding_lock)]
async fn contained_ssh_revoke_during_probe_preserves_charge_and_stops_observed_processes() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut fixture = Fixture::new().await;
    let task = fixture.plan().await;
    Services::call("stall", &[]);
    let running = fixture.run(&task);
    let review = fixture.workstation.wait_review("ssh.health_manifest").await;
    fixture.verify_review(&review, &task);
    fixture.assert_unapproved_host();
    fixture.workstation.respond(&review, true).await.unwrap();
    let observed = fixture.wait_probe().await;
    let reserved = fixture.get(&task).await;
    assert_eq!(reserved["slots"][0]["state"], "reserved");
    assert!(reserved["slots"][0]["reserved_at"].is_number());

    // Both real effects already happened: Vault signed once and the NSS
    // workload reached the health service once. Revoke through the actual
    // broker RPC while its SSH driver is collecting the blocked response.
    let revoked = fixture
        .daemon
        .agent()
        .ok(
            "task_revoke",
            json!({"task_id":task["id"]}),
            Some(&fixture.session),
        )
        .await;
    assert_eq!(revoked["task"]["state"], "revoked");
    let response = running.await.unwrap().unwrap();
    assert!(response["error"].is_null());
    let charged = &response["result"]["task"];
    assert_eq!(charged["state"], "revoked");
    assert_eq!(charged["slots"][0]["state"], "unknown");
    assert_eq!(charged["slots"][0]["outcome"]["code"], "transport_unknown");
    assert!(charged["slots"][0]["outcome"]["ssh_receipt"].is_null());
    assert_eq!(
        charged["slots"][0]["reserved_at"],
        reserved["slots"][0]["reserved_at"]
    );
    fixture.receipt(charged).await;
    let stopped = fixture.wait_guard_idle().await;
    assert_eq!(stopped["reads"], 1);
    assert_eq!(stopped["vault_sign_requests"], 1);
    assert_eq!(
        stopped["probe_observations"],
        observed["probe_observations"]
    );
    assert_eq!(stopped["grants"].as_array().unwrap().len(), 1);
    // Host ledger `completed` means its one reservation was finalized;
    // the authenticated receipt below carries the actual revoked outcome.
    assert_eq!(stopped["grants"][0]["state"], "completed");
    assert_eq!(stopped["grants"][0]["revoked"], 1);
    assert!(
        stopped["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|receipt| receipt["status"] == "revoked" && receipt["result_code"] == "revoked")
    );
    Services::call(
        "replay-host",
        &[&fixture.layout.base.path().join("planned-task.json")],
    );
    let host_after_replay = Services::call("snapshot", &[]);
    fixture.no_replay(&task).await;
    fixture.restart(&task).await;
    assert_eq!(fixture.get(&task).await, *charged);
    assert_eq!(Services::call("snapshot", &[]), host_after_replay);
    fixture.no_replay(&task).await;
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
    assert_eq!(evidence["guard_idle"], true);
    assert_eq!(evidence["probe_observations"].as_array().unwrap().len(), 1);
    assert_eq!(
        evidence["probe_observations"][0]["probe"]["uids"],
        json!([7382, 7382, 7382, 7382])
    );
    assert_eq!(
        evidence["probe_observations"][0]["probe"]["gids"],
        json!([7382, 7382, 7382, 7382])
    );
    assert_eq!(
        evidence["probe_observations"][0]["probe"]["groups"],
        json!([])
    );
    let receipt = fixture.receipt(completed).await;
    fixture.no_replay(&task).await;
    fixture.restart(&task).await;
    assert_eq!(Services::call("snapshot", &[]), evidence);
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
    assert_eq!(snapshot["grants"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["guard_idle"], true);
    assert_eq!(snapshot["probe_observations"].as_array().unwrap().len(), 1);
    assert_eq!(
        snapshot["probe_observations"][0]["probe"]["uids"],
        json!([7382, 7382, 7382, 7382])
    );
    assert_eq!(
        snapshot["probe_observations"][0]["probe"]["gids"],
        json!([7382, 7382, 7382, 7382])
    );
    assert_eq!(
        snapshot["probe_observations"][0]["probe"]["groups"],
        json!([])
    );
    assert!(
        snapshot["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|receipt| receipt["status"] == "unknown"
                && receipt["result_code"] == "restart_unknown")
    );
    Services::call(
        "replay-host",
        &[&fixture.layout.base.path().join("planned-task.json")],
    );
    let after_denial = Services::call("snapshot", &[]);
    assert_eq!(fixture.get(&task).await, *task_state);
    fixture.no_replay(&task).await;
    fixture.restart(&task).await;
    assert_eq!(Services::call("snapshot", &[]), after_denial);
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

/// Observe the real llama-server's independent generation counter. The
/// dedicated runner owns the server/model processes and their byte hashes;
/// this test never stands in for its metadata, tokenizer, or completions.
async fn actual_generated_tokens(profile: &Value) -> u64 {
    let mut endpoint = reqwest::Url::parse(profile["api_url"].as_str().unwrap()).unwrap();
    endpoint.set_path("/metrics");
    let response = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(endpoint)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let metrics = response.text().await.unwrap();
    assert!(metrics.len() <= 64 * 1024, "unexpected model metrics size");
    let samples: Vec<_> = metrics
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("llamacpp:tokens_predicted_total") {
                return None;
            }
            let value = fields.next().unwrap().parse::<u64>().unwrap();
            assert!(fields.next().is_none(), "unexpected model metric labels");
            Some(value)
        })
        .collect();
    assert_eq!(
        samples.len(),
        1,
        "real model generation counter unavailable"
    );
    samples[0]
}

#[tokio::test]
#[ignore = "requires the owned real-model profile, pinned llama-server/GGUF, and Linux systemd fixture"]
#[allow(clippy::await_holding_lock)]
async fn contained_real_model_completions_require_signed_review_and_survive_restart() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let profile_path = PathBuf::from(
        std::env::var_os("OPAQUE_TEST_REAL_MODEL_PROFILE")
            .expect("the real-model runner must supply its observed profile"),
    );
    assert!(profile_path.is_absolute());
    let mut profile: Value = serde_json::from_slice(&std::fs::read(profile_path).unwrap()).unwrap();
    assert_eq!(
        profile["source_id"],
        opaque_bounded_work::inference::DEMO_SOURCE_ID
    );
    let source_snapshot = opaque_bounded_work::inference::demo_source_snapshot_sha256();
    if let Some(supplied) = profile.get("source_snapshot_sha256") {
        assert!(supplied == "" || supplied == &source_snapshot);
    }
    // Derive the fixed public source identity from production code, rather
    // than duplicating its prompts or hash in the process-owning Python layer.
    profile["source_snapshot_sha256"] = json!(source_snapshot);
    assert_eq!(actual_generated_tokens(&profile).await, 0);
    let mut fixture = Fixture::with_inference(Some(&profile)).await;
    let args =
        json!({"title":"Actual model completions under signed review", "expires_in_secs":300});
    let rejected = fixture
        .daemon
        .agent()
        .ok("task_plan_inference", args.clone(), Some(&fixture.session))
        .await["task"]
        .clone();
    let running = fixture.run(&rejected);
    let review = fixture
        .workstation
        .wait_review("inference.fixed_manifest")
        .await;
    fixture.verify_review(&review, &rejected);
    assert_eq!(actual_generated_tokens(&profile).await, 0);
    fixture.workstation.respond(&review, false).await.unwrap();
    let denied = running.await.unwrap().unwrap();
    assert_eq!(denied["error"]["code"], "task_unavailable");
    assert!(denied["result"].is_null());
    let uncharged = fixture.get(&rejected).await;
    assert_eq!(uncharged["state"], "partial");
    for field in ["approved_at", "approval_mode", "workstation_receipt"] {
        assert!(uncharged[field].is_null());
    }
    assert_eq!(uncharged["slots"].as_array().unwrap().len(), 3);
    for slot in uncharged["slots"].as_array().unwrap() {
        assert_eq!(slot["state"], "pending");
        for field in ["reserved_at", "request_id", "outcome", "finished_at"] {
            assert!(slot[field].is_null());
        }
    }
    assert!(fixture.run(&rejected).await.unwrap().unwrap()["error"].is_object());
    assert!(fixture.workstation.pending().await.is_empty());
    assert_eq!(fixture.get(&rejected).await, uncharged);
    assert_eq!(actual_generated_tokens(&profile).await, 0);

    let approved = fixture
        .daemon
        .agent()
        .ok("task_plan_inference", args, Some(&fixture.session))
        .await["task"]
        .clone();
    assert_ne!(approved["id"], rejected["id"]);
    for action in approved["manifest"]["actions"].as_array().unwrap() {
        for field in [
            "profile_id",
            "model_id",
            "model_artifact_sha256",
            "source_id",
            "source_snapshot_sha256",
        ] {
            assert_eq!(
                action[field], profile[field],
                "approved {field} differs from observed profile"
            );
        }
    }
    let running = fixture.run(&approved);
    let review = fixture
        .workstation
        .wait_review("inference.fixed_manifest")
        .await;
    fixture.verify_review(&review, &approved);
    assert_eq!(actual_generated_tokens(&profile).await, 0);
    fixture.workstation.respond(&review, true).await.unwrap();
    let response = running.await.unwrap().unwrap();
    assert!(response["error"].is_null(), "actual model task failed");
    let completed = &response["result"]["task"];
    assert_eq!(completed["state"], "completed");
    assert_eq!(completed["slots"].as_array().unwrap().len(), 3);
    let mut predicted_tokens = 0;
    let mut request_ids = std::collections::BTreeSet::new();
    for slot in completed["slots"].as_array().unwrap() {
        assert_eq!(slot["state"], "api_accepted");
        assert!(slot["reserved_at"].is_number());
        assert!(request_ids.insert(slot["request_id"].as_str().unwrap()));
        let receipt = &slot["outcome"]["inference_receipt"];
        assert_eq!(receipt["code"], "completion_observed");
        assert_eq!(receipt["reserved_output_tokens"], 96);
        assert!((1..=512).contains(&receipt["input_tokens"].as_u64().unwrap()));
        let tokens = receipt["observed_output_tokens"].as_u64().unwrap();
        assert!((1..=96).contains(&tokens));
        let output = receipt["output_text"].as_str().unwrap();
        assert!(
            !output.trim().is_empty(),
            "actual model returned no completion text"
        );
        assert_eq!(
            receipt["output_sha256"],
            opaque_core::inference::sha256(output.as_bytes())
        );
        assert_eq!(receipt["tenant"], approved["tenant"]);
        predicted_tokens += tokens;
    }
    let signed_receipt = fixture.receipt(completed).await;
    assert_eq!(actual_generated_tokens(&profile).await, predicted_tokens);
    let rows = fixture.task_rows();
    for restarted in [false, true] {
        if restarted {
            fixture.restart(&approved).await;
        }
        assert_eq!(fixture.get(&approved).await, *completed);
        assert_eq!(fixture.get(&rejected).await, uncharged);
        assert_eq!(fixture.receipt(completed).await, signed_receipt);
        for task in [&approved, &rejected] {
            assert!(fixture.run(task).await.unwrap().unwrap()["error"].is_object());
        }
        assert!(fixture.workstation.pending().await.is_empty());
        assert_eq!(fixture.task_rows(), rows);
        assert_eq!(actual_generated_tokens(&profile).await, predicted_tokens);
    }
}
