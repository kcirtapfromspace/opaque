//! Fully automated real-daemon composition: signed mock OIDC, sealed split-UID
//! custody, pinned workstation TLS, explicit synthetic signing, real task IPC,
//! counted GitHub/Vault protocol effects and independently checked receipts.
//! No UI, customer credentials or claim of actual human approval. The ignored
//! cases are mandatory in the Linux-root synthesized profile (--include-ignored
//! --exact), and fail their prerequisite instead of returning an empty pass.
#![cfg(target_os = "linux")]
#[path = "support/oidc.rs"]
mod oidc;
#[path = "support/preparation_fence.rs"]
mod preparation_fence;
#[path = "support/split_daemon.rs"]
mod split_daemon;
#[path = "support/workstation.rs"]
mod workstation;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use opaque_core::workstation::{SignedWorkstationReceipt, WorkstationReview};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use split_daemon::{Daemon, Layout, Peer};
use std::time::{Duration, Instant};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};
use workstation::ScriptedWorkstation;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const PAT: &str = "ghp_synthetic_review_fixture_only";
const VAULT_TOKEN: &str = "synthetic-review-vault-token";
const SECRET: &str = "synthetic-secret-custody-sentinel";
const CLIENT: &str = "opaque-synthesized-review";
const LIFECYCLE_TOKEN: &str = "synthetic-lifecycle-transport-credential-for-disposable-ci-only";

struct Providers {
    github: MockServer,
    vault: MockServer,
    key: crypto_box::SecretKey,
}
impl Providers {
    async fn new() -> Self {
        let github = MockServer::start().await;
        let vault = MockServer::start().await;
        let key = crypto_box::SecretKey::from([42; 32]);
        Mock::given(method("GET"))
            .and(path("/repos/acme/synthetic"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id":918273,"full_name":"acme/synthetic"})),
            )
            .mount(&github)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/synthetic/actions/secrets/public-key"))
            .and(header("authorization", format!("Bearer {PAT}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"key_id":"568250167","key":STANDARD.encode(key.public_key().as_bytes())}),
            ))
            .mount(&github)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/acme/synthetic/actions/secrets/CI_TOKEN"))
            .and(header("authorization", format!("Bearer {PAT}")))
            .respond_with(ResponseTemplate::new(201))
            .mount(&github)
            .await;
        Mock::given(method("GET")).and(path("/v1/secret/data/synthetic")).and(header("x-vault-token",VAULT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":{"data":{"TOKEN":SECRET},"metadata":{"version":1,"destroyed":false,"deletion_time":""}}}))).mount(&vault).await;
        Self { github, vault, key }
    }
    async fn effects(&self) -> (usize, usize) {
        let vault = self.vault.received_requests().await.unwrap();
        let github = self.github.received_requests().await.unwrap();
        (
            vault.len(),
            github.iter().filter(|r| r.method.as_str() == "PUT").count(),
        )
    }
    async fn verify_one_effect(&self) {
        assert_eq!(self.effects().await, (1, 1));
        let requests = self.github.received_requests().await.unwrap();
        let write = requests
            .iter()
            .find(|r| r.method.as_str() == "PUT")
            .unwrap();
        let body: Value = serde_json::from_slice(&write.body).unwrap();
        assert_eq!(body["key_id"], "568250167");
        let encrypted = STANDARD
            .decode(body["encrypted_value"].as_str().unwrap())
            .unwrap();
        assert_eq!(self.key.unseal(&encrypted).unwrap(), SECRET.as_bytes());
        assert!(!String::from_utf8_lossy(&write.body).contains(SECRET));
    }
}
fn env<'a>(github: &'a str, vault: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("OPAQUE_GITHUB_API_URL", github),
        ("OPAQUE_VAULT_URL", vault),
        ("OPAQUE_DOGFOOD_LOOPBACK", "1"),
        ("OPAQUE_VAULT_TOKEN_REF", "env:OPAQUE_SYNTH_VAULT_TOKEN"),
        ("OPAQUE_SYNTH_VAULT_TOKEN", VAULT_TOKEN),
        ("OPAQUE_SYNTH_PAT", PAT),
    ]
}
fn config(layout: &Layout, issuer: &str, port: u16, reviewer: Option<(&str, &str)>) -> String {
    let mapping=reviewer.map(|(principal,key)|format!("workstation_approvers = [{{public_key_hex = \"{key}\", name = \"Synthetic CI reviewer\", principal_id = \"{principal}\"}}]\n")).unwrap_or_default();
    let remote=reviewer.map(|(_,key)|format!("\n[remote_approvals]\nreviewer_public_key_hex = \"{key}\"\nrequired_role = \"approver\"\n")).unwrap_or_default();
    let mut result = format!(
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
id = "synthesized-review-fixture"
[trust_domain]
enforce = true
socket_group = "{}"
socket_path = "{}"
[approval]
server_bind = "127.0.0.1:{port}"
timeout_secs = 5
session_factor = "paired_workstation"
[identity]
issuer = "{issuer}"
client_id = "{CLIENT}"
required = true
session_ttl_secs = 600
allowed_subjects = ["reviewer", "requester"]
[attestation]
interval_secs = 0
{remote}
"#,
        layout.state.display(),
        layout.human_binary.display(),
        split_daemon::SOCKET_GID,
        layout.socket.display()
    );
    for operation in ["github.publish_manifest", "github.set_actions_secret"] {
        result += &format!(
            r#"
[[rules]]
name = "synthetic-{operation}"
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
    result
}
async fn login(peer: &Peer, idp: &oidc::MockOidc, subject: &str) -> Value {
    let start = peer.ok("identity.login_start", Value::Null, None).await;
    let url = reqwest::Url::parse(start["auth_url"].as_str().unwrap()).unwrap();
    let value = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .unwrap()
            .1
            .into_owned()
    };
    idp.register_redirect(&value("redirect_uri"));
    idp.select_identity(
        &value("state"),
        oidc::TestIdentity {
            subject: subject.into(),
            email: format!("{subject}@example.invalid"),
            token_nonce_override: None,
        },
    );
    let authorize = idp.authorize(url.as_str()).await;
    assert_eq!(authorize.status(), reqwest::StatusCode::FOUND);
    let callback = authorize.headers()["location"].to_str().unwrap();
    assert!(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap()
            .get(callback)
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
        assert_eq!(
            result["status"], "pending",
            "synthetic signed OIDC login failed"
        );
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
fn manifest() -> Value {
    json!({"schema_version":1,"title":"Synthetic encrypted secret publication","expires_in_secs":300,"actions":[{
    "repo":"acme/synthetic","secret_name":"CI_TOKEN","value_ref":"vault:secret/data/synthetic?version=1#TOKEN","github_token_ref":"env:OPAQUE_SYNTH_PAT"}]})
}

struct Fixture {
    daemon: Daemon,
    workstation: ScriptedWorkstation,
    layout: Layout,
    idp: oidc::MockOidc,
    providers: Providers,
    reviewer: String,
    requester: String,
    session: String,
}
impl Fixture {
    async fn enable_lifecycle(&mut self, github: &str) {
        use std::os::unix::fs::PermissionsExt;
        self.daemon.stop();
        let token = self.layout.state.join("identity-lifecycle.token");
        std::fs::write(&token, LIFECYCLE_TOKEN).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let name = std::ffi::CString::new(token.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::chown(
                    name.as_ptr(),
                    split_daemon::BROKER_UID,
                    split_daemon::BROKER_UID,
                )
            },
            0
        );
        let endpoint = &self.workstation.state.enrollment.as_ref().unwrap().endpoint;
        let port = reqwest::Url::parse(endpoint).unwrap().port().unwrap();
        let mut document = config(
            &self.layout,
            &self.idp.uri(),
            port,
            Some((&self.reviewer, &self.workstation.state.public_key_hex)),
        );
        document += &format!(
            "\n[lifecycle]\nsocket_path = {:?}\nallowed_adapter_uids = [0]\ntoken_file = {:?}\n[lifecycle.group_roles]\nreviewers = [\"approver\"]\noperators = [\"operator\"]\n",
            self.layout.state.join("lifecycle.sock"),
            token
        );
        self.layout.seal(&document);
        self.daemon = self.layout.start(&env(github, &self.providers.vault.uri()));
        // The ordinary socket/token appear before optional ingress startup.
        // Complete an RPC before attempting the separate listener readiness check.
        self.daemon.human().ok("version", Value::Null, None).await;
        self.workstation
            .reconnect(&std::fs::read(self.layout.state.join("approval_server.cert")).unwrap());
        let initial = self.lifecycle_batch(1, true);
        self.deliver_lifecycle(&initial).await;
        let requester = login(&self.daemon.human(), &self.idp, "requester").await;
        assert_eq!(requester["principal_id"], self.requester);
        self.session = self.delegate().await;
    }

    fn lifecycle_batch(
        &self,
        revision: u64,
        active: bool,
    ) -> opaque_core::identity_lifecycle::LifecycleBatch {
        use opaque_core::identity_lifecycle::{LifecycleBatch, SubjectUpdate};
        LifecycleBatch {
            schema_version: 1,
            binding: serde_json::from_slice(
                &std::fs::read(self.layout.state.join("tenant.binding.json")).unwrap(),
            )
            .unwrap(),
            issuer: self.idp.uri(),
            revision,
            updates: [("reviewer", "reviewers"), ("requester", "operators")]
                .into_iter()
                .map(|(subject, group)| SubjectUpdate {
                    subject: subject.into(),
                    active,
                    deleted: false,
                    groups: if active { vec![group.into()] } else { vec![] },
                })
                .collect(),
            suspend: false,
        }
    }

    async fn deliver_lifecycle(
        &self,
        batch: &opaque_core::identity_lifecycle::LifecycleBatch,
    ) -> opaque_core::identity_lifecycle::LifecycleReceipt {
        let socket = self.layout.state.join("lifecycle.sock");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                use std::os::unix::fs::FileTypeExt;
                if std::fs::symlink_metadata(&socket)
                    .is_ok_and(|metadata| metadata.file_type().is_socket())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("sealed fixture lifecycle listener did not become ready after daemon startup");
        opaque_core::identity_lifecycle::deliver(
            &socket,
            split_daemon::BROKER_UID,
            LIFECYCLE_TOKEN,
            batch,
        )
        .await
        .unwrap_or_else(|error| panic!("lifecycle revision {} failed: {error}", batch.revision))
    }

    async fn new() -> Self {
        let layout = Layout::new();
        let idp = oidc::MockOidc::start(CLIENT).await;
        let providers = Providers::new().await;
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let mut workstation = ScriptedWorkstation::new(&layout.base.path().join("workstation"));
        layout.seal(&config(&layout, &idp.uri(), port, None));
        let github = providers.github.uri();
        let vault = providers.vault.uri();
        let mut bootstrap = layout.start(&env(&github, &vault));
        let reviewer_identity = login(&bootstrap.human(), &idp, "reviewer").await;
        assert!(
            reviewer_identity["roles"]
                .as_array()
                .unwrap()
                .contains(&json!("approver"))
        );
        let reviewer = reviewer_identity["principal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        bootstrap.stop();
        drop(bootstrap);
        layout.seal(&config(
            &layout,
            &idp.uri(),
            port,
            Some((&reviewer, &workstation.state.public_key_hex)),
        ));
        let daemon = layout.start(&env(&github, &vault));
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
        let requester_identity = login(&daemon.human(), &idp, "requester").await;
        assert_eq!(requester_identity["roles"], json!(["operator"]));
        let requester = requester_identity["principal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(reviewer, requester);
        assert_eq!(
            idp.counts(),
            oidc::Counts {
                codes_issued: 2,
                token_requests: 2,
                tokens_issued: 2,
                token_rejections: 0
            }
        );
        let denied = daemon
            .agent()
            .call("task_plan", json!({"manifest":manifest()}), None)
            .await;
        assert!(
            denied.is_err() || denied.unwrap()["error"].is_object(),
            "unwrapped agent gained task authority"
        );
        let mut fixture = Self {
            daemon,
            workstation,
            layout,
            idp,
            providers,
            reviewer,
            requester,
            session: String::new(),
        };
        fixture.session = fixture.delegate().await;
        let human = fixture.daemon.human().ok("whoami", Value::Null, None).await;
        assert_eq!(human["uid"], split_daemon::CLIENT_UID);
        assert_eq!(human["client_type"], "human");
        assert_eq!(
            human["exe_path"],
            fixture.layout.human_binary.to_str().unwrap()
        );
        assert!(human["pid"].as_u64().unwrap() > 0);
        assert_eq!(
            human["exe_sha256"],
            hex_sha(&std::fs::read(&fixture.layout.human_binary).unwrap())
        );
        let agent = fixture
            .daemon
            .agent()
            .ok("whoami", Value::Null, Some(&fixture.session))
            .await;
        assert_eq!(agent["uid"], split_daemon::CLIENT_UID);
        assert_eq!(agent["client_type"], "agent");
        assert!(agent["agent_session_id"].is_string());
        assert_eq!(fixture.providers.effects().await, (0, 0));
        fixture
    }
    async fn delegate(&self) -> String {
        let peer = self.daemon.human();
        let request = tokio::spawn(async move {
            peer.ok("agent_session_start",json!({"label":"synthetic-agent","reason":"automated protocol acceptance","ttl_secs":300}),None).await
        });
        let review = self.workstation.wait_review("agent_session_start").await;
        assert_eq!(review.challenge.schema_version, 1);
        assert!(review.challenge.authority.is_none());
        self.workstation.respond(&review, true).await.unwrap();
        let response = request.await.unwrap();
        assert_eq!(response["mode"], "delegated");
        assert_eq!(response["on_behalf_of"], self.requester);
        let session = response["session_token"].as_str().unwrap().to_owned();
        assert!(session.starts_with("opqd1."));
        session
    }
    async fn plan(&self) -> Value {
        self.daemon
            .agent()
            .ok(
                "task_plan",
                json!({"manifest":manifest()}),
                Some(&self.session),
            )
            .await["task"]
            .clone()
    }
    fn start_task(&self, task: &Value) -> tokio::task::JoinHandle<Result<Value, String>> {
        let peer = self.daemon.agent();
        let session = self.session.clone();
        let id = task["id"].clone();
        tokio::spawn(async move {
            peer.call("task_run", json!({"task_id":id}), Some(&session))
                .await
        })
    }
    fn assert_bound_review(&self, review: &WorkstationReview, task: &Value) {
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
        for text in [
            "acme/synthetic",
            "CI_TOKEN",
            "vault:secret/data/synthetic?version=1#TOKEN",
            "env:OPAQUE_SYNTH_PAT",
        ] {
            assert!(review.review_text.contains(text));
        }
        for secret in [PAT, VAULT_TOKEN, SECRET] {
            assert!(!review.review_text.contains(secret));
        }
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
    async fn verify_receipt(&self, task: &Value) -> SignedWorkstationReceipt {
        let reference = &task["workstation_receipt"];
        let receipt = self
            .workstation
            .receipt(reference["approval_id"].as_str().unwrap())
            .await;
        assert_eq!(
            hex_sha(&serde_json::to_vec(&receipt).unwrap()),
            reference["sha256"].as_str().unwrap()
        );
        self.assert_bound_review(&receipt.review, task);
        assert_eq!(
            receipt.response.decision,
            opaque_core::workstation::WorkstationDecision::Approve
        );
        for secret in [PAT, VAULT_TOKEN, SECRET] {
            assert!(!task.to_string().contains(secret));
        }
        receipt
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.daemon.stop();
    }
}
fn hex_sha(bytes: &[u8]) -> String {
    opaque_core::workstation::hex(&Sha256::digest(bytes))
}
fn uncharged(task: &Value) {
    assert_eq!(task["state"], "partial");
    assert!(task["approved_at"].is_null());
    assert!(task["workstation_receipt"].is_null());
    assert!(task["approval_mode"].is_null());
    let slots = task["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0]["state"], "pending");
    for key in ["reserved_at", "request_id", "outcome", "finished_at"] {
        assert!(slots[0][key].is_null());
    }
}

#[tokio::test]
#[ignore = "requires Linux root; mandatory synthesized contained profile"]
#[allow(clippy::await_holding_lock)]
async fn synthesized_oidc_review_receipt_and_restart_preserve_authority() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut f = Fixture::new().await;
    let task = f.plan().await;
    let request = f.start_task(&task);
    let review = f.workstation.wait_review("github.publish_manifest").await;
    f.assert_bound_review(&review, &task);
    assert_eq!(f.providers.effects().await, (0, 0));
    f.workstation.respond(&review, true).await.unwrap();
    let response = request.await.unwrap().unwrap();
    assert!(response["error"].is_null());
    let completed = response["result"]["task"].clone();
    assert_eq!(completed["state"], "completed");
    assert_eq!(completed["approval_mode"], "insecure_test");
    assert_eq!(completed["slots"][0]["state"], "api_accepted");
    f.providers.verify_one_effect().await;
    let receipt = f.verify_receipt(&completed).await;
    assert_eq!(f.get(&task).await, completed);
    let list = f
        .daemon
        .agent()
        .ok("task_list", json!({}), Some(&f.session))
        .await;
    assert_eq!(
        list["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == task["id"])
            .unwrap(),
        &completed
    );
    assert!(f.workstation.respond(&review, true).await.is_err());
    assert!(
        f.daemon
            .agent()
            .call("task_run", json!({"task_id":task["id"]}), Some(&f.session))
            .await
            .unwrap()["error"]
            .is_object()
    );
    assert!(f.workstation.pending().await.is_empty());
    f.providers.verify_one_effect().await;

    let original_session = f.session.clone();
    let identity_counts = f.idp.counts();
    f.daemon.stop();
    f.daemon = f
        .layout
        .start(&env(&f.providers.github.uri(), &f.providers.vault.uri()));
    f.workstation
        .reconnect(&std::fs::read(f.layout.state.join("approval_server.cert")).unwrap());
    assert!(
        f.daemon
            .agent()
            .call(
                "task_get",
                json!({"task_id":task["id"]}),
                Some(&original_session)
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.daemon
            .human()
            .ok("agent_session_list", Value::Null, None)
            .await["count"],
        0
    );
    assert_eq!(
        f.daemon.human().ok("whoami", Value::Null, None).await["identity"]["principal_id"],
        f.requester
    );
    f.session = f.delegate().await;
    assert_ne!(f.session, original_session);
    assert_eq!(f.idp.counts(), identity_counts);
    let recovered = f.get(&task).await;
    assert_eq!(recovered, completed);
    assert_eq!(f.verify_receipt(&recovered).await, receipt);
    assert!(
        f.daemon
            .agent()
            .call("task_run", json!({"task_id":task["id"]}), Some(&f.session))
            .await
            .unwrap()["error"]
            .is_object()
    );
    assert!(f.workstation.pending().await.is_empty());
    f.providers.verify_one_effect().await;
}

#[tokio::test]
#[ignore = "requires Linux root; mandatory synthesized contained profile"]
#[allow(clippy::await_holding_lock)]
async fn synthesized_signed_rejection_leaves_task_uncharged() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new().await;
    let task = f.plan().await;
    let request = f.start_task(&task);
    let review = f.workstation.wait_review("github.publish_manifest").await;
    f.assert_bound_review(&review, &task);
    let mut substituted = review.clone();
    substituted.challenge.content_hash = "aa".repeat(32);
    assert!(f.workstation.respond(&substituted, true).await.is_err());
    assert_eq!(f.workstation.pending().await.len(), 1);
    assert_eq!(f.providers.effects().await, (0, 0));
    f.workstation.respond(&review, false).await.unwrap();
    assert!(request.await.unwrap().unwrap()["error"].is_object());
    uncharged(&f.get(&task).await);
    assert!(f.workstation.pending().await.is_empty());
    assert_eq!(f.providers.effects().await, (0, 0));
    assert!(
        f.daemon
            .agent()
            .call("task_run", json!({"task_id":task["id"]}), Some(&f.session))
            .await
            .unwrap()["error"]
            .is_object()
    );
    assert!(f.workstation.pending().await.is_empty());
    assert_eq!(f.providers.effects().await, (0, 0));
}

#[tokio::test]
#[ignore = "requires Linux root; mandatory synthesized contained profile"]
#[allow(clippy::await_holding_lock)]
async fn synthesized_review_timeout_rejects_late_signature_without_effects() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new().await;
    let task = f.plan().await;
    let request = f.start_task(&task);
    let review = f.workstation.wait_review("github.publish_manifest").await;
    f.assert_bound_review(&review, &task);
    let response = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response["error"]["code"], "task_unavailable");
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
    uncharged(&f.get(&task).await);
    assert!(f.workstation.pending().await.is_empty());
    assert_eq!(f.providers.effects().await, (0, 0));
    assert!(f.workstation.respond(&review, true).await.is_err());
    assert!(
        f.daemon
            .agent()
            .call("task_run", json!({"task_id":task["id"]}), Some(&f.session))
            .await
            .unwrap()["error"]
            .is_object()
    );
    assert!(f.workstation.pending().await.is_empty());
    assert_eq!(f.providers.effects().await, (0, 0));
}

#[tokio::test]
#[ignore = "requires Linux root; mandatory synthesized contained profile"]
#[allow(clippy::await_holding_lock)]
async fn synthesized_lifecycle_regrant_during_preparation_keeps_signed_task_charged_and_denied() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut f = Fixture::new().await;
    let fence = preparation_fence::PreparationFence::new(&f.providers.github.uri()).await;
    f.enable_lifecycle(fence.uri()).await;
    let task = f.plan().await;
    let old_session = f.session.clone();
    let request = f.start_task(&task);
    let review = f.workstation.wait_review("github.publish_manifest").await;
    f.assert_bound_review(&review, &task);
    assert_eq!(f.providers.effects().await, (0, 0));
    f.workstation.respond(&review, true).await.unwrap();
    fence.wait_for_preparation().await;
    let charged = f.get(&task).await;
    assert_eq!(charged["slots"][0]["state"], "reserved");
    assert!(charged["approved_at"].is_number());
    let receipt = f.verify_receipt(&charged).await;
    // Provider preparation reads the pinned source before the final write
    // authorization fence. This scenario proves zero GitHub writes, not zero reads.
    assert_eq!(f.providers.effects().await, (1, 0));
    let removed = f.lifecycle_batch(2, false);
    f.deliver_lifecycle(&removed).await;
    let restored = f.lifecycle_batch(3, true);
    let restoration = f.deliver_lifecycle(&restored).await;
    let old_access = f
        .daemon
        .agent()
        .call(
            "task_get",
            json!({"task_id":task["id"]}),
            Some(&old_session),
        )
        .await
        .expect("live broker transport should return a structured authorization denial");
    assert_eq!(old_access["error"]["code"], "delegation_invalid");
    assert!(old_access["result"].is_null());
    for secret in [PAT, VAULT_TOKEN, SECRET, LIFECYCLE_TOKEN] {
        assert!(!old_access.to_string().contains(secret));
    }
    assert_eq!(
        login(&f.daemon.human(), &f.idp, "requester").await["principal_id"],
        f.requester
    );
    f.session = f.delegate().await;
    fence.release();
    let response = request.await.unwrap().unwrap();
    assert!(response["error"].is_null());
    let denied = response["result"]["task"].clone();
    assert_eq!(denied["state"], "partial");
    assert_eq!(denied["slots"][0]["state"], "rejected");
    assert_eq!(
        denied["slots"][0]["request_id"],
        charged["slots"][0]["request_id"]
    );
    assert_eq!(
        denied["slots"][0]["reserved_at"],
        charged["slots"][0]["reserved_at"]
    );
    assert_eq!(
        denied["workstation_receipt"],
        charged["workstation_receipt"]
    );
    assert_eq!(f.providers.effects().await, (1, 0));

    let before_restart = f.session.clone();
    f.daemon.stop();
    f.daemon = f.layout.start(&env(fence.uri(), &f.providers.vault.uri()));
    f.workstation
        .reconnect(&std::fs::read(f.layout.state.join("approval_server.cert")).unwrap());
    assert!(
        f.daemon
            .agent()
            .call(
                "task_get",
                json!({"task_id":task["id"]}),
                Some(&before_restart)
            )
            .await
            .is_err()
    );
    assert!(
        f.daemon
            .agent()
            .call(
                "task_get",
                json!({"task_id":task["id"]}),
                Some(&old_session)
            )
            .await
            .is_err()
    );
    assert_eq!(f.deliver_lifecycle(&restored).await, restoration);
    assert!(
        opaque_core::identity_lifecycle::deliver(
            &f.layout.state.join("lifecycle.sock"),
            split_daemon::BROKER_UID,
            LIFECYCLE_TOKEN,
            &removed
        )
        .await
        .is_err()
    );
    f.session = f.delegate().await;
    let recovered = f.get(&task).await;
    assert_eq!(recovered, denied);
    assert_eq!(f.verify_receipt(&recovered).await, receipt);
    assert!(
        f.daemon
            .agent()
            .call("task_run", json!({"task_id":task["id"]}), Some(&f.session))
            .await
            .unwrap()["error"]
            .is_object()
    );
    assert!(f.workstation.pending().await.is_empty());
    assert_eq!(f.providers.effects().await, (1, 0));
}
