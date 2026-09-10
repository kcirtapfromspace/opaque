//! Real neutral lifecycle ingress under sealed tenant custody. No external IdP
//! or shared Keychain writes; private SCIM adapter behavior is tested separately.
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

const TOKEN: &str = "scim_disposable_fixture_credential_not_for_production";
struct Daemon {
    child: Child,
    config: PathBuf,
    home: PathBuf,
    log: PathBuf,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}
impl Daemon {
    async fn start(issuer: &str) -> Self {
        Self::start_with(issuer, "tenant-a").await
    }
    async fn start_with(issuer: &str, tenant: &str) -> Self {
        let root = Path::new("/tmp").canonicalize().unwrap();
        let dir = tempfile::Builder::new()
            .prefix("oqscim-")
            .tempdir_in(root)
            .unwrap();
        let home = dir.path().join("home");
        let state = home.join(".opaque");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Provision the immutable tenant boundary before adding its ingress
        // credential; startup refuses preexisting unbound state by design.
        drop(
            opaque_tenant::tenant::TenantBoundary::open(
                &opaque_tenant::tenant::TenantConfig {
                    id: opaque_core::tenant::TenantId::parse(tenant).unwrap(),
                },
                &state,
                true,
            )
            .unwrap(),
        );
        let token = state.join("identity-lifecycle.token");
        std::fs::write(&token, TOKEN).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let socket = dir.path().join("lifecycle.sock");
        let config = home.join("config.toml");
        let body = format!(
            r#"require_seal=true
[identity]
issuer="{issuer}"
client_id="scim-fixture"
required=true
allowed_subjects=["alice","bob"]
[tenant]
id="{tenant}"
[lifecycle]
socket_path="{}"
allowed_adapter_uids=[{}]
token_file="{}"
[lifecycle.group_roles]
reviewers=["approver","operator"]
[trust_domain]
enforce=true
allow_root=true
socket_group="{}"
socket_path="{}"
[attestation]
interval_secs=0
"#,
            socket.display(),
            unsafe { libc::geteuid() },
            token.display(),
            unsafe { libc::getegid() },
            dir.path().join("opaqued.sock").display()
        );
        std::fs::write(&config, &body).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_local_seal(&home, &body);
        let log = dir.path().join("daemon.log");
        let child = spawn(&config, &home, &log);
        let mut daemon = Self {
            child,
            config,
            home,
            log,
            socket,
            _dir: dir,
        };
        daemon.ready().await;
        daemon
    }
    async fn ready(&mut self) {
        for _ in 0..150 {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "daemon exited {status}: {}",
                    std::fs::read_to_string(&self.log).unwrap()
                );
            }
            if tokio::net::UnixStream::connect(&self.socket).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "Lifecycle startup timed out: {}",
            std::fs::read_to_string(&self.log).unwrap()
        );
    }
    async fn restart(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.child = spawn(&self.config, &self.home, &self.log);
        self.ready().await;
    }
}
fn spawn(config: &Path, home: &Path, log: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_opaqued"))
        .env("HOME", home)
        .env("OPAQUE_CONFIG", config)
        .env_remove("OPAQUE_SOCK")
        .env_remove("OPAQUE_INSECURE_AUTO_APPROVE")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(log).unwrap())
        .spawn()
        .unwrap()
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_local_seal(home: &Path, body: &str) {
    let path = home.join("config.seal");
    let key = opaque_core::seal::load_or_create_seal_key(&path).unwrap();
    let seal = opaque_core::seal::compute_seal_keyed(body.as_bytes(), &key);
    std::fs::write(&path, seal).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn persisted_lifecycle_cannot_be_removed_with_identity_or_optional_invalid_config() {
    let idp = wiremock::MockServer::start().await;
    let mut daemon = Daemon::start(&idp.uri()).await;
    daemon.child.kill().unwrap();
    daemon.child.wait().unwrap();
    let original = std::fs::read_to_string(&daemon.config).unwrap();
    for optional_invalid in [false, true] {
        let mut document = original.parse::<toml_edit::DocumentMut>().unwrap();
        if optional_invalid {
            document["identity"]["required"] = toml_edit::value(false);
            document["identity"]["issuer"] = toml_edit::value("invalid-issuer");
        } else {
            document.remove("identity");
            document.remove("lifecycle");
        }
        let body = document.to_string();
        std::fs::write(&daemon.config, &body).unwrap();
        write_local_seal(&daemon.home, &body);
        daemon.child = spawn(&daemon.config, &daemon.home, &daemon.log);
        let mut failed = false;
        for _ in 0..100 {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                assert!(!status.success());
                failed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(failed, "downgraded daemon should refuse startup");
        let log = std::fs::read_to_string(&daemon.log).unwrap();
        assert!(log.contains("persisted managed lifecycle"), "{log}");
    }
}
#[tokio::test]
async fn scoped_neutral_ingress_rejects_auth_scope_and_replay_across_restart() {
    let idp = wiremock::MockServer::start().await;
    let mut daemon = Daemon::start(&idp.uri()).await;
    let binding: Value = serde_json::from_slice(
        &std::fs::read(daemon.home.join(".opaque/tenant.binding.json")).unwrap(),
    )
    .unwrap();
    let mut batch = json!({"schema_version":1,"binding":binding,"issuer":idp.uri(),"revision":1,"updates":[{"subject":"alice","active":true,"deleted":false,"groups":["reviewers"]}],"suspend":false});
    async fn send(
        socket: &Path,
        token: &str,
        batch: &Value,
    ) -> Result<opaque_core::identity_lifecycle::LifecycleReceipt, String> {
        opaque_core::identity_lifecycle::deliver(
            socket,
            unsafe { libc::geteuid() },
            token,
            &serde_json::from_value(batch.clone()).unwrap(),
        )
        .await
    }
    assert!(
        send(
            &daemon.socket,
            "wrong_fixture_credential_with_sufficient_length",
            &batch
        )
        .await
        .unwrap_err()
        .contains("credential")
    );
    let mut wrong = batch.clone();
    wrong["issuer"] = json!("https://wrong.example");
    assert!(send(&daemon.socket, TOKEN, &wrong).await.is_err());
    wrong = batch.clone();
    wrong["updates"][0]["subject"] = json!("unadmitted");
    assert!(send(&daemon.socket, TOKEN, &wrong).await.is_err());
    let receipt = send(&daemon.socket, TOKEN, &batch).await.unwrap();
    daemon.restart().await;
    assert_eq!(receipt, send(&daemon.socket, TOKEN, &batch).await.unwrap());
    batch["updates"][0]["active"] = json!(false);
    assert!(send(&daemon.socket, TOKEN, &batch).await.is_err());
    batch["revision"] = json!(2);
    assert!(send(&daemon.socket, TOKEN, &batch).await.is_ok());
    let db = rusqlite::Connection::open_with_flags(
        daemon.home.join(".opaque/identity.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let disabled: bool = db
        .query_row(
            "SELECT disabled FROM principals WHERE sub='alice'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(disabled);
}
#[tokio::test]
async fn legacy_adapter_config_cannot_silently_enable_unmanaged_identity_on_fresh_state() {
    let idp = wiremock::MockServer::start().await;
    let mut daemon = Daemon::start(&idp.uri()).await;
    daemon.child.kill().unwrap();
    daemon.child.wait().unwrap();
    // This is disposable fixture state only: reproduce a first boot with an
    // operator's old configuration and no existing managed identity database.
    std::fs::remove_file(daemon.home.join(".opaque/identity.db")).unwrap();
    let text = std::fs::read_to_string(&daemon.config).unwrap();
    let mut doc = text.parse::<toml_edit::DocumentMut>().unwrap();
    let legacy = doc.remove("lifecycle").unwrap();
    doc["scim"] = legacy;
    let text = doc.to_string();
    std::fs::write(&daemon.config, &text).unwrap();
    write_local_seal(&daemon.home, &text);
    daemon.child = spawn(&daemon.config, &daemon.home, &daemon.log);
    for _ in 0..100 {
        if let Some(status) = daemon.child.try_wait().unwrap() {
            assert!(!status.success());
            let log = std::fs::read_to_string(&daemon.log).unwrap();
            assert!(log.to_ascii_lowercase().contains("scim"), "{log}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("old adapter config must refuse startup before unmanaged identity can run");
}

#[tokio::test]
async fn disallowed_adapter_uid_and_oversized_frames_never_mutate_authority() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let idp = wiremock::MockServer::start().await;
    let mut daemon = Daemon::start(&idp.uri()).await;
    let mut stream = tokio::net::UnixStream::connect(&daemon.socket)
        .await
        .unwrap();
    stream
        .write_u32((opaque_core::identity_lifecycle::MAX_REQUEST_BYTES + 1) as u32)
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.is_empty());
    let mut document = std::fs::read_to_string(&daemon.config)
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let mut uids = toml_edit::Array::new();
    uids.push(i64::from(unsafe { libc::geteuid() }.wrapping_add(1)));
    document["lifecycle"]["allowed_adapter_uids"] = toml_edit::value(uids);
    let body = document.to_string();
    std::fs::write(&daemon.config, &body).unwrap();
    write_local_seal(&daemon.home, &body);
    daemon.restart().await;
    let binding = serde_json::from_slice(
        &std::fs::read(daemon.home.join(".opaque/tenant.binding.json")).unwrap(),
    )
    .unwrap();
    let batch = opaque_core::identity_lifecycle::LifecycleBatch {
        schema_version: 1,
        binding,
        issuer: idp.uri(),
        revision: 1,
        updates: vec![],
        suspend: true,
    };
    assert!(
        opaque_core::identity_lifecycle::deliver(
            &daemon.socket,
            unsafe { libc::geteuid() },
            TOKEN,
            &batch
        )
        .await
        .is_err()
    );
    let db = rusqlite::Connection::open_with_flags(
        daemon.home.join(".opaque/identity.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT source_revision FROM lifecycle_config", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
