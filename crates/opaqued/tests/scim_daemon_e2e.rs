//! Real daemon SCIM ingress under sealed tenant custody. HTTP lifecycle tests
//! do not claim a distinct-UID client login or a production IdP pilot. The
//! signed OIDC callback lifecycle race is exercised in identity::scim::tests.
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

const TOKEN: &str = "scim_disposable_fixture_credential_not_for_production";
const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
struct Daemon {
    child: Child,
    config: PathBuf,
    home: PathBuf,
    log: PathBuf,
    base: String,
    _dir: tempfile::TempDir,
}
impl Daemon {
    async fn start(issuer: &str) -> Self {
        Self::start_with(issuer, "tenant-a", None).await
    }
    async fn start_with(issuer: &str, tenant: &str, fleet: Option<(&str, &str)>) -> Self {
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
        let token = state.join("scim.token");
        std::fs::write(&token, TOKEN).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let config = home.join("config.toml");
        let fleet_config = if let Some((url, token)) = fleet {
            let file = state.join("fleet.token");
            std::fs::write(&file, token).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            format!(
                "\n[fleet]\ncollector_url=\"{url}\"\ntoken_file=\"{}\"\ninterval_secs=1\n",
                file.display()
            )
        } else {
            String::new()
        };
        let body = format!(
            r#"require_seal=true
[identity]
issuer="{issuer}"
client_id="scim-fixture"
required=true
allowed_subjects=["alice","bob"]
[tenant]
id="{tenant}"
[scim]
listen="{address}"
token_file="{}"
[scim.group_roles]
reviewers=["approver","operator"]
[trust_domain]
enforce=true
allow_root=true
socket_group="{}"
socket_path="{}"
[attestation]
interval_secs=0
{fleet_config}
"#,
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
            base: format!("http://{address}/scim/v2/{tenant}"),
            _dir: dir,
        };
        daemon.ready().await;
        daemon
    }
    async fn ready(&mut self) {
        let client = reqwest::Client::new();
        for _ in 0..150 {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "daemon exited {status}: {}",
                    std::fs::read_to_string(&self.log).unwrap()
                );
            }
            if client
                .get(format!("{}/Users", self.base))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "SCIM startup timed out: {}",
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

#[tokio::test]
async fn real_daemon_scim_roles_deactivate_restart_and_replay() {
    let idp = wiremock::MockServer::start().await;
    // No external service is used. The configured issuer is a local mock.
    let mut daemon = Daemon::start(&idp.uri()).await;
    let client = reqwest::Client::new();
    let user =
        json!({"schemas":[USER],"externalId":"external-alice","userName":"alice","active":true});
    assert_eq!(
        client
            .get(format!("{}/Users", daemon.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(daemon.base.replace("tenant-a", "tenant-b") + "/Users")
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let created = client
        .post(format!("{}/Users", daemon.base))
        .bearer_auth(TOKEN)
        .header("Idempotency-Key", "create-user")
        .json(&user)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let etag = created.headers()["etag"].to_str().unwrap().to_owned();
    let created: Value = created.json().await.unwrap();
    let id = created["id"].as_str().unwrap();
    let group = json!({"schemas":[GROUP],"externalId":"reviewers","displayName":"Untrusted group label","members":[{"value":id}]});
    assert_eq!(
        client
            .post(format!("{}/Groups", daemon.base))
            .bearer_auth(TOKEN)
            .header("Idempotency-Key", "group")
            .json(&group)
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let db = rusqlite::Connection::open_with_flags(
        daemon.home.join(".opaque/identity.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let roles: String = db
        .query_row("SELECT roles FROM principals WHERE sub='alice'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(roles.contains("approver"));
    let mut inactive = user.clone();
    inactive["active"] = json!(false);
    let response = client
        .put(format!("{}/Users/{id}", daemon.base))
        .bearer_auth(TOKEN)
        .header("Idempotency-Key", "deactivate")
        .header("If-Match", &etag)
        .json(&inactive)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let disabled: bool = db
        .query_row(
            "SELECT disabled FROM principals WHERE sub='alice'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(disabled);
    assert_eq!(
        client
            .put(format!("{}/Users/{id}", daemon.base))
            .bearer_auth(TOKEN)
            .header("Idempotency-Key", "stale-restore")
            .header("If-Match", &etag)
            .json(&user)
            .send()
            .await
            .unwrap()
            .status(),
        412
    );
    daemon.restart().await;
    assert_eq!(
        client
            .post(format!("{}/Users", daemon.base))
            .bearer_auth(TOKEN)
            .header("Idempotency-Key", "create-user")
            .json(&user)
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let current: Value = client
        .get(format!("{}/Users/{id}", daemon.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(current["active"], false);
    let events: i64 = db
        .query_row("SELECT COUNT(*) FROM scim_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(events, 3, "replay has no additional mutation");
}

#[tokio::test]
async fn two_real_daemons_report_enrolled_tenant_inventory_and_revocation() {
    use opaque_core::tenant::TenantBinding;
    use opaque_federation_runtime::fleet::{
        CollectorConfig, Enrollment, FleetStore, TenantCredentials, serve_listener,
    };
    use std::{collections::BTreeMap, sync::Arc};
    let temp = tempfile::tempdir().unwrap();
    let store_dir = temp.path().join("collector");
    let store = Arc::new(FleetStore::open(&store_dir).unwrap());
    let mut tenants = BTreeMap::new();
    for tenant in ["tenant-a", "tenant-b"] {
        let reader = temp.path().join(format!("{tenant}-reader"));
        let report = temp.path().join(format!("{tenant}-report"));
        for (path, role) in [(&reader, "reader"), (&report, "reporter")] {
            std::fs::write(
                path,
                format!("{tenant}_{role}_synthetic_fixture_credential_123456"),
            )
            .unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        tenants.insert(
            tenant.to_string(),
            TenantCredentials {
                read_token_file: reader,
                report_token_file: report,
            },
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}/");
    let config = CollectorConfig {
        listen: address,
        tenants,
        fresh_secs: 5,
        offline_secs: 10,
    };
    let collector = store.clone();
    let server =
        tokio::spawn(async move { serve_listener(collector, config, listener).await.unwrap() });
    let idp = wiremock::MockServer::start().await;
    let a = Daemon::start_with(
        &idp.uri(),
        "tenant-a",
        Some((
            &url,
            "tenant-a_reporter_synthetic_fixture_credential_123456",
        )),
    )
    .await;
    let mut b = Daemon::start_with(
        &idp.uri(),
        "tenant-b",
        Some((
            &url,
            "tenant-b_reporter_synthetic_fixture_credential_123456",
        )),
    )
    .await;
    let mut bindings = Vec::new();
    for daemon in [&a, &b] {
        let state = daemon.home.join(".opaque");
        let binding: TenantBinding =
            serde_json::from_slice(&std::fs::read(state.join("tenant.binding.json")).unwrap())
                .unwrap();
        let key = opaque_federation_runtime::attest::load_or_create_key_in(&state)
            .unwrap()
            .verifying_key();
        store
            .enroll(
                &Enrollment {
                    binding: binding.clone(),
                    public_key: key.to_bytes().iter().map(|b| format!("{b:02x}")).collect(),
                    expected_policy_version: None,
                    expected_policy_digest: None,
                },
                false,
                opaque_core::identity::now_unix(),
            )
            .unwrap();
        bindings.push(binding);
    }
    for _ in 0..100 {
        if ["tenant-a", "tenant-b"].iter().all(|tenant| {
            store
                .inventory(tenant, opaque_core::identity::now_unix(), 5, 10)
                .unwrap()["brokers"][0]["status"]
                == "fresh"
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for tenant in ["tenant-a", "tenant-b"] {
        let view = store
            .inventory(tenant, opaque_core::identity::now_unix(), 5, 10)
            .unwrap();
        assert_eq!(view["brokers"][0]["status"], "fresh", "{}", view);
        assert!(
            view["brokers"][0]["acknowledged_evidence_sequence"]
                .as_u64()
                .is_some()
        );
    }
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{url}v1/tenants/tenant-b/brokers"))
            .bearer_auth("tenant-a_reader_synthetic_fixture_credential_123456")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    store
        .revoke(&bindings[0], opaque_core::identity::now_unix())
        .unwrap();
    assert_eq!(
        store
            .inventory("tenant-a", opaque_core::identity::now_unix(), 5, 10)
            .unwrap()["brokers"][0]["status"],
        "revoked"
    );
    b.child.kill().unwrap();
    b.child.wait().unwrap();
    let offline = store
        .inventory("tenant-b", opaque_core::identity::now_unix() + 11, 5, 10)
        .unwrap();
    assert_eq!(offline["brokers"][0]["status"], "offline");
    assert!(offline["brokers"][0]["current_posture"].is_null());
    server.abort();
}

fn write_local_seal(home: &Path, body: &str) {
    let path = home.join("config.seal");
    let key = opaque_core::seal::load_or_create_seal_key(&path).unwrap();
    let seal = opaque_core::seal::compute_seal_keyed(body.as_bytes(), &key);
    std::fs::write(&path, seal).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn persisted_scim_cannot_be_removed_with_identity_or_optional_invalid_config() {
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
            document.remove("scim");
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
        assert!(log.contains("persisted SCIM lifecycle"), "{log}");
    }
}
