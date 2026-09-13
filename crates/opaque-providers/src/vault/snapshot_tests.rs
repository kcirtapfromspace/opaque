use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const USER_REF: &str = "vault:database/creds/coherent#username";
const PASSWORD_REF: &str = "vault:database/creds/coherent#password";
const TOKEN_ENV: &str = "OPAQUE_VAULT_SNAPSHOT_FIXTURE_TOKEN";

async fn rotating_server(ttl: u64, renewable: bool) -> (MockServer, Arc<AtomicUsize>) {
    let server = MockServer::start().await;
    let count = Arc::new(AtomicUsize::new(0));
    let sequence = count.clone();
    Mock::given(method("GET")).and(path("/v1/database/creds/coherent"))
        .respond_with(move |_: &wiremock::Request| {
            let i=sequence.fetch_add(1, Ordering::SeqCst)+1;
            ResponseTemplate::new(200).set_delay(Duration::from_millis(25)).set_body_json(serde_json::json!({
                "lease_id":format!("database/creds/coherent/{i}"),"lease_duration":ttl,"renewable":renewable,
                "data":{"username":format!("user-{i}"),"password":format!("password-{i}")}
            }))
        }).mount(&server).await;
    (server, count)
}

fn resolver(server: &MockServer) -> VaultResolver {
    unsafe {
        std::env::set_var(TOKEN_ENV, "synthetic-token-one");
    }
    VaultResolver::with_token_ref(
        VaultClient::with_base_url(server.uri()),
        format!("env:{TOKEN_ENV}"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_fields_and_independent_resolvers_share_one_issuance() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(120, false).await;
    let first = Arc::new(resolver(&server));
    let second = Arc::new(resolver(&server));
    let barrier = Arc::new(tokio::sync::Barrier::new(24));
    let mut tasks = Vec::new();
    for i in 0..24 {
        let resolver = if i % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let reference = if i % 2 == 0 { USER_REF } else { PASSWORD_REF };
            let value = resolver.resolve(reference).unwrap();
            assert_eq!(
                value.as_str(),
                Some(if i % 2 == 0 { "user-1" } else { "password-1" })
            );
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_preserves_original_order_duplicates_and_complete_dynamic_pair() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(120, false).await;
    let resolver = resolver(&server);
    let values = resolver
        .resolve_batch(&[PASSWORD_REF, USER_REF, PASSWORD_REF])
        .unwrap();
    assert_eq!(
        values
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        ["password-1", "user-1", "password-1"]
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(resolver.resolve_batch(&[]).unwrap().is_empty());
    assert!(
        resolver
            .resolve_batch(&[USER_REF, "vault:../bad#field"])
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn token_rotation_cannot_reuse_another_tokens_dynamic_credential() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(120, false).await;
    let resolver = resolver(&server);
    assert_eq!(resolver.resolve(USER_REF).unwrap().as_str(), Some("user-1"));
    unsafe {
        std::env::set_var(TOKEN_ENV, "synthetic-token-two");
    }
    let values = resolver.resolve_batch(&[USER_REF, PASSWORD_REF]).unwrap();
    assert_eq!(values[0].as_str(), Some("user-2"));
    assert_eq!(values[1].as_str(), Some("password-2"));
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_expiry_refresh_issues_one_replacement_pair() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(1, false).await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/leases/revoke"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let resolver = Arc::new(resolver(&server));
    resolver.resolve(USER_REF).unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            let values = resolver.resolve_batch(&[USER_REF, PASSWORD_REF]).unwrap();
            assert_eq!(values[0].as_str(), Some("user-2"));
            assert_eq!(values[1].as_str(), Some("password-2"));
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_fails_wholly_if_lease_expires_during_other_secret_resolution() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(1, false).await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(1100))
                .set_body_json(serde_json::json!({"data":{"field":"static-fixture"}})),
        )
        .mount(&server)
        .await;
    let resolver = resolver(&server);
    let error = resolver
        .resolve_batch(&[USER_REF, "vault:secret/slow#field", PASSWORD_REF])
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("expired while resolving execution snapshot")
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "must not silently reissue just the password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_renewal_rejection_does_not_return_cached_secret() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(20, true).await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    let resolver = resolver(&server);
    resolver.resolve(USER_REF).unwrap();
    assert!(
        resolver
            .resolve(PASSWORD_REF)
            .unwrap_err()
            .to_string()
            .contains("authentication failed")
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_field_does_not_issue_a_second_dynamic_credential() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(120, false).await;
    let resolver = resolver(&server);
    resolver.resolve(USER_REF).unwrap();
    assert!(
        resolver
            .resolve("vault:database/creds/coherent#absent")
            .is_err()
    );
    assert_eq!(
        resolver.resolve(PASSWORD_REF).unwrap().as_str(),
        Some("password-1")
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires explicitly configured disposable live Vault database role"]
async fn live_dynamic_fields_share_one_real_lease() {
    assert_eq!(
        std::env::var("OPAQUE_VAULT_LIVE_ACCEPTANCE").as_deref(),
        Ok("1")
    );
    let role = std::env::var("OPAQUE_VAULT_LIVE_ROLE_PATH")
        .expect("disposable database/creds role required");
    assert!(role.starts_with("database/creds/"));
    // Dedicated token ref must be supplied explicitly; never default to Keychain.
    let token_ref =
        std::env::var("OPAQUE_VAULT_LIVE_TOKEN_REF").expect("dedicated test token ref required");
    assert!(token_ref.starts_with("env:"));
    std::env::var(super::super::client::VAULT_URL_ENV).expect("explicit live Vault URL required");
    let psql = std::env::var("OPAQUE_VAULT_LIVE_PSQL_PATH")
        .expect("absolute psql path required to validate the credential pair");
    assert!(std::path::Path::new(&psql).is_absolute());
    let database_host =
        std::env::var("OPAQUE_VAULT_LIVE_PGHOST").expect("disposable database host required");
    let database_name =
        std::env::var("OPAQUE_VAULT_LIVE_PGDATABASE").expect("disposable database name required");
    let database_port = std::env::var("OPAQUE_VAULT_LIVE_PGPORT").unwrap_or_else(|_| "5432".into());
    let resolver = VaultResolver::with_token_ref(VaultClient::new().unwrap(), token_ref);
    let values = resolver
        .resolve_batch(&[
            &format!("vault:{role}#username"),
            &format!("vault:{role}#password"),
        ])
        .unwrap();
    assert!(!values[0].as_bytes().is_empty());
    assert!(!values[1].as_bytes().is_empty());
    let lease_id = {
        let cache = VaultResolver::lock_cache();
        let slots = cache
            .iter()
            .filter(|(key, _)| key.path == role)
            .collect::<Vec<_>>();
        assert_eq!(slots.len(), 1);
        slots[0]
            .1
            .try_lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .lease
            .lease_id
            .clone()
    };
    let mut command = tokio::process::Command::new(psql);
    command
        .env_clear()
        .env("PGHOST", database_host)
        .env("PGPORT", database_port)
        .env("PGDATABASE", database_name)
        .env("PGUSER", values[0].as_str().unwrap())
        .env("PGPASSWORD", values[1].as_str().unwrap())
        .env("PGCONNECT_TIMEOUT", "10")
        .args(["--no-password", "--no-psqlrc", "--command", "SELECT 1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let result = tokio::time::timeout(Duration::from_secs(20), command.status()).await;
    let token = BaseResolver::new().resolve(&resolver.token_ref).unwrap();
    resolver
        .client
        .revoke_lease(token.as_str().unwrap(), &lease_id)
        .await
        .expect("live test lease cleanup failed");
    assert!(
        result
            .expect("database login timed out")
            .expect("psql could not start")
            .success(),
        "issued username/password pair could not authenticate to the disposable database"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_issuance_lifetimes_fail_without_panicking_or_returning_credentials() {
    let _guard = super::tests::test_lock().await;
    for ttl in [0, u64::MAX] {
        VaultResolver::clear_cache_for_tests();
        let (server, count) = rotating_server(ttl, false).await;
        assert!(
            resolver(&server)
                .resolve_batch(&[USER_REF, PASSWORD_REF])
                .is_err()
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_renewal_cannot_silently_extend_or_reuse_a_credential() {
    let _guard = super::tests::test_lock().await;
    for (id, ttl) in [("database/creds/coherent/1", 0), ("other-lease", 120)] {
        VaultResolver::clear_cache_for_tests();
        let (server, count) = rotating_server(20, true).await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id":id, "lease_duration":ttl, "renewable":true
            })))
            .expect(1)
            .mount(&server)
            .await;
        let resolver = resolver(&server);
        resolver.resolve(USER_REF).unwrap();
        assert!(
            resolver
                .resolve(PASSWORD_REF)
                .unwrap_err()
                .to_string()
                .contains("invalid lease metadata")
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_near_expiry_reads_share_one_renewal() {
    let _guard = super::tests::test_lock().await;
    VaultResolver::clear_cache_for_tests();
    let (server, count) = rotating_server(20, true).await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(25))
                .set_body_json(serde_json::json!({
                    "lease_id":"database/creds/coherent/1", "lease_duration":120, "renewable":true
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let resolver = Arc::new(resolver(&server));
    resolver.resolve(USER_REF).unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            let pair = resolver.resolve_batch(&[USER_REF, PASSWORD_REF]).unwrap();
            assert_eq!(pair[0].as_str(), Some("user-1"));
            assert_eq!(pair[1].as_str(), Some("password-1"));
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn unversioned_kv_v1_scalar_siblings_survive_a_nested_data_key() {
    let _guard = super::tests::test_lock().await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/document"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data":{"TOKEN":"direct-token", "data":{"OTHER":"nested-field"}}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let values = resolver(&server)
        .resolve_batch(&["vault:secret/document#TOKEN", "vault:secret/document#OTHER"])
        .unwrap();
    assert_eq!(values[0].as_str(), Some("direct-token"));
    assert_eq!(values[1].as_str(), Some("nested-field"));
}
