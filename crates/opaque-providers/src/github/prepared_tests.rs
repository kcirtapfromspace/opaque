use super::*;
use base64::Engine as _;
use opaque_core::audit::InMemoryAuditEmitter;
use opaque_core::operation::{ClientIdentity, ClientType};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn request(operation: &str, params: serde_json::Value) -> OperationRequest {
    OperationRequest {
        principal: None,
        request_id: uuid::Uuid::new_v4(),
        client_identity: ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        },
        client_type: ClientType::Human,
        operation: operation.into(),
        target: Default::default(),
        secret_ref_names: vec![],
        created_at: std::time::SystemTime::now(),
        expires_at: None,
        params,
        workspace: None,
    }
}

#[tokio::test]
async fn every_generic_operation_prepares_actual_scope_without_provider_or_credentials() {
    let server = MockServer::start().await;
    let audit = Arc::new(InMemoryAuditEmitter::new());
    let handler =
        GitHubHandler::with_client(audit.clone(), GitHubClient::with_base_url(server.uri()));
    for (operation, params, scope, kind) in [
        (
            "github.set_actions_secret",
            json!({"repo":"acme/app", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "environment":"production"}),
            "actions",
            "environment",
        ),
        (
            "github.set_codespaces_secret",
            json!({"secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "selected_repository_ids":[12,3,12]}),
            "codespaces",
            "user",
        ),
        (
            "github.set_dependabot_secret",
            json!({"repo":"acme/app", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED"}),
            "dependabot",
            "repository",
        ),
        (
            "github.set_org_secret",
            json!({"org":"acme", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "visibility":null}),
            "org",
            "organization",
        ),
        (
            "github.list_secrets",
            json!({"repo":"acme/app", "scope":null, "environment":null}),
            "actions",
            "repository",
        ),
        (
            "github.delete_secret",
            json!({"repo":"acme/app", "secret_name":"TOKEN", "environment":"production"}),
            "actions",
            "environment",
        ),
    ] {
        let mut request = request(operation, params);
        request.params["github_token_ref"] = "env:UNRESOLVED_TOKEN".into();
        let prepared = handler.prepare(&request).unwrap();
        assert_eq!(prepared.target()["scope"], scope);
        assert_eq!(prepared.target()["scope_kind"], kind);
        assert_eq!(prepared.target()["github_api_url"], server.uri());
        assert!(
            prepared
                .secret_ref_names()
                .contains(&"env:UNRESOLVED_TOKEN".into())
        );
        if operation == "github.set_codespaces_secret" {
            assert_eq!(prepared.target()["selected_repository_ids"], "[3,12]");
        }
        if operation == "github.set_org_secret" {
            assert_eq!(prepared.target()["visibility"], "private");
            assert!(!prepared.target().contains_key("selected_repository_ids"));
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(audit.events().is_empty());
}

#[tokio::test]
async fn malformed_or_competing_actions_fail_before_resolution_and_network() {
    let server = MockServer::start().await;
    let audit = Arc::new(InMemoryAuditEmitter::new());
    let handler =
        GitHubHandler::with_client(audit.clone(), GitHubClient::with_base_url(server.uri()));
    let set = json!({"repo":"acme/app", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "github_token_ref":"env:UNRESOLVED_TOKEN"});
    for (field, value) in [
        ("environment", json!(17)),
        ("org", json!("other-org")),
        ("repo", json!("acme/../other")),
        ("repo", json!("acme/app?redirect=other")),
        ("repo", json!("acme/..")),
        ("environment", json!("..")),
        ("github_token_ref", json!(false)),
        ("value_ref", json!({})),
        ("scope", json!("org")),
        ("unexpected", json!(true)),
    ] {
        let mut params = set.clone();
        params[field] = value;
        let error = handler
            .execute(&request("github.set_actions_secret", params))
            .await
            .expect_err("malformed action must fail");
        assert!(
            !error.contains("failed to resolve"),
            "{field} reached credential resolution: {error}"
        );
    }
    for params in [
        json!({"scope":"org", "org":"acme", "repo":"acme/app"}),
        json!({"scope":"codespaces", "environment":"production"}),
        json!({"scope":"dependabot", "repo":"acme/app", "environment":"production"}),
        json!({"scope":"actions", "repo":"acme/app", "org":"acme"}),
        json!({"scope":false, "repo":"acme/app"}),
    ] {
        assert!(
            handler
                .prepare(&request("github.list_secrets", params))
                .is_err()
        );
    }
    for params in [
        json!({"org":"acme", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "visibility":"all", "selected_repository_ids":[1]}),
        json!({"org":"acme", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "visibility":"selected", "selected_repository_ids":[1,"2"]}),
        json!({"org":"acme", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "visibility":"selected", "selected_repository_ids":[0]}),
        json!({"org":"acme", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "visibility":false}),
        json!({"org":"acme", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "visibility":"selected"}),
    ] {
        assert!(
            handler
                .prepare(&request("github.set_org_secret", params))
                .is_err()
        );
    }
    assert!(handler.prepare(&request("github.set_codespaces_secret", json!({"repo":"acme/app", "secret_name":"TOKEN", "value_ref":"env:UNRESOLVED", "selected_repository_ids":[1]}))).is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(audit.events().is_empty());
}

#[test]
fn omitted_codespaces_audience_is_distinct_from_explicit_empty_audience() {
    let handler = GitHubHandler::new(Arc::new(InMemoryAuditEmitter::new())).unwrap();
    let mut request = request(
        "github.set_codespaces_secret",
        json!({
            "secret_name":"TOKEN", "value_ref":"env:VALUE", "github_token_ref":"env:TOKEN",
        }),
    );
    let omitted = handler.prepare(&request).unwrap();
    assert_eq!(
        omitted.target()["selected_repository_ids"],
        "preserve_or_provider_default"
    );
    assert!(
        omitted.params()["effect"]["audience"]
            .get("selected_repository_ids")
            .is_none()
    );
    request.params["selected_repository_ids"] = json!([]);
    let explicit = handler.prepare(&request).unwrap();
    assert_eq!(explicit.target()["selected_repository_ids"], "[]");
    assert_ne!(omitted.params(), explicit.params());
}

struct EnvRestore(Vec<(String, Option<std::ffi::OsString>)>);
impl EnvRestore {
    fn set(&mut self, key: &str, value: &str) {
        self.0.push((key.into(), std::env::var_os(key)));
        unsafe {
            std::env::set_var(key, value);
        }
    }
}
impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, previous) in self.0.drain(..).rev() {
            unsafe {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

#[tokio::test]
async fn prepared_execution_freezes_destination_audience_and_environment_token_reference() {
    let _lock = TEST_ENV_LOCK.lock().await;
    let server = MockServer::start().await;
    let audit = Arc::new(InMemoryAuditEmitter::new());
    let handler =
        GitHubHandler::with_client(audit.clone(), GitHubClient::with_base_url(server.uri()));
    let mut env = EnvRestore(vec![]);
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let token_var = format!("OPAQUE_PREPARED_GITHUB_TOKEN_{suffix}");
    let value_var = format!("OPAQUE_PREPARED_GITHUB_VALUE_{suffix}");
    env.set(&token_var, "synthetic-github-token");
    env.set(&value_var, "synthetic-secret-value");
    env.set(GITHUB_TOKEN_REF_ENV, &format!("env:{token_var}"));
    let key = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
    let public_key = base64::engine::general_purpose::STANDARD.encode(key.public_key().as_bytes());
    Mock::given(method("GET"))
        .and(path("/orgs/acme/actions/secrets/public-key"))
        .and(header("authorization", "Bearer synthetic-github-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"key_id":"fixture-key", "key":public_key})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/orgs/acme/actions/secrets/TOKEN"))
        .and(header("authorization", "Bearer synthetic-github-token"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    let mut request = request(
        "github.set_org_secret",
        json!({
            "org":"acme", "secret_name":"TOKEN", "value_ref":format!("env:{value_var}"),
            "visibility":"selected", "selected_repository_ids":[12,3,12],
        }),
    );
    let prepared = handler.prepare(&request).unwrap();
    assert_eq!(prepared.target()["org"], "acme");
    assert_eq!(prepared.target()["visibility"], "selected");
    assert_eq!(prepared.target()["selected_repository_ids"], "[3,12]");
    assert!(audit.events().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
    request.params["org"] = "unapproved".into();
    request.params["visibility"] = "all".into();
    env.set(GITHUB_TOKEN_REF_ENV, "env:UNAPPROVED_TOKEN");
    let result = prepared.execute().await.unwrap();
    assert_eq!(result["org"], "acme");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let payload: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(payload["visibility"], "selected");
    assert_eq!(payload["selected_repository_ids"], json!([3, 12]));
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(payload["encrypted_value"].as_str().unwrap())
        .unwrap();
    assert_eq!(key.unseal(&ciphertext).unwrap(), b"synthetic-secret-value");
    assert!(!result.to_string().contains("synthetic-secret-value"));
}
