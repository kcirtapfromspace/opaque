use super::*;
use opaque_core::audit::InMemoryAuditEmitter;
use opaque_core::operation::{ClientIdentity, ClientType};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};
fn request(operation: &str, params: serde_json::Value) -> OperationRequest {
    OperationRequest {
        principal: None,
        request_id: uuid::Uuid::new_v4(),
        client_identity: ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(123),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        },
        client_type: ClientType::Agent,
        operation: operation.into(),
        target: HashMap::from([("project".into(), "caller-lie".into())]),
        secret_ref_names: vec!["env:CALLER_LIE".into()],
        created_at: std::time::SystemTime::now(),
        expires_at: None,
        params,
        workspace: None,
    }
}
fn handler(base: &str, credential_ref: &str) -> GcpHandler {
    GcpHandler::from_client(
        Arc::new(InMemoryAuditEmitter::new()),
        GcpSecretManagerClient::with_auth(
            base,
            client::AuthBinding::AccessToken {
                credential_ref: credential_ref.into(),
            },
        )
        .unwrap(),
    )
}
#[test]
fn preparation_binds_endpoint_refs_and_exact_target_without_resolving() {
    let handler = handler(
        "https://secretmanager.googleapis.com/v1",
        "env:OPAQUE_GCP_PREPARE_MISSING_TOKEN",
    );
    let mut raw = request(
        "gcp.add_secret_version",
        json!({"project":"123456789012","secret_id":"deploy-token","value_ref":"env:OPAQUE_GCP_PREPARE_MISSING_VALUE"}),
    );
    let prepared = handler.prepare(&raw).unwrap();
    assert_eq!(prepared.target()["project"], "123456789012");
    assert_eq!(prepared.target()["gcp_api_url"], client::DEFAULT_BASE_URL);
    assert_eq!(
        prepared.secret_ref_names(),
        [
            "env:OPAQUE_GCP_PREPARE_MISSING_TOKEN",
            "env:OPAQUE_GCP_PREPARE_MISSING_VALUE"
        ]
    );
    raw.params["project"] = json!("changed");
    assert_eq!(prepared.params()["project"], "123456789012");
    assert_eq!(
        prepared.params()["token_endpoint"],
        "https://oauth2.googleapis.com/token"
    );
}
#[tokio::test]
async fn invalid_authority_and_reveal_fail_before_any_network() {
    let server = MockServer::start().await;
    let handler = handler(&server.uri(), "env:OPAQUE_GCP_MISSING_TOKEN");
    for params in [
        json!({"project":"p/../victim"}),
        json!({"project":"p?x"}),
        json!({"project":"p","endpoint":"https://evil.invalid"}),
        json!({"project":null}),
        json!({}),
    ] {
        assert!(
            handler
                .prepare(&request("gcp.list_secrets", params))
                .is_err()
        );
    }
    for secret in ["..", "s/../x", "s%2fother", "s?alt=media", "s#x", "s\\x"] {
        assert!(
            handler
                .prepare(&request(
                    "gcp.get_secret",
                    json!({"project":"123456789012","secret_id":secret})
                ))
                .is_err()
        );
    }
    assert!(
        handler
            .execute(&request(
                "gcp.access_secret_version",
                json!({"project":"123456789012","secret_id":"secret"})
            ))
            .await
            .unwrap_err()
            .contains("reveal")
    );
    assert!(
        handler
            .prepare(&request(
                "gcp.add_secret_version",
                json!({"project":"123456789012","secret_id":"secret","value_ref":"profile:mutable"})
            ))
            .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn handler_executes_real_protocol_and_never_returns_written_payload() {
    let server = MockServer::start().await;
    let token_name = format!("OPAQUE_GCP_TEST_TOKEN_{}", uuid::Uuid::new_v4().simple());
    let value_name = format!("OPAQUE_GCP_TEST_VALUE_{}", uuid::Uuid::new_v4().simple());
    unsafe {
        std::env::set_var(&token_name, "only-synthetic-access-token");
        std::env::set_var(&value_name, "only-synthetic-secret");
    }
    let handler = handler(&server.uri(), &format!("env:{token_name}"));
    Mock::given(method("POST"))
        .and(path("/projects/123456789012/secrets/secret:addVersion"))
        .and(header(
            "Authorization",
            "Bearer only-synthetic-access-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"name":"projects/123456789012/secrets/secret/versions/1","state":"ENABLED"}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let output=handler.execute(&request("gcp.add_secret_version",json!({"project":"123456789012","secret_id":"secret","value_ref":format!("env:{value_name}")}))).await.unwrap();
    assert_eq!(
        output["version"],
        "projects/123456789012/secrets/secret/versions/1"
    );
    assert!(!output.to_string().contains("only-synthetic"));
    let calls = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&calls[0].body).unwrap();
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(body["payload"]["data"].as_str().unwrap())
            .unwrap(),
        b"only-synthetic-secret"
    );
    unsafe {
        std::env::remove_var(&token_name);
        std::env::remove_var(&value_name);
    }
}
#[tokio::test]
async fn metadata_and_create_preserve_resource_shape() {
    let server = MockServer::start().await;
    let token_name = format!("OPAQUE_GCP_META_TOKEN_{}", uuid::Uuid::new_v4().simple());
    unsafe {
        std::env::set_var(&token_name, "synthetic-token");
    }
    let handler = handler(&server.uri(), &format!("env:{token_name}"));
    Mock::given(method("GET")).and(path("/projects/123456789012/secrets/secret")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"name":"projects/123456789012/secrets/secret","createTime":"2026-09-11T00:00:00Z","replication":{"untrusted":"not-output"}}))).mount(&server).await;
    let metadata = handler
        .execute(&request(
            "gcp.get_secret",
            json!({"project":"123456789012","secret_id":"secret"}),
        ))
        .await
        .unwrap();
    assert!(metadata.get("replication").is_none());
    Mock::given(method("POST"))
        .and(path("/projects/123456789012/secrets"))
        .and(body_json(json!({"replication":{"automatic":{}}})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"name":"projects/123456789012/secrets/secret"})),
        )
        .mount(&server)
        .await;
    let created = handler
        .execute(&request(
            "gcp.create_secret",
            json!({"project":"123456789012","secret_id":"secret"}),
        ))
        .await
        .unwrap();
    assert_eq!(created["name"], "projects/123456789012/secrets/secret");
    unsafe {
        std::env::remove_var(&token_name);
    }
}
#[test]
fn operation_catalog_has_only_supported_safe_contracts() {
    let definitions = operations();
    assert_eq!(definitions.len(), 4);
    for definition in definitions {
        assert_eq!(
            definition.safety,
            opaque_core::operation::OperationSafety::Safe
        );
        assert!(!definition.name.contains("access"));
        assert_eq!(
            definition.params_schema.unwrap()["additionalProperties"],
            false
        );
    }
}
