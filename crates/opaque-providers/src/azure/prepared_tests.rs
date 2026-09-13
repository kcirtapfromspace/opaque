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
        target: HashMap::from([("vault".into(), "caller-lie".into())]),
        secret_ref_names: vec!["env:CALLER_LIE".into()],
        created_at: std::time::SystemTime::now(),
        expires_at: None,
        params,
        workspace: None,
    }
}
fn handler(base: &str, token_url: Option<String>, credential_ref: &str) -> AzureHandler {
    let mut client = AzureKeyVaultClient::new(
        base,
        "tenant-123".into(),
        "client-456".into(),
        credential_ref.into(),
    )
    .unwrap();
    client.token_endpoint_override = token_url;
    AzureHandler::from_client(Arc::new(InMemoryAuditEmitter::new()), client)
}
#[test]
fn preparation_freezes_vault_identity_refs_and_name_without_credentials() {
    let handler = handler(
        "https://myvault.vault.azure.net",
        None,
        "env:OPAQUE_AZURE_MISSING_AUTH",
    );
    let prepared = handler
        .prepare(&request(
            "azure.set_secret",
            json!({"name":"deploy-token","value_ref":"env:OPAQUE_AZURE_MISSING_VALUE"}),
        ))
        .unwrap();
    assert_eq!(prepared.target()["vault"], "myvault");
    assert_eq!(prepared.target()["name"], "deploy-token");
    assert_eq!(prepared.params()["auth"]["tenant_id"], "tenant-123");
    assert_eq!(
        prepared.params()["auth"]["scope"],
        "https://vault.azure.net/.default"
    );
    assert_eq!(
        prepared.secret_ref_names(),
        [
            "env:OPAQUE_AZURE_MISSING_AUTH",
            "env:OPAQUE_AZURE_MISSING_VALUE"
        ]
    );
}
#[tokio::test]
async fn invalid_selectors_and_extra_authority_are_denied_before_auth() {
    let server = MockServer::start().await;
    let handler = handler(
        &server.uri(),
        Some(format!("{}/token", server.uri())),
        "env:OPAQUE_AZURE_MISSING_AUTH",
    );
    for name in [
        "..",
        "name/else",
        "name?x",
        "name%2felse",
        "name#x",
        "name\\else",
    ] {
        assert!(
            handler
                .prepare(&request("azure.get_secret", json!({"name":name})))
                .is_err()
        );
    }
    for params in [
        json!({"name":"secret","vault":"other"}),
        json!({"name":"secret","version":"1/else"}),
        json!({"name":"secret","value":"raw-secret"}),
    ] {
        assert!(
            handler
                .prepare(&request("azure.get_secret", params))
                .is_err()
        );
    }
    assert!(
        handler
            .prepare(&request(
                "azure.set_secret",
                json!({"name":"secret","value_ref":"azure:other/recursive"})
            ))
            .is_err()
    );
    assert!(
        handler
            .prepare(&request("azure.reveal_secret", json!({"name":"secret"})))
            .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn handler_authenticates_gets_metadata_and_writes_without_secret_output() {
    let server = MockServer::start().await;
    let auth = format!("OPAQUE_AZURE_AUTH_TEST_{}", uuid::Uuid::new_v4().simple());
    let value = format!("OPAQUE_AZURE_VALUE_TEST_{}", uuid::Uuid::new_v4().simple());
    unsafe {
        std::env::set_var(&auth, "synthetic-client-secret");
        std::env::set_var(&value, "synthetic-write-value");
    }
    let handler = handler(
        &server.uri(),
        Some(format!("{}/token", server.uri())),
        &format!("env:{auth}"),
    );
    Mock::given(method("POST")).and(path("/token")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"synthetic-access-token","token_type":"Bearer","expires_in":3600}))).expect(1).mount(&server).await;
    Mock::given(method("GET")).and(path("/secrets/secret")).and(header("Authorization","Bearer synthetic-access-token")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":format!("{}/secrets/secret/version1",server.uri()),"value":"SYNTHETIC-RAW-SECRET","attributes":{"enabled":true}}))).expect(1).mount(&server).await;
    let output = handler
        .execute(&request("azure.get_secret", json!({"name":"secret"})))
        .await
        .unwrap();
    assert_eq!(output["metadata_only"], true);
    assert!(!output.to_string().contains("RAW-SECRET"));
    assert!(output.get("value").is_none());
    Mock::given(method("PUT")).and(path("/secrets/secret")).and(body_json(json!({"value":"synthetic-write-value"}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":format!("{}/secrets/secret/version2",server.uri()),"value":"synthetic-write-value"}))).expect(1).mount(&server).await;
    let result = handler
        .execute(&request(
            "azure.set_secret",
            json!({"name":"secret","value_ref":format!("env:{value}")}),
        ))
        .await
        .unwrap();
    assert_eq!(result, json!({"name":"secret","status":"written"}));
    let calls = server.received_requests().await.unwrap();
    let token_request = std::str::from_utf8(&calls[0].body).unwrap();
    assert!(token_request.contains("scope=https%3A%2F%2Fvault.azure.net%2F.default"));
    assert!(token_request.contains("grant_type=client_credentials"));
    unsafe {
        std::env::remove_var(&auth);
        std::env::remove_var(&value);
    }
}
#[test]
fn metadata_cannot_claim_a_different_vault_or_path() {
    let client = AzureKeyVaultClient::new(
        "https://myvault.vault.azure.net",
        "tenant".into(),
        "client".into(),
        "env:AUTH".into(),
    )
    .unwrap();
    assert_eq!(
        client
            .resource_name(
                "https://myvault.vault.azure.net/secrets/my-secret/version1",
                "secrets"
            )
            .unwrap(),
        "my-secret"
    );
    for id in [
        "https://other.vault.azure.net/secrets/secret",
        "https://myvault.vault.azure.net/secrets/%2e%2e",
        "https://myvault.vault.azure.net/keys/secret",
        "https://myvault.vault.azure.net/secrets/secret?value=raw",
    ] {
        assert!(client.resource_name(id, "secrets").is_err());
    }
}
#[test]
fn catalog_matches_supported_non_reveal_operations() {
    assert_eq!(operations().len(), 5);
    for definition in operations() {
        assert_eq!(
            definition.safety,
            opaque_core::operation::OperationSafety::Safe
        );
        assert_eq!(
            definition.params_schema.unwrap()["additionalProperties"],
            false
        );
    }
}
