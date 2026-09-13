use super::test_support::*;
use super::*;
use opaque_core::audit::InMemoryAuditEmitter;
use opaque_core::operation::{ClientIdentity, ClientType};

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
            workload: None,
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

fn handler(fixture: &Fixture) -> (BitwardenHandler, Arc<InMemoryAuditEmitter>) {
    let audit = Arc::new(InMemoryAuditEmitter::new());
    (
        BitwardenHandler {
            audit: audit.clone(),
            client: fixture.client.clone(),
            token_ref: "env:OPAQUE_BW_HANDLER_TEST_TOKEN".into(),
        },
        audit,
    )
}

#[test]
fn preparation_binds_endpoints_executable_selector_and_credential_ref() {
    let fixture = Fixture::new();
    let (handler, audit) = handler(&fixture);
    let prepared = handler
        .prepare(&request(
            "bitwarden.read_secret",
            serde_json::json!({"secret_id":SECRET_ID}),
        ))
        .unwrap();
    assert_eq!(prepared.target()["secret_id"], SECRET_ID);
    assert_eq!(
        prepared.target()["bitwarden_identity_url"],
        "https://identity.bitwarden.com"
    );
    assert_eq!(
        prepared.target()["bitwarden_cli_sha256"],
        fixture.client.executable_sha256()
    );
    assert_eq!(
        prepared.params()["executable_sha256"],
        fixture.client.executable_sha256()
    );
    assert_eq!(
        prepared.secret_ref_names(),
        &[
            SECRET_ID.to_owned(),
            "env:OPAQUE_BW_HANDLER_TEST_TOKEN".to_owned()
        ]
    );
    assert!(audit.events().is_empty());
    assert!(!fixture.dir.path().join("args").exists());
}

#[test]
fn prepared_payload_distinguishes_endpoint_binary_and_project_scope() {
    let first = Fixture::new();
    let second = Fixture::new();
    let (first_handler, _) = handler(&first);
    let (mut second_handler, _) = handler(&second);
    second_handler.client = BitwardenClient::with_executable(
        "https://api.bitwarden.eu",
        "https://identity.bitwarden.eu",
        &second.executable,
    )
    .unwrap();
    let req = request("bitwarden.list_projects", serde_json::json!({}));
    assert_ne!(
        first_handler.prepare(&req).unwrap().params(),
        second_handler.prepare(&req).unwrap().params()
    );
    let no_project = first_handler
        .prepare(&request("bitwarden.list_secrets", serde_json::json!({})))
        .unwrap();
    let null_project = first_handler
        .prepare(&request(
            "bitwarden.list_secrets",
            serde_json::json!({"project":null}),
        ))
        .unwrap();
    let selected = first_handler
        .prepare(&request(
            "bitwarden.list_secrets",
            serde_json::json!({"project":"Production"}),
        ))
        .unwrap();
    assert_eq!(no_project.params(), null_project.params());
    assert_ne!(no_project.params(), selected.params());
}

#[test]
fn invalid_actions_and_extra_fields_fail_before_provider_work() {
    let fixture = Fixture::new();
    let (handler, audit) = handler(&fixture);
    for (operation, params) in [
        ("bitwarden.unknown", serde_json::json!({})),
        (
            "bitwarden.list_projects",
            serde_json::json!({"project":"hidden"}),
        ),
        ("bitwarden.list_projects", serde_json::json!([])),
        (
            "bitwarden.list_secrets",
            serde_json::json!({"project":false}),
        ),
        ("bitwarden.list_secrets", serde_json::json!({"project":""})),
        ("bitwarden.read_secret", serde_json::json!({})),
        (
            "bitwarden.read_secret",
            serde_json::json!({"secret_id":"--help"}),
        ),
        (
            "bitwarden.read_secret",
            serde_json::json!({"secret_id":SECRET_ID,"token":"hidden"}),
        ),
    ] {
        assert!(handler.prepare(&request(operation, params)).is_err());
    }
    assert!(audit.events().is_empty());
    assert!(!fixture.dir.path().join("args").exists());
}

#[tokio::test]
async fn prepared_execution_retains_selector_and_sanitizes_browsing() {
    // Only this test uses this dedicated environment key; no shared Keychain.
    unsafe {
        std::env::set_var("OPAQUE_BW_HANDLER_TEST_TOKEN", TOKEN);
    }
    let fixture = Fixture::new();
    let (handler, audit) = handler(&fixture);
    let mut req = request(
        "bitwarden.read_secret",
        serde_json::json!({"secret_id":SECRET_ID}),
    );
    let prepared = handler.prepare(&req).unwrap();
    req.params["secret_id"] = OTHER_ID.into();
    let result = prepared.execute().await.unwrap();
    assert_eq!(result["secret_id"], SECRET_ID);
    assert_eq!(result["value"], "secret with trailing spaces  \n");
    let result = handler
        .execute(&request(
            "bitwarden.list_secrets",
            serde_json::json!({"project":"Production"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        result,
        serde_json::json!({"project":"Production","secrets":[{"key":"DB_PASSWORD"}]})
    );
    let projects = handler
        .execute(&request("bitwarden.list_projects", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(
        projects,
        serde_json::json!({"projects":[{"name":"Production"}]})
    );
    let audit_json = serde_json::to_string(&audit.events()).unwrap();
    assert!(!audit_json.contains(TOKEN));
    assert!(!audit_json.contains("secret with trailing"));
    assert!(!audit_json.contains("private fixture note"));
    unsafe {
        std::env::remove_var("OPAQUE_BW_HANDLER_TEST_TOKEN");
    }
}

#[test]
fn secret_name_policies_still_bind_the_real_resource() {
    use opaque_core::policy::SecretNameMatch;
    let fixture = Fixture::new();
    let (handler, _) = handler(&fixture);
    let policy = SecretNameMatch {
        patterns: vec!["env:OPAQUE_BW_HANDLER_TEST_TOKEN".into(), SECRET_ID.into()],
    };
    let allowed = handler
        .prepare(&request(
            "bitwarden.read_secret",
            serde_json::json!({"secret_id":SECRET_ID}),
        ))
        .unwrap();
    let mut forged = request(
        "bitwarden.read_secret",
        serde_json::json!({"secret_id":OTHER_ID}),
    );
    forged.secret_ref_names = vec![SECRET_ID.into()];
    let denied = handler.prepare(&forged).unwrap();
    assert!(policy.matches(allowed.secret_ref_names()));
    assert!(!policy.matches(denied.secret_ref_names()));
}
