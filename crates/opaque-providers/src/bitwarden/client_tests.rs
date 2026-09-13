use super::*;

#[test]
fn official_cloud_and_self_hosted_endpoints_are_explicit() {
    assert_eq!(
        identity_url(DEFAULT_BASE_URL, None).unwrap(),
        "https://identity.bitwarden.com"
    );
    assert_eq!(
        identity_url("https://api.bitwarden.eu", None).unwrap(),
        "https://identity.bitwarden.eu"
    );
    assert_eq!(
        identity_url("https://secrets.example.test/api", None).unwrap(),
        "https://secrets.example.test/identity"
    );
    assert!(identity_url("https://custom-api.example.test", None).is_err());
    for url in [
        "https://secret@example.test",
        "https://example.test?token=secret",
        "http://remote.example.test",
        "http://127.0.0.1:8200",
        "https://example.test#secret",
    ] {
        let error = validate_endpoint(url).unwrap_err().to_string();
        assert!(!error.contains("secret"));
        assert!(!error.contains(url));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn official_cli_commands_parse_and_preserve_values() {
    use crate::bitwarden::test_support::*;
    let fixture = Fixture::new();
    let projects = fixture.client.list_projects(TOKEN).await.unwrap();
    assert_eq!(projects[0].name, "Production");
    let summaries = fixture
        .client
        .list_secrets(TOKEN, Some(PROJECT_ID))
        .await
        .unwrap();
    assert_eq!(summaries[0].key, "DB_PASSWORD");
    assert!(!serde_json::to_string(&summaries).unwrap().contains("value"));
    let secret = fixture.client.get_secret(TOKEN, SECRET_ID).await.unwrap();
    assert_eq!(
        secret.value.as_deref(),
        Some("secret with trailing spaces  \n")
    );
    assert!(!format!("{secret:?}").contains("private fixture note"));
    assert!(!format!("{secret:?}").contains("secret with trailing"));
    let args = fixture.recorded_args();
    assert!(args.contains("secret\nlist\n"));
    assert!(args.contains(PROJECT_ID));
    assert!(!args.contains(TOKEN));
    let config = std::fs::read_to_string(fixture.dir.path().join("config")).unwrap();
    assert!(config.contains("state_opt_out = \"true\""));
    assert!(config.contains("https://identity.bitwarden.com"));
    assert!(!config.contains(TOKEN));
}

#[cfg(unix)]
#[tokio::test]
async fn changed_executable_is_rejected_before_token_delivery() {
    use crate::bitwarden::test_support::*;
    let fixture = Fixture::new();
    std::fs::write(&fixture.executable, "#!/bin/sh\nexit 0\n").unwrap();
    assert!(matches!(
        fixture.client.list_projects(TOKEN).await,
        Err(BitwardenApiError::ExecutableChanged)
    ));
    assert!(!fixture.dir.path().join("args").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn invalid_ids_and_mismatched_response_are_rejected() {
    use crate::bitwarden::test_support::*;
    let fixture = Fixture::new();
    for id in [
        "--help",
        "../secret",
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
    ] {
        assert!(matches!(
            fixture.client.get_secret(TOKEN, id).await,
            Err(BitwardenApiError::InvalidSelector)
        ));
    }
    assert!(!fixture.dir.path().join("args").exists());
    assert!(matches!(
        fixture.client.get_secret(TOKEN, OTHER_ID).await,
        Err(BitwardenApiError::InvalidResponse)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn ambiguous_names_do_not_choose_an_arbitrary_secret() {
    use crate::bitwarden::test_support::*;
    let fixture = Fixture::new();
    std::fs::write(
        fixture.dir.path().join("projects.json"),
        serde_json::json!([
            {"id":PROJECT_ID,"name":"Production"},{"id":OTHER_ID,"name":"Production"}
        ])
        .to_string(),
    )
    .unwrap();
    assert!(matches!(
        fixture
            .client
            .find_project_by_name(TOKEN, "Production")
            .await,
        Err(BitwardenApiError::AmbiguousName)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn child_failures_invalid_output_and_timeouts_are_sanitized() {
    use crate::bitwarden::test_support::*;
    for script in [
        "printf 'secret-child-output'; printf 'secret-child-error' >&2; exit 1",
        "printf 'secret-child-output'; exit 0",
    ] {
        let fixture = Fixture::script(script);
        let error = fixture.client.list_projects(TOKEN).await.unwrap_err();
        assert!(!error.to_string().contains("secret-child"));
    }
    // A shell builtin loop avoids leaving a sleeping grandchild behind.
    let mut fixture = Fixture::script("while :; do :; done");
    fixture.client.timeout = Duration::from_millis(100);
    assert!(matches!(
        fixture.client.list_projects(TOKEN).await,
        Err(BitwardenApiError::Timeout)
    ));
}

/// Real read-only acceptance: set the marker, dedicated machine token and a
/// disposable secret UUID + expected SHA-256. Never prints secret contents.
#[tokio::test]
#[ignore = "requires official bws and explicitly configured disposable live Bitwarden account"]
async fn live_machine_authentication_and_secret_decryption() {
    assert_eq!(
        std::env::var("OPAQUE_BITWARDEN_LIVE_ACCEPTANCE").as_deref(),
        Ok("1")
    );
    let token = Zeroizing::new(
        std::env::var("OPAQUE_BITWARDEN_LIVE_TOKEN").expect("dedicated live test token required"),
    );
    let id =
        std::env::var("OPAQUE_BITWARDEN_LIVE_SECRET_ID").expect("disposable secret UUID required");
    let expected = std::env::var("OPAQUE_BITWARDEN_LIVE_VALUE_SHA256")
        .expect("expected disposable secret digest required");
    let client = BitwardenClient::new(
        &std::env::var(BITWARDEN_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_URL.into()),
    )
    .unwrap();
    client.list_projects(&token).await.unwrap();
    let mut secret = client.get_secret(&token, &id).await.unwrap();
    let value = Zeroizing::new(secret.value.take().expect("live test secret has no value"));
    assert!(
        format!("{:x}", Sha256::digest(value.as_bytes())) == expected,
        "live secret digest did not match expected fixture"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn excessive_output_is_bounded_and_ambient_configuration_is_not_inherited() {
    use crate::bitwarden::test_support::*;
    let fixture = Fixture::script("exec /usr/bin/head -c 16777217 /dev/zero");
    assert!(matches!(
        fixture.client.list_projects(TOKEN).await,
        Err(BitwardenApiError::OutputLimit)
    ));
    unsafe {
        std::env::set_var("OPAQUE_BWS_PARENT_ONLY", "must-not-reach-child");
    }
    let fixture = Fixture::new();
    fixture.client.list_projects(TOKEN).await.unwrap();
    unsafe {
        std::env::remove_var("OPAQUE_BWS_PARENT_ONLY");
    }
    let args = fixture.recorded_args();
    let config_path = args.lines().nth(1).unwrap();
    assert!(
        !Path::new(config_path).exists(),
        "isolated config must be removed after command completion"
    );
}
