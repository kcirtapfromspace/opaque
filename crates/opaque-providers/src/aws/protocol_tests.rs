use super::*;
use serde_json::json;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::*};

const IDENTITY_XML: &str = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/fixture</Arn><UserId>AIDAFIXTURE</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>fixture</RequestId></ResponseMetadata></GetCallerIdentityResponse>"#;

#[test]
fn production_regions_bind_canonical_endpoints_without_ambient_credentials() {
    for (region, suffix) in [
        ("us-east-2", "amazonaws.com"),
        ("us-gov-west-1", "amazonaws.com"),
        ("cn-north-1", "amazonaws.com.cn"),
    ] {
        let client = AwsClient::for_region(region).unwrap();
        assert!(!client.fixture_only());
        assert_eq!(client.sts_url, format!("https://sts.{region}.{suffix}"));
        assert_eq!(client.ssm_url, format!("https://ssm.{region}.{suffix}"));
        assert_eq!(
            client.secretsmanager_url,
            format!("https://secretsmanager.{region}.{suffix}")
        );
    }
    for region in [
        "",
        "https://example.com",
        "us-east-1.evil.example",
        "us-east-1/path",
        "us-east-1@evil",
        "us-iso-east-1",
        "us-east-1\n",
    ] {
        assert!(AwsClient::for_region(region).is_err());
    }
    for url in [
        "https://example.com",
        "http://localhost:8000",
        "http://127.0.0.1@evil.example",
        "http://127.0.0.1:80/path",
        "http://127.0.0.1/?secret=x",
    ] {
        assert!(AwsClient::new(url, url, url).is_err());
    }
}

#[test]
fn official_signer_binds_payload_service_region_and_temporary_session() {
    let client = AwsClient::for_region("us-west-2").unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    let build = |body: &[u8], token| {
        client
            .signed_request(
                &client.ssm_url,
                "ssm",
                Some("AmazonSSM.PutParameter"),
                body.to_vec(),
                FIXTURE_ACCESS_KEY,
                FIXTURE_SECRET_KEY,
                token,
                now,
            )
            .unwrap()
    };
    let first = build(
        br#"{"Name":"/fixture","Value":"confidential"}"#,
        Some(FIXTURE_SESSION_TOKEN),
    );
    let authorization = first.headers()["authorization"].to_str().unwrap();
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential="));
    assert!(authorization.contains("/20200913/us-west-2/ssm/aws4_request"));
    assert!(
        authorization.contains("content-type;host;x-amz-date;x-amz-security-token;x-amz-target")
    );
    assert_eq!(
        first.headers()["x-amz-security-token"],
        FIXTURE_SESSION_TOKEN
    );
    assert!(first.headers()["authorization"].is_sensitive());
    assert!(first.headers()["x-amz-security-token"].is_sensitive());
    assert!(!first.headers().contains_key("x-amz-secret-key"));
    assert!(!first.headers().contains_key("x-amz-access-key"));
    assert!(!authorization.contains(FIXTURE_SECRET_KEY));
    let changed = build(
        br#"{"Name":"/fixture","Value":"changed"}"#,
        Some(FIXTURE_SESSION_TOKEN),
    );
    assert_ne!(authorization, changed.headers()["authorization"]);
    let without_token = build(br#"{"Name":"/fixture","Value":"confidential"}"#, None);
    assert!(!without_token.headers().contains_key("x-amz-security-token"));
    assert_ne!(authorization, without_token.headers()["authorization"]);
}

// Published AWS signing-suite vector, independent of our adapter assertions.
// aws-sigv4 1.5.1/aws-signing-test-suite/v4/post-x-www-form-urlencoded/
// (Apache-2.0, smithy-lang/smithy-rs). Expected signature copied from
// header-signature.txt; never computed using the implementation under test.
#[test]
fn published_aws_post_form_signing_vector_and_independent_sts_signature() {
    use aws_sigv4::{
        http_request::{PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign},
        sign::v4,
    };
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_440_938_160);
    let key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let identity =
        aws_credential_types::Credentials::new("AKIDEXAMPLE", key, None, None, "published-vector")
            .into();
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("service")
        .time(time)
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let request = SignableRequest::new(
        "POST",
        "https://example.amazonaws.com/",
        [
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", "13"),
        ]
        .into_iter(),
        SignableBody::Precomputed(
            "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e".into(),
        ),
    )
    .unwrap();
    let (instructions, signature) = sign(request, &params).unwrap().into_parts();
    assert_eq!(
        signature,
        "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b"
    );
    assert!(
        instructions
            .headers()
            .any(|(name, value)| name == "authorization" && value.ends_with(&signature))
    );

    // Adapter-specific STS signature independently calculated with Python stdlib
    // hashlib/hmac from the documented SigV4 canonical request and key ladder.
    let client = AwsClient::for_region("us-east-1").unwrap();
    let request = client
        .signed_request(
            &client.sts_url,
            "sts",
            None,
            b"Action=GetCallerIdentity&Version=2011-06-15".to_vec(),
            "AKIDEXAMPLE",
            key,
            None,
            time,
        )
        .unwrap();
    assert_eq!(request.url().path(), "/");
    assert_eq!(request.url().query(), None);
    assert_eq!(
        request.headers()["authorization"],
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=94405bc26f219569999dadb25c560bc61134371b330f394151ebb698c4d5fb3a"
    );
}

#[tokio::test]
async fn malformed_success_cannot_claim_collection_or_write_acknowledgment() {
    for response in [
        json!(null),
        json!([]),
        json!({"__type":"AccessDeniedException"}),
        json!({"Version":0}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(3)
            .mount(&server)
            .await;
        let client = AwsClient::new_single(&server.uri());
        assert!(
            client
                .put_parameter(
                    FIXTURE_ACCESS_KEY,
                    FIXTURE_SECRET_KEY,
                    "/test",
                    "value",
                    "String",
                    false
                )
                .await
                .is_err()
        );
        assert!(
            client
                .put_secret_value(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "test", "value")
                .await
                .is_err()
        );
        assert!(
            client
                .delete_secret(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "test")
                .await
                .is_err()
        );
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        AwsClient::new_single(&server.uri())
            .list_secrets(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sts_uses_query_xml_and_encodes_role_parameters() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string("Action=GetCallerIdentity&Version=2011-06-15"))
        .respond_with(ResponseTemplate::new(200).set_body_string(IDENTITY_XML))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(body_string("Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ffixture&RoleSessionName=reviewer%2Bsession"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASIAFIXTURE</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>temporary</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"#))
        .expect(1).mount(&server).await;
    let client = AwsClient::new_single(&server.uri());
    assert_eq!(
        client
            .get_caller_identity(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY)
            .await
            .unwrap()
            .account,
        "123456789012"
    );
    let credentials = client
        .assume_role(
            FIXTURE_ACCESS_KEY,
            FIXTURE_SECRET_KEY,
            "arn:aws:iam::123456789012:role/fixture",
            "reviewer+session",
        )
        .await
        .unwrap();
    assert_eq!(credentials.session_token, "temporary");
    assert!(!format!("{credentials:?}").contains("temporary"));
    for request in server.received_requests().await.unwrap() {
        assert!(!request.headers.contains_key("x-amz-target"));
        assert!(!request.headers.contains_key("x-amz-secret-key"));
        assert!(
            request.headers["authorization"]
                .to_str()
                .unwrap()
                .contains("/us-east-1/sts/aws4_request")
        );
    }
}

async fn json_mock(
    server: &MockServer,
    target: &str,
    request: serde_json::Value,
    response: serde_json::Value,
) {
    Mock::given(method("POST"))
        .and(header("x-amz-target", target))
        .and(header("content-type", "application/x-amz-json-1.1"))
        .and(body_partial_json(request))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn secrets_manager_real_json_contracts_cover_reads_and_mutations() {
    let server = MockServer::start().await;
    json_mock(
        &server,
        "secretsmanager.GetSecretValue",
        json!({"SecretId":"fixture"}),
        json!({"Name":"fixture","SecretBinary":"AAEC/w=="}),
    )
    .await;
    json_mock(
        &server,
        "secretsmanager.CreateSecret",
        json!({"Name":"fixture","SecretString":"one","Description":"test"}),
        json!({"Name":"fixture","VersionId":"first"}),
    )
    .await;
    json_mock(
        &server,
        "secretsmanager.PutSecretValue",
        json!({"SecretId":"fixture","SecretString":"two"}),
        json!({"Name":"fixture","VersionId":"second"}),
    )
    .await;
    json_mock(
        &server,
        "secretsmanager.DeleteSecret",
        json!({"SecretId":"fixture","ForceDeleteWithoutRecovery":false}),
        json!({"Name":"fixture","DeletionDate":1_900_000_000.0}),
    )
    .await;
    let client = AwsClient::new_single(&server.uri());
    let value = client
        .get_secret_value(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "fixture")
        .await
        .unwrap();
    assert_eq!(value.into_secret_bytes().unwrap(), [0, 1, 2, 255]);
    assert_eq!(
        client
            .create_secret(
                FIXTURE_ACCESS_KEY,
                FIXTURE_SECRET_KEY,
                "fixture",
                "one",
                Some("test")
            )
            .await
            .unwrap()
            .version_id
            .as_deref(),
        Some("first")
    );
    client
        .put_secret_value(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "fixture", "two")
        .await
        .unwrap();
    client
        .delete_secret(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "fixture")
        .await
        .unwrap();
    for request in server.received_requests().await.unwrap() {
        assert!(
            request.headers["authorization"]
                .to_str()
                .unwrap()
                .contains("/secretsmanager/aws4_request")
        );
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        if body.get("SecretString").is_some() {
            uuid::Uuid::parse_str(body["ClientRequestToken"].as_str().unwrap()).unwrap();
        }
    }
}

#[tokio::test]
async fn ssm_real_json_contracts_preserve_decryption_and_overwrite() {
    let server = MockServer::start().await;
    json_mock(
        &server,
        "AmazonSSM.GetParameter",
        json!({"Name":"/fixture:2","WithDecryption":true}),
        json!({"Parameter":{"Name":"/fixture","Type":"SecureString","Value":"value","Version":2}}),
    )
    .await;
    json_mock(
        &server,
        "AmazonSSM.PutParameter",
        json!({"Name":"/fixture","Value":"new","Type":"SecureString","Overwrite":false}),
        json!({"Version":1,"Tier":"Standard"}),
    )
    .await;
    json_mock(
        &server,
        "AmazonSSM.DeleteParameter",
        json!({"Name":"/fixture"}),
        json!({}),
    )
    .await;
    let client = AwsClient::new_single(&server.uri());
    assert_eq!(
        client
            .get_parameter(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "/fixture:2", true)
            .await
            .unwrap()
            .value
            .as_deref(),
        Some("value")
    );
    client
        .put_parameter(
            FIXTURE_ACCESS_KEY,
            FIXTURE_SECRET_KEY,
            "/fixture",
            "new",
            "SecureString",
            false,
        )
        .await
        .unwrap();
    client
        .delete_parameter(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "/fixture")
        .await
        .unwrap();
}

#[tokio::test]
async fn collection_pagination_preserves_scope_and_does_not_claim_a_partial_list() {
    let server = MockServer::start().await;
    for (target, first, second, first_response, second_response) in [
        (
            "secretsmanager.ListSecrets",
            json!({"MaxResults":100}),
            json!({"MaxResults":100,"NextToken":"next"}),
            json!({"SecretList":[{"Name":"a"}],"NextToken":"next"}),
            json!({"SecretList":[{"Name":"b"}]}),
        ),
        (
            "AmazonSSM.GetParametersByPath",
            json!({"Path":"/fixture","Recursive":true,"WithDecryption":false,"MaxResults":10}),
            json!({"Path":"/fixture","Recursive":true,"WithDecryption":false,"MaxResults":10,"NextToken":"next"}),
            json!({"Parameters":[],"NextToken":"next"}),
            json!({"Parameters":[{"Name":"/fixture/a"}]}),
        ),
    ] {
        Mock::given(header("x-amz-target", target))
            .and(body_json(first))
            .respond_with(ResponseTemplate::new(200).set_body_json(first_response))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(header("x-amz-target", target))
            .and(body_json(second))
            .respond_with(ResponseTemplate::new(200).set_body_json(second_response))
            .expect(1)
            .mount(&server)
            .await;
    }
    let client = AwsClient::new_single(&server.uri());
    assert_eq!(
        client
            .list_secrets(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY)
            .await
            .unwrap()
            .secret_list
            .len(),
        2
    );
    assert_eq!(
        client
            .get_parameters_by_path(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "/fixture", false)
            .await
            .unwrap()
            .parameters
            .len(),
        1
    );
}

#[tokio::test]
async fn repeated_pagination_token_fails_instead_of_looping() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"SecretList":[],"NextToken":"repeat"})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let client = AwsClient::new_single(&server.uri());
    assert!(matches!(
        client
            .list_secrets(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY)
            .await,
        Err(AwsApiError::CollectionLimit)
    ));
}

#[tokio::test]
async fn vendor_error_codes_are_classified_without_exposing_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(400).set_body_json(json!({"__type":"com.amazonaws.ssm#ParameterNotFound","message":"confidential upstream content"}))).expect(1).mount(&server).await;
    let error = AwsClient::new_single(&server.uri())
        .get_parameter(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "/fixture", true)
        .await
        .unwrap_err();
    assert!(matches!(error, AwsApiError::NotFound));
    assert!(!format!("{error:?} {error}").contains("confidential"));
    let error = error_response(403, br#"<ErrorResponse><Error><Code>ExpiredToken</Code><Message>secret</Message></Error></ErrorResponse>"#);
    assert!(matches!(error, AwsApiError::Unauthorized));
}

#[tokio::test]
async fn redirect_and_uncertain_write_are_never_retried() {
    let destination = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&destination)
        .await;
    let server = MockServer::start().await;
    Mock::given(header("x-amz-target", "AmazonSSM.PutParameter"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(header("x-amz-target", "AmazonSSM.DeleteParameter"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", destination.uri()))
        .expect(1)
        .mount(&server)
        .await;
    let client = AwsClient::new_single(&server.uri());
    assert!(
        client
            .put_parameter(
                FIXTURE_ACCESS_KEY,
                FIXTURE_SECRET_KEY,
                "/fixture",
                "value",
                "SecureString",
                false
            )
            .await
            .is_err()
    );
    assert!(
        client
            .delete_parameter(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "/fixture")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn real_credentials_cannot_be_sent_to_a_fixture() {
    let server = MockServer::start().await;
    let client = AwsClient::new_single(&server.uri());
    assert!(matches!(
        client
            .get_caller_identity("AKIAREALLOOKINGKEY", "non-fixture-secret")
            .await,
        Err(AwsApiError::MockOnly)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn oversized_and_malformed_success_are_rejected_without_content_disclosure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_RESPONSE_BYTES + 1]))
        .expect(1)
        .mount(&server)
        .await;
    let error = AwsClient::new_single(&server.uri())
        .get_secret_value(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "fixture")
        .await
        .unwrap_err();
    assert!(matches!(error, AwsApiError::ParseError));
    assert!(!format!("{error:?}").contains("xxxx"));
}

/// Opt-in live qualification uses only explicitly named references and reads.
/// It never discovers ambient SDK credentials or prints returned secrets.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires explicit live-read opt-in, region, account and base credential references"]
async fn live_aws_read_only_identity_and_selected_resources() {
    assert_eq!(
        std::env::var("OPAQUE_AWS_LIVE_ACCEPTANCE").as_deref(),
        Ok("read-only")
    );
    let client = AwsClient::from_env()
        .unwrap()
        .expect("explicit AWS region required");
    assert!(!client.fixture_only());
    let expected_account =
        std::env::var("OPAQUE_AWS_LIVE_ACCOUNT").expect("expected account required");
    let access_ref =
        std::env::var("OPAQUE_AWS_ACCESS_KEY_REF").expect("explicit access reference required");
    let secret_ref =
        std::env::var("OPAQUE_AWS_SECRET_KEY_REF").expect("explicit secret reference required");
    assert!(valid_credential_ref(&access_ref) && valid_credential_ref(&secret_ref));
    let base = BaseResolver::new();
    let access = base
        .resolve(&access_ref)
        .expect("explicit access credential");
    let secret = base
        .resolve(&secret_ref)
        .expect("explicit secret credential");
    let access = access.as_str().unwrap();
    let secret = secret.as_str().unwrap();
    let identity = client
        .get_caller_identity(access, secret)
        .await
        .expect("STS protocol acceptance");
    assert!(
        identity.account == expected_account,
        "AWS account does not match qualification scope"
    );
    if let Ok(name) = std::env::var("OPAQUE_AWS_LIVE_SECRET_NAME") {
        assert!(
            !client
                .get_secret_value(access, secret, &name)
                .await
                .expect("selected Secrets Manager read")
                .into_secret_bytes()
                .unwrap()
                .is_empty()
        );
    }
    if let Ok(name) = std::env::var("OPAQUE_AWS_LIVE_PARAMETER_NAME") {
        assert!(
            client
                .get_parameter(access, secret, &name, true)
                .await
                .expect("selected SSM read")
                .value
                .is_some()
        );
    }
}

#[test]
fn credential_signing_guards_reject_each_invalid_field_before_request_creation() {
    let client = AwsClient::for_region("us-east-1").unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    let bad = vec![
        (String::new(), "valid".into(), None),
        ("a".repeat(129), "valid".into(), None),
        ("access-".into(), "valid".into(), None),
        ("ACCESS".into(), String::new(), None),
        ("ACCESS".into(), "a".repeat(513), None),
        ("ACCESS".into(), "contains space".into(), None),
        ("ACCESS".into(), "valid".into(), Some(String::new())),
        ("ACCESS".into(), "valid".into(), Some("a".repeat(16385))),
        ("ACCESS".into(), "valid".into(), Some("line\nbreak".into())),
    ];
    for (access, secret, token) in bad {
        assert!(matches!(
            client.signed_request(
                &client.ssm_url,
                "ssm",
                None,
                vec![],
                &access,
                &secret,
                token.as_deref(),
                now
            ),
            Err(AwsApiError::Configuration)
        ));
    }
    assert!(matches!(
        client.signed_request(
            &client.ssm_url,
            "ssm",
            None,
            vec![0; 1024 * 1024 + 1],
            "ACCESS",
            "valid",
            None,
            now
        ),
        Err(AwsApiError::BadRequest)
    ));
    let fixture = AwsClient::new_single("http://127.0.0.1:9");
    for (access, secret, token) in [
        ("OTHER", FIXTURE_SECRET_KEY, None),
        (FIXTURE_ACCESS_KEY, "OTHER", None),
        (FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, Some("OTHER")),
    ] {
        assert!(matches!(
            fixture.signed_request(
                &fixture.ssm_url,
                "ssm",
                None,
                vec![],
                access,
                secret,
                token,
                now
            ),
            Err(AwsApiError::MockOnly)
        ));
    }
}

#[test]
fn region_and_reference_boundaries_preserve_explicit_authority() {
    for reference in [
        "".into(),
        "x".repeat(513),
        "env:A\n".into(),
        "env:".into(),
        "env:bad-name".into(),
        "keychain:/account".into(),
        "keychain:service/".into(),
        "keychain:missing".into(),
    ] {
        assert!(!valid_credential_ref(&reference), "{reference:?}");
        assert!(matches!(
            AwsClient::for_region("us-east-1")
                .unwrap()
                .with_session_token_ref(&reference),
            Err(AwsApiError::Configuration)
        ));
    }
    for reference in ["env:EXPLICIT_SESSION_1", "keychain:service/account"] {
        let client = AwsClient::for_region("us-east-1")
            .unwrap()
            .with_session_token_ref(reference)
            .unwrap();
        assert_eq!(client.session_token_ref(), Some(reference));
        assert_eq!(client.backend(), "aws_sigv4");
    }
    for region in [
        "us-a-1".repeat(12),
        "us-east".into(),
        "us--1".into(),
        "us-east-x".into(),
        "zz-east-1".into(),
    ] {
        assert!(matches!(
            region_suffix(&region),
            Err(AwsApiError::Configuration)
        ));
    }
    assert!(matches!(
        validate_fixture_url("ftp://127.0.0.1"),
        Err(AwsApiError::MockOnly)
    ));
}

#[tokio::test]
async fn malformed_write_acknowledgments_never_retry_or_claim_success() {
    for (operation, body) in [
        (
            "create",
            json!({"ARN":"arn","Name":"foreign","VersionId":"v"}),
        ),
        (
            "create",
            json!({"ARN":"arn","Name":"fixture","VersionId":""}),
        ),
        ("put", json!({"ARN":"arn","Name":"","VersionId":"v"})),
        ("put", json!({"ARN":"arn","Name":"fixture","VersionId":""})),
        ("delete", json!({"Name":"","DeletionDate":1.0})),
        ("delete", json!({"Name":"fixture","DeletionDate":0.0})),
        ("delete", json!({"Name":"fixture"})),
        ("parameter", json!({"unexpected":"not an acknowledgment"})),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let client = AwsClient::new_single(&server.uri());
        let result = match operation {
            "create" => client
                .create_secret(
                    FIXTURE_ACCESS_KEY,
                    FIXTURE_SECRET_KEY,
                    "fixture",
                    "disposable",
                    None,
                )
                .await
                .map(|_| ()),
            "put" => {
                client
                    .put_secret_value(
                        FIXTURE_ACCESS_KEY,
                        FIXTURE_SECRET_KEY,
                        "fixture",
                        "disposable",
                    )
                    .await
            }
            "delete" => {
                client
                    .delete_secret(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "fixture")
                    .await
            }
            _ => {
                client
                    .delete_parameter(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "/fixture")
                    .await
            }
        };
        assert!(matches!(result, Err(AwsApiError::ParseError)));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn collection_shape_and_budget_failures_never_return_partial_results() {
    for (body, collection_limit) in [
        (json!([]), false),
        (json!({"SecretList":[],"foreign":true}), false),
        (json!({"SecretList":"not an array"}), false),
        (json!({"SecretList":[],"NextToken":""}), true),
        (json!({"SecretList":[],"NextToken":"x".repeat(8193)}), true),
        (json!({"SecretList":[],"NextToken":3}), true),
        (
            json!({"SecretList":vec![json!({});MAX_COLLECTION_ITEMS+1]}),
            true,
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let error = AwsClient::new_single(&server.uri())
            .list_secrets(FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY)
            .await
            .unwrap_err();
        assert!(if collection_limit {
            matches!(error, AwsApiError::CollectionLimit)
        } else {
            matches!(error, AwsApiError::ParseError)
        });
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
