// Controlled HTTP IdP tests with real RSA/P-256 signatures. Cache aging below
// selects a deterministic refresh window; it does not replace signature checks.

fn ec_fixture(kid: &str, scalar: u8) -> (serde_json::Value, jsonwebtoken::EncodingKey) {
    use p256::pkcs8::EncodePrivateKey;
    let secret = p256::SecretKey::from_slice(&[scalar; 32]).unwrap();
    let point = secret.public_key().to_sec1_bytes();
    let key = jsonwebtoken::EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes());
    (
        serde_json::json!({
            "kty":"EC", "kid":kid, "crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y":URL_SAFE_NO_PAD.encode(&point[33..65])
        }),
        key,
    )
}

fn sign_ec(
    claims: &serde_json::Value,
    kid: Option<&str>,
    key: &jsonwebtoken::EncodingKey,
) -> String {
    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = kid.map(str::to_owned);
    jsonwebtoken::encode(&header, claims, key).unwrap()
}

async fn replace_jwks(server: &MockServer, keys: Vec<serde_json::Value>) {
    // reset removes response rules and request history; each phase asserts its
    // own actual requests before advancing the stateful history.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"keys":keys})))
        .mount(server)
        .await;
}

async fn assert_only_jwks_requests(server: &MockServer, count: usize) {
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), count);
    for request in requests {
        assert_eq!(request.method.as_str(), "GET");
        assert_eq!(request.url.path(), "/jwks");
        assert!(request.body.is_empty());
    }
}

#[tokio::test]
async fn es256_verifies_identity_and_rejects_a_different_signing_key() {
    let (server, client) = mock_idp().await;
    let (jwk, key) = ec_fixture("ec-current", 7);
    replace_jwks(&server, vec![jwk]).await;
    let claims = base_claims(&server.uri(), "ec-nonce");
    let token = sign_ec(&claims, Some("ec-current"), &key);
    let verified = client.verify_id_token(&token, "ec-nonce").await.unwrap();
    assert_eq!(verified.sub, "user-123");
    assert_eq!(verified.email.as_deref(), Some("dev@example.com"));
    assert_eq!(verified.name.as_deref(), Some("Dev Example"));
    assert!(verified.persona.is_none());
    let (_, wrong) = ec_fixture("ec-current", 8);
    let forged = sign_ec(&claims, Some("ec-current"), &wrong);
    assert_eq!(
        client
            .verify_id_token(&forged, "ec-nonce")
            .await
            .unwrap_err(),
        "id_token verification failed: InvalidSignature"
    );
    assert_eq!(
        client.verify_id_token(&token, "wrong").await.unwrap_err(),
        "id_token nonce mismatch"
    );
    assert_only_jwks_requests(&server, 1).await;
}

#[tokio::test]
async fn jwks_rotation_is_throttled_then_replaces_retired_keys() {
    let (server, client) = mock_idp().await;
    let (old_jwk, old_key) = ec_fixture("old", 9);
    let (new_jwk, new_key) = ec_fixture("new", 10);
    let claims = base_claims(&server.uri(), "rotation");
    let old = sign_ec(&claims, Some("old"), &old_key);
    let new = sign_ec(&claims, Some("new"), &new_key);
    replace_jwks(&server, vec![old_jwk]).await;
    assert_eq!(
        client.verify_id_token(&old, "rotation").await.unwrap().sub,
        "user-123"
    );
    assert_only_jwks_requests(&server, 1).await;
    replace_jwks(&server, vec![new_jwk]).await;
    assert_eq!(
        client.verify_id_token(&new, "rotation").await.unwrap_err(),
        "id_token kid unknown (JWKS refresh throttled)"
    );
    assert_eq!(
        client.verify_id_token(&old, "rotation").await.unwrap().sub,
        "user-123"
    );
    assert_only_jwks_requests(&server, 0).await;
    client.jwks.lock().await.last_fetch = Some(Instant::now() - JWKS_REFRESH_COOLDOWN);
    assert_eq!(
        client.verify_id_token(&new, "rotation").await.unwrap().sub,
        "user-123"
    );
    assert_eq!(
        client.verify_id_token(&old, "rotation").await.unwrap_err(),
        "id_token kid unknown (JWKS refresh throttled)"
    );
    assert_only_jwks_requests(&server, 1).await;
    assert_eq!(
        client
            .jwks
            .lock()
            .await
            .keys
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["new"]
    );
}

#[tokio::test]
async fn concurrent_unknown_kids_share_one_refresh_and_do_not_evict_known_key() {
    let (server, client) = mock_idp().await;
    let (jwk, key) = ec_fixture("known", 11);
    replace_jwks(&server, vec![jwk]).await;
    let claims = base_claims(&server.uri(), "concurrent");
    let missing = sign_ec(&claims, Some("missing"), &key);
    let results = futures_util::future::join_all(
        (0..16).map(|_| client.verify_id_token(&missing, "concurrent")),
    )
    .await;
    let errors: Vec<_> = results.into_iter().map(Result::unwrap_err).collect();
    assert_eq!(
        errors
            .iter()
            .filter(|e| e.as_str() == "id_token kid not present in JWKS")
            .count(),
        1
    );
    assert_eq!(
        errors
            .iter()
            .filter(|e| e.as_str() == "id_token kid unknown (JWKS refresh throttled)")
            .count(),
        15
    );
    let known = sign_ec(&claims, Some("known"), &key);
    assert_eq!(
        client
            .verify_id_token(&known, "concurrent")
            .await
            .unwrap()
            .sub,
        "user-123"
    );
    assert_only_jwks_requests(&server, 1).await;
}

#[tokio::test]
async fn jwks_key_type_mismatch_is_rejected_both_before_and_after_cache_fill() {
    let (server, client) = mock_idp().await;
    let (jwk, key) = ec_fixture("same-id", 12);
    replace_jwks(&server, vec![jwk]).await;
    let claims = base_claims(&server.uri(), "type");
    let wrong_alg = sign_id_token(claims.clone(), "same-id");
    for _ in 0..2 {
        assert_eq!(
            client
                .verify_id_token(&wrong_alg, "type")
                .await
                .unwrap_err(),
            "id_token alg does not match JWKS key type"
        );
    }
    let valid = sign_ec(&claims, Some("same-id"), &key);
    assert_eq!(
        client.verify_id_token(&valid, "type").await.unwrap().sub,
        "user-123"
    );
    assert_only_jwks_requests(&server, 1).await;
}

#[tokio::test]
async fn malformed_jwk_entries_are_ignored_without_replacing_valid_identity() {
    let (server, client) = mock_idp().await;
    let (valid, key) = ec_fixture("valid", 13);
    let keys = vec![
        serde_json::json!({"kty":"RSA"}),
        serde_json::json!({"kty":"RSA","kid":"rsa-no-n","e":"AQAB"}),
        serde_json::json!({"kty":"RSA","kid":"rsa-no-e","n":"AQAB"}),
        serde_json::json!({"kty":"RSA","kid":"rsa-invalid","n":"!","e":"AQAB"}),
        serde_json::json!({"kty":"EC","kid":"ec-curve","crv":"P-384","x":"AA","y":"AA"}),
        serde_json::json!({"kty":"EC","kid":"ec-no-x","crv":"P-256","y":"AA"}),
        serde_json::json!({"kty":"EC","kid":"ec-no-y","crv":"P-256","x":"AA"}),
        serde_json::json!({"kty":"EC","kid":"ec-invalid","crv":"P-256","x":"!","y":"AA"}),
        serde_json::json!({"kty":"oct","kid":"symmetric","k":"AA"}),
        valid,
    ];
    replace_jwks(&server, keys).await;
    let claims = base_claims(&server.uri(), "malformed");
    assert_eq!(
        client
            .verify_id_token(&sign_ec(&claims, Some("valid"), &key), "malformed")
            .await
            .unwrap()
            .sub,
        "user-123"
    );
    for kid in [
        "rsa-no-n",
        "rsa-no-e",
        "rsa-invalid",
        "ec-curve",
        "ec-no-x",
        "ec-no-y",
        "ec-invalid",
        "symmetric",
    ] {
        assert_eq!(
            client
                .verify_id_token(&sign_ec(&claims, Some(kid), &key), "malformed")
                .await
                .unwrap_err(),
            "id_token kid unknown (JWKS refresh throttled)"
        );
    }
    assert_eq!(
        client
            .jwks
            .lock()
            .await
            .keys
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["valid"]
    );
    assert_only_jwks_requests(&server, 1).await;
}

#[tokio::test]
async fn failed_jwks_refresh_keeps_previously_verified_key_and_does_not_mark_success() {
    let (server, client) = mock_idp().await;
    let (jwk, key) = ec_fixture("retained", 14);
    let claims = base_claims(&server.uri(), "refresh");
    let retained = sign_ec(&claims, Some("retained"), &key);
    let missing = sign_ec(&claims, Some("missing"), &key);
    replace_jwks(&server, vec![jwk]).await;
    client.verify_id_token(&retained, "refresh").await.unwrap();
    for response in [
        ResponseTemplate::new(503).set_body_string("private-upstream-body"),
        ResponseTemplate::new(200).set_body_string("private-invalid-json"),
    ] {
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(response)
            .mount(&server)
            .await;
        let prior = Instant::now() - JWKS_REFRESH_COOLDOWN;
        client.jwks.lock().await.last_fetch = Some(prior);
        let error = client
            .verify_id_token(&missing, "refresh")
            .await
            .unwrap_err();
        assert!(
            error.starts_with("JWKS fetch failed:") || error == "JWKS invalid JSON",
            "{error}"
        );
        assert!(!error.contains("private-"));
        assert_eq!(client.jwks.lock().await.last_fetch, Some(prior));
        assert_eq!(
            client
                .verify_id_token(&retained, "refresh")
                .await
                .unwrap()
                .sub,
            "user-123"
        );
        assert_only_jwks_requests(&server, 1).await;
    }
}

#[tokio::test]
async fn invalid_token_headers_and_oversized_persona_never_fetch_keys() {
    let (server, client) = mock_idp().await;
    server.reset().await;
    let (_, key) = ec_fixture("unused", 15);
    let token = sign_ec(&base_claims(&server.uri(), "nonce"), None, &key);
    assert_eq!(
        client.verify_id_token(&token, "nonce").await.unwrap_err(),
        "id_token missing kid"
    );
    assert_eq!(
        client.verify_id_token("broken", "nonce").await.unwrap_err(),
        "id_token header invalid"
    );
    let persona = PersonaConfig {
        groups_claim: "groups".into(),
        max_age_secs: 60,
    };
    assert_eq!(
        client
            .verify_id_token_with_persona(&"x".repeat(64 * 1024 + 1), "nonce", &persona)
            .await
            .unwrap_err(),
        "id_token exceeds persona verification limit"
    );
    assert!(client.jwks.lock().await.last_fetch.is_none());
    assert_only_jwks_requests(&server, 0).await;
}

#[tokio::test]
async fn discovery_rejects_nonlocal_http_lookalikes_and_unsafe_endpoint_forms() {
    for endpoint in [
        "http://localhost.attacker.invalid/token",
        "http://127.0.0.1.attacker.invalid/token",
        "http://localhost@attacker.invalid/token",
        "http://127.0.0.10/token",
        "file:///tmp/token",
        "ftp://idp.example/token",
        "https://",
        "https://user:password@idp.example/token",
        "https://:password@idp.example/token",
        "https://idp.example/token#fragment",
    ] {
        for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let server = MockServer::start().await;
            let mut doc = serde_json::json!({"issuer":server.uri(), "authorization_endpoint":"https://idp.example/authorize",
                "token_endpoint":"https://idp.example/token", "jwks_uri":"https://keys.example/jwks"});
            doc[field] = endpoint.into();
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(doc))
                .mount(&server)
                .await;
            let result = OidcClient::discover(
                &server.uri(),
                "opaque-cli".into(),
                "opaque-cli".into(),
                reqwest::Client::new(),
            )
            .await;
            assert_eq!(
                result.err(),
                Some(format!("OIDC {field} has disallowed scheme")),
                "{endpoint}"
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].url.path(), "/.well-known/openid-configuration");
        }
    }
}

#[tokio::test]
async fn discovery_accepts_exact_loopback_and_separate_https_endpoints() {
    for endpoint in [
        "http://localhost:1234/path",
        "http://127.0.0.1:1234/path",
        "https://separate-idp.example/path",
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"issuer":server.uri(),
                "authorization_endpoint":endpoint,"token_endpoint":endpoint,"jwks_uri":endpoint})),
            )
            .mount(&server)
            .await;
        let client = OidcClient::discover(
            &server.uri(),
            "opaque-cli".into(),
            "opaque-cli".into(),
            reqwest::Client::new(),
        )
        .await
        .unwrap();
        assert_eq!(client.authorization_endpoint, endpoint);
        assert_eq!(client.token_endpoint, endpoint);
        assert_eq!(client.jwks_uri, endpoint);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
