//! Minimal OIDC relying party: discovery, PKCE, JWKS, ID-token verification.
//!
//! Hand-rolled on `reqwest` + `jsonwebtoken` (the same pattern the provider
//! clients use for service JWTs) — deliberately no OAuth/OIDC crate. Only the
//! authorization-code + PKCE flow is supported, only RS256/ES256 tokens are
//! accepted, and the token endpoint is the sole consumer of the authorization
//! code (the code never leaves the daemon).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::persona::{PersonaConfig, VerifiedPersonaClaims};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Minimum interval between JWKS refetches triggered by unknown `kid`s.
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

/// Claims extracted from a verified ID token.
#[derive(Debug, Clone)]
pub struct VerifiedIdToken {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    /// Present only when opt-in persona verification has passed.
    pub persona: Option<VerifiedPersonaClaims>,
}

#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDoc {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksDoc {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

/// OIDC client bound to one issuer + client id.
pub struct OidcClient {
    issuer: String,
    client_id: String,
    audience: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    http: reqwest::Client,
    jwks: tokio::sync::Mutex<JwksCache>,
}

struct JwksCache {
    keys: HashMap<String, (Algorithm, DecodingKey)>,
    last_fetch: Option<Instant>,
}

impl OidcClient {
    /// Fetch `{issuer}/.well-known/openid-configuration` and validate it.
    pub async fn discover(
        issuer: &str,
        client_id: String,
        audience: String,
        http: reqwest::Client,
    ) -> Result<Self, String> {
        let url = format!("{}/.well-known/openid-configuration", issuer);
        let doc: DiscoveryDoc = http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("OIDC discovery request failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("OIDC discovery failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("OIDC discovery returned invalid JSON: {e}"))?;

        // RFC 8414 §3.3: the discovered issuer MUST match the configured one.
        if doc.issuer != issuer {
            return Err(format!(
                "OIDC discovery issuer mismatch: configured {issuer:?}, discovered {:?}",
                doc.issuer
            ));
        }
        for (name, endpoint) in [
            ("authorization_endpoint", &doc.authorization_endpoint),
            ("token_endpoint", &doc.token_endpoint),
            ("jwks_uri", &doc.jwks_uri),
        ] {
            if !(endpoint.starts_with("https://")
                || endpoint.starts_with("http://127.0.0.1")
                || endpoint.starts_with("http://localhost"))
            {
                return Err(format!("OIDC {name} has disallowed scheme"));
            }
        }

        Ok(Self {
            issuer: issuer.to_owned(),
            client_id,
            audience,
            authorization_endpoint: doc.authorization_endpoint,
            token_endpoint: doc.token_endpoint,
            jwks_uri: doc.jwks_uri,
            http,
            jwks: tokio::sync::Mutex::new(JwksCache {
                keys: HashMap::new(),
                last_fetch: None,
            }),
        })
    }

    /// Build the authorization URL for the browser step.
    pub fn build_auth_url(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
        redirect_uri: &str,
    ) -> String {
        self.auth_url_for_scope(
            state,
            nonce,
            code_challenge,
            redirect_uri,
            "openid email profile",
        )
    }

    pub fn build_auth_url_with_persona(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
        redirect_uri: &str,
        persona: &PersonaConfig,
    ) -> Result<String, String> {
        persona.validate()?;
        Ok(format!(
            "{}&max_age={}",
            self.auth_url_for_scope(
                state,
                nonce,
                code_challenge,
                redirect_uri,
                "openid email profile groups"
            ),
            persona.max_age_secs,
        ))
    }

    fn auth_url_for_scope(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
        redirect_uri: &str,
        scope: &str,
    ) -> String {
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            self.authorization_endpoint,
            urlencode(&self.client_id),
            urlencode(redirect_uri),
            urlencode(scope),
            urlencode(state),
            urlencode(nonce),
            urlencode(code_challenge),
        )
    }

    /// Exchange an authorization code (PKCE) for an ID token.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<String, String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }

        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &self.client_id),
            ("code_verifier", code_verifier),
        ];
        let resp = self
            .http
            .post(&self.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("token exchange request failed: {e}"))?;
        if !resp.status().is_success() {
            // Do not echo the response body — it may reflect the code.
            return Err(format!("token endpoint returned {}", resp.status()));
        }
        let tokens: TokenResponse = resp
            .json()
            .await
            .map_err(|_| "token endpoint returned invalid JSON".to_string())?;
        Ok(tokens.id_token)
    }

    /// Verify an ID token: allowed alg, known kid, signature, iss, aud,
    /// exp (60s leeway), and the expected nonce. Persona mode additionally
    /// requires strictly fresh signed iat/auth_time and bounded exact groups.
    pub async fn verify_id_token(
        &self,
        raw: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdToken, String> {
        self.verify_token(raw, expected_nonce, None).await
    }

    pub async fn verify_id_token_with_persona(
        &self,
        raw: &str,
        expected_nonce: &str,
        persona: &PersonaConfig,
    ) -> Result<VerifiedIdToken, String> {
        persona.validate()?;
        if raw.len() > 64 * 1024 {
            return Err("id_token exceeds persona verification limit".into());
        }
        self.verify_token(raw, expected_nonce, Some(persona)).await
    }

    async fn verify_token(
        &self,
        raw: &str,
        expected_nonce: &str,
        persona: Option<&PersonaConfig>,
    ) -> Result<VerifiedIdToken, String> {
        let header =
            jsonwebtoken::decode_header(raw).map_err(|_| "id_token header invalid".to_string())?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
            return Err(format!("id_token alg {:?} not allowed", header.alg));
        }
        let kid = header
            .kid
            .ok_or_else(|| "id_token missing kid".to_string())?;

        let key = self.resolve_key(&kid, header.alg).await?;

        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 60;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        #[derive(Deserialize)]
        struct Claims {
            sub: String,
            #[serde(default)]
            nonce: Option<String>,
            #[serde(default)]
            email: Option<String>,
            #[serde(default)]
            name: Option<String>,
            #[serde(flatten)]
            extra: serde_json::Map<String, serde_json::Value>,
        }

        let data = jsonwebtoken::decode::<Claims>(raw, &key, &validation)
            .map_err(|e| format!("id_token verification failed: {e}"))?;

        match data.claims.nonce.as_deref() {
            Some(n) if n == expected_nonce => {}
            _ => return Err("id_token nonce mismatch".into()),
        }

        // This map came from the successful signature/issuer/audience/nonce
        // verification above. Never decode a second, unverified token payload.
        let verified_persona = persona
            .map(|config| {
                VerifiedPersonaClaims::from_verified_claims(
                    &self.issuer,
                    &data.claims.sub,
                    config,
                    &data.claims.extra,
                    opaque_core::identity::now_unix(),
                )
            })
            .transpose()?;

        Ok(VerifiedIdToken {
            sub: data.claims.sub,
            email: data.claims.email,
            name: data.claims.name,
            persona: verified_persona,
        })
    }

    /// Look up a decoding key by kid, refetching the JWKS at most once per
    /// cooldown window when the kid is unknown.
    async fn resolve_key(&self, kid: &str, alg: Algorithm) -> Result<DecodingKey, String> {
        let mut cache = self.jwks.lock().await;
        if let Some((key_alg, key)) = cache.keys.get(kid) {
            if *key_alg == alg {
                return Ok(key.clone());
            }
            return Err("id_token alg does not match JWKS key type".into());
        }

        let may_refresh = cache
            .last_fetch
            .is_none_or(|t| t.elapsed() >= JWKS_REFRESH_COOLDOWN);
        if !may_refresh {
            return Err("id_token kid unknown (JWKS refresh throttled)".into());
        }

        let doc: JwksDoc = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .json()
            .await
            .map_err(|_| "JWKS invalid JSON".to_string())?;

        cache.last_fetch = Some(Instant::now());
        cache.keys.clear();
        for jwk in &doc.keys {
            let Some(id) = jwk.kid.clone() else { continue };
            match jwk.kty.as_str() {
                "RSA" => {
                    if let (Some(n), Some(e)) = (&jwk.n, &jwk.e)
                        && let Ok(key) = DecodingKey::from_rsa_components(n, e)
                    {
                        cache.keys.insert(id, (Algorithm::RS256, key));
                    }
                }
                "EC" => {
                    if jwk.crv.as_deref() == Some("P-256")
                        && let (Some(x), Some(y)) = (&jwk.x, &jwk.y)
                        && let Ok(key) = DecodingKey::from_ec_components(x, y)
                    {
                        cache.keys.insert(id, (Algorithm::ES256, key));
                    }
                }
                _ => {}
            }
        }

        match cache.keys.get(kid) {
            Some((key_alg, key)) if *key_alg == alg => Ok(key.clone()),
            Some(_) => Err("id_token alg does not match JWKS key type".into()),
            None => Err("id_token kid not present in JWKS".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// PKCE + randomness helpers
// ---------------------------------------------------------------------------

/// A random base64url string from `bytes` CSPRNG bytes.
pub fn random_urlsafe(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("csprng failure");
    URL_SAFE_NO_PAD.encode(&buf)
}

/// PKCE S256 code challenge for a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Percent-encode a query component (RFC 3986 unreserved set kept).
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Percent-decode a query component (`+` treated as space).
pub fn urldecode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                let v = u8::from_str_radix(hex, 16).ok()?;
                out.push(v);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(crate) const TEST_RSA_PEM: &str = include_str!("../../tests/fixtures/test_rsa_key.pem");
    pub(crate) const TEST_JWKS: &str = include_str!("../../tests/fixtures/test_idp_jwks.json");

    /// Mount a discovery doc + JWKS on a fresh mock IdP and discover it.
    pub(crate) async fn mock_idp() -> (MockServer, OidcClient) {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let client = OidcClient::discover(
            &server.uri(),
            "opaque-cli".into(),
            "opaque-cli".into(),
            reqwest::Client::new(),
        )
        .await
        .expect("discovery should succeed");
        (server, client)
    }

    pub(crate) async fn mount_discovery(server: &MockServer, issuer: &str) {
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::from_str::<serde_json::Value>(TEST_JWKS).unwrap()),
            )
            .mount(server)
            .await;
    }

    /// Sign an id_token with the fixture RSA key.
    pub(crate) fn sign_id_token(claims: serde_json::Value, kid: &str) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    pub(crate) fn base_claims(issuer: &str, nonce: &str) -> serde_json::Value {
        let now = opaque_core::identity::now_unix();
        serde_json::json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": "opaque-cli",
            "exp": now + 600,
            "iat": now,
            "nonce": nonce,
            "email": "dev@example.com",
            "name": "Dev Example",
        })
    }

    #[tokio::test]
    async fn discovery_rejects_issuer_mismatch() {
        let server = MockServer::start().await;
        mount_discovery(&server, "https://someone-else.example.com").await;
        let err = OidcClient::discover(
            &server.uri(),
            "opaque-cli".into(),
            "opaque-cli".into(),
            reqwest::Client::new(),
        )
        .await
        .err()
        .expect("discovery must fail on issuer mismatch");
        assert!(err.contains("issuer mismatch"), "{err}");
    }

    #[tokio::test]
    async fn verify_accepts_valid_rs256_token() {
        let (server, client) = mock_idp().await;
        let token = sign_id_token(base_claims(&server.uri(), "nonce-1"), "test-key-1");
        let verified = client.verify_id_token(&token, "nonce-1").await.unwrap();
        assert_eq!(verified.sub, "user-123");
        assert_eq!(verified.email.as_deref(), Some("dev@example.com"));
        assert_eq!(verified.name.as_deref(), Some("Dev Example"));
        assert!(verified.persona.is_none());
    }

    #[tokio::test]
    async fn persona_groups_are_extracted_only_after_signed_token_verification() {
        let (server, client) = mock_idp().await;
        let config = PersonaConfig {
            groups_claim: "organization_groups".into(),
            max_age_secs: 60,
        };
        let now = opaque_core::identity::now_unix();
        let mut claims = base_claims(&server.uri(), "persona-nonce");
        claims["organization_groups"] = serde_json::json!(["reviewers"]);
        claims["auth_time"] = serde_json::json!(now);
        let token = sign_id_token(claims.clone(), "test-key-1");
        assert!(
            client
                .verify_id_token_with_persona(&token, "persona-nonce", &config)
                .await
                .unwrap()
                .persona
                .is_some()
        );
        // A valid signed token followed by payload substitution must not refresh
        // persona evidence, even if the replacement claims have the right shape.
        let parts: Vec<_> = token.split('.').collect();
        claims["organization_groups"] = serde_json::json!(["administrators"]);
        let altered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
            parts[2]
        );
        assert!(
            client
                .verify_id_token_with_persona(&altered, "persona-nonce", &config)
                .await
                .is_err()
        );
        for (field, replacement) in [
            ("auth_time", serde_json::Value::Null),
            ("auth_time", serde_json::json!(now - 120)),
            ("auth_time", serde_json::json!(now + 120)),
            ("iat", serde_json::json!(now + 120)),
            ("exp", serde_json::json!(now - 1)),
            ("organization_groups", serde_json::Value::Null),
            ("organization_groups", serde_json::json!(["reviewers", 1])),
        ] {
            let mut invalid = claims.clone();
            invalid[field] = replacement;
            let signed = sign_id_token(invalid, "test-key-1");
            assert!(
                client
                    .verify_id_token_with_persona(&signed, "persona-nonce", &config)
                    .await
                    .is_err(),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn regular_login_keeps_optional_persona_claims_and_authentication_behavior() {
        let (server, client) = mock_idp().await;
        let mut claims = base_claims(&server.uri(), "nonce");
        claims.as_object_mut().unwrap().remove("iat");
        let token = sign_id_token(claims, "test-key-1");
        assert!(
            client
                .verify_id_token(&token, "nonce")
                .await
                .unwrap()
                .persona
                .is_none()
        );
        let regular = client.build_auth_url("s", "n", "c", "http://127.0.0.1:1/callback");
        assert!(!regular.contains("max_age="));
        assert!(regular.contains("scope=openid%20email%20profile&"));
        let persona = PersonaConfig {
            groups_claim: "groups".into(),
            max_age_secs: 60,
        };
        let fresh = client
            .build_auth_url_with_persona("s", "n", "c", "http://127.0.0.1:1/callback", &persona)
            .unwrap();
        assert!(fresh.contains("scope=openid%20email%20profile%20groups&"));
        assert!(fresh.ends_with("&max_age=60"));
    }

    #[tokio::test]
    async fn verify_rejects_wrong_issuer_claim() {
        let (server, client) = mock_idp().await;
        let mut claims = base_claims(&server.uri(), "n");
        claims["iss"] = serde_json::json!("https://evil.example.com");
        let token = sign_id_token(claims, "test-key-1");
        assert!(client.verify_id_token(&token, "n").await.is_err());
    }

    #[tokio::test]
    async fn verify_rejects_wrong_audience() {
        let (server, client) = mock_idp().await;
        let mut claims = base_claims(&server.uri(), "n");
        claims["aud"] = serde_json::json!("someone-else");
        let token = sign_id_token(claims, "test-key-1");
        assert!(client.verify_id_token(&token, "n").await.is_err());
    }

    #[tokio::test]
    async fn verify_rejects_wrong_nonce() {
        let (server, client) = mock_idp().await;
        let token = sign_id_token(base_claims(&server.uri(), "nonce-a"), "test-key-1");
        let err = client.verify_id_token(&token, "nonce-b").await.unwrap_err();
        assert!(err.contains("nonce"), "{err}");
    }

    #[tokio::test]
    async fn verify_rejects_missing_nonce() {
        let (server, client) = mock_idp().await;
        let mut claims = base_claims(&server.uri(), "x");
        claims.as_object_mut().unwrap().remove("nonce");
        let token = sign_id_token(claims, "test-key-1");
        assert!(client.verify_id_token(&token, "x").await.is_err());
    }

    #[tokio::test]
    async fn verify_rejects_expired_token() {
        let (server, client) = mock_idp().await;
        let mut claims = base_claims(&server.uri(), "n");
        let now = opaque_core::identity::now_unix();
        claims["exp"] = serde_json::json!(now - 3600);
        let token = sign_id_token(claims, "test-key-1");
        assert!(client.verify_id_token(&token, "n").await.is_err());
    }

    #[tokio::test]
    async fn verify_rejects_unknown_kid() {
        let (server, client) = mock_idp().await;
        let token = sign_id_token(base_claims(&server.uri(), "n"), "other-key");
        let err = client.verify_id_token(&token, "n").await.unwrap_err();
        assert!(err.contains("kid"), "{err}");
    }

    #[tokio::test]
    async fn verify_rejects_hs256() {
        let (server, client) = mock_idp().await;
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.kid = Some("test-key-1".into());
        let token = jsonwebtoken::encode(
            &header,
            &base_claims(&server.uri(), "n"),
            &jsonwebtoken::EncodingKey::from_secret(b"shared"),
        )
        .unwrap();
        let err = client.verify_id_token(&token, "n").await.unwrap_err();
        assert!(err.contains("not allowed"), "{err}");
    }

    #[tokio::test]
    async fn verify_rejects_tampered_signature() {
        let (server, client) = mock_idp().await;
        let token = sign_id_token(base_claims(&server.uri(), "n"), "test-key-1");
        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2].to_owned();
        let flipped = match sig.strip_prefix('A') {
            Some(rest) => format!("B{rest}"),
            None => format!("A{}", &sig[1..]),
        };
        parts[2] = &flipped;
        let tampered = parts.join(".");
        assert!(client.verify_id_token(&tampered, "n").await.is_err());
    }

    #[tokio::test]
    async fn exchange_code_posts_pkce_form() {
        let (server, client) = mock_idp().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(wiremock::matchers::body_string_contains("code=the-code"))
            .and(wiremock::matchers::body_string_contains(
                "code_verifier=the-verifier",
            ))
            .and(wiremock::matchers::body_string_contains(
                "grant_type=authorization_code",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id_token": "tok"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let id_token = client
            .exchange_code("the-code", "the-verifier", "http://127.0.0.1:1/callback")
            .await
            .unwrap();
        assert_eq!(id_token, "tok");
    }

    #[tokio::test]
    async fn exchange_code_error_does_not_echo_body() {
        let (server, client) = mock_idp().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("error=invalid_grant&code=SECRETCODE"),
            )
            .mount(&server)
            .await;
        let err = client
            .exchange_code("c", "v", "http://127.0.0.1:1/callback")
            .await
            .unwrap_err();
        assert!(
            !err.contains("SECRETCODE"),
            "error must not echo body: {err}"
        );
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_urlsafe_lengths_and_uniqueness() {
        let a = random_urlsafe(32);
        let b = random_urlsafe(32);
        assert_ne!(a, b);
        assert_eq!(a.len(), 43); // ceil(32*4/3) unpadded
        let v = random_urlsafe(48);
        assert_eq!(v.len(), 64); // PKCE verifier length
    }

    #[test]
    fn urlencode_decode_roundtrip() {
        let raw = "a b&c=d%e/f+g:h?i#j";
        let enc = urlencode(raw);
        assert!(!enc.contains(' ') && !enc.contains('&') && !enc.contains('#'));
        assert_eq!(urldecode(&enc).unwrap(), raw);
    }

    #[test]
    fn urldecode_rejects_bad_percent() {
        assert!(urldecode("%").is_none());
        assert!(urldecode("%2").is_none());
        assert!(urldecode("%zz").is_none());
        assert_eq!(urldecode("%2B").unwrap(), "+");
        assert_eq!(urldecode("plain").unwrap(), "plain");
    }
}
