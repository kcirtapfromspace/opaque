//! Stateful OIDC protocol double for real-daemon integration tests.
//!
//! The test driver supplies a synthetic subject instead of an interactive login.
//! Authorization codes still cross actual HTTP, bind a registered client/redirect
//! and S256 challenge, and can be redeemed successfully only once. ID tokens use
//! the repository's public test RSA key; no production authentication is replaced.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

const TEST_RSA_PEM: &str = include_str!("../fixtures/test_rsa_key.pem");
const TEST_JWKS: &str = include_str!("../fixtures/test_idp_jwks.json");

#[derive(Clone)]
pub struct TestIdentity {
    pub subject: String,
    pub email: String,
    /// Deliberately corrupt only the signed nonce for verifier rejection tests.
    pub token_nonce_override: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub codes_issued: usize,
    pub token_requests: usize,
    pub tokens_issued: usize,
    pub token_rejections: usize,
}

struct Grant {
    redirect_uri: String,
    challenge: String,
    nonce: String,
    identity: TestIdentity,
}

struct State {
    issuer: String,
    client_id: String,
    redirects: HashSet<String>,
    identities: HashMap<String, TestIdentity>,
    codes: HashMap<String, Grant>,
    counts: Counts,
}

pub struct MockOidc {
    server: MockServer,
    state: Arc<Mutex<State>>,
}

impl MockOidc {
    pub async fn start(client_id: &str) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let state = Arc::new(Mutex::new(State {
            issuer: issuer.clone(),
            client_id: client_id.into(),
            redirects: HashSet::new(),
            identities: HashMap::new(),
            codes: HashMap::new(),
            counts: Counts::default(),
        }));
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer, "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"), "jwks_uri": format!("{issuer}/jwks"),
                "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::from_str::<serde_json::Value>(TEST_JWKS).unwrap()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/authorize"))
            .respond_with(Authorization(state.clone()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(Token(state.clone()))
            .mount(&server)
            .await;
        Self { server, state }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Register the daemon's exact ephemeral loopback callback before issuing
    /// a browser request. Mutating that request does not register a new URI.
    pub fn register_redirect(&self, redirect: &str) {
        let url = reqwest::Url::parse(redirect).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.port().is_some());
        assert_eq!(url.path(), "/callback");
        assert!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        );
        self.state.lock().unwrap().redirects.insert(redirect.into());
    }

    /// Test-only subject selection represents the IdP login/consent result.
    pub fn select_identity(&self, state: &str, identity: TestIdentity) {
        assert!(
            self.state
                .lock()
                .unwrap()
                .identities
                .insert(state.into(), identity)
                .is_none()
        );
    }

    pub async fn authorize(&self, url: &str) -> reqwest::Response {
        let parsed = reqwest::Url::parse(url).unwrap();
        assert_eq!(
            parsed.origin(),
            reqwest::Url::parse(&self.uri()).unwrap().origin()
        );
        assert_eq!(parsed.path(), "/authorize");
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
            .get(parsed)
            .send()
            .await
            .unwrap()
    }

    pub fn counts(&self) -> Counts {
        self.state.lock().unwrap().counts
    }
}

fn unique_pairs(url: &reqwest::Url) -> Option<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if values
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    Some(values)
}

pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn error(code: &str) -> ResponseTemplate {
    // No submitted code, verifier, token or identity is reflected in errors.
    ResponseTemplate::new(400).set_body_json(json!({"error": code}))
}

struct Authorization(Arc<Mutex<State>>);
impl Respond for Authorization {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let Some(values) = unique_pairs(&request.url) else {
            return error("invalid_request");
        };
        let get = |key: &str| values.get(key).map(String::as_str).unwrap_or("");
        let mut state = self.0.lock().unwrap();
        if get("client_id") != state.client_id
            || !state.redirects.contains(get("redirect_uri"))
            || get("response_type") != "code"
            || get("code_challenge_method") != "S256"
            || !get("scope")
                .split_whitespace()
                .any(|scope| scope == "openid")
            || get("state").is_empty()
            || get("nonce").is_empty()
            || URL_SAFE_NO_PAD
                .decode(get("code_challenge"))
                .ok()
                .is_none_or(|bytes| bytes.len() != 32)
        {
            return error("invalid_request");
        }
        let Some(identity) = state.identities.remove(get("state")) else {
            return error("access_denied");
        };
        let code = uuid::Uuid::new_v4().to_string();
        state.codes.insert(
            code.clone(),
            Grant {
                redirect_uri: get("redirect_uri").into(),
                challenge: get("code_challenge").into(),
                nonce: get("nonce").into(),
                identity,
            },
        );
        state.counts.codes_issued += 1;
        let mut callback = reqwest::Url::parse(get("redirect_uri")).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", get("state"));
        ResponseTemplate::new(302).insert_header("location", callback.as_str())
    }
}

struct Token(Arc<Mutex<State>>);
impl Respond for Token {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut state = self.0.lock().unwrap();
        state.counts.token_requests += 1;
        let mut exchange = || -> Option<String> {
            if !request
                .headers
                .get("content-type")?
                .to_str()
                .ok()?
                .starts_with("application/x-www-form-urlencoded")
            {
                return None;
            }
            let body = std::str::from_utf8(&request.body).ok()?;
            let mut form_url = reqwest::Url::parse("http://fixture.invalid/").unwrap();
            form_url.set_query(Some(body));
            let values = unique_pairs(&form_url)?;
            let get = |key: &str| values.get(key).map(String::as_str).unwrap_or("");
            let verifier = get("code_verifier");
            if get("grant_type") != "authorization_code"
                || get("client_id") != state.client_id
                || !(43..=128).contains(&verifier.len())
                || !verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            {
                return None;
            }
            let grant = state.codes.get(get("code"))?;
            if get("redirect_uri") != grant.redirect_uri || challenge(verifier) != grant.challenge {
                return None;
            }
            // Validate and consume under the same lock: concurrent exchanges
            // can issue at most one token for this exact authorization code.
            let grant = state.codes.remove(get("code"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let claims = json!({"iss": state.issuer, "aud": state.client_id, "sub": grant.identity.subject,
                "email": grant.identity.email, "email_verified": true, "name": "Synthetic OIDC human",
                "nonce": grant.identity.token_nonce_override.unwrap_or(grant.nonce), "iat": now, "exp": now + 600});
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("test-key-1".into());
            let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();
            Some(jsonwebtoken::encode(&header, &claims, &key).unwrap())
        };
        match exchange() {
            Some(token) => {
                state.counts.tokens_issued += 1;
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token": "unused-synthetic-access-token",
                    "token_type": "Bearer", "id_token": token}))
            }
            None => {
                state.counts.token_rejections += 1;
                error("invalid_grant")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "stateful-fixture-client";
    const REDIRECT: &str = "http://127.0.0.1:31999/callback";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

    async fn authorization_fixture() -> (MockOidc, reqwest::Url) {
        let idp = MockOidc::start(CLIENT).await;
        idp.register_redirect(REDIRECT);
        idp.select_identity(
            "stateful-request",
            TestIdentity {
                subject: "test-subject".into(),
                email: "test@example.invalid".into(),
                token_nonce_override: None,
            },
        );
        let mut url = reqwest::Url::parse(&format!("{}/authorize", idp.uri())).unwrap();
        url.query_pairs_mut().extend_pairs([
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "openid email"),
            ("state", "stateful-request"),
            ("nonce", "signed-nonce"),
            ("code_challenge_method", "S256"),
            ("code_challenge", challenge(VERIFIER).as_str()),
        ]);
        (idp, url)
    }

    fn replace(url: &reqwest::Url, key: &str, replacement: &str) -> reqwest::Url {
        let mut changed = url.clone();
        let pairs: Vec<_> = url
            .query_pairs()
            .map(|(k, v)| {
                let v = if k == key {
                    replacement.to_owned()
                } else {
                    v.into_owned()
                };
                (k.into_owned(), v)
            })
            .collect();
        changed.query_pairs_mut().clear().extend_pairs(pairs);
        changed
    }

    async fn code(idp: &MockOidc, url: &reqwest::Url) -> String {
        let response = idp.authorize(url.as_str()).await;
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        let callback =
            reqwest::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        assert_eq!(
            callback
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1,
            "stateful-request"
        );
        callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned()
    }

    fn token_form(code: &str) -> Vec<(String, String)> {
        [
            ("client_id", CLIENT),
            ("redirect_uri", REDIRECT),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", VERIFIER),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }

    #[tokio::test]
    async fn stateful_idp_enforces_registered_authorization_and_exact_exchange_binding() {
        let (idp, authorization) = authorization_fixture().await;
        for (key, wrong) in [
            ("client_id", "foreign-client"),
            ("redirect_uri", "http://127.0.0.1:31998/callback"),
            ("code_challenge_method", "plain"),
            ("code_challenge", "not-a-sha256-challenge"),
        ] {
            let response = idp
                .authorize(replace(&authorization, key, wrong).as_str())
                .await;
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
            assert!(response.headers().get("location").is_none());
        }
        let mut duplicate = authorization.clone();
        duplicate.query_pairs_mut().append_pair("client_id", CLIENT);
        assert_eq!(
            idp.authorize(duplicate.as_str()).await.status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        assert_eq!(idp.counts(), Counts::default());
        let code = code(&idp, &authorization).await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        for (key, wrong) in [
            ("client_id", "foreign-client"),
            ("redirect_uri", "http://127.0.0.1:31998/callback"),
            (
                "code_verifier",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-wrong",
            ),
        ] {
            let mut form = token_form(&code);
            form.iter_mut().find(|(k, _)| k == key).unwrap().1 = wrong.into();
            let response = client
                .post(format!("{}/token", idp.uri()))
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap(),
                json!({"error":"invalid_grant"})
            );
        }
        let mut duplicate = token_form(&code);
        duplicate.push(("code".into(), code.clone()));
        assert_eq!(
            client
                .post(format!("{}/token", idp.uri()))
                .form(&duplicate)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        // Invalid exchanges cannot accidentally pass; the original exact
        // binding remains a positive control for those rejection cases.
        let response = client
            .post(format!("{}/token", idp.uri()))
            .form(&token_form(&code))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            idp.counts(),
            Counts {
                codes_issued: 1,
                token_requests: 5,
                tokens_issued: 1,
                token_rejections: 4
            }
        );
    }

    #[tokio::test]
    async fn stateful_idp_consumes_code_atomically_and_rejects_identical_replay() {
        let (idp, authorization) = authorization_fixture().await;
        let code = code(&idp, &authorization).await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let form = token_form(&code);
        let redeem = || {
            client
                .post(format!("{}/token", idp.uri()))
                .form(&form)
                .send()
        };
        let (first, second) = tokio::join!(redeem(), redeem());
        let mut statuses = [
            first.unwrap().status().as_u16(),
            second.unwrap().status().as_u16(),
        ];
        statuses.sort();
        assert_eq!(statuses, [200, 400]);
        assert_eq!(
            redeem().await.unwrap().status(),
            reqwest::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            idp.counts(),
            Counts {
                codes_issued: 1,
                token_requests: 3,
                tokens_issued: 1,
                token_rejections: 2
            }
        );
    }
}
