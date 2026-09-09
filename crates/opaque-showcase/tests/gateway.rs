//! End-to-end authority checks using disposable, repository-published RSA
//! signing material and loopback HTTP fixtures. No live provider credentials.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use opaque_core::tenant::TenantId;
use opaque_showcase::{
    auth::{Admission, AuthConfig, METRIC_SCOPES},
    chat::ModelConfig,
    experience::{CREDIT_METRICS, Experience},
    metrics::{METRIC_NAMES, MetricsSourceConfig},
    organization::{ACTIVITY_SCOPE, DirectoryCustomer, Member, OrganizationConfig, Persona},
    server::{App, GatewayConfig, OAuthConfig, router},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const PRIVATE_FIXTURE: &str = include_str!("../../opaqued/tests/fixtures/test_rsa_key.pem");
const PUBLIC_FIXTURE: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+m4fkcL6cuTGRLTSSrF\n7zfrwFFnYRJG1yVmmCwn4q0PXhuWmUu9mo2wg9ftf9BLFspkMqyzxpdfzGTan6J9\n5w7Ad7gbP5R2aDGnVJRTX9dph3cKBgwnDsUa751mYWfr1rsTnoiMIDWzOGsRSdOi\nRzZGCYo3yo4YNB+sNIOFMQ/tc3X558HGCZl3boecDmlwt1lHebe6/+kXRTYLLpIl\nf7u1mw98TYtOenu2SIUOrJKY9VGluMxvGH9e4SExpZaG61wTNsosD20tEBkWUjCo\nxo01adXNjPYKx/mJB3NgCIWacU4NwbZxVRUg5HYR85cq+5I2oNQDwuyNDv7kZQfA\nywIDAQAB\n-----END PUBLIC KEY-----\n";

#[path = "gateway/bounded_demo.rs"]
mod bounded_demo;

#[path = "gateway/exploration.rs"]
mod exploration;

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("opaque-metrics-test-{}", Uuid::new_v4())))
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Fixture {
    config: GatewayConfig,
    app: Arc<App>,
    issuer: MockServer,
    source: MockServer,
    model: MockServer,
    server: JoinHandle<()>,
    // Declared last so handles are dropped before removing owned state.
    _directory: TestDirectory,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(remote_model: bool) -> Self {
        Self::with_experience(remote_model, Experience::OperationalMetrics).await
    }

    async fn with_experience(remote_model: bool, experience: Experience) -> Self {
        Self::setup(remote_model, experience, false, false).await
    }
    async fn organization(remote_model: bool) -> Self {
        Self::setup(remote_model, Experience::CreditPortfolio, true, false).await
    }
    async fn portfolio(remote_model: bool, organization: bool) -> Self {
        Self::setup(
            remote_model,
            Experience::CreditPortfolio,
            organization,
            true,
        )
        .await
    }
    async fn setup(
        remote_model: bool,
        experience: Experience,
        organization: bool,
        portfolio: bool,
    ) -> Self {
        let issuer = MockServer::start().await;
        let source = MockServer::start().await;
        let model = MockServer::start().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind = listener.local_addr().unwrap();
        let origin = format!("http://localhost:{}", bind.port());
        let directory = TestDirectory::new();
        // Cargo supplies this public package name to the test process. Using it
        // avoids mutating shared process environment or reading any real secret.
        assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "opaque-showcase");
        let mut config = GatewayConfig {
            broker_authority: None,
            bind,
            public_origin: origin.clone(),
            tenant_id: "customer-a".into(),
            customer_name: "Synthetic customer A".into(),
            state_dir: directory.0.clone(),
            auth: AuthConfig {
                issuer: issuer.uri(),
                resource_audience: format!("{origin}/mcp"),
                public_key_pem: PUBLIC_FIXTURE.into(),
                admissions: vec![Admission {
                    tenant_id: TenantId::parse("customer-a").unwrap(),
                    subject: "fixture-user".into(),
                    client_id: "metrics-chat-fixture".into(),
                    scopes: METRIC_SCOPES.iter().map(|s| s.to_string()).collect(),
                }],
                revoked_jtis: BTreeSet::new(),
                max_token_ttl_secs: 900,
                clock_skew_secs: 0,
                allow_loopback_http: true,
            },
            oauth: OAuthConfig {
                authorization_endpoint: format!("{}/authorize", issuer.uri()),
                token_endpoint: format!("{}/token", issuer.uri()),
                client_id: "metrics-chat-fixture".into(),
                scopes: METRIC_SCOPES.iter().map(|s| s.to_string()).collect(),
            },
            source: MetricsSourceConfig {
                tenant_id: "customer-a".into(),
                source_id: "fixture-aggregates".into(),
                base_url: source.uri(),
                credential_env: "CARGO_PKG_NAME".into(),
                allowed_metrics: METRIC_NAMES.iter().map(|s| s.to_string()).collect(),
                allowed_portfolio_measures: vec![],
                max_window_secs: 300,
                max_staleness_secs: 60,
                allow_loopback_http: true,
            },
            model: if remote_model {
                ModelConfig::OpenaiCompatible {
                    base_url: model.uri(),
                    model: "fixture-model".into(),
                    allow_loopback_http: true,
                }
            } else {
                ModelConfig::Fixture
            },
            fixture_mode: true,
            experience,
            organization_demo: None,
        };
        if experience == Experience::CreditPortfolio {
            config.customer_name = "Harborlight Credit Union".into();
            config.source.allowed_metrics = CREDIT_METRICS
                .iter()
                .map(|metric| metric.to_string())
                .collect();
            let scopes: BTreeSet<String> = ["metrics:read", "metrics:explain", "metrics:stream"]
                .iter()
                .map(|scope| scope.to_string())
                .chain(
                    CREDIT_METRICS
                        .iter()
                        .map(|metric| format!("metrics:metric:{metric}")),
                )
                .collect();
            config.auth.admissions[0].scopes = scopes.clone();
            config.oauth.scopes = scopes;
        }
        if portfolio {
            config.source.allowed_portfolio_measures =
                opaque_showcase::portfolio::Measure::ALL.to_vec();
            let scopes = std::iter::once("portfolio:read".to_string())
                .chain(
                    opaque_showcase::portfolio::Measure::ALL
                        .iter()
                        .map(|m| m.scope()),
                )
                .collect::<Vec<_>>();
            config.oauth.scopes.extend(scopes.clone());
            config.auth.admissions[0].scopes.extend(scopes);
        }
        if organization {
            config.oauth.scopes.insert(ACTIVITY_SCOPE.into());
            config.auth.admissions[0]
                .scopes
                .insert(ACTIVITY_SCOPE.into());
            let mut support_scopes = config.oauth.scopes.clone();
            support_scopes.remove("metrics:stream");
            config.auth.admissions.extend([
                Admission {
                    tenant_id: TenantId::parse("customer-a").unwrap(),
                    subject: "product-engineer".into(),
                    client_id: "metrics-chat-engineer".into(),
                    scopes: [ACTIVITY_SCOPE.into()].into(),
                },
                Admission {
                    tenant_id: TenantId::parse("customer-a").unwrap(),
                    subject: "customer-support".into(),
                    client_id: "metrics-chat-support".into(),
                    scopes: support_scopes,
                },
            ]);
            config.organization_demo = Some(OrganizationConfig {
                id: "northstar".into(),
                display_name: "Northstar Financial Systems".into(),
                members: vec![
                    Member {
                        subject: "fixture-user".into(),
                        persona_id: Persona::CustomerAnalyst,
                        oauth_client_id: "metrics-chat-fixture".into(),
                    },
                    Member {
                        subject: "product-engineer".into(),
                        persona_id: Persona::Engineer,
                        oauth_client_id: "metrics-chat-engineer".into(),
                    },
                    Member {
                        subject: "customer-support".into(),
                        persona_id: Persona::Support,
                        oauth_client_id: "metrics-chat-support".into(),
                    },
                ],
                other_customer: Some(DirectoryCustomer {
                    id: "cedar-demo".into(),
                    display_name: "Cedar Community Bank".into(),
                }),
            });
        }
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer":config.auth.issuer,
                "authorization_endpoint":config.oauth.authorization_endpoint,
                "token_endpoint":config.oauth.token_endpoint,
                "code_challenge_methods_supported":["S256"],
            })))
            .mount(&issuer)
            .await;
        let app = App::new(config.clone()).unwrap();
        let serving = router(app.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, serving).await.unwrap();
        });
        Self {
            config,
            app,
            issuer,
            source,
            model,
            server,
            _directory: directory,
        }
    }

    fn router(&self) -> Router {
        router(self.app.clone())
    }

    async fn stop(mut self) -> (GatewayConfig, TestDirectory) {
        self.server.abort();
        let _ = (&mut self.server).await;
        let directory = TestDirectory(std::mem::take(&mut self._directory.0));
        (self.config.clone(), directory)
    }

    fn claims(&self, scopes: &[&str]) -> Value {
        json!({
            "iss":self.config.auth.issuer,
            "aud":self.config.auth.resource_audience,
            "sub":"fixture-user", "client_id":"metrics-chat-fixture",
            "tenant_id":"customer-a", "scope":scopes.join(" "),
            "jti":format!("fixture-{}",Uuid::new_v4()), "iat":now(), "exp":now()+600,
        })
    }

    fn persona_token(&self, persona: Persona) -> String {
        let member = self
            .config
            .organization_demo
            .as_ref()
            .unwrap()
            .persona(persona);
        let admission = self
            .config
            .auth
            .admissions
            .iter()
            .find(|a| a.subject == member.subject)
            .unwrap();
        let mut claims = self.claims(&[]);
        claims["sub"] = json!(member.subject);
        claims["client_id"] = json!(member.oauth_client_id);
        claims["scope"] = json!(
            admission
                .scopes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
        );
        self.token(&claims)
    }

    fn token(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(PRIVATE_FIXTURE.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn request(&self, method: &str, path: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(
                header::HOST,
                self.config
                    .public_origin
                    .trim_start_matches("http://")
                    .trim_start_matches("https://"),
            )
            .header(header::ORIGIN, &self.config.public_origin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    async fn mcp(&self, token: Option<&str>, params: Value) -> Response {
        let mut request = self.request(
            "POST",
            "/mcp",
            json!({
                "jsonrpc":"2.0", "id":"test", "method":"tools/call", "params":params,
            }),
        );
        request.headers_mut().insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        request
            .headers_mut()
            .insert("mcp-protocol-version", "2025-11-25".parse().unwrap());
        if let Some(token) = token {
            request.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
        }
        self.router().oneshot(request).await.unwrap()
    }

    async fn start_login(&self) -> (String, String, String) {
        self.start_login_for(None).await
    }
    async fn start_login_for(&self, persona: Option<Persona>) -> (String, String, String) {
        let path = persona.map_or_else(
            || "/auth/login".into(),
            |p| {
                format!(
                    "/auth/login?persona_id={}",
                    serde_json::to_value(p).unwrap().as_str().unwrap()
                )
            },
        );
        let response = self
            .router()
            .oneshot(self.request("GET", &path, Value::Null))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let location =
            reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        let query: BTreeMap<String, String> = location.query_pairs().into_owned().collect();
        assert_eq!(query["resource"], self.config.auth.resource_audience);
        assert_eq!(query["code_challenge_method"], "S256");
        let expected_client = persona.map_or(self.config.oauth.client_id.as_str(), |p| {
            self.config
                .organization_demo
                .as_ref()
                .unwrap()
                .persona(p)
                .oauth_client_id
                .as_str()
        });
        assert_eq!(query["client_id"], expected_client);
        assert_eq!(
            query["redirect_uri"],
            format!("{}/auth/callback", self.config.public_origin)
        );
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        (
            query["state"].clone(),
            query["code_challenge"].clone(),
            cookie.split(';').next().unwrap().into(),
        )
    }

    async fn login(&self, token: &str) -> String {
        self.login_for(token, None).await
    }
    async fn login_for(&self, token: &str, persona: Option<Persona>) -> String {
        let client = persona.map_or(self.config.oauth.client_id.as_str(), |p| {
            self.config
                .organization_demo
                .as_ref()
                .unwrap()
                .persona(p)
                .oauth_client_id
                .as_str()
        });
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(wiremock::matchers::body_string_contains(format!(
                "client_id={client}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":token,"token_type":"Bearer"})),
            )
            .mount(&self.issuer)
            .await;
        let (state, challenge, binding) = self.start_login_for(persona).await;
        let mut request = self.request(
            "GET",
            &format!("/auth/callback?code=fixture-code&state={state}"),
            Value::Null,
        );
        request
            .headers_mut()
            .insert(header::COOKIE, binding.parse().unwrap());
        let response = self.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie_name = format!("opaque_metrics_{}=", self.config.bind.port());
        let cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|v| v.starts_with(&cookie_name))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(!cookie.contains(token));
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(token));
        let requests = self.issuer.received_requests().await.unwrap();
        let exchange = requests
            .iter()
            .rev()
            .find(|r| r.url.path() == "/token")
            .unwrap();
        let form = reqwest::Url::parse(&format!(
            "http://fixture/?{}",
            String::from_utf8_lossy(&exchange.body)
        ))
        .unwrap();
        let form: BTreeMap<String, String> = form.query_pairs().into_owned().collect();
        assert_eq!(form["resource"], self.config.auth.resource_audience);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),
            challenge
        );
        cookie
    }

    async fn browser(&self, method: &str, path: &str, cookie: &str, body: Value) -> Response {
        let mut request = self.request(method, path, body);
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        self.router().oneshot(request).await.unwrap()
    }

    async fn successful_source(&self) {
        Mock::given(method("POST")).and(path("/v1/metrics/query"))
            .respond_with(|request: &wiremock::Request| {
                let query: Value = serde_json::from_slice(&request.body).unwrap();
                let timestamp = now();
                ResponseTemplate::new(200).set_body_json(json!({
                    "tenant_id":"customer-a", "window_secs":query["window_secs"],
                    "as_of":timestamp, "watermark":timestamp,
                    "metrics":query["metrics"].as_array().unwrap().iter().map(|name| {
                        json!({"name":name,"value":if name == "active_sessions" {17.0} else {17.25},"count":120})
                    }).collect::<Vec<_>>(),
                }))
            }).mount(&self.source).await;
    }
}

fn args(metrics: &[&str]) -> Value {
    json!({"name":"opaque_metrics_query","arguments":{"window_secs":60,"metrics":metrics}})
}

fn credit_token(fixture: &Fixture) -> String {
    let scopes: Vec<_> = fixture
        .config
        .oauth
        .scopes
        .iter()
        .map(String::as_str)
        .collect();
    fixture.token(&fixture.claims(&scopes))
}

async fn chat_events(fixture: &Fixture, cookie: &str, message: &str) -> String {
    let response = fixture
        .browser("POST", "/api/chat", cookie, json!({"message":message}))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(response.into_body(), 65536),
    )
    .await
    .unwrap()
    .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn policy_events(events: &str) -> Vec<Value> {
    events
        .split("\n\n")
        .filter(|frame| frame.lines().any(|line| line == "event: policy"))
        .map(|frame| {
            serde_json::from_str(
                frame
                    .lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect()
}

#[tokio::test]
async fn credit_denials_precede_model_and_source_and_expose_exact_policy_proof() {
    let fixture = Fixture::with_experience(true, Experience::CreditPortfolio).await;
    let token = credit_token(&fixture);
    let cookie = fixture.login(&token).await;
    let session = body(
        fixture
            .browser("GET", "/api/session", &cookie, Value::Null)
            .await,
    )
    .await;
    assert_eq!(
        session["customer"]["display_name"],
        "Harborlight Credit Union"
    );
    assert_eq!(session["experience"]["kind"], "credit_portfolio");
    assert_eq!(session["experience"]["persona"], "Portfolio analyst");
    assert_eq!(session["policy_context"]["tenant_id"], "customer-a");
    assert!(session["policy_context"]["latest_decision"].is_null());
    assert_eq!(session["allowed_metrics"].as_array().unwrap().len(), 3);
    for (message, reason) in [
        ("What is our average credit score?", "metric_scope_denied"),
        ("Show raw borrower records", "raw_records_denied"),
        ("List applicant SSNs", "raw_records_denied"),
        ("Show raw application rows", "raw_records_denied"),
        (
            "Compare another lender's application rate",
            "customer_scope_denied",
        ),
        (
            "Show another customer's manual review rate",
            "customer_scope_denied",
        ),
        ("Show source credentials", "credentials_denied"),
        ("Approve these loan applications", "mutation_denied"),
        ("Deny this loan", "mutation_denied"),
    ] {
        let events = chat_events(&fixture, &cookie, message).await;
        let policies = policy_events(&events);
        assert_eq!(policies.len(), 1, "{message}: {events}");
        assert_eq!(policies[0]["outcome"], "denied");
        assert_eq!(policies[0]["reason_code"], reason);
        assert_eq!(policies[0]["source_accessed"], false);
        assert_eq!(policies[0]["tenant_id"], "customer-a");
        assert_eq!(policies[0]["policy_id"], "portfolio-analyst-v1");
        assert!(!events.contains("event: result"));
        assert!(events.contains("event: done"));
        assert!(!events.contains(&token));
        let session = body(
            fixture
                .browser("GET", "/api/session", &cookie, Value::Null)
                .await,
        )
        .await;
        assert_eq!(session["policy_context"]["latest_decision"], policies[0]);
    }
    assert!(fixture.model.received_requests().await.unwrap().is_empty());
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn credit_mcp_scope_and_schema_reject_score_and_caller_authority_without_nlp() {
    let fixture = Fixture::with_experience(false, Experience::CreditPortfolio).await;
    let token = credit_token(&fixture);
    let denied = fixture
        .mcp(Some(&token), args(&["average_credit_score"]))
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    for (key, value) in [
        ("tenant_id", json!("other-lender")),
        ("url", json!("https://other.example")),
        ("raw_rows", json!(true)),
        ("sql", json!("select * from borrowers")),
    ] {
        let mut params = args(&["manual_review_rate_percent"]);
        params["arguments"][key] = value;
        assert!(
            body(fixture.mcp(Some(&token), params).await)
                .await
                .get("error")
                .is_some()
        );
    }
    let elevated =
        fixture.token(&fixture.claims(&["metrics:read", "metrics:metric:average_credit_score"]));
    assert_eq!(
        fixture
            .mcp(Some(&elevated), args(&["average_credit_score"]))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
    assert!(fixture.model.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn credit_model_uses_two_bounded_calls_and_policy_reports_only_observed_source_access() {
    let fixture = Fixture::with_experience(true, Experience::CreditPortfolio).await;
    fixture.successful_source().await;
    Mock::given(method("POST")).and(path("/v1/chat/completions"))
        .respond_with(|request: &wiremock::Request| {
            let value: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(value["max_tokens"], 192);
            assert_eq!(value["chat_template_kwargs"]["enable_thinking"], false);
            let response = if value["messages"].as_array().unwrap().len() == 2 {
                json!({"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"credit-fixture","type":"function","function":{"name":"opaque_metrics_query","arguments":"{\"metrics\":[\"credit_applications_per_minute\",\"manual_review_rate_percent\"],\"window_secs\":60,\"watch_secs\":0}"}}]}}]})
            } else {
                json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"The synthetic application rate is 17.25 apps/min and the manual review rate is 17.25% over 60 seconds."}}]})
            };
            ResponseTemplate::new(200).set_body_json(response)
        }).expect(2).mount(&fixture.model).await;
    let token = credit_token(&fixture);
    let cookie = fixture.login(&token).await;
    let events = chat_events(
        &fixture,
        &cookie,
        "What are my application rate and manual review rate?",
    )
    .await;
    let policies = policy_events(&events);
    assert_eq!(policies.len(), 2, "{events}");
    assert_eq!(policies[0]["phase"], "tool_check");
    assert_eq!(policies[0]["source_accessed"], false);
    assert_eq!(policies[1]["phase"], "source_read");
    assert_eq!(policies[1]["source_accessed"], true);
    assert!(events.contains("event: answer"));
    assert!(events.contains("apps/min"));
    assert!(!events.contains(&token));
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert_eq!(fixture.model.received_requests().await.unwrap().len(), 2);
    for request in fixture.model.received_requests().await.unwrap() {
        assert!(request.headers.get("authorization").is_none());
        assert!(!String::from_utf8_lossy(&request.body).contains(&token));
    }
    let session = body(
        fixture
            .browser("GET", "/api/session", &cookie, Value::Null)
            .await,
    )
    .await;
    assert_eq!(session["policy_context"]["latest_decision"], policies[1]);
}

#[tokio::test]
async fn credit_failed_or_foreign_source_never_claims_successful_source_evidence() {
    let fixture = Fixture::with_experience(false, Experience::CreditPortfolio).await;
    let token = credit_token(&fixture);
    let cookie = fixture.login(&token).await;
    for source_body in [
        json!({"error":"unavailable"}),
        json!({"tenant_id":"other-lender","window_secs":60,
        "as_of":now(),"watermark":now(),"metrics":[{"name":"manual_review_rate_percent","value":20,"count":120}]}),
    ] {
        fixture.source.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(source_body))
            .mount(&fixture.source)
            .await;
        let events = chat_events(&fixture, &cookie, "What is my manual review rate?").await;
        assert!(events.contains("event: error"));
        assert!(!events.contains("event: result"));
        let policies = policy_events(&events);
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0]["phase"], "tool_check");
        assert_ne!(policies[0]["outcome"], "denied");
        assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn credit_watch_still_requires_stream_scope_before_any_source_read() {
    let fixture = Fixture::with_experience(false, Experience::CreditPortfolio).await;
    let token = fixture.token(&fixture.claims(&[
        "metrics:read",
        "metrics:explain",
        "metrics:metric:manual_review_rate_percent",
    ]));
    let cookie = fixture.login(&token).await;
    let events = chat_events(&fixture, &cookie, "Watch my manual review rate live").await;
    let policies = policy_events(&events);
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["reason_code"], "stream_scope_denied");
    assert_eq!(policies[0]["source_accessed"], false);
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn credit_profile_rejects_score_scope_configuration_and_operational_mode_stays_unchanged() {
    let fixture = Fixture::with_experience(false, Experience::CreditPortfolio).await;
    for change in ["source", "admission", "oauth"] {
        let mut config = fixture.config.clone();
        match change {
            "source" => config
                .source
                .allowed_metrics
                .push("average_credit_score".into()),
            "admission" => {
                config.auth.admissions[0]
                    .scopes
                    .insert("metrics:metric:average_credit_score".into());
            }
            _ => {
                config
                    .oauth
                    .scopes
                    .insert("metrics:metric:average_credit_score".into());
            }
        }
        assert!(
            matches!(App::new(config), Err(message) if message.contains("three aggregate metrics"))
        );
    }
    let operational = Fixture::new(false).await;
    let token = operational.token(&operational.claims(&METRIC_SCOPES));
    let cookie = operational.login(&token).await;
    let session = body(
        operational
            .browser("GET", "/api/session", &cookie, Value::Null)
            .await,
    )
    .await;
    assert!(session.get("experience").is_none());
    assert!(session.get("policy_context").is_none());
    assert_eq!(
        session["suggested_questions"][0],
        "What is my request rate?"
    );
    // A deployment file written before the credit experience existed still deserializes unchanged.
    let source = &operational.config.source;
    let old_config = json!({"bind":operational.config.bind.to_string(),"public_origin":operational.config.public_origin,
        "tenant_id":operational.config.tenant_id,"customer_name":operational.config.customer_name,
        "state_dir":operational.config.state_dir,"auth":operational.config.auth,
        "oauth":{"authorization_endpoint":operational.config.oauth.authorization_endpoint,
            "token_endpoint":operational.config.oauth.token_endpoint,"client_id":operational.config.oauth.client_id,"scopes":operational.config.oauth.scopes},
        "source":{"tenant_id":source.tenant_id,"source_id":source.source_id,"base_url":source.base_url,
            "credential_env":source.credential_env,"allowed_metrics":source.allowed_metrics,"max_window_secs":source.max_window_secs,
            "max_staleness_secs":source.max_staleness_secs,"allow_loopback_http":source.allow_loopback_http},
        "model":{"kind":"fixture"},"fixture_mode":true});
    assert_eq!(
        serde_json::from_value::<GatewayConfig>(old_config)
            .unwrap()
            .experience,
        Experience::OperationalMetrics
    );
    assert_eq!(
        serde_json::from_value::<Experience>(json!("operational_metrics")).unwrap(),
        Experience::default()
    );
}
async fn body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}

#[tokio::test]
async fn missing_invalid_and_insufficient_bearers_have_resource_challenges_and_no_source_calls() {
    let fixture = Fixture::new(false).await;
    let response = fixture.mcp(None, args(&["requests_per_second"])).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let challenge = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    assert!(challenge.contains(&format!(
        "resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\"",
        fixture.config.public_origin
    )));
    let invalid = fixture
        .mcp(Some("not-a-token"), args(&["requests_per_second"]))
        .await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let token = fixture.token(&fixture.claims(&["metrics:read"]));
    let denied = fixture
        .mcp(Some(&token), args(&["requests_per_second"]))
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(
        denied.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("insufficient_scope")
    );
    let metadata = fixture
        .router()
        .oneshot(fixture.request(
            "GET",
            "/.well-known/oauth-protected-resource/mcp",
            Value::Null,
        ))
        .await
        .unwrap();
    let metadata = body(metadata).await;
    assert_eq!(metadata["resource"], fixture.config.auth.resource_audience);
    assert_eq!(
        metadata["authorization_servers"],
        json!([fixture.config.auth.issuer])
    );
    assert_eq!(metadata["bearer_methods_supported"], json!(["header"]));
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn ambiguous_authorization_headers_are_rejected_before_the_source() {
    let fixture = Fixture::new(false).await;
    let token = fixture.token(&fixture.claims(&METRIC_SCOPES));
    let valid = format!("Bearer {token}");
    for values in [
        [valid.as_str(), "Bearer invalid"],
        ["Bearer invalid", valid.as_str()],
        [valid.as_str(), valid.as_str()],
    ] {
        let mut request = fixture.request(
            "POST",
            "/mcp",
            json!({
                "jsonrpc":"2.0", "id":"test", "method":"tools/call",
                "params":args(&["requests_per_second"]),
            }),
        );
        request.headers_mut().insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        for value in values {
            request
                .headers_mut()
                .append(header::AUTHORIZATION, value.parse().unwrap());
        }
        let denied = fixture.router().oneshot(request).await.unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn production_configuration_cannot_enable_fixture_model_transport() {
    let fixture = Fixture::new(false).await;
    let directory = TestDirectory::new();
    let mut config = fixture.config.clone();
    config.state_dir = directory.0.clone();
    config.fixture_mode = false;
    config.public_origin = "https://metrics.example".into();
    config.auth.resource_audience = "https://metrics.example/mcp".into();
    config.auth.issuer = "https://issuer.example".into();
    config.auth.allow_loopback_http = false;
    config.oauth.authorization_endpoint = "https://issuer.example/authorize".into();
    config.oauth.token_endpoint = "https://issuer.example/token".into();
    config.source.base_url = "https://metrics-source.example".into();
    config.source.allow_loopback_http = false;
    config.model = ModelConfig::OpenaiCompatible {
        base_url: "https://model.example".into(),
        model: "configured-model".into(),
        allow_loopback_http: false,
    };
    assert!(
        App::new(config.clone())
            .err()
            .unwrap()
            .contains("requires broker_authority")
    );
    // The credential is disposable test data. Construction reads it but never
    // grants a request while this intentionally absent broker is unavailable.
    std::fs::create_dir_all(&directory.0).unwrap();
    let credential_file = directory.0.join("resource.key");
    std::fs::write(&credential_file, [9u8; 32]).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&credential_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    config.broker_authority = Some(opaque_showcase::auth::BrokerClientConfig {
        socket_path: directory.0.join("resource.sock"),
        credential_file,
        broker_uid: unsafe { libc::geteuid() },
        binding: opaque_core::tenant::TenantBinding::new(
            TenantId::parse("customer-a").unwrap(),
            Uuid::new_v4(),
        )
        .unwrap(),
    });
    config.auth.admissions.clear();
    config.auth.public_key_pem.clear();
    // The otherwise identical production configuration is usable; this test
    // cannot pass merely because another configuration field is invalid.
    drop(App::new(config.clone()).unwrap());
    config.model = ModelConfig::OpenaiCompatible {
        base_url: "http://127.0.0.1:39999".into(),
        model: "configured-model".into(),
        allow_loopback_http: true,
    };
    let error = App::new(config)
        .err()
        .expect("production HTTP model must fail closed");
    assert!(error.contains("explicit fixture mode"));
}

#[tokio::test]
async fn each_metric_requires_its_own_scope_and_foreign_tenant_never_reaches_source() {
    let fixture = Fixture::new(false).await;
    for metric in METRIC_NAMES {
        for scopes in [
            vec!["metrics:read".to_string()],
            vec![format!("metrics:metric:{metric}")],
        ] {
            let scopes: Vec<_> = scopes.iter().map(String::as_str).collect();
            let token = fixture.token(&fixture.claims(&scopes));
            let response = fixture.mcp(Some(&token), args(&[metric])).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "metric {metric}");
        }
    }
    for (field, value) in [
        ("tenant_id", "customer-b"),
        ("sub", "other-subject"),
        ("aud", "https://foreign.example/mcp"),
        ("iss", "https://foreign.example"),
    ] {
        let mut claims = fixture.claims(&METRIC_SCOPES);
        claims[field] = json!(value);
        let response = fixture
            .mcp(
                Some(&fixture.token(&claims)),
                args(&["requests_per_second"]),
            )
            .await;
        assert!(matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ));
    }
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn direct_mcp_rejects_unadmitted_client_before_source_or_model_access() {
    let fixture = Fixture::new(true).await;
    let mut claims = fixture.claims(&METRIC_SCOPES);
    claims["client_id"] = json!("unadmitted-oauth-client");
    let response = fixture
        .mcp(
            Some(&fixture.token(&claims)),
            args(&["requests_per_second"]),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
    assert!(fixture.model.received_requests().await.unwrap().is_empty());

    // The same subject and scopes still work through its exact admitted client.
    fixture.successful_source().await;
    let token = fixture.token(&fixture.claims(&METRIC_SCOPES));
    let response = fixture
        .mcp(Some(&token), args(&["requests_per_second"]))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert!(fixture.model.received_requests().await.unwrap().is_empty());

    // A client admitted for another subject cannot borrow the analyst's grant.
    let organization = Fixture::organization(true).await;
    let mut claims = organization.claims(&[
        "metrics:read",
        "metrics:metric:credit_applications_per_minute",
    ]);
    claims["client_id"] = json!("metrics-chat-engineer");
    let response = organization
        .mcp(
            Some(&organization.token(&claims)),
            args(&["credit_applications_per_minute"]),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        organization
            .source
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        organization
            .model
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn every_unsupported_argument_is_rejected_before_the_source() {
    let fixture = Fixture::new(false).await;
    let token = fixture.token(&fixture.claims(&METRIC_SCOPES));
    for field in [
        "tenant",
        "tenant_id",
        "customer_id",
        "url",
        "credential",
        "token",
        "sql",
        "columns",
        "raw_rows",
        "source_id",
    ] {
        let mut params = args(&["requests_per_second"]);
        params["arguments"][field] = json!("caller-selected");
        let response = fixture.mcp(Some(&token), params).await;
        assert_eq!(
            body(response).await["error"]["code"],
            -32602,
            "field {field}"
        );
    }
    let mut params = args(&["requests_per_second"]);
    params["tenant_id"] = json!("customer-b");
    assert_eq!(
        body(fixture.mcp(Some(&token), params).await).await["error"]["code"],
        -32602
    );
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn authorized_mcp_uses_only_configured_source_credential_and_returns_bounded_evidence() {
    let fixture = Fixture::new(false).await;
    fixture.successful_source().await;
    let token =
        fixture.token(&fixture.claims(&["metrics:read", "metrics:metric:requests_per_second"]));
    let response = fixture
        .mcp(Some(&token), args(&["requests_per_second"]))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = body(response).await;
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"]["tenant_id"],
        "customer-a"
    );
    assert_eq!(
        response["result"]["structuredContent"]["metrics"][0]["value"],
        17.25
    );
    let requests = fixture.source.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers[header::AUTHORIZATION],
        "Bearer opaque-showcase"
    );
    assert!(!String::from_utf8_lossy(&requests[0].body).contains(&token));
    assert!(!response.to_string().contains(&token));
    assert!(!response.to_string().contains("Bearer opaque-showcase"));
}

#[tokio::test]
async fn browser_login_is_pkce_and_cookie_bound_and_mcp_never_accepts_that_cookie() {
    let fixture = Fixture::new(false).await;
    let (state, _, binding) = fixture.start_login().await;
    let denied = fixture
        .router()
        .oneshot(fixture.request(
            "GET",
            &format!("/auth/callback?code=fixture-code&state={state}"),
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    let replay = fixture
        .browser(
            "GET",
            &format!("/auth/callback?code=fixture-code&state={state}"),
            &binding,
            Value::Null,
        )
        .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(
        fixture
            .issuer
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.url.path() != "/token")
    );
    let token = fixture.token(&fixture.claims(&METRIC_SCOPES));
    let cookie = fixture.login(&token).await;
    let session = fixture
        .browser("GET", "/api/session", &cookie, Value::Null)
        .await;
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(body(session).await["customer"]["id"], "customer-a");
    let mcp = fixture
        .browser(
            "POST",
            "/mcp",
            &cookie,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await;
    assert_eq!(mcp.status(), StatusCode::UNAUTHORIZED);
    let mut cross_origin = fixture.request("POST", "/auth/logout", Value::Null);
    cross_origin
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    cross_origin
        .headers_mut()
        .insert(header::ORIGIN, "https://foreign.example".parse().unwrap());
    assert_eq!(
        fixture
            .router()
            .oneshot(cross_origin)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn explain_scope_is_required_before_model_planning_or_source_access() {
    let fixture = Fixture::new(true).await;
    let token =
        fixture.token(&fixture.claims(&["metrics:read", "metrics:metric:requests_per_second"]));
    let cookie = fixture.login(&token).await;
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &cookie,
            json!({"message":"What is my request rate?"}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fixture.model.received_requests().await.unwrap().is_empty());
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn model_cannot_add_customer_selection_and_trigger_source_access() {
    let fixture = Fixture::new(true).await;
    Mock::given(method("POST")).and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"choices":[{
            "finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{
                "id":"fixture-call","type":"function","function":{"name":"opaque_metrics_query",
                    "arguments":"{\"metrics\":[\"requests_per_second\"],\"window_secs\":60,\"tenant_id\":\"customer-b\"}"}
            }]}
        }]}))).mount(&fixture.model).await;
    let token = fixture.token(&fixture.claims(&METRIC_SCOPES));
    let cookie = fixture.login(&token).await;
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &cookie,
            json!({"message":"What is my request rate?"}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(response.into_body(), 65536),
    )
    .await
    .unwrap()
    .unwrap();
    let events = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(events.contains("request_denied"));
    assert!(!events.contains("event: result"));
    assert_eq!(fixture.model.received_requests().await.unwrap().len(), 1);
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn logout_discards_already_queued_metric_events_and_stops_stream() {
    let fixture = Fixture::new(false).await;
    fixture.successful_source().await;
    let token = fixture.token(&fixture.claims(&METRIC_SCOPES));
    let cookie = fixture.login(&token).await;
    // Keep this response body unpolled: bounded producer queue fills with
    // status/tool/result events before logout, so emission-time checks alone
    // cannot pass this regression.
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &cookie,
            json!({"message":"Watch my request rate, errors, latency and sessions live"}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !fixture.source.received_requests().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let logged_out = fixture
        .browser("POST", "/auth/logout", &cookie, Value::Null)
        .await;
    assert_eq!(logged_out.status(), StatusCode::OK);
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(response.into_body(), 65536),
    )
    .await
    .unwrap()
    .unwrap();
    let events = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !events.contains("event: result"),
        "queued metric leaked after revocation: {events}"
    );
    assert!(
        !events.contains("event: answer"),
        "queued answer leaked after revocation: {events}"
    );
    assert!(events.contains("auth_expired"));
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        fixture
            .mcp(Some(&token), args(&["requests_per_second"]))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // The next scheduled live poll would occur after two seconds. Revoking
    // closes the body and cancels the producer before that additional read.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn state_is_single_writer_and_logout_revocation_survives_restart() {
    let fixture = Fixture::new(false).await;
    assert!(
        App::new(fixture.config.clone()).is_err(),
        "concurrent state writers must be excluded"
    );
    let token = fixture.token(&fixture.claims(&METRIC_SCOPES));
    let cookie = fixture.login(&token).await;
    assert_eq!(
        fixture
            .browser("POST", "/auth/logout", &cookie, Value::Null)
            .await
            .status(),
        StatusCode::OK
    );
    let mut request = fixture.request(
        "POST",
        "/mcp",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    );
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
    // Preserve only on-disk state while dropping every old verifier, browser
    // session and writer lock. The new instance must enforce persisted denial.
    let (config, _directory) = fixture.stop().await;
    let restarted = App::new(config).unwrap();
    let denied = router(restarted).oneshot(request).await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn persisted_tenant_binding_and_corrupt_revocations_fail_closed() {
    let fixture = Fixture::new(false).await;
    let (config, _directory) = fixture.stop().await;
    let mut foreign = config.clone();
    foreign.tenant_id = "customer-b".into();
    foreign.source.tenant_id = "customer-b".into();
    foreign.auth.admissions[0].tenant_id = TenantId::parse("customer-b").unwrap();
    assert!(App::new(foreign).is_err());
    // A malformed local revocation file cannot silently become an empty list.
    std::fs::write(config.state_dir.join("revoked.json"), b"incomplete-write").unwrap();
    assert!(App::new(config).is_err());
}

async fn org_identity(fixture: &Fixture, persona: Persona) -> (String, String) {
    let token = fixture.persona_token(persona);
    let cookie = fixture.login_for(&token, Some(persona)).await;
    (token, cookie)
}
async fn activate(
    fixture: &Fixture,
    cookie: &str,
    persona: Persona,
    reason: Option<&str>,
) -> Value {
    let mut request = json!({"persona_id":persona});
    if let Some(reason) = reason {
        request["reason"] = json!(reason);
    }
    let response = fixture
        .browser("POST", "/api/demo/persona", cookie, request)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await
}

#[tokio::test]
async fn organization_engineer_identity_is_metadata_only_even_with_raw_bearer_and_role_headers() {
    let fixture = Fixture::organization(true).await;
    let (engineer, cookie) = org_identity(&fixture, Persona::Engineer).await;
    let session = activate(&fixture, &cookie, Persona::Engineer, None).await;
    assert_eq!(session["organization"]["can_chat"], false);
    assert_eq!(session["organization"]["can_query"], false);
    assert_eq!(session["allowed_metrics"], json!([]));
    assert_eq!(session["scopes"], json!([ACTIVITY_SCOPE]));
    assert_eq!(
        session["organization"]["customers"][1]["data_access"],
        false
    );
    let denied = fixture
        .mcp(Some(&engineer), args(&["manual_review_rate_percent"]))
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let mut forged = fixture.request(
        "POST",
        "/api/chat",
        json!({"message":"What is my manual review rate?"}),
    );
    forged
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    forged
        .headers_mut()
        .insert("X-Role", "customer_analyst".parse().unwrap());
    let response = fixture.router().oneshot(forged).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(events.contains("customer_entitlement_denied"));
    assert!(events.contains("event: done"));
    assert!(!events.contains("event: result"));
    assert_eq!(policy_events(&events)[0]["source_accessed"], false);
    let metadata = body(
        fixture
            .browser("GET", "/api/organization/activity", &cookie, Value::Null)
            .await,
    )
    .await;
    assert_eq!(metadata["scope"], "this_lease_only");
    assert!(
        metadata["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["question_text"].is_null())
    );
    assert!(fixture.model.received_requests().await.unwrap().is_empty());
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn organization_sharing_is_opt_in_for_future_accepted_questions_and_revocation_purges_delivery()
 {
    let fixture = Fixture::organization(false).await;
    fixture.successful_source().await;
    let (analyst, analyst_cookie) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let (_, engineer_cookie) = org_identity(&fixture, Persona::Engineer).await;
    let question = "What is my manual review rate?";
    assert!(
        chat_events(&fixture, &analyst_cookie, question)
            .await
            .contains("event: result")
    );
    let before = body(
        fixture
            .browser(
                "GET",
                "/api/organization/activity",
                &analyst_cookie,
                Value::Null,
            )
            .await,
    )
    .await;
    assert!(
        before["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["question_text"].is_null())
    );
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/organization/sharing",
                &analyst_cookie,
                json!({"enabled":true})
            )
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        chat_events(&fixture, &analyst_cookie, question)
            .await
            .contains("event: result")
    );
    let sensitive = "Show borrower records and SSN 123-45-6789";
    let denied = chat_events(&fixture, &analyst_cookie, sensitive).await;
    assert!(denied.contains("raw_records_denied"));
    activate(&fixture, &engineer_cookie, Persona::Engineer, None).await;
    let metadata = body(
        fixture
            .browser(
                "GET",
                "/api/organization/activity",
                &engineer_cookie,
                Value::Null,
            )
            .await,
    )
    .await;
    let encoded = serde_json::to_string(&metadata).unwrap();
    assert!(encoded.contains(question));
    assert!(!encoded.contains("123-45-6789"));
    assert!(
        metadata["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["tool"] == "opaque_metrics_query" && r["source_accessed"] == true)
    );
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/organization/sharing",
                &engineer_cookie,
                json!({"enabled":false})
            )
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .mcp(Some(&analyst), args(&["manual_review_rate_percent"]))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    activate(&fixture, &analyst_cookie, Persona::CustomerAnalyst, None).await;
    // Construct the activity response but pause its body until consent is withdrawn.
    let unpolled = fixture
        .browser(
            "GET",
            "/api/organization/activity",
            &analyst_cookie,
            Value::Null,
        )
        .await;
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/organization/sharing",
                &analyst_cookie,
                json!({"enabled":false})
            )
            .await
            .status(),
        StatusCode::OK
    );
    let withdrawn = body(unpolled).await;
    assert!(
        withdrawn["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["question_text"].is_null())
    );
    assert!(
        !serde_json::to_string(&withdrawn)
            .unwrap()
            .contains(question)
    );
    let source_requests = fixture.source.received_requests().await.unwrap();
    for request in source_requests {
        let payload: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(payload["metrics"], json!(["manual_review_rate_percent"]));
        assert!(payload.get("tenant_id").is_none());
    }
}

#[tokio::test]
async fn organization_support_requires_assigned_subject_reason_and_expiring_case_without_impersonation()
 {
    let fixture = Fixture::organization(false).await;
    fixture.successful_source().await;
    let (_, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let (support_token, support) = org_identity(&fixture, Persona::Support).await;
    let baseline = body(
        fixture
            .browser("GET", "/api/session", &analyst, Value::Null)
            .await,
    )
    .await;
    for request in [
        json!({"persona_id":"support"}),
        json!({"persona_id":"support","reason":"short"}),
        json!({"persona_id":"support","reason":"Review issue","tenant_id":"cedar-demo"}),
    ] {
        assert_ne!(
            fixture
                .browser("POST", "/api/demo/persona", &support, request)
                .await
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/demo/persona",
                &analyst,
                json!({"persona_id":"support","reason":"Investigate stale portfolio metrics"})
            )
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let unchanged = body(
        fixture
            .browser("GET", "/api/session", &analyst, Value::Null)
            .await,
    )
    .await;
    assert_eq!(
        unchanged["organization"]["generation"],
        baseline["organization"]["generation"]
    );
    let session = activate(
        &fixture,
        &support,
        Persona::Support,
        Some("Investigate stale portfolio metrics"),
    )
    .await;
    let case = &session["organization"]["support_case"];
    assert_eq!(case["tenant_id"], "customer-a");
    assert_eq!(case["subject"], "customer-support");
    assert!(case["expires_at"].as_i64().unwrap() <= now() + 300);
    assert_eq!(session["subject"]["id"], "customer-support");
    assert_eq!(
        session["organization"]["customers"][1]["data_access"],
        false
    );
    assert!(
        chat_events(&fixture, &support, "What is my manual review rate?")
            .await
            .contains("event: result")
    );
    let watch = chat_events(&fixture, &support, "Watch my manual review rate live").await;
    assert!(watch.contains("stream_scope_denied"));
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert_eq!(
        fixture
            .mcp(Some(&support_token), args(&["average_credit_score"]))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let audit = std::fs::read_to_string(fixture.config.state_dir.join("audit.jsonl")).unwrap();
    assert!(audit.contains("Investigate stale portfolio metrics"));
    assert!(audit.contains("customer-support"));
    assert!(!audit.contains(&support_token));
}

#[tokio::test]
async fn organization_epoch_blocks_queued_results_and_delayed_nested_mcp_after_analyst_engineer_analyst()
 {
    let fixture = Fixture::organization(false).await;
    fixture.successful_source().await;
    let (analyst_token, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let (_, engineer) = org_identity(&fixture, Persona::Engineer).await;
    let first = body(
        fixture
            .browser("GET", "/api/session", &analyst, Value::Null)
            .await,
    )
    .await;
    let epoch = first["organization"]["generation"].as_u64().unwrap();
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &analyst,
            json!({"message":"Watch my manual review rate live"}),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.source.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    activate(&fixture, &engineer, Persona::Engineer, None).await;
    let returned = activate(&fixture, &analyst, Persona::CustomerAnalyst, None).await;
    assert!(returned["organization"]["generation"].as_u64().unwrap() > epoch);
    let events = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!events.contains("event: result"));
    assert!(!events.contains("event: answer"));
    let mut delayed=fixture.request("POST","/mcp",json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":args(&["manual_review_rate_percent"])}));
    delayed.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {analyst_token}").parse().unwrap(),
    );
    delayed.headers_mut().insert(
        header::ACCEPT,
        "application/json, text/event-stream".parse().unwrap(),
    );
    delayed.headers_mut().insert(
        "X-Opaque-Persona-Generation",
        epoch.to_string().parse().unwrap(),
    );
    assert_eq!(
        fixture.router().oneshot(delayed).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn organization_pure_state_intersects_case_expiry_epoch_and_preserves_prior_source_evidence()
{
    use opaque_showcase::{auth::AuthVerifier, organization::OrganizationState};
    let fixture = Fixture::organization(false).await;
    let verifier = AuthVerifier::new(fixture.config.auth.clone()).unwrap();
    let token = fixture.persona_token(Persona::Support);
    let access = verifier
        .verify_bearer(Some(&format!("Bearer {token}")))
        .unwrap();
    let config = fixture.config.organization_demo.as_ref().unwrap();
    let mut state = OrganizationState::default();
    state
        .activate(
            config,
            &access,
            Persona::Support,
            Some("Investigate missing aggregate updates"),
            now(),
            |_| Ok(()),
        )
        .unwrap();
    let epoch = state.snapshot(config, &access).unwrap();
    let expiry = state.support_case.as_ref().unwrap().expires_at;
    assert!(state.check_data(config, &access, epoch, expiry - 1).is_ok());
    assert!(state.check_data(config, &access, epoch, expiry).is_err());
    let id = state
        .begin(config, &access, "chat", "fixture".into(), None, now())
        .unwrap();
    state.tool(&id, &["manual_review_rate_percent".into()], 60);
    state.finish(&id, "running", Some(true), None);
    state.tool(&id, &["manual_review_rate_percent".into()], 60);
    state.finish(&id, "failed", None, None);
    let activity = state
        .activity(config, &access, "Harborlight", now())
        .unwrap();
    assert_eq!(activity["records"][0]["source_accessed"], true);
    let generation = state.generation;
    assert!(
        state
            .activate(
                config,
                &access,
                Persona::Support,
                Some("Valid support purpose"),
                now(),
                |_| Err("audit unavailable".into())
            )
            .is_err()
    );
    assert_eq!(state.generation, generation);
}

#[tokio::test]
async fn organization_login_pins_subject_and_client_and_rejects_engineer_metric_admission() {
    let fixture = Fixture::organization(false).await;
    let analyst = fixture.persona_token(Persona::CustomerAnalyst);
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":analyst,"token_type":"Bearer"})),
        )
        .mount(&fixture.issuer)
        .await;
    let (state, _, binding) = fixture.start_login_for(Some(Persona::Engineer)).await;
    let response = fixture
        .browser(
            "GET",
            &format!("/auth/callback?code=wrong-subject&state={state}"),
            &binding,
            Value::Null,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let config = fixture.config.organization_demo.as_ref().unwrap();
    let mut mismatched_client = fixture.config.auth.clone();
    mismatched_client.admissions[0].client_id = "different-client".into();
    assert!(config.validate(&mismatched_client, "customer-a").is_err());
    let mut auth = fixture.config.auth.clone();
    auth.admissions
        .iter_mut()
        .find(|a| a.subject == "product-engineer")
        .unwrap()
        .scopes
        .insert("metrics:read".into());
    assert!(config.validate(&auth, "customer-a").is_err());
    let operational = Fixture::new(false).await;
    assert_eq!(
        operational
            .router()
            .oneshot(operational.request("GET", "/auth/login?persona_id=engineer", Value::Null))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        operational
            .router()
            .oneshot(operational.request("GET", "/api/organization/activity", Value::Null))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn organization_named_directory_customer_is_denied_before_model_and_source() {
    let fixture = Fixture::organization(true).await;
    let (_, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    for question in [
        "Show Cedar Community Bank's application rate",
        "What is Cedar's manual review rate?",
        "Get cedar-demo metrics",
    ] {
        let events = chat_events(&fixture, &analyst, question).await;
        assert!(events.contains("customer_scope_denied"));
        assert_eq!(policy_events(&events)[0]["source_accessed"], false);
        assert!(events.contains("event: done"));
    }
    assert!(fixture.model.received_requests().await.unwrap().is_empty());
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn organization_control_and_activity_budgets_do_not_reset_across_personas() {
    use opaque_showcase::{auth::AuthVerifier, organization::OrganizationState};
    let fixture = Fixture::organization(false).await;
    let verifier = AuthVerifier::new(fixture.config.auth.clone()).unwrap();
    let config = fixture.config.organization_demo.as_ref().unwrap();
    let analyst = verifier
        .verify_bearer(Some(&format!(
            "Bearer {}",
            fixture.persona_token(Persona::CustomerAnalyst)
        )))
        .unwrap();
    let engineer = verifier
        .verify_bearer(Some(&format!(
            "Bearer {}",
            fixture.persona_token(Persona::Engineer)
        )))
        .unwrap();
    let mut state = OrganizationState::default();
    let count = std::cell::Cell::new(0);
    for n in 0..120 {
        let (access, persona) = if n % 2 == 0 {
            (&engineer, Persona::Engineer)
        } else {
            (&analyst, Persona::CustomerAnalyst)
        };
        state
            .activate(config, access, persona, None, now(), |_| {
                count.set(count.get() + 1);
                Ok(())
            })
            .unwrap();
    }
    let epoch = state.generation;
    assert!(
        state
            .activate(config, &engineer, Persona::Engineer, None, now(), |_| {
                count.set(count.get() + 1);
                Ok(())
            })
            .is_err()
    );
    assert!(
        state
            .set_sharing(config, &analyst, true, |_| {
                count.set(count.get() + 1);
                Ok(())
            })
            .is_err()
    );
    assert_eq!(count.get(), 120);
    assert_eq!(state.generation, epoch);
    for _ in 0..110 {
        state.begin(
            config,
            &analyst,
            "chat",
            "fixture".into(),
            Some("What is my manual review rate?"),
            now(),
        );
    }
    let activity = state
        .activity(config, &analyst, "Harborlight", now())
        .unwrap();
    assert_eq!(activity["records"].as_array().unwrap().len(), 100);
    assert!(
        activity["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["question_text"].is_null())
    );
}

#[tokio::test]
async fn organization_role_change_while_model_plans_prevents_source_dispatch_and_second_model_call()
{
    let fixture = Fixture::organization(true).await;
    fixture.successful_source().await;
    Mock::given(method("POST")).and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(300)).set_body_json(json!({"choices":[{
            "finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"plan","type":"function","function":{
                "name":"opaque_metrics_query","arguments":"{\"metrics\":[\"manual_review_rate_percent\"],\"window_secs\":60,\"watch_secs\":0}"}}]}
        }]}))).mount(&fixture.model).await;
    let (_, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let (_, engineer) = org_identity(&fixture, Persona::Engineer).await;
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &analyst,
            json!({"message":"What is my manual review rate?"}),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.model.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    activate(&fixture, &engineer, Persona::Engineer, None).await;
    activate(&fixture, &analyst, Persona::CustomerAnalyst, None).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    let events = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!events.contains("event: result"));
    assert!(!events.contains("event: answer"));
    assert_eq!(fixture.model.received_requests().await.unwrap().len(), 1);
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

fn portfolio_args() -> Value {
    json!({"name":"opaque_portfolio_query","arguments":{"view":"breakdown","window_secs":900,"measures":["manual_review_rate_percent"],"dimension":"channel"}})
}
fn portfolio_response(query: Value) -> Value {
    let as_of = now();
    let window = query["window_secs"].as_i64().unwrap();
    let keys: Vec<&str> = match query["view"].as_str().unwrap() {
        "summary" => vec!["all"],
        "comparison" => vec!["current", "previous"],
        "trend" => vec![
            "bucket_0", "bucket_1", "bucket_2", "bucket_3", "bucket_4", "bucket_5",
        ],
        _ => match query["dimension"].as_str().unwrap() {
            "region" => vec!["northeast", "southeast", "midwest", "west"],
            "product" => vec!["personal_loan", "auto_loan", "credit_card"],
            _ => vec!["web", "mobile", "partner"],
        },
    };
    let rows=keys.iter().enumerate().map(|(index,key)|{
        let (start,end)=if query["view"]=="trend"{let start=as_of-window+index as i64*(window/6);(start,start+window/6)}else if *key=="previous"{(as_of-2*window,as_of-window)}else{(as_of-window,as_of)};
        let values=query["measures"].as_array().unwrap().iter().map(|m|(m.as_str().unwrap().to_owned(),json!(if m=="application_count"{100}else{10+index*10}))).collect::<serde_json::Map<_,_>>();
        json!({"key":key,"period_start":start,"period_end":end,"sample_count":100,"values":values})
    }).collect::<Vec<_>>();
    let comparison = if query["view"] == "comparison" {
        query["measures"].as_array().unwrap().iter().map(|m|{
        let current=rows[0]["values"][m.as_str().unwrap()].as_f64().unwrap();let previous=rows[1]["values"][m.as_str().unwrap()].as_f64().unwrap();let delta=current-previous;
        json!({"measure":m,"current":current,"previous":previous,"delta":delta,"delta_unit":if m=="mean_processing_seconds"{"seconds"}else if m.as_str().unwrap().ends_with("_count"){"applications"}else{"percentage_points"},"relative_percent":delta/previous.abs()*100.0})
    }).collect::<Vec<_>>()
    } else {
        vec![]
    };
    json!({"tenant_id":"customer-a","query":query,"as_of":as_of,"watermark":as_of,"history_start":as_of-7205,"history_kind":"synthetic_seeded_and_live","rows":rows,"comparison":comparison})
}
async fn portfolio_source(fixture: &Fixture, delay: Duration) {
    Mock::given(method("POST"))
        .and(path("/v1/portfolio/query"))
        .respond_with(move |request: &wiremock::Request| {
            ResponseTemplate::new(200)
                .set_delay(delay)
                .set_body_json(portfolio_response(request.body_json().unwrap()))
        })
        .mount(&fixture.source)
        .await;
}
fn event_value(events: &str, kind: &str) -> Value {
    let name = format!("event: {kind}");
    let frame = events
        .split("\n\n")
        .find(|frame| frame.lines().any(|line| line == name))
        .unwrap_or_else(|| panic!("missing {kind}: {events}"));
    serde_json::from_str(
        frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap()
}
#[tokio::test]
async fn portfolio_chat_plans_and_selects_computed_findings_with_exact_source_binding() {
    let fixture = Fixture::portfolio(true, false).await;
    portfolio_source(&fixture, Duration::ZERO).await;
    let query = portfolio_args()["arguments"].clone();
    exploration::model_plan(&fixture, json!({"kind":"query","interpretation":"Compare channel review rates over the last 15 minutes.","queries":[query]}), None).await;
    let token = credit_token(&fixture);
    let cookie = fixture.login(&token).await;
    let session = body(
        fixture
            .browser("GET", "/api/session", &cookie, Value::Null)
            .await,
    )
    .await;
    assert_eq!(session["dataset"]["measures"].as_array().unwrap().len(), 6);
    assert_eq!(session["dataset"]["source_id"], "fixture-aggregates");
    assert_eq!(
        session["policy_context"]["allowed_tools"],
        json!(["opaque_metrics_query", "opaque_portfolio_query"])
    );
    let events = chat_events(
        &fixture,
        &cookie,
        "Which channel has the highest manual review rate in the last 15 minutes?",
    )
    .await;
    let result = event_value(&events, "portfolio_result");
    assert_eq!(result["coverage"], "complete");
    assert_eq!(result["query"], query);
    assert!(
        event_value(&events, "answer")["text"]
            .as_str()
            .unwrap()
            .contains("Partner has the highest manual review rate: 30.00 %")
    );
    assert!(
        result["answer"]
            .as_str()
            .unwrap()
            .contains("Partner has the highest manual review rate: 30.00 %")
    );
    assert_eq!(fixture.model.received_requests().await.unwrap().len(), 2);
    let calls = fixture.source.received_requests().await.unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].headers["authorization"], "Bearer opaque-showcase");
    assert!(
        policy_events(&events)
            .iter()
            .all(|p| p["tool"] == "opaque_portfolio_query")
    );
    assert!(!events.contains(&token));
    assert!(!events.contains("Bearer"));
}
#[tokio::test]
async fn portfolio_fixture_answers_all_views_and_keeps_legacy_watch_available() {
    let fixture = Fixture::portfolio(false, false).await;
    portfolio_source(&fixture, Duration::ZERO).await;
    fixture.successful_source().await;
    let cookie = fixture.login(&credit_token(&fixture)).await;
    for (question, view, measure) in [
        (
            "What is my application rate?",
            "summary",
            "application_count",
        ),
        (
            "Which channel has the most reviews?",
            "breakdown",
            "manual_review_count",
        ),
        (
            "Compare mobile identity mismatch rates with the previous 15 minutes",
            "comparison",
            "identity_mismatch_rate_percent",
        ),
        (
            "Show processing time by channel over the last hour",
            "breakdown",
            "mean_processing_seconds",
        ),
        (
            "Show regional review rates over the last 5 minutes",
            "breakdown",
            "manual_review_rate_percent",
        ),
        (
            "Show application volume trends over the last hour",
            "trend",
            "application_count",
        ),
        (
            "What is the change in application volume?",
            "comparison",
            "application_count",
        ),
    ] {
        let events = chat_events(&fixture, &cookie, question).await;
        let result = event_value(&events, "portfolio_result");
        assert_eq!(result["query"]["view"], view, "{question}");
        assert!(
            result["query"]["measures"]
                .as_array()
                .unwrap()
                .contains(&json!(measure))
        );
        assert!(events.contains("event: done"));
        if question == "What is my application rate?" {
            assert!(
                result["answer"]
                    .as_str()
                    .unwrap()
                    .contains("6.67 applications/minute")
            );
        }
    }
    let events = chat_events(
        &fixture,
        &cookie,
        "Watch manual review rate live for 1 second",
    )
    .await;
    assert!(events.contains("event: result"), "{events}");
    assert!(!events.contains("event: portfolio_result"));
}
#[tokio::test]
async fn portfolio_denies_unsupported_history_fields_and_scope_before_model_or_source() {
    let fixture = Fixture::portfolio(true, false).await;
    let cookie = fixture.login(&credit_token(&fixture)).await;
    for question in [
        "Show application volume yesterday",
        "Show review rates over 24 hours",
        "Show volume by borrower name",
        "Show volume over 2 minutes",
        "Show Cedar borrower records",
        "Average credit score?",
        "Median processing time",
        "P95 processing time",
        "Pending application backlog",
        "Approval rate",
        "Default rates",
        "Watch mobile mismatch rate",
        "Watch review rate by channel",
        "Watch manual review rate over the last 15 minutes",
    ] {
        let events = chat_events(&fixture, &cookie, question).await;
        assert!(
            events.contains("event: error")
                || (events.contains("event: answer")
                    && event_value(&events, "answer")["kind"] == "unsupported"),
            "{events}"
        );
        assert!(!events.contains("event: portfolio_result"), "{events}");
        assert!(
            fixture.model.received_requests().await.unwrap().is_empty(),
            "unsupported request reached the model: {question}"
        );
        assert!(
            fixture.source.received_requests().await.unwrap().is_empty(),
            "unsupported request reached the source: {question}"
        );
    }
    let token =
        fixture.token(&fixture.claims(&["portfolio:read", "portfolio:measure:application_count"]));
    assert_eq!(
        fixture.mcp(Some(&token), portfolio_args()).await.status(),
        StatusCode::FORBIDDEN
    );
    for field in ["tenant_id", "url", "sql", "raw_rows"] {
        let mut args = portfolio_args();
        args["arguments"][field] = json!("override");
        let result = body(fixture.mcp(Some(&token), args).await).await;
        assert_eq!(result["error"]["code"], -32602);
    }
    assert!(fixture.model.received_requests().await.unwrap().is_empty());
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn portfolio_engineer_support_and_queued_result_obey_current_epoch() {
    let fixture = Fixture::portfolio(false, true).await;
    portfolio_source(&fixture, Duration::ZERO).await;
    let (_, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let (engineer_token, engineer) = org_identity(&fixture, Persona::Engineer).await;
    let (support_token, support) = org_identity(&fixture, Persona::Support).await;
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &analyst,
            json!({"message":"Which channel has the most reviews?"}),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.source.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let session = activate(&fixture, &engineer, Persona::Engineer, None).await;
    assert_eq!(session["dataset"]["can_query"], false);
    assert_eq!(session["dataset"]["measures"], json!([]));
    assert_eq!(
        fixture
            .mcp(Some(&engineer_token), portfolio_args())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .mcp(Some(&support_token), portfolio_args())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    activate(&fixture, &analyst, Persona::CustomerAnalyst, None).await;
    let events = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!events.contains("event: portfolio_result"));
    assert!(!events.contains("event: answer"));
    let session = activate(
        &fixture,
        &support,
        Persona::Support,
        Some("Inspect customer application volume"),
    )
    .await;
    assert_eq!(session["dataset"]["can_query"], true);
    let result = body(fixture.mcp(Some(&support_token), portfolio_args()).await).await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn portfolio_only_read_scope_supports_chat_without_legacy_metric_authority() {
    let fixture = Fixture::portfolio(false, false).await;
    portfolio_source(&fixture, Duration::ZERO).await;
    let scopes = [
        "portfolio:read",
        "portfolio:measure:application_count",
        "metrics:explain",
    ];
    let token = fixture.token(&fixture.claims(&scopes));
    let cookie = fixture.login(&token).await;
    let events = chat_events(&fixture, &cookie, "What is my application volume?").await;
    assert!(events.contains("event: portfolio_result"), "{events}");
    let denied = fixture
        .mcp(Some(&token), args(&["manual_review_rate_percent"]))
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
}
