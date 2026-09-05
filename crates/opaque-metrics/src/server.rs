//! A single-tenant OAuth resource server and same-origin chat BFF.
//! Provider credentials never enter the browser, model context, or MCP result.
use crate::{
    auth::{AuthConfig, AuthError, AuthVerifier, VerifiedAccess},
    chat::{ChatModel, ModelConfig, label, unit},
    experience::{CREDIT_METRICS, CREDIT_POLICY_ID, Experience, credit_request_denial},
    metrics::{MetricsClient, MetricsEvidence, MetricsQuery, MetricsSourceConfig},
    organization::{OrganizationConfig, OrganizationState, Persona},
    portfolio::{self, Measure, PortfolioEvidence, PortfolioQuery},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response, Sse, sse::Event},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::stream;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    fs::{File, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, mpsc};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub scopes: BTreeSet<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub bind: SocketAddr,
    pub public_origin: String,
    pub tenant_id: String,
    pub customer_name: String,
    pub state_dir: PathBuf,
    pub auth: AuthConfig,
    pub oauth: OAuthConfig,
    pub source: MetricsSourceConfig,
    pub model: ModelConfig,
    #[serde(default)]
    pub experience: Experience,
    #[serde(default)]
    pub fixture_mode: bool,
    #[serde(default)]
    pub organization_demo: Option<OrganizationConfig>,
}
struct BrowserSession {
    token: Zeroizing<String>,
    expires_at: i64,
}
struct PendingLogin {
    verifier: Zeroizing<String>,
    browser_binding: String,
    created_at: i64,
    client_id: String,
    expected_subject: Option<String>,
    scopes: BTreeSet<String>,
}
struct Rate {
    start: i64,
    count: u32,
}
pub struct App {
    config: GatewayConfig,
    auth: AuthVerifier,
    metrics: MetricsClient,
    model: ChatModel,
    http: reqwest::Client,
    sessions: Mutex<HashMap<String, BrowserSession>>,
    pending: Mutex<HashMap<String, PendingLogin>>,
    rates: Mutex<HashMap<String, Rate>>,
    active_chats: Mutex<BTreeSet<String>>,
    latest_policy: Mutex<HashMap<String, Value>>,
    organization: Mutex<OrganizationState>,
    capacity: Arc<Semaphore>,
    revoked: Mutex<BTreeSet<String>>,
    audit: Mutex<File>,
    csp: HeaderValue,
    // Closing this last-held descriptor releases the exclusive lifetime lock.
    _state_lock: File,
}
impl Drop for App {
    fn drop(&mut self) {
        // Explicit unlock also releases the lock if a concurrent fork briefly
        // inherited the open description before its close-on-exec runs.
        // SAFETY: the descriptor remains live for the duration of this drop.
        unsafe {
            libc::flock(self._state_lock.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs() as i64)
        .unwrap_or(0)
}
fn random() -> Result<String, String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| "random source unavailable")?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}
fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 160 && !s.chars().any(char::is_control)
}
fn trusted_url(s: &str, fixture: bool) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(s).map_err(|_| "invalid trusted URL")?;
    let local = u.host_str().is_some_and(|v| {
        v.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if !(u.scheme() == "https" || (fixture && u.scheme() == "http" && local))
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        return Err("trusted endpoint requires HTTPS or explicit loopback fixture".into());
    }
    Ok(u)
}
impl App {
    pub fn new(mut config: GatewayConfig) -> Result<Arc<Self>, String> {
        let origin = trusted_url(&config.public_origin, config.fixture_mode)?;
        if origin.path() != "/"
            || config.public_origin.ends_with('/')
            || !config.bind.ip().is_loopback()
            || config.bind.port() == 0
            || !valid_label(&config.customer_name)
            || !valid_label(&config.tenant_id)
        {
            return Err("gateway requires a canonical public origin and loopback listener".into());
        }
        if config.auth.resource_audience != format!("{}/mcp", config.public_origin)
            || config.source.tenant_id != config.tenant_id
            || config
                .auth
                .admissions
                .iter()
                .any(|a| a.tenant_id.as_str() != config.tenant_id)
            || config.source.max_window_secs > 300
        {
            return Err("gateway, source and admitted tenant must match".into());
        }
        if !config.source.allowed_portfolio_measures.is_empty()
            && (!config.fixture_mode || config.experience != Experience::CreditPortfolio)
        {
            return Err("portfolio history requires the synthetic credit profile".into());
        }
        if config.experience == Experience::CreditPortfolio {
            let permitted = |scope: &str| {
                scope
                    .strip_prefix("metrics:metric:")
                    .is_none_or(|metric| CREDIT_METRICS.contains(&metric))
            };
            if !config.fixture_mode
                || config
                    .source
                    .allowed_metrics
                    .iter()
                    .any(|metric| !CREDIT_METRICS.contains(&metric.as_str()))
                || config
                    .auth
                    .admissions
                    .iter()
                    .any(|admission| admission.scopes.iter().any(|scope| !permitted(scope)))
                || config.oauth.scopes.iter().any(|scope| !permitted(scope))
            {
                return Err(
                    "credit portfolio profile permits only its three aggregate metrics".into(),
                );
            }
        }
        if let Some(organization) = &config.organization_demo {
            if !config.fixture_mode || config.experience != Experience::CreditPortfolio {
                return Err(
                    "organization role simulation requires the synthetic credit demo".into(),
                );
            }
            organization.validate(&config.auth, &config.tenant_id)?;
            let analyst = organization.persona(Persona::CustomerAnalyst);
            if analyst.oauth_client_id != config.oauth.client_id {
                return Err("default OAuth client must be the configured customer analyst".into());
            }
        }
        if !config.fixture_mode
            && (config.auth.allow_loopback_http
                || config.source.allow_loopback_http
                || matches!(
                    &config.model,
                    ModelConfig::OpenaiCompatible {
                        allow_loopback_http: true,
                        ..
                    }
                )
                || matches!(config.model, ModelConfig::Fixture))
        {
            return Err("test transports and test agent require explicit fixture mode".into());
        }
        let issuer = trusted_url(&config.auth.issuer, config.fixture_mode)?;
        for url in [
            &config.oauth.authorization_endpoint,
            &config.oauth.token_endpoint,
        ] {
            if trusted_url(url, config.fixture_mode)?.origin() != issuer.origin() {
                return Err("OAuth endpoints must use the trusted issuer origin".into());
            }
        }
        if !valid_label(&config.oauth.client_id)
            || !config.oauth.scopes.contains("metrics:read")
            || config
                .oauth
                .scopes
                .iter()
                .any(|s| !crate::auth::METRIC_SCOPES.contains(&s.as_str()))
        {
            return Err("invalid preregistered OAuth scopes".into());
        }
        std::fs::create_dir_all(&config.state_dir).map_err(|_| "state directory unavailable")?;
        let md = std::fs::symlink_metadata(&config.state_dir)
            .map_err(|_| "state directory unavailable")?;
        if !md.is_dir() || md.file_type().is_symlink() {
            return Err("state directory must be a real directory".into());
        }
        std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "private state unavailable")?;
        let state_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(config.state_dir.join("gateway.lock"))
            .map_err(|_| "state lock unavailable")?;
        // SAFETY: flock receives a live file descriptor and no pointers.
        if unsafe { libc::flock(state_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("this tenant gateway state is already in use".into());
        }
        let binding_path = config.state_dir.join("tenant.json");
        if binding_path.exists() {
            let binding: Value = serde_json::from_slice(
                &std::fs::read(&binding_path).map_err(|_| "tenant binding unavailable")?,
            )
            .map_err(|_| "tenant binding invalid")?;
            if binding.get("tenant_id").and_then(Value::as_str) != Some(config.tenant_id.as_str())
                || binding.get("audience").and_then(Value::as_str)
                    != Some(config.auth.resource_audience.as_str())
            {
                return Err("state directory belongs to a different tenant or resource".into());
            }
        } else {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&binding_path)
                .map_err(|_| "tenant binding unavailable")?;
            f.write_all(
                serde_json::to_string(
                    &json!({"tenant_id":config.tenant_id,"audience":config.auth.resource_audience}),
                )
                .unwrap()
                .as_bytes(),
            )
            .map_err(|_| "tenant binding write failed")?;
            f.sync_all()
                .map_err(|_| "tenant binding persistence failed")?;
        }
        let revoked_path = config.state_dir.join("revoked.json");
        let mut revoked = config.auth.revoked_jtis.clone();
        if revoked_path.exists() {
            let bytes = std::fs::read(revoked_path).map_err(|_| "revocation state unavailable")?;
            if bytes.len() > 1024 * 1024 {
                return Err("revocation state exceeded limit".into());
            }
            revoked.extend(
                serde_json::from_slice::<BTreeSet<String>>(&bytes)
                    .map_err(|_| "invalid revocation state")?,
            );
        }
        config.auth.revoked_jtis = revoked.clone();
        let auth = AuthVerifier::new(config.auth.clone()).map_err(|e| e.to_string())?;
        let metrics = MetricsClient::new(vec![config.source.clone()]).map_err(|e| e.to_string())?;
        let model = ChatModel::new(config.model.clone())?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| "HTTP client unavailable")?;
        let audit = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(config.state_dir.join("audit.jsonl"))
            .map_err(|_| "audit unavailable")?;
        let script = include_str!("../static/index.html")
            .split_once("<script>")
            .and_then(|(_, rest)| rest.split_once("</script>").map(|(script, _)| script))
            .ok_or("chat UI script is missing")?;
        let script_hash =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
        let csp = HeaderValue::from_str(&format!("default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"))
            .map_err(|_| "chat content policy is invalid")?;
        Ok(Arc::new(Self {
            config,
            auth,
            metrics,
            model,
            http,
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
            active_chats: Mutex::new(BTreeSet::new()),
            latest_policy: Mutex::new(HashMap::new()),
            organization: Mutex::new(OrganizationState::default()),
            capacity: Arc::new(Semaphore::new(8)),
            revoked: Mutex::new(revoked),
            audit: Mutex::new(audit),
            csp,
            _state_lock: state_lock,
        }))
    }
    fn cookie_name(&self) -> String {
        format!("opaque_metrics_{}", self.config.bind.port())
    }
    fn set_cookie(&self, name: &str, value: &str, seconds: i64) -> String {
        format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={seconds}{}",
            if self.config.public_origin.starts_with("https:") {
                "; Secure"
            } else {
                ""
            }
        )
    }
    fn session(
        &self,
        headers: &HeaderMap,
    ) -> Result<(Zeroizing<String>, VerifiedAccess), AuthError> {
        let sid = cookie(headers, &self.cookie_name()).ok_or(AuthError::MissingBearer)?;
        let mut sessions = self.sessions.lock().map_err(|_| AuthError::Unavailable)?;
        sessions.retain(|_, s| s.expires_at > now());
        let session = sessions.get(&sid).ok_or(AuthError::InvalidToken)?;
        let token = Zeroizing::new(session.token.to_string());
        let access = self
            .auth
            .verify_bearer(Some(&format!("Bearer {}", token.as_str())))?;
        Ok((token, access))
    }
    fn audit(
        &self,
        access: &VerifiedAccess,
        operation: &str,
        outcome: &str,
        evidence: Option<&MetricsEvidence>,
    ) -> Result<(), String> {
        let hash =
            evidence.map(|e| format!("{:x}", Sha256::digest(serde_json::to_vec(e).unwrap())));
        let record = json!({"at":now(),"event_id":Uuid::new_v4(),"tenant_id":access.tenant_id(),"subject":access.subject(),"operation":operation,"outcome":outcome,"evidence_sha256":hash});
        let mut file = self.audit.lock().map_err(|_| "audit unavailable")?;
        writeln!(file, "{record}").map_err(|_| "audit write failed")?;
        file.sync_data()
            .map_err(|_| "audit persistence failed".into())
    }
    fn organization_audit(&self, access: &VerifiedAccess, details: &Value) -> Result<(), String> {
        let record = json!({"at":now(),"event_id":Uuid::new_v4(),"tenant_id":access.tenant_id(),"subject":access.subject(),"details":details});
        let mut audit = self.audit.lock().map_err(|_| "audit unavailable")?;
        writeln!(audit, "{record}").map_err(|_| "audit write failed")?;
        audit
            .sync_data()
            .map_err(|_| "audit persistence failed".into())
    }
    fn access_epoch(&self, access: &VerifiedAccess) -> Result<Option<u64>, String> {
        self.auth.check_access(access).map_err(|e| e.to_string())?;
        self.config
            .organization_demo
            .as_ref()
            .map(|config| {
                self.organization
                    .lock()
                    .map_err(|_| "organization state unavailable".to_string())?
                    .snapshot(config, access)
            })
            .transpose()
    }
    fn check_epoch(&self, access: &VerifiedAccess, epoch: Option<u64>) -> Result<(), String> {
        if self.access_epoch(access)? != epoch {
            return Err("The demo identity changed; this request has stopped.".into());
        }
        Ok(())
    }
    fn check_data(&self, access: &VerifiedAccess, epoch: Option<u64>) -> Result<(), String> {
        self.check_epoch(access, epoch)?;
        if let Some(config) = &self.config.organization_demo {
            self.organization
                .lock()
                .map_err(|_| "organization state unavailable")?
                .check_data(
                    config,
                    access,
                    epoch.ok_or("Organization authority unavailable")?,
                    now(),
                )?;
        }
        Ok(())
    }
    fn begin_activity(
        &self,
        access: &VerifiedAccess,
        kind: &'static str,
        question: Option<&str>,
    ) -> Option<String> {
        self.organization.lock().ok()?.begin(
            self.config.organization_demo.as_ref()?,
            access,
            kind,
            self.model.label(),
            question,
            now(),
        )
    }
    fn activity_tool(&self, id: &Option<String>, query: &MetricsQuery) {
        if let Some(id) = id
            && let Ok(mut organization) = self.organization.lock()
        {
            organization.tool(id, &query.metrics, query.window_secs);
        }
    }
    fn activity_portfolio(&self, id: &Option<String>, query: &PortfolioQuery) {
        if let Some(id) = id
            && let Ok(mut organization) = self.organization.lock()
        {
            organization.portfolio_tool(id, query);
        }
    }
    fn finish_activity(
        &self,
        id: &Option<String>,
        outcome: &'static str,
        source: Option<bool>,
        reason: Option<&str>,
    ) {
        if let Some(id) = id
            && let Ok(mut organization) = self.organization.lock()
        {
            organization.finish(id, outcome, source, reason);
        }
    }
    fn rate(&self, access: &VerifiedAccess) -> Result<(), String> {
        let time = now();
        let mut rates = self.rates.lock().map_err(|_| "rate state unavailable")?;
        rates.retain(|_, r| time - r.start < 60);
        if rates.len() >= 1024 && !rates.contains_key(access.jti()) {
            return Err("rate capacity reached".into());
        }
        let rate = rates.entry(access.jti().to_owned()).or_insert(Rate {
            start: time,
            count: 0,
        });
        if rate.count >= 40 {
            return Err("metric request limit reached; wait for the next minute".into());
        }
        rate.count += 1;
        Ok(())
    }
}
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/.well-known/oauth-protected-resource", get(metadata))
        .route("/.well-known/oauth-protected-resource/mcp", get(metadata))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/api/session", get(session))
        .route("/api/chat", post(chat))
        .route("/api/demo/persona", post(activate_persona))
        .route("/api/organization/activity", get(organization_activity))
        .route("/api/organization/sharing", post(organization_sharing))
        .route("/mcp", post(mcp))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), security))
        .with_state(app)
}
async fn security(
    State(app): State<Arc<App>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let expected = reqwest::Url::parse(&app.config.public_origin).unwrap();
    let authority = match expected.port() {
        Some(port) => format!("{}:{port}", expected.host_str().unwrap()),
        None => expected.host_str().unwrap().to_string(),
    };
    if request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        != Some(authority.as_str())
    {
        return error(
            StatusCode::FORBIDDEN,
            "invalid_host",
            "Unrecognized gateway host.",
        );
    }
    if let Some(origin) = request.headers().get(header::ORIGIN)
        && origin.to_str().ok() != Some(app.config.public_origin.as_str())
    {
        return error(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "Cross-origin requests are not permitted.",
        );
    }
    if request.method() == axum::http::Method::POST
        && request.uri().path() != "/mcp"
        && request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            != Some(app.config.public_origin.as_str())
    {
        return error(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "A same-origin browser request is required.",
        );
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, app.csp.clone());
    response
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .filter(|(n, _)| *n == name)
        .map(|(_, v)| v.to_owned())
        .collect::<Vec<_>>();
    if values.len() == 1 {
        Some(values[0].clone())
    } else {
        None
    }
}
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"error":{"code":code,"message":message}})),
    )
        .into_response()
}
fn auth_error(app: &App, e: AuthError) -> Response {
    let status = StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::UNAUTHORIZED);
    let code = if status == StatusCode::FORBIDDEN {
        "insufficient_scope"
    } else {
        "auth_expired"
    };
    let mut response = error(status, code, &e.to_string());
    let challenge = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", error=\"{}\"",
        app.config.public_origin,
        if status == StatusCode::FORBIDDEN {
            "insufficient_scope"
        } else {
            "invalid_token"
        }
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).unwrap(),
    );
    response
}
async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}
async fn metadata(State(app): State<Arc<App>>) -> Json<Value> {
    Json(
        json!({"resource":app.config.auth.resource_audience,"authorization_servers":[app.config.auth.issuer],"scopes_supported":crate::auth::METRIC_SCOPES,"bearer_methods_supported":["header"],"resource_name":format!("Opaque metrics · {}",app.config.customer_name)}),
    )
}
async fn session(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let (_, access) = match app.session(&headers) {
        Ok(v) => v,
        Err(e) => return auth_error(&app, e),
    };
    let mut value = json!({"customer":{"id":access.tenant_id(),"display_name":app.config.customer_name},"subject":{"id":access.subject(),"display_name":access.subject()},"allowed_metrics":allowed_metrics(&access).iter().map(|m|json!({"id":m,"label":label(m),"unit":unit(m)})).collect::<Vec<_>>(),"runtime":{"kind":if app.model.is_fixture(){"fixture"}else{"language_model"},"label":app.model.label()},"source":{"kind":if app.config.fixture_mode{"synthetic_stream"}else{"customer_stream"},"label":app.config.source.source_id},"approval_mode":if app.config.fixture_mode{"TEST OAUTH · synthetic customer data"}else{"Customer OAuth grant"},"expires_at":access.expires_at(),"scopes":access.scopes(),"suggested_questions":["What is my request rate?","Watch my error rate live"]});
    if app.config.experience == Experience::CreditPortfolio {
        value["experience"] = json!({"kind":"credit_portfolio","title":"Portfolio intelligence","persona":"Portfolio analyst","dataset":"Synthetic loan application events","purpose":"Portfolio monitoring","policy_id":CREDIT_POLICY_ID,"allowed_tool":"opaque_metrics_query"});
        value["suggested_questions"] = json!([
            "What is my application rate?",
            "Watch my manual review rate live",
            "What is my identity mismatch rate?",
            "What is our average credit score?",
            "Show another lender's portfolio",
            "Show raw borrower records"
        ]);
        value["policy_context"] = json!({"tenant_id":access.tenant_id(),"policy_id":CREDIT_POLICY_ID,"persona":"Portfolio analyst","purpose":"Portfolio monitoring","allowed_tool":"opaque_metrics_query","allowed_metrics":allowed_metrics(&access),"latest_decision":app.latest_policy.lock().ok().and_then(|latest|latest.get(access.jti()).cloned())});
    }
    if let Some(config) = &app.config.organization_demo {
        let organization = app
            .organization
            .lock()
            .map_err(|_| "organization state unavailable")
            .and_then(|state| {
                state
                    .session(config, &access, &app.config.customer_name, now())
                    .map_err(|_| "Organization identity unavailable")
            });
        let Ok(mut organization) = organization else {
            return organization_error("Organization identity unavailable.");
        };
        let can_query = organization
            .pointer("/data_entitlement/allowed")
            .and_then(Value::as_bool)
            == Some(true);
        let can_chat = can_query && access.require_scope("metrics:explain").is_ok();
        organization["can_chat"] = json!(can_chat);
        organization["can_query"] = json!(can_query);
        if !can_query {
            value["allowed_metrics"] = json!([]);
            value["scopes"] = json!(
                access
                    .scopes()
                    .iter()
                    .filter(|s| !s.starts_with("metrics:") && !s.starts_with("portfolio:"))
                    .collect::<Vec<_>>()
            );
            value["policy_context"]["allowed_metrics"] = json!([]);
        }
        let persona = organization
            .pointer("/membership/label")
            .cloned()
            .unwrap_or(Value::Null);
        value["experience"]["persona"] = persona.clone();
        value["policy_context"]["persona"] = persona;
        value["organization"] = organization;
    }
    if !app.config.source.allowed_portfolio_measures.is_empty() {
        let permitted = app
            .access_epoch(&access)
            .and_then(|epoch| app.check_data(&access, epoch))
            .is_ok();
        let measures = if permitted {
            allowed_portfolio(&app, &access)
        } else {
            vec![]
        };
        let can_query = permitted
            && access.require_scope(portfolio::READ_SCOPE).is_ok()
            && !measures.is_empty();
        value["dataset"] = portfolio::dataset(&measures, &app.config.source.source_id, can_query);
        value["suggested_questions"] = json!([
            "Which channel has the highest manual review rate in the last 15 minutes?",
            "Compare mobile identity mismatch rates with the previous 15 minutes",
            "Show processing time by channel over the last hour",
            "Show application volume trends over the last hour",
            "Watch our manual review rate live"
        ]);
        let mut tools = vec![];
        if permitted && access.require_scope("metrics:read").is_ok() {
            tools.push("opaque_metrics_query");
        }
        if can_query {
            tools.push(portfolio::TOOL);
        }
        value["policy_context"]["allowed_tools"] = json!(tools);
    }
    Json(value).into_response()
}

fn organization_error(message: &str) -> Response {
    error(StatusCode::FORBIDDEN, "organization_access_denied", message)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonaRequest {
    persona_id: Persona,
    reason: Option<String>,
}
async fn activate_persona(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PersonaRequest>,
) -> Response {
    let Some(config) = &app.config.organization_demo else {
        return error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Organization simulation is not enabled.",
        );
    };
    let (_, access) = match app.session(&headers) {
        Ok(value) => value,
        Err(e) => return auth_error(&app, e),
    };
    let result = app
        .organization
        .lock()
        .map_err(|_| "organization state unavailable".to_string())
        .and_then(|mut state| {
            state.activate(
                config,
                &access,
                request.persona_id,
                request.reason.as_deref(),
                now(),
                |details| app.organization_audit(&access, details),
            )
        });
    if let Err(message) = result {
        return organization_error(&message);
    }
    session(State(app), headers).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharingRequest {
    enabled: bool,
}
async fn organization_sharing(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<SharingRequest>,
) -> Response {
    let Some(config) = &app.config.organization_demo else {
        return error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Organization simulation is not enabled.",
        );
    };
    let (_, access) = match app.session(&headers) {
        Ok(value) => value,
        Err(e) => return auth_error(&app, e),
    };
    let result = app
        .organization
        .lock()
        .map_err(|_| "organization state unavailable".to_string())
        .and_then(|mut state| {
            state.set_sharing(config, &access, request.enabled, |details| {
                app.organization_audit(&access, details)
            })
        });
    if let Err(message) = result {
        return organization_error(&message);
    }
    session(State(app), headers).await
}
async fn organization_activity(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some(config) = &app.config.organization_demo else {
        return error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Organization simulation is not enabled.",
        );
    };
    let (_, access) = match app.session(&headers) {
        Ok(value) => value,
        Err(e) => return auth_error(&app, e),
    };
    let result = app
        .organization
        .lock()
        .map_err(|_| "organization state unavailable".to_string())
        .and_then(|mut state| state.activity(config, &access, &app.config.customer_name, now()));
    if let Err(message) = result {
        return organization_error(&message);
    }
    let epoch = match app.access_epoch(&access) {
        Ok(value) => value,
        Err(message) => return organization_error(&message),
    };
    // Project at body delivery, not when the request handler was entered: a
    // paused reader cannot retain text after the customer withdraws consent.
    let body = axum::body::Body::from_stream(stream::once(async move {
        let result = app.check_epoch(&access, epoch).and_then(|_| {
            let config = app
                .config
                .organization_demo
                .as_ref()
                .ok_or("Organization unavailable")?;
            app.organization
                .lock()
                .map_err(|_| "organization state unavailable".to_string())?
                .activity(config, &access, &app.config.customer_name, now())
        });
        let value=result.unwrap_or_else(|_|json!({"error":{"code":"organization_access_denied","message":"Organization authority changed before activity delivery."}}));
        Ok::<_, Infallible>(serde_json::to_vec(&value).unwrap())
    }));
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}
async fn bounded_json(mut response: reqwest::Response) -> Result<Value, String> {
    if !response.status().is_success() {
        return Err("upstream rejected request".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "upstream response interrupted")?
    {
        if bytes.len() + chunk.len() > 32768 {
            return Err("upstream response exceeded limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid upstream JSON".into())
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginQuery {
    persona_id: Option<Persona>,
}
async fn login(State(app): State<Arc<App>>, Query(query): Query<LoginQuery>) -> Response {
    let (client_id, expected_subject, scopes) = if let Some(config) = &app.config.organization_demo
    {
        let member = config.persona(query.persona_id.unwrap_or(Persona::CustomerAnalyst));
        let scopes = app
            .config
            .auth
            .admissions
            .iter()
            .find(|a| a.subject == member.subject)
            .expect("validated member admission")
            .scopes
            .clone();
        (
            member.oauth_client_id.clone(),
            Some(member.subject.clone()),
            scopes,
        )
    } else {
        if query.persona_id.is_some() {
            return error(
                StatusCode::NOT_FOUND,
                "not_found",
                "Persona sign-in is available only in the organization demo.",
            );
        }
        (
            app.config.oauth.client_id.clone(),
            None,
            app.config.oauth.scopes.clone(),
        )
    };
    // The client is preregistered. Check S256 support from the trusted issuer's
    // metadata; never discover endpoints from a browser-supplied issuer.
    let issuer_url = reqwest::Url::parse(&app.config.auth.issuer).unwrap();
    let issuer_path = issuer_url.path().trim_end_matches('/');
    let mut metadata_urls = Vec::new();
    for path in [
        format!("/.well-known/oauth-authorization-server{issuer_path}"),
        format!("/.well-known/openid-configuration{issuer_path}"),
        format!("{issuer_path}/.well-known/openid-configuration"),
    ] {
        let mut url = issuer_url.clone();
        url.set_path(&path);
        if !metadata_urls.contains(&url) {
            metadata_urls.push(url);
        }
    }
    let mut valid = false;
    for metadata_url in metadata_urls {
        let metadata = match app.http.get(metadata_url).send().await {
            Ok(r) => bounded_json(r).await,
            Err(_) => Err("issuer unavailable".into()),
        };
        if metadata.is_ok_and(|m| {
            m.get("issuer").and_then(Value::as_str) == Some(app.config.auth.issuer.as_str())
                && m.get("authorization_endpoint").and_then(Value::as_str)
                    == Some(app.config.oauth.authorization_endpoint.as_str())
                && m.get("token_endpoint").and_then(Value::as_str)
                    == Some(app.config.oauth.token_endpoint.as_str())
                && m.get("code_challenge_methods_supported")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().any(|v| v == "S256"))
        }) {
            valid = true;
            break;
        }
    }
    if !valid {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "issuer_unavailable",
            "The trusted OAuth issuer is unavailable or does not support the required PKCE flow.",
        );
    }
    let (state, verifier, binding) = match (random(), random(), random()) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Login unavailable.",
            );
        }
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    {
        let mut pending = app.pending.lock().unwrap();
        pending.retain(|_, p| now() - p.created_at < 300);
        if pending.len() >= 256 {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "busy",
                "Too many pending sign-ins.",
            );
        }
        pending.insert(
            state.clone(),
            PendingLogin {
                verifier: Zeroizing::new(verifier),
                browser_binding: binding.clone(),
                created_at: now(),
                client_id: client_id.clone(),
                expected_subject,
                scopes: scopes.clone(),
            },
        );
    }
    let mut url = reqwest::Url::parse(&app.config.oauth.authorization_endpoint).unwrap();
    url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        (
            "redirect_uri",
            &format!("{}/auth/callback", app.config.public_origin),
        ),
        ("resource", app.config.auth.resource_audience.as_str()),
        (
            "scope",
            &scopes.iter().cloned().collect::<Vec<_>>().join(" "),
        ),
        ("state", &state),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let mut response = Redirect::temporary(url.as_str()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&app.set_cookie(
            &format!("{}_login", app.cookie_name()),
            &binding,
            300,
        ))
        .unwrap(),
    );
    response
}
#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
}
async fn callback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    let Some(state) = query.state.filter(|v| v.len() <= 128) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_login",
            "Login state is missing.",
        );
    };
    let pending = app.pending.lock().unwrap().remove(&state);
    let Some(pending) = pending else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_login",
            "Login is expired or already used.",
        );
    };
    if now() - pending.created_at >= 300
        || cookie(&headers, &format!("{}_login", app.cookie_name())).as_deref()
            != Some(&pending.browser_binding)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_login",
            "Login browser binding did not match.",
        );
    }
    let Some(code) = query.code.filter(|v| !v.is_empty() && v.len() <= 4096) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_login",
            "Authorization code is missing.",
        );
    };
    let response = app
        .http
        .post(&app.config.oauth.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", pending.client_id.as_str()),
            (
                "redirect_uri",
                &format!("{}/auth/callback", app.config.public_origin),
            ),
            ("resource", app.config.auth.resource_audience.as_str()),
            ("code", &code),
            ("code_verifier", pending.verifier.as_str()),
        ])
        .send()
        .await;
    let body = match response {
        Ok(r) => bounded_json(r).await,
        Err(_) => Err("token exchange failed".into()),
    };
    let Ok(body) = body else {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_login",
            "OAuth token exchange failed.",
        );
    };
    if body
        .get("token_type")
        .and_then(Value::as_str)
        .is_none_or(|t| !t.eq_ignore_ascii_case("bearer"))
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_login",
            "Issuer returned an unsupported token type.",
        );
    }
    let Some(token) = body.get("access_token").and_then(Value::as_str) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_login",
            "Issuer returned no access token.",
        );
    };
    let access = match app.auth.verify_bearer(Some(&format!("Bearer {token}"))) {
        Ok(v) => v,
        Err(e) => return auth_error(&app, e),
    };
    if !access.scopes().is_subset(&pending.scopes)
        || access.client_id() != pending.client_id
        || pending
            .expected_subject
            .as_ref()
            .is_some_and(|subject| access.subject() != subject)
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_login",
            "Issuer granted unrequested scope.",
        );
    }
    let sid = match random() {
        Ok(v) => v,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Session unavailable.",
            );
        }
    };
    {
        let mut sessions = app.sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires_at > now());
        if sessions.len() >= 256 {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "busy",
                "Session capacity reached.",
            );
        }
        sessions.insert(
            sid.clone(),
            BrowserSession {
                token: Zeroizing::new(token.into()),
                expires_at: access.expires_at(),
            },
        );
    }
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&app.set_cookie(
            &app.cookie_name(),
            &sid,
            access.expires_at() - now(),
        ))
        .unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&app.set_cookie(&format!("{}_login", app.cookie_name()), "", 0))
            .unwrap(),
    );
    response
}
async fn logout(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let (_, access) = match app.session(&headers) {
        Ok(v) => v,
        Err(e) => return auth_error(&app, e),
    };
    if app.auth.revoke_jti(access.jti()).is_err() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Revocation unavailable.",
        );
    }
    let persisted = (|| -> Result<(), String> {
        let mut revoked = app
            .revoked
            .lock()
            .map_err(|_| "revocation state unavailable")?;
        revoked.insert(access.jti().to_owned());
        let path = app.config.state_dir.join("revoked.json.new");
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| "revocation persistence failed")?;
        f.write_all(&serde_json::to_vec(&*revoked).unwrap())
            .map_err(|_| "revocation persistence failed")?;
        f.sync_all().map_err(|_| "revocation persistence failed")?;
        std::fs::rename(path, app.config.state_dir.join("revoked.json"))
            .map_err(|_| "revocation persistence failed")?;
        File::open(&app.config.state_dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| "revocation persistence failed")?;
        Ok(())
    })();
    if persisted.is_err() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Access is revoked here, but durable revocation could not be recorded.",
        );
    }
    if let Some(sid) = cookie(&headers, &app.cookie_name()) {
        app.sessions.lock().unwrap().remove(&sid);
    }
    let mut response = Json(json!({"revoked":true})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&app.set_cookie(&app.cookie_name(), "", 0)).unwrap(),
    );
    response
}
fn allowed_metrics(access: &VerifiedAccess) -> Vec<String> {
    crate::chat::METRICS
        .iter()
        .filter(|m| access.scopes().contains(&format!("metrics:metric:{m}")))
        .map(|m| m.to_string())
        .collect()
}
fn allowed_portfolio(app: &App, access: &VerifiedAccess) -> Vec<Measure> {
    app.config
        .source
        .allowed_portfolio_measures
        .iter()
        .filter(|m| access.scopes().contains(&m.scope()))
        .copied()
        .collect()
}
fn portfolio_scope(
    app: &App,
    access: &VerifiedAccess,
    query: &PortfolioQuery,
) -> Result<(), String> {
    app.auth.check_access(access).map_err(|e| e.to_string())?;
    access
        .require_scope(portfolio::READ_SCOPE)
        .map_err(|e| e.to_string())?;
    query.validate(&allowed_portfolio(app, access))
}
fn query_scope(access: &VerifiedAccess, query: &MetricsQuery) -> Result<(), AuthError> {
    access.require_scope("metrics:read")?;
    for name in &query.metrics {
        access.require_scope(&format!("metrics:metric:{name}"))?;
    }
    Ok(())
}
fn rpc(id: Value, result: Value) -> Response {
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}
fn rpc_error(id: Value, code: i32, message: &str) -> Response {
    Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})).into_response()
}
async fn mcp(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return auth_error(&app, AuthError::MissingBearer);
    }
    let access = match app.auth.verify_bearer(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
    ) {
        Ok(v) => v,
        Err(e) => return auth_error(&app, e),
    };
    let epoch = match app.access_epoch(&access) {
        Ok(value) => value,
        Err(message) => return organization_error(&message),
    };
    // This optional expectation only narrows server authority. Nested chat
    // requests carry it so an old request cannot become new work after ABA.
    if let Some(expected) = headers.get("x-opaque-persona-generation")
        && expected.to_str().ok().and_then(|v| v.parse::<u64>().ok()) != Some(epoch.unwrap_or(0))
    {
        return organization_error("The demo identity changed before this tool request arrived.");
    }
    if let Some(version) = headers.get("mcp-protocol-version")
        && version != "2025-11-25"
        && version != "2025-06-18"
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_protocol",
            "Unsupported MCP protocol version.",
        );
    }
    if headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| !v.contains("application/json") || !v.contains("text/event-stream"))
    {
        return error(
            StatusCode::NOT_ACCEPTABLE,
            "invalid_accept",
            "Accept must include application/json and text/event-stream.",
        );
    }
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !request.is_object()
        || (!id.is_null() && !id.is_string() && !id.is_i64() && !id.is_u64())
    {
        return rpc_error(id, -32600, "Invalid JSON-RPC request");
    }
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "notifications/initialized" && id.is_null() {
        return StatusCode::ACCEPTED.into_response();
    }
    if id.is_null() {
        return rpc_error(id, -32600, "Request ID is required");
    }
    match method {
        "initialize" => {
            let version = request
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-11-25");
            let negotiated = if ["2025-11-25", "2025-06-18"].contains(&version) {
                version
            } else {
                "2025-11-25"
            };
            rpc(
                id,
                json!({"protocolVersion":negotiated,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"opaque-metrics","version":env!("CARGO_PKG_VERSION")},"instructions":"Customer identity comes from the access token. Never put tenant IDs or credentials in tool arguments. Results are scoped aggregate evidence."}),
            )
        }
        "ping" => rpc(id, json!({})),
        "tools/list" => {
            let mut tools = if access.require_scope("metrics:read").is_ok()
                && app.check_data(&access, epoch).is_ok()
            {
                vec![
                    json!({"name":"opaque_metrics_query","description":"Read a bounded aggregate snapshot of the authenticated customer's live metrics. The server selects the source and credential. No tenant override, SQL, URL, raw rows or credentials are accepted.","inputSchema":{"type":"object","additionalProperties":false,"properties":{"window_secs":{"type":"integer","minimum":1,"maximum":300},"metrics":{"type":"array","items":{"type":"string","enum":allowed_metrics(&access)},"minItems":1,"maxItems":4}},"required":["window_secs","metrics"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
                ]
            } else {
                vec![]
            };
            let measures = allowed_portfolio(&app, &access);
            if access.require_scope(portfolio::READ_SCOPE).is_ok()
                && app.check_data(&access, epoch).is_ok()
                && !measures.is_empty()
            {
                tools.push(json!({"name":portfolio::TOOL,"description":"Read computed synthetic portfolio totals, trends, category breakdowns or adjacent-period comparisons. No tenant override, URL, SQL, raw records or credentials.","inputSchema":portfolio::tool_schema(&measures),"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}));
            }
            rpc(id, json!({"tools":tools}))
        }
        "tools/call" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ToolCall {
                name: String,
                arguments: Value,
            }
            let call = match serde_json::from_value::<ToolCall>(
                request.get("params").cloned().unwrap_or(Value::Null),
            ) {
                Ok(v) => v,
                Err(_) => return rpc_error(id, -32602, "Invalid tool arguments"),
            };
            if call.name == portfolio::TOOL {
                let query = match serde_json::from_value::<PortfolioQuery>(call.arguments) {
                    Ok(query) => query,
                    Err(_) => return rpc_error(id, -32602, "Invalid portfolio arguments"),
                };
                return portfolio_mcp(&app, &access, epoch, id, query).await;
            }
            if call.name != "opaque_metrics_query" {
                return rpc_error(id, -32602, "Unsupported tool");
            }
            let arguments = match serde_json::from_value::<MetricsQuery>(call.arguments) {
                Ok(query) => query,
                Err(_) => return rpc_error(id, -32602, "Invalid metric arguments"),
            };
            let activity = app.begin_activity(&access, "tool_call", None);
            if let Err(message) = app.check_data(&access, epoch) {
                app.finish_activity(
                    &activity,
                    "denied",
                    Some(false),
                    Some("customer_entitlement_denied"),
                );
                let _ = app.audit(
                    &access,
                    "metrics.query",
                    "denied_customer_entitlement",
                    None,
                );
                return organization_error(&message);
            }
            if let Err(e) = query_scope(&access, &arguments) {
                app.finish_activity(
                    &activity,
                    "denied",
                    Some(false),
                    Some("metric_scope_denied"),
                );
                let _ = app.audit(&access, "metrics.query", "denied_scope", None);
                return auth_error(&app, e);
            }
            if app.rate(&access).is_err() {
                app.finish_activity(&activity, "denied", Some(false), Some("rate_limit"));
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limit",
                    "Metric request limit reached.",
                );
            }
            if app
                .audit(&access, "metrics.query", "authorized", None)
                .is_err()
            {
                app.finish_activity(&activity, "failed", Some(false), Some("audit_unavailable"));
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "audit_unavailable",
                    "Metric query could not be recorded.",
                );
            }
            if let Err(message) = app.check_data(&access, epoch) {
                return organization_error(&message);
            }
            app.activity_tool(&activity, &arguments);
            let evidence = match app.metrics.query(access.tenant_id(), arguments).await {
                Ok(v) => v,
                Err(_) => {
                    app.finish_activity(&activity, "failed", None, Some("source_unavailable"));
                    let _ = app.audit(&access, "metrics.query", "source_unavailable", None);
                    return rpc(
                        id,
                        json!({"isError":true,"content":[{"type":"text","text":"Metric source returned no usable, fresh evidence. No automatic retry was made."}]}),
                    );
                }
            };
            app.finish_activity(&activity, "observed", Some(true), None);
            if let Err(message) = app.check_data(&access, epoch) {
                return organization_error(&message);
            }
            if app
                .audit(&access, "metrics.query", "observed", Some(&evidence))
                .is_err()
            {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "audit_unavailable",
                    "Metric result could not be recorded.",
                );
            }
            rpc(
                id,
                json!({"isError":false,"structuredContent":evidence,"content":[{"type":"text","text":serde_json::to_string(&evidence).unwrap()}]}),
            )
        }
        _ => rpc_error(id, -32601, "Method not found"),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatRequest {
    message: String,
}
type ChatEvent = Result<(Event, bool), Infallible>;
struct ActiveChat {
    app: Arc<App>,
    jti: String,
}
impl Drop for ActiveChat {
    fn drop(&mut self) {
        if let Ok(mut set) = self.app.active_chats.lock() {
            set.remove(&self.jti);
        }
    }
}
async fn chat(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<ChatRequest>,
) -> Response {
    let (token, access) = match app.session(&headers) {
        Ok(v) => v,
        Err(e) => return auth_error(&app, e),
    };
    let portfolio_request = app.config.experience == Experience::CreditPortfolio
        && !app.config.source.allowed_portfolio_measures.is_empty()
        && crate::chat::requested_watch_secs(&request.message).is_ok_and(|seconds| seconds == 0);
    if app.config.organization_demo.is_none()
        && let Err(e) = access.require_scope("metrics:explain").and_then(|_| {
            access.require_scope(if portfolio_request {
                portfolio::READ_SCOPE
            } else {
                "metrics:read"
            })
        })
    {
        return auth_error(&app, e);
    }
    if request.message.trim().is_empty()
        || request.message.len() > 2000
        || request
            .message
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_question",
            "Ask a metric question using at most 2,000 bytes.",
        );
    }
    let epoch = match app.access_epoch(&access) {
        Ok(value) => value,
        Err(message) => {
            return Sse::new(stream::iter(vec![
                Ok::<_, Infallible>(
                    Event::default()
                        .event("error")
                        .json_data(json!({"code":"organization_access_denied","message":message}))
                        .unwrap(),
                ),
                Ok(Event::default().event("done").data("{}")),
            ]))
            .into_response();
        }
    };
    let permit = match app.capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return error(StatusCode::TOO_MANY_REQUESTS, "busy", "The agent is busy."),
    };
    {
        let mut active = app.active_chats.lock().unwrap();
        if !active.insert(access.jti().to_owned()) {
            return error(
                StatusCode::CONFLICT,
                "busy",
                "A live answer is already running for this grant.",
            );
        }
    }
    let guard = ActiveChat {
        app: app.clone(),
        jti: access.jti().to_owned(),
    };
    let activity = app.begin_activity(&access, "chat", Some(&request.message));
    let (tx, rx) = mpsc::channel::<ChatEvent>(4);
    let stream_app = app.clone();
    let stream_access = access.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let _permit = permit;
        tokio::select! {_ = tx.closed()=>{}, _=run_chat(app.clone(),token,access,request.message,epoch,activity,&tx)=>{}}
    });
    let events = stream::unfold(
        (rx, stream_app, stream_access, false),
        move |(mut rx, app, access, ended)| async move {
            if ended {
                return None;
            }
            let Ok((event, requires_data)) = rx.recv().await?;
            // Check again at body delivery: revocation must discard evidence that
            // was queued while the consumer was paused or applying backpressure.
            if app.check_epoch(&access, epoch).is_err()
                || (requires_data && app.check_data(&access, epoch).is_err())
            {
                rx.close();
                let revoked = Event::default().event("error").data("{\"code\":\"auth_expired\",\"message\":\"Authorization expired or was revoked. The live answer has stopped.\"}");
                return Some((Ok::<Event, Infallible>(revoked), (rx, app, access, true)));
            }
            Some((Ok(event), (rx, app, access, false)))
        },
    );
    Sse::new(events)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(5)))
        .into_response()
}
async fn emit(tx: &mpsc::Sender<ChatEvent>, kind: &str, value: Value) -> Result<(), String> {
    tx.send(Ok((
        Event::default()
            .event(kind)
            .json_data(value)
            .map_err(|_| "event encoding failed")?,
        matches!(kind, "result" | "portfolio_result" | "answer" | "tool"),
    )))
    .await
    .map_err(|_| "client disconnected".into())
}
async fn run_chat(
    app: Arc<App>,
    token: Zeroizing<String>,
    access: VerifiedAccess,
    message: String,
    epoch: Option<u64>,
    activity: Option<String>,
    tx: &mpsc::Sender<ChatEvent>,
) {
    let result = run_chat_inner(&app, &token, &access, &message, epoch, &activity, tx).await;
    app.finish_activity(
        &activity,
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
        None,
        None,
    );
    if let Err(e) = result {
        let auth_failed = app.auth.check_access(&access).is_err();
        let _ = emit(
            tx,
            "error",
            json!({"code":if auth_failed{"auth_expired"}else{"request_denied"},"message":e}),
        )
        .await;
    }
    let _ = emit(
        tx,
        "done",
        json!({"request_id":activity.unwrap_or_else(||Uuid::new_v4().to_string())}),
    )
    .await;
}
async fn policy_event(
    (app, access, tx): (&App, &VerifiedAccess, &mpsc::Sender<ChatEvent>),
    phase: &str,
    outcome: &str,
    reason_code: &str,
    message: &str,
    source_accessed: bool,
) -> Result<(), String> {
    policy_event_for(
        (app, access, tx, "opaque_metrics_query"),
        phase,
        outcome,
        reason_code,
        message,
        source_accessed,
    )
    .await
}
async fn policy_event_for(
    (app, access, tx, tool): (&App, &VerifiedAccess, &mpsc::Sender<ChatEvent>, &str),
    phase: &str,
    outcome: &str,
    reason_code: &str,
    message: &str,
    source_accessed: bool,
) -> Result<(), String> {
    if app.config.experience != Experience::CreditPortfolio {
        return Ok(());
    }
    app.auth.check_access(access).map_err(|e| e.to_string())?;
    let value = json!({"phase":phase,"outcome":outcome,"reason_code":reason_code,"message":message,
        "tenant_id":access.tenant_id(),"policy_id":CREDIT_POLICY_ID,"tool":tool,"source_accessed":source_accessed});
    {
        let mut latest = app
            .latest_policy
            .lock()
            .map_err(|_| "policy state unavailable")?;
        if latest.len() >= 512
            && !latest.contains_key(access.jti())
            && let Some(key) = latest.keys().next().cloned()
        {
            latest.remove(&key);
        }
        latest.insert(access.jti().to_owned(), value.clone());
    }
    emit(tx, "policy", value).await
}
async fn run_chat_inner(
    app: &Arc<App>,
    token: &str,
    access: &VerifiedAccess,
    message: &str,
    epoch: Option<u64>,
    activity: &Option<String>,
    tx: &mpsc::Sender<ChatEvent>,
) -> Result<(), String> {
    app.check_epoch(access, epoch)?;
    let use_portfolio = app.config.experience == Experience::CreditPortfolio
        && !app.config.source.allowed_portfolio_measures.is_empty()
        && crate::chat::requested_watch_secs(message)? == 0;
    let data = app.check_data(access, epoch).and_then(|_| {
        access
            .require_scope(if use_portfolio {
                portfolio::READ_SCOPE
            } else {
                "metrics:read"
            })
            .and_then(|_| access.require_scope("metrics:explain"))
            .map_err(|e| e.to_string())
    });
    if let Err(message) = data {
        app.audit(
            access,
            "organization.customer_query",
            "denied_customer_entitlement",
            None,
        )?;
        app.finish_activity(
            activity,
            "denied",
            Some(false),
            Some("customer_entitlement_denied"),
        );
        policy_event(
            (app, access, tx),
            "request_check",
            "denied",
            "customer_entitlement_denied",
            &message,
            false,
        )
        .await?;
        return Err(message);
    }
    if app.rate(access).is_err() {
        return Err("Agent request limit reached; wait for the next minute.".into());
    }
    if app.config.experience == Experience::CreditPortfolio {
        if app
            .config
            .organization_demo
            .as_ref()
            .is_some_and(|config| config.foreign_customer_requested(message))
        {
            let reason = "The named customer is a directory entry only. Organization membership does not grant access to its metrics; this session can read only its assigned customer's aggregates.";
            app.audit(access, "portfolio.policy", "customer_scope_denied", None)?;
            app.finish_activity(
                activity,
                "denied",
                Some(false),
                Some("customer_scope_denied"),
            );
            policy_event(
                (app, access, tx),
                "request_check",
                "denied",
                "customer_scope_denied",
                reason,
                false,
            )
            .await?;
            return Err(reason.into());
        }
        if let Some(denial) = credit_request_denial(message) {
            app.audit(access, "portfolio.policy", denial.reason_code, None)?;
            app.finish_activity(activity, "denied", Some(false), Some(denial.reason_code));
            policy_event(
                (app, access, tx),
                "request_check",
                "denied",
                denial.reason_code,
                denial.message,
                false,
            )
            .await?;
            return Err(denial.message.into());
        }
        if !use_portfolio
            && !app.config.source.allowed_portfolio_measures.is_empty()
            && let Err(message) = crate::chat::portfolio_watch_check(message)
        {
            app.finish_activity(
                activity,
                "denied",
                Some(false),
                Some("unsupported_watch_query"),
            );
            app.audit(access, "portfolio.policy", "unsupported_watch_query", None)?;
            policy_event(
                (app, access, tx),
                "request_check",
                "denied",
                "unsupported_watch_query",
                &message,
                false,
            )
            .await?;
            return Err(message);
        }
        if !use_portfolio
            && let Err(message) =
                crate::chat::deny_explicit_out_of_scope_metrics(message, &allowed_metrics(access))
        {
            app.audit(access, "portfolio.policy", "metric_scope_denied", None)?;
            app.finish_activity(activity, "denied", Some(false), Some("metric_scope_denied"));
            policy_event(
                (app, access, tx),
                "request_check",
                "denied",
                "metric_scope_denied",
                &message,
                false,
            )
            .await?;
            return Err(message);
        }
    }
    emit(
        tx,
        "status",
        json!({"message":"Selecting an authorized metrics tool…"}),
    )
    .await?;
    // A separate explain scope authorizes this configured model destination.
    app.audit(access, "metrics.explain", "authorized", None)?;
    // Each chat is a short-lived MCP client. Negotiate the stateless transport
    // and retrieve its scoped tool catalog before asking the model to plan.
    let initialized = app.http.post(format!("{}/mcp", app.config.public_origin))
        .bearer_auth(token).header("X-Opaque-Persona-Generation",epoch.unwrap_or(0)).header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({"jsonrpc":"2.0","id":"initialize","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"opaque-chat","version":env!("CARGO_PKG_VERSION")}}}))
        .send().await.map_err(|_| "MCP initialization did not complete.")?;
    let initialized = bounded_json(initialized).await?;
    if initialized
        .pointer("/result/protocolVersion")
        .and_then(Value::as_str)
        != Some("2025-11-25")
    {
        return Err("MCP protocol negotiation failed.".into());
    }
    let acknowledged = app
        .http
        .post(format!("{}/mcp", app.config.public_origin))
        .bearer_auth(token)
        .header("X-Opaque-Persona-Generation", epoch.unwrap_or(0))
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .map_err(|_| "MCP initialization acknowledgement failed.")?;
    if acknowledged.status() != StatusCode::ACCEPTED {
        return Err("MCP initialization was not accepted.".into());
    }
    let catalog = app
        .http
        .post(format!("{}/mcp", app.config.public_origin))
        .bearer_auth(token)
        .header("X-Opaque-Persona-Generation", epoch.unwrap_or(0))
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-11-25")
        .json(&json!({"jsonrpc":"2.0","id":"tools","method":"tools/list"}))
        .send()
        .await
        .map_err(|_| "MCP tool discovery failed.")?;
    let catalog = bounded_json(catalog).await?;
    let wanted_tool = if use_portfolio {
        portfolio::TOOL
    } else {
        "opaque_metrics_query"
    };
    if catalog
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .is_none_or(|tools| {
            !tools
                .iter()
                .any(|tool| tool.get("name").and_then(Value::as_str) == Some(wanted_tool))
        })
    {
        return Err("No authorized metric tool is available.".into());
    }
    app.check_data(access, epoch)?;
    if use_portfolio {
        return run_portfolio_chat(app, token, access, message, epoch, activity, tx).await;
    }
    // A failed model response is not evidence of a policy denial. The error
    // channel reports it without inventing a source-access or authorization verdict.
    let plan = app.model.plan(message, &allowed_metrics(access)).await?;
    app.check_data(access, epoch)?;
    if let Err(error) = query_scope(access, &plan.query()) {
        let message = error.to_string();
        policy_event(
            (app, access, tx),
            "tool_check",
            "denied",
            "metric_scope_denied",
            &message,
            false,
        )
        .await?;
        return Err(message);
    }
    if plan.watch_secs > 0 && access.require_scope("metrics:stream").is_err() {
        let message = "Live monitoring is outside this session's allowed stream scope.";
        policy_event(
            (app, access, tx),
            "tool_check",
            "denied",
            "stream_scope_denied",
            message,
            false,
        )
        .await?;
        return Err(message.into());
    }
    let end = tokio::time::Instant::now() + Duration::from_secs(plan.watch_secs as u64);
    let mut sequence = 0;
    let evidence = loop {
        app.check_data(access, epoch)?;
        query_scope(access, &plan.query()).map_err(|e| e.to_string())?;
        policy_event((app, access, tx), "tool_check", "allowed", "tool_scope_allowed",
            "Metric scopes checked for this customer. MCP will authorize this aggregate read separately.", false).await?;
        sequence += 1;
        let evidence_id = Uuid::new_v4().to_string();
        emit(tx,"tool",json!({"name":"opaque_metrics_query","phase":"request","message":format!("Authorized {} · {} second window",access.tenant_id(),plan.window_secs),"evidence_id":evidence_id})).await?;
        // Exercise the same bearer-authenticated HTTP MCP boundary used by
        // external agents. No direct provider shortcut exists in the chat path.
        app.check_data(access, epoch)?;
        app.activity_tool(activity, &plan.query());
        let response=app.http.post(format!("{}/mcp",app.config.public_origin)).bearer_auth(token).header("X-Opaque-Persona-Generation",epoch.unwrap_or(0)).header(header::ACCEPT,"application/json, text/event-stream").header("MCP-Protocol-Version","2025-11-25").json(&json!({"jsonrpc":"2.0","id":evidence_id,"method":"tools/call","params":{"name":"opaque_metrics_query","arguments":plan.query()}})).send().await.map_err(|_|"MCP request did not complete; no automatic retry was made.")?;
        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
        {
            return Err("MCP authorization denied this request.".into());
        }
        let body = bounded_json(response)
            .await
            .map_err(|_| "MCP returned no usable response; no automatic retry was made.")?;
        if body.pointer("/result/isError").and_then(Value::as_bool) != Some(false) {
            return Err(
                "MCP returned no authorized metric evidence; the live answer has stopped.".into(),
            );
        }
        let evidence: MetricsEvidence = serde_json::from_value(
            body.pointer("/result/structuredContent")
                .cloned()
                .ok_or("MCP result had no evidence")?,
        )
        .map_err(|_| "MCP evidence was invalid")?;
        if evidence.tenant_id != access.tenant_id() {
            return Err("MCP evidence tenant did not match authorization.".into());
        }
        app.check_data(access, epoch)?;
        app.finish_activity(activity, "running", Some(true), None);
        policy_event(
            (app, access, tx),
            "source_read",
            "allowed",
            "source_evidence_received",
            "Fresh aggregate evidence received through the authorized customer source.",
            true,
        )
        .await?;
        for metric in &evidence.metrics {
            app.check_data(access, epoch)?;
            emit(tx,"result",json!({"metric_id":metric.name,"label":label(&metric.name),"value":metric.value,"unit":unit(&metric.name),"observed_at":evidence.observed_at,"as_of":evidence.as_of,"watermark":evidence.watermark,"window_secs":evidence.window_secs,"sample_count":metric.count,"stale_after_secs":app.config.source.max_staleness_secs,"source":evidence.source_id,"evidence_id":evidence_id,"sequence":sequence})).await?;
        }
        emit(tx,"tool",json!({"name":"opaque_metrics_query","phase":"complete","message":"Scoped aggregate evidence received","evidence_id":evidence_id})).await?;
        if plan.watch_secs == 0 || tokio::time::Instant::now() + Duration::from_secs(2) > end {
            break evidence;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    app.check_data(access, epoch)?;
    access
        .require_scope("metrics:explain")
        .map_err(|e| e.to_string())?;
    emit(
        tx,
        "status",
        json!({"message":"Explaining the latest authorized snapshot…"}),
    )
    .await?;
    app.check_data(access, epoch)?;
    access
        .require_scope("metrics:explain")
        .map_err(|e| e.to_string())?;
    let answer = app.model.answer(message, &evidence).await?;
    app.check_data(access, epoch)?;
    app.audit(access, "metrics.explain", "observed", Some(&evidence))?;
    emit(tx, "answer", json!({"text":answer})).await?;
    Ok(())
}

async fn portfolio_mcp(
    app: &Arc<App>,
    access: &VerifiedAccess,
    epoch: Option<u64>,
    id: Value,
    query: PortfolioQuery,
) -> Response {
    let activity = app.begin_activity(access, "tool_call", None);
    if let Err(message) = app
        .check_data(access, epoch)
        .and_then(|_| portfolio_scope(app, access, &query))
    {
        app.finish_activity(
            &activity,
            "denied",
            Some(false),
            Some("portfolio_scope_denied"),
        );
        let _ = app.audit(access, "portfolio.query", "denied_scope", None);
        return organization_error(&message);
    }
    if app.rate(access).is_err() {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit",
            "Portfolio request limit reached.",
        );
    }
    if app
        .audit(access, "portfolio.query", "authorized", None)
        .is_err()
    {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "Portfolio query could not be recorded.",
        );
    }
    if let Err(message) = app
        .check_data(access, epoch)
        .and_then(|_| portfolio_scope(app, access, &query))
    {
        return organization_error(&message);
    }
    app.activity_portfolio(&activity, &query);
    let evidence = match app.metrics.query_portfolio(access.tenant_id(), query).await {
        Ok(evidence) => evidence,
        Err(_) => {
            app.finish_activity(&activity, "failed", None, Some("source_unavailable"));
            let _ = app.audit(access, "portfolio.query", "source_unavailable", None);
            return rpc(
                id,
                json!({"isError":true,"content":[{"type":"text","text":"Portfolio source returned no complete, fresh aggregate evidence. No automatic retry was made."}]}),
            );
        }
    };
    app.finish_activity(&activity, "observed", Some(true), None);
    if let Err(message) = app
        .check_data(access, epoch)
        .and_then(|_| portfolio_scope(app, access, &evidence.snapshot.query))
    {
        return organization_error(&message);
    }
    if portfolio_audit(app, access, &evidence).is_err() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            "Portfolio evidence could not be recorded.",
        );
    }
    rpc(
        id,
        json!({"isError":false,"structuredContent":evidence,"content":[{"type":"text","text":serde_json::to_string(&evidence).unwrap()}]}),
    )
}
fn portfolio_audit(
    app: &App,
    access: &VerifiedAccess,
    evidence: &PortfolioEvidence,
) -> Result<(), String> {
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(evidence).map_err(|_| "Evidence encoding failed")?)
    );
    app.organization_audit(access,&json!({"operation":"portfolio.query","outcome":"observed","source_id":evidence.source_id,"query":evidence.snapshot.query,"as_of":evidence.snapshot.as_of,"watermark":evidence.snapshot.watermark,"evidence_sha256":digest}))
}
async fn run_portfolio_chat(
    app: &Arc<App>,
    token: &str,
    access: &VerifiedAccess,
    message: &str,
    epoch: Option<u64>,
    activity: &Option<String>,
    tx: &mpsc::Sender<ChatEvent>,
) -> Result<(), String> {
    app.check_data(access, epoch)?;
    app.auth.check_access(access).map_err(|e| e.to_string())?;
    access
        .require_scope("metrics:explain")
        .map_err(|e| e.to_string())?;
    let query = app
        .model
        .plan_portfolio(message, &allowed_portfolio(app, access))
        .await?;
    app.check_data(access, epoch)?;
    portfolio_scope(app, access, &query)?;
    policy_event_for((app,access,tx,portfolio::TOOL),"tool_check","allowed","tool_scope_allowed","Portfolio measures and query bounds checked. MCP will independently authorize the customer aggregate read.",false).await?;
    let evidence_id = Uuid::new_v4().to_string();
    emit(tx,"tool",json!({"name":portfolio::TOOL,"phase":"request","message":format!("Authorized portfolio aggregates · {} second window",query.window_secs),"evidence_id":evidence_id})).await?;
    app.check_data(access, epoch)?;
    portfolio_scope(app, access, &query)?;
    app.activity_portfolio(activity, &query);
    let response=app.http.post(format!("{}/mcp",app.config.public_origin)).bearer_auth(token).header("X-Opaque-Persona-Generation",epoch.unwrap_or(0)).header(header::ACCEPT,"application/json, text/event-stream").header("MCP-Protocol-Version","2025-11-25").json(&json!({"jsonrpc":"2.0","id":evidence_id,"method":"tools/call","params":{"name":portfolio::TOOL,"arguments":query}})).send().await.map_err(|_|"MCP portfolio request did not complete; no retry was made.")?;
    let body = bounded_json(response)
        .await
        .map_err(|_| "MCP returned no usable portfolio response; no retry was made.")?;
    if body.pointer("/result/isError").and_then(Value::as_bool) != Some(false) {
        return Err("MCP returned no authorized, complete portfolio evidence.".into());
    }
    let evidence: PortfolioEvidence = serde_json::from_value(
        body.pointer("/result/structuredContent")
            .cloned()
            .ok_or("MCP evidence absent")?,
    )
    .map_err(|_| "MCP portfolio evidence invalid")?;
    evidence.snapshot.validate(
        access.tenant_id(),
        &query,
        &allowed_portfolio(app, access),
        now(),
        app.config.source.max_staleness_secs,
    )?;
    if evidence.source_id != app.config.source.source_id
        || evidence.coverage != "complete"
        || evidence.observed_at > now() + 5
        || evidence.observed_at < now() - i64::from(app.config.source.max_staleness_secs)
    {
        return Err("MCP source or coverage did not match the authorized query.".into());
    }
    app.check_data(access, epoch)?;
    portfolio_scope(app, access, &query)?;
    app.finish_activity(activity, "running", Some(true), None);
    policy_event_for((app,access,tx,portfolio::TOOL),"source_read","allowed","source_evidence_received","Complete portfolio aggregates received from the authorized customer source. Answers are computed from this evidence.",true).await?;
    app.check_data(access, epoch)?;
    portfolio_scope(app, access, &query)?;
    portfolio_audit(app, access, &evidence)?;
    emit(tx, "portfolio_result", evidence.presentation(&evidence_id)).await?;
    app.check_data(access, epoch)?;
    portfolio_scope(app, access, &query)?;
    emit(tx,"tool",json!({"name":portfolio::TOOL,"phase":"complete","message":"Validated portfolio aggregates received","evidence_id":evidence_id})).await?;
    app.check_data(access, epoch)?;
    emit(tx, "answer", json!({"text":evidence.answer()})).await?;
    Ok(())
}
