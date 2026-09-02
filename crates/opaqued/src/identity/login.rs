//! Browser-login attempt lifecycle.
//!
//! `identity.login_start` creates an attempt: state + nonce + PKCE verifier,
//! a daemon-owned loopback listener for the IdP redirect, and an
//! authorization URL for the CLI to display. The authorization code lands on
//! the listener, is exchanged (PKCE) and verified (JWKS + nonce) entirely
//! inside the daemon, then a human principal is upserted and a login session
//! created. The CLI polls `identity.login_status` — it never touches a code
//! or token, so an agent driving the CLI can start a login but never complete
//! one without the human at the browser.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use opaque_core::identity::Role;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use super::IdentityRuntime;
use super::oidc::{pkce_challenge, random_urlsafe, urldecode};

/// How long a login attempt stays valid.
const ATTEMPT_TTL: Duration = Duration::from_secs(300);
/// Cap on junk requests (favicon etc.) served before giving up.
const MAX_CALLBACK_REQUESTS: usize = 32;
/// Cap on the callback request head we are willing to read.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Outcome of a login attempt.
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    Pending,
    /// Login completed; the session id names the created human session
    /// (consumed by the delegation wiring in Stage C — audit correlation).
    Done {
        #[allow(dead_code)]
        session_id: String,
    },
    Failed {
        reason: String,
    },
}

struct Attempt {
    outcome: AttemptOutcome,
    created: Instant,
    /// Aborts the listener task when the attempt is superseded.
    listener_task: Option<tokio::task::JoinHandle<()>>,
}

/// Pending login attempts keyed by attempt id (uuid).
#[derive(Default)]
pub struct LoginAttempts {
    inner: std::sync::Mutex<HashMap<String, Attempt>>,
}

impl LoginAttempts {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Attempt>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn gc(&self) {
        let mut map = self.lock();
        map.retain(|_, a| {
            let keep = a.created.elapsed() < ATTEMPT_TTL * 2;
            if !keep && let Some(task) = a.listener_task.take() {
                task.abort();
            }
            keep
        });
    }

    fn set_outcome(&self, attempt_id: &str, outcome: AttemptOutcome) {
        if let Some(a) = self.lock().get_mut(attempt_id) {
            // Never regress a terminal outcome.
            if matches!(a.outcome, AttemptOutcome::Pending) {
                a.outcome = outcome;
            }
        }
    }
}

/// Result of starting a login attempt.
pub struct StartedLogin {
    pub attempt_id: String,
    pub auth_url: String,
    pub expires_in_secs: u64,
}

impl IdentityRuntime {
    /// Begin a browser login. Supersedes any prior pending attempt.
    pub async fn login_start(self: &Arc<Self>) -> Result<StartedLogin, String> {
        self.attempts.gc();

        let oidc = self.oidc_client().await?;

        // Bind the loopback listener first so the redirect URI is exact.
        let port = self.config.redirect_port.unwrap_or(0);
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| format!("failed to bind loopback listener: {e}"))?;
        let bound_port = listener
            .local_addr()
            .map_err(|e| format!("failed to read listener addr: {e}"))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{bound_port}/callback");

        let attempt_id = uuid::Uuid::new_v4().to_string();
        let state = random_urlsafe(32);
        let nonce = random_urlsafe(32);
        let verifier = random_urlsafe(48);
        let auth_url =
            oidc.build_auth_url(&state, &nonce, &pkce_challenge(&verifier), &redirect_uri);

        // Supersede: abort every previously pending attempt's listener.
        {
            let mut map = self.attempts.lock();
            for (_, a) in map.iter_mut() {
                if matches!(a.outcome, AttemptOutcome::Pending) {
                    a.outcome = AttemptOutcome::Failed {
                        reason: "superseded by a newer login attempt".into(),
                    };
                    if let Some(task) = a.listener_task.take() {
                        task.abort();
                    }
                }
            }
            map.insert(
                attempt_id.clone(),
                Attempt {
                    outcome: AttemptOutcome::Pending,
                    created: Instant::now(),
                    listener_task: None,
                },
            );
        }

        let runtime = self.clone();
        let task_attempt_id = attempt_id.clone();
        let task = tokio::spawn(async move {
            let result = tokio::time::timeout(
                ATTEMPT_TTL,
                run_callback_listener(
                    runtime.clone(),
                    oidc,
                    listener,
                    task_attempt_id.clone(),
                    state,
                    nonce,
                    verifier,
                    redirect_uri,
                ),
            )
            .await;
            if result.is_err() {
                runtime.attempts.set_outcome(
                    &task_attempt_id,
                    AttemptOutcome::Failed {
                        reason: "login timed out".into(),
                    },
                );
            }
        });
        if let Some(a) = self.attempts.lock().get_mut(&attempt_id) {
            a.listener_task = Some(task);
        }

        info!("login attempt started (redirect port {bound_port})");
        Ok(StartedLogin {
            attempt_id,
            auth_url,
            expires_in_secs: ATTEMPT_TTL.as_secs(),
        })
    }

    /// Poll a login attempt.
    pub fn login_status(&self, attempt_id: &str) -> Option<AttemptOutcome> {
        self.attempts.gc();
        self.attempts.lock().get(attempt_id).map(|a| {
            if matches!(a.outcome, AttemptOutcome::Pending) && a.created.elapsed() >= ATTEMPT_TTL {
                AttemptOutcome::Failed {
                    reason: "login timed out".into(),
                }
            } else {
                a.outcome.clone()
            }
        })
    }
}

/// Serve the loopback redirect: accept until the real callback arrives,
/// then complete the login and answer the browser.
#[allow(clippy::too_many_arguments)]
async fn run_callback_listener(
    runtime: Arc<IdentityRuntime>,
    oidc: Arc<super::oidc::OidcClient>,
    listener: TcpListener,
    attempt_id: String,
    expected_state: String,
    nonce: String,
    verifier: String,
    redirect_uri: String,
) {
    for _ in 0..MAX_CALLBACK_REQUESTS {
        let (mut stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("login callback accept error: {e}");
                runtime.attempts.set_outcome(
                    &attempt_id,
                    AttemptOutcome::Failed {
                        reason: "callback listener failed".into(),
                    },
                );
                return;
            }
        };
        // Loopback only — refuse anything else outright (defense in depth;
        // the bind address already guarantees this).
        if !peer.ip().is_loopback() {
            continue;
        }

        let Some(target) = read_request_target(&mut stream).await else {
            let _ = respond_html(&mut stream, 400, ERROR_PAGE).await;
            continue;
        };

        let Some(query) = target.strip_prefix("/callback?") else {
            // Browsers probe /favicon.ico etc. — 404 and keep listening.
            let _ = respond_html(&mut stream, 404, NOT_FOUND_PAGE).await;
            continue;
        };

        let params = parse_query(query);
        let state_ok = params
            .get("state")
            .is_some_and(|s| constant_time_str_eq(s, &expected_state));
        if !state_ok {
            warn!("login callback with wrong or missing state — ignoring");
            let _ = respond_html(&mut stream, 400, ERROR_PAGE).await;
            continue;
        }

        // From here the outcome is terminal: success or failure.
        if let Some(err) = params.get("error") {
            // IdP-reported error (e.g. access_denied). Error codes are
            // registry tokens — safe to surface after charset filtering.
            let code: String = err
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(64)
                .collect();
            runtime.attempts.set_outcome(
                &attempt_id,
                AttemptOutcome::Failed {
                    reason: format!("identity provider reported: {code}"),
                },
            );
            let _ = respond_html(&mut stream, 200, ERROR_PAGE).await;
            return;
        }

        let Some(code) = params.get("code") else {
            runtime.attempts.set_outcome(
                &attempt_id,
                AttemptOutcome::Failed {
                    reason: "callback missing authorization code".into(),
                },
            );
            let _ = respond_html(&mut stream, 400, ERROR_PAGE).await;
            return;
        };

        let outcome = complete_login(&runtime, &oidc, code, &verifier, &nonce, &redirect_uri).await;
        let (status, page) = match &outcome {
            AttemptOutcome::Done { .. } => (200, SUCCESS_PAGE),
            _ => (200, ERROR_PAGE),
        };
        runtime.attempts.set_outcome(&attempt_id, outcome);
        let _ = respond_html(&mut stream, status, page).await;
        return;
    }

    runtime.attempts.set_outcome(
        &attempt_id,
        AttemptOutcome::Failed {
            reason: "too many stray requests on the callback listener".into(),
        },
    );
}

/// Exchange + verify + persist. Returns the terminal outcome.
async fn complete_login(
    runtime: &Arc<IdentityRuntime>,
    oidc: &super::oidc::OidcClient,
    code: &str,
    verifier: &str,
    nonce: &str,
    redirect_uri: &str,
) -> AttemptOutcome {
    let id_token = match oidc.exchange_code(code, verifier, redirect_uri).await {
        Ok(t) => t,
        Err(e) => {
            warn!("login code exchange failed: {e}");
            return AttemptOutcome::Failed {
                reason: "code exchange with the identity provider failed".into(),
            };
        }
    };

    let verified = match oidc.verify_id_token(&id_token, nonce).await {
        Ok(v) => v,
        Err(e) => {
            warn!("id_token rejected: {e}");
            return AttemptOutcome::Failed {
                reason: "identity token failed verification".into(),
            };
        }
    };

    // Email domain allowlist (fail closed when configured and email absent).
    let domains = &runtime.config.allowed_email_domains;
    if !domains.is_empty() {
        let allowed = verified
            .email
            .as_deref()
            .and_then(|e| e.rsplit_once('@'))
            .is_some_and(|(_, domain)| domains.iter().any(|d| domain.eq_ignore_ascii_case(d)));
        if !allowed {
            info!("login rejected: email not in allowed_email_domains");
            return AttemptOutcome::Failed {
                reason: "email domain not permitted by daemon policy".into(),
            };
        }
    }

    // Bootstrap: the very first human gets the full role set; later humans
    // start as operator and are promoted by an admin.
    let first_human = matches!(runtime.store.count_humans(), Ok(0));
    let initial_roles: BTreeSet<Role> = if first_human {
        BTreeSet::from([Role::Admin, Role::Approver, Role::Operator])
    } else {
        BTreeSet::from([Role::Operator])
    };

    let principal = match runtime.store.upsert_human(
        &runtime.config.issuer,
        &verified.sub,
        verified.email.as_deref(),
        verified.name.as_deref(),
        &initial_roles,
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!("failed to persist principal: {e}");
            return AttemptOutcome::Failed {
                reason: "failed to persist principal".into(),
            };
        }
    };
    if principal.disabled {
        info!("login rejected: principal is disabled");
        return AttemptOutcome::Failed {
            reason: "this identity has been disabled".into(),
        };
    }

    let session = match runtime.store.create_human_session(
        &principal.id,
        runtime.config.session_ttl_secs(),
        &runtime.config.issuer,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to create login session: {e}");
            return AttemptOutcome::Failed {
                reason: "failed to create login session".into(),
            };
        }
    };

    info!(
        "human logged in: {} ({}), session {}",
        principal.display_label(),
        principal.id,
        session.id
    );
    AttemptOutcome::Done {
        session_id: session.id,
    }
}

// ---------------------------------------------------------------------------
// Minimal HTTP handling (no deps)
// ---------------------------------------------------------------------------

/// Read one HTTP/1.x request head and return the request target of a GET.
async fn read_request_target(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let deadline = Duration::from_secs(10);
    loop {
        let n = tokio::time::timeout(deadline, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return None;
        }
    }
    let head = std::str::from_utf8(&buf).ok()?;
    let request_line = head.lines().next()?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method != "GET" || !version.starts_with("HTTP/1.") {
        return None;
    }
    Some(target.to_owned())
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if let (Some(k), Some(v)) = (urldecode(k), urldecode(v)) {
            out.entry(k).or_insert(v);
        }
    }
    out
}

async fn respond_html(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.shutdown().await
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

const SUCCESS_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>opaque — signed in</title></head>\
<body style=\"font-family:-apple-system,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#101418;color:#e6edf3\">\
<div style=\"text-align:center\"><div style=\"font-size:42px\">&#128274;</div>\
<h1 style=\"font-weight:600\">Signed in to opaque</h1>\
<p style=\"color:#8b949e\">You can close this tab and return to the terminal.</p></div></body></html>";

const ERROR_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>opaque — sign-in failed</title></head>\
<body style=\"font-family:-apple-system,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#101418;color:#e6edf3\">\
<div style=\"text-align:center\"><div style=\"font-size:42px\">&#9888;&#65039;</div>\
<h1 style=\"font-weight:600\">Sign-in did not complete</h1>\
<p style=\"color:#8b949e\">Return to the terminal and run <code>opaque login</code> again.</p></div></body></html>";

const NOT_FOUND_PAGE: &str = "<!doctype html><html><body>not found</body></html>";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::oidc::tests::{base_claims, mount_discovery, sign_id_token};
    use crate::identity::{IdentityConfig, ServicePrincipalConfig};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_query_decodes_and_keeps_first() {
        let q = parse_query("code=abc%2Fdef&state=x+y&code=second");
        assert_eq!(q.get("code").unwrap(), "abc/def");
        assert_eq!(q.get("state").unwrap(), "x y");
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_str_eq("abc", "abc"));
        assert!(!constant_time_str_eq("abc", "abd"));
        assert!(!constant_time_str_eq("abc", "ab"));
    }

    // -- full login flow against a mock IdP ---------------------------------

    fn test_config(issuer: &str, domains: Vec<String>) -> IdentityConfig {
        IdentityConfig {
            issuer: issuer.to_owned(),
            client_id: "opaque-cli".into(),
            audience: None,
            redirect_port: None,
            session_ttl_secs: None,
            allowed_email_domains: domains,
            required: false,
            service_principals: vec![ServicePrincipalConfig {
                name: "ci".into(),
                roles: vec!["operator".into()],
            }],
        }
    }

    fn runtime_with(
        server_uri: &str,
        domains: Vec<String>,
    ) -> (tempfile::TempDir, Arc<IdentityRuntime>) {
        let dir = tempfile::tempdir().unwrap();
        let rt = IdentityRuntime::initialize(test_config(server_uri, domains), dir.path())
            .expect("identity runtime should initialize");
        (dir, Arc::new(rt))
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        let query = url.split_once('?')?.1;
        parse_query(query).remove(key)
    }

    async fn drive_callback(auth_url: &str, code: &str, state: &str) -> u16 {
        let redirect_uri = query_param(auth_url, "redirect_uri").expect("redirect_uri in url");
        let url = format!(
            "{redirect_uri}?code={}&state={}",
            super::super::oidc::urlencode(code),
            super::super::oidc::urlencode(state)
        );
        reqwest::get(&url)
            .await
            .expect("callback GET")
            .status()
            .as_u16()
    }

    async fn wait_terminal(rt: &Arc<IdentityRuntime>, attempt_id: &str) -> AttemptOutcome {
        for _ in 0..100 {
            match rt.login_status(attempt_id) {
                Some(AttemptOutcome::Pending) => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Some(outcome) => return outcome,
                None => panic!("attempt vanished"),
            }
        }
        panic!("login attempt never became terminal");
    }

    #[tokio::test]
    async fn full_login_flow_bootstraps_first_admin() {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let (_dir, rt) = runtime_with(&server.uri(), vec![]);

        let started = rt.login_start().await.expect("login_start");
        assert!(started.auth_url.contains("code_challenge_method=S256"));
        let state = query_param(&started.auth_url, "state").unwrap();
        let nonce = query_param(&started.auth_url, "nonce").unwrap();

        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("code=good-code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": sign_id_token(base_claims(&server.uri(), &nonce), "test-key-1"),
            })))
            .mount(&server)
            .await;

        let status = drive_callback(&started.auth_url, "good-code", &state).await;
        assert_eq!(status, 200);

        let outcome = wait_terminal(&rt, &started.attempt_id).await;
        assert!(
            matches!(outcome, AttemptOutcome::Done { .. }),
            "{outcome:?}"
        );

        // First human bootstraps as admin+approver+operator.
        let identity = rt.current_identity_json().expect("logged in");
        assert_eq!(identity["email"], "dev@example.com");
        let roles: Vec<String> = serde_json::from_value(identity["roles"].clone()).unwrap();
        assert!(roles.contains(&"admin".to_string()));
        assert!(roles.contains(&"approver".to_string()));
        assert!(rt.current_human_has_role(Role::Admin));

        // Service principal from config was registered at initialize.
        assert_eq!(rt.store.list_principals().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn wrong_state_is_ignored_then_correct_state_completes() {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let (_dir, rt) = runtime_with(&server.uri(), vec![]);

        let started = rt.login_start().await.unwrap();
        let state = query_param(&started.auth_url, "state").unwrap();
        let nonce = query_param(&started.auth_url, "nonce").unwrap();

        // Forged state: rejected with 400, attempt stays pending.
        let status = drive_callback(&started.auth_url, "any", "forged-state").await;
        assert_eq!(status, 400);
        assert!(matches!(
            rt.login_status(&started.attempt_id),
            Some(AttemptOutcome::Pending)
        ));

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": sign_id_token(base_claims(&server.uri(), &nonce), "test-key-1"),
            })))
            .mount(&server)
            .await;
        drive_callback(&started.auth_url, "good", &state).await;
        let outcome = wait_terminal(&rt, &started.attempt_id).await;
        assert!(matches!(outcome, AttemptOutcome::Done { .. }));
    }

    #[tokio::test]
    async fn email_domain_allowlist_fails_closed() {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let (_dir, rt) = runtime_with(&server.uri(), vec!["corp.example".into()]);

        let started = rt.login_start().await.unwrap();
        let state = query_param(&started.auth_url, "state").unwrap();
        let nonce = query_param(&started.auth_url, "nonce").unwrap();

        // base_claims email is dev@example.com — not under corp.example.
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": sign_id_token(base_claims(&server.uri(), &nonce), "test-key-1"),
            })))
            .mount(&server)
            .await;
        drive_callback(&started.auth_url, "c", &state).await;
        let outcome = wait_terminal(&rt, &started.attempt_id).await;
        match outcome {
            AttemptOutcome::Failed { reason } => {
                assert!(reason.contains("domain"), "{reason}");
            }
            other => panic!("expected failure, got {other:?}"),
        }
        assert!(rt.current_identity_json().is_none());
        assert_eq!(rt.store.count_humans().unwrap(), 0);
    }

    #[tokio::test]
    async fn second_human_does_not_get_admin() {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let (_dir, rt) = runtime_with(&server.uri(), vec![]);

        // First login (sub user-123).
        let started = rt.login_start().await.unwrap();
        let state = query_param(&started.auth_url, "state").unwrap();
        let nonce = query_param(&started.auth_url, "nonce").unwrap();
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("code=first"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": sign_id_token(base_claims(&server.uri(), &nonce), "test-key-1"),
            })))
            .mount(&server)
            .await;
        drive_callback(&started.auth_url, "first", &state).await;
        wait_terminal(&rt, &started.attempt_id).await;

        // Second login, different subject.
        let started2 = rt.login_start().await.unwrap();
        let state2 = query_param(&started2.auth_url, "state").unwrap();
        let nonce2 = query_param(&started2.auth_url, "nonce").unwrap();
        let mut claims2 = base_claims(&server.uri(), &nonce2);
        claims2["sub"] = serde_json::json!("user-456");
        claims2["email"] = serde_json::json!("second@example.com");
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("code=second"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": sign_id_token(claims2, "test-key-1"),
            })))
            .mount(&server)
            .await;
        drive_callback(&started2.auth_url, "second", &state2).await;
        let outcome = wait_terminal(&rt, &started2.attempt_id).await;
        assert!(matches!(outcome, AttemptOutcome::Done { .. }));

        let identity = rt.current_identity_json().unwrap();
        assert_eq!(identity["email"], "second@example.com");
        let roles: Vec<String> = serde_json::from_value(identity["roles"].clone()).unwrap();
        assert_eq!(roles, vec!["operator".to_string()]);
        assert_eq!(rt.store.count_humans().unwrap(), 2);
    }

    #[tokio::test]
    async fn new_login_supersedes_pending_attempt() {
        let server = MockServer::start().await;
        mount_discovery(&server, &server.uri()).await;
        let (_dir, rt) = runtime_with(&server.uri(), vec![]);

        let first = rt.login_start().await.unwrap();
        let second = rt.login_start().await.unwrap();
        match rt.login_status(&first.attempt_id) {
            Some(AttemptOutcome::Failed { reason }) => {
                assert!(reason.contains("superseded"), "{reason}");
            }
            other => panic!("expected superseded, got {other:?}"),
        }
        assert!(matches!(
            rt.login_status(&second.attempt_id),
            Some(AttemptOutcome::Pending)
        ));
    }
}
