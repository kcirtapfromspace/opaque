//! Disposable real-daemon + real HTTP gateway integration. The test alone may
//! mutate its private fixture identity DB; the gateway receives neither that
//! database path nor the broad daemon token.
use opaque_core::{
    resource_auth::{AuthError, BrokerClient, BrokerClientConfig},
    tenant::{TenantBinding, TenantId},
};
use opaque_showcase::server::{App, GatewayConfig, router};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
const PRIVATE_KEY: &str = include_str!("fixtures/test_rsa_key.pem");
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+m4fkcL6cuTGRLTSSrF\n7zfrwFFnYRJG1yVmmCwn4q0PXhuWmUu9mo2wg9ftf9BLFspkMqyzxpdfzGTan6J9\n5w7Ad7gbP5R2aDGnVJRTX9dph3cKBgwnDsUa751mYWfr1rsTnoiMIDWzOGsRSdOi\nRzZGCYo3yo4YNB+sNIOFMQ/tc3X558HGCZl3boecDmlwt1lHebe6/+kXRTYLLpIl\nf7u1mw98TYtOenu2SIUOrJKY9VGluMxvGH9e4SExpZaG61wTNsosD20tEBkWUjCo\nxo01adXNjPYKx/mJB3NgCIWacU4NwbZxVRUg5HYR85cq+5I2oNQDwuyNDv7kZQfA\nywIDAQAB\n-----END PUBLIC KEY-----\n";
const SCOPES: &str =
    "metrics:read metrics:explain metrics:stream metrics:metric:requests_per_second";
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
struct Daemon {
    child: Child,
    root: PathBuf,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Daemon {
    async fn start(root: &Path) -> Self {
        let _ = std::fs::remove_file(root.join("resource.sock")); // Our killed fixture's path only.
        let mut child = Command::new(env!("CARGO_BIN_EXE_opaqued"))
            .env("HOME", root)
            .env("XDG_RUNTIME_DIR", root.join("run"))
            .env("OPAQUE_CONFIG", root.join("config.toml"))
            .env("OPAQUE_RESOURCE_AUTHORITY_FIXTURE", "1")
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        for _ in 0..200 {
            if root.join("resource.sock").exists() {
                return Self {
                    child,
                    root: root.into(),
                };
            }
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "fixture daemon exited: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        panic!(
            "fixture daemon unavailable: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn db(&self) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(self.root.join("state/identity.db")).unwrap();
        c.busy_timeout(Duration::from_secs(2)).unwrap();
        c
    }
    fn update(&self, sql: &str) {
        self.db().execute(sql, []).unwrap();
    }
}
fn sign(claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}
async fn mcp(http: &reqwest::Client, origin: &str, token: &str) -> (reqwest::StatusCode, Value) {
    let response=http.post(format!("{origin}/mcp")).bearer_auth(token).header("Origin",origin)
        .header("Accept","application/json, text/event-stream").json(&json!({"jsonrpc":"2.0","id":"test","method":"tools/call","params":{"name":"opaque_metrics_query","arguments":{"window_secs":60,"metrics":["requests_per_second"]}}})).send().await.unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}
async fn login(http: &reqwest::Client, origin: &str) -> String {
    let response = http
        .get(format!("{origin}/auth/login"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    let url = reqwest::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let binding = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = http
        .get(format!(
            "{origin}/auth/callback?code=fixture-code&state={state}"
        ))
        .header("Cookie", binding)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|v| !v.contains("_login="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_identity_is_live_for_gateway_queries_disclosures_and_logout() {
    let tmp = Path::new("/tmp").canonicalize().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("oq-resource-")
        .tempdir_in(tmp)
        .unwrap();
    let root = directory.path();
    for child in ["run", "state", "gateway"] {
        std::fs::create_dir(root.join(child)).unwrap();
        std::fs::set_permissions(root.join(child), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(root.join("resource.key"), [7u8; 32]).unwrap();
    std::fs::set_permissions(
        root.join("resource.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let issuer = MockServer::start().await;
    let source = MockServer::start().await;
    let model = MockServer::start().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap();
    let origin = format!("http://{bind}");
    let binding =
        TenantBinding::new(TenantId::parse("customer-a").unwrap(), uuid::Uuid::new_v4()).unwrap();
    let uid = unsafe { libc::geteuid() };
    let scopes = SCOPES.split(' ').collect::<Vec<_>>();
    let config = format!(
        r#"data_dir = {state}
[identity]
issuer = {issuer}
client_id = "opaque-login"
required = true
allowed_subjects = ["fixture-user"]
allowed_email_domains = ["example.com"]
[resource_authority]
socket_path = {socket}
credential_file = {key}
allowed_gateway_uids = [{uid}]
fixture_mode = true
[resource_authority.binding]
schema_version = 1
tenant_id = "customer-a"
broker_id = "{broker_id}"
[resource_authority.role_scopes]
operator = {scopes}
[resource_authority.auth]
issuer = {issuer}
resource_audience = {audience}
public_key_pem = '''{public_key}'''
allow_loopback_http = true
[[resource_authority.auth.admissions]]
tenant_id = "customer-a"
subject = "fixture-user"
client_id = "gateway-client"
scopes = {scopes}
"#,
        state = json!(root.join("state")),
        issuer = json!(issuer.uri()),
        socket = json!(root.join("resource.sock")),
        key = json!(root.join("resource.key")),
        broker_id = binding.broker_id,
        scopes = json!(scopes),
        audience = json!(format!("{origin}/mcp")),
        public_key = PUBLIC_KEY
    );
    std::fs::write(root.join("config.toml"), config).unwrap();
    let mut daemon = Daemon::start(root).await;
    let broker_config = BrokerClientConfig {
        socket_path: root.join("resource.sock"),
        credential_file: root.join("resource.key"),
        broker_uid: uid,
        binding: binding.clone(),
    };
    let broker =
        BrokerClient::new(broker_config.clone(), issuer.uri(), format!("{origin}/mcp")).unwrap();
    let claims = json!({"iss":issuer.uri(),"aud":format!("{origin}/mcp"),"sub":"fixture-user","client_id":"gateway-client","tenant_id":"customer-a","scope":SCOPES,"jti":"active-fixture","iat":now(),"exp":now()+600});
    let token = sign(&claims);
    let bearer = format!("Bearer {token}");
    assert_eq!(
        broker.verify_bearer(Some(&bearer)).unwrap_err(),
        AuthError::NotAdmitted,
        "token must never bootstrap a broker principal"
    );
    daemon.db().execute("INSERT INTO principals(id,kind,iss,sub,email,roles,created_at,last_seen) VALUES('hum_00000000000000000000000000000001','human',?1,'fixture-user','fixture@example.com','operator',?2,?2)",rusqlite::params![issuer.uri(),now()]).unwrap();
    let access = broker.verify_bearer(Some(&bearer)).unwrap();
    let mut wrong_uid = broker_config.clone();
    wrong_uid.broker_uid = uid.wrapping_add(1);
    assert_eq!(
        BrokerClient::new(wrong_uid, issuer.uri(), format!("{origin}/mcp"))
            .unwrap()
            .verify_bearer(Some(&bearer))
            .unwrap_err(),
        AuthError::Unavailable
    );
    let wrong_key_path = root.join("wrong-resource.key");
    std::fs::write(&wrong_key_path, [8u8; 32]).unwrap();
    std::fs::set_permissions(&wrong_key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut wrong_key = broker_config.clone();
    wrong_key.credential_file = wrong_key_path;
    assert_eq!(
        BrokerClient::new(wrong_key, issuer.uri(), format!("{origin}/mcp"))
            .unwrap()
            .verify_bearer(Some(&bearer))
            .unwrap_err(),
        AuthError::NotAdmitted
    );
    let mut short = claims.clone();
    short["jti"] = json!("short-lived-fixture");
    short["exp"] = json!(now() + 2);
    let short_access = broker
        .verify_bearer(Some(&format!("Bearer {}", sign(&short))))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2050)).await;
    assert_eq!(
        broker.check_access(&short_access),
        Err(AuthError::InvalidToken)
    );
    let gateway_config:GatewayConfig=serde_json::from_value(json!({"bind":bind,"public_origin":origin,"tenant_id":"customer-a","customer_name":"Resource fixture","state_dir":root.join("gateway"),"fixture_mode":true,
        "broker_authority":broker_config,"auth":{"issuer":issuer.uri(),"resource_audience":format!("{origin}/mcp"),"allow_loopback_http":true},
        "oauth":{"authorization_endpoint":format!("{}/authorize",issuer.uri()),"token_endpoint":format!("{}/token",issuer.uri()),"client_id":"gateway-client","scopes":scopes},
        "source":{"tenant_id":"customer-a","source_id":"application-fixture","base_url":source.uri(),"credential_env":"CARGO_PKG_NAME","allowed_metrics":["requests_per_second"],"max_window_secs":300,"max_staleness_secs":60,"allow_loopback_http":true},
        "model":{"kind":"openai_compatible","base_url":model.uri(),"model":"fixture-model","allow_loopback_http":true}
    })).unwrap();
    let app = App::new(gateway_config).unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, router(app)).await.unwrap() });
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Mock::given(method("POST")).and(path("/v1/metrics/query")).respond_with(|request:&wiremock::Request| {
        assert_ne!(request.headers.get("authorization").unwrap(),"Bearer active-fixture");
        ResponseTemplate::new(200).set_body_json(json!({"tenant_id":"customer-a","window_secs":60,"as_of":now(),"watermark":now(),"metrics":[{"name":"requests_per_second","value":17.25,"count":120}]}))
    }).mount(&source).await;
    assert_eq!(
        mcp(&http, &origin, &token).await.1["result"]["isError"],
        false
    );
    let before = source.received_requests().await.unwrap().len();
    for sql in [
        "UPDATE principals SET disabled=1",
        "UPDATE principals SET roles='auditor'",
        "UPDATE principals SET email='fixture@removed.example'",
        "UPDATE principals SET sub='removed-subject'",
    ] {
        daemon.update(sql);
        assert!(broker.check_access(&access).is_err());
        let (status, body) = mcp(&http, &origin, &token).await;
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{body}");
        assert_eq!(source.received_requests().await.unwrap().len(), before);
        assert!(model.received_requests().await.unwrap().is_empty());
        daemon.update("UPDATE principals SET disabled=0,roles='operator',email='fixture@example.com',sub='fixture-user'");
    }
    for (field, value) in [
        ("tenant_id", json!("customer-b")),
        ("client_id", json!("foreign-client")),
        ("iss", json!("https://other.example")),
        ("exp", json!(now() - 1)),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        if field == "exp" {
            invalid["iat"] = json!(now() - 30)
        }
        assert!(!mcp(&http, &origin, &sign(&invalid)).await.0.is_success());
        assert_eq!(source.received_requests().await.unwrap().len(), before);
    }
    let mut foreign = broker_config.clone();
    foreign.binding.broker_id = uuid::Uuid::new_v4();
    assert_eq!(
        BrokerClient::new(foreign, issuer.uri(), format!("{origin}/mcp"))
            .unwrap()
            .verify_bearer(Some(&bearer))
            .unwrap_err(),
        AuthError::NotAdmitted
    );
    // A role removal while the source runs withholds its returned evidence.
    source.reset().await;
    let database = root.join("state/identity.db");
    Mock::given(method("POST")).and(path("/v1/metrics/query")).respond_with(move |_:&wiremock::Request| {
        rusqlite::Connection::open(&database).unwrap().execute("UPDATE principals SET roles=''",[]).unwrap();
        ResponseTemplate::new(200).set_body_json(json!({"tenant_id":"customer-a","window_secs":60,"as_of":now(),"watermark":now(),"metrics":[{"name":"requests_per_second","value":918273.5,"count":120}]}))
    }).mount(&source).await;
    let (status, body) = mcp(&http, &origin, &token).await;
    assert!(!status.is_success());
    assert!(!body.to_string().contains("918273"));
    assert!(model.received_requests().await.unwrap().is_empty());
    daemon.update("UPDATE principals SET roles='operator'");
    Mock::given(method("GET")).and(path("/.well-known/oauth-authorization-server")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"issuer":issuer.uri(),"authorization_endpoint":format!("{}/authorize",issuer.uri()),"token_endpoint":format!("{}/token",issuer.uri()),"code_challenge_methods_supported":["S256"]}))).mount(&issuer).await;
    let login_token = std::sync::Arc::new(std::sync::Mutex::new(token.clone()));
    let login_response_token = login_token.clone();
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(
                json!({"access_token":*login_response_token.lock().unwrap(),"token_type":"Bearer"}),
            )
        })
        .mount(&issuer)
        .await;
    let cookie = login(&http, &origin).await;
    let mut outage_claims = claims.clone();
    outage_claims["jti"] = json!("outage-logout-fixture");
    *login_token.lock().unwrap() = sign(&outage_claims);
    let outage_cookie = login(&http, &origin).await;
    let mut expired_claims = claims.clone();
    expired_claims["jti"] = json!("expired-cookie-fixture");
    expired_claims["iat"] = json!(now());
    expired_claims["exp"] = json!(now() + 2);
    *login_token.lock().unwrap() = sign(&expired_claims);
    let expired_cookie = login(&http, &origin).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;

    // Losing access must not prevent self-revocation: restoring the account
    // after logout must never revive its original bearer.
    let count = source.received_requests().await.unwrap().len();
    daemon.update("UPDATE principals SET roles='', disabled=1");
    assert_eq!(
        mcp(&http, &origin, &token).await.0,
        reqwest::StatusCode::FORBIDDEN
    );
    let logout = http
        .post(format!("{origin}/auth/logout"))
        .header("Origin", &origin)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert!(logout.status().is_success());
    assert!(
        logout.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        logout.json::<Value>().await.unwrap(),
        json!({"signed_out":true,"revoked":true})
    );
    daemon.update("UPDATE principals SET roles='operator', disabled=0");
    assert_eq!(broker.check_access(&access), Err(AuthError::Revoked));
    assert_eq!(
        mcp(&http, &origin, &token).await.0,
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(source.received_requests().await.unwrap().len(), count);
    assert_eq!(
        daemon
            .db()
            .query_row(
                "SELECT COUNT(*) FROM resource_revocations WHERE jti='active-fixture'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    daemon.child.kill().unwrap();
    daemon.child.wait().unwrap();
    let unavailable_logout = http
        .post(format!("{origin}/auth/logout"))
        .header("Origin", &origin)
        .header("Cookie", &outage_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        unavailable_logout.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!unavailable_logout.headers().contains_key("set-cookie"));
    assert_ne!(
        unavailable_logout
            .json::<Value>()
            .await
            .unwrap()
            .get("revoked"),
        Some(&Value::Bool(true))
    );
    for absent_or_expired in ["", "opaque_session=unknown", &expired_cookie] {
        let local_logout = http
            .post(format!("{origin}/auth/logout"))
            .header("Origin", &origin)
            .header("Cookie", absent_or_expired)
            .send()
            .await
            .unwrap();
        assert!(local_logout.status().is_success());
        assert!(
            local_logout.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        assert_eq!(
            local_logout.json::<Value>().await.unwrap(),
            json!({"signed_out":true,"revoked":false})
        );
    }
    assert_eq!(
        mcp(&http, &origin, &token).await.0,
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(source.received_requests().await.unwrap().len(), count);
    daemon = Daemon::start(root).await;
    let retried_logout = http
        .post(format!("{origin}/auth/logout"))
        .header("Origin", &origin)
        .header("Cookie", &outage_cookie)
        .send()
        .await
        .unwrap();
    assert!(retried_logout.status().is_success());
    assert_eq!(
        retried_logout.json::<Value>().await.unwrap().get("revoked"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        broker
            .verify_bearer(Some(&format!("Bearer {}", sign(&outage_claims))))
            .unwrap_err(),
        AuthError::Revoked
    );
    assert_eq!(
        broker.check_access(&access),
        Err(AuthError::Revoked),
        "broker restart must preserve logout"
    );
    assert_eq!(
        mcp(&http, &origin, &token).await.0,
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(model.received_requests().await.unwrap().is_empty());
    drop(daemon);
    task.abort();
    let _ = task.await;
}
