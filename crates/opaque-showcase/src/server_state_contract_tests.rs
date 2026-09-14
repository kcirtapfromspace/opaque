//! Real App state transitions with a deliberately held organization mutex.
//! Software RSA tokens and local audit acknowledgments are synthetic fixtures.
use super::*;
use crate::organization::ACTIVITY_SCOPE;

const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+m4fkcL6cuTGRLTSSrF\n7zfrwFFnYRJG1yVmmCwn4q0PXhuWmUu9mo2wg9ftf9BLFspkMqyzxpdfzGTan6J9\n5w7Ad7gbP5R2aDGnVJRTX9dph3cKBgwnDsUa751mYWfr1rsTnoiMIDWzOGsRSdOi\nRzZGCYo3yo4YNB+sNIOFMQ/tc3X558HGCZl3boecDmlwt1lHebe6/+kXRTYLLpIl\nf7u1mw98TYtOenu2SIUOrJKY9VGluMxvGH9e4SExpZaG61wTNsosD20tEBkWUjCo\nxo01adXNjPYKx/mJB3NgCIWacU4NwbZxVRUg5HYR85cq+5I2oNQDwuyNDv7kZQfA\nywIDAQAB\n-----END PUBLIC KEY-----\n";
const PRIVATE_KEY: &str = include_str!("../../opaqued/tests/fixtures/test_rsa_key.pem");

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    app: Arc<App>,
    server: wiremock::MockServer,
    _directory: Directory,
}
impl Fixture {
    async fn new() -> Self {
        let server = wiremock::MockServer::start().await;
        let port = reqwest::Url::parse(&server.uri()).unwrap().port().unwrap();
        let origin = format!("http://localhost:{port}");
        let directory =
            Directory(std::env::temp_dir().join(format!("opaque-state-{}", Uuid::new_v4())));
        let members = vec![
            json!({"subject":"analyst","persona_id":"customer_analyst","oauth_client_id":"analyst-client"}),
            json!({"subject":"engineer","persona_id":"engineer","oauth_client_id":"engineer-client"}),
            json!({"subject":"support","persona_id":"support","oauth_client_id":"support-client"}),
        ];
        let admissions=members.iter().map(|member| json!({
            "tenant_id":"customer-a","subject":member["subject"],"client_id":member["oauth_client_id"],
            "scopes":if member["subject"]=="engineer" {vec![ACTIVITY_SCOPE]} else {vec![ACTIVITY_SCOPE,"metrics:read"]},
        })).collect::<Vec<_>>();
        let cfg:GatewayConfig=serde_json::from_value(json!({
            "bind":format!("127.0.0.1:{port}"),"public_origin":origin,"tenant_id":"customer-a","customer_name":"Synthetic customer",
            "state_dir":directory.0,"fixture_mode":true,"experience":"credit_portfolio",
            "auth":{"issuer":server.uri(),"resource_audience":format!("{origin}/mcp"),"public_key_pem":PUBLIC_KEY,
                "admissions":admissions,"revoked_jtis":[],"max_token_ttl_secs":900,"clock_skew_secs":0,"allow_loopback_http":true},
            "oauth":{"authorization_endpoint":format!("{}/authorize",server.uri()),"token_endpoint":format!("{}/token",server.uri()),
                "client_id":"analyst-client","scopes":[ACTIVITY_SCOPE,"metrics:read"]},
            "source":{"tenant_id":"customer-a","source_id":"fixture-source","base_url":server.uri(),"credential_env":"CARGO_PKG_NAME",
                "allowed_metrics":CREDIT_METRICS,"max_window_secs":300,"max_staleness_secs":60,"allow_loopback_http":true},
            "model":{"kind":"fixture"},
            "organization_demo":{"id":"fixture-org","display_name":"Synthetic organization","members":members}
        })).unwrap();
        Self {
            app: App::new(cfg).unwrap(),
            server,
            _directory: directory,
        }
    }
    fn access(&self, persona: Persona) -> VerifiedAccess {
        let member = self
            .app
            .config
            .organization_demo
            .as_ref()
            .unwrap()
            .persona(persona);
        let admission = self
            .app
            .config
            .auth
            .admissions
            .iter()
            .find(|a| a.subject == member.subject)
            .unwrap();
        let claims = json!({"iss":self.app.config.auth.issuer,"aud":self.app.config.auth.resource_audience,
            "sub":member.subject,"client_id":member.oauth_client_id,"tenant_id":"customer-a",
            "scope":admission.scopes.iter().cloned().collect::<Vec<_>>().join(" "),"jti":Uuid::new_v4().to_string(),"iat":now(),"exp":now()+600});
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        self.app
            .auth
            .verify_bearer(Some(&format!("Bearer {token}")))
            .unwrap()
    }
    fn activity(&self, access: &VerifiedAccess) -> Value {
        self.app
            .organization
            .lock()
            .unwrap()
            .activity(
                self.app.config.organization_demo.as_ref().unwrap(),
                access,
                &self.app.config.customer_name,
                now(),
            )
            .unwrap()
    }
}

#[tokio::test]
async fn held_organization_transaction_blocks_activity_changes_until_custody_is_released() {
    let f = Fixture::new().await;
    let access = f.access(Persona::CustomerAnalyst);
    let activity = f
        .app
        .begin_activity(&access, "chat", Some("Synthetic aggregate question"));
    assert!(activity.is_some());
    let before = f.activity(&access);
    let transaction = f.app.organization.lock().unwrap();
    let app = f.app.clone();
    let worker_access = access.clone();
    let worker_activity = activity.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let epoch = app.access_epoch(&worker_access);
        let blocked = app.begin_activity(&worker_access, "tool_call", None);
        app.activity_tool(
            &worker_activity,
            &MetricsQuery {
                window_secs: 60,
                metrics: vec!["manual_review_rate_percent".into()],
            },
        );
        let query:PortfolioQuery=serde_json::from_value(json!({"view":"breakdown","window_secs":900,"measures":["manual_review_rate_percent"],"dimension":"channel"})).unwrap();
        app.activity_portfolio(&worker_activity, &query);
        app.finish_activity(
            &worker_activity,
            "completed",
            Some(true),
            Some("must-not-commit"),
        );
        sender.send((epoch, blocked)).unwrap();
    });
    let result = receiver.recv_timeout(Duration::from_secs(2));
    // Release the real lock even on deadline failure, then join the owned worker.
    drop(transaction);
    worker.join().unwrap();
    let (epoch, blocked) =
        result.expect("activity calls must fail closed without waiting for custody");
    assert_eq!(epoch, Err(ORGANIZATION_UNAVAILABLE.into()));
    assert_eq!(blocked, None);
    assert_eq!(f.activity(&access), before);
    f.app.activity_tool(
        &activity,
        &MetricsQuery {
            window_secs: 60,
            metrics: vec!["manual_review_rate_percent".into()],
        },
    );
    f.app
        .finish_activity(&activity, "observed", Some(true), None);
    let after = f.activity(&access);
    let records = after["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["tool_calls"], 1);
    assert_eq!(records[0]["outcome"], "observed");
    assert_eq!(records[0]["source_accessed"], true);
    assert_eq!(records[0]["reason_code"], Value::Null);
    assert!(f.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn changed_active_persona_is_rejected_after_state_lock_succeeds() {
    let f = Fixture::new().await;
    let analyst = f.access(Persona::CustomerAnalyst);
    let engineer = f.access(Persona::Engineer);
    let old_epoch = f.app.access_epoch(&analyst).unwrap();
    assert!(old_epoch.is_some());
    f.app
        .organization
        .lock()
        .unwrap()
        .activate(
            f.app.config.organization_demo.as_ref().unwrap(),
            &engineer,
            Persona::Engineer,
            None,
            now(),
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(
        f.app.access_epoch(&analyst).unwrap_err(),
        "This demo identity is not the active persona."
    );
    assert!(f.app.check_data(&analyst, old_epoch).is_err());
    let new_epoch = f.app.access_epoch(&engineer).unwrap();
    assert_ne!(new_epoch, old_epoch);
    assert!(
        f.app
            .check_data(&engineer, new_epoch)
            .unwrap_err()
            .contains("metadata only")
    );
    assert!(
        f.activity(&engineer)["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(f.server.received_requests().await.unwrap().is_empty());
}
