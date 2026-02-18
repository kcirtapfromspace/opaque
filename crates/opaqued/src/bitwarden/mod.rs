//! Bitwarden Secrets Manager integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `bitwarden:<secret-id>` or `bitwarden:<project>/<key>` refs
//! - **CLI browsing** via `bitwarden.list_projects` and `bitwarden.list_secrets` operations
//!
//! Uses the Bitwarden Secrets Manager REST API with service account access tokens.
//!
//! Backend selection:
//! 1. If `OPAQUE_BITWARDEN_URL` is set → use that URL
//! 2. Otherwise → use default `https://api.bitwarden.com`
//! 3. If no token is configured → disabled

pub mod client;
pub mod resolve;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use crate::enclave::OperationHandler;
use crate::sandbox::resolve::{BaseResolver, SecretResolver};

use client::BitwardenClient;

/// Default keychain ref for the Bitwarden access token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/bitwarden-token";

/// Environment variable to override the default Bitwarden token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_BITWARDEN_TOKEN_REF";

/// The Bitwarden Secrets Manager operation handler.
///
/// Handles project/secret browsing operations. A single `BitwardenHandler`
/// instance is registered for each Bitwarden operation name; it dispatches
/// by `request.operation`.
pub struct BitwardenHandler {
    audit: Arc<dyn AuditSink>,
    client: BitwardenClient,
    token_ref: String,
}

impl fmt::Debug for BitwardenHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenHandler")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

impl BitwardenHandler {
    /// Create a handler for the Bitwarden Secrets Manager API.
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Self {
        let token_ref = std::env::var(TOKEN_REF_ENV)
            .unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Self {
            audit,
            client: BitwardenClient::new(base_url),
            token_ref,
        }
    }

    /// Resolve the Bitwarden access token.
    fn resolve_token(&self) -> Result<String, String> {
        let base = BaseResolver::new();
        let token_value = base
            .resolve(&self.token_ref)
            .map_err(|e| format!("failed to resolve Bitwarden access token: {e}"))?;
        token_value
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| "Bitwarden access token is not valid UTF-8".to_string())
    }
}

impl OperationHandler for BitwardenHandler {
    fn execute(
        &self,
        request: &OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + '_>> {
        let request_id = request.request_id;
        let params = request.params.clone();
        let operation = request.operation.clone();
        let audit = self.audit.clone();

        Box::pin(async move {
            match operation.as_str() {
                "bitwarden.list_projects" => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=list_projects"),
                    );

                    let token = self.resolve_token()?;
                    let projects = self
                        .client
                        .list_projects(&token)
                        .await
                        .map_err(|e| format!("failed to list projects: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("projects_count={}", projects.len())),
                    );

                    // Return sanitized response: names only (no IDs).
                    let sanitized: Vec<serde_json::Value> = projects
                        .into_iter()
                        .map(|p| {
                            serde_json::json!({
                                "name": p.name,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({ "projects": sanitized }))
                }
                "bitwarden.list_secrets" => {
                    let project_name = params
                        .get("project")
                        .and_then(|v| v.as_str());

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=list_secrets project={}",
                                project_name.unwrap_or("(all)")
                            )),
                    );

                    let token = self.resolve_token()?;

                    // If project name given, resolve it to an ID first.
                    let project_id = if let Some(name) = project_name {
                        Some(
                            self.client
                                .find_project_by_name(&token, name)
                                .await
                                .map_err(|e| format!("project lookup failed: {e}"))?,
                        )
                    } else {
                        None
                    };

                    let secrets = self
                        .client
                        .list_secrets(&token, project_id.as_deref())
                        .await
                        .map_err(|e| format!("failed to list secrets: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={} secrets_count={}",
                                project_name.unwrap_or("(all)"),
                                secrets.len()
                            )),
                    );

                    // Return sanitized response: keys only (no IDs or values).
                    let sanitized: Vec<serde_json::Value> = secrets
                        .into_iter()
                        .map(|s| {
                            serde_json::json!({
                                "key": s.key,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({
                        "project": project_name,
                        "secrets": sanitized,
                    }))
                }
                "bitwarden.read_secret" => {
                    let secret_id = params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'secret_id' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=read_secret secret_id={secret_id}")),
                    );

                    let token = self.resolve_token()?;
                    let secret = self
                        .client
                        .get_secret(&token, secret_id)
                        .await
                        .map_err(|e| format!("failed to get secret: {e}"))?;

                    let value = secret
                        .value
                        .ok_or_else(|| format!("secret '{secret_id}' has no value"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "secret_id={secret_id} value_len={}",
                                value.len()
                            )),
                    );

                    Ok(serde_json::json!({
                        "secret_id": secret_id,
                        "key": secret.key,
                        "value": value,
                    }))
                }
                other => Err(format!("unknown Bitwarden operation: {other}")),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::operation::{ClientIdentity, ClientType};

    fn make_request(operation: &str, params: serde_json::Value) -> OperationRequest {
        OperationRequest {
            request_id: uuid::Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: ClientType::Human,
            operation: operation.into(),
            target: std::collections::HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params,
            workspace: None,
        }
    }

    #[test]
    fn handler_debug() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = BitwardenHandler::new(audit, "http://localhost:8080");
        let debug = format!("{handler:?}");
        assert!(debug.contains("BitwardenHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = BitwardenHandler::new(audit, "http://localhost:8080");
        let request = make_request("bitwarden.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown Bitwarden operation"));
    }

    #[tokio::test]
    async fn read_secret_missing_id_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = BitwardenHandler::new(audit, "http://localhost:8080");
        let request = make_request("bitwarden.read_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_id'"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with the access token
    /// provided via env var.
    async fn setup_handler_with_mock() -> (BitwardenHandler, MockServer, Arc<InMemoryAuditEmitter>)
    {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide the access token via env var so resolve_token()
        // uses env resolver instead of keychain.
        let token_env = format!("OPAQUE_TEST_BW_TOKEN_{}", uuid::Uuid::new_v4().as_simple());
        unsafe { std::env::set_var(&token_env, "test-bw-token") };
        unsafe { std::env::set_var(TOKEN_REF_ENV, format!("env:{token_env}")) };

        let handler = BitwardenHandler::new(audit.clone(), &mock_server.uri());
        (handler, mock_server, audit)
    }

    /// Clean up env vars after test.
    fn cleanup_env() {
        unsafe { std::env::remove_var(TOKEN_REF_ENV) };
    }

    #[tokio::test]
    async fn list_projects_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .and(header("Authorization", "Bearer test-bw-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "p1", "name": "Production"},
                {"id": "p2", "name": "Staging"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("bitwarden.list_projects", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        // Response should contain sanitized projects (names only, no IDs).
        let projects = result["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0]["name"], "Production");
        assert!(projects[0].get("id").is_none()); // ID must not leak
        assert_eq!(projects[1]["name"], "Staging");

        // Verify audit events were emitted.
        let events = audit.events();
        assert!(events.len() >= 2); // ProviderFetchStarted + ProviderFetchFinished

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        // Mock list_projects to resolve project name → ID
        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "p1", "name": "Production"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock list_secrets for the resolved project ID
        Mock::given(method("GET"))
            .and(path("/api/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "s1", "key": "DB_PASSWORD"},
                {"id": "s2", "key": "API_KEY"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "bitwarden.list_secrets",
            serde_json::json!({"project": "Production"}),
        );
        let result = handler.execute(&request).await.unwrap();

        // Response should contain sanitized secrets (keys only, no IDs).
        assert_eq!(result["project"], "Production");
        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0]["key"], "DB_PASSWORD");
        assert!(secrets[0].get("id").is_none()); // ID must not leak
        assert_eq!(secrets[1]["key"], "API_KEY");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_no_project_filter() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/api/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "s1", "key": "DB_PASSWORD"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("bitwarden.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0]["key"], "DB_PASSWORD");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_projects_auth_failure() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("bitwarden.list_projects", serde_json::json!({}));
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication failed"));

        cleanup_env();
    }

    #[tokio::test]
    async fn read_secret_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/api/secrets/sec-123"))
            .and(header("Authorization", "Bearer test-bw-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sec-123",
                "key": "DB_PASSWORD",
                "value": "supersecret",
                "projectId": "p1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "bitwarden.read_secret",
            serde_json::json!({"secret_id": "sec-123"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["secret_id"], "sec-123");
        assert_eq!(result["key"], "DB_PASSWORD");
        assert_eq!(result["value"], "supersecret");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn read_secret_not_found() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/api/secrets/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "bitwarden.read_secret",
            serde_json::json!({"secret_id": "missing"}),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_project_not_found() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        // Project lookup returns empty list → project not found
        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "bitwarden.list_secrets",
            serde_json::json!({"project": "Nonexistent"}),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("project lookup failed"));

        cleanup_env();
    }
}
