//! Google Cloud Secret Manager integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `gcp:<project>/<secret>` or `gcp:<project>/<secret>/<version>` refs
//! - **CLI browsing** via `gcp.list_secrets`, `gcp.get_secret`, `gcp.create_secret`,
//!   `gcp.add_secret_version` operations
//! - **Secret access** via `gcp.access_secret_version` (Reveal -- hard-blocked for agents)
//!
//! Uses the GCP Secret Manager REST API v1 with OAuth2 service account auth.
//!
//! Backend selection:
//! 1. If `OPAQUE_GCP_SM_URL` is set -> use that URL
//! 2. Otherwise -> use default `https://secretmanager.googleapis.com/v1`
//! 3. If no credentials are configured -> disabled

pub mod client;
pub mod resolve;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use crate::enclave::OperationHandler;

use client::GcpSecretManagerClient;

/// The GCP Secret Manager operation handler.
///
/// Handles secret browsing and management operations. A single `GcpHandler`
/// instance is registered for each GCP operation name; it dispatches
/// by `request.operation`.
pub struct GcpHandler {
    audit: Arc<dyn AuditSink>,
    client: GcpSecretManagerClient,
}

impl fmt::Debug for GcpHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcpHandler").finish()
    }
}

impl GcpHandler {
    /// Create a handler for the GCP Secret Manager API.
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Result<Self, client::GcpApiError> {
        Ok(Self {
            audit,
            client: GcpSecretManagerClient::new(base_url)?,
        })
    }

    /// Resolve the GCP access token.
    async fn resolve_token(&self) -> Result<String, String> {
        self.client
            .get_access_token()
            .await
            .map_err(|e| format!("failed to resolve GCP access token: {e}"))
    }
}

impl OperationHandler for GcpHandler {
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
                "gcp.list_secrets" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=list_secrets project={project}")),
                    );

                    let token = self.resolve_token().await?;
                    let secrets = self
                        .client
                        .list_secrets(&token, project)
                        .await
                        .map_err(|e| format!("failed to list secrets: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={project} secrets_count={}",
                                secrets.len()
                            )),
                    );

                    // Return sanitized response: names only.
                    let sanitized: Vec<serde_json::Value> = secrets
                        .into_iter()
                        .map(|s| {
                            // Extract just the secret name from the full resource path.
                            let short_name = s.name.rsplit('/').next().unwrap_or(&s.name);
                            serde_json::json!({
                                "name": short_name,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({
                        "project": project,
                        "secrets": sanitized,
                    }))
                }
                "gcp.get_secret" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let secret_id = params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'secret_id' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=get_secret project={project} secret={secret_id}"
                            )),
                    );

                    let token = self.resolve_token().await?;
                    let secret = self
                        .client
                        .get_secret(&token, project, secret_id)
                        .await
                        .map_err(|e| format!("failed to get secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("project={project} secret={secret_id}")),
                    );

                    // Return metadata only, no values.
                    Ok(serde_json::json!({
                        "name": secret.name,
                        "create_time": secret.create_time,
                    }))
                }
                "gcp.access_secret_version" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let secret_id = params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'secret_id' parameter".to_string())?;
                    let version = params
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("latest");

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=access_secret_version project={project} secret={secret_id} version={version}"
                            )),
                    );

                    let token = self.resolve_token().await?;
                    let resp = self
                        .client
                        .access_secret_version(&token, project, secret_id, version)
                        .await
                        .map_err(|e| format!("failed to access secret version: {e}"))?;

                    let decoded = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &resp.payload.data,
                    )
                    .map_err(|e| format!("failed to decode secret payload: {e}"))?;

                    let value = String::from_utf8(decoded)
                        .map_err(|e| format!("secret payload is not valid UTF-8: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={project} secret={secret_id} version={version} value_len={}",
                                value.len()
                            )),
                    );

                    Ok(serde_json::json!({
                        "project": project,
                        "secret_id": secret_id,
                        "version": version,
                        "value": value,
                    }))
                }
                "gcp.add_secret_version" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let secret_id = params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'secret_id' parameter".to_string())?;
                    let value_ref = params
                        .get("value_ref")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'value_ref' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=add_secret_version project={project} secret={secret_id}"
                            )),
                    );

                    // Resolve the secret value from the ref.
                    let base = crate::sandbox::resolve::BaseResolver::new();
                    let secret_value =
                        crate::sandbox::resolve::SecretResolver::resolve(&base, value_ref)
                            .map_err(|e| format!("failed to resolve value_ref: {e}"))?;

                    let token = self.resolve_token().await?;
                    let version = self
                        .client
                        .add_secret_version(&token, project, secret_id, secret_value.as_bytes())
                        .await
                        .map_err(|e| format!("failed to add secret version: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={project} secret={secret_id} version={}",
                                version.name
                            )),
                    );

                    Ok(serde_json::json!({
                        "version": version.name,
                        "state": version.state,
                    }))
                }
                "gcp.create_secret" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let secret_id = params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'secret_id' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=create_secret project={project} secret_id={secret_id}"
                            )),
                    );

                    let token = self.resolve_token().await?;
                    let secret = self
                        .client
                        .create_secret(&token, project, secret_id)
                        .await
                        .map_err(|e| format!("failed to create secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={project} secret_id={secret_id} name={}",
                                secret.name
                            )),
                    );

                    Ok(serde_json::json!({
                        "name": secret.name,
                        "create_time": secret.create_time,
                    }))
                }
                other => Err(format!("unknown GCP operation: {other}")),
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
        let handler = GcpHandler::new(audit, "http://localhost:8080").unwrap();
        let debug = format!("{handler:?}");
        assert!(debug.contains("GcpHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GcpHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("gcp.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown GCP operation"));
    }

    #[tokio::test]
    async fn list_secrets_missing_project_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GcpHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("gcp.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));
    }

    #[tokio::test]
    async fn get_secret_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GcpHandler::new(audit, "http://localhost:8080").unwrap();

        // Missing project
        let request = make_request("gcp.get_secret", serde_json::json!({"secret_id": "test"}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));

        // Missing secret_id
        let request = make_request("gcp.get_secret", serde_json::json!({"project": "test"}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_id'"));
    }

    #[tokio::test]
    async fn access_secret_version_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GcpHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("gcp.access_secret_version", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));
    }

    #[tokio::test]
    async fn add_secret_version_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GcpHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("gcp.add_secret_version", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));
    }

    #[tokio::test]
    async fn create_secret_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GcpHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("gcp.create_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with the access token
    /// provided via env var.
    async fn setup_handler_with_mock() -> (GcpHandler, MockServer, Arc<InMemoryAuditEmitter>) {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide the access token via env var.
        let token_env = format!("OPAQUE_GCP_TEST_TOKEN_{}", uuid::Uuid::new_v4().as_simple());
        unsafe {
            std::env::set_var(&token_env, "test-gcp-token");
            std::env::set_var(client::GCP_ACCESS_TOKEN_ENV, "test-gcp-token");
        }

        let handler = GcpHandler::new(audit.clone(), &mock_server.uri()).unwrap();
        (handler, mock_server, audit)
    }

    /// Clean up env vars after test.
    fn cleanup_env() {
        unsafe {
            std::env::remove_var(client::GCP_ACCESS_TOKEN_ENV);
        }
    }

    #[tokio::test]
    async fn list_secrets_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets"))
            .and(header("Authorization", "Bearer test-gcp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": [
                    {"name": "projects/my-project/secrets/db-password"},
                    {"name": "projects/my-project/secrets/api-key"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gcp.list_secrets",
            serde_json::json!({"project": "my-project"}),
        );
        let result = handler.execute(&request).await.unwrap();

        // Response should contain sanitized secrets (short names only).
        assert_eq!(result["project"], "my-project");
        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0]["name"], "db-password");
        assert_eq!(secrets[1]["name"], "api-key");

        // Verify audit events were emitted.
        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn get_secret_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets/db-password"))
            .and(header("Authorization", "Bearer test-gcp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/db-password",
                "createTime": "2024-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gcp.get_secret",
            serde_json::json!({"project": "my-project", "secret_id": "db-password"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["name"], "projects/my-project/secrets/db-password");
        assert_eq!(result["create_time"], "2024-01-01T00:00:00Z");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn access_secret_version_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path(
                "/projects/my-project/secrets/db-password/versions/latest:access",
            ))
            .and(header("Authorization", "Bearer test-gcp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/db-password/versions/1",
                "payload": {
                    "data": "c3VwZXJzZWNyZXQ="
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gcp.access_secret_version",
            serde_json::json!({
                "project": "my-project",
                "secret_id": "db-password"
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["project"], "my-project");
        assert_eq!(result["secret_id"], "db-password");
        assert_eq!(result["version"], "latest");
        assert_eq!(result["value"], "supersecret");

        cleanup_env();
    }

    #[tokio::test]
    async fn create_secret_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/projects/my-project/secrets"))
            .and(query_param("secretId", "new-secret"))
            .and(header("Authorization", "Bearer test-gcp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/new-secret",
                "createTime": "2024-06-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gcp.create_secret",
            serde_json::json!({
                "project": "my-project",
                "secret_id": "new-secret"
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["name"], "projects/my-project/secrets/new-secret");
        assert_eq!(result["create_time"], "2024-06-01T00:00:00Z");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn add_secret_version_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        // Set up the env var that will be resolved via value_ref.
        let val_env = format!("OPAQUE_GCP_TEST_VAL_{}", uuid::Uuid::new_v4().as_simple());
        unsafe {
            std::env::set_var(&val_env, "my-secret-value");
        }

        Mock::given(method("POST"))
            .and(path("/projects/my-project/secrets/db-password:addVersion"))
            .and(header("Authorization", "Bearer test-gcp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/db-password/versions/2",
                "state": "ENABLED"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gcp.add_secret_version",
            serde_json::json!({
                "project": "my-project",
                "secret_id": "db-password",
                "value_ref": format!("env:{val_env}")
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(
            result["version"],
            "projects/my-project/secrets/db-password/versions/2"
        );
        assert_eq!(result["state"], "ENABLED");

        unsafe {
            std::env::remove_var(&val_env);
        }
        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_auth_failure() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gcp.list_secrets",
            serde_json::json!({"project": "my-project"}),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication failed"));

        cleanup_env();
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gcp.get_secret",
            serde_json::json!({
                "project": "my-project",
                "secret_id": "missing"
            }),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));

        cleanup_env();
    }
}
