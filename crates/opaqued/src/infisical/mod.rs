//! Infisical Secrets Manager integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `infisical:<project-id>/<environment>/<secret-name>` refs
//! - **CLI browsing** via `infisical.list_projects`, `infisical.list_secrets`,
//!   `infisical.get_secret`, `infisical.create_secret`, and `infisical.update_secret`
//!
//! Uses the Infisical REST API with service tokens or machine identity tokens.
//!
//! Backend selection:
//! 1. If `OPAQUE_INFISICAL_URL` is set -> use that URL
//! 2. Otherwise -> use default `https://app.infisical.com/api`
//! 3. If no token is configured -> disabled

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

use client::InfisicalClient;

/// Default keychain ref for the Infisical service token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/infisical-token";

/// Environment variable to override the default Infisical token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_INFISICAL_TOKEN_REF";

/// The Infisical operation handler.
///
/// Handles project/secret browsing operations. A single `InfisicalHandler`
/// instance is registered for each Infisical operation name; it dispatches
/// by `request.operation`.
pub struct InfisicalHandler {
    audit: Arc<dyn AuditSink>,
    client: InfisicalClient,
    token_ref: String,
}

impl fmt::Debug for InfisicalHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InfisicalHandler")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

impl InfisicalHandler {
    /// Create a handler for the Infisical API.
    pub fn new(
        audit: Arc<dyn AuditSink>,
        base_url: &str,
    ) -> Result<Self, client::InfisicalApiError> {
        let token_ref =
            std::env::var(TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Ok(Self {
            audit,
            client: InfisicalClient::new(base_url)?,
            token_ref,
        })
    }

    /// Resolve the Infisical service token.
    fn resolve_token(&self) -> Result<String, String> {
        let base = BaseResolver::new();
        let token_value = base
            .resolve(&self.token_ref)
            .map_err(|e| format!("failed to resolve Infisical service token: {e}"))?;
        token_value
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| "Infisical service token is not valid UTF-8".to_string())
    }
}

impl OperationHandler for InfisicalHandler {
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
                "infisical.list_projects" => {
                    let org_id = params
                        .get("org_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'org_id' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=list_projects org_id={org_id}")),
                    );

                    let token = self.resolve_token()?;
                    let projects = self
                        .client
                        .list_projects(&token, org_id)
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
                "infisical.list_secrets" => {
                    let project_id = params
                        .get("project_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project_id' parameter".to_string())?;
                    let env = params
                        .get("environment")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'environment' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=list_secrets project_id={project_id} env={env}"
                            )),
                    );

                    let token = self.resolve_token()?;
                    let secrets = self
                        .client
                        .list_secrets(&token, project_id, env)
                        .await
                        .map_err(|e| format!("failed to list secrets: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project_id={project_id} env={env} secrets_count={}",
                                secrets.len()
                            )),
                    );

                    // Return keys only, not values.
                    let sanitized: Vec<serde_json::Value> = secrets
                        .into_iter()
                        .map(|s| {
                            serde_json::json!({
                                "key": s.key,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({
                        "project_id": project_id,
                        "environment": env,
                        "secrets": sanitized,
                    }))
                }
                "infisical.get_secret" => {
                    let project_id = params
                        .get("project_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project_id' parameter".to_string())?;
                    let env = params
                        .get("environment")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'environment' parameter".to_string())?;
                    let name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=get_secret project_id={project_id} env={env} name={name}"
                            )),
                    );

                    let token = self.resolve_token()?;
                    let secret = self
                        .client
                        .get_secret(&token, project_id, env, name)
                        .await
                        .map_err(|e| format!("failed to get secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project_id={project_id} env={env} name={name} value_len={}",
                                secret.value.len()
                            )),
                    );

                    Ok(serde_json::json!({
                        "project_id": project_id,
                        "environment": env,
                        "name": name,
                        "value": secret.value,
                    }))
                }
                "infisical.create_secret" => {
                    let project_id = params
                        .get("project_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project_id' parameter".to_string())?;
                    let env = params
                        .get("environment")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'environment' parameter".to_string())?;
                    let name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;
                    let value = params
                        .get("value")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'value' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=create_secret project_id={project_id} env={env} name={name}"
                            )),
                    );

                    let token = self.resolve_token()?;
                    self.client
                        .create_secret(&token, project_id, env, name, value)
                        .await
                        .map_err(|e| format!("failed to create secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("project_id={project_id} env={env} name={name}")),
                    );

                    Ok(serde_json::json!({
                        "project_id": project_id,
                        "environment": env,
                        "name": name,
                        "status": "created",
                    }))
                }
                "infisical.update_secret" => {
                    let project_id = params
                        .get("project_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project_id' parameter".to_string())?;
                    let env = params
                        .get("environment")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'environment' parameter".to_string())?;
                    let name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;
                    let value = params
                        .get("value")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'value' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=update_secret project_id={project_id} env={env} name={name}"
                            )),
                    );

                    let token = self.resolve_token()?;
                    self.client
                        .update_secret(&token, project_id, env, name, value)
                        .await
                        .map_err(|e| format!("failed to update secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("project_id={project_id} env={env} name={name}")),
                    );

                    Ok(serde_json::json!({
                        "project_id": project_id,
                        "environment": env,
                        "name": name,
                        "status": "updated",
                    }))
                }
                other => Err(format!("unknown Infisical operation: {other}")),
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
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let debug = format!("{handler:?}");
        assert!(debug.contains("InfisicalHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("infisical.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown Infisical operation"));
    }

    #[tokio::test]
    async fn list_projects_missing_org_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("infisical.list_projects", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'org_id'"));
    }

    #[tokio::test]
    async fn get_secret_missing_project_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "infisical.get_secret",
            serde_json::json!({"environment": "prod", "name": "KEY"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project_id'"));
    }

    #[tokio::test]
    async fn get_secret_missing_env_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "infisical.get_secret",
            serde_json::json!({"project_id": "proj", "name": "KEY"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'environment'"));
    }

    #[tokio::test]
    async fn get_secret_missing_name_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "infisical.get_secret",
            serde_json::json!({"project_id": "proj", "environment": "prod"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));
    }

    #[tokio::test]
    async fn create_secret_missing_value_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "infisical.create_secret",
            serde_json::json!({"project_id": "proj", "environment": "prod", "name": "KEY"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value'"));
    }

    #[tokio::test]
    async fn update_secret_missing_value_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "infisical.update_secret",
            serde_json::json!({"project_id": "proj", "environment": "prod", "name": "KEY"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value'"));
    }

    #[tokio::test]
    async fn list_secrets_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = InfisicalHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("infisical.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project_id'"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with the service token
    /// provided via env var.
    async fn setup_handler_with_mock() -> (InfisicalHandler, MockServer, Arc<InMemoryAuditEmitter>)
    {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide the service token via env var so resolve_token()
        // uses env resolver instead of keychain.
        let token_env = format!("OPAQUE_TEST_INF_TOKEN_{}", uuid::Uuid::new_v4().as_simple());
        unsafe { std::env::set_var(&token_env, "test-inf-token") };
        unsafe { std::env::set_var(TOKEN_REF_ENV, format!("env:{token_env}")) };

        let handler = InfisicalHandler::new(audit.clone(), &mock_server.uri()).unwrap();
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
            .and(path("/organizations/org-1/workspaces"))
            .and(header("Authorization", "Bearer test-inf-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspaces": [
                    {"id": "p1", "name": "Production"},
                    {"id": "p2", "name": "Staging"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "infisical.list_projects",
            serde_json::json!({"org_id": "org-1"}),
        );
        let result = handler.execute(&request).await.unwrap();

        let projects = result["projects"].as_array().unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0]["name"], "Production");
        assert!(projects[0].get("id").is_none());
        assert_eq!(projects[1]["name"], "Staging");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("workspaceId", "proj-1"))
            .and(query_param("environment", "production"))
            .and(header("Authorization", "Bearer test-inf-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": [
                    {"_id": "s1", "secretKey": "DB_PASSWORD", "secretValue": "secret123"},
                    {"_id": "s2", "secretKey": "API_KEY", "secretValue": "key456"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "infisical.list_secrets",
            serde_json::json!({"project_id": "proj-1", "environment": "production"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["project_id"], "proj-1");
        assert_eq!(result["environment"], "production");
        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0]["key"], "DB_PASSWORD");
        // Values must not be in the list output
        assert!(secrets[0].get("value").is_none());

        cleanup_env();
    }

    #[tokio::test]
    async fn get_secret_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/secrets/DB_PASSWORD"))
            .and(query_param("workspaceId", "proj-1"))
            .and(query_param("environment", "production"))
            .and(header("Authorization", "Bearer test-inf-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secret": {
                    "secretKey": "DB_PASSWORD",
                    "secretValue": "supersecret"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "infisical.get_secret",
            serde_json::json!({
                "project_id": "proj-1",
                "environment": "production",
                "name": "DB_PASSWORD"
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["project_id"], "proj-1");
        assert_eq!(result["environment"], "production");
        assert_eq!(result["name"], "DB_PASSWORD");
        assert_eq!(result["value"], "supersecret");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn create_secret_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/secrets/NEW_SECRET"))
            .and(header("Authorization", "Bearer test-inf-token"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "secret": {
                    "secretKey": "NEW_SECRET",
                    "secretValue": "newval"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "infisical.create_secret",
            serde_json::json!({
                "project_id": "proj-1",
                "environment": "production",
                "name": "NEW_SECRET",
                "value": "newval"
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["status"], "created");
        assert_eq!(result["name"], "NEW_SECRET");

        cleanup_env();
    }

    #[tokio::test]
    async fn update_secret_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("PATCH"))
            .and(path("/secrets/DB_PASSWORD"))
            .and(header("Authorization", "Bearer test-inf-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secret": {
                    "secretKey": "DB_PASSWORD",
                    "secretValue": "updated"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "infisical.update_secret",
            serde_json::json!({
                "project_id": "proj-1",
                "environment": "production",
                "name": "DB_PASSWORD",
                "value": "updated"
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["status"], "updated");
        assert_eq!(result["name"], "DB_PASSWORD");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_projects_auth_failure() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/organizations/org-1/workspaces"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "infisical.list_projects",
            serde_json::json!({"org_id": "org-1"}),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication failed"));

        cleanup_env();
    }
}
