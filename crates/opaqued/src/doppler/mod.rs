//! Doppler Secrets Manager integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `doppler:<project>/<config>/<secret-name>` refs
//! - **CLI browsing** via `doppler.list_projects`, `doppler.list_configs`,
//!   `doppler.list_secrets`, `doppler.get_secret`, and `doppler.set_secret`
//!
//! Uses the Doppler REST API with service tokens.
//!
//! Backend selection:
//! 1. If `OPAQUE_DOPPLER_URL` is set -> use that URL
//! 2. Otherwise -> use default `https://api.doppler.com/v3`
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

use client::DopplerClient;

/// Default keychain ref for the Doppler service token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/doppler-token";

/// Environment variable to override the default Doppler token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_DOPPLER_TOKEN_REF";

/// The Doppler operation handler.
///
/// Handles project/config/secret browsing operations. A single `DopplerHandler`
/// instance is registered for each Doppler operation name; it dispatches
/// by `request.operation`.
pub struct DopplerHandler {
    audit: Arc<dyn AuditSink>,
    client: DopplerClient,
    token_ref: String,
}

impl fmt::Debug for DopplerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DopplerHandler")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

impl DopplerHandler {
    /// Create a handler for the Doppler API.
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Result<Self, client::DopplerApiError> {
        let token_ref =
            std::env::var(TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Ok(Self {
            audit,
            client: DopplerClient::new(base_url)?,
            token_ref,
        })
    }

    /// Resolve the Doppler service token.
    fn resolve_token(&self) -> Result<String, String> {
        let base = BaseResolver::new();
        let token_value = base
            .resolve(&self.token_ref)
            .map_err(|e| format!("failed to resolve Doppler service token: {e}"))?;
        token_value
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| "Doppler service token is not valid UTF-8".to_string())
    }
}

impl OperationHandler for DopplerHandler {
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
                "doppler.list_projects" => {
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
                "doppler.list_configs" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=list_configs project={project}")),
                    );

                    let token = self.resolve_token()?;
                    let configs = self
                        .client
                        .list_configs(&token, project)
                        .await
                        .map_err(|e| format!("failed to list configs: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={project} configs_count={}",
                                configs.len()
                            )),
                    );

                    let sanitized: Vec<serde_json::Value> = configs
                        .into_iter()
                        .map(|c| {
                            serde_json::json!({
                                "name": c.name,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({
                        "project": project,
                        "configs": sanitized,
                    }))
                }
                "doppler.list_secrets" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let config = params
                        .get("config")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'config' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=list_secrets project={project} config={config}"
                            )),
                    );

                    let token = self.resolve_token()?;
                    let secrets = self
                        .client
                        .list_secrets(&token, project, config)
                        .await
                        .map_err(|e| format!("failed to list secrets: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={project} config={config} secrets_count={}",
                                secrets.len()
                            )),
                    );

                    // Return names only, not values.
                    let names: Vec<String> = secrets.keys().cloned().collect();

                    Ok(serde_json::json!({
                        "project": project,
                        "config": config,
                        "secrets": names,
                    }))
                }
                "doppler.get_secret" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let config = params
                        .get("config")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'config' parameter".to_string())?;
                    let name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=get_secret project={project} config={config} name={name}"
                            )),
                    );

                    let token = self.resolve_token()?;
                    let secret = self
                        .client
                        .get_secret(&token, project, config, name)
                        .await
                        .map_err(|e| format!("failed to get secret: {e}"))?;

                    let value = secret
                        .value
                        .computed
                        .or(secret.value.raw)
                        .ok_or_else(|| format!("secret '{name}' has no value"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={project} config={config} name={name} value_len={}",
                                value.len()
                            )),
                    );

                    Ok(serde_json::json!({
                        "project": project,
                        "config": config,
                        "name": name,
                        "value": value,
                    }))
                }
                "doppler.set_secret" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let config = params
                        .get("config")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'config' parameter".to_string())?;
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
                                "endpoint=set_secret project={project} config={config} name={name}"
                            )),
                    );

                    let token = self.resolve_token()?;
                    self.client
                        .set_secret(&token, project, config, name, value)
                        .await
                        .map_err(|e| format!("failed to set secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("project={project} config={config} name={name}")),
                    );

                    Ok(serde_json::json!({
                        "project": project,
                        "config": config,
                        "name": name,
                        "status": "ok",
                    }))
                }
                other => Err(format!("unknown Doppler operation: {other}")),
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
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let debug = format!("{handler:?}");
        assert!(debug.contains("DopplerHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("doppler.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown Doppler operation"));
    }

    #[tokio::test]
    async fn get_secret_missing_project_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "doppler.get_secret",
            serde_json::json!({"config": "prod", "name": "KEY"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));
    }

    #[tokio::test]
    async fn get_secret_missing_config_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "doppler.get_secret",
            serde_json::json!({"project": "proj", "name": "KEY"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'config'"));
    }

    #[tokio::test]
    async fn get_secret_missing_name_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "doppler.get_secret",
            serde_json::json!({"project": "proj", "config": "prod"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));
    }

    #[tokio::test]
    async fn set_secret_missing_value_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request(
            "doppler.set_secret",
            serde_json::json!({"project": "proj", "config": "prod", "name": "KEY"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value'"));
    }

    #[tokio::test]
    async fn list_configs_missing_project_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("doppler.list_configs", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));
    }

    #[tokio::test]
    async fn list_secrets_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = DopplerHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("doppler.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'project'"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with the service token
    /// provided via env var.
    async fn setup_handler_with_mock() -> (DopplerHandler, MockServer, Arc<InMemoryAuditEmitter>) {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide the service token via env var so resolve_token()
        // uses env resolver instead of keychain.
        let token_env = format!("OPAQUE_TEST_DP_TOKEN_{}", uuid::Uuid::new_v4().as_simple());
        unsafe { std::env::set_var(&token_env, "test-dp-token") };
        unsafe { std::env::set_var(TOKEN_REF_ENV, format!("env:{token_env}")) };

        let handler = DopplerHandler::new(audit.clone(), &mock_server.uri()).unwrap();
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
            .and(path("/workplace/projects"))
            .and(header("Authorization", "Bearer test-dp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "projects": [
                    {"id": "p1", "name": "Production"},
                    {"id": "p2", "name": "Staging"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("doppler.list_projects", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        // Response should contain sanitized projects (names only, no IDs).
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
    async fn list_configs_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/configs"))
            .and(query_param("project", "my-project"))
            .and(header("Authorization", "Bearer test-dp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "configs": [
                    {"name": "production", "root": true},
                    {"name": "staging", "root": false}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "doppler.list_configs",
            serde_json::json!({"project": "my-project"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["project"], "my-project");
        let configs = result["configs"].as_array().unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0]["name"], "production");
        assert_eq!(configs[1]["name"], "staging");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/configs/config/secrets"))
            .and(query_param("project", "my-project"))
            .and(query_param("config", "production"))
            .and(header("Authorization", "Bearer test-dp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": {
                    "DB_PASSWORD": {"raw": "secret", "computed": "secret"},
                    "API_KEY": {"raw": "key", "computed": "key"}
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "doppler.list_secrets",
            serde_json::json!({"project": "my-project", "config": "production"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["project"], "my-project");
        assert_eq!(result["config"], "production");
        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn get_secret_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/configs/config/secret"))
            .and(query_param("project", "my-project"))
            .and(query_param("config", "production"))
            .and(query_param("name", "DB_PASSWORD"))
            .and(header("Authorization", "Bearer test-dp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "DB_PASSWORD",
                "value": {
                    "raw": "supersecret",
                    "computed": "supersecret"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "doppler.get_secret",
            serde_json::json!({
                "project": "my-project",
                "config": "production",
                "name": "DB_PASSWORD"
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["project"], "my-project");
        assert_eq!(result["config"], "production");
        assert_eq!(result["name"], "DB_PASSWORD");
        assert_eq!(result["value"], "supersecret");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn set_secret_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/configs/config/secrets"))
            .and(header("Authorization", "Bearer test-dp-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": {
                    "NEW_SECRET": {"raw": "newval", "computed": "newval"}
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "doppler.set_secret",
            serde_json::json!({
                "project": "my-project",
                "config": "production",
                "name": "NEW_SECRET",
                "value": "newval"
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["name"], "NEW_SECRET");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_projects_auth_failure() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/workplace/projects"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("doppler.list_projects", serde_json::json!({}));
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication failed"));

        cleanup_env();
    }
}
