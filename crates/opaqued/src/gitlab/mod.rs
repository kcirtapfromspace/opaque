//! GitLab CI/CD variable integration.
//!
//! Provides:
//! - `gitlab.set_ci_variable` operation (safe write-only secret sync)

pub mod client;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;
use opaque_core::profile::ALLOWED_REF_SCHEMES;

use crate::enclave::OperationHandler;
use crate::sandbox::resolve::{CompositeResolver, SecretResolver};

use client::{GitLabClient, SetCiVariableOptions, SetCiVariableResponse};

/// Default keychain ref for the GitLab token.
const DEFAULT_GITLAB_TOKEN_REF: &str = "keychain:opaque/gitlab-pat";

/// Environment variable to override default GitLab token ref.
const GITLAB_TOKEN_REF_ENV: &str = "OPAQUE_GITLAB_TOKEN_REF";

/// GitLab operation handler.
pub struct GitLabHandler {
    audit: Arc<dyn AuditSink>,
    client: GitLabClient,
}

impl fmt::Debug for GitLabHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitLabHandler").finish()
    }
}

impl GitLabHandler {
    pub fn new(audit: Arc<dyn AuditSink>) -> Self {
        Self {
            audit,
            client: GitLabClient::new(),
        }
    }

    #[cfg(test)]
    pub fn with_client(audit: Arc<dyn AuditSink>, client: GitLabClient) -> Self {
        Self { audit, client }
    }
}

/// Resolve GitLab token ref from params, env override, or default.
fn resolve_gitlab_token_ref(params: &serde_json::Value) -> String {
    let env_ref = std::env::var(GITLAB_TOKEN_REF_ENV).ok();
    params
        .get("gitlab_token_ref")
        .and_then(|v| v.as_str())
        .or(env_ref.as_deref())
        .unwrap_or(DEFAULT_GITLAB_TOKEN_REF)
        .to_owned()
}

fn validate_project(project: &str) -> Result<(), String> {
    if project.is_empty() {
        return Err("project must be non-empty".into());
    }
    if project.len() > 512 {
        return Err("project must be at most 512 characters".into());
    }
    if project.chars().any(|c| c.is_ascii_control()) {
        return Err("project must not contain control characters".into());
    }
    Ok(())
}

fn validate_variable_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("key must be non-empty".into());
    }
    if key.len() > 255 {
        return Err("key must be at most 255 characters".into());
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("key must contain only alphanumeric characters and underscores".into());
    }
    Ok(())
}

fn validate_value_ref(ref_str: &str) -> Result<(), String> {
    if ALLOWED_REF_SCHEMES.iter().any(|p| ref_str.starts_with(p)) {
        Ok(())
    } else {
        Err(format!(
            "value_ref must start with a known scheme ({ALLOWED_REF_SCHEMES:?}), got: '{ref_str}'"
        ))
    }
}

fn validate_variable_type(variable_type: Option<&str>) -> Result<(), String> {
    if let Some(t) = variable_type
        && !matches!(t, "env_var" | "file")
    {
        return Err(format!(
            "variable_type must be 'env_var' or 'file', got: '{t}'"
        ));
    }
    Ok(())
}

impl OperationHandler for GitLabHandler {
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
                "gitlab.set_ci_variable" => {
                    let project = params
                        .get("project")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'project' parameter".to_string())?;
                    let key = params
                        .get("key")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'key' parameter".to_string())?;
                    let value_ref = params
                        .get("value_ref")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'value_ref' parameter".to_string())?;

                    let environment_scope =
                        params.get("environment_scope").and_then(|v| v.as_str());
                    let protected = params.get("protected").and_then(|v| v.as_bool());
                    let masked = params.get("masked").and_then(|v| v.as_bool());
                    let raw = params.get("raw").and_then(|v| v.as_bool());
                    let variable_type = params.get("variable_type").and_then(|v| v.as_str());

                    validate_project(project)?;
                    validate_variable_key(key)?;
                    validate_value_ref(value_ref)?;
                    validate_variable_type(variable_type)?;

                    let gitlab_token_ref = resolve_gitlab_token_ref(&params);
                    validate_value_ref(&gitlab_token_ref)?;

                    let resolver = CompositeResolver::new();
                    let secret_value = resolver
                        .resolve(value_ref)
                        .map_err(|e| format!("failed to resolve value_ref: {e}"))?;
                    secret_value.mlock();
                    let value = secret_value
                        .as_str()
                        .ok_or_else(|| "resolved secret value is not valid UTF-8".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::SecretResolved)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("resolved")
                            .with_detail(format!(
                                "ref_scheme={}",
                                value_ref.split(':').next().unwrap_or("unknown")
                            )),
                    );

                    let token_value = resolver
                        .resolve(&gitlab_token_ref)
                        .map_err(|e| format!("failed to resolve gitlab_token_ref: {e}"))?;
                    token_value.mlock();
                    let token = token_value
                        .as_str()
                        .ok_or_else(|| "GitLab token is not valid UTF-8".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::SecretResolved)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("resolved")
                            .with_detail("ref_scheme=gitlab_token"),
                    );

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=set_ci_variable project={project} key={key}"
                            )),
                    );

                    let response = self
                        .client
                        .set_ci_variable(
                            token,
                            project,
                            key,
                            value,
                            SetCiVariableOptions {
                                environment_scope,
                                protected,
                                masked,
                                raw,
                                variable_type,
                            },
                        )
                        .await
                        .map_err(|e| format!("failed to set ci variable: {e}"))?;

                    let status = match response {
                        SetCiVariableResponse::Created => "created",
                        SetCiVariableResponse::Updated => "updated",
                    };

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome(status)
                            .with_detail(format!("project={project} key={key}")),
                    );

                    let mut result = serde_json::json!({
                        "status": status,
                        "project": project,
                        "key": key,
                    });
                    if let Some(scope) = environment_scope {
                        result["environment_scope"] = serde_json::Value::String(scope.to_owned());
                    }
                    if let Some(p) = protected {
                        result["protected"] = serde_json::Value::Bool(p);
                    }
                    if let Some(m) = masked {
                        result["masked"] = serde_json::Value::Bool(m);
                    }
                    if let Some(r) = raw {
                        result["raw"] = serde_json::Value::Bool(r);
                    }
                    if let Some(t) = variable_type {
                        result["variable_type"] = serde_json::Value::String(t.to_owned());
                    }

                    Ok(result)
                }
                other => Err(format!("unknown GitLab operation: {other}")),
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let handler = GitLabHandler::new(audit);
        let debug = format!("{handler:?}");
        assert!(debug.contains("GitLabHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitLabHandler::new(audit);
        let request = make_request("gitlab.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown GitLab operation"));
    }

    #[tokio::test]
    async fn missing_key_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitLabHandler::new(audit);
        let request = make_request(
            "gitlab.set_ci_variable",
            serde_json::json!({
                "project": "group/proj",
                "value_ref": "env:MY_VAR",
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'key'"));
    }

    #[tokio::test]
    async fn invalid_variable_type_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitLabHandler::new(audit);
        let request = make_request(
            "gitlab.set_ci_variable",
            serde_json::json!({
                "project": "group/proj",
                "key": "API_KEY",
                "value_ref": "env:MY_VAR",
                "variable_type": "INVALID",
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("variable_type"));
    }

    #[tokio::test]
    async fn set_ci_variable_via_handler() {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = GitLabClient::with_base_url(mock_server.uri());
        let handler = GitLabHandler::with_client(audit.clone(), client);

        let token_env = format!(
            "OPAQUE_TEST_GITLAB_TOKEN_{}",
            uuid::Uuid::new_v4().as_simple()
        );
        let value_env = format!(
            "OPAQUE_TEST_GITLAB_VALUE_{}",
            uuid::Uuid::new_v4().as_simple()
        );
        unsafe { std::env::set_var(&token_env, "glpat-test-token") };
        unsafe { std::env::set_var(&value_env, "secret-value") };
        unsafe { std::env::set_var(GITLAB_TOKEN_REF_ENV, format!("env:{token_env}")) };

        Mock::given(method("PUT"))
            .and(path("/projects/group%2Fproj/variables/API_KEY"))
            .and(header("private-token", "glpat-test-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "gitlab.set_ci_variable",
            serde_json::json!({
                "project": "group/proj",
                "key": "API_KEY",
                "value_ref": format!("env:{value_env}"),
                "environment_scope": "*",
                "protected": true,
                "masked": false,
                "raw": true,
                "variable_type": "env_var",
            }),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["status"], "updated");
        assert_eq!(result["project"], "group/proj");
        assert_eq!(result["key"], "API_KEY");
        assert!(result.get("value").is_none());

        let events = audit.events();
        assert!(events.len() >= 3);

        unsafe {
            std::env::remove_var(&token_env);
            std::env::remove_var(&value_env);
            std::env::remove_var(GITLAB_TOKEN_REF_ENV);
        }
    }
}
