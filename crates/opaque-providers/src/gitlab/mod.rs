//! GitLab CI/CD variable integration.
//!
//! Provides:
//! - `gitlab.set_ci_variable` operation (safe write-only secret sync)

pub mod client;

use std::fmt;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;
use opaque_core::profile::ALLOWED_REF_SCHEMES;

use crate::internal_resolve::CompositeResolver;
use opaque_core::operation_handler::{OperationHandler, PreparedOperation};
use opaque_core::resolver::SecretResolver;

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
    pub fn new(audit: Arc<dyn AuditSink>) -> Result<Self, String> {
        Ok(Self {
            audit,
            client: GitLabClient::new().map_err(|e| e.to_string())?,
        })
    }

    #[cfg(test)]
    pub fn with_client(audit: Arc<dyn AuditSink>, client: GitLabClient) -> Self {
        Self { audit, client }
    }
}

/// Freeze reference selection before policy or credentials.
fn resolve_gitlab_token_ref(explicit: Option<String>) -> Result<String, String> {
    let reference = explicit
        .or_else(|| std::env::var(GITLAB_TOKEN_REF_ENV).ok())
        .unwrap_or_else(|| DEFAULT_GITLAB_TOKEN_REF.to_owned());
    validate_value_ref(&reference)?;
    Ok(reference)
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct GitLabInput {
    project: String,
    key: String,
    value_ref: String,
    gitlab_token_ref: Option<String>,
    environment_scope: Option<String>,
    protected: Option<bool>,
    masked: Option<bool>,
    raw: Option<bool>,
    variable_type: Option<String>,
}

#[derive(serde::Serialize)]
struct GitLabAction {
    gitlab_api_url: String,
    #[serde(flatten)]
    input: GitLabInput,
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
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        if request.operation != "gitlab.set_ci_variable" {
            return Err(format!("unknown GitLab operation: {}", request.operation));
        }
        let mut input: GitLabInput =
            serde_json::from_value(request.params.clone()).map_err(|error| {
                let message = error.to_string();
                if let Some(field) = message
                    .strip_prefix("missing field `")
                    .and_then(|s| s.strip_suffix('`'))
                {
                    format!("missing '{field}' parameter")
                } else {
                    "invalid GitLab parameters (unexpected field or incorrect type)".to_owned()
                }
            })?;
        validate_project(&input.project)?;
        validate_variable_key(&input.key)?;
        validate_value_ref(&input.value_ref)?;
        validate_variable_type(input.variable_type.as_deref())?;
        let environment_scope = input.environment_scope.take().unwrap_or_else(|| "*".into());
        if environment_scope.is_empty()
            || environment_scope.len() > 255
            || environment_scope.chars().any(char::is_control)
        {
            return Err("environment_scope must contain 1-255 non-control characters".into());
        }
        input.environment_scope = Some(environment_scope.clone());
        let token_ref = resolve_gitlab_token_ref(input.gitlab_token_ref.take())?;
        input.gitlab_token_ref = Some(token_ref.clone());
        let refs = vec![input.value_ref.clone(), token_ref];
        let mut target = std::collections::HashMap::from([
            ("project".into(), input.project.clone()),
            ("key".into(), input.key.clone()),
            ("environment_scope".into(), environment_scope),
            ("gitlab_api_url".into(), self.client.base_url().to_owned()),
            (
                "variable_type".into(),
                input
                    .variable_type
                    .clone()
                    .unwrap_or_else(|| "preserve_or_provider_default".into()),
            ),
        ]);
        // An omitted attribute preserves its existing update value. Explicitly
        // show that contract; assigning false here could unprotect a variable.
        for (key, value) in [
            ("protected", input.protected),
            ("masked", input.masked),
            ("raw", input.raw),
        ] {
            target.insert(
                key.into(),
                value
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "preserve_or_provider_default".into()),
            );
        }
        let action = GitLabAction {
            gitlab_api_url: self.client.base_url().to_owned(),
            input,
        };
        let request_id = request.request_id;
        PreparedOperation::new(action, target, refs, move |action| async move {
            self.execute_prepared(request_id, action).await
        })
    }
}

impl GitLabHandler {
    async fn execute_prepared(
        &self,
        request_id: uuid::Uuid,
        action: GitLabAction,
    ) -> Result<serde_json::Value, String> {
        let input = action.input;
        let project = input.project.as_str();
        let key = input.key.as_str();
        let value_ref = input.value_ref.as_str();
        let gitlab_token_ref = input
            .gitlab_token_ref
            .as_deref()
            .expect("prepared reference");
        let environment_scope = input.environment_scope.as_deref();
        let protected = input.protected;
        let masked = input.masked;
        let raw = input.raw;
        let variable_type = input.variable_type.as_deref();
        let operation = "gitlab.set_ci_variable";
        let audit = &self.audit;
        let resolver = CompositeResolver::new(crate::internal_resolve::default_secret_resolvers());
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
                .with_operation(operation)
                .with_outcome("resolved")
                .with_detail(format!(
                    "ref_scheme={}",
                    value_ref.split(':').next().unwrap_or("unknown")
                )),
        );

        let token_value = resolver
            .resolve(gitlab_token_ref)
            .map_err(|e| format!("failed to resolve gitlab_token_ref: {e}"))?;
        token_value.mlock();
        let token = token_value
            .as_str()
            .ok_or_else(|| "GitLab token is not valid UTF-8".to_string())?;

        audit.emit(
            AuditEvent::new(AuditEventKind::SecretResolved)
                .with_request_id(request_id)
                .with_operation(operation)
                .with_outcome("resolved")
                .with_detail("ref_scheme=gitlab_token"),
        );

        audit.emit(
            AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                .with_request_id(request_id)
                .with_operation(operation)
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
                .with_operation(operation)
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
            principal: None,
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
        let handler = GitLabHandler::new(audit).unwrap();
        let debug = format!("{handler:?}");
        assert!(debug.contains("GitLabHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitLabHandler::new(audit).unwrap();
        let request = make_request("gitlab.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown GitLab operation"));
    }

    #[tokio::test]
    async fn missing_key_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitLabHandler::new(audit).unwrap();
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
        let handler = GitLabHandler::new(audit).unwrap();
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
                "gitlab_token_ref": format!("env:{token_env}"),
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
        }
    }
    #[tokio::test]
    async fn preparation_binds_scope_and_option_semantics_without_credentials() {
        let server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler =
            GitLabHandler::with_client(audit.clone(), GitLabClient::with_base_url(server.uri()));
        let request = make_request(
            "gitlab.set_ci_variable",
            serde_json::json!({
                "project":"group/project", "key":"TOKEN", "value_ref":"env:UNRESOLVED",
                "gitlab_token_ref":"env:UNRESOLVED_TOKEN", "environment_scope":null,
                "protected":null, "masked":true, "raw":false, "variable_type":null,
            }),
        );
        let prepared = handler.prepare(&request).unwrap();
        assert_eq!(prepared.target()["environment_scope"], "*");
        assert_eq!(
            prepared.target()["protected"],
            "preserve_or_provider_default"
        );
        assert_eq!(prepared.target()["masked"], "true");
        assert_eq!(prepared.target()["raw"], "false");
        assert_eq!(
            prepared.target()["variable_type"],
            "preserve_or_provider_default"
        );
        assert_eq!(prepared.target()["gitlab_api_url"], server.uri());
        assert_eq!(prepared.params()["environment_scope"], "*");
        assert_eq!(
            prepared.secret_ref_names(),
            ["env:UNRESOLVED", "env:UNRESOLVED_TOKEN"]
        );
        assert!(audit.events().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_options_and_competing_destinations_fail_before_credentials_or_network() {
        let server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler =
            GitLabHandler::with_client(audit.clone(), GitLabClient::with_base_url(server.uri()));
        let original = serde_json::json!({
            "project":"group/project", "key":"TOKEN", "value_ref":"env:UNRESOLVED",
            "gitlab_token_ref":"env:UNRESOLVED_TOKEN",
        });
        for (field, value) in [
            ("protected", serde_json::json!("true")),
            ("masked", serde_json::json!(1)),
            ("raw", serde_json::json!([])),
            ("variable_type", serde_json::json!(false)),
            ("gitlab_token_ref", serde_json::json!(3)),
            ("environment_scope", serde_json::json!(true)),
            ("environment_scope", serde_json::json!("")),
            ("environment_scope", serde_json::json!("prod\n")),
            ("repo", serde_json::json!("group/competing")),
            ("project", serde_json::json!(false)),
        ] {
            let mut params = original.clone();
            params[field] = value;
            let error = handler
                .execute(&make_request("gitlab.set_ci_variable", params))
                .await
                .expect_err("malformed action must fail");
            assert!(
                !error.contains("failed to resolve"),
                "{field} reached credential resolution: {error}"
            );
        }
        assert!(audit.events().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn prepared_dispatch_pins_environment_filter_options_and_token_reference() {
        use wiremock::matchers::{body_json, query_param};
        let server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler =
            GitLabHandler::with_client(audit.clone(), GitLabClient::with_base_url(server.uri()));
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let token_var = format!("OPAQUE_PREPARED_GITLAB_TOKEN_{suffix}");
        let value_var = format!("OPAQUE_PREPARED_GITLAB_VALUE_{suffix}");
        let previous_token_ref = std::env::var_os(GITLAB_TOKEN_REF_ENV);
        unsafe {
            std::env::set_var(&token_var, "synthetic-gitlab-token");
            std::env::set_var(&value_var, "synthetic-variable-value");
            std::env::set_var(GITLAB_TOKEN_REF_ENV, format!("env:{token_var}"));
        }
        Mock::given(method("PUT"))
            .and(path("/projects/group%2Fproject/variables/TOKEN"))
            .and(query_param("filter[environment_scope]", "staging"))
            .and(header("private-token", "synthetic-gitlab-token"))
            .and(body_json(serde_json::json!({
                "value":"synthetic-variable-value", "environment_scope":"staging",
                "protected":true, "masked":true, "raw":false, "variable_type":"file",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let mut request = make_request(
            "gitlab.set_ci_variable",
            serde_json::json!({
                "project":"group/project", "key":"TOKEN", "value_ref":format!("env:{value_var}"),
                "environment_scope":"staging", "protected":true, "masked":true, "raw":false, "variable_type":"file",
            }),
        );
        let prepared = handler.prepare(&request).unwrap();
        assert!(audit.events().is_empty());
        request.params["project"] = "group/competing".into();
        request.params["protected"] = false.into();
        request.params["environment_scope"] = "production".into();
        unsafe {
            std::env::set_var(GITLAB_TOKEN_REF_ENV, "env:UNAPPROVED_TOKEN");
        }
        let result = prepared.execute().await;
        unsafe {
            std::env::remove_var(&token_var);
            std::env::remove_var(&value_var);
            match previous_token_ref {
                Some(value) => std::env::set_var(GITLAB_TOKEN_REF_ENV, value),
                None => std::env::remove_var(GITLAB_TOKEN_REF_ENV),
            }
        }
        let result = result.unwrap();
        assert_eq!(result["project"], "group/project");
        assert_eq!(result["environment_scope"], "staging");
        assert_eq!(result["protected"], true);
        assert!(!result.to_string().contains("synthetic-variable-value"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
