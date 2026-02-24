//! AWS Secrets Manager + SSM Parameter Store integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `aws-sm:<name>` and `aws-ssm:<name>` refs
//! - **CLI browsing** via `aws.list_secrets`, `aws.describe_secret`, etc.
//!
//! Uses the AWS Secrets Manager and SSM Parameter Store REST APIs with
//! credentials from the standard AWS credential chain.
//!
//! Backend selection:
//! 1. If `OPAQUE_AWS_SM_URL` is set -> use that URL
//! 2. Otherwise -> use default `https://secretsmanager.{region}.amazonaws.com`
//! 3. If no credentials are configured -> operations will fail at runtime

pub mod client;
pub mod resolve;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use crate::enclave::OperationHandler;
use crate::sandbox::resolve::SecretResolver;

use client::{AwsCredentials, AwsSecretsManagerClient};

/// The AWS Secrets Manager + SSM operation handler.
///
/// Handles secret/parameter browsing and write operations. A single
/// `AwsHandler` instance is registered for each AWS operation name;
/// it dispatches by `request.operation`.
pub struct AwsHandler {
    audit: Arc<dyn AuditSink>,
    client: AwsSecretsManagerClient,
}

impl fmt::Debug for AwsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsHandler")
            .field("region", &self.client.region())
            .finish()
    }
}

impl AwsHandler {
    /// Create a handler for AWS Secrets Manager + SSM.
    pub fn new(audit: Arc<dyn AuditSink>) -> Result<Self, client::AwsApiError> {
        Ok(Self {
            audit,
            client: AwsSecretsManagerClient::new()?,
        })
    }

    /// Create a handler with explicit base URLs (for testing).
    pub fn with_urls(
        audit: Arc<dyn AuditSink>,
        sm_url: &str,
        ssm_url: &str,
        region: &str,
    ) -> Result<Self, client::AwsApiError> {
        Ok(Self {
            audit,
            client: AwsSecretsManagerClient::with_urls(sm_url, ssm_url, region)?,
        })
    }

    /// Resolve AWS credentials from the environment.
    fn resolve_credentials(&self) -> Result<AwsCredentials, String> {
        AwsCredentials::from_env().map_err(|e| format!("failed to resolve AWS credentials: {e}"))
    }
}

impl OperationHandler for AwsHandler {
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
                "aws.list_secrets" => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=list_secrets"),
                    );

                    let credentials = self.resolve_credentials()?;
                    let secrets = self
                        .client
                        .list_secrets(&credentials)
                        .await
                        .map_err(|e| format!("failed to list secrets: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("secrets_count={}", secrets.len())),
                    );

                    // Return sanitized response: names and descriptions only.
                    let sanitized: Vec<serde_json::Value> = secrets
                        .into_iter()
                        .map(|s| {
                            serde_json::json!({
                                "name": s.name,
                                "description": s.description,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({ "secrets": sanitized }))
                }
                "aws.describe_secret" => {
                    let secret_id = params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'secret_id' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=describe_secret secret_id={secret_id}")),
                    );

                    let credentials = self.resolve_credentials()?;
                    let desc = self
                        .client
                        .describe_secret(&credentials, secret_id)
                        .await
                        .map_err(|e| format!("failed to describe secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("secret_id={secret_id}")),
                    );

                    Ok(serde_json::json!({
                        "name": desc.name,
                        "description": desc.description,
                        "last_changed_date": desc.last_changed_date,
                        "last_accessed_date": desc.last_accessed_date,
                    }))
                }
                "aws.get_secret_value" => {
                    let secret_id = params
                        .get("secret_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'secret_id' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=get_secret_value secret_id={secret_id}"
                            )),
                    );

                    let credentials = self.resolve_credentials()?;
                    let sv = self
                        .client
                        .get_secret_value(&credentials, secret_id)
                        .await
                        .map_err(|e| format!("failed to get secret value: {e}"))?;

                    let value = sv
                        .secret_string
                        .ok_or_else(|| format!("secret '{secret_id}' has no SecretString"))?;

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
                        "name": sv.name,
                        "value": value,
                    }))
                }
                "aws.put_secret_value" => {
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
                                "endpoint=put_secret_value secret_id={secret_id}"
                            )),
                    );

                    // Resolve the secret value from the ref (e.g. keychain:opaque/my-key).
                    let base = crate::sandbox::resolve::BaseResolver::new();
                    let secret_value = base
                        .resolve(value_ref)
                        .map_err(|e| format!("failed to resolve value_ref '{value_ref}': {e}"))?;
                    let value_str = secret_value
                        .as_str()
                        .ok_or_else(|| "resolved value is not valid UTF-8".to_string())?;

                    let credentials = self.resolve_credentials()?;
                    let resp = self
                        .client
                        .put_secret_value(&credentials, secret_id, value_str)
                        .await
                        .map_err(|e| format!("failed to put secret value: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("secret_id={secret_id}")),
                    );

                    Ok(serde_json::json!({
                        "secret_id": secret_id,
                        "name": resp.name,
                        "version_id": resp.version_id,
                    }))
                }
                "aws.get_parameter" => {
                    let name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=get_parameter name={name}")),
                    );

                    let credentials = self.resolve_credentials()?;
                    let param = self
                        .client
                        .get_parameter(&credentials, name)
                        .await
                        .map_err(|e| format!("failed to get parameter: {e}"))?;

                    let value = param
                        .value
                        .ok_or_else(|| format!("parameter '{name}' has no value"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("name={name} value_len={}", value.len())),
                    );

                    Ok(serde_json::json!({
                        "name": name,
                        "value": value,
                        "type": param.parameter_type,
                    }))
                }
                "aws.put_parameter" => {
                    let name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;

                    let value_ref = params
                        .get("value_ref")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'value_ref' parameter".to_string())?;

                    let param_type = params
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("SecureString");

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=put_parameter name={name} type={param_type}"
                            )),
                    );

                    // Resolve the secret value from the ref.
                    let base = crate::sandbox::resolve::BaseResolver::new();
                    let secret_value = base
                        .resolve(value_ref)
                        .map_err(|e| format!("failed to resolve value_ref '{value_ref}': {e}"))?;
                    let value_str = secret_value
                        .as_str()
                        .ok_or_else(|| "resolved value is not valid UTF-8".to_string())?;

                    let credentials = self.resolve_credentials()?;
                    let resp = self
                        .client
                        .put_parameter(&credentials, name, value_str, param_type)
                        .await
                        .map_err(|e| format!("failed to put parameter: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("name={name}")),
                    );

                    Ok(serde_json::json!({
                        "name": name,
                        "version": resp.version,
                    }))
                }
                other => Err(format!("unknown AWS operation: {other}")),
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
        let handler = AwsHandler::with_urls(
            audit,
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();
        let debug = format!("{handler:?}");
        assert!(debug.contains("AwsHandler"));
        assert!(debug.contains("us-east-1"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::with_urls(
            audit,
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();
        let request = make_request("aws.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown AWS operation"));
    }

    #[tokio::test]
    async fn describe_secret_missing_id_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::with_urls(
            audit,
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();
        let request = make_request("aws.describe_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_id'"));
    }

    #[tokio::test]
    async fn get_secret_value_missing_id_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::with_urls(
            audit,
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();
        let request = make_request("aws.get_secret_value", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_id'"));
    }

    #[tokio::test]
    async fn put_secret_value_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::with_urls(
            audit,
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();

        // Missing secret_id
        let request = make_request("aws.put_secret_value", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_id'"));

        // Missing value_ref
        let request = make_request(
            "aws.put_secret_value",
            serde_json::json!({"secret_id": "test"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value_ref'"));
    }

    #[tokio::test]
    async fn get_parameter_missing_name_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::with_urls(
            audit,
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();
        let request = make_request("aws.get_parameter", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));
    }

    #[tokio::test]
    async fn put_parameter_missing_params_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::with_urls(
            audit,
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();

        // Missing name
        let request = make_request("aws.put_parameter", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));

        // Missing value_ref
        let request = make_request("aws.put_parameter", serde_json::json!({"name": "/test"}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value_ref'"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{body_partial_json, header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with AWS credentials
    /// provided via env vars.
    async fn setup_handler_with_mock() -> (AwsHandler, MockServer, Arc<InMemoryAuditEmitter>) {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide AWS credentials via env vars.
        let key_env = format!("OPAQUE_TEST_AWS_KEY_{}", uuid::Uuid::new_v4().as_simple());
        unsafe {
            std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE");
            std::env::set_var(
                "AWS_SECRET_ACCESS_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            );
        };
        let _ = key_env; // suppress warning

        let handler = AwsHandler::with_urls(
            audit.clone(),
            &mock_server.uri(),
            &mock_server.uri(),
            "us-east-1",
        )
        .unwrap();
        (handler, mock_server, audit)
    }

    /// Clean up env vars after test.
    fn cleanup_env() {
        // Note: we leave AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY set
        // because other tests may need them. In a real test suite these
        // would use unique keys per test.
    }

    #[tokio::test]
    async fn list_secrets_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "SecretList": [
                    {"Name": "prod/db-password", "Description": "DB password"},
                    {"Name": "prod/api-key"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("aws.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        // Response should contain sanitized secrets (names and descriptions only).
        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0]["name"], "prod/db-password");
        assert_eq!(secrets[0]["description"], "DB password");
        assert_eq!(secrets[1]["name"], "prod/api-key");
        // ARN must not leak
        assert!(secrets[0].get("arn").is_none());

        // Verify audit events were emitted.
        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn describe_secret_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.DescribeSecret"))
            .and(body_partial_json(
                serde_json::json!({"SecretId": "prod/db-password"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "prod/db-password",
                "ARN": "arn:1",
                "Description": "Production DB password",
                "LastChangedDate": 1700000000.0,
                "LastAccessedDate": 1700086400.0
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.describe_secret",
            serde_json::json!({"secret_id": "prod/db-password"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["name"], "prod/db-password");
        assert_eq!(result["description"], "Production DB password");
        assert!(result["last_changed_date"].is_number());
        // ARN must not leak
        assert!(result.get("arn").is_none());

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_auth_failure() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("aws.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("access denied"));

        cleanup_env();
    }

    #[tokio::test]
    async fn describe_secret_not_found() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.DescribeSecret"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.describe_secret",
            serde_json::json!({"secret_id": "nonexistent"}),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));

        cleanup_env();
    }
}
