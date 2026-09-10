//! AWS integration.
//!
//! Provides capabilities for:
//! - **STS** — `aws.get_caller_identity`, `aws.assume_role`
//! - **Secrets Manager** — `aws.get_secret_value`, `aws.create_secret`,
//!   `aws.put_secret_value`, `aws.list_secrets`, `aws.delete_secret`
//! - **SSM Parameter Store** — `aws.get_parameter`, `aws.put_parameter`,
//!   `aws.get_parameters_by_path`, `aws.delete_parameter`
//! - **Secret resolution** via `aws:<secret-name>` or `aws:ssm:<param-name>` refs
//!
//! Production AWS support is disabled pending Signature V4. Mock use requires
//! `OPAQUE_AWS_ALLOW_INSECURE=1` and a loopback `OPAQUE_AWS_MOCK_URL`, with
//! disposable credentials supplied through the configured base resolver refs.

mod action;
pub mod client;
pub mod resolve;

use std::fmt;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use opaque_core::operation_handler::{OperationHandler, PreparedOperation};

use action::AwsAction;
use opaque_core::resolver::{BaseResolver, SecretResolver};

use client::AwsClient;

/// Default keychain ref for the AWS access key ID.
const DEFAULT_ACCESS_KEY_REF: &str = "keychain:opaque/aws-access-key-id";

/// Default keychain ref for the AWS secret access key.
const DEFAULT_SECRET_KEY_REF: &str = "keychain:opaque/aws-secret-access-key";

/// Environment variable to override the AWS access key ref.
const ACCESS_KEY_REF_ENV: &str = "OPAQUE_AWS_ACCESS_KEY_REF";

/// Environment variable to override the AWS secret key ref.
const SECRET_KEY_REF_ENV: &str = "OPAQUE_AWS_SECRET_KEY_REF";

/// The AWS operation handler.
///
/// Handles STS, Secrets Manager, and SSM Parameter Store operations.
/// A single `AwsHandler` instance is registered for each AWS operation name;
/// it dispatches by `request.operation`.
pub struct AwsHandler {
    audit: Arc<dyn AuditSink>,
    client: AwsClient,
    access_key_ref: String,
    secret_key_ref: String,
}

impl fmt::Debug for AwsHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsHandler")
            .field("access_key_ref", &self.access_key_ref)
            .field("secret_key_ref", &self.secret_key_ref)
            .finish()
    }
}

impl AwsHandler {
    /// Create a handler for the AWS APIs.
    pub fn new(audit: Arc<dyn AuditSink>, client: AwsClient) -> Self {
        let access_key_ref =
            std::env::var(ACCESS_KEY_REF_ENV).unwrap_or_else(|_| DEFAULT_ACCESS_KEY_REF.to_owned());
        let secret_key_ref =
            std::env::var(SECRET_KEY_REF_ENV).unwrap_or_else(|_| DEFAULT_SECRET_KEY_REF.to_owned());
        Self {
            audit,
            client,
            access_key_ref,
            secret_key_ref,
        }
    }

    /// Resolve the AWS access key.
    fn resolve_access_key(&self) -> Result<String, String> {
        let base = BaseResolver::new();
        let value = base
            .resolve(&self.access_key_ref)
            .map_err(|e| format!("failed to resolve AWS access key: {e}"))?;
        value
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| "AWS access key is not valid UTF-8".to_string())
    }

    /// Resolve the AWS secret access key.
    fn resolve_secret_key(&self) -> Result<String, String> {
        let base = BaseResolver::new();
        let value = base
            .resolve(&self.secret_key_ref)
            .map_err(|e| format!("failed to resolve AWS secret key: {e}"))?;
        value
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| "AWS secret key is not valid UTF-8".to_string())
    }
}

impl OperationHandler for AwsHandler {
    fn fixture_only(&self) -> bool {
        // AwsClient deliberately has no production SigV4 transport.
        true
    }

    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let action = AwsAction::parse(&request.operation, &request.params)?;
        let mut secret_refs = vec![self.access_key_ref.clone(), self.secret_key_ref.clone()];
        // Resource selectors were already part of read-operation secret_names
        // policy. Credential refs supplement that authority, never replace it.
        match &action {
            AwsAction::GetSecretValue { secret_id } => secret_refs.push(secret_id.clone()),
            AwsAction::GetParameter { name, .. } => secret_refs.push(name.clone()),
            _ => {}
        }
        let mut target = action.target();
        let api_url = self
            .client
            .endpoint_for_operation(&request.operation)
            .ok_or("unknown AWS operation")?
            .to_owned();
        let backend = "unsigned_loopback_fixture";
        target.insert("aws_backend".into(), backend.into());
        target.insert("aws_api_url".into(), api_url.clone());
        let action = action::BoundAction {
            action,
            backend,
            api_url,
        };
        let request_id = request.request_id;
        let operation = request.operation.clone();
        let audit = self.audit.clone();

        PreparedOperation::new(action, target, secret_refs, move |action| async move {
            let action = action.action;
            match &action {
                // ---------------------------------------------------------
                // STS operations
                // ---------------------------------------------------------
                AwsAction::GetCallerIdentity {} => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=GetCallerIdentity"),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    let identity = self
                        .client
                        .get_caller_identity(&access_key, &secret_key)
                        .await
                        .map_err(|e| format!("GetCallerIdentity failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("account={}", identity.account)),
                    );

                    Ok(serde_json::json!({
                        "account": identity.account,
                        "arn": identity.arn,
                        "user_id": identity.user_id,
                    }))
                }

                AwsAction::AssumeRole {
                    role_arn,
                    session_name,
                } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=AssumeRole role={role_arn}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    let creds = self
                        .client
                        .assume_role(&access_key, &secret_key, role_arn, session_name)
                        .await
                        .map_err(|e| format!("AssumeRole failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("role={role_arn} expires={}", creds.expiration)),
                    );

                    Ok(serde_json::json!({
                        "access_key_id": creds.access_key_id,
                        "secret_access_key": creds.secret_access_key,
                        "session_token": creds.session_token,
                        "expiration": creds.expiration,
                    }))
                }

                // ---------------------------------------------------------
                // Secrets Manager operations
                // ---------------------------------------------------------
                AwsAction::ListSecrets {} => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=ListSecrets"),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    let resp = self
                        .client
                        .list_secrets(&access_key, &secret_key)
                        .await
                        .map_err(|e| format!("ListSecrets failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("secrets_count={}", resp.secret_list.len())),
                    );

                    // Return sanitized: names and descriptions only (no ARNs or values).
                    let sanitized: Vec<serde_json::Value> = resp
                        .secret_list
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

                AwsAction::GetSecretValue { secret_id } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=GetSecretValue secret_id={secret_id}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    let sv = self
                        .client
                        .get_secret_value(&access_key, &secret_key, secret_id)
                        .await
                        .map_err(|e| format!("GetSecretValue failed: {e}"))?;

                    let value = sv
                        .secret_string
                        .ok_or_else(|| format!("secret '{secret_id}' has no string value"))?;

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
                        "name": sv.name,
                        "value": value,
                    }))
                }

                AwsAction::CreateSecret {
                    name,
                    value,
                    description,
                } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=CreateSecret name={name}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    let resp = self
                        .client
                        .create_secret(
                            &access_key,
                            &secret_key,
                            name,
                            value.expose(),
                            description.as_deref(),
                        )
                        .await
                        .map_err(|e| format!("CreateSecret failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("name={name}")),
                    );

                    Ok(serde_json::json!({
                        "name": resp.name,
                        "version_id": resp.version_id,
                    }))
                }

                AwsAction::PutSecretValue { secret_id, value } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=PutSecretValue secret_id={secret_id}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    self.client
                        .put_secret_value(&access_key, &secret_key, secret_id, value.expose())
                        .await
                        .map_err(|e| format!("PutSecretValue failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("secret_id={secret_id}")),
                    );

                    Ok(serde_json::json!({
                        "secret_id": secret_id,
                        "status": "updated",
                    }))
                }

                AwsAction::DeleteSecret { secret_id, .. } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=DeleteSecret secret_id={secret_id}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    self.client
                        .delete_secret(&access_key, &secret_key, secret_id)
                        .await
                        .map_err(|e| format!("DeleteSecret failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("secret_id={secret_id}")),
                    );

                    Ok(serde_json::json!({
                        "secret_id": secret_id,
                        "status": "deletion_scheduled",
                    }))
                }

                // ---------------------------------------------------------
                // SSM Parameter Store operations
                // ---------------------------------------------------------
                AwsAction::GetParameter {
                    name,
                    with_decryption,
                } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=GetParameter name={name}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    let param = self
                        .client
                        .get_parameter(&access_key, &secret_key, name, *with_decryption)
                        .await
                        .map_err(|e| format!("GetParameter failed: {e}"))?;

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
                        "name": param.name,
                        "type": param.parameter_type,
                        "value": value,
                        "version": param.version,
                    }))
                }

                AwsAction::PutParameter {
                    name,
                    value,
                    parameter_type,
                    overwrite,
                } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=PutParameter name={name}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    self.client
                        .put_parameter(
                            &access_key,
                            &secret_key,
                            name,
                            value.expose(),
                            parameter_type,
                            *overwrite,
                        )
                        .await
                        .map_err(|e| format!("PutParameter failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("name={name}")),
                    );

                    Ok(serde_json::json!({
                        "name": name,
                        "status": "created",
                    }))
                }

                AwsAction::GetParametersByPath {
                    path: path_prefix,
                    with_decryption,
                    ..
                } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=GetParametersByPath path={path_prefix}"
                            )),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    let resp = self
                        .client
                        .get_parameters_by_path(
                            &access_key,
                            &secret_key,
                            path_prefix,
                            *with_decryption,
                        )
                        .await
                        .map_err(|e| format!("GetParametersByPath failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "path={path_prefix} count={}",
                                resp.parameters.len()
                            )),
                    );

                    // Return sanitized: names and types only (no values).
                    let sanitized: Vec<serde_json::Value> = resp
                        .parameters
                        .into_iter()
                        .map(|p| {
                            serde_json::json!({
                                "name": p.name,
                                "type": p.parameter_type,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({
                        "path": path_prefix,
                        "parameters": sanitized,
                    }))
                }

                AwsAction::DeleteParameter { name } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=DeleteParameter name={name}")),
                    );

                    let access_key = self.resolve_access_key()?;
                    let secret_key = self.resolve_secret_key()?;
                    self.client
                        .delete_parameter(&access_key, &secret_key, name)
                        .await
                        .map_err(|e| format!("DeleteParameter failed: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("name={name}")),
                    );

                    Ok(serde_json::json!({
                        "name": name,
                        "status": "deleted",
                    }))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::operation::{ClientIdentity, ClientType};

    /// Serializes tests that mutate process-global env vars. Local to this
    /// module (rather than reusing `gcp`'s copy) so `aws`'s tests build and
    /// run independently of whether the `gcp` feature is enabled.
    fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};

        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("aws test env lock poisoned")
    }

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
    fn prepared_actions_pin_the_selected_service_endpoint() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::new(
            audit.clone(),
            AwsClient::new(
                "http://127.0.0.1:1",
                "http://127.0.0.1:2",
                "http://127.0.0.1:3",
            )
            .unwrap(),
        );
        let changed = AwsHandler::new(audit.clone(), AwsClient::new_single("http://127.0.0.1:4"));
        for (operation, params, expected) in [
            (
                "aws.get_caller_identity",
                serde_json::json!({}),
                "http://127.0.0.1:1",
            ),
            (
                "aws.get_secret_value",
                serde_json::json!({"secret_id":"fixture"}),
                "http://127.0.0.1:2",
            ),
            (
                "aws.get_parameter",
                serde_json::json!({"name":"fixture"}),
                "http://127.0.0.1:3",
            ),
        ] {
            let request = make_request(operation, params);
            let prepared = handler.prepare(&request).unwrap();
            assert_eq!(prepared.target()["aws_api_url"], expected);
            assert_eq!(prepared.params()["api_url"], expected);
            assert_eq!(prepared.params()["backend"], "unsigned_loopback_fixture");
            assert_ne!(
                prepared.params(),
                changed.prepare(&request).unwrap().params()
            );
        }
        assert!(audit.events().is_empty());
    }

    #[test]
    fn handler_debug() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = AwsClient::new_single("http://localhost:8080");
        let handler = AwsHandler::new(audit, client);
        let debug = format!("{handler:?}");
        assert!(debug.contains("AwsHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = AwsClient::new_single("http://localhost:8080");
        let handler = AwsHandler::new(audit, client);
        let request = make_request("aws.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown AWS operation"));
    }

    #[tokio::test]
    async fn get_secret_value_missing_id_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = AwsClient::new_single("http://localhost:8080");
        let handler = AwsHandler::new(audit, client);
        let request = make_request("aws.get_secret_value", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_id'"));
    }

    #[tokio::test]
    async fn assume_role_missing_arn_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = AwsClient::new_single("http://localhost:8080");
        let handler = AwsHandler::new(audit, client);
        let request = make_request("aws.assume_role", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'role_arn'"));
    }

    #[tokio::test]
    async fn create_secret_missing_name_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = AwsClient::new_single("http://localhost:8080");
        let handler = AwsHandler::new(audit, client);
        let request = make_request("aws.create_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));
    }

    #[tokio::test]
    async fn get_parameter_missing_name_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = AwsClient::new_single("http://localhost:8080");
        let handler = AwsHandler::new(audit, client);
        let request = make_request("aws.get_parameter", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));
    }

    #[tokio::test]
    async fn get_parameters_by_path_missing_path_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let client = AwsClient::new_single("http://localhost:8080");
        let handler = AwsHandler::new(audit, client);
        let request = make_request("aws.get_parameters_by_path", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'path'"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with credentials
    /// provided via env vars.
    async fn setup_handler_with_mock() -> (
        std::sync::MutexGuard<'static, ()>,
        AwsHandler,
        MockServer,
        Arc<InMemoryAuditEmitter>,
    ) {
        let env_guard = test_env_lock();
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide credentials via env vars so resolve_access_key/resolve_secret_key
        // use env resolver instead of keychain.
        let ak_env = format!("OPAQUE_TEST_AWS_AK_{}", uuid::Uuid::new_v4().as_simple());
        let sk_env = format!("OPAQUE_TEST_AWS_SK_{}", uuid::Uuid::new_v4().as_simple());
        unsafe { std::env::set_var(&ak_env, "AKIAIOSFODNN7EXAMPLE") };
        unsafe { std::env::set_var(&sk_env, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") };
        unsafe { std::env::set_var(ACCESS_KEY_REF_ENV, format!("env:{ak_env}")) };
        unsafe { std::env::set_var(SECRET_KEY_REF_ENV, format!("env:{sk_env}")) };

        let client = AwsClient::new_single(&mock_server.uri());
        let handler = AwsHandler::new(audit.clone(), client);
        (env_guard, handler, mock_server, audit)
    }

    /// Clean up env vars after test.
    fn cleanup_env() {
        unsafe { std::env::remove_var(ACCESS_KEY_REF_ENV) };
        unsafe { std::env::remove_var(SECRET_KEY_REF_ENV) };
    }

    #[tokio::test]
    async fn get_caller_identity_via_handler() {
        let (_env_guard, handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.GetCallerIdentity",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Account": "123456789012",
                "Arn": "arn:aws:iam::123456789012:user/test",
                "UserId": "AIDEXAMPLE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("aws.get_caller_identity", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["account"], "123456789012");
        assert_eq!(result["arn"], "arn:aws:iam::123456789012:user/test");
        assert_eq!(result["user_id"], "AIDEXAMPLE");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn assume_role_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.AssumeRole",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Credentials": {
                    "AccessKeyId": "ASIAEXAMPLE",
                    "SecretAccessKey": "newsecret",
                    "SessionToken": "FwoGZX...",
                    "Expiration": "2026-02-25T00:00:00Z"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.assume_role",
            serde_json::json!({"role_arn": "arn:aws:iam::123:role/test"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["access_key_id"], "ASIAEXAMPLE");
        assert_eq!(result["secret_access_key"], "newsecret");
        assert_eq!(result["session_token"], "FwoGZX...");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_via_handler() {
        let (_env_guard, handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "SecretList": [
                    {"Name": "prod/db", "ARN": "arn:...", "Description": "Production DB"},
                    {"Name": "prod/api-key", "ARN": "arn:..."}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("aws.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0]["name"], "prod/db");
        assert_eq!(secrets[0]["description"], "Production DB");
        // ARN must not leak
        assert!(secrets[0].get("arn").is_none());

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn get_secret_value_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.GetSecretValue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "prod/db",
                "SecretString": "supersecret",
                "VersionId": "v1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.get_secret_value",
            serde_json::json!({"secret_id": "prod/db"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["name"], "prod/db");
        assert_eq!(result["value"], "supersecret");

        cleanup_env();
    }

    #[tokio::test]
    async fn get_secret_value_not_found() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.GetSecretValue"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.get_secret_value",
            serde_json::json!({"secret_id": "missing"}),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));

        cleanup_env();
    }

    #[tokio::test]
    async fn create_secret_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.CreateSecret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "new-secret",
                "VersionId": "v1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.create_secret",
            serde_json::json!({"name": "new-secret", "value": "secret123"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["name"], "new-secret");

        cleanup_env();
    }

    #[tokio::test]
    async fn put_secret_value_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.PutSecretValue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "my-secret",
                "VersionId": "v2"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.put_secret_value",
            serde_json::json!({"secret_id": "my-secret", "value": "new-value"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["secret_id"], "my-secret");
        assert_eq!(result["status"], "updated");

        cleanup_env();
    }

    #[tokio::test]
    async fn delete_secret_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.DeleteSecret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "old-secret"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.delete_secret",
            serde_json::json!({"secret_id": "old-secret"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["status"], "deletion_scheduled");

        cleanup_env();
    }

    #[tokio::test]
    async fn get_parameter_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.GetParameter"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Parameter": {
                    "Name": "/myapp/config",
                    "Type": "SecureString",
                    "Value": "secret-config",
                    "Version": 3
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.get_parameter",
            serde_json::json!({"name": "/myapp/config"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["name"], "/myapp/config");
        assert_eq!(result["type"], "SecureString");
        assert_eq!(result["value"], "secret-config");
        assert_eq!(result["version"], 3);

        cleanup_env();
    }

    #[tokio::test]
    async fn put_parameter_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.PutParameter"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Version": 1
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.put_parameter",
            serde_json::json!({"name": "/myapp/key", "value": "val"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["name"], "/myapp/key");
        assert_eq!(result["status"], "created");

        cleanup_env();
    }

    #[tokio::test]
    async fn get_parameters_by_path_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.GetParametersByPath"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Parameters": [
                    {"Name": "/app/key1", "Type": "String", "Value": "val1"},
                    {"Name": "/app/key2", "Type": "SecureString", "Value": "val2"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.get_parameters_by_path",
            serde_json::json!({"path": "/app/"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["path"], "/app/");
        let params = result["parameters"].as_array().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0]["name"], "/app/key1");
        assert_eq!(params[0]["type"], "String");
        // Values must not leak in list response.
        assert!(params[0].get("value").is_none());

        cleanup_env();
    }

    #[tokio::test]
    async fn delete_parameter_via_handler() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.DeleteParameter"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "aws.delete_parameter",
            serde_json::json!({"name": "/myapp/old"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["status"], "deleted");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_secrets_auth_failure() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("aws.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication failed"));

        cleanup_env();
    }

    #[test]
    fn prepared_actions_bind_every_destination_and_effective_option() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler {
            audit: audit.clone(),
            client: AwsClient::new_single("http://127.0.0.1:1"),
            access_key_ref: "env:OPAQUE_MISSING_CANONICAL_AWS_AK".into(),
            secret_key_ref: "env:OPAQUE_MISSING_CANONICAL_AWS_SK".into(),
        };
        assert!(handler.fixture_only());
        for (operation, params, expected) in [
            (
                "aws.get_caller_identity",
                serde_json::json!({}),
                serde_json::json!({}),
            ),
            (
                "aws.list_secrets",
                serde_json::json!({}),
                serde_json::json!({}),
            ),
            (
                "aws.assume_role",
                serde_json::json!({"role_arn":"arn:fixture"}),
                serde_json::json!({"role_arn":"arn:fixture","session_name":"opaque-session"}),
            ),
            (
                "aws.get_secret_value",
                serde_json::json!({"secret_id":"approved"}),
                serde_json::json!({"secret_id":"approved"}),
            ),
            (
                "aws.create_secret",
                serde_json::json!({"name":"approved","value":"synthetic-fixture"}),
                serde_json::json!({"name":"approved"}),
            ),
            (
                "aws.put_secret_value",
                serde_json::json!({"secret_id":"approved","value":"synthetic-fixture"}),
                serde_json::json!({"secret_id":"approved"}),
            ),
            (
                "aws.delete_secret",
                serde_json::json!({"secret_id":"approved"}),
                serde_json::json!({"secret_id":"approved","force_delete_without_recovery":"false"}),
            ),
            (
                "aws.get_parameter",
                serde_json::json!({"name":"/approved"}),
                serde_json::json!({"name":"/approved","with_decryption":"true"}),
            ),
            (
                "aws.put_parameter",
                serde_json::json!({"name":"/approved","value":"synthetic-fixture"}),
                serde_json::json!({"name":"/approved","type":"SecureString","overwrite":"false"}),
            ),
            (
                "aws.get_parameters_by_path",
                serde_json::json!({"path":"/approved/"}),
                serde_json::json!({"path":"/approved/","with_decryption":"false","recursive":"true"}),
            ),
            (
                "aws.delete_parameter",
                serde_json::json!({"name":"/approved"}),
                serde_json::json!({"name":"/approved"}),
            ),
        ] {
            let mut request = make_request(operation, params);
            request.target.insert("name".into(), "decoy".into());
            request
                .secret_ref_names
                .push("raw-secret-must-not-bind".into());
            let prepared = handler.prepare(&request).unwrap();
            let mut expected = expected;
            expected["aws_backend"] = "unsigned_loopback_fixture".into();
            expected["aws_api_url"] = "http://127.0.0.1:1".into();
            assert_eq!(serde_json::to_value(prepared.target()).unwrap(), expected);
            let mut expected_refs = vec![
                "env:OPAQUE_MISSING_CANONICAL_AWS_AK".to_string(),
                "env:OPAQUE_MISSING_CANONICAL_AWS_SK".to_string(),
            ];
            if operation == "aws.get_secret_value" {
                expected_refs.push("approved".into());
            }
            if operation == "aws.get_parameter" {
                expected_refs.push("/approved".into());
            }
            expected_refs.sort();
            assert_eq!(prepared.secret_ref_names(), expected_refs);
            assert_eq!(prepared.params()["action"], format!("{operation}.v1"));
            assert!(!prepared.params().to_string().contains("synthetic-fixture"));
        }
        assert!(audit.events().is_empty());
    }

    #[tokio::test]
    async fn malformed_options_fail_before_credentials_and_provider_audit() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler::new(audit.clone(), AwsClient::new_single("http://127.0.0.1:1"));
        for (operation, params) in [
            ("aws.get_caller_identity", serde_json::Value::Null),
            (
                "aws.list_secrets",
                serde_json::json!({"secret_id":"hidden"}),
            ),
            (
                "aws.assume_role",
                serde_json::json!({"role_arn":"arn:fixture","session_name":1}),
            ),
            (
                "aws.create_secret",
                serde_json::json!({"name":"n","value":null}),
            ),
            (
                "aws.create_secret",
                serde_json::json!({"name":"n","value":"v","description":false}),
            ),
            (
                "aws.get_parameter",
                serde_json::json!({"name":"/n","with_decryption":"false"}),
            ),
            (
                "aws.put_parameter",
                serde_json::json!({"name":"/n","value":"v","overwrite":"true"}),
            ),
            (
                "aws.put_parameter",
                serde_json::json!({"name":"/n","value":"v","type":"unknown"}),
            ),
            (
                "aws.get_parameters_by_path",
                serde_json::json!({"path":"/n","recursive":false}),
            ),
            (
                "aws.delete_secret",
                serde_json::json!({"secret_id":"n","force_delete_without_recovery":true}),
            ),
            ("aws.delete_parameter", serde_json::json!({"name":"\n"})),
        ] {
            assert!(
                handler
                    .execute(&make_request(operation, params))
                    .await
                    .is_err()
            );
        }
        assert!(audit.events().is_empty());
    }

    #[tokio::test]
    async fn prepared_write_binds_confidential_bytes_and_executes_exact_original_options() {
        let (_guard, handler, mock_server, _) = setup_handler_with_mock().await;
        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "AmazonSSM.PutParameter"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "Name":"/approved", "Value":"original-synthetic-fixture", "Type":"String", "Overwrite":true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"Version":1})))
            .expect(1).mount(&mock_server).await;
        let mut request = make_request(
            "aws.put_parameter",
            serde_json::json!({
                "name":"/approved","value":"original-synthetic-fixture","type":"String","overwrite":true
            }),
        );
        let prepared = handler.prepare(&request).unwrap();
        let original = prepared.params().clone();
        assert!(!original.to_string().contains("original-synthetic-fixture"));
        request.params["value"] = "changed-synthetic-fixture".into();
        let changed = handler.prepare(&request).unwrap();
        assert_ne!(
            original["params"]["value_sha256"],
            changed.params()["params"]["value_sha256"]
        );
        assert_eq!(prepared.target()["overwrite"], "true");
        request.params["name"] = "/changed".into();
        request.params["overwrite"] = false.into();
        assert_eq!(prepared.execute().await.unwrap()["name"], "/approved");
        assert_eq!(mock_server.received_requests().await.unwrap().len(), 1);
        cleanup_env();
    }

    #[test]
    fn resource_secret_name_policy_keeps_secret_and_parameter_constraints() {
        use opaque_core::policy::SecretNameMatch;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AwsHandler {
            audit: audit.clone(),
            client: AwsClient::new_single("http://127.0.0.1:1"),
            access_key_ref: "env:FIXTURE_AWS_AK".into(),
            secret_key_ref: "env:FIXTURE_AWS_SK".into(),
        };
        let policy = SecretNameMatch {
            patterns: vec![
                "env:FIXTURE_AWS_AK".into(),
                "env:FIXTURE_AWS_SK".into(),
                "approved-resource".into(),
            ],
        };
        for (operation, selector) in [
            ("aws.get_secret_value", "secret_id"),
            ("aws.get_parameter", "name"),
        ] {
            let approved = handler
                .prepare(&make_request(
                    operation,
                    serde_json::json!({selector:"approved-resource"}),
                ))
                .unwrap();
            let mut request = make_request(
                operation,
                serde_json::json!({selector:"different-resource"}),
            );
            request.secret_ref_names = vec!["approved-resource".into()];
            let denied = handler.prepare(&request).unwrap();
            assert!(policy.matches(approved.secret_ref_names()));
            assert!(!policy.matches(denied.secret_ref_names()));
            assert!(
                !SecretNameMatch {
                    patterns: vec!["env:FIXTURE_AWS_AK".into(), "env:FIXTURE_AWS_SK".into()]
                }
                .matches(approved.secret_ref_names())
            );
        }
        assert!(audit.events().is_empty());
    }
}
