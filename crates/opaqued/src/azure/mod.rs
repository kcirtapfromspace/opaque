//! Azure Key Vault integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `azure:<vault>/<secret>` or `azure:<vault>/<secret>/<version>` refs
//! - **CLI browsing** via `azure.list_secrets`, `azure.list_keys`, and `azure.list_certificates`
//! - **Write-only** via `azure.set_secret` (never returns secret values)
//!
//! Uses the Azure Key Vault REST API with Azure AD client credentials flow.
//!
//! Backend selection:
//! 1. If `OPAQUE_AZURE_VAULT_URL` is set -> use that URL directly
//! 2. Otherwise -> construct from vault name: `https://{vault-name}.vault.azure.net`
//! 3. If no Azure AD credentials configured -> disabled

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

use client::AzureKeyVaultClient;

/// The Azure Key Vault operation handler.
///
/// Handles secret/key/certificate browsing and write-only secret operations.
/// A single `AzureHandler` instance is registered for each Azure operation
/// name; it dispatches by `request.operation`.
pub struct AzureHandler {
    audit: Arc<dyn AuditSink>,
    client: AzureKeyVaultClient,
}

impl fmt::Debug for AzureHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzureHandler").finish()
    }
}

impl AzureHandler {
    /// Create a handler for the Azure Key Vault API.
    pub fn new(
        audit: Arc<dyn AuditSink>,
        base_url: &str,
        tenant_id: String,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, client::AzureApiError> {
        Ok(Self {
            audit,
            client: AzureKeyVaultClient::new(base_url, tenant_id, client_id, client_secret)?,
        })
    }

    /// Extract the secret name from a Key Vault URL id.
    ///
    /// Azure Key Vault returns IDs like `https://myvault.vault.azure.net/secrets/my-secret`.
    /// We extract just the name portion for sanitized responses.
    fn extract_name_from_id(id: &str) -> &str {
        id.rsplit('/').next().unwrap_or(id)
    }
}

impl OperationHandler for AzureHandler {
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
                "azure.list_secrets" => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=list_secrets"),
                    );

                    let secrets = self
                        .client
                        .list_secrets()
                        .await
                        .map_err(|e| format!("failed to list secrets: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("secrets_count={}", secrets.len())),
                    );

                    // Return sanitized response: names only (no values, no full URLs).
                    let sanitized: Vec<serde_json::Value> = secrets
                        .into_iter()
                        .map(|s| {
                            serde_json::json!({
                                "name": Self::extract_name_from_id(&s.id),
                                "enabled": s.attributes.as_ref().and_then(|a| a.enabled),
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({ "secrets": sanitized }))
                }
                "azure.list_keys" => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=list_keys"),
                    );

                    let keys = self
                        .client
                        .list_keys()
                        .await
                        .map_err(|e| format!("failed to list keys: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("keys_count={}", keys.len())),
                    );

                    let sanitized: Vec<serde_json::Value> = keys
                        .into_iter()
                        .map(|k| {
                            serde_json::json!({
                                "name": Self::extract_name_from_id(&k.kid),
                                "enabled": k.attributes.as_ref().and_then(|a| a.enabled),
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({ "keys": sanitized }))
                }
                "azure.list_certificates" => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=list_certificates"),
                    );

                    let certs = self
                        .client
                        .list_certificates()
                        .await
                        .map_err(|e| format!("failed to list certificates: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("certs_count={}", certs.len())),
                    );

                    let sanitized: Vec<serde_json::Value> = certs
                        .into_iter()
                        .map(|c| {
                            serde_json::json!({
                                "name": Self::extract_name_from_id(&c.id),
                                "enabled": c.attributes.as_ref().and_then(|a| a.enabled),
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({ "certificates": sanitized }))
                }
                "azure.get_secret" => {
                    let secret_name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;
                    let version = params.get("version").and_then(|v| v.as_str());

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=get_secret name={secret_name} version={}",
                                version.unwrap_or("(latest)")
                            )),
                    );

                    let secret = self
                        .client
                        .get_secret(secret_name, version)
                        .await
                        .map_err(|e| format!("failed to get secret: {e}"))?;

                    let value = secret
                        .value
                        .ok_or_else(|| format!("secret '{secret_name}' has no value"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("name={secret_name} value_len={}", value.len())),
                    );

                    Ok(serde_json::json!({
                        "name": secret_name,
                        "value": value,
                    }))
                }
                "azure.set_secret" => {
                    let secret_name = params
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'name' parameter".to_string())?;
                    let value_ref = params
                        .get("value_ref")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'value_ref' parameter".to_string())?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=set_secret name={secret_name}")),
                    );

                    // Resolve the secret value from the ref.
                    let base = crate::sandbox::resolve::BaseResolver::new();
                    let secret_value = base
                        .resolve(value_ref)
                        .map_err(|e| format!("failed to resolve value_ref '{value_ref}': {e}"))?;
                    let value_str = secret_value
                        .as_str()
                        .ok_or_else(|| "resolved value is not valid UTF-8".to_string())?;

                    let _result = self
                        .client
                        .set_secret(secret_name, value_str)
                        .await
                        .map_err(|e| format!("failed to set secret: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("name={secret_name}")),
                    );

                    // Write-only: never return the secret value.
                    Ok(serde_json::json!({
                        "name": secret_name,
                        "status": "ok",
                    }))
                }
                other => Err(format!("unknown Azure operation: {other}")),
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
        let handler = AzureHandler::new(
            audit,
            "http://localhost:8080",
            "t".into(),
            "c".into(),
            "s".into(),
        )
        .unwrap();
        let debug = format!("{handler:?}");
        assert!(debug.contains("AzureHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AzureHandler::new(
            audit,
            "http://localhost:8080",
            "t".into(),
            "c".into(),
            "s".into(),
        )
        .unwrap();
        let request = make_request("azure.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown Azure operation"));
    }

    #[tokio::test]
    async fn get_secret_missing_name_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AzureHandler::new(
            audit,
            "http://localhost:8080",
            "t".into(),
            "c".into(),
            "s".into(),
        )
        .unwrap();
        let request = make_request("azure.get_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));
    }

    #[tokio::test]
    async fn set_secret_missing_name_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AzureHandler::new(
            audit,
            "http://localhost:8080",
            "t".into(),
            "c".into(),
            "s".into(),
        )
        .unwrap();
        let request = make_request(
            "azure.set_secret",
            serde_json::json!({"value_ref": "env:X"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'name'"));
    }

    #[tokio::test]
    async fn set_secret_missing_value_ref_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = AzureHandler::new(
            audit,
            "http://localhost:8080",
            "t".into(),
            "c".into(),
            "s".into(),
        )
        .unwrap();
        let request = make_request("azure.set_secret", serde_json::json!({"name": "test"}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value_ref'"));
    }

    #[test]
    fn extract_name_from_id_full_url() {
        assert_eq!(
            AzureHandler::extract_name_from_id("https://myvault.vault.azure.net/secrets/my-secret"),
            "my-secret"
        );
    }

    #[test]
    fn extract_name_from_id_with_version() {
        assert_eq!(
            AzureHandler::extract_name_from_id(
                "https://myvault.vault.azure.net/secrets/my-secret/abc123"
            ),
            "abc123"
        );
    }

    #[test]
    fn extract_name_from_id_bare() {
        assert_eq!(
            AzureHandler::extract_name_from_id("just-a-name"),
            "just-a-name"
        );
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with OAuth mocked.
    async fn setup_handler_with_mock() -> (AzureHandler, MockServer, Arc<InMemoryAuditEmitter>) {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Mock OAuth2 token endpoint.
        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-azure-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let mut client = AzureKeyVaultClient::new(
            &mock_server.uri(),
            "test-tenant".into(),
            "test-client".into(),
            "test-secret".into(),
        )
        .unwrap();
        client.token_endpoint_override = Some(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        let handler = AzureHandler {
            audit: audit.clone(),
            client,
        };
        (handler, mock_server, audit)
    }

    #[tokio::test]
    async fn list_secrets_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer test-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "https://vault/secrets/db-password", "attributes": {"enabled": true}},
                    {"id": "https://vault/secrets/api-key", "attributes": {"enabled": false}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("azure.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        let secrets = result["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0]["name"], "db-password");
        assert_eq!(secrets[0]["enabled"], true);
        assert_eq!(secrets[1]["name"], "api-key");
        assert_eq!(secrets[1]["enabled"], false);

        // No full URLs should leak.
        assert!(secrets[0].get("id").is_none());

        // Verify audit events were emitted.
        let events = audit.events();
        assert!(events.len() >= 2);
    }

    #[tokio::test]
    async fn list_keys_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/keys"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"kid": "https://vault/keys/signing-key", "attributes": {"enabled": true}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("azure.list_keys", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        let keys = result["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["name"], "signing-key");
    }

    #[tokio::test]
    async fn list_certificates_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/certificates"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "https://vault/certificates/tls-cert", "attributes": {"enabled": true}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("azure.list_certificates", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        let certs = result["certificates"].as_array().unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0]["name"], "tls-cert");
    }

    #[tokio::test]
    async fn list_secrets_auth_failure() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("azure.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication failed"));
    }

    #[tokio::test]
    async fn list_secrets_forbidden() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("azure.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("forbidden"));
    }
}
