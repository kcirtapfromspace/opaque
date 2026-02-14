//! 1Password Connect Server integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `onepassword:<vault>/<item>[/<field>]` refs
//! - **CLI browsing** via `onepassword.list_vaults` and `onepassword.list_items` operations
//!
//! All API calls go through the self-hosted Connect Server using bearer token auth.

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

use client::OnePasswordClient;

/// Default keychain ref for the 1Password Connect token.
const DEFAULT_CONNECT_TOKEN_REF: &str = "keychain:opaque/1password-connect-token";

/// Environment variable to override the default Connect token ref.
const CONNECT_TOKEN_REF_ENV: &str = "OPAQUE_1PASSWORD_TOKEN_REF";

/// The 1Password operation handler.
///
/// Handles vault/item browsing operations. A single `OnePasswordHandler`
/// instance is registered for each 1Password operation name; it dispatches
/// by `request.operation`.
pub struct OnePasswordHandler {
    audit: Arc<dyn AuditSink>,
    client: OnePasswordClient,
}

impl fmt::Debug for OnePasswordHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnePasswordHandler").finish()
    }
}

impl OnePasswordHandler {
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Self {
        Self {
            audit,
            client: OnePasswordClient::new(base_url),
        }
    }

    /// Resolve the Connect token from env var override or default keychain ref.
    fn resolve_connect_token(&self) -> Result<String, String> {
        let token_ref = std::env::var(CONNECT_TOKEN_REF_ENV)
            .unwrap_or_else(|_| DEFAULT_CONNECT_TOKEN_REF.to_owned());
        let base = BaseResolver::new();
        let token_value = base
            .resolve(&token_ref)
            .map_err(|e| format!("failed to resolve 1Password connect token: {e}"))?;
        token_value
            .as_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| "1Password connect token is not valid UTF-8".to_string())
    }
}

impl OperationHandler for OnePasswordHandler {
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
                "onepassword.list_vaults" => {
                    let token = self.resolve_connect_token()?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=list_vaults"),
                    );

                    let vaults = self
                        .client
                        .list_vaults(&token)
                        .await
                        .map_err(|e| format!("failed to list vaults: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("vaults_count={}", vaults.len())),
                    );

                    // Return sanitized response: names and descriptions only (no IDs).
                    let sanitized: Vec<serde_json::Value> = vaults
                        .into_iter()
                        .map(|v| {
                            serde_json::json!({
                                "name": v.name,
                                "description": v.description,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({ "vaults": sanitized }))
                }
                "onepassword.list_items" => {
                    let vault_name = params
                        .get("vault")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "missing 'vault' parameter".to_string())?;

                    let token = self.resolve_connect_token()?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=list_items vault={vault_name}")),
                    );

                    let vault_id = self
                        .client
                        .find_vault_by_name(&token, vault_name)
                        .await
                        .map_err(|e| format!("vault lookup failed: {e}"))?;

                    let items = self
                        .client
                        .list_items(&token, &vault_id)
                        .await
                        .map_err(|e| format!("failed to list items: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!("vault={vault_name} items_count={}", items.len())),
                    );

                    // Return sanitized response: titles and categories only (no IDs).
                    let sanitized: Vec<serde_json::Value> = items
                        .into_iter()
                        .map(|i| {
                            serde_json::json!({
                                "title": i.title,
                                "category": i.category,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({ "vault": vault_name, "items": sanitized }))
                }
                other => Err(format!("unknown 1Password operation: {other}")),
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
        let handler = OnePasswordHandler::new(audit, "http://localhost:8080");
        let debug = format!("{handler:?}");
        assert!(debug.contains("OnePasswordHandler"));
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler::new(audit, "http://localhost:8080");
        let request = make_request("onepassword.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown 1Password operation"));
    }

    #[tokio::test]
    async fn list_items_missing_vault_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler::new(audit, "http://localhost:8080");
        let request = make_request("onepassword.list_items", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'vault'"));
    }
}
