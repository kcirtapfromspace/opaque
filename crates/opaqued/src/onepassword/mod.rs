//! 1Password integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `onepassword:<vault>/<item>[/<field>]` refs
//! - **CLI browsing** via `onepassword.list_vaults` and `onepassword.list_items` operations
//!
//! Two backends are supported:
//! - **Connect Server** — self-hosted REST API with bearer token auth
//! - **`op` CLI** — locally installed 1Password CLI using the desktop app (Touch ID)
//!
//! Backend selection:
//! 1. If `OPAQUE_1PASSWORD_CONNECT_URL` is set → Connect Server
//! 2. If `op` CLI is found in PATH → `op` CLI
//! 3. Otherwise → disabled

pub mod client;
pub mod op_cli;
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
use op_cli::OpCliClient;

/// Default keychain ref for the 1Password Connect token.
const DEFAULT_CONNECT_TOKEN_REF: &str = "keychain:opaque/1password-connect-token";

/// Environment variable to override the default Connect token ref.
const CONNECT_TOKEN_REF_ENV: &str = "OPAQUE_1PASSWORD_TOKEN_REF";

/// Which backend the handler uses for 1Password operations.
pub enum OnePasswordBackend {
    /// Self-hosted Connect Server (REST API + bearer token).
    ConnectServer {
        client: OnePasswordClient,
        connect_token_ref: String,
    },
    /// Locally installed `op` CLI (desktop app + biometric auth).
    Cli(OpCliClient),
}

impl fmt::Debug for OnePasswordBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectServer { .. } => write!(f, "ConnectServer"),
            Self::Cli(_) => write!(f, "OpCli"),
        }
    }
}

/// The 1Password operation handler.
///
/// Handles vault/item browsing operations. A single `OnePasswordHandler`
/// instance is registered for each 1Password operation name; it dispatches
/// by `request.operation`.
pub struct OnePasswordHandler {
    audit: Arc<dyn AuditSink>,
    backend: OnePasswordBackend,
}

impl fmt::Debug for OnePasswordHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnePasswordHandler")
            .field("backend", &self.backend)
            .finish()
    }
}

impl OnePasswordHandler {
    /// Create a handler backed by the Connect Server API.
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Self {
        let connect_token_ref = std::env::var(CONNECT_TOKEN_REF_ENV)
            .unwrap_or_else(|_| DEFAULT_CONNECT_TOKEN_REF.to_owned());
        Self {
            audit,
            backend: OnePasswordBackend::ConnectServer {
                client: OnePasswordClient::new(base_url),
                connect_token_ref,
            },
        }
    }

    /// Create a handler backed by the `op` CLI.
    pub fn from_cli(audit: Arc<dyn AuditSink>, cli: OpCliClient) -> Self {
        Self {
            audit,
            backend: OnePasswordBackend::Cli(cli),
        }
    }

    /// Resolve the Connect token (only for ConnectServer backend).
    fn resolve_connect_token(&self) -> Result<String, String> {
        match &self.backend {
            OnePasswordBackend::ConnectServer {
                connect_token_ref, ..
            } => {
                let base = BaseResolver::new();
                let token_value = base
                    .resolve(connect_token_ref)
                    .map_err(|e| format!("failed to resolve 1Password connect token: {e}"))?;
                token_value
                    .as_str()
                    .map(|s| s.to_owned())
                    .ok_or_else(|| "1Password connect token is not valid UTF-8".to_string())
            }
            OnePasswordBackend::Cli(_) => {
                Err("connect token not needed for op CLI backend".to_string())
            }
        }
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
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail("endpoint=list_vaults"),
                    );

                    let vaults = match &self.backend {
                        OnePasswordBackend::ConnectServer { client, .. } => {
                            let token = self.resolve_connect_token()?;
                            client
                                .list_vaults(&token)
                                .await
                                .map_err(|e| format!("failed to list vaults: {e}"))?
                        }
                        OnePasswordBackend::Cli(cli) => cli
                            .list_vaults()
                            .await
                            .map_err(|e| format!("failed to list vaults: {e}"))?,
                    };

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

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=list_items vault={vault_name}")),
                    );

                    let items = match &self.backend {
                        OnePasswordBackend::ConnectServer { client, .. } => {
                            let token = self.resolve_connect_token()?;
                            let vault_id = client
                                .find_vault_by_name(&token, vault_name)
                                .await
                                .map_err(|e| format!("vault lookup failed: {e}"))?;
                            client
                                .list_items(&token, &vault_id)
                                .await
                                .map_err(|e| format!("failed to list items: {e}"))?
                        }
                        OnePasswordBackend::Cli(cli) => cli
                            .list_items(vault_name)
                            .await
                            .map_err(|e| format!("failed to list items: {e}"))?,
                    };

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
    fn handler_debug_connect() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler::new(audit, "http://localhost:8080");
        let debug = format!("{handler:?}");
        assert!(debug.contains("OnePasswordHandler"));
        assert!(debug.contains("ConnectServer"));
    }

    #[test]
    fn handler_debug_cli() {
        if let Ok(cli) = OpCliClient::new() {
            let audit = Arc::new(InMemoryAuditEmitter::new());
            let handler = OnePasswordHandler::from_cli(audit, cli);
            let debug = format!("{handler:?}");
            assert!(debug.contains("OnePasswordHandler"));
            assert!(debug.contains("OpCli"));
        }
    }

    #[test]
    fn backend_debug() {
        let backend = OnePasswordBackend::ConnectServer {
            client: OnePasswordClient::new("http://localhost:8080"),
            connect_token_ref: "keychain:test".into(),
        };
        assert_eq!(format!("{backend:?}"), "ConnectServer");
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

    // -----------------------------------------------------------------------
    // Integration tests using wiremock (Connect Server backend)
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Set up a handler pointing at a mock server with the connect token
    /// provided via env var.
    async fn setup_handler_with_mock() -> (OnePasswordHandler, MockServer, Arc<InMemoryAuditEmitter>)
    {
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide the connect token via env var so resolve_connect_token()
        // uses env resolver instead of keychain.
        let token_env = format!("OPAQUE_TEST_1P_TOKEN_{}", uuid::Uuid::new_v4().as_simple());
        unsafe { std::env::set_var(&token_env, "test-connect-token") };
        unsafe { std::env::set_var(CONNECT_TOKEN_REF_ENV, format!("env:{token_env}")) };

        let handler = OnePasswordHandler::new(audit.clone(), &mock_server.uri());
        (handler, mock_server, audit)
    }

    /// Clean up env vars after test.
    fn cleanup_env() {
        unsafe { std::env::remove_var(CONNECT_TOKEN_REF_ENV) };
    }

    #[tokio::test]
    async fn list_vaults_via_handler() {
        let (handler, mock_server, audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .and(header("Authorization", "Bearer test-connect-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal", "description": "My vault"},
                {"id": "v2", "name": "Shared"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("onepassword.list_vaults", serde_json::json!({}));
        let result = handler.execute(&request).await.unwrap();

        // Response should contain sanitized vaults (names only, no IDs).
        let vaults = result["vaults"].as_array().unwrap();
        assert_eq!(vaults.len(), 2);
        assert_eq!(vaults[0]["name"], "Personal");
        assert_eq!(vaults[0]["description"], "My vault");
        assert!(vaults[0].get("id").is_none()); // ID must not leak
        assert_eq!(vaults[1]["name"], "Shared");

        // Verify audit events were emitted.
        let events = audit.events();
        assert!(events.len() >= 2); // ProviderFetchStarted + ProviderFetchFinished

        cleanup_env();
    }

    #[tokio::test]
    async fn list_items_via_handler() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        // Mock list_vaults to resolve vault name → ID
        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock list_items for the resolved vault ID
        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "i1", "title": "GitHub Token", "category": "LOGIN"},
                {"id": "i2", "title": "DB Password", "category": "PASSWORD"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "onepassword.list_items",
            serde_json::json!({"vault": "Personal"}),
        );
        let result = handler.execute(&request).await.unwrap();

        // Response should contain sanitized items (titles only, no IDs).
        assert_eq!(result["vault"], "Personal");
        let items = result["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["title"], "GitHub Token");
        assert_eq!(items[0]["category"], "LOGIN");
        assert!(items[0].get("id").is_none()); // ID must not leak
        assert_eq!(items[1]["title"], "DB Password");

        cleanup_env();
    }

    #[tokio::test]
    async fn list_vaults_auth_failure() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request("onepassword.list_vaults", serde_json::json!({}));
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication failed"));

        cleanup_env();
    }

    #[tokio::test]
    async fn list_items_vault_not_found() {
        let (handler, mock_server, _audit) = setup_handler_with_mock().await;

        // Vault lookup returns empty list → vault not found
        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "onepassword.list_items",
            serde_json::json!({"vault": "Nonexistent"}),
        );
        let result = handler.execute(&request).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("vault lookup failed"));

        cleanup_env();
    }
}
