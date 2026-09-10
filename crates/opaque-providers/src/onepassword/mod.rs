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

mod action;
pub mod client;
pub mod op_cli;
pub mod resolve;

use std::fmt;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use opaque_core::operation_handler::{OperationHandler, PreparedOperation};

use action::OnePasswordAction;
use opaque_core::resolver::{BaseResolver, SecretResolver};

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
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Result<Self, client::ConnectApiError> {
        let connect_token_ref = std::env::var(CONNECT_TOKEN_REF_ENV)
            .unwrap_or_else(|_| DEFAULT_CONNECT_TOKEN_REF.to_owned());
        Ok(Self {
            audit,
            backend: OnePasswordBackend::ConnectServer {
                client: OnePasswordClient::new(base_url)?,
                connect_token_ref,
            },
        })
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
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let action = OnePasswordAction::parse(&request.operation, &request.params)?;
        let mut secret_refs = match &self.backend {
            OnePasswordBackend::ConnectServer {
                connect_token_ref, ..
            } => vec![connect_token_ref.clone()],
            OnePasswordBackend::Cli(_) => Vec::new(),
        };
        if matches!(self.backend, OnePasswordBackend::Cli(_)) {
            action.validate_cli_selectors()?;
        }
        if let OnePasswordAction::ReadField { vault, item, field } = &action {
            secret_refs.push(format!("onepassword:{vault}/{item}/{field}"));
        }
        let mut target = action.target();
        let backend = match &self.backend {
            OnePasswordBackend::ConnectServer { client, .. } => {
                target.insert("onepassword_backend".into(), "connect_server".into());
                target.insert("onepassword_api_url".into(), client.base_url().into());
                action::BackendBinding::ConnectServer {
                    api_url: client.base_url().into(),
                }
            }
            OnePasswordBackend::Cli(cli) => {
                target.insert("onepassword_backend".into(), "cli".into());
                target.insert("onepassword_cli_path".into(), cli.executable_path().into());
                action::BackendBinding::Cli {
                    executable: cli.executable_path().into(),
                }
            }
        };
        let action = action::BoundAction { action, backend };
        let request_id = request.request_id;
        let operation = request.operation.clone();
        let audit = self.audit.clone();

        PreparedOperation::new(action, target, secret_refs, move |action| async move {
            let action = action.action;
            match &action {
                OnePasswordAction::ListVaults {} => {
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
                OnePasswordAction::ReadField {
                    vault: vault_name,
                    item: item_name,
                    field: field_name,
                } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=read_field vault={vault_name} item={item_name} field={field_name}"
                            )),
                    );

                    let value = match &self.backend {
                        OnePasswordBackend::ConnectServer { client, .. } => {
                            let token = self.resolve_connect_token()?;
                            let vault_id = client
                                .find_vault_by_name(&token, vault_name)
                                .await
                                .map_err(|e| format!("vault lookup failed: {e}"))?;
                            let item_id = client
                                .find_item_by_title(&token, &vault_id, item_name)
                                .await
                                .map_err(|e| format!("item lookup failed: {e}"))?;
                            let item = client
                                .get_item(&token, &vault_id, &item_id)
                                .await
                                .map_err(|e| format!("failed to get item: {e}"))?;

                            item.fields
                                .iter()
                                .find(|f| f.label.as_deref() == Some(field_name))
                                .and_then(|f| f.value.clone())
                                .ok_or_else(|| {
                                    format!("field '{field_name}' not found in item '{item_name}'")
                                })?
                        }
                        OnePasswordBackend::Cli(cli) => cli
                            .read_field(vault_name, item_name, field_name)
                            .await
                            .map_err(|e| format!("failed to read field: {e}"))?,
                    };

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "vault={vault_name} item={item_name} field={field_name} value_len={}",
                                value.len()
                            )),
                    );

                    Ok(serde_json::json!({
                        "vault": vault_name,
                        "item": item_name,
                        "field": field_name,
                        "value": value,
                    }))
                }
                OnePasswordAction::ListItems { vault: vault_name } => {
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
    /// module (rather than reusing `gcp`'s copy) so `onepassword`'s tests
    /// build and run independently of whether the `gcp` feature is enabled.
    fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};

        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("onepassword test env lock poisoned")
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
    fn handler_debug_connect() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler::new(audit, "http://localhost:8080").unwrap();
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
            client: OnePasswordClient::new("http://localhost:8080").unwrap(),
            connect_token_ref: "keychain:test".into(),
        };
        assert_eq!(format!("{backend:?}"), "ConnectServer");
    }

    #[tokio::test]
    async fn unknown_operation_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler::new(audit, "http://localhost:8080").unwrap();
        let request = make_request("onepassword.unknown", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown 1Password operation"));
    }

    #[tokio::test]
    async fn list_items_missing_vault_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler::new(audit, "http://localhost:8080").unwrap();
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
    async fn setup_handler_with_mock() -> (
        std::sync::MutexGuard<'static, ()>,
        OnePasswordHandler,
        MockServer,
        Arc<InMemoryAuditEmitter>,
    ) {
        let env_guard = test_env_lock();
        let mock_server = MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());

        // Provide the connect token via env var so resolve_connect_token()
        // uses env resolver instead of keychain.
        let token_env = format!("OPAQUE_TEST_1P_TOKEN_{}", uuid::Uuid::new_v4().as_simple());
        unsafe { std::env::set_var(&token_env, "test-connect-token") };
        unsafe { std::env::set_var(CONNECT_TOKEN_REF_ENV, format!("env:{token_env}")) };

        let handler = OnePasswordHandler::new(audit.clone(), &mock_server.uri()).unwrap();
        (env_guard, handler, mock_server, audit)
    }

    /// Clean up env vars after test.
    fn cleanup_env() {
        unsafe { std::env::remove_var(CONNECT_TOKEN_REF_ENV) };
    }

    #[tokio::test]
    async fn list_vaults_via_handler() {
        let (_env_guard, handler, mock_server, audit) = setup_handler_with_mock().await;

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
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

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
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

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
    async fn read_field_via_handler() {
        let (_env_guard, handler, mock_server, audit) = setup_handler_with_mock().await;

        // Step 1: find vault by name
        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Step 2: find item by title
        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "i1", "title": "GitHub Token", "category": "LOGIN"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Step 3: get item with fields
        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items/i1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "i1",
                "title": "GitHub Token",
                "fields": [
                    {"id": "f1", "label": "username", "value": "user@example.com"},
                    {"id": "f2", "label": "password", "value": "ghp_secret123"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "onepassword.read_field",
            serde_json::json!({"vault": "Personal", "item": "GitHub Token", "field": "password"}),
        );
        let result = handler.execute(&request).await.unwrap();

        assert_eq!(result["vault"], "Personal");
        assert_eq!(result["item"], "GitHub Token");
        assert_eq!(result["field"], "password");
        assert_eq!(result["value"], "ghp_secret123");

        let events = audit.events();
        assert!(events.len() >= 2);

        cleanup_env();
    }

    #[tokio::test]
    async fn read_field_missing_params_rejected() {
        let (_env_guard, handler, _mock_server, _audit) = setup_handler_with_mock().await;

        // Missing vault
        let request = make_request(
            "onepassword.read_field",
            serde_json::json!({"item": "Token", "field": "password"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'vault'"));

        // Missing item
        let request = make_request(
            "onepassword.read_field",
            serde_json::json!({"vault": "Personal", "field": "password"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'item'"));

        // Missing field
        let request = make_request(
            "onepassword.read_field",
            serde_json::json!({"vault": "Personal", "item": "Token"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'field'"));

        cleanup_env();
    }

    #[tokio::test]
    async fn read_field_field_not_found() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "i1", "title": "Token", "category": "LOGIN"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items/i1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "i1",
                "title": "Token",
                "fields": [
                    {"id": "f1", "label": "username", "value": "user@test.com"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let request = make_request(
            "onepassword.read_field",
            serde_json::json!({"vault": "Personal", "item": "Token", "field": "nonexistent"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("field 'nonexistent' not found")
        );

        cleanup_env();
    }

    #[tokio::test]
    async fn list_items_vault_not_found() {
        let (_env_guard, handler, mock_server, _audit) = setup_handler_with_mock().await;

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

    #[test]
    fn prepared_actions_bind_exact_selectors_and_configured_credentials() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler {
            audit: audit.clone(),
            backend: OnePasswordBackend::ConnectServer {
                client: OnePasswordClient::new("http://127.0.0.1:1").unwrap(),
                connect_token_ref: "env:OPAQUE_MISSING_CANONICAL_1P_TOKEN".into(),
            },
        };
        for (operation, params, expected) in [
            (
                "onepassword.list_vaults",
                serde_json::json!({}),
                serde_json::json!({}),
            ),
            (
                "onepassword.list_items",
                serde_json::json!({"vault":"Exact Vault"}),
                serde_json::json!({"vault":"Exact Vault"}),
            ),
            (
                "onepassword.read_field",
                serde_json::json!({"vault":"Exact Vault","item":"Exact Item","field":"username"}),
                serde_json::json!({"vault":"Exact Vault","item":"Exact Item","field":"username"}),
            ),
        ] {
            let mut request = make_request(operation, params);
            request.target.insert("vault".into(), "decoy".into());
            request.secret_ref_names.push("env:DECOY".into());
            let prepared = handler.prepare(&request).unwrap();
            let mut expected = expected;
            expected["onepassword_backend"] = "connect_server".into();
            expected["onepassword_api_url"] = "http://127.0.0.1:1".into();
            assert_eq!(serde_json::to_value(prepared.target()).unwrap(), expected);
            let mut expected_refs = vec!["env:OPAQUE_MISSING_CANONICAL_1P_TOKEN".to_string()];
            if operation == "onepassword.read_field" {
                expected_refs.push("onepassword:Exact Vault/Exact Item/username".into());
            }
            assert_eq!(prepared.secret_ref_names(), expected_refs);
            assert_eq!(prepared.params()["action"], format!("{operation}.v1"));
        }
        assert!(audit.events().is_empty());
    }

    #[test]
    fn prepared_hash_payload_distinguishes_connect_endpoints_and_cli_backend() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let first = OnePasswordHandler::new(audit.clone(), "http://127.0.0.1:1").unwrap();
        let second = OnePasswordHandler::new(audit.clone(), "http://127.0.0.1:2").unwrap();
        let cli = OnePasswordHandler::from_cli(audit.clone(), OpCliClient::preparation_fixture());
        let request = make_request("onepassword.list_vaults", serde_json::json!({}));
        let first = first.prepare(&request).unwrap();
        let second = second.prepare(&request).unwrap();
        let cli = cli.prepare(&request).unwrap();
        assert_ne!(first.params(), second.params());
        assert_ne!(first.params(), cli.params());
        assert_eq!(first.params()["backend"]["api_url"], "http://127.0.0.1:1");
        assert_eq!(
            cli.params()["backend"]["executable"],
            "/opaque-fixture-not-executed"
        );
        assert_eq!(cli.target()["onepassword_backend"], "cli");
        assert_eq!(
            cli.target()["onepassword_cli_path"],
            "/opaque-fixture-not-executed"
        );
        assert!(!cli.target().contains_key("onepassword_api_url"));
        assert!(audit.events().is_empty());
    }

    #[tokio::test]
    async fn malformed_actions_fail_before_credentials_and_provider_audit() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = OnePasswordHandler::new(audit.clone(), "http://127.0.0.1:1").unwrap();
        for (operation, params) in [
            (
                "onepassword.list_vaults",
                serde_json::json!({"vault":"hidden-scope"}),
            ),
            ("onepassword.list_vaults", serde_json::Value::Null),
            ("onepassword.list_items", serde_json::json!({"vault":null})),
            ("onepassword.list_items", serde_json::json!({"vault":"   "})),
            (
                "onepassword.read_field",
                serde_json::json!({"vault":"v","item":"i","field":"f","unknown":true}),
            ),
            (
                "onepassword.read_field",
                serde_json::json!({"vault":"v","item":"i","field":"f\nredirect"}),
            ),
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

    #[test]
    fn cli_uri_components_cannot_redirect_the_prepared_field() {
        for value in ["a/b", "a?b", "a#b", "a%2fb"] {
            for key in ["vault", "item", "field"] {
                let mut params = serde_json::json!({"vault":"v","item":"i","field":"f"});
                params[key] = value.into();
                let action = OnePasswordAction::parse("onepassword.read_field", &params).unwrap();
                assert!(action.validate_cli_selectors().is_err());
            }
        }
    }

    #[tokio::test]
    async fn prepared_listing_executes_original_vault_after_request_changes() {
        let (_guard, handler, mock_server, _) = setup_handler_with_mock().await;
        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id":"v1","name":"approved"}, {"id":"v2","name":"changed"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;
        let mut request = make_request(
            "onepassword.list_items",
            serde_json::json!({"vault":"approved"}),
        );
        let prepared = handler.prepare(&request).unwrap();
        request.params["vault"] = "changed".into();
        assert_eq!(prepared.target()["vault"], "approved");
        assert_eq!(prepared.execute().await.unwrap()["vault"], "approved");
        assert_eq!(mock_server.received_requests().await.unwrap().len(), 2);
        cleanup_env();
    }

    #[test]
    fn resource_secret_name_policy_cannot_be_bypassed_by_an_allowed_service_token() {
        use opaque_core::policy::SecretNameMatch;
        for backend in [
            OnePasswordBackend::ConnectServer {
                client: OnePasswordClient::new("http://127.0.0.1:1").unwrap(),
                connect_token_ref: "env:FIXTURE_1P_AUTH".into(),
            },
            OnePasswordBackend::Cli(OpCliClient::preparation_fixture()),
        ] {
            let audit = Arc::new(InMemoryAuditEmitter::new());
            let handler = OnePasswordHandler {
                audit: audit.clone(),
                backend,
            };
            let policy = SecretNameMatch {
                patterns: vec![
                    "env:FIXTURE_1P_AUTH".into(),
                    "onepassword:allowed/item/field".into(),
                ],
            };
            let approved = make_request(
                "onepassword.read_field",
                serde_json::json!({"vault":"allowed","item":"item","field":"field"}),
            );
            let mut denied = make_request(
                "onepassword.read_field",
                serde_json::json!({"vault":"other","item":"item","field":"field"}),
            );
            denied.secret_ref_names = vec!["onepassword:allowed/item/field".into()];
            let approved = handler.prepare(&approved).unwrap();
            let denied = handler.prepare(&denied).unwrap();
            assert!(policy.matches(approved.secret_ref_names()));
            assert!(!policy.matches(denied.secret_ref_names()));
            assert!(
                approved
                    .secret_ref_names()
                    .iter()
                    .any(|name| name == "onepassword:allowed/item/field")
            );
            assert!(
                !SecretNameMatch {
                    patterns: vec!["env:FIXTURE_1P_AUTH".into()]
                }
                .matches(approved.secret_ref_names())
            );
            assert!(audit.events().is_empty());
        }
    }
}
