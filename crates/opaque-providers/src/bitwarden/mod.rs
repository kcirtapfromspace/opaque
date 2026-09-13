//! Bitwarden Secrets Manager integration.
//!
//! Provides two capabilities:
//! - **Secret resolution** via `bitwarden:<secret-id>` or `bitwarden:<project>/<key>` refs
//! - **CLI browsing** via `bitwarden.list_projects` and `bitwarden.list_secrets` operations
//!
//! Uses the official `bws` CLI for machine-token authentication and decryption.
//! Requires an installed trusted executable and the configured machine token ref.

mod action;
pub mod client;
pub mod resolve;

use std::fmt;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use opaque_core::operation_handler::{OperationHandler, PreparedOperation};

use action::BitwardenAction;
use opaque_core::resolver::{BaseResolver, SecretResolver};

use client::BitwardenClient;
use zeroize::Zeroizing;

/// Default keychain ref for the Bitwarden access token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/bitwarden-token";

/// Environment variable to override the default Bitwarden token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_BITWARDEN_TOKEN_REF";

/// The Bitwarden Secrets Manager operation handler.
///
/// Handles project/secret browsing operations. A single `BitwardenHandler`
/// instance is registered for each Bitwarden operation name; it dispatches
/// by `request.operation`.
pub struct BitwardenHandler {
    audit: Arc<dyn AuditSink>,
    client: BitwardenClient,
    token_ref: String,
}

impl fmt::Debug for BitwardenHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenHandler")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

impl BitwardenHandler {
    /// Create a handler for the Bitwarden Secrets Manager API.
    pub fn new(audit: Arc<dyn AuditSink>, base_url: &str) -> Result<Self, String> {
        let token_ref =
            std::env::var(TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Ok(Self {
            audit,
            client: BitwardenClient::new(base_url).map_err(|e| e.to_string())?,
            token_ref,
        })
    }

    /// Resolve the Bitwarden access token.
    fn resolve_token(&self) -> Result<Zeroizing<String>, String> {
        let base = BaseResolver::new();
        let token_value = base
            .resolve(&self.token_ref)
            .map_err(|e| format!("failed to resolve Bitwarden access token: {e}"))?;
        token_value
            .as_str()
            .map(|s| Zeroizing::new(s.to_owned()))
            .ok_or_else(|| "Bitwarden access token is not valid UTF-8".to_string())
    }
}

impl OperationHandler for BitwardenHandler {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let action = BitwardenAction::parse(&request.operation, &request.params)?;
        let mut secret_refs = vec![self.token_ref.clone()];
        if let BitwardenAction::ReadSecret { secret_id } = &action {
            // Preserve the resource selector used by existing secret_names
            // policies in addition to the service-account credential ref.
            secret_refs.push(secret_id.clone());
        }
        let mut target = action.target();
        let api_url = self.client.base_url().to_owned();
        target.insert("bitwarden_api_url".into(), api_url.clone());
        let identity_url = self.client.identity_url().to_owned();
        let executable = self.client.executable_path().to_string_lossy().into_owned();
        let executable_sha256 = self.client.executable_sha256().to_owned();
        target.insert("bitwarden_identity_url".into(), identity_url.clone());
        target.insert("bitwarden_cli_sha256".into(), executable_sha256.clone());
        let action = action::BoundAction {
            action,
            api_url,
            identity_url,
            executable,
            executable_sha256,
        };
        let request_id = request.request_id;
        let operation = request.operation.clone();
        let audit = self.audit.clone();

        PreparedOperation::new(action, target, secret_refs, move |action| async move {
            let action = action.action;
            match &action {
                BitwardenAction::ListProjects {} => {
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
                BitwardenAction::ListSecrets { project } => {
                    let project_name = project.as_deref();

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!(
                                "endpoint=list_secrets project={}",
                                project_name.unwrap_or("(all)")
                            )),
                    );

                    let token = self.resolve_token()?;

                    // If project name given, resolve it to an ID first.
                    let project_id = if let Some(name) = project_name {
                        Some(
                            self.client
                                .find_project_by_name(&token, name)
                                .await
                                .map_err(|e| format!("project lookup failed: {e}"))?,
                        )
                    } else {
                        None
                    };

                    let secrets = self
                        .client
                        .list_secrets(&token, project_id.as_deref())
                        .await
                        .map_err(|e| format!("failed to list secrets: {e}"))?;

                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_outcome("ok")
                            .with_detail(format!(
                                "project={} secrets_count={}",
                                project_name.unwrap_or("(all)"),
                                secrets.len()
                            )),
                    );

                    // Return sanitized response: keys only (no IDs or values).
                    let sanitized: Vec<serde_json::Value> = secrets
                        .into_iter()
                        .map(|s| {
                            serde_json::json!({
                                "key": s.key,
                            })
                        })
                        .collect();

                    Ok(serde_json::json!({
                        "project": project_name,
                        "secrets": sanitized,
                    }))
                }
                BitwardenAction::ReadSecret { secret_id } => {
                    audit.emit(
                        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                            .with_request_id(request_id)
                            .with_operation(&operation)
                            .with_detail(format!("endpoint=read_secret secret_id={secret_id}")),
                    );

                    let token = self.resolve_token()?;
                    let mut secret = self
                        .client
                        .get_secret(&token, secret_id)
                        .await
                        .map_err(|e| format!("failed to get secret: {e}"))?;

                    let value = secret
                        .value
                        .take()
                        .ok_or_else(|| format!("secret '{secret_id}' has no value"))?;

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
                        "key": secret.key,
                        "value": value,
                    }))
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod test_support;
#[cfg(all(test, unix))]
#[path = "handler_tests.rs"]
mod tests;
