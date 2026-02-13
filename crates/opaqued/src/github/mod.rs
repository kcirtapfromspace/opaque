//! GitHub provider integration.
//!
//! Implements `github.set_actions_secret` — resolves a secret ref, encrypts
//! it with the repo's public key, and sets it via the GitHub API. The CLI
//! never sees the secret value.

pub mod client;
pub mod crypto;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use crate::enclave::OperationHandler;
use crate::sandbox::resolve::{CompositeResolver, SecretResolver};

use client::GitHubClient;
use crypto::encrypt_secret;

/// Known ref schemes that are allowed as `value_ref`.
const ALLOWED_REF_PREFIXES: &[&str] = &["env:", "keychain:", "profile:"];

/// Default keychain ref for the GitHub PAT when not specified.
const DEFAULT_GITHUB_TOKEN_REF: &str = "keychain:opaque/github-pat";

/// The GitHub Actions secret handler.
///
/// Resolves a secret ref, encrypts the value with the repo's NaCl public key,
/// and sets the secret via the GitHub API. The response never contains the
/// secret value or ciphertext.
pub struct GitHubHandler {
    audit: Arc<dyn AuditSink>,
    client: GitHubClient,
}

impl fmt::Debug for GitHubHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubHandler").finish()
    }
}

impl GitHubHandler {
    pub fn new(audit: Arc<dyn AuditSink>) -> Self {
        Self {
            audit,
            client: GitHubClient::new(),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn with_client(audit: Arc<dyn AuditSink>, client: GitHubClient) -> Self {
        Self { audit, client }
    }
}

/// Validate that a repo string is in `owner/repo` format.
fn validate_repo(repo: &str) -> Result<(&str, &str), String> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| "repo must be in 'owner/repo' format".to_string())?;

    if owner.is_empty() || name.is_empty() {
        return Err("repo owner and name must be non-empty".into());
    }

    // Reject additional slashes.
    if name.contains('/') {
        return Err("repo must be in 'owner/repo' format (no extra slashes)".into());
    }

    Ok((owner, name))
}

/// Validate that a secret name matches GitHub's requirements.
fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("secret_name must be non-empty".into());
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("secret_name must contain only alphanumeric characters and underscores".into());
    }

    // GitHub requires names to not start with GITHUB_ or a digit.
    if name.starts_with("GITHUB_") {
        return Err("secret_name must not start with GITHUB_".into());
    }

    if name.starts_with(|c: char| c.is_ascii_digit()) {
        return Err("secret_name must not start with a digit".into());
    }

    Ok(())
}

/// Validate that a value_ref uses a known scheme.
fn validate_value_ref(ref_str: &str) -> Result<(), String> {
    if ALLOWED_REF_PREFIXES.iter().any(|p| ref_str.starts_with(p)) {
        Ok(())
    } else {
        Err(format!(
            "value_ref must start with a known scheme ({ALLOWED_REF_PREFIXES:?}), got: '{ref_str}'"
        ))
    }
}

impl OperationHandler for GitHubHandler {
    fn execute(
        &self,
        request: &OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + '_>> {
        let request_id = request.request_id;
        let params = request.params.clone();
        let audit = self.audit.clone();

        Box::pin(async move {
            // 1. Extract and validate params.
            let repo = params
                .get("repo")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing 'repo' parameter".to_string())?;

            let secret_name = params
                .get("secret_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing 'secret_name' parameter".to_string())?;

            let value_ref = params
                .get("value_ref")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing 'value_ref' parameter".to_string())?;

            let github_token_ref = params
                .get("github_token_ref")
                .and_then(|v| v.as_str())
                .unwrap_or(DEFAULT_GITHUB_TOKEN_REF);

            // 2. Validate inputs.
            let (owner, repo_name) = validate_repo(repo)?;
            validate_secret_name(secret_name)?;
            validate_value_ref(value_ref)?;
            validate_value_ref(github_token_ref)?;

            // 3. Resolve secret value and GitHub PAT.
            let resolver = CompositeResolver::new();

            let secret_value = resolver
                .resolve(value_ref)
                .map_err(|e| format!("failed to resolve value_ref: {e}"))?;

            audit.emit(
                AuditEvent::new(AuditEventKind::SecretResolved)
                    .with_request_id(request_id)
                    .with_operation("github.set_actions_secret")
                    .with_outcome("resolved")
                    .with_detail(format!(
                        "ref_scheme={}",
                        value_ref.split(':').next().unwrap_or("unknown")
                    )),
            );

            let github_token = resolver
                .resolve(github_token_ref)
                .map_err(|e| format!("failed to resolve github_token_ref: {e}"))?;

            let github_token_str = github_token
                .as_str()
                .ok_or_else(|| "github token is not valid UTF-8".to_string())?;

            audit.emit(
                AuditEvent::new(AuditEventKind::SecretResolved)
                    .with_request_id(request_id)
                    .with_operation("github.set_actions_secret")
                    .with_outcome("resolved")
                    .with_detail("ref_scheme=github_token"),
            );

            // 4. Fetch repo public key.
            audit.emit(
                AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                    .with_request_id(request_id)
                    .with_operation("github.set_actions_secret")
                    .with_detail(format!("endpoint=public_key repo={owner}/{repo_name}")),
            );

            let pk_resp = self
                .client
                .get_public_key(github_token_str, owner, repo_name)
                .await
                .map_err(|e| format!("failed to get repo public key: {e}"))?;

            // 5. Encrypt the secret (uses raw bytes, zeroed on drop).
            let encrypted_value = encrypt_secret(secret_value.as_bytes(), &pk_resp.key)
                .map_err(|e| format!("encryption failed: {e}"))?;

            // 6. Set the secret via API.
            let set_result = self
                .client
                .set_secret(
                    github_token_str,
                    owner,
                    repo_name,
                    secret_name,
                    &encrypted_value,
                    &pk_resp.key_id,
                )
                .await
                .map_err(|e| format!("failed to set secret: {e}"))?;

            let status = match set_result {
                client::SetSecretResponse::Created => "created",
                client::SetSecretResponse::Updated => "updated",
            };

            audit.emit(
                AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                    .with_request_id(request_id)
                    .with_operation("github.set_actions_secret")
                    .with_outcome(status)
                    .with_detail(format!(
                        "repo={owner}/{repo_name} secret_name={secret_name}"
                    )),
            );

            // 7. Return sanitized result — NEVER the secret value or ciphertext.
            Ok(serde_json::json!({
                "status": status,
                "repo": format!("{owner}/{repo_name}"),
                "secret_name": secret_name,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_repo_valid() {
        let (owner, name) = validate_repo("myorg/myrepo").unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(name, "myrepo");
    }

    #[test]
    fn validate_repo_no_slash() {
        assert!(validate_repo("noslash").is_err());
    }

    #[test]
    fn validate_repo_empty_parts() {
        assert!(validate_repo("/repo").is_err());
        assert!(validate_repo("owner/").is_err());
    }

    #[test]
    fn validate_repo_extra_slashes() {
        assert!(validate_repo("owner/repo/extra").is_err());
    }

    #[test]
    fn validate_secret_name_valid() {
        assert!(validate_secret_name("MY_SECRET").is_ok());
        assert!(validate_secret_name("AWS_ACCESS_KEY_ID").is_ok());
        assert!(validate_secret_name("token").is_ok());
    }

    #[test]
    fn validate_secret_name_empty() {
        assert!(validate_secret_name("").is_err());
    }

    #[test]
    fn validate_secret_name_invalid_chars() {
        assert!(validate_secret_name("my-secret").is_err());
        assert!(validate_secret_name("my.secret").is_err());
        assert!(validate_secret_name("my secret").is_err());
    }

    #[test]
    fn validate_secret_name_github_prefix() {
        assert!(validate_secret_name("GITHUB_TOKEN").is_err());
    }

    #[test]
    fn validate_secret_name_digit_prefix() {
        assert!(validate_secret_name("1SECRET").is_err());
    }

    #[test]
    fn validate_value_ref_valid() {
        assert!(validate_value_ref("env:MY_VAR").is_ok());
        assert!(validate_value_ref("keychain:opaque/my-token").is_ok());
        assert!(validate_value_ref("profile:prod:AWS_KEY").is_ok());
    }

    #[test]
    fn validate_value_ref_invalid() {
        assert!(validate_value_ref("literal:foo").is_err());
        assert!(validate_value_ref("raw-value").is_err());
        assert!(validate_value_ref("").is_err());
    }

    #[test]
    fn github_handler_debug() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let debug = format!("{handler:?}");
        assert!(debug.contains("GitHubHandler"));
    }

    #[tokio::test]
    async fn missing_repo_param_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        use opaque_core::operation::{ClientIdentity, ClientType};

        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);

        let request = OperationRequest {
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
            operation: "github.set_actions_secret".into(),
            target: std::collections::HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({}),
            workspace: None,
        };

        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'repo'"));
    }

    #[tokio::test]
    async fn missing_secret_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        use opaque_core::operation::{ClientIdentity, ClientType};

        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);

        let request = OperationRequest {
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
            operation: "github.set_actions_secret".into(),
            target: std::collections::HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({"repo": "owner/repo"}),
            workspace: None,
        };

        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_name'"));
    }

    #[tokio::test]
    async fn raw_value_ref_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        use opaque_core::operation::{ClientIdentity, ClientType};

        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);

        let request = OperationRequest {
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
            operation: "github.set_actions_secret".into(),
            target: std::collections::HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({
                "repo": "owner/repo",
                "secret_name": "MY_SECRET",
                "value_ref": "raw-value-not-a-ref"
            }),
            workspace: None,
        };

        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("known scheme"));
    }

    #[tokio::test]
    async fn invalid_repo_format_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        use opaque_core::operation::{ClientIdentity, ClientType};

        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);

        let request = OperationRequest {
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
            operation: "github.set_actions_secret".into(),
            target: std::collections::HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({
                "repo": "noslash",
                "secret_name": "MY_SECRET",
                "value_ref": "env:MY_VAR"
            }),
            workspace: None,
        };

        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("owner/repo"));
    }
}
