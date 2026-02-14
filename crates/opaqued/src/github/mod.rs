//! GitHub provider integration.
//!
//! Implements secret-setting operations across all GitHub secret scopes:
//! - `github.set_actions_secret` — repo-level and environment Actions secrets
//! - `github.set_codespaces_secret` — user-level and repo-level Codespaces secrets
//! - `github.set_dependabot_secret` — repo-level Dependabot secrets
//! - `github.set_org_secret` — org-level Actions secrets
//!
//! All scopes use the same NaCl sealed-box encryption. The handler dispatches
//! by operation name and delegates to a shared `set_secret_flow()` helper.

pub mod client;
pub mod crypto;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use opaque_core::profile::ALLOWED_REF_SCHEMES;

use crate::enclave::OperationHandler;
use crate::sandbox::resolve::{CompositeResolver, SecretResolver};

use client::{GitHubClient, SecretScope};
use crypto::encrypt_secret;

/// Default keychain ref for the GitHub PAT when not specified by the caller.
/// Override with the `OPAQUE_GITHUB_TOKEN_REF` environment variable to use a
/// different keychain entry or ref scheme for the GitHub personal access token.
const DEFAULT_GITHUB_TOKEN_REF: &str = "keychain:opaque/github-pat";

/// Environment variable to override the default GitHub PAT ref.
const GITHUB_TOKEN_REF_ENV: &str = "OPAQUE_GITHUB_TOKEN_REF";

/// The GitHub secret handler.
///
/// Handles all GitHub secret-setting operations. A single `GitHubHandler` instance
/// is registered for each operation name; it dispatches by `request.operation`.
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
    if ALLOWED_REF_SCHEMES.iter().any(|p| ref_str.starts_with(p)) {
        Ok(())
    } else {
        Err(format!(
            "value_ref must start with a known scheme ({ALLOWED_REF_SCHEMES:?}), got: '{ref_str}'"
        ))
    }
}

/// Validate a GitHub environment name.
/// Must be 1-255 chars, alphanumeric / hyphens / underscores / dots.
fn validate_environment_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("environment name must be non-empty".into());
    }
    if name.len() > 255 {
        return Err("environment name must be at most 255 characters".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(
            "environment name must contain only alphanumeric characters, hyphens, underscores, and dots".into(),
        );
    }
    Ok(())
}

/// Validate a GitHub organization name.
/// Must be 1-39 chars, alphanumeric / hyphens, cannot start/end with hyphen.
fn validate_org_name(org: &str) -> Result<(), String> {
    if org.is_empty() {
        return Err("org name must be non-empty".into());
    }
    if org.len() > 39 {
        return Err("org name must be at most 39 characters".into());
    }
    if !org.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("org name must contain only alphanumeric characters and hyphens".into());
    }
    if org.starts_with('-') || org.ends_with('-') {
        return Err("org name must not start or end with a hyphen".into());
    }
    Ok(())
}

/// Shared secret-setting flow used by all sub-handlers.
///
/// Steps: resolve secret → resolve token → audit → get public key → encrypt → PUT → audit.
/// Returns a sanitized JSON response. Never includes secret values or ciphertext.
#[allow(clippy::too_many_arguments)]
async fn set_secret_flow(
    client: &GitHubClient,
    audit: &Arc<dyn AuditSink>,
    request_id: uuid::Uuid,
    scope: &SecretScope<'_>,
    secret_name: &str,
    value_ref: &str,
    github_token_ref: &str,
    operation_name: &str,
    extra_body: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    // 1. Resolve secret value and GitHub PAT.
    let resolver = CompositeResolver::new();

    let secret_value = resolver
        .resolve(value_ref)
        .map_err(|e| format!("failed to resolve value_ref: {e}"))?;
    secret_value.mlock();

    audit.emit(
        AuditEvent::new(AuditEventKind::SecretResolved)
            .with_request_id(request_id)
            .with_operation(operation_name)
            .with_outcome("resolved")
            .with_detail(format!(
                "ref_scheme={}",
                value_ref.split(':').next().unwrap_or("unknown")
            )),
    );

    let github_token = resolver
        .resolve(github_token_ref)
        .map_err(|e| format!("failed to resolve github_token_ref: {e}"))?;
    github_token.mlock();

    let github_token_str = github_token
        .as_str()
        .ok_or_else(|| "github token is not valid UTF-8".to_string())?;

    audit.emit(
        AuditEvent::new(AuditEventKind::SecretResolved)
            .with_request_id(request_id)
            .with_operation(operation_name)
            .with_outcome("resolved")
            .with_detail("ref_scheme=github_token"),
    );

    // 2. Fetch public key for the target scope.
    audit.emit(
        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
            .with_request_id(request_id)
            .with_operation(operation_name)
            .with_detail(format!("endpoint=public_key {}", scope.display_target())),
    );

    let pk_resp = client
        .get_public_key_scoped(github_token_str, scope)
        .await
        .map_err(|e| format!("failed to get public key: {e}"))?;

    // 3. Encrypt the secret.
    let encrypted_value = encrypt_secret(secret_value.as_bytes(), &pk_resp.key)
        .map_err(|e| format!("encryption failed: {e}"))?;

    // 4. Set the secret via API.
    let set_result = client
        .set_secret_scoped(
            github_token_str,
            scope,
            secret_name,
            &encrypted_value,
            &pk_resp.key_id,
            extra_body,
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
            .with_operation(operation_name)
            .with_outcome(status)
            .with_detail(format!(
                "{} secret_name={secret_name}",
                scope.display_target()
            )),
    );

    // 5. Build sanitized response — NEVER the secret value or ciphertext.
    let mut resp = serde_json::json!({
        "status": status,
        "secret_name": secret_name,
    });

    match scope {
        SecretScope::RepoActions { owner, repo }
        | SecretScope::CodespacesRepo { owner, repo }
        | SecretScope::Dependabot { owner, repo } => {
            resp["repo"] = serde_json::Value::String(format!("{owner}/{repo}"));
        }
        SecretScope::EnvActions {
            owner,
            repo,
            environment,
        } => {
            resp["repo"] = serde_json::Value::String(format!("{owner}/{repo}"));
            resp["environment"] = serde_json::Value::String(environment.to_string());
        }
        SecretScope::CodespacesUser => {
            resp["scope"] = serde_json::Value::String("user".into());
        }
        SecretScope::OrgActions { org } => {
            resp["org"] = serde_json::Value::String(org.to_string());
        }
    }

    Ok(resp)
}

/// Resolve the GitHub token ref from params, env, or default.
fn resolve_github_token_ref(params: &serde_json::Value) -> String {
    let env_token_ref = std::env::var(GITHUB_TOKEN_REF_ENV).ok();
    params
        .get("github_token_ref")
        .and_then(|v| v.as_str())
        .or(env_token_ref.as_deref())
        .unwrap_or(DEFAULT_GITHUB_TOKEN_REF)
        .to_owned()
}

impl OperationHandler for GitHubHandler {
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
                "github.set_actions_secret" => {
                    self.handle_actions_secret(request_id, &params, &audit)
                        .await
                }
                "github.set_codespaces_secret" => {
                    self.handle_codespaces_secret(request_id, &params, &audit)
                        .await
                }
                "github.set_dependabot_secret" => {
                    self.handle_dependabot_secret(request_id, &params, &audit)
                        .await
                }
                "github.set_org_secret" => {
                    self.handle_org_secret(request_id, &params, &audit).await
                }
                "github.list_secrets" => {
                    self.handle_list_secrets(request_id, &params, &audit).await
                }
                "github.delete_secret" => {
                    self.handle_delete_secret(request_id, &params, &audit).await
                }
                other => Err(format!("unknown GitHub operation: {other}")),
            }
        })
    }
}

impl GitHubHandler {
    /// Handle `github.set_actions_secret`: repo-level or environment-level.
    async fn handle_actions_secret(
        &self,
        request_id: uuid::Uuid,
        params: &serde_json::Value,
        audit: &Arc<dyn AuditSink>,
    ) -> Result<serde_json::Value, String> {
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
        let environment = params.get("environment").and_then(|v| v.as_str());
        let github_token_ref = resolve_github_token_ref(params);

        let (owner, repo_name) = validate_repo(repo)?;
        validate_secret_name(secret_name)?;
        validate_value_ref(value_ref)?;
        validate_value_ref(&github_token_ref)?;

        let scope = if let Some(env_name) = environment {
            validate_environment_name(env_name)?;
            SecretScope::EnvActions {
                owner,
                repo: repo_name,
                environment: env_name,
            }
        } else {
            SecretScope::RepoActions {
                owner,
                repo: repo_name,
            }
        };

        set_secret_flow(
            &self.client,
            audit,
            request_id,
            &scope,
            secret_name,
            value_ref,
            &github_token_ref,
            "github.set_actions_secret",
            None,
        )
        .await
    }

    /// Handle `github.set_codespaces_secret`: user-level or repo-level.
    async fn handle_codespaces_secret(
        &self,
        request_id: uuid::Uuid,
        params: &serde_json::Value,
        audit: &Arc<dyn AuditSink>,
    ) -> Result<serde_json::Value, String> {
        let secret_name = params
            .get("secret_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'secret_name' parameter".to_string())?;
        let value_ref = params
            .get("value_ref")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'value_ref' parameter".to_string())?;
        let repo = params.get("repo").and_then(|v| v.as_str());
        let github_token_ref = resolve_github_token_ref(params);

        validate_secret_name(secret_name)?;
        validate_value_ref(value_ref)?;
        validate_value_ref(&github_token_ref)?;

        let scope = if let Some(repo_str) = repo {
            let (owner, repo_name) = validate_repo(repo_str)?;
            SecretScope::CodespacesRepo {
                owner,
                repo: repo_name,
            }
        } else {
            SecretScope::CodespacesUser
        };

        // Build extra body for user-level codespaces (selected_repository_ids).
        let extra_body = if repo.is_none() {
            params
                .get("selected_repository_ids")
                .map(|ids| serde_json::json!({ "selected_repository_ids": ids }))
        } else {
            None
        };

        set_secret_flow(
            &self.client,
            audit,
            request_id,
            &scope,
            secret_name,
            value_ref,
            &github_token_ref,
            "github.set_codespaces_secret",
            extra_body.as_ref(),
        )
        .await
    }

    /// Handle `github.set_dependabot_secret`: repo-level only.
    async fn handle_dependabot_secret(
        &self,
        request_id: uuid::Uuid,
        params: &serde_json::Value,
        audit: &Arc<dyn AuditSink>,
    ) -> Result<serde_json::Value, String> {
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
        let github_token_ref = resolve_github_token_ref(params);

        let (owner, repo_name) = validate_repo(repo)?;
        validate_secret_name(secret_name)?;
        validate_value_ref(value_ref)?;
        validate_value_ref(&github_token_ref)?;

        let scope = SecretScope::Dependabot {
            owner,
            repo: repo_name,
        };

        set_secret_flow(
            &self.client,
            audit,
            request_id,
            &scope,
            secret_name,
            value_ref,
            &github_token_ref,
            "github.set_dependabot_secret",
            None,
        )
        .await
    }

    /// Handle `github.set_org_secret`: org-level Actions secrets.
    async fn handle_org_secret(
        &self,
        request_id: uuid::Uuid,
        params: &serde_json::Value,
        audit: &Arc<dyn AuditSink>,
    ) -> Result<serde_json::Value, String> {
        let org = params
            .get("org")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'org' parameter".to_string())?;
        let secret_name = params
            .get("secret_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'secret_name' parameter".to_string())?;
        let value_ref = params
            .get("value_ref")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'value_ref' parameter".to_string())?;
        let github_token_ref = resolve_github_token_ref(params);

        validate_org_name(org)?;
        validate_secret_name(secret_name)?;
        validate_value_ref(value_ref)?;
        validate_value_ref(&github_token_ref)?;

        let scope = SecretScope::OrgActions { org };

        let visibility = params
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("private");

        // Validate visibility value.
        if !["all", "private", "selected"].contains(&visibility) {
            return Err(format!(
                "visibility must be 'all', 'private', or 'selected', got: '{visibility}'"
            ));
        }

        let mut extra = serde_json::json!({ "visibility": visibility });
        if let Some(ids) = params.get("selected_repository_ids") {
            extra["selected_repository_ids"] = ids.clone();
        }

        set_secret_flow(
            &self.client,
            audit,
            request_id,
            &scope,
            secret_name,
            value_ref,
            &github_token_ref,
            "github.set_org_secret",
            Some(&extra),
        )
        .await
    }

    /// Handle `github.list_secrets`: list secret names for any scope.
    async fn handle_list_secrets(
        &self,
        request_id: uuid::Uuid,
        params: &serde_json::Value,
        audit: &Arc<dyn AuditSink>,
    ) -> Result<serde_json::Value, String> {
        let github_token_ref = resolve_github_token_ref(params);
        validate_value_ref(&github_token_ref)?;

        let scope = parse_scope(params)?;

        let resolver = CompositeResolver::new();
        let github_token = resolver
            .resolve(&github_token_ref)
            .map_err(|e| format!("failed to resolve github_token_ref: {e}"))?;
        github_token.mlock();
        let github_token_str = github_token
            .as_str()
            .ok_or_else(|| "github token is not valid UTF-8".to_string())?;

        audit.emit(
            AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                .with_request_id(request_id)
                .with_operation("github.list_secrets")
                .with_detail(format!("endpoint=list_secrets {}", scope.display_target())),
        );

        let list_resp = self
            .client
            .list_secrets_scoped(github_token_str, &scope)
            .await
            .map_err(|e| format!("failed to list secrets: {e}"))?;

        audit.emit(
            AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                .with_request_id(request_id)
                .with_operation("github.list_secrets")
                .with_outcome("ok")
                .with_detail(format!(
                    "{} total_count={}",
                    scope.display_target(),
                    list_resp.total_count
                )),
        );

        let secrets: Vec<serde_json::Value> = list_resp
            .secrets
            .into_iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "total_count": list_resp.total_count,
            "secrets": secrets,
        }))
    }

    /// Handle `github.delete_secret`: delete a secret from any scope.
    async fn handle_delete_secret(
        &self,
        request_id: uuid::Uuid,
        params: &serde_json::Value,
        audit: &Arc<dyn AuditSink>,
    ) -> Result<serde_json::Value, String> {
        let secret_name = params
            .get("secret_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'secret_name' parameter".to_string())?;
        let github_token_ref = resolve_github_token_ref(params);

        validate_secret_name(secret_name)?;
        validate_value_ref(&github_token_ref)?;

        let scope = parse_scope(params)?;

        let resolver = CompositeResolver::new();
        let github_token = resolver
            .resolve(&github_token_ref)
            .map_err(|e| format!("failed to resolve github_token_ref: {e}"))?;
        github_token.mlock();
        let github_token_str = github_token
            .as_str()
            .ok_or_else(|| "github token is not valid UTF-8".to_string())?;

        audit.emit(
            AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                .with_request_id(request_id)
                .with_operation("github.delete_secret")
                .with_detail(format!(
                    "endpoint=delete_secret {} secret_name={secret_name}",
                    scope.display_target()
                )),
        );

        self.client
            .delete_secret_scoped(github_token_str, &scope, secret_name)
            .await
            .map_err(|e| format!("failed to delete secret: {e}"))?;

        audit.emit(
            AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                .with_request_id(request_id)
                .with_operation("github.delete_secret")
                .with_outcome("deleted")
                .with_detail(format!(
                    "{} secret_name={secret_name}",
                    scope.display_target()
                )),
        );

        let mut resp = serde_json::json!({
            "status": "deleted",
            "secret_name": secret_name,
        });

        match &scope {
            SecretScope::RepoActions { owner, repo }
            | SecretScope::CodespacesRepo { owner, repo }
            | SecretScope::Dependabot { owner, repo } => {
                resp["repo"] = serde_json::Value::String(format!("{owner}/{repo}"));
            }
            SecretScope::EnvActions {
                owner,
                repo,
                environment,
            } => {
                resp["repo"] = serde_json::Value::String(format!("{owner}/{repo}"));
                resp["environment"] = serde_json::Value::String(environment.to_string());
            }
            SecretScope::CodespacesUser => {
                resp["scope"] = serde_json::Value::String("user".into());
            }
            SecretScope::OrgActions { org } => {
                resp["org"] = serde_json::Value::String(org.to_string());
            }
        }

        Ok(resp)
    }
}

/// Parse a `SecretScope` from operation params.
///
/// The `scope` parameter determines the secret type: `"actions"` (default),
/// `"codespaces"`, `"dependabot"`, or `"org"`. Combined with `repo`, `org`,
/// and `environment` parameters to build the full scope.
fn parse_scope(params: &serde_json::Value) -> Result<SecretScope<'_>, String> {
    let scope_type = params
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("actions");

    match scope_type {
        "actions" => {
            let repo = params
                .get("repo")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing 'repo' parameter".to_string())?;
            let (owner, repo_name) = validate_repo(repo)?;

            if let Some(env_name) = params.get("environment").and_then(|v| v.as_str()) {
                validate_environment_name(env_name)?;
                Ok(SecretScope::EnvActions {
                    owner,
                    repo: repo_name,
                    environment: env_name,
                })
            } else {
                Ok(SecretScope::RepoActions {
                    owner,
                    repo: repo_name,
                })
            }
        }
        "codespaces" => {
            if let Some(repo) = params.get("repo").and_then(|v| v.as_str()) {
                let (owner, repo_name) = validate_repo(repo)?;
                Ok(SecretScope::CodespacesRepo {
                    owner,
                    repo: repo_name,
                })
            } else {
                Ok(SecretScope::CodespacesUser)
            }
        }
        "dependabot" => {
            let repo = params
                .get("repo")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing 'repo' parameter for dependabot scope".to_string())?;
            let (owner, repo_name) = validate_repo(repo)?;
            Ok(SecretScope::Dependabot {
                owner,
                repo: repo_name,
            })
        }
        "org" => {
            let org = params
                .get("org")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing 'org' parameter for org scope".to_string())?;
            validate_org_name(org)?;
            Ok(SecretScope::OrgActions { org })
        }
        other => Err(format!(
            "unknown scope '{other}': expected 'actions', 'codespaces', 'dependabot', or 'org'"
        )),
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

    // -----------------------------------------------------------------------
    // Environment name validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_environment_name_valid() {
        assert!(validate_environment_name("production").is_ok());
        assert!(validate_environment_name("staging-1").is_ok());
        assert!(validate_environment_name("test_env.v2").is_ok());
    }

    #[test]
    fn validate_environment_name_empty() {
        assert!(validate_environment_name("").is_err());
    }

    #[test]
    fn validate_environment_name_too_long() {
        let long = "a".repeat(256);
        assert!(validate_environment_name(&long).is_err());
        // 255 chars should be fine.
        let max = "a".repeat(255);
        assert!(validate_environment_name(&max).is_ok());
    }

    #[test]
    fn validate_environment_name_invalid_chars() {
        assert!(validate_environment_name("prod env").is_err());
        assert!(validate_environment_name("prod/env").is_err());
        assert!(validate_environment_name("prod@env").is_err());
    }

    // -----------------------------------------------------------------------
    // Org name validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_org_name_valid() {
        assert!(validate_org_name("myorg").is_ok());
        assert!(validate_org_name("my-org").is_ok());
        assert!(validate_org_name("org123").is_ok());
    }

    #[test]
    fn validate_org_name_empty() {
        assert!(validate_org_name("").is_err());
    }

    #[test]
    fn validate_org_name_too_long() {
        let long = "a".repeat(40);
        assert!(validate_org_name(&long).is_err());
        let max = "a".repeat(39);
        assert!(validate_org_name(&max).is_ok());
    }

    #[test]
    fn validate_org_name_invalid_chars() {
        assert!(validate_org_name("my_org").is_err());
        assert!(validate_org_name("my.org").is_err());
        assert!(validate_org_name("my org").is_err());
    }

    #[test]
    fn validate_org_name_leading_trailing_hyphen() {
        assert!(validate_org_name("-org").is_err());
        assert!(validate_org_name("org-").is_err());
    }

    // -----------------------------------------------------------------------
    // Handler tests
    // -----------------------------------------------------------------------

    #[test]
    fn github_handler_debug() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let debug = format!("{handler:?}");
        assert!(debug.contains("GitHubHandler"));
    }

    fn make_request(operation: &str, params: serde_json::Value) -> OperationRequest {
        use opaque_core::operation::{ClientIdentity, ClientType};
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

    // --- Actions secret tests ---

    #[tokio::test]
    async fn missing_repo_param_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request("github.set_actions_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'repo'"));
    }

    #[tokio::test]
    async fn missing_secret_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({"repo": "owner/repo"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_name'"));
    }

    #[tokio::test]
    async fn raw_value_ref_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({
                "repo": "owner/repo",
                "secret_name": "MY_SECRET",
                "value_ref": "raw-value-not-a-ref"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("known scheme"));
    }

    #[tokio::test]
    async fn invalid_repo_format_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({
                "repo": "noslash",
                "secret_name": "MY_SECRET",
                "value_ref": "env:MY_VAR"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("owner/repo"));
    }

    #[tokio::test]
    async fn invalid_environment_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({
                "repo": "owner/repo",
                "secret_name": "MY_SECRET",
                "value_ref": "env:MY_VAR",
                "environment": "invalid env!"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("environment name"));
    }

    // --- Codespaces secret tests ---

    #[tokio::test]
    async fn codespaces_missing_secret_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request("github.set_codespaces_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_name'"));
    }

    #[tokio::test]
    async fn codespaces_missing_value_ref_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_codespaces_secret",
            serde_json::json!({"secret_name": "MY_SECRET"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value_ref'"));
    }

    // --- Dependabot secret tests ---

    #[tokio::test]
    async fn dependabot_missing_repo_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_dependabot_secret",
            serde_json::json!({
                "secret_name": "NPM_TOKEN",
                "value_ref": "env:NPM_TOKEN"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'repo'"));
    }

    // --- Org secret tests ---

    #[tokio::test]
    async fn org_secret_missing_org_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_org_secret",
            serde_json::json!({
                "secret_name": "ORG_TOKEN",
                "value_ref": "env:TOKEN"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'org'"));
    }

    #[tokio::test]
    async fn org_secret_invalid_org_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_org_secret",
            serde_json::json!({
                "org": "-bad-org-",
                "secret_name": "MY_SECRET",
                "value_ref": "env:TOKEN"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("org name"));
    }

    #[tokio::test]
    async fn org_secret_invalid_visibility_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.set_org_secret",
            serde_json::json!({
                "org": "myorg",
                "secret_name": "MY_SECRET",
                "value_ref": "env:TOKEN",
                "visibility": "invalid"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("visibility"));
    }

    // --- Unknown operation test ---

    #[tokio::test]
    async fn unknown_operation_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request("github.unknown_op", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown GitHub operation"));
    }

    // --- parse_scope tests ---

    #[test]
    fn parse_scope_default_actions() {
        let params = serde_json::json!({"repo": "owner/repo"});
        let scope = parse_scope(&params).unwrap();
        assert_eq!(
            scope,
            SecretScope::RepoActions {
                owner: "owner",
                repo: "repo"
            }
        );
    }

    #[test]
    fn parse_scope_actions_with_environment() {
        let params = serde_json::json!({"repo": "owner/repo", "environment": "production"});
        let scope = parse_scope(&params).unwrap();
        assert_eq!(
            scope,
            SecretScope::EnvActions {
                owner: "owner",
                repo: "repo",
                environment: "production"
            }
        );
    }

    #[test]
    fn parse_scope_codespaces_user() {
        let params = serde_json::json!({"scope": "codespaces"});
        let scope = parse_scope(&params).unwrap();
        assert_eq!(scope, SecretScope::CodespacesUser);
    }

    #[test]
    fn parse_scope_codespaces_repo() {
        let params = serde_json::json!({"scope": "codespaces", "repo": "owner/repo"});
        let scope = parse_scope(&params).unwrap();
        assert_eq!(
            scope,
            SecretScope::CodespacesRepo {
                owner: "owner",
                repo: "repo"
            }
        );
    }

    #[test]
    fn parse_scope_dependabot() {
        let params = serde_json::json!({"scope": "dependabot", "repo": "owner/repo"});
        let scope = parse_scope(&params).unwrap();
        assert_eq!(
            scope,
            SecretScope::Dependabot {
                owner: "owner",
                repo: "repo"
            }
        );
    }

    #[test]
    fn parse_scope_dependabot_missing_repo() {
        let params = serde_json::json!({"scope": "dependabot"});
        assert!(parse_scope(&params).is_err());
    }

    #[test]
    fn parse_scope_org() {
        let params = serde_json::json!({"scope": "org", "org": "myorg"});
        let scope = parse_scope(&params).unwrap();
        assert_eq!(scope, SecretScope::OrgActions { org: "myorg" });
    }

    #[test]
    fn parse_scope_org_missing_org() {
        let params = serde_json::json!({"scope": "org"});
        assert!(parse_scope(&params).is_err());
    }

    #[test]
    fn parse_scope_unknown() {
        let params = serde_json::json!({"scope": "invalid"});
        assert!(parse_scope(&params).is_err());
    }

    // --- list_secrets handler tests ---

    #[tokio::test]
    async fn list_secrets_missing_repo_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request("github.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'repo'"));
    }

    #[tokio::test]
    async fn list_secrets_invalid_scope_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.list_secrets",
            serde_json::json!({"scope": "invalid"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown scope"));
    }

    // --- delete_secret handler tests ---

    #[tokio::test]
    async fn delete_secret_missing_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.delete_secret",
            serde_json::json!({"repo": "owner/repo"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_name'"));
    }

    #[tokio::test]
    async fn delete_secret_invalid_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let handler = GitHubHandler::new(audit);
        let request = make_request(
            "github.delete_secret",
            serde_json::json!({"repo": "owner/repo", "secret_name": "GITHUB_TOKEN"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("GITHUB_"));
    }
}
