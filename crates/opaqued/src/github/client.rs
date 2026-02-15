//! GitHub REST API client for secrets management.
//!
//! Wraps the endpoints needed to set secrets across GitHub secret scopes:
//! - Repo Actions, Environment Actions, Codespaces (user/repo), Dependabot, Org Actions
//!
//! Uses [`SecretScope`] to generate correct endpoint paths for all variants.
//!
//! **Never** leaks raw GitHub API error bodies to callers — all errors
//! are mapped to sanitized [`GitHubApiError`] variants.

use serde::{Deserialize, Serialize};

/// GitHub API version header value.
/// See: https://docs.github.com/en/rest/about-the-rest-api/api-versions
const GITHUB_API_VERSION: &str = "2022-11-28";

/// GitHub API accept header for JSON responses.
const GITHUB_ACCEPT: &str = "application/vnd.github+json";

/// Default GitHub API base URL. Override with `OPAQUE_GITHUB_API_URL` env var
/// (useful for GitHub Enterprise Server or testing).
const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com";

/// Environment variable to override the GitHub API base URL.
const GITHUB_API_URL_ENV: &str = "OPAQUE_GITHUB_API_URL";

/// GitHub API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum GitHubApiError {
    #[error("network error communicating with GitHub API")]
    Network(#[source] reqwest::Error),

    #[error("GitHub authentication failed (check token permissions)")]
    Unauthorized,

    #[error("repository not found or insufficient permissions: {0}")]
    NotFound(String),

    #[error("GitHub API rate limit exceeded")]
    RateLimited,

    #[error("GitHub API server error")]
    ServerError,

    #[error("unexpected GitHub API response: status {0}")]
    UnexpectedStatus(u16),
}

impl GitHubApiError {
    /// Returns `true` if the error is transient and the request may succeed on retry.
    ///
    /// Transient: network issues, rate limits, server errors.
    /// Permanent: auth failure, not found, unexpected status.
    #[allow(dead_code)]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            GitHubApiError::Network(_) | GitHubApiError::RateLimited | GitHubApiError::ServerError
        )
    }
}

/// Identifies which GitHub secret scope (API endpoint family) to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretScope<'a> {
    /// `repos/{owner}/{repo}/actions/secrets`
    RepoActions { owner: &'a str, repo: &'a str },
    /// `repos/{owner}/{repo}/environments/{env}/secrets`
    EnvActions {
        owner: &'a str,
        repo: &'a str,
        environment: &'a str,
    },
    /// `user/codespaces/secrets`
    CodespacesUser,
    /// `repos/{owner}/{repo}/codespaces/secrets`
    CodespacesRepo { owner: &'a str, repo: &'a str },
    /// `repos/{owner}/{repo}/dependabot/secrets`
    Dependabot { owner: &'a str, repo: &'a str },
    /// `orgs/{org}/actions/secrets`
    OrgActions { org: &'a str },
}

impl<'a> SecretScope<'a> {
    /// Returns the API path segment for fetching the public key.
    pub fn public_key_path(&self) -> String {
        match self {
            SecretScope::RepoActions { owner, repo } => {
                format!("/repos/{owner}/{repo}/actions/secrets/public-key")
            }
            SecretScope::EnvActions {
                owner,
                repo,
                environment,
            } => {
                format!("/repos/{owner}/{repo}/environments/{environment}/secrets/public-key")
            }
            SecretScope::CodespacesUser => "/user/codespaces/secrets/public-key".into(),
            SecretScope::CodespacesRepo { owner, repo } => {
                format!("/repos/{owner}/{repo}/codespaces/secrets/public-key")
            }
            SecretScope::Dependabot { owner, repo } => {
                format!("/repos/{owner}/{repo}/dependabot/secrets/public-key")
            }
            SecretScope::OrgActions { org } => {
                format!("/orgs/{org}/actions/secrets/public-key")
            }
        }
    }

    /// Returns the API path segment for listing secrets.
    pub fn list_secrets_path(&self) -> String {
        match self {
            SecretScope::RepoActions { owner, repo } => {
                format!("/repos/{owner}/{repo}/actions/secrets")
            }
            SecretScope::EnvActions {
                owner,
                repo,
                environment,
            } => {
                format!("/repos/{owner}/{repo}/environments/{environment}/secrets")
            }
            SecretScope::CodespacesUser => "/user/codespaces/secrets".into(),
            SecretScope::CodespacesRepo { owner, repo } => {
                format!("/repos/{owner}/{repo}/codespaces/secrets")
            }
            SecretScope::Dependabot { owner, repo } => {
                format!("/repos/{owner}/{repo}/dependabot/secrets")
            }
            SecretScope::OrgActions { org } => {
                format!("/orgs/{org}/actions/secrets")
            }
        }
    }

    /// Returns the API path segment for setting (PUT) a secret.
    pub fn set_secret_path(&self, name: &str) -> String {
        match self {
            SecretScope::RepoActions { owner, repo } => {
                format!("/repos/{owner}/{repo}/actions/secrets/{name}")
            }
            SecretScope::EnvActions {
                owner,
                repo,
                environment,
            } => {
                format!("/repos/{owner}/{repo}/environments/{environment}/secrets/{name}")
            }
            SecretScope::CodespacesUser => {
                format!("/user/codespaces/secrets/{name}")
            }
            SecretScope::CodespacesRepo { owner, repo } => {
                format!("/repos/{owner}/{repo}/codespaces/secrets/{name}")
            }
            SecretScope::Dependabot { owner, repo } => {
                format!("/repos/{owner}/{repo}/dependabot/secrets/{name}")
            }
            SecretScope::OrgActions { org } => {
                format!("/orgs/{org}/actions/secrets/{name}")
            }
        }
    }

    /// Returns a human-readable target description for error messages and audit logs.
    /// Never includes secret values.
    pub fn display_target(&self) -> String {
        match self {
            SecretScope::RepoActions { owner, repo } => format!("repo={owner}/{repo}"),
            SecretScope::EnvActions {
                owner,
                repo,
                environment,
            } => format!("repo={owner}/{repo} environment={environment}"),
            SecretScope::CodespacesUser => "scope=user/codespaces".into(),
            SecretScope::CodespacesRepo { owner, repo } => {
                format!("repo={owner}/{repo} scope=codespaces")
            }
            SecretScope::Dependabot { owner, repo } => {
                format!("repo={owner}/{repo} scope=dependabot")
            }
            SecretScope::OrgActions { org } => format!("org={org}"),
        }
    }

    /// Returns the 404 context string for error messages.
    fn not_found_context(&self) -> String {
        match self {
            SecretScope::RepoActions { owner, repo }
            | SecretScope::EnvActions { owner, repo, .. }
            | SecretScope::CodespacesRepo { owner, repo }
            | SecretScope::Dependabot { owner, repo } => format!("{owner}/{repo}"),
            SecretScope::CodespacesUser => "user/codespaces".into(),
            SecretScope::OrgActions { org } => format!("org/{org}"),
        }
    }
}

/// Response from `GET .../secrets/public-key`.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicKeyResponse {
    /// The ID of the key used for encryption.
    pub key_id: String,
    /// Base64-encoded Curve25519 public key.
    pub key: String,
}

/// Response from `GET .../secrets` (list secrets).
#[derive(Debug, Clone, Deserialize)]
pub struct ListSecretsResponse {
    pub total_count: i64,
    pub secrets: Vec<SecretEntry>,
}

/// A single secret entry (name + timestamps, never the value).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretEntry {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Response variants from `PUT .../secrets/{name}`.
#[derive(Debug, Clone)]
pub enum SetSecretResponse {
    /// Secret was created (HTTP 201).
    Created,
    /// Secret was updated (HTTP 204).
    Updated,
}

/// Payload for setting a secret.
#[derive(Debug, Serialize)]
struct SetSecretPayload {
    encrypted_value: String,
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_repository_ids: Option<Vec<i64>>,
}

/// Validate that a URL uses `https://`, allowing `http://` only for localhost.
fn validate_url_scheme(url: &str) {
    if url.starts_with("https://") {
        return;
    }
    if url.starts_with("http://") {
        if let Some(host_part) = url.strip_prefix("http://") {
            let host = host_part.split('/').next().unwrap_or("");
            let host_no_port = host.split(':').next().unwrap_or("");
            if host_no_port == "localhost" || host_no_port == "127.0.0.1" {
                return;
            }
        }
        panic!(
            "insecure HTTP URL rejected: {url}. \
             Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
        );
    }
    panic!(
        "unsupported URL scheme: {url}. \
         Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
    );
}

/// GitHub REST API client for secrets.
#[derive(Debug, Clone)]
pub struct GitHubClient {
    http: reqwest::Client,
    base_url: String,
}

impl GitHubClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client. Uses `OPAQUE_GITHUB_API_URL` env var if set,
    /// otherwise defaults to `https://api.github.com`.
    ///
    /// Panics if the base URL uses `http://` for a non-localhost host.
    pub fn new() -> Self {
        let base_url =
            std::env::var(GITHUB_API_URL_ENV).unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.to_owned());

        validate_url_scheme(&base_url);

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .build()
            .expect("failed to build reqwest client");

        Self { http, base_url }
    }

    /// Create a client pointing at a custom base URL (for testing with mock servers).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn with_base_url(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .build()
            .expect("failed to build reqwest client");

        Self { http, base_url }
    }

    /// Fetch the public key for a given secret scope.
    pub async fn get_public_key_scoped(
        &self,
        token: &str,
        scope: &SecretScope<'_>,
    ) -> Result<PublicKeyResponse, GitHubApiError> {
        let url = format!("{}{}", self.base_url, scope.public_key_path());

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .header("Accept", GITHUB_ACCEPT)
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .send()
            .await
            .map_err(GitHubApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<PublicKeyResponse>()
                .await
                .map_err(GitHubApiError::Network),
            401 | 403 => Err(GitHubApiError::Unauthorized),
            404 => Err(GitHubApiError::NotFound(scope.not_found_context())),
            429 => Err(GitHubApiError::RateLimited),
            500..=599 => Err(GitHubApiError::ServerError),
            other => Err(GitHubApiError::UnexpectedStatus(other)),
        }
    }

    /// Set (create or update) a secret for a given scope.
    ///
    /// `extra_body` merges additional fields into the PUT payload (e.g.,
    /// `visibility` and `selected_repository_ids` for org/codespaces-user secrets).
    pub async fn set_secret_scoped(
        &self,
        token: &str,
        scope: &SecretScope<'_>,
        name: &str,
        encrypted_value: &str,
        key_id: &str,
        extra_body: Option<&serde_json::Value>,
    ) -> Result<SetSecretResponse, GitHubApiError> {
        let url = format!("{}{}", self.base_url, scope.set_secret_path(name));

        let visibility = extra_body
            .and_then(|v| v.get("visibility"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());

        let selected_repository_ids = extra_body
            .and_then(|v| v.get("selected_repository_ids"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect::<Vec<i64>>());

        let payload = SetSecretPayload {
            encrypted_value: encrypted_value.to_owned(),
            key_id: key_id.to_owned(),
            visibility,
            selected_repository_ids,
        };

        let resp = self
            .http
            .put(&url)
            .bearer_auth(token)
            .header("Accept", GITHUB_ACCEPT)
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .json(&payload)
            .send()
            .await
            .map_err(GitHubApiError::Network)?;

        match resp.status().as_u16() {
            201 => Ok(SetSecretResponse::Created),
            204 => Ok(SetSecretResponse::Updated),
            401 | 403 => Err(GitHubApiError::Unauthorized),
            404 => Err(GitHubApiError::NotFound(scope.not_found_context())),
            422 => Err(GitHubApiError::UnexpectedStatus(422)),
            429 => Err(GitHubApiError::RateLimited),
            500..=599 => Err(GitHubApiError::ServerError),
            other => Err(GitHubApiError::UnexpectedStatus(other)),
        }
    }

    /// List secrets for a given scope (names and timestamps only, never values).
    pub async fn list_secrets_scoped(
        &self,
        token: &str,
        scope: &SecretScope<'_>,
    ) -> Result<ListSecretsResponse, GitHubApiError> {
        let url = format!("{}{}", self.base_url, scope.list_secrets_path());

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .header("Accept", GITHUB_ACCEPT)
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .send()
            .await
            .map_err(GitHubApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<ListSecretsResponse>()
                .await
                .map_err(GitHubApiError::Network),
            401 | 403 => Err(GitHubApiError::Unauthorized),
            404 => Err(GitHubApiError::NotFound(scope.not_found_context())),
            429 => Err(GitHubApiError::RateLimited),
            500..=599 => Err(GitHubApiError::ServerError),
            other => Err(GitHubApiError::UnexpectedStatus(other)),
        }
    }

    /// Delete a secret for a given scope.
    pub async fn delete_secret_scoped(
        &self,
        token: &str,
        scope: &SecretScope<'_>,
        name: &str,
    ) -> Result<(), GitHubApiError> {
        let url = format!("{}{}", self.base_url, scope.set_secret_path(name));

        let resp = self
            .http
            .delete(&url)
            .bearer_auth(token)
            .header("Accept", GITHUB_ACCEPT)
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .send()
            .await
            .map_err(GitHubApiError::Network)?;

        match resp.status().as_u16() {
            204 => Ok(()),
            401 | 403 => Err(GitHubApiError::Unauthorized),
            404 => Err(GitHubApiError::NotFound(scope.not_found_context())),
            429 => Err(GitHubApiError::RateLimited),
            500..=599 => Err(GitHubApiError::ServerError),
            other => Err(GitHubApiError::UnexpectedStatus(other)),
        }
    }

    /// Fetch the repository's public key for encrypting secrets.
    ///
    /// Delegates to [`get_public_key_scoped`] with `SecretScope::RepoActions`.
    #[allow(dead_code)]
    pub async fn get_public_key(
        &self,
        token: &str,
        owner: &str,
        repo: &str,
    ) -> Result<PublicKeyResponse, GitHubApiError> {
        self.get_public_key_scoped(token, &SecretScope::RepoActions { owner, repo })
            .await
    }

    /// Set (create or update) a repository Actions secret.
    ///
    /// Delegates to [`set_secret_scoped`] with `SecretScope::RepoActions`.
    #[allow(dead_code)]
    pub async fn set_secret(
        &self,
        token: &str,
        owner: &str,
        repo: &str,
        name: &str,
        encrypted_value: &str,
        key_id: &str,
    ) -> Result<SetSecretResponse, GitHubApiError> {
        self.set_secret_scoped(
            token,
            &SecretScope::RepoActions { owner, repo },
            name,
            encrypted_value,
            key_id,
            None,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_errors_identified() {
        assert!(GitHubApiError::RateLimited.is_transient());
        assert!(GitHubApiError::ServerError.is_transient());
        // Permanent errors.
        assert!(!GitHubApiError::Unauthorized.is_transient());
        assert!(!GitHubApiError::NotFound("x".into()).is_transient());
        assert!(!GitHubApiError::UnexpectedStatus(422).is_transient());
    }

    #[test]
    fn github_api_error_display() {
        let err = GitHubApiError::Unauthorized;
        assert!(format!("{err}").contains("authentication failed"));

        let err = GitHubApiError::NotFound("owner/repo".into());
        assert!(format!("{err}").contains("not found"));

        let err = GitHubApiError::RateLimited;
        assert!(format!("{err}").contains("rate limit"));

        let err = GitHubApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = GitHubApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));
    }

    #[test]
    fn client_default_base_url() {
        // Remove env override if set, to test the default.
        let prev = std::env::var(super::GITHUB_API_URL_ENV).ok();
        unsafe { std::env::remove_var(super::GITHUB_API_URL_ENV) };

        let client = GitHubClient::new();
        assert_eq!(client.base_url, super::DEFAULT_GITHUB_API_URL);

        // Restore if it was set.
        if let Some(v) = prev {
            unsafe { std::env::set_var(super::GITHUB_API_URL_ENV, v) };
        }
    }

    #[test]
    fn client_respects_env_override() {
        unsafe {
            std::env::set_var(
                super::GITHUB_API_URL_ENV,
                "https://github.example.com/api/v3",
            )
        };
        let client = GitHubClient::new();
        assert_eq!(client.base_url, "https://github.example.com/api/v3");
        unsafe { std::env::remove_var(super::GITHUB_API_URL_ENV) };
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = GitHubClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
        assert!(!ua.contains("0.1") || ua == format!("opaqued/{}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn client_custom_base_url() {
        let client = GitHubClient::with_base_url("http://localhost:9999".into());
        assert_eq!(client.base_url, "http://localhost:9999");
    }

    #[test]
    fn set_secret_response_variants() {
        let created = SetSecretResponse::Created;
        let updated = SetSecretResponse::Updated;
        // Verify we can construct both variants.
        let _ = format!("{created:?}");
        let _ = format!("{updated:?}");
    }

    #[test]
    fn public_key_response_deserialize() {
        let json = r#"{"key_id":"568250167242549743","key":"dGVzdC1rZXktYmFzZTY0"}"#;
        let resp: PublicKeyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.key_id, "568250167242549743");
        assert_eq!(resp.key, "dGVzdC1rZXktYmFzZTY0");
    }

    // -----------------------------------------------------------------------
    // SecretScope path generation tests
    // -----------------------------------------------------------------------

    #[test]
    fn scope_repo_actions_paths() {
        let scope = SecretScope::RepoActions {
            owner: "myorg",
            repo: "myrepo",
        };
        assert_eq!(
            scope.public_key_path(),
            "/repos/myorg/myrepo/actions/secrets/public-key"
        );
        assert_eq!(
            scope.set_secret_path("MY_SECRET"),
            "/repos/myorg/myrepo/actions/secrets/MY_SECRET"
        );
    }

    #[test]
    fn scope_env_actions_paths() {
        let scope = SecretScope::EnvActions {
            owner: "myorg",
            repo: "myrepo",
            environment: "production",
        };
        assert_eq!(
            scope.public_key_path(),
            "/repos/myorg/myrepo/environments/production/secrets/public-key"
        );
        assert_eq!(
            scope.set_secret_path("DB_PASSWORD"),
            "/repos/myorg/myrepo/environments/production/secrets/DB_PASSWORD"
        );
    }

    #[test]
    fn scope_codespaces_user_paths() {
        let scope = SecretScope::CodespacesUser;
        assert_eq!(
            scope.public_key_path(),
            "/user/codespaces/secrets/public-key"
        );
        assert_eq!(
            scope.set_secret_path("TOKEN"),
            "/user/codespaces/secrets/TOKEN"
        );
    }

    #[test]
    fn scope_codespaces_repo_paths() {
        let scope = SecretScope::CodespacesRepo {
            owner: "myorg",
            repo: "myrepo",
        };
        assert_eq!(
            scope.public_key_path(),
            "/repos/myorg/myrepo/codespaces/secrets/public-key"
        );
        assert_eq!(
            scope.set_secret_path("API_KEY"),
            "/repos/myorg/myrepo/codespaces/secrets/API_KEY"
        );
    }

    #[test]
    fn scope_dependabot_paths() {
        let scope = SecretScope::Dependabot {
            owner: "myorg",
            repo: "myrepo",
        };
        assert_eq!(
            scope.public_key_path(),
            "/repos/myorg/myrepo/dependabot/secrets/public-key"
        );
        assert_eq!(
            scope.set_secret_path("NPM_TOKEN"),
            "/repos/myorg/myrepo/dependabot/secrets/NPM_TOKEN"
        );
    }

    #[test]
    fn scope_org_actions_paths() {
        let scope = SecretScope::OrgActions { org: "myorg" };
        assert_eq!(
            scope.public_key_path(),
            "/orgs/myorg/actions/secrets/public-key"
        );
        assert_eq!(
            scope.set_secret_path("ORG_SECRET"),
            "/orgs/myorg/actions/secrets/ORG_SECRET"
        );
    }

    #[test]
    fn scope_display_target() {
        assert_eq!(
            SecretScope::RepoActions {
                owner: "o",
                repo: "r"
            }
            .display_target(),
            "repo=o/r"
        );
        assert_eq!(
            SecretScope::EnvActions {
                owner: "o",
                repo: "r",
                environment: "prod"
            }
            .display_target(),
            "repo=o/r environment=prod"
        );
        assert_eq!(
            SecretScope::CodespacesUser.display_target(),
            "scope=user/codespaces"
        );
        assert_eq!(
            SecretScope::CodespacesRepo {
                owner: "o",
                repo: "r"
            }
            .display_target(),
            "repo=o/r scope=codespaces"
        );
        assert_eq!(
            SecretScope::Dependabot {
                owner: "o",
                repo: "r"
            }
            .display_target(),
            "repo=o/r scope=dependabot"
        );
        assert_eq!(
            SecretScope::OrgActions { org: "myorg" }.display_target(),
            "org=myorg"
        );
    }

    // -----------------------------------------------------------------------
    // list_secrets_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn scope_repo_actions_list_path() {
        let scope = SecretScope::RepoActions {
            owner: "myorg",
            repo: "myrepo",
        };
        assert_eq!(
            scope.list_secrets_path(),
            "/repos/myorg/myrepo/actions/secrets"
        );
    }

    #[test]
    fn scope_env_actions_list_path() {
        let scope = SecretScope::EnvActions {
            owner: "myorg",
            repo: "myrepo",
            environment: "prod",
        };
        assert_eq!(
            scope.list_secrets_path(),
            "/repos/myorg/myrepo/environments/prod/secrets"
        );
    }

    #[test]
    fn scope_codespaces_user_list_path() {
        assert_eq!(
            SecretScope::CodespacesUser.list_secrets_path(),
            "/user/codespaces/secrets"
        );
    }

    #[test]
    fn scope_org_actions_list_path() {
        let scope = SecretScope::OrgActions { org: "myorg" };
        assert_eq!(
            scope.list_secrets_path(),
            "/orgs/myorg/actions/secrets"
        );
    }

    // -----------------------------------------------------------------------
    // Response type tests
    // -----------------------------------------------------------------------

    #[test]
    fn list_secrets_response_deserialize() {
        let json = r#"{
            "total_count": 2,
            "secrets": [
                {"name": "MY_SECRET", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-06-01T00:00:00Z"},
                {"name": "DEPLOY_KEY", "created_at": "2024-02-01T00:00:00Z", "updated_at": "2024-07-01T00:00:00Z"}
            ]
        }"#;
        let resp: ListSecretsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.total_count, 2);
        assert_eq!(resp.secrets.len(), 2);
        assert_eq!(resp.secrets[0].name, "MY_SECRET");
        assert_eq!(resp.secrets[1].name, "DEPLOY_KEY");
    }

    #[test]
    fn secret_entry_deserialize() {
        let json = r#"{"name": "TOKEN", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-06-01T00:00:00Z"}"#;
        let entry: SecretEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.name, "TOKEN");
        assert!(!entry.created_at.is_empty());
        assert!(!entry.updated_at.is_empty());
    }

    // -----------------------------------------------------------------------
    // Integration tests for list/delete (wiremock)
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_secrets_scoped_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/myorg/myrepo/actions/secrets"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 2,
                "secrets": [
                    {"name": "DB_PASSWORD", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-06-01T00:00:00Z"},
                    {"name": "API_KEY", "created_at": "2024-02-01T00:00:00Z", "updated_at": "2024-07-01T00:00:00Z"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GitHubClient::with_base_url(mock_server.uri());
        let scope = SecretScope::RepoActions {
            owner: "myorg",
            repo: "myrepo",
        };
        let resp = client
            .list_secrets_scoped("test-token", &scope)
            .await
            .unwrap();

        assert_eq!(resp.total_count, 2);
        assert_eq!(resp.secrets.len(), 2);
        assert_eq!(resp.secrets[0].name, "DB_PASSWORD");
        assert_eq!(resp.secrets[1].name, "API_KEY");
    }

    #[tokio::test]
    async fn list_secrets_scoped_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/myorg/myrepo/actions/secrets"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GitHubClient::with_base_url(mock_server.uri());
        let scope = SecretScope::RepoActions {
            owner: "myorg",
            repo: "myrepo",
        };
        let result = client.list_secrets_scoped("bad-token", &scope).await;
        assert!(matches!(result.unwrap_err(), GitHubApiError::Unauthorized));
    }

    #[tokio::test]
    async fn delete_secret_scoped_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/repos/myorg/myrepo/actions/secrets/MY_SECRET"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GitHubClient::with_base_url(mock_server.uri());
        let scope = SecretScope::RepoActions {
            owner: "myorg",
            repo: "myrepo",
        };
        client
            .delete_secret_scoped("test-token", &scope, "MY_SECRET")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_secret_scoped_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/repos/myorg/myrepo/actions/secrets/NOPE"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GitHubClient::with_base_url(mock_server.uri());
        let scope = SecretScope::RepoActions {
            owner: "myorg",
            repo: "myrepo",
        };
        let result = client
            .delete_secret_scoped("test-token", &scope, "NOPE")
            .await;
        assert!(matches!(result.unwrap_err(), GitHubApiError::NotFound(_)));
    }

    #[test]
    fn scope_not_found_context() {
        assert_eq!(
            SecretScope::RepoActions {
                owner: "o",
                repo: "r"
            }
            .not_found_context(),
            "o/r"
        );
        assert_eq!(
            SecretScope::CodespacesUser.not_found_context(),
            "user/codespaces"
        );
        assert_eq!(
            SecretScope::OrgActions { org: "myorg" }.not_found_context(),
            "org/myorg"
        );
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://api.github.com");
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080");
        validate_url_scheme("http://127.0.0.1:9000/v1");
    }

    #[test]
    #[should_panic(expected = "insecure HTTP URL rejected")]
    fn validate_url_scheme_rejects_remote_http() {
        validate_url_scheme("http://api.github.com");
    }

    #[test]
    #[should_panic(expected = "unsupported URL scheme")]
    fn validate_url_scheme_rejects_ftp() {
        validate_url_scheme("ftp://example.com/file");
    }
}
