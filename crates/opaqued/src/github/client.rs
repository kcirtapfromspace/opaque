//! GitHub REST API client for Actions secrets management.
//!
//! Wraps the two endpoints needed to set a repository secret:
//! - `GET /repos/{owner}/{repo}/actions/secrets/public-key`
//! - `PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}`
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

/// Response from `GET /repos/{owner}/{repo}/actions/secrets/public-key`.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicKeyResponse {
    /// The ID of the key used for encryption.
    pub key_id: String,
    /// Base64-encoded Curve25519 public key.
    pub key: String,
}

/// Response variants from `PUT /repos/{owner}/{repo}/actions/secrets/{name}`.
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
}

/// GitHub REST API client for Actions secrets.
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
    pub fn new() -> Self {
        let base_url =
            std::env::var(GITHUB_API_URL_ENV).unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.to_owned());

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

    /// Fetch the repository's public key for encrypting secrets.
    ///
    /// `GET /repos/{owner}/{repo}/actions/secrets/public-key`
    pub async fn get_public_key(
        &self,
        token: &str,
        owner: &str,
        repo: &str,
    ) -> Result<PublicKeyResponse, GitHubApiError> {
        let url = format!(
            "{}/repos/{owner}/{repo}/actions/secrets/public-key",
            self.base_url
        );

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
            404 => Err(GitHubApiError::NotFound(format!("{owner}/{repo}"))),
            429 => Err(GitHubApiError::RateLimited),
            500..=599 => Err(GitHubApiError::ServerError),
            other => Err(GitHubApiError::UnexpectedStatus(other)),
        }
    }

    /// Set (create or update) a repository secret.
    ///
    /// `PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}`
    pub async fn set_secret(
        &self,
        token: &str,
        owner: &str,
        repo: &str,
        name: &str,
        encrypted_value: &str,
        key_id: &str,
    ) -> Result<SetSecretResponse, GitHubApiError> {
        let url = format!(
            "{}/repos/{owner}/{repo}/actions/secrets/{name}",
            self.base_url
        );

        let payload = SetSecretPayload {
            encrypted_value: encrypted_value.to_owned(),
            key_id: key_id.to_owned(),
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
            404 => Err(GitHubApiError::NotFound(format!("{owner}/{repo}"))),
            422 => Err(GitHubApiError::UnexpectedStatus(422)),
            429 => Err(GitHubApiError::RateLimited),
            500..=599 => Err(GitHubApiError::ServerError),
            other => Err(GitHubApiError::UnexpectedStatus(other)),
        }
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
}
