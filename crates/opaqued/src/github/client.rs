//! GitHub REST API client for Actions secrets management.
//!
//! Wraps the two endpoints needed to set a repository secret:
//! - `GET /repos/{owner}/{repo}/actions/secrets/public-key`
//! - `PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}`
//!
//! **Never** leaks raw GitHub API error bodies to callers — all errors
//! are mapped to sanitized [`GitHubApiError`] variants.

use serde::{Deserialize, Serialize};

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
    /// Create a new client pointing at the public GitHub API.
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent("opaqued/0.1")
            .build()
            .expect("failed to build reqwest client");

        Self {
            http,
            base_url: "https://api.github.com".into(),
        }
    }

    /// Create a client pointing at a custom base URL (for testing with mock servers).
    #[cfg(test)]
    pub fn with_base_url(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("opaqued/0.1")
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
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
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
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
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
        let client = GitHubClient::new();
        assert_eq!(client.base_url, "https://api.github.com");
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
