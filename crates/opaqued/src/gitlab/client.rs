//! GitLab REST API client for CI/CD variables.
//!
//! Supports `gitlab.set_ci_variable` by upserting project-level CI variables:
//! - `PUT /projects/:id/variables/:key` (update path)
//! - fallback `POST /projects/:id/variables` (create path)
//!
//! Raw provider bodies are never surfaced to callers.

use serde::Serialize;

/// Default GitLab API base URL.
pub const DEFAULT_BASE_URL: &str = "https://gitlab.com/api/v4";

/// Environment variable to override the GitLab API base URL.
pub const GITLAB_API_URL_ENV: &str = "OPAQUE_GITLAB_API_URL";

/// GitLab API error types. Raw API responses are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum GitLabApiError {
    #[error("network error communicating with GitLab API")]
    Network(#[source] reqwest::Error),

    #[error("GitLab authentication failed (check token permissions)")]
    Unauthorized,

    #[error("GitLab resource not found: {0}")]
    NotFound(String),

    #[error("GitLab API rate limit exceeded")]
    RateLimited,

    #[error("GitLab API server error")]
    ServerError,

    #[error("unexpected GitLab API response: status {0}")]
    UnexpectedStatus(u16),
}

impl GitLabApiError {
    /// Returns `true` if retrying may succeed.
    #[allow(dead_code)]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            GitLabApiError::Network(_) | GitLabApiError::RateLimited | GitLabApiError::ServerError
        )
    }
}

/// Result of set/update operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetCiVariableResponse {
    Created,
    Updated,
}

/// Optional variable attributes for upsert calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetCiVariableOptions<'a> {
    pub environment_scope: Option<&'a str>,
    pub protected: Option<bool>,
    pub masked: Option<bool>,
    pub raw: Option<bool>,
    pub variable_type: Option<&'a str>,
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

/// Percent-encode a single URL path component.
fn percent_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        let safe = b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit((b & 0x0F) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

#[derive(Debug, Serialize)]
struct UpdateVariablePayload<'a> {
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment_scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    masked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variable_type: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct CreateVariablePayload<'a> {
    key: &'a str,
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment_scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    masked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    variable_type: Option<&'a str>,
}

/// GitLab REST API client.
#[derive(Debug, Clone)]
pub struct GitLabClient {
    http: reqwest::Client,
    base_url: String,
}

impl GitLabClient {
    /// Build the user-agent string from crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a client with env-configured or default base URL.
    pub fn new() -> Self {
        let base_url =
            std::env::var(GITLAB_API_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        validate_url_scheme(&base_url);

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .build()
            .expect("failed to build reqwest client");

        Self { http, base_url }
    }

    /// Create a client at custom base URL (for tests).
    #[cfg(test)]
    pub fn with_base_url(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .build()
            .expect("failed to build reqwest client");
        Self { http, base_url }
    }

    /// Upsert a GitLab CI/CD variable.
    ///
    /// First tries update (`PUT`). If variable is missing (`404`), falls back
    /// to create (`POST`).
    pub async fn set_ci_variable(
        &self,
        token: &str,
        project: &str,
        key: &str,
        value: &str,
        options: SetCiVariableOptions<'_>,
    ) -> Result<SetCiVariableResponse, GitLabApiError> {
        let project_encoded = percent_encode_component(project);
        let key_encoded = percent_encode_component(key);

        let update_url = format!(
            "{}/projects/{}/variables/{}",
            self.base_url, project_encoded, key_encoded
        );
        let update_payload = UpdateVariablePayload {
            value,
            environment_scope: options.environment_scope,
            protected: options.protected,
            masked: options.masked,
            raw: options.raw,
            variable_type: options.variable_type,
        };

        let update_resp = self
            .http
            .put(&update_url)
            .header("PRIVATE-TOKEN", token)
            .header("Accept", "application/json")
            .json(&update_payload)
            .send()
            .await
            .map_err(GitLabApiError::Network)?;

        match update_resp.status().as_u16() {
            200 | 201 => return Ok(SetCiVariableResponse::Updated),
            401 | 403 => return Err(GitLabApiError::Unauthorized),
            429 => return Err(GitLabApiError::RateLimited),
            500..=599 => return Err(GitLabApiError::ServerError),
            404 => {
                // Variable missing or project missing — try create next.
            }
            other => return Err(GitLabApiError::UnexpectedStatus(other)),
        }

        let create_url = format!("{}/projects/{}/variables", self.base_url, project_encoded);
        let create_payload = CreateVariablePayload {
            key,
            value,
            environment_scope: options.environment_scope,
            protected: options.protected,
            masked: options.masked,
            raw: options.raw,
            variable_type: options.variable_type,
        };

        let create_resp = self
            .http
            .post(&create_url)
            .header("PRIVATE-TOKEN", token)
            .header("Accept", "application/json")
            .json(&create_payload)
            .send()
            .await
            .map_err(GitLabApiError::Network)?;

        match create_resp.status().as_u16() {
            201 | 200 => Ok(SetCiVariableResponse::Created),
            401 | 403 => Err(GitLabApiError::Unauthorized),
            404 => Err(GitLabApiError::NotFound(format!("project '{project}'"))),
            429 => Err(GitLabApiError::RateLimited),
            500..=599 => Err(GitLabApiError::ServerError),
            other => Err(GitLabApiError::UnexpectedStatus(other)),
        }
    }
}

impl Default for GitLabClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn transient_errors_identified() {
        assert!(GitLabApiError::RateLimited.is_transient());
        assert!(GitLabApiError::ServerError.is_transient());
        assert!(!GitLabApiError::Unauthorized.is_transient());
        assert!(!GitLabApiError::NotFound("x".into()).is_transient());
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = GitLabClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn percent_encode_path_component() {
        assert_eq!(
            percent_encode_component("group/sub/project"),
            "group%2Fsub%2Fproject"
        );
        assert_eq!(percent_encode_component("A_B-1.2~x"), "A_B-1.2~x");
        assert_eq!(percent_encode_component("space name"), "space%20name");
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://gitlab.example.com/api/v4");
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080/api/v4");
        validate_url_scheme("http://127.0.0.1:8080/api/v4");
    }

    #[test]
    #[should_panic(expected = "insecure HTTP URL rejected")]
    fn validate_url_scheme_rejects_remote_http() {
        validate_url_scheme("http://gitlab.example.com/api/v4");
    }

    #[test]
    #[should_panic(expected = "unsupported URL scheme")]
    fn validate_url_scheme_rejects_ftp() {
        validate_url_scheme("ftp://gitlab.example.com/api/v4");
    }

    #[tokio::test]
    async fn set_ci_variable_updated_via_put() {
        let mock_server = MockServer::start().await;
        let client = GitLabClient::with_base_url(mock_server.uri());

        Mock::given(method("PUT"))
            .and(path("/projects/group%2Fproj/variables/MY_KEY"))
            .and(header("private-token", "glpat-test"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client
            .set_ci_variable(
                "glpat-test",
                "group/proj",
                "MY_KEY",
                "secret-value",
                SetCiVariableOptions::default(),
            )
            .await
            .unwrap();

        assert_eq!(result, SetCiVariableResponse::Updated);
    }

    #[tokio::test]
    async fn set_ci_variable_created_via_post_fallback() {
        let mock_server = MockServer::start().await;
        let client = GitLabClient::with_base_url(mock_server.uri());

        Mock::given(method("PUT"))
            .and(path("/projects/group%2Fproj/variables/MY_KEY"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/projects/group%2Fproj/variables"))
            .and(header("private-token", "glpat-test"))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client
            .set_ci_variable(
                "glpat-test",
                "group/proj",
                "MY_KEY",
                "secret-value",
                SetCiVariableOptions {
                    environment_scope: Some("*"),
                    protected: Some(true),
                    masked: Some(false),
                    raw: Some(true),
                    variable_type: Some("env_var"),
                },
            )
            .await
            .unwrap();

        assert_eq!(result, SetCiVariableResponse::Created);
    }

    #[tokio::test]
    async fn set_ci_variable_unauthorized() {
        let mock_server = MockServer::start().await;
        let client = GitLabClient::with_base_url(mock_server.uri());

        Mock::given(method("PUT"))
            .and(path("/projects/group%2Fproj/variables/MY_KEY"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let err = client
            .set_ci_variable(
                "bad-token",
                "group/proj",
                "MY_KEY",
                "secret-value",
                SetCiVariableOptions::default(),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, GitLabApiError::Unauthorized));
    }

    #[tokio::test]
    async fn set_ci_variable_project_not_found_after_fallback() {
        let mock_server = MockServer::start().await;
        let client = GitLabClient::with_base_url(mock_server.uri());

        Mock::given(method("PUT"))
            .and(path("/projects/group%2Fmissing/variables/MY_KEY"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/projects/group%2Fmissing/variables"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let err = client
            .set_ci_variable(
                "glpat-test",
                "group/missing",
                "MY_KEY",
                "secret-value",
                SetCiVariableOptions::default(),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, GitLabApiError::NotFound(_)));
        assert!(format!("{err}").contains("group/missing"));
    }
}
