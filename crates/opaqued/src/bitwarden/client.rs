//! Bitwarden Secrets Manager API client.
//!
//! Wraps the REST endpoints needed to browse projects/secrets and resolve
//! secret values via the Bitwarden Secrets Manager API.
//!
//! **Never** leaks raw API error bodies to callers — all errors are
//! mapped to sanitized strings.

use serde::{Deserialize, Serialize};

/// Environment variable to override the default Bitwarden Secrets Manager base URL.
pub const BITWARDEN_URL_ENV: &str = "OPAQUE_BITWARDEN_URL";

/// Default Bitwarden Secrets Manager API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.bitwarden.com";

/// Bitwarden Secrets Manager API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum BitwardenApiError {
    #[error("network error communicating with Bitwarden Secrets Manager")]
    Network(#[source] reqwest::Error),

    #[error("Bitwarden Secrets Manager authentication failed (check access token)")]
    Unauthorized,

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("Bitwarden Secrets Manager server error")]
    ServerError,

    #[error("unexpected Bitwarden Secrets Manager response: status {0}")]
    UnexpectedStatus(u16),
}

/// A Bitwarden Secrets Manager project.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitwardenProject {
    pub id: String,
    pub name: String,
}

/// A Bitwarden secret summary (returned by list endpoints, no value).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitwardenSecretSummary {
    pub id: String,
    pub key: String,
}

/// A Bitwarden secret with its value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitwardenSecret {
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default, rename = "projectId")]
    pub project_id: Option<String>,
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

/// Bitwarden Secrets Manager REST API client.
///
/// Follows the same pattern as `OnePasswordClient`: no stored token (passed
/// per-call), timeouts, and a user-agent header.
#[derive(Debug, Clone)]
pub struct BitwardenClient {
    http: reqwest::Client,
    base_url: String,
}

impl BitwardenClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client pointing at the given Bitwarden Secrets Manager URL.
    ///
    /// Panics if the base URL uses `http://` for a non-localhost host.
    pub fn new(base_url: &str) -> Self {
        validate_url_scheme(base_url);

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// List all projects accessible with the given token.
    pub async fn list_projects(
        &self,
        token: &str,
    ) -> Result<Vec<BitwardenProject>, BitwardenApiError> {
        let url = format!("{}/api/projects", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(BitwardenApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<Vec<BitwardenProject>>()
                .await
                .map_err(BitwardenApiError::Network),
            401 | 403 => Err(BitwardenApiError::Unauthorized),
            404 => Err(BitwardenApiError::NotFound("projects endpoint".into())),
            500..=599 => Err(BitwardenApiError::ServerError),
            other => Err(BitwardenApiError::UnexpectedStatus(other)),
        }
    }

    /// List secrets, optionally filtered by project ID.
    pub async fn list_secrets(
        &self,
        token: &str,
        project_id: Option<&str>,
    ) -> Result<Vec<BitwardenSecretSummary>, BitwardenApiError> {
        let mut url = format!("{}/api/secrets", self.base_url);
        if let Some(pid) = project_id {
            url = format!("{url}?projectId={pid}");
        }

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(BitwardenApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<Vec<BitwardenSecretSummary>>()
                .await
                .map_err(BitwardenApiError::Network),
            401 | 403 => Err(BitwardenApiError::Unauthorized),
            404 => Err(BitwardenApiError::NotFound("secrets endpoint".into())),
            500..=599 => Err(BitwardenApiError::ServerError),
            other => Err(BitwardenApiError::UnexpectedStatus(other)),
        }
    }

    /// Get a single secret with its value.
    pub async fn get_secret(
        &self,
        token: &str,
        secret_id: &str,
    ) -> Result<BitwardenSecret, BitwardenApiError> {
        let url = format!("{}/api/secrets/{}", self.base_url, secret_id);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(BitwardenApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<BitwardenSecret>()
                .await
                .map_err(BitwardenApiError::Network),
            401 | 403 => Err(BitwardenApiError::Unauthorized),
            404 => Err(BitwardenApiError::NotFound(format!("secret {secret_id}"))),
            500..=599 => Err(BitwardenApiError::ServerError),
            other => Err(BitwardenApiError::UnexpectedStatus(other)),
        }
    }

    /// Resolve a project name to its ID by listing all projects and matching by name.
    pub async fn find_project_by_name(
        &self,
        token: &str,
        name: &str,
    ) -> Result<String, BitwardenApiError> {
        let projects = self.list_projects(token).await?;
        projects
            .into_iter()
            .find(|p| p.name == name)
            .map(|p| p.id)
            .ok_or_else(|| BitwardenApiError::NotFound(format!("project '{name}'")))
    }

    /// Resolve a secret key to its ID within a project.
    pub async fn find_secret_by_key(
        &self,
        token: &str,
        project_id: &str,
        key: &str,
    ) -> Result<String, BitwardenApiError> {
        let secrets = self.list_secrets(token, Some(project_id)).await?;
        secrets
            .into_iter()
            .find(|s| s.key == key)
            .map(|s| s.id)
            .ok_or_else(|| BitwardenApiError::NotFound(format!("secret '{key}' in project")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_stores_base_url_trimmed() {
        let client = BitwardenClient::new("http://localhost:8080/");
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = BitwardenClient::new("http://localhost:8080");
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = BitwardenClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn project_deserialize() {
        let json = r#"{"id":"proj-123","name":"My Project"}"#;
        let project: BitwardenProject = serde_json::from_str(json).unwrap();
        assert_eq!(project.id, "proj-123");
        assert_eq!(project.name, "My Project");
    }

    #[test]
    fn secret_summary_deserialize() {
        let json = r#"{"id":"sec-456","key":"DB_PASSWORD"}"#;
        let secret: BitwardenSecretSummary = serde_json::from_str(json).unwrap();
        assert_eq!(secret.id, "sec-456");
        assert_eq!(secret.key, "DB_PASSWORD");
    }

    #[test]
    fn secret_deserialize_with_value() {
        let json = r#"{
            "id": "sec-456",
            "key": "DB_PASSWORD",
            "value": "supersecret",
            "note": "Production database password",
            "projectId": "proj-123"
        }"#;
        let secret: BitwardenSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.id, "sec-456");
        assert_eq!(secret.key, "DB_PASSWORD");
        assert_eq!(secret.value.as_deref(), Some("supersecret"));
        assert_eq!(secret.note.as_deref(), Some("Production database password"));
        assert_eq!(secret.project_id.as_deref(), Some("proj-123"));
    }

    #[test]
    fn secret_deserialize_minimal() {
        let json = r#"{"id": "sec-456", "key": "TOKEN"}"#;
        let secret: BitwardenSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.id, "sec-456");
        assert!(secret.value.is_none());
        assert!(secret.note.is_none());
        assert!(secret.project_id.is_none());
    }

    #[test]
    fn bitwarden_api_error_display() {
        let err = BitwardenApiError::Unauthorized;
        assert!(format!("{err}").contains("authentication failed"));

        let err = BitwardenApiError::NotFound("secret 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = BitwardenApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = BitwardenApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));
    }

    #[test]
    fn projects_list_deserialize() {
        let json = r#"[
            {"id":"p1","name":"Production"},
            {"id":"p2","name":"Staging"}
        ]"#;
        let projects: Vec<BitwardenProject> = serde_json::from_str(json).unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].name, "Production");
        assert_eq!(projects[1].name, "Staging");
    }

    #[test]
    fn secrets_list_deserialize() {
        let json = r#"[
            {"id":"s1","key":"DB_PASSWORD"},
            {"id":"s2","key":"API_KEY"}
        ]"#;
        let secrets: Vec<BitwardenSecretSummary> = serde_json::from_str(json).unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].key, "DB_PASSWORD");
        assert_eq!(secrets[1].key, "API_KEY");
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_projects_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "p1", "name": "Production"},
                {"id": "p2", "name": "Staging"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let projects = client.list_projects("test-token").await.unwrap();

        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].id, "p1");
        assert_eq!(projects[0].name, "Production");
        assert_eq!(projects[1].id, "p2");
        assert_eq!(projects[1].name, "Staging");
    }

    #[tokio::test]
    async fn list_projects_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let result = client.list_projects("bad-token").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BitwardenApiError::Unauthorized
        ));
    }

    #[tokio::test]
    async fn list_projects_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let result = client.list_projects("token").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BitwardenApiError::ServerError
        ));
    }

    #[tokio::test]
    async fn list_secrets_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/secrets"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "s1", "key": "DB_PASSWORD"},
                {"id": "s2", "key": "API_KEY"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let secrets = client.list_secrets("test-token", None).await.unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].key, "DB_PASSWORD");
        assert_eq!(secrets[1].key, "API_KEY");
    }

    #[tokio::test]
    async fn get_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/secrets/sec-123"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sec-123",
                "key": "DB_PASSWORD",
                "value": "supersecret",
                "note": "Production DB",
                "projectId": "proj-1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let secret = client.get_secret("test-token", "sec-123").await.unwrap();

        assert_eq!(secret.id, "sec-123");
        assert_eq!(secret.key, "DB_PASSWORD");
        assert_eq!(secret.value.as_deref(), Some("supersecret"));
        assert_eq!(secret.note.as_deref(), Some("Production DB"));
        assert_eq!(secret.project_id.as_deref(), Some("proj-1"));
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/secrets/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let result = client.get_secret("token", "missing").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BitwardenApiError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn find_project_by_name_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "p1", "name": "Production"},
                {"id": "p2", "name": "Staging"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let project_id = client
            .find_project_by_name("token", "Staging")
            .await
            .unwrap();
        assert_eq!(project_id, "p2");
    }

    #[tokio::test]
    async fn find_project_by_name_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "p1", "name": "Production"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let result = client.find_project_by_name("token", "Nonexistent").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BitwardenApiError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn find_secret_by_key_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "s1", "key": "DB_PASSWORD"},
                {"id": "s2", "key": "API_KEY"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let secret_id = client
            .find_secret_by_key("token", "p1", "API_KEY")
            .await
            .unwrap();
        assert_eq!(secret_id, "s2");
    }

    /// Full end-to-end resolution chain:
    /// find_project_by_name → find_secret_by_key → get_secret → extract value
    #[tokio::test]
    async fn full_resolution_chain() {
        let mock_server = MockServer::start().await;

        // Step 1: list projects → find "Production" → project_id="p1"
        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "p1", "name": "Production"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Step 2: list secrets in project → find "DB_PASSWORD" → secret_id="s1"
        Mock::given(method("GET"))
            .and(path("/api/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "s1", "key": "DB_PASSWORD"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Step 3: get secret s1 → extract value
        Mock::given(method("GET"))
            .and(path("/api/secrets/s1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "s1",
                "key": "DB_PASSWORD",
                "value": "realpassword123",
                "projectId": "p1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let token = "test-token";

        let project_id = client
            .find_project_by_name(token, "Production")
            .await
            .unwrap();
        assert_eq!(project_id, "p1");

        let secret_id = client
            .find_secret_by_key(token, &project_id, "DB_PASSWORD")
            .await
            .unwrap();
        assert_eq!(secret_id, "s1");

        let secret = client.get_secret(token, &secret_id).await.unwrap();
        assert_eq!(secret.value.as_deref(), Some("realpassword123"));
    }

    /// Verify bearer token is sent correctly in the Authorization header.
    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let projects = client.list_projects("my-secret-token").await.unwrap();
        assert!(projects.is_empty());
    }

    /// Verify the user-agent header is sent.
    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        client.list_projects("token").await.unwrap();
    }

    /// Verify unexpected status codes are handled.
    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(418)) // I'm a teapot
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let result = client.list_projects("token").await;
        assert!(matches!(
            result.unwrap_err(),
            BitwardenApiError::UnexpectedStatus(418)
        ));
    }

    /// Verify 403 is treated as unauthorized (same as 401).
    #[tokio::test]
    async fn forbidden_treated_as_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/projects"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitwardenClient::new(&mock_server.uri());
        let result = client.list_projects("token").await;
        assert!(matches!(
            result.unwrap_err(),
            BitwardenApiError::Unauthorized
        ));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://api.bitwarden.com");
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080");
        validate_url_scheme("http://127.0.0.1:9000/api");
    }

    #[test]
    #[should_panic(expected = "insecure HTTP URL rejected")]
    fn validate_url_scheme_rejects_remote_http() {
        validate_url_scheme("http://api.bitwarden.com");
    }

    #[test]
    #[should_panic(expected = "unsupported URL scheme")]
    fn validate_url_scheme_rejects_ftp() {
        validate_url_scheme("ftp://example.com/file");
    }
}
