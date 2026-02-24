//! Doppler Secrets Manager API client.
//!
//! Wraps the REST endpoints needed to browse projects/configs/secrets and
//! resolve secret values via the Doppler API.
//!
//! **Never** leaks raw API error bodies to callers -- all errors are
//! mapped to sanitized strings.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Environment variable for the Doppler service token.
#[allow(dead_code)]
pub const DOPPLER_TOKEN_ENV: &str = "OPAQUE_DOPPLER_TOKEN";

/// Environment variable to override the default Doppler API base URL.
pub const DOPPLER_URL_ENV: &str = "OPAQUE_DOPPLER_URL";

/// Default Doppler API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.doppler.com/v3";

/// Doppler API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum DopplerApiError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("network error communicating with Doppler")]
    HttpError(#[source] reqwest::Error),

    #[error("Doppler authentication failed (check service token)")]
    AuthError,

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("Doppler server error")]
    ServerError,

    #[error("unexpected Doppler API response: status {0}")]
    UnexpectedStatus(u16),
}

/// A Doppler project.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DopplerProject {
    pub id: String,
    pub name: String,
}

/// A Doppler config (environment configuration).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DopplerConfig {
    pub name: String,
    #[serde(default)]
    pub root: bool,
}

/// A Doppler secret (name + computed value).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DopplerSecret {
    pub raw: Option<String>,
    pub computed: Option<String>,
}

/// A single Doppler secret value response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DopplerSecretValue {
    pub name: String,
    pub value: DopplerSecretValueInner,
}

/// Inner value wrapper for a Doppler secret response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DopplerSecretValueInner {
    pub raw: Option<String>,
    pub computed: Option<String>,
}

/// Validate that a URL uses `https://`, allowing `http://` only for localhost.
fn validate_url_scheme(url: &str) -> Result<(), DopplerApiError> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://") {
        if let Some(host_part) = url.strip_prefix("http://") {
            let host = host_part.split('/').next().unwrap_or("");
            let host_no_port = host.split(':').next().unwrap_or("");
            if host_no_port == "localhost" || host_no_port == "127.0.0.1" {
                return Ok(());
            }
        }
        return Err(DopplerApiError::InvalidUrl(format!(
            "insecure HTTP URL rejected: {url}. \
             Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
        )));
    }
    Err(DopplerApiError::InvalidUrl(format!(
        "unsupported URL scheme: {url}. \
         Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
    )))
}

/// Doppler REST API client.
#[derive(Debug, Clone)]
pub struct DopplerClient {
    http: reqwest::Client,
    base_url: String,
}

impl DopplerClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client pointing at the given Doppler API URL.
    ///
    /// Returns an error if the base URL uses an unsupported scheme.
    pub fn new(base_url: &str) -> Result<Self, DopplerApiError> {
        validate_url_scheme(base_url)?;

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
        })
    }

    /// List all projects accessible with the given service token.
    pub async fn list_projects(&self, token: &str) -> Result<Vec<DopplerProject>, DopplerApiError> {
        let url = format!("{}/workplace/projects", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(DopplerApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct ListProjectsResponse {
                    projects: Vec<DopplerProject>,
                }
                let body: ListProjectsResponse =
                    resp.json().await.map_err(DopplerApiError::HttpError)?;
                Ok(body.projects)
            }
            401 | 403 => Err(DopplerApiError::AuthError),
            404 => Err(DopplerApiError::NotFound("projects endpoint".into())),
            500..=599 => Err(DopplerApiError::ServerError),
            other => Err(DopplerApiError::UnexpectedStatus(other)),
        }
    }

    /// List configs for a project.
    pub async fn list_configs(
        &self,
        token: &str,
        project: &str,
    ) -> Result<Vec<DopplerConfig>, DopplerApiError> {
        let url = format!("{}/configs?project={}", self.base_url, project);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(DopplerApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct ListConfigsResponse {
                    configs: Vec<DopplerConfig>,
                }
                let body: ListConfigsResponse =
                    resp.json().await.map_err(DopplerApiError::HttpError)?;
                Ok(body.configs)
            }
            401 | 403 => Err(DopplerApiError::AuthError),
            404 => Err(DopplerApiError::NotFound(format!(
                "configs for project '{project}'"
            ))),
            500..=599 => Err(DopplerApiError::ServerError),
            other => Err(DopplerApiError::UnexpectedStatus(other)),
        }
    }

    /// List all secrets in a project/config (returns name + metadata, no values).
    pub async fn list_secrets(
        &self,
        token: &str,
        project: &str,
        config: &str,
    ) -> Result<HashMap<String, DopplerSecret>, DopplerApiError> {
        let url = format!(
            "{}/configs/config/secrets?project={}&config={}",
            self.base_url, project, config
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(DopplerApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct ListSecretsResponse {
                    secrets: HashMap<String, DopplerSecret>,
                }
                let body: ListSecretsResponse =
                    resp.json().await.map_err(DopplerApiError::HttpError)?;
                Ok(body.secrets)
            }
            401 | 403 => Err(DopplerApiError::AuthError),
            404 => Err(DopplerApiError::NotFound(format!(
                "secrets for project '{project}' config '{config}'"
            ))),
            500..=599 => Err(DopplerApiError::ServerError),
            other => Err(DopplerApiError::UnexpectedStatus(other)),
        }
    }

    /// Get a single secret value.
    pub async fn get_secret(
        &self,
        token: &str,
        project: &str,
        config: &str,
        name: &str,
    ) -> Result<DopplerSecretValue, DopplerApiError> {
        let url = format!(
            "{}/configs/config/secret?project={}&config={}&name={}",
            self.base_url, project, config, name
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(DopplerApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                let body: DopplerSecretValue =
                    resp.json().await.map_err(DopplerApiError::HttpError)?;
                Ok(body)
            }
            401 | 403 => Err(DopplerApiError::AuthError),
            404 => Err(DopplerApiError::NotFound(format!(
                "secret '{name}' in project '{project}' config '{config}'"
            ))),
            500..=599 => Err(DopplerApiError::ServerError),
            other => Err(DopplerApiError::UnexpectedStatus(other)),
        }
    }

    /// Set (create or update) a secret value.
    pub async fn set_secret(
        &self,
        token: &str,
        project: &str,
        config: &str,
        name: &str,
        value: &str,
    ) -> Result<(), DopplerApiError> {
        let url = format!("{}/configs/config/secrets", self.base_url);

        let body = serde_json::json!({
            "project": project,
            "config": config,
            "secrets": {
                name: value
            }
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(DopplerApiError::HttpError)?;

        match resp.status().as_u16() {
            200 | 201 => Ok(()),
            401 | 403 => Err(DopplerApiError::AuthError),
            404 => Err(DopplerApiError::NotFound(format!(
                "project '{project}' config '{config}'"
            ))),
            500..=599 => Err(DopplerApiError::ServerError),
            other => Err(DopplerApiError::UnexpectedStatus(other)),
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
    fn client_stores_base_url_trimmed() {
        let client = DopplerClient::new("http://localhost:8080/").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = DopplerClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = DopplerClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn project_deserialize() {
        let json = r#"{"id":"proj-123","name":"My Project"}"#;
        let project: DopplerProject = serde_json::from_str(json).unwrap();
        assert_eq!(project.id, "proj-123");
        assert_eq!(project.name, "My Project");
    }

    #[test]
    fn config_deserialize() {
        let json = r#"{"name":"production","root":true}"#;
        let config: DopplerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "production");
        assert!(config.root);
    }

    #[test]
    fn config_deserialize_minimal() {
        let json = r#"{"name":"dev"}"#;
        let config: DopplerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "dev");
        assert!(!config.root);
    }

    #[test]
    fn secret_deserialize() {
        let json = r#"{"raw":"mysecret","computed":"mysecret"}"#;
        let secret: DopplerSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.raw.as_deref(), Some("mysecret"));
        assert_eq!(secret.computed.as_deref(), Some("mysecret"));
    }

    #[test]
    fn secret_value_deserialize() {
        let json = r#"{"name":"API_KEY","value":{"raw":"abc123","computed":"abc123"}}"#;
        let sv: DopplerSecretValue = serde_json::from_str(json).unwrap();
        assert_eq!(sv.name, "API_KEY");
        assert_eq!(sv.value.computed.as_deref(), Some("abc123"));
    }

    #[test]
    fn doppler_api_error_display() {
        let err = DopplerApiError::AuthError;
        assert!(format!("{err}").contains("authentication failed"));

        let err = DopplerApiError::NotFound("secret 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = DopplerApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = DopplerApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://api.doppler.com/v3").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080").unwrap();
        validate_url_scheme("http://127.0.0.1:9000/api").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://api.doppler.com").unwrap_err();
        assert!(matches!(err, DopplerApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("insecure HTTP URL rejected"));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/file").unwrap_err();
        assert!(matches!(err, DopplerApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("unsupported URL scheme"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_projects_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/workplace/projects"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "projects": [
                    {"id": "p1", "name": "Production"},
                    {"id": "p2", "name": "Staging"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
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
            .and(path("/workplace/projects"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("bad-token").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DopplerApiError::AuthError));
    }

    #[tokio::test]
    async fn list_projects_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/workplace/projects"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("token").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DopplerApiError::ServerError));
    }

    #[tokio::test]
    async fn list_configs_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/configs"))
            .and(query_param("project", "my-project"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "configs": [
                    {"name": "production", "root": true},
                    {"name": "staging", "root": false}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let configs = client
            .list_configs("test-token", "my-project")
            .await
            .unwrap();

        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].name, "production");
        assert!(configs[0].root);
        assert_eq!(configs[1].name, "staging");
    }

    #[tokio::test]
    async fn list_configs_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/configs"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_configs("bad-token", "proj").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DopplerApiError::AuthError));
    }

    #[tokio::test]
    async fn list_secrets_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/configs/config/secrets"))
            .and(query_param("project", "my-project"))
            .and(query_param("config", "production"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": {
                    "DB_PASSWORD": {"raw": "secret123", "computed": "secret123"},
                    "API_KEY": {"raw": "key456", "computed": "key456"}
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("test-token", "my-project", "production")
            .await
            .unwrap();

        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("DB_PASSWORD"));
        assert!(secrets.contains_key("API_KEY"));
    }

    #[tokio::test]
    async fn get_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/configs/config/secret"))
            .and(query_param("project", "my-project"))
            .and(query_param("config", "production"))
            .and(query_param("name", "DB_PASSWORD"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "DB_PASSWORD",
                "value": {
                    "raw": "supersecret",
                    "computed": "supersecret"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let secret = client
            .get_secret("test-token", "my-project", "production", "DB_PASSWORD")
            .await
            .unwrap();

        assert_eq!(secret.name, "DB_PASSWORD");
        assert_eq!(secret.value.computed.as_deref(), Some("supersecret"));
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/configs/config/secret"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client.get_secret("token", "proj", "cfg", "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DopplerApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn set_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/configs/config/secrets"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": {
                    "NEW_SECRET": {"raw": "newvalue", "computed": "newvalue"}
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .set_secret(
                "test-token",
                "my-project",
                "production",
                "NEW_SECRET",
                "newvalue",
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn set_secret_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/configs/config/secrets"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .set_secret("bad-token", "proj", "cfg", "KEY", "val")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DopplerApiError::AuthError));
    }

    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/workplace/projects"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"projects": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let projects = client.list_projects("my-secret-token").await.unwrap();
        assert!(projects.is_empty());
    }

    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/workplace/projects"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"projects": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        client.list_projects("token").await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/workplace/projects"))
            .respond_with(ResponseTemplate::new(418))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("token").await;
        assert!(matches!(
            result.unwrap_err(),
            DopplerApiError::UnexpectedStatus(418)
        ));
    }

    #[tokio::test]
    async fn forbidden_treated_as_auth_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/workplace/projects"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = DopplerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("token").await;
        assert!(matches!(result.unwrap_err(), DopplerApiError::AuthError));
    }
}
