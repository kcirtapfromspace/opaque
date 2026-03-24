//! Infisical Secrets Manager API client.
//!
//! Wraps the REST endpoints needed to browse projects/secrets and resolve
//! secret values via the Infisical API.
//!
//! **Never** leaks raw API error bodies to callers -- all errors are
//! mapped to sanitized strings.

use serde::{Deserialize, Serialize};

/// Environment variable for the Infisical service/machine identity token.
pub const INFISICAL_TOKEN_ENV: &str = "OPAQUE_INFISICAL_TOKEN";

/// Environment variable to override the default Infisical API base URL.
pub const INFISICAL_URL_ENV: &str = "OPAQUE_INFISICAL_URL";

/// Default Infisical API base URL.
pub const DEFAULT_BASE_URL: &str = "https://app.infisical.com/api";

/// Infisical API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum InfisicalApiError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("network error communicating with Infisical")]
    HttpError(#[source] reqwest::Error),

    #[error("Infisical authentication failed (check service token)")]
    AuthError,

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("Infisical server error")]
    ServerError,

    #[error("unexpected Infisical API response: status {0}")]
    UnexpectedStatus(u16),
}

/// An Infisical project (workspace).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InfisicalProject {
    pub id: String,
    pub name: String,
}

/// An Infisical secret summary (returned by list endpoints).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InfisicalSecret {
    #[serde(alias = "_id", default)]
    pub id: String,
    #[serde(alias = "secretKey")]
    pub key: String,
    #[serde(default, alias = "secretValue")]
    pub value: Option<String>,
}

/// An Infisical secret with its value (returned by get endpoint).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InfisicalSecretValue {
    #[serde(alias = "secretKey")]
    pub key: String,
    #[serde(alias = "secretValue")]
    pub value: String,
}

/// Validate that a URL uses `https://`, allowing `http://` only for localhost.
fn validate_url_scheme(url: &str) -> Result<(), InfisicalApiError> {
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
        return Err(InfisicalApiError::InvalidUrl(format!(
            "insecure HTTP URL rejected: {url}. \
             Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
        )));
    }
    Err(InfisicalApiError::InvalidUrl(format!(
        "unsupported URL scheme: {url}. \
         Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
    )))
}

/// Infisical REST API client.
#[derive(Debug, Clone)]
pub struct InfisicalClient {
    http: reqwest::Client,
    base_url: String,
}

impl InfisicalClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client pointing at the given Infisical API URL.
    ///
    /// Returns an error if the base URL uses an unsupported scheme.
    pub fn new(base_url: &str) -> Result<Self, InfisicalApiError> {
        validate_url_scheme(base_url)?;

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(InfisicalApiError::HttpError)?;

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
        })
    }

    /// List all projects (workspaces) accessible with the given token.
    ///
    /// Uses the organization workspaces endpoint.
    pub async fn list_projects(
        &self,
        token: &str,
        org_id: &str,
    ) -> Result<Vec<InfisicalProject>, InfisicalApiError> {
        let url = format!("{}/organizations/{}/workspaces", self.base_url, org_id);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(InfisicalApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct ListWorkspacesResponse {
                    workspaces: Vec<InfisicalProject>,
                }
                let body: ListWorkspacesResponse =
                    resp.json().await.map_err(InfisicalApiError::HttpError)?;
                Ok(body.workspaces)
            }
            401 | 403 => Err(InfisicalApiError::AuthError),
            404 => Err(InfisicalApiError::NotFound(format!(
                "workspaces for org '{org_id}'"
            ))),
            500..=599 => Err(InfisicalApiError::ServerError),
            other => Err(InfisicalApiError::UnexpectedStatus(other)),
        }
    }

    /// List secrets in a project/environment.
    pub async fn list_secrets(
        &self,
        token: &str,
        project_id: &str,
        env: &str,
    ) -> Result<Vec<InfisicalSecret>, InfisicalApiError> {
        let url = format!(
            "{}/secrets?workspaceId={}&environment={}",
            self.base_url, project_id, env
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(InfisicalApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct ListSecretsResponse {
                    secrets: Vec<InfisicalSecret>,
                }
                let body: ListSecretsResponse =
                    resp.json().await.map_err(InfisicalApiError::HttpError)?;
                Ok(body.secrets)
            }
            401 | 403 => Err(InfisicalApiError::AuthError),
            404 => Err(InfisicalApiError::NotFound(format!(
                "secrets for project '{project_id}' env '{env}'"
            ))),
            500..=599 => Err(InfisicalApiError::ServerError),
            other => Err(InfisicalApiError::UnexpectedStatus(other)),
        }
    }

    /// Get a single secret by name.
    pub async fn get_secret(
        &self,
        token: &str,
        project_id: &str,
        env: &str,
        name: &str,
    ) -> Result<InfisicalSecretValue, InfisicalApiError> {
        let url = format!(
            "{}/secrets/{}?workspaceId={}&environment={}",
            self.base_url, name, project_id, env
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(InfisicalApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct GetSecretResponse {
                    secret: InfisicalSecretValue,
                }
                let body: GetSecretResponse =
                    resp.json().await.map_err(InfisicalApiError::HttpError)?;
                Ok(body.secret)
            }
            401 | 403 => Err(InfisicalApiError::AuthError),
            404 => Err(InfisicalApiError::NotFound(format!(
                "secret '{name}' in project '{project_id}' env '{env}'"
            ))),
            500..=599 => Err(InfisicalApiError::ServerError),
            other => Err(InfisicalApiError::UnexpectedStatus(other)),
        }
    }

    /// Create a new secret.
    pub async fn create_secret(
        &self,
        token: &str,
        project_id: &str,
        env: &str,
        name: &str,
        value: &str,
    ) -> Result<(), InfisicalApiError> {
        let url = format!("{}/secrets/{}", self.base_url, name);

        let body = serde_json::json!({
            "workspaceId": project_id,
            "environment": env,
            "secretValue": value,
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(InfisicalApiError::HttpError)?;

        match resp.status().as_u16() {
            200 | 201 => Ok(()),
            401 | 403 => Err(InfisicalApiError::AuthError),
            404 => Err(InfisicalApiError::NotFound(format!(
                "project '{project_id}' env '{env}'"
            ))),
            500..=599 => Err(InfisicalApiError::ServerError),
            other => Err(InfisicalApiError::UnexpectedStatus(other)),
        }
    }

    /// Update an existing secret.
    pub async fn update_secret(
        &self,
        token: &str,
        project_id: &str,
        env: &str,
        name: &str,
        value: &str,
    ) -> Result<(), InfisicalApiError> {
        let url = format!("{}/secrets/{}", self.base_url, name);

        let body = serde_json::json!({
            "workspaceId": project_id,
            "environment": env,
            "secretValue": value,
        });

        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(InfisicalApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => Ok(()),
            401 | 403 => Err(InfisicalApiError::AuthError),
            404 => Err(InfisicalApiError::NotFound(format!(
                "secret '{name}' in project '{project_id}' env '{env}'"
            ))),
            500..=599 => Err(InfisicalApiError::ServerError),
            other => Err(InfisicalApiError::UnexpectedStatus(other)),
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
        let client = InfisicalClient::new("http://localhost:8080/").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = InfisicalClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = InfisicalClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn project_deserialize() {
        let json = r#"{"id":"proj-123","name":"My Project"}"#;
        let project: InfisicalProject = serde_json::from_str(json).unwrap();
        assert_eq!(project.id, "proj-123");
        assert_eq!(project.name, "My Project");
    }

    #[test]
    fn secret_deserialize() {
        let json = r#"{"_id":"sec-456","secretKey":"DB_PASSWORD","secretValue":"mysecret"}"#;
        let secret: InfisicalSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.id, "sec-456");
        assert_eq!(secret.key, "DB_PASSWORD");
        assert_eq!(secret.value.as_deref(), Some("mysecret"));
    }

    #[test]
    fn secret_deserialize_minimal() {
        let json = r#"{"secretKey":"TOKEN"}"#;
        let secret: InfisicalSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.key, "TOKEN");
        assert!(secret.value.is_none());
    }

    #[test]
    fn secret_value_deserialize() {
        let json = r#"{"secretKey":"DB_PASSWORD","secretValue":"supersecret"}"#;
        let sv: InfisicalSecretValue = serde_json::from_str(json).unwrap();
        assert_eq!(sv.key, "DB_PASSWORD");
        assert_eq!(sv.value, "supersecret");
    }

    #[test]
    fn infisical_api_error_display() {
        let err = InfisicalApiError::AuthError;
        assert!(format!("{err}").contains("authentication failed"));

        let err = InfisicalApiError::NotFound("secret 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = InfisicalApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = InfisicalApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://app.infisical.com/api").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080").unwrap();
        validate_url_scheme("http://127.0.0.1:9000/api").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://app.infisical.com").unwrap_err();
        assert!(matches!(err, InfisicalApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("insecure HTTP URL rejected"));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/file").unwrap_err();
        assert!(matches!(err, InfisicalApiError::InvalidUrl(_)));
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
            .and(path("/organizations/org-1/workspaces"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "workspaces": [
                    {"id": "p1", "name": "Production"},
                    {"id": "p2", "name": "Staging"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let projects = client.list_projects("test-token", "org-1").await.unwrap();

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
            .and(path("/organizations/org-1/workspaces"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("bad-token", "org-1").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InfisicalApiError::AuthError));
    }

    #[tokio::test]
    async fn list_projects_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/organizations/org-1/workspaces"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("token", "org-1").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InfisicalApiError::ServerError
        ));
    }

    #[tokio::test]
    async fn list_secrets_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("workspaceId", "proj-1"))
            .and(query_param("environment", "production"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": [
                    {"_id": "s1", "secretKey": "DB_PASSWORD", "secretValue": "secret123"},
                    {"_id": "s2", "secretKey": "API_KEY", "secretValue": "key456"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("test-token", "proj-1", "production")
            .await
            .unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].key, "DB_PASSWORD");
        assert_eq!(secrets[1].key, "API_KEY");
    }

    #[tokio::test]
    async fn get_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/secrets/DB_PASSWORD"))
            .and(query_param("workspaceId", "proj-1"))
            .and(query_param("environment", "production"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secret": {
                    "secretKey": "DB_PASSWORD",
                    "secretValue": "supersecret"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let secret = client
            .get_secret("test-token", "proj-1", "production", "DB_PASSWORD")
            .await
            .unwrap();

        assert_eq!(secret.key, "DB_PASSWORD");
        assert_eq!(secret.value, "supersecret");
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/secrets/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client.get_secret("token", "proj", "dev", "missing").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InfisicalApiError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn create_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/secrets/NEW_SECRET"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "secret": {
                    "secretKey": "NEW_SECRET",
                    "secretValue": "newvalue"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client
            .create_secret(
                "test-token",
                "proj-1",
                "production",
                "NEW_SECRET",
                "newvalue",
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn create_secret_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/secrets/KEY"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client
            .create_secret("bad-token", "proj", "dev", "KEY", "val")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InfisicalApiError::AuthError));
    }

    #[tokio::test]
    async fn update_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/secrets/DB_PASSWORD"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secret": {
                    "secretKey": "DB_PASSWORD",
                    "secretValue": "updated_value"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client
            .update_secret(
                "test-token",
                "proj-1",
                "production",
                "DB_PASSWORD",
                "updated_value",
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn update_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/secrets/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client
            .update_secret("token", "proj", "dev", "missing", "val")
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InfisicalApiError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/organizations/org-1/workspaces"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"workspaces": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let projects = client
            .list_projects("my-secret-token", "org-1")
            .await
            .unwrap();
        assert!(projects.is_empty());
    }

    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/organizations/org-1/workspaces"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"workspaces": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        client.list_projects("token", "org-1").await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/organizations/org-1/workspaces"))
            .respond_with(ResponseTemplate::new(418))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("token", "org-1").await;
        assert!(matches!(
            result.unwrap_err(),
            InfisicalApiError::UnexpectedStatus(418)
        ));
    }

    #[tokio::test]
    async fn forbidden_treated_as_auth_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/organizations/org-1/workspaces"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = InfisicalClient::new(&mock_server.uri()).unwrap();
        let result = client.list_projects("token", "org-1").await;
        assert!(matches!(result.unwrap_err(), InfisicalApiError::AuthError));
    }
}
