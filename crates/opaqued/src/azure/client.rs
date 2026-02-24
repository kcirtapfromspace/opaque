//! Azure Key Vault API client.
//!
//! Wraps the REST endpoints needed to browse secrets/keys/certificates and
//! resolve secret values via the Azure Key Vault API.
//!
//! Authentication uses Azure AD OAuth2 client credentials flow with token
//! caching. The access token is obtained from the Microsoft identity platform
//! and cached until expiry.
//!
//! **Never** leaks raw API error bodies to callers --- all errors are
//! mapped to sanitized strings.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Environment variable to override the vault URL directly.
pub const AZURE_VAULT_URL_ENV: &str = "OPAQUE_AZURE_VAULT_URL";

/// Environment variable for the Azure AD tenant ID.
pub const AZURE_TENANT_ID_ENV: &str = "OPAQUE_AZURE_TENANT_ID";

/// Environment variable for the Azure AD client (application) ID.
pub const AZURE_CLIENT_ID_ENV: &str = "OPAQUE_AZURE_CLIENT_ID";

/// Environment variable for the Azure AD client secret.
pub const AZURE_CLIENT_SECRET_ENV: &str = "OPAQUE_AZURE_CLIENT_SECRET";

/// Default Azure Key Vault API version query parameter.
const API_VERSION: &str = "7.4";

/// Azure Key Vault API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum AzureApiError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("network error communicating with Azure Key Vault")]
    HttpError(#[source] reqwest::Error),

    #[error("Azure AD authentication failed (check tenant, client ID, and secret)")]
    AuthError,

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("access forbidden (check Key Vault access policies)")]
    Forbidden,

    #[error("Azure Key Vault server error")]
    ServerError,

    #[error("unexpected Azure Key Vault response: status {0}")]
    UnexpectedStatus(u16),
}

/// An Azure AD OAuth2 token response.
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Cached access token with expiry tracking.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

/// An Azure Key Vault secret item (list endpoint, no value).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureSecretItem {
    pub id: String,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}

/// An Azure Key Vault secret with its value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureSecret {
    pub id: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}

/// An Azure Key Vault key item (list endpoint).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureKeyItem {
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}

/// An Azure Key Vault certificate item (list endpoint).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureCertItem {
    pub id: String,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}

/// Common Key Vault resource attributes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureAttributes {
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Azure Key Vault list response envelope (paginated).
#[derive(Debug, Deserialize)]
struct ListResponse<T> {
    value: Vec<T>,
}

/// Azure Key Vault set-secret request body.
#[derive(Debug, Serialize)]
struct SetSecretRequest<'a> {
    value: &'a str,
}

/// Validate that a URL uses `https://`, allowing `http://` only for localhost.
fn validate_url_scheme(url: &str) -> Result<(), AzureApiError> {
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
        return Err(AzureApiError::InvalidUrl(format!(
            "insecure HTTP URL rejected: {url}. \
             Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
        )));
    }
    Err(AzureApiError::InvalidUrl(format!(
        "unsupported URL scheme: {url}. \
         Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
    )))
}

/// Azure Key Vault REST API client.
///
/// Handles Azure AD OAuth2 client credentials flow for authentication,
/// with token caching and automatic refresh on expiry.
pub struct AzureKeyVaultClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    /// Override for the token endpoint (for testing).
    pub(crate) token_endpoint_override: Option<String>,
    /// Cached access token.
    cached_token: Mutex<Option<CachedToken>>,
}

impl std::fmt::Debug for AzureKeyVaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKeyVaultClient")
            .field("base_url", &self.base_url)
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .finish()
    }
}

impl AzureKeyVaultClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new Azure Key Vault client.
    ///
    /// Returns an error if the base URL uses an unsupported scheme.
    pub fn new(
        base_url: &str,
        tenant_id: String,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, AzureApiError> {
        validate_url_scheme(base_url)?;

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            tenant_id,
            client_id,
            client_secret,
            token_endpoint_override: None,
            cached_token: Mutex::new(None),
        })
    }

    /// Override the token endpoint URL (for testing with wiremock).
    #[cfg(test)]
    fn with_token_endpoint(mut self, endpoint: String) -> Self {
        self.token_endpoint_override = Some(endpoint);
        self
    }

    /// Get the token endpoint URL.
    fn token_endpoint(&self) -> String {
        if let Some(ref override_url) = self.token_endpoint_override {
            return override_url.clone();
        }
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        )
    }

    /// Obtain an access token, using the cached one if still valid.
    async fn get_access_token(&self) -> Result<String, AzureApiError> {
        // Check cache first.
        {
            let cache = self.cached_token.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(ref cached) = *cache
                && cached.expires_at > Instant::now()
            {
                return Ok(cached.access_token.clone());
            }
        }

        // Fetch a new token.
        let token_url = self.token_endpoint();
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", "https://vault.azure.net/.default"),
        ];

        let resp = self
            .http
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(AzureApiError::HttpError)?;

        if !resp.status().is_success() {
            return Err(AzureApiError::AuthError);
        }

        let token_resp: TokenResponse = resp.json().await.map_err(AzureApiError::HttpError)?;

        let cached = CachedToken {
            access_token: token_resp.access_token.clone(),
            // Subtract 60 seconds for safety margin.
            expires_at: Instant::now()
                + Duration::from_secs(token_resp.expires_in.saturating_sub(60)),
        };

        {
            let mut cache = self.cached_token.lock().unwrap_or_else(|p| p.into_inner());
            *cache = Some(cached);
        }

        Ok(token_resp.access_token)
    }

    /// Build a URL with the api-version query parameter.
    fn api_url(&self, path: &str) -> String {
        format!("{}{path}?api-version={API_VERSION}", self.base_url,)
    }

    /// Map HTTP status codes to error types.
    fn map_status(status: u16, resource: &str) -> Result<(), AzureApiError> {
        match status {
            200..=299 => Ok(()),
            401 => Err(AzureApiError::AuthError),
            403 => Err(AzureApiError::Forbidden),
            404 => Err(AzureApiError::NotFound(resource.to_owned())),
            500..=599 => Err(AzureApiError::ServerError),
            other => Err(AzureApiError::UnexpectedStatus(other)),
        }
    }

    /// List all secrets in the vault.
    pub async fn list_secrets(&self) -> Result<Vec<AzureSecretItem>, AzureApiError> {
        let token = self.get_access_token().await?;
        let url = self.api_url("/secrets");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(AzureApiError::HttpError)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(Self::map_status(status, "secrets list").unwrap_err());
        }

        let body: ListResponse<AzureSecretItem> =
            resp.json().await.map_err(AzureApiError::HttpError)?;
        Ok(body.value)
    }

    /// Get a secret by name, optionally at a specific version.
    pub async fn get_secret(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<AzureSecret, AzureApiError> {
        let token = self.get_access_token().await?;
        let path = match version {
            Some(v) => format!("/secrets/{name}/{v}"),
            None => format!("/secrets/{name}"),
        };
        let url = self.api_url(&path);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(AzureApiError::HttpError)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(Self::map_status(status, &format!("secret '{name}'")).unwrap_err());
        }

        resp.json::<AzureSecret>()
            .await
            .map_err(AzureApiError::HttpError)
    }

    /// Set (create or update) a secret by name.
    pub async fn set_secret(&self, name: &str, value: &str) -> Result<AzureSecret, AzureApiError> {
        let token = self.get_access_token().await?;
        let url = self.api_url(&format!("/secrets/{name}"));

        let body = SetSecretRequest { value };

        let resp = self
            .http
            .put(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(AzureApiError::HttpError)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(Self::map_status(status, &format!("secret '{name}'")).unwrap_err());
        }

        resp.json::<AzureSecret>()
            .await
            .map_err(AzureApiError::HttpError)
    }

    /// List all keys in the vault.
    pub async fn list_keys(&self) -> Result<Vec<AzureKeyItem>, AzureApiError> {
        let token = self.get_access_token().await?;
        let url = self.api_url("/keys");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(AzureApiError::HttpError)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(Self::map_status(status, "keys list").unwrap_err());
        }

        let body: ListResponse<AzureKeyItem> =
            resp.json().await.map_err(AzureApiError::HttpError)?;
        Ok(body.value)
    }

    /// List all certificates in the vault.
    pub async fn list_certificates(&self) -> Result<Vec<AzureCertItem>, AzureApiError> {
        let token = self.get_access_token().await?;
        let url = self.api_url("/certificates");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(AzureApiError::HttpError)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(Self::map_status(status, "certificates list").unwrap_err());
        }

        let body: ListResponse<AzureCertItem> =
            resp.json().await.map_err(AzureApiError::HttpError)?;
        Ok(body.value)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Unit tests: URL validation, deserialization, error display
    // -----------------------------------------------------------------------

    #[test]
    fn client_stores_base_url_trimmed() {
        let client = AzureKeyVaultClient::new(
            "http://localhost:8080/",
            "tenant".into(),
            "client".into(),
            "secret".into(),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = AzureKeyVaultClient::new(
            "http://localhost:8080",
            "tenant".into(),
            "client".into(),
            "secret".into(),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = AzureKeyVaultClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn client_debug_does_not_leak_secret() {
        let client = AzureKeyVaultClient::new(
            "http://localhost:8080",
            "tenant-123".into(),
            "client-456".into(),
            "super-secret".into(),
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("AzureKeyVaultClient"));
        assert!(debug.contains("tenant-123"));
        assert!(debug.contains("client-456"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn secret_item_deserialize() {
        let json = r#"{"id":"https://myvault.vault.azure.net/secrets/mysecret","attributes":{"enabled":true}}"#;
        let item: AzureSecretItem = serde_json::from_str(json).unwrap();
        assert!(item.id.contains("mysecret"));
        assert_eq!(item.attributes.unwrap().enabled, Some(true));
    }

    #[test]
    fn secret_deserialize_with_value() {
        let json = r#"{
            "id": "https://myvault.vault.azure.net/secrets/mysecret/version1",
            "value": "supersecret",
            "attributes": {"enabled": true}
        }"#;
        let secret: AzureSecret = serde_json::from_str(json).unwrap();
        assert!(secret.id.contains("mysecret"));
        assert_eq!(secret.value.as_deref(), Some("supersecret"));
    }

    #[test]
    fn secret_deserialize_minimal() {
        let json = r#"{"id": "https://myvault.vault.azure.net/secrets/test"}"#;
        let secret: AzureSecret = serde_json::from_str(json).unwrap();
        assert!(secret.value.is_none());
        assert!(secret.attributes.is_none());
    }

    #[test]
    fn key_item_deserialize() {
        let json =
            r#"{"kid":"https://myvault.vault.azure.net/keys/mykey","attributes":{"enabled":true}}"#;
        let item: AzureKeyItem = serde_json::from_str(json).unwrap();
        assert!(item.kid.contains("mykey"));
    }

    #[test]
    fn cert_item_deserialize() {
        let json = r#"{"id":"https://myvault.vault.azure.net/certificates/mycert","attributes":{"enabled":true}}"#;
        let item: AzureCertItem = serde_json::from_str(json).unwrap();
        assert!(item.id.contains("mycert"));
    }

    #[test]
    fn list_response_deserialize_secrets() {
        let json = r#"{
            "value": [
                {"id": "https://vault/secrets/a"},
                {"id": "https://vault/secrets/b"}
            ]
        }"#;
        let list: ListResponse<AzureSecretItem> = serde_json::from_str(json).unwrap();
        assert_eq!(list.value.len(), 2);
    }

    #[test]
    fn azure_api_error_display() {
        let err = AzureApiError::AuthError;
        assert!(format!("{err}").contains("authentication failed"));

        let err = AzureApiError::NotFound("secret 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = AzureApiError::Forbidden;
        assert!(format!("{err}").contains("forbidden"));

        let err = AzureApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = AzureApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));

        let err = AzureApiError::InvalidUrl("bad".into());
        assert!(format!("{err}").contains("invalid URL"));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://myvault.vault.azure.net").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080").unwrap();
        validate_url_scheme("http://127.0.0.1:9000/api").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://myvault.vault.azure.net").unwrap_err();
        assert!(matches!(err, AzureApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("insecure HTTP URL rejected"));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/file").unwrap_err();
        assert!(matches!(err, AzureApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("unsupported URL scheme"));
    }

    #[test]
    fn api_url_includes_version() {
        let client =
            AzureKeyVaultClient::new("http://localhost:8080", "t".into(), "c".into(), "s".into())
                .unwrap();
        let url = client.api_url("/secrets");
        assert_eq!(url, "http://localhost:8080/secrets?api-version=7.4");
    }

    #[test]
    fn map_status_returns_correct_errors() {
        assert!(AzureKeyVaultClient::map_status(200, "x").is_ok());
        assert!(AzureKeyVaultClient::map_status(204, "x").is_ok());
        assert!(matches!(
            AzureKeyVaultClient::map_status(401, "x").unwrap_err(),
            AzureApiError::AuthError
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(403, "x").unwrap_err(),
            AzureApiError::Forbidden
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(404, "x").unwrap_err(),
            AzureApiError::NotFound(_)
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(500, "x").unwrap_err(),
            AzureApiError::ServerError
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(418, "x").unwrap_err(),
            AzureApiError::UnexpectedStatus(418)
        ));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: start a mock server and create a client pointed at it,
    /// with OAuth token mocked.
    async fn setup_mock_client() -> (AzureKeyVaultClient, MockServer) {
        let mock_server = MockServer::start().await;

        // Mock the OAuth2 token endpoint.
        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fvault.azure.net%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock-azure-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let client = AzureKeyVaultClient::new(
            &mock_server.uri(),
            "test-tenant".into(),
            "test-client-id".into(),
            "test-client-secret".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        (client, mock_server)
    }

    #[tokio::test]
    async fn oauth_token_flow() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "my-azure-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AzureKeyVaultClient::new(
            &mock_server.uri(),
            "tenant".into(),
            "client-id".into(),
            "client-secret".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        let token = client.get_access_token().await.unwrap();
        assert_eq!(token, "my-azure-token");

        // Second call should use cache (mock expects only 1 call).
        let token2 = client.get_access_token().await.unwrap();
        assert_eq!(token2, "my-azure-token");
    }

    #[tokio::test]
    async fn oauth_token_auth_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "bad credentials"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AzureKeyVaultClient::new(
            &mock_server.uri(),
            "tenant".into(),
            "bad-client".into(),
            "bad-secret".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        let result = client.get_access_token().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::AuthError));
    }

    #[tokio::test]
    async fn list_secrets_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "https://vault/secrets/secret1", "attributes": {"enabled": true}},
                    {"id": "https://vault/secrets/secret2", "attributes": {"enabled": false}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secrets = client.list_secrets().await.unwrap();
        assert_eq!(secrets.len(), 2);
        assert!(secrets[0].id.contains("secret1"));
        assert!(secrets[1].id.contains("secret2"));
    }

    #[tokio::test]
    async fn list_secrets_unauthorized() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::AuthError));
    }

    #[tokio::test]
    async fn list_secrets_forbidden() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::Forbidden));
    }

    #[tokio::test]
    async fn list_secrets_server_error() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::ServerError));
    }

    #[tokio::test]
    async fn get_secret_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets/my-secret"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "https://vault/secrets/my-secret/version1",
                "value": "the-secret-value",
                "attributes": {"enabled": true}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secret = client.get_secret("my-secret", None).await.unwrap();
        assert!(secret.id.contains("my-secret"));
        assert_eq!(secret.value.as_deref(), Some("the-secret-value"));
    }

    #[tokio::test]
    async fn get_secret_with_version() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets/my-secret/abc123"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "https://vault/secrets/my-secret/abc123",
                "value": "versioned-value"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secret = client
            .get_secret("my-secret", Some("abc123"))
            .await
            .unwrap();
        assert_eq!(secret.value.as_deref(), Some("versioned-value"));
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets/missing"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.get_secret("missing", None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn set_secret_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("PUT"))
            .and(path("/secrets/new-secret"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "https://vault/secrets/new-secret/v1",
                "value": "new-value",
                "attributes": {"enabled": true}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secret = client.set_secret("new-secret", "new-value").await.unwrap();
        assert!(secret.id.contains("new-secret"));
        assert_eq!(secret.value.as_deref(), Some("new-value"));
    }

    #[tokio::test]
    async fn set_secret_forbidden() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("PUT"))
            .and(path("/secrets/restricted"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.set_secret("restricted", "val").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::Forbidden));
    }

    #[tokio::test]
    async fn list_keys_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/keys"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"kid": "https://vault/keys/key1", "attributes": {"enabled": true}},
                    {"kid": "https://vault/keys/key2", "attributes": {"enabled": true}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let keys = client.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].kid.contains("key1"));
        assert!(keys[1].kid.contains("key2"));
    }

    #[tokio::test]
    async fn list_keys_forbidden() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/keys"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_keys().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::Forbidden));
    }

    #[tokio::test]
    async fn list_certificates_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/certificates"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "https://vault/certificates/cert1", "attributes": {"enabled": true}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let certs = client.list_certificates().await.unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].id.contains("cert1"));
    }

    #[tokio::test]
    async fn list_certificates_server_error() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/certificates"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_certificates().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::ServerError));
    }

    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secrets = client.list_secrets().await.unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn user_agent_header_sent() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        client.list_secrets().await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .respond_with(ResponseTemplate::new(418)) // I'm a teapot
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(matches!(
            result.unwrap_err(),
            AzureApiError::UnexpectedStatus(418)
        ));
    }

    #[tokio::test]
    async fn token_cached_across_calls() {
        let mock_server = MockServer::start().await;

        // Token endpoint should be called only once.
        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "cached-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Two API calls should both use the cached token.
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "7.4"))
            .and(header("Authorization", "Bearer cached-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .expect(2)
            .mount(&mock_server)
            .await;

        let client =
            AzureKeyVaultClient::new(&mock_server.uri(), "t".into(), "c".into(), "s".into())
                .unwrap()
                .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        client.list_secrets().await.unwrap();
        client.list_secrets().await.unwrap();
    }
}
