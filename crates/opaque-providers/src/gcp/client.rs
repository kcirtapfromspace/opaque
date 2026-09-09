//! Google Cloud Secret Manager API client.
//!
//! Wraps the REST endpoints needed to list, create, and access secrets
//! via the GCP Secret Manager API v1.
//!
//! **Never** leaks raw API error bodies to callers -- all errors are
//! mapped to sanitized strings.
//!
//! Authentication:
//! - `OPAQUE_GCP_ACCESS_TOKEN` env var for direct token
//! - `OPAQUE_GCP_SERVICE_ACCOUNT_KEY` env var for service account JSON key file
//! - JWT creation: sign with RS256, exchange at `https://oauth2.googleapis.com/token`
//! - Token caching with expiry

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Environment variable to override the default GCP Secret Manager base URL.
pub const GCP_SM_URL_ENV: &str = "OPAQUE_GCP_SM_URL";

/// Default GCP Secret Manager API base URL.
pub const DEFAULT_BASE_URL: &str = "https://secretmanager.googleapis.com/v1";

/// Environment variable for a direct GCP access token.
pub const GCP_ACCESS_TOKEN_ENV: &str = "OPAQUE_GCP_ACCESS_TOKEN";

/// Environment variable for the path to a GCP service account JSON key file.
pub const GCP_SERVICE_ACCOUNT_KEY_ENV: &str = "OPAQUE_GCP_SERVICE_ACCOUNT_KEY";

#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};

    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("gcp test env lock poisoned")
}

/// Google OAuth2 token endpoint.
const OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// GCP Secret Manager API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum GcpApiError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("network error communicating with GCP Secret Manager")]
    HttpError(#[source] reqwest::Error),

    #[error("GCP Secret Manager authentication failed")]
    AuthError(String),

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("GCP Secret Manager permission denied")]
    PermissionDenied,

    #[error("GCP Secret Manager server error")]
    ServerError,

    #[error("unexpected GCP Secret Manager response: status {0}")]
    UnexpectedStatus(u16),
}

/// A GCP secret resource.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpSecret {
    /// Full resource name: `projects/*/secrets/*`
    pub name: String,
    /// Replication policy (simplified).
    #[serde(default)]
    pub replication: Option<serde_json::Value>,
    /// Create time.
    #[serde(default, rename = "createTime")]
    pub create_time: Option<String>,
}

/// A GCP secret version resource.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpSecretVersion {
    /// Full resource name: `projects/*/secrets/*/versions/*`
    pub name: String,
    /// State of the version.
    #[serde(default)]
    pub state: Option<String>,
    /// Create time.
    #[serde(default, rename = "createTime")]
    pub create_time: Option<String>,
}

/// Payload returned by the access endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpSecretPayload {
    /// Base64-encoded secret data.
    pub data: String,
}

/// Response from the access endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpAccessSecretVersionResponse {
    /// The secret version name.
    #[serde(default)]
    pub name: Option<String>,
    /// The actual secret payload.
    pub payload: GcpSecretPayload,
}

/// Response from the list secrets endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpListSecretsResponse {
    #[serde(default)]
    pub secrets: Vec<GcpSecret>,
    #[serde(default, rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

/// Request body for adding a new secret version.
#[derive(Debug, Serialize)]
struct AddSecretVersionRequest {
    payload: AddSecretVersionPayload,
}

#[derive(Debug, Serialize)]
struct AddSecretVersionPayload {
    data: String,
}

/// Request body for creating a new secret.
#[derive(Debug, Serialize)]
struct CreateSecretRequest {
    replication: CreateSecretReplication,
}

#[derive(Debug, Serialize)]
struct CreateSecretReplication {
    automatic: serde_json::Value,
}

/// Cached OAuth2 access token.
#[derive(Debug)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Service account key file structure.
#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}

/// OAuth2 token response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Validate that a URL uses `https://`, allowing `http://` only for localhost.
fn validate_url_scheme(url: &str) -> Result<(), GcpApiError> {
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
        return Err(GcpApiError::InvalidUrl(format!(
            "insecure HTTP URL rejected: {url}. \
             Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
        )));
    }
    Err(GcpApiError::InvalidUrl(format!(
        "unsupported URL scheme: {url}. \
         Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
    )))
}

/// GCP Secret Manager REST API client.
///
/// Follows the same pattern as `BitwardenClient`: timeouts, user-agent,
/// and URL validation. Supports both direct token and service account
/// JWT-based authentication.
#[derive(Debug)]
pub struct GcpSecretManagerClient {
    http: reqwest::Client,
    base_url: String,
    /// Cached OAuth2 token (from JWT exchange).
    token_cache: Mutex<Option<CachedToken>>,
}

impl GcpSecretManagerClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client pointing at the given GCP Secret Manager URL.
    ///
    /// Returns an error if the base URL uses an unsupported scheme.
    pub fn new(base_url: &str) -> Result<Self, GcpApiError> {
        validate_url_scheme(base_url)?;

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(GcpApiError::HttpError)?;

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            token_cache: Mutex::new(None),
        })
    }

    /// Obtain a valid access token.
    ///
    /// Priority:
    /// 1. Direct token from `OPAQUE_GCP_ACCESS_TOKEN`
    /// 2. Cached token (if not expired)
    /// 3. Fresh token from service account JWT exchange
    pub async fn get_access_token(&self) -> Result<String, GcpApiError> {
        // 1. Direct token from env var.
        if let Ok(token) = std::env::var(GCP_ACCESS_TOKEN_ENV)
            && !token.is_empty()
        {
            return Ok(token);
        }

        // 2. Check cached token.
        {
            let cache = self.token_cache.lock().unwrap();
            if let Some(ref cached) = *cache
                && cached.expires_at > Instant::now()
            {
                return Ok(cached.token.clone());
            }
        }

        // 3. Exchange service account JWT for access token.
        let key_path = std::env::var(GCP_SERVICE_ACCOUNT_KEY_ENV).map_err(|_| {
            GcpApiError::AuthError(format!(
                "neither {GCP_ACCESS_TOKEN_ENV} nor {GCP_SERVICE_ACCOUNT_KEY_ENV} is set"
            ))
        })?;

        let key_contents = std::fs::read_to_string(&key_path).map_err(|e| {
            GcpApiError::AuthError(format!("failed to read service account key file: {e}"))
        })?;

        let sa_key: ServiceAccountKey = serde_json::from_str(&key_contents).map_err(|e| {
            GcpApiError::AuthError(format!("failed to parse service account key JSON: {e}"))
        })?;

        let token_uri = sa_key.token_uri.as_deref().unwrap_or(OAUTH2_TOKEN_URL);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_jwt(&sa_key.client_email, &sa_key.private_key, now)?;

        let token_resp = self
            .http
            .post(token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| GcpApiError::AuthError(format!("token exchange failed: {e}")))?;

        if !token_resp.status().is_success() {
            return Err(GcpApiError::AuthError(
                "OAuth2 token exchange returned non-success status".into(),
            ));
        }

        let token_data: TokenResponse = token_resp
            .json()
            .await
            .map_err(|e| GcpApiError::AuthError(format!("failed to parse token response: {e}")))?;

        // Cache with 60 second margin.
        let expires_at =
            Instant::now() + Duration::from_secs(token_data.expires_in.saturating_sub(60));
        let token = token_data.access_token.clone();
        {
            let mut cache = self.token_cache.lock().unwrap();
            *cache = Some(CachedToken {
                token: token_data.access_token,
                expires_at,
            });
        }

        Ok(token)
    }

    /// List all secrets in a project.
    pub async fn list_secrets(
        &self,
        token: &str,
        project: &str,
    ) -> Result<Vec<GcpSecret>, GcpApiError> {
        let url = format!("{}/projects/{}/secrets", self.base_url, project);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(GcpApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => {
                let list_resp: GcpListSecretsResponse =
                    resp.json().await.map_err(GcpApiError::HttpError)?;
                Ok(list_resp.secrets)
            }
            401 => Err(GcpApiError::AuthError("authentication failed".into())),
            403 => Err(GcpApiError::PermissionDenied),
            404 => Err(GcpApiError::NotFound(format!("project {project}"))),
            500..=599 => Err(GcpApiError::ServerError),
            other => Err(GcpApiError::UnexpectedStatus(other)),
        }
    }

    /// Get a single secret resource.
    pub async fn get_secret(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
    ) -> Result<GcpSecret, GcpApiError> {
        let url = format!(
            "{}/projects/{}/secrets/{}",
            self.base_url, project, secret_id
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(GcpApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<GcpSecret>()
                .await
                .map_err(GcpApiError::HttpError),
            401 => Err(GcpApiError::AuthError("authentication failed".into())),
            403 => Err(GcpApiError::PermissionDenied),
            404 => Err(GcpApiError::NotFound(format!("secret {secret_id}"))),
            500..=599 => Err(GcpApiError::ServerError),
            other => Err(GcpApiError::UnexpectedStatus(other)),
        }
    }

    /// Access a specific version of a secret (returns the payload data).
    pub async fn access_secret_version(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
        version: &str,
    ) -> Result<GcpAccessSecretVersionResponse, GcpApiError> {
        let url = format!(
            "{}/projects/{}/secrets/{}/versions/{}:access",
            self.base_url, project, secret_id, version
        );

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(GcpApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<GcpAccessSecretVersionResponse>()
                .await
                .map_err(GcpApiError::HttpError),
            401 => Err(GcpApiError::AuthError("authentication failed".into())),
            403 => Err(GcpApiError::PermissionDenied),
            404 => Err(GcpApiError::NotFound(format!(
                "secret {secret_id} version {version}"
            ))),
            500..=599 => Err(GcpApiError::ServerError),
            other => Err(GcpApiError::UnexpectedStatus(other)),
        }
    }

    /// Add a new version to an existing secret.
    pub async fn add_secret_version(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
        payload: &[u8],
    ) -> Result<GcpSecretVersion, GcpApiError> {
        let url = format!(
            "{}/projects/{}/secrets/{}:addVersion",
            self.base_url, project, secret_id
        );

        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let body = AddSecretVersionRequest {
            payload: AddSecretVersionPayload { data: encoded },
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(GcpApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<GcpSecretVersion>()
                .await
                .map_err(GcpApiError::HttpError),
            401 => Err(GcpApiError::AuthError("authentication failed".into())),
            403 => Err(GcpApiError::PermissionDenied),
            404 => Err(GcpApiError::NotFound(format!("secret {secret_id}"))),
            500..=599 => Err(GcpApiError::ServerError),
            other => Err(GcpApiError::UnexpectedStatus(other)),
        }
    }

    /// Create a new secret in a project.
    pub async fn create_secret(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
    ) -> Result<GcpSecret, GcpApiError> {
        let url = format!(
            "{}/projects/{}/secrets?secretId={}",
            self.base_url, project, secret_id
        );

        let body = CreateSecretRequest {
            replication: CreateSecretReplication {
                automatic: serde_json::json!({}),
            },
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(GcpApiError::HttpError)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<GcpSecret>()
                .await
                .map_err(GcpApiError::HttpError),
            401 => Err(GcpApiError::AuthError("authentication failed".into())),
            403 => Err(GcpApiError::PermissionDenied),
            404 => Err(GcpApiError::NotFound(format!("project {project}"))),
            409 => Err(GcpApiError::UnexpectedStatus(409)), // Conflict -- secret already exists
            500..=599 => Err(GcpApiError::ServerError),
            other => Err(GcpApiError::UnexpectedStatus(other)),
        }
    }
}

/// Create a signed JWT assertion for the Google OAuth2 token exchange.
///
/// The JWT is signed using RS256 (RSA + SHA-256) as required by Google's
/// OAuth2 server-to-server flow.
fn create_jwt(
    client_email: &str,
    private_key_pem: &str,
    now_secs: u64,
) -> Result<String, GcpApiError> {
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT"
    });

    let claims = serde_json::json!({
        "iss": client_email,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": OAUTH2_TOKEN_URL,
        "iat": now_secs,
        "exp": now_secs + 3600,
    });

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = b64.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| GcpApiError::AuthError(format!("invalid RSA private key: {e}")))?;

    let signature = jsonwebtoken::crypto::sign(
        signing_input.as_bytes(),
        &key,
        jsonwebtoken::Algorithm::RS256,
    )
    .map_err(|e| GcpApiError::AuthError(format!("JWT signing failed: {e}")))?;

    Ok(format!("{signing_input}.{signature}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;

    #[test]
    fn client_stores_base_url_trimmed() {
        let client = GcpSecretManagerClient::new("http://localhost:8080/").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = GcpSecretManagerClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = GcpSecretManagerClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn gcp_secret_deserialize() {
        let json = r#"{"name":"projects/my-project/secrets/my-secret","createTime":"2024-01-01T00:00:00Z"}"#;
        let secret: GcpSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.name, "projects/my-project/secrets/my-secret");
        assert_eq!(secret.create_time.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn gcp_secret_deserialize_minimal() {
        let json = r#"{"name":"projects/p/secrets/s"}"#;
        let secret: GcpSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.name, "projects/p/secrets/s");
        assert!(secret.create_time.is_none());
        assert!(secret.replication.is_none());
    }

    #[test]
    fn gcp_secret_version_deserialize() {
        let json = r#"{"name":"projects/p/secrets/s/versions/1","state":"ENABLED","createTime":"2024-01-01T00:00:00Z"}"#;
        let version: GcpSecretVersion = serde_json::from_str(json).unwrap();
        assert_eq!(version.name, "projects/p/secrets/s/versions/1");
        assert_eq!(version.state.as_deref(), Some("ENABLED"));
    }

    #[test]
    fn gcp_secret_payload_deserialize() {
        let json = r#"{"data":"c2VjcmV0"}"#;
        let payload: GcpSecretPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.data, "c2VjcmV0");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&payload.data)
            .unwrap();
        assert_eq!(decoded, b"secret");
    }

    #[test]
    fn gcp_access_response_deserialize() {
        let json = r#"{"name":"projects/p/secrets/s/versions/1","payload":{"data":"c2VjcmV0"}}"#;
        let resp: GcpAccessSecretVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            resp.name.as_deref(),
            Some("projects/p/secrets/s/versions/1")
        );
        assert_eq!(resp.payload.data, "c2VjcmV0");
    }

    #[test]
    fn gcp_list_secrets_response_deserialize() {
        let json =
            r#"{"secrets":[{"name":"projects/p/secrets/a"},{"name":"projects/p/secrets/b"}]}"#;
        let resp: GcpListSecretsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.secrets.len(), 2);
        assert_eq!(resp.secrets[0].name, "projects/p/secrets/a");
        assert_eq!(resp.secrets[1].name, "projects/p/secrets/b");
    }

    #[test]
    fn gcp_list_secrets_response_empty() {
        let json = r#"{}"#;
        let resp: GcpListSecretsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.secrets.is_empty());
    }

    #[test]
    fn gcp_api_error_display() {
        let err = GcpApiError::AuthError("token expired".into());
        assert!(format!("{err}").contains("authentication failed"));

        let err = GcpApiError::NotFound("secret my-secret".into());
        assert!(format!("{err}").contains("not found"));

        let err = GcpApiError::PermissionDenied;
        assert!(format!("{err}").contains("permission denied"));

        let err = GcpApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = GcpApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));

        let err = GcpApiError::InvalidUrl("bad://url".into());
        assert!(format!("{err}").contains("invalid URL"));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://secretmanager.googleapis.com/v1").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080").unwrap();
        validate_url_scheme("http://127.0.0.1:9000/v1").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://secretmanager.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, GcpApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("insecure HTTP URL rejected"));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/file").unwrap_err();
        assert!(matches!(err, GcpApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("unsupported URL scheme"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_secrets_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": [
                    {"name": "projects/my-project/secrets/db-password"},
                    {"name": "projects/my-project/secrets/api-key"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("test-token", "my-project")
            .await
            .unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].name, "projects/my-project/secrets/db-password");
        assert_eq!(secrets[1].name, "projects/my-project/secrets/api-key");
    }

    #[tokio::test]
    async fn list_secrets_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("test-token", "my-project")
            .await
            .unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn list_secrets_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("bad-token", "my-project").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::AuthError(_)));
    }

    #[tokio::test]
    async fn list_secrets_permission_denied() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("token", "my-project").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::PermissionDenied));
    }

    #[tokio::test]
    async fn list_secrets_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("token", "my-project").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::ServerError));
    }

    #[tokio::test]
    async fn get_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets/my-secret"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/my-secret",
                "createTime": "2024-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secret = client
            .get_secret("test-token", "my-project", "my-secret")
            .await
            .unwrap();

        assert_eq!(secret.name, "projects/my-project/secrets/my-secret");
        assert_eq!(secret.create_time.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/my-project/secrets/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.get_secret("token", "my-project", "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn access_secret_version_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/projects/my-project/secrets/my-secret/versions/latest:access",
            ))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/my-secret/versions/1",
                "payload": {
                    "data": "c2VjcmV0LXZhbHVl"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let resp = client
            .access_secret_version("test-token", "my-project", "my-secret", "latest")
            .await
            .unwrap();

        assert_eq!(resp.payload.data, "c2VjcmV0LXZhbHVl");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&resp.payload.data)
            .unwrap();
        assert_eq!(decoded, b"secret-value");
    }

    #[tokio::test]
    async fn access_secret_version_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/projects/my-project/secrets/my-secret/versions/99:access",
            ))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .access_secret_version("token", "my-project", "my-secret", "99")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn add_secret_version_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/my-project/secrets/my-secret:addVersion"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/my-secret/versions/2",
                "state": "ENABLED"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let version = client
            .add_secret_version("test-token", "my-project", "my-secret", b"new-value")
            .await
            .unwrap();

        assert_eq!(
            version.name,
            "projects/my-project/secrets/my-secret/versions/2"
        );
        assert_eq!(version.state.as_deref(), Some("ENABLED"));
    }

    #[tokio::test]
    async fn add_secret_version_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/my-project/secrets/missing:addVersion"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .add_secret_version("token", "my-project", "missing", b"val")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn create_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/my-project/secrets"))
            .and(query_param("secretId", "new-secret"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/my-project/secrets/new-secret",
                "createTime": "2024-06-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secret = client
            .create_secret("test-token", "my-project", "new-secret")
            .await
            .unwrap();

        assert_eq!(secret.name, "projects/my-project/secrets/new-secret");
    }

    #[tokio::test]
    async fn create_secret_permission_denied() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/my-project/secrets"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .create_secret("token", "my-project", "new-secret")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::PermissionDenied));
    }

    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/proj/secrets"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"secrets": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("my-secret-token", "proj")
            .await
            .unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/proj/secrets"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"secrets": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        client.list_secrets("token", "proj").await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/proj/secrets"))
            .respond_with(ResponseTemplate::new(418))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("token", "proj").await;
        assert!(matches!(
            result.unwrap_err(),
            GcpApiError::UnexpectedStatus(418)
        ));
    }

    #[tokio::test]
    async fn oauth_token_exchange_success() {
        let _env_guard = test_env_lock();
        let mock_server = MockServer::start().await;

        // Mock the token endpoint.
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.exchanged-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Create a temp key file with a test RSA key.
        let sa_key = serde_json::json!({
            "client_email": "test@project.iam.gserviceaccount.com",
            "private_key": include_str!("../../tests/fixtures/test_rsa_key.pem"),
            "token_uri": format!("{}/token", mock_server.uri())
        });

        let tmp_dir =
            std::env::temp_dir().join(format!("opaque_gcp_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let key_path = tmp_dir.join("sa_key.json");
        std::fs::write(&key_path, serde_json::to_string(&sa_key).unwrap()).unwrap();

        // Set env vars for service account auth.
        unsafe {
            std::env::remove_var(GCP_ACCESS_TOKEN_ENV);
            std::env::set_var(GCP_SERVICE_ACCOUNT_KEY_ENV, key_path.to_str().unwrap());
        }

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let token = client.get_access_token().await.unwrap();
        assert_eq!(token, "ya29.exchanged-token");

        // Second call should use cached token.
        // (Mock expects exactly 1 call, so a second HTTP call would fail.)
        let token2 = client.get_access_token().await.unwrap();
        assert_eq!(token2, "ya29.exchanged-token");

        // Cleanup.
        unsafe {
            std::env::remove_var(GCP_SERVICE_ACCOUNT_KEY_ENV);
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn direct_access_token_takes_priority() {
        let _env_guard = test_env_lock();
        let unique_token = format!("direct-token-{}", uuid::Uuid::new_v4().as_simple());
        unsafe {
            std::env::set_var(GCP_ACCESS_TOKEN_ENV, &unique_token);
        }

        let client = GcpSecretManagerClient::new("http://localhost:9999").unwrap();
        let token = client.get_access_token().await.unwrap();
        assert_eq!(token, unique_token);

        unsafe {
            std::env::remove_var(GCP_ACCESS_TOKEN_ENV);
        }
    }

    #[tokio::test]
    async fn auth_error_when_no_credentials() {
        let _env_guard = test_env_lock();
        unsafe {
            std::env::remove_var(GCP_ACCESS_TOKEN_ENV);
            std::env::remove_var(GCP_SERVICE_ACCOUNT_KEY_ENV);
        }

        let client = GcpSecretManagerClient::new("http://localhost:9999").unwrap();
        let result = client.get_access_token().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::AuthError(_)));
    }
}
