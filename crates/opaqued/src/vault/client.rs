//! HashiCorp Vault HTTP client for secret-field reads.
//!
//! Supports extracting fields from both KV v1 and KV v2 style payloads.

use std::num::NonZeroU64;

/// Environment variable to override the default Vault API base URL.
pub const VAULT_URL_ENV: &str = "OPAQUE_VAULT_URL";

/// Default Vault API base URL.
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8200";

/// Vault API error types. Raw API responses are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum VaultApiError {
    #[error("network error communicating with Vault")]
    Network(#[source] reqwest::Error),

    #[error("Vault authentication failed (check token permissions)")]
    Unauthorized,

    #[error("Vault resource not found: {0}")]
    NotFound(String),

    #[error("Vault API rate limit exceeded")]
    RateLimited,

    #[error("Vault rejected request parameters")]
    BadRequest,

    #[error("Vault API server error")]
    ServerError,

    #[error("unexpected Vault API response: status {0}")]
    UnexpectedStatus(u16),

    #[error("{0}")]
    InvalidUrlScheme(String),

    #[error("Vault response is missing valid KV v2 version metadata")]
    MissingVersionMetadata,

    #[error("Vault returned version {actual}, expected pinned version {expected}")]
    VersionMismatch { expected: u64, actual: u64 },

    #[error("Vault pinned version {0} is deleted, destroyed, or unavailable")]
    VersionUnavailable(u64),
}

/// Validate that a URL uses `https://`, allowing `http://` only for localhost.
fn validate_url_scheme(url: &str) -> Result<(), VaultApiError> {
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
        return Err(VaultApiError::InvalidUrlScheme(format!(
            "insecure HTTP URL rejected: {url}. \
             Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
        )));
    }
    Err(VaultApiError::InvalidUrlScheme(format!(
        "unsupported URL scheme: {url}. \
         Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
    )))
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

/// Percent-encode each segment of a slash-delimited Vault path.
fn encode_vault_path(path: &str) -> String {
    path.split('/')
        .map(percent_encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

fn scalar_field_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Extract a string field from KV v1/v2 style response payloads.
fn extract_field_value(body: &serde_json::Value, field: &str) -> Option<String> {
    // KV v2 style: { "data": { "data": { <field>: <value> } } }
    if let Some(v2) = body
        .get("data")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get(field))
    {
        return scalar_field_value(v2);
    }

    // KV v1 style: { "data": { <field>: <value> } }
    if let Some(v1) = body.get("data").and_then(|v| v.get(field)) {
        return scalar_field_value(v1);
    }

    None
}

/// Lease metadata returned by Vault for dynamic secret engines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultLease {
    pub lease_id: String,
    pub lease_duration_secs: u64,
    pub renewable: bool,
}

/// Secret read result with optional lease metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSecretField {
    pub value: String,
    pub lease: Option<VaultLease>,
}

fn extract_lease(body: &serde_json::Value) -> Option<VaultLease> {
    let lease_id = body
        .get("lease_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if lease_id.is_empty() {
        return None;
    }

    let lease_duration_secs = body
        .get("lease_duration")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
        })
        .unwrap_or(0);
    if lease_duration_secs == 0 {
        return None;
    }

    Some(VaultLease {
        lease_id: lease_id.to_owned(),
        lease_duration_secs,
        renewable: body
            .get("renewable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

/// Vault REST API client.
#[derive(Debug, Clone)]
pub struct VaultClient {
    http: reqwest::Client,
    base_url: String,
}

impl VaultClient {
    /// Build the user-agent string from crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a client with env-configured or default base URL.
    pub fn new() -> Result<Self, VaultApiError> {
        let base_url = std::env::var(VAULT_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        validate_url_scheme(&base_url)?;
        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(VaultApiError::Network)?;

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
        })
    }

    /// Create a client at custom base URL (for tests).
    #[cfg(test)]
    pub fn with_base_url(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client");
        Self { http, base_url }
    }

    /// Return the client base URL (without trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Read a single secret field from Vault at the given path.
    #[allow(dead_code)]
    pub async fn read_secret_field(
        &self,
        token: &str,
        path: &str,
        field: &str,
    ) -> Result<String, VaultApiError> {
        self.read_secret_field_with_lease(token, path, field)
            .await
            .map(|result| result.value)
    }

    /// Read a single secret field and include lease metadata when present.
    pub async fn read_secret_field_with_lease(
        &self,
        token: &str,
        path: &str,
        field: &str,
    ) -> Result<VaultSecretField, VaultApiError> {
        self.read_secret_field_at_version(token, path, field, None)
            .await
    }

    /// Read one exact KV v2 version, or retain legacy unversioned behavior.
    /// Pinned reads require verified KV v2 metadata and never fall back to v1
    /// fields or the latest version. Version zero cannot be represented.
    pub async fn read_secret_field_at_version(
        &self,
        token: &str,
        path: &str,
        field: &str,
        version: Option<NonZeroU64>,
    ) -> Result<VaultSecretField, VaultApiError> {
        let path_trimmed = path.trim_matches('/');
        if path_trimmed.is_empty() {
            return Err(VaultApiError::NotFound("empty secret path".into()));
        }
        if field.is_empty() {
            return Err(VaultApiError::NotFound("empty secret field".into()));
        }

        let encoded_path = encode_vault_path(path_trimmed);
        let url = format!("{}/v1/{encoded_path}", self.base_url);
        let mut request = self
            .http
            .get(&url)
            .header("X-Vault-Token", token)
            .header("Accept", "application/json");
        if let Some(version) = version {
            request = request.query(&[("version", version.get())]);
        }
        let resp = request.send().await.map_err(VaultApiError::Network)?;

        match resp.status().as_u16() {
            200 => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(VaultApiError::Network)?;
                let value = if let Some(version) = version {
                    let metadata = body
                        .get("data")
                        .and_then(|data| data.get("metadata"))
                        .ok_or(VaultApiError::MissingVersionMetadata)?;
                    let actual = metadata
                        .get("version")
                        .and_then(|v| v.as_u64())
                        .filter(|v| *v > 0)
                        .ok_or(VaultApiError::MissingVersionMetadata)?;
                    if actual != version.get() {
                        return Err(VaultApiError::VersionMismatch {
                            expected: version.get(),
                            actual,
                        });
                    }
                    let destroyed = metadata
                        .get("destroyed")
                        .and_then(|v| v.as_bool())
                        .ok_or(VaultApiError::MissingVersionMetadata)?;
                    let deletion_time = metadata
                        .get("deletion_time")
                        .and_then(|v| v.as_str())
                        .ok_or(VaultApiError::MissingVersionMetadata)?;
                    if destroyed || !deletion_time.is_empty() {
                        return Err(VaultApiError::VersionUnavailable(version.get()));
                    }
                    let data = body
                        .get("data")
                        .and_then(|data| data.get("data"))
                        .filter(|data| data.is_object())
                        .ok_or(VaultApiError::VersionUnavailable(version.get()))?;
                    // Only the KV v2 data object can supply a pinned field.
                    data.get(field).and_then(scalar_field_value)
                } else {
                    extract_field_value(&body, field)
                }
                .ok_or_else(|| {
                    VaultApiError::NotFound(format!("field '{field}' at path '{path_trimmed}'"))
                })?;
                Ok(VaultSecretField {
                    value,
                    lease: extract_lease(&body),
                })
            }
            401 | 403 => Err(VaultApiError::Unauthorized),
            404 => Err(match version {
                Some(version) => VaultApiError::VersionUnavailable(version.get()),
                None => VaultApiError::NotFound(format!("path '{path_trimmed}'")),
            }),
            429 => Err(VaultApiError::RateLimited),
            500..=599 => Err(VaultApiError::ServerError),
            other => Err(VaultApiError::UnexpectedStatus(other)),
        }
    }

    /// Revoke a previously-issued Vault lease.
    pub async fn revoke_lease(&self, token: &str, lease_id: &str) -> Result<(), VaultApiError> {
        let lease_id_trimmed = lease_id.trim();
        if lease_id_trimmed.is_empty() {
            return Err(VaultApiError::BadRequest);
        }

        let url = format!("{}/v1/sys/leases/revoke", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", token)
            .header("Accept", "application/json")
            .json(&serde_json::json!({ "lease_id": lease_id_trimmed }))
            .send()
            .await
            .map_err(VaultApiError::Network)?;

        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            400 => Err(VaultApiError::BadRequest),
            401 | 403 => Err(VaultApiError::Unauthorized),
            404 => Err(VaultApiError::NotFound(format!(
                "lease '{lease_id_trimmed}'"
            ))),
            429 => Err(VaultApiError::RateLimited),
            500..=599 => Err(VaultApiError::ServerError),
            other => Err(VaultApiError::UnexpectedStatus(other)),
        }
    }

    /// Renew a previously-issued Vault lease.
    pub async fn renew_lease(
        &self,
        token: &str,
        lease_id: &str,
    ) -> Result<VaultLease, VaultApiError> {
        let lease_id_trimmed = lease_id.trim();
        if lease_id_trimmed.is_empty() {
            return Err(VaultApiError::BadRequest);
        }

        let url = format!("{}/v1/sys/leases/renew", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", token)
            .header("Accept", "application/json")
            .json(&serde_json::json!({ "lease_id": lease_id_trimmed }))
            .send()
            .await
            .map_err(VaultApiError::Network)?;

        match resp.status().as_u16() {
            200 => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(VaultApiError::Network)?;
                extract_lease(&body).ok_or(VaultApiError::ServerError)
            }
            400 => Err(VaultApiError::BadRequest),
            401 | 403 => Err(VaultApiError::Unauthorized),
            404 => Err(VaultApiError::NotFound(format!(
                "lease '{lease_id_trimmed}'"
            ))),
            429 => Err(VaultApiError::RateLimited),
            500..=599 => Err(VaultApiError::ServerError),
            other => Err(VaultApiError::UnexpectedStatus(other)),
        }
    }
}

impl Default for VaultClient {
    fn default() -> Self {
        Self::new().expect("invalid Vault URL scheme")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn user_agent_contains_version() {
        let ua = VaultClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn percent_encode_path_component() {
        assert_eq!(percent_encode_component("my app"), "my%20app");
        assert_eq!(percent_encode_component("A_B-1.2~x"), "A_B-1.2~x");
    }

    #[test]
    fn encode_vault_path_keeps_slashes() {
        assert_eq!(
            encode_vault_path("secret/data/my app"),
            "secret/data/my%20app"
        );
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://vault.example.com").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8200").unwrap();
        validate_url_scheme("http://127.0.0.1:8200").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://vault.example.com").unwrap_err();
        assert!(err.to_string().contains("insecure HTTP URL rejected"));
    }

    #[test]
    fn extract_field_value_supports_kv_v2() {
        let body = serde_json::json!({
            "data": {
                "data": { "DATABASE_URL": "postgres://example" }
            }
        });
        assert_eq!(
            extract_field_value(&body, "DATABASE_URL"),
            Some("postgres://example".into())
        );
    }

    #[test]
    fn extract_field_value_supports_kv_v1() {
        let body = serde_json::json!({
            "data": { "API_KEY": "abc123" }
        });
        assert_eq!(extract_field_value(&body, "API_KEY"), Some("abc123".into()));
    }

    #[test]
    fn extract_lease_supports_dynamic_secret_metadata() {
        let body = serde_json::json!({
            "lease_id": "database/creds/readonly/abc123",
            "lease_duration": 1800,
            "renewable": true
        });
        let lease = extract_lease(&body).expect("lease should parse");
        assert_eq!(lease.lease_id, "database/creds/readonly/abc123");
        assert_eq!(lease.lease_duration_secs, 1800);
        assert!(lease.renewable);
    }

    #[tokio::test]
    async fn read_secret_field_kv_v2_ok() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myapp"))
            .and(header("x-vault-token", "vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": { "DATABASE_URL": "postgres://example" }
                }
            })))
            .mount(&server)
            .await;

        let value = client
            .read_secret_field("vault-token", "secret/data/myapp", "DATABASE_URL")
            .await
            .unwrap();
        assert_eq!(value, "postgres://example");
    }

    fn pinned_response() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "data": { "FIELD": "approved-value" },
                "metadata": { "version": 7, "destroyed": false, "deletion_time": "" }
            }
        })
    }

    #[tokio::test]
    async fn pinned_read_sends_version_query_and_verifies_metadata() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/demo"))
            .and(header("x-vault-token", "disposable-token"))
            .and(query_param("version", "7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(pinned_response()))
            .expect(1)
            .mount(&server)
            .await;
        let result = client
            .read_secret_field_at_version(
                "disposable-token",
                "kv/data/demo",
                "FIELD",
                NonZeroU64::new(7),
            )
            .await
            .unwrap();
        assert_eq!(result.value, "approved-value");
        assert_eq!(
            server.received_requests().await.unwrap()[0].url.query(),
            Some("version=7")
        );
    }

    #[tokio::test]
    async fn pinned_read_rejects_wrong_or_missing_version_without_retry() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());
        for version in [
            serde_json::json!(8),
            serde_json::Value::Null,
            serde_json::json!("7"),
        ] {
            server.reset().await;
            let mut body = pinned_response();
            body["data"]["metadata"]["version"] = version.clone();
            Mock::given(method("GET"))
                .and(path("/v1/kv/data/demo"))
                .and(query_param("version", "7"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
            let err = client
                .read_secret_field_at_version(
                    "disposable-token",
                    "kv/data/demo",
                    "FIELD",
                    NonZeroU64::new(7),
                )
                .await
                .unwrap_err();
            if version == serde_json::json!(8) {
                assert!(matches!(
                    err,
                    VaultApiError::VersionMismatch {
                        expected: 7,
                        actual: 8
                    }
                ));
            } else {
                assert!(matches!(err, VaultApiError::MissingVersionMetadata));
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn pinned_read_rejects_deleted_destroyed_and_missing_versions() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());
        for (destroyed, deletion_time, status) in [
            (true, "", 200),
            (false, "2026-09-01T00:00:00Z", 200),
            (false, "", 404),
        ] {
            server.reset().await;
            let mut body = pinned_response();
            // Retaining data in the mocked response proves metadata is enforced
            // even when a broken backend returns a plaintext value alongside it.
            body["data"]["metadata"]["destroyed"] = destroyed.into();
            body["data"]["metadata"]["deletion_time"] = deletion_time.into();
            Mock::given(method("GET"))
                .and(path("/v1/kv/data/demo"))
                .and(query_param("version", "7"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
            let err = client
                .read_secret_field_at_version(
                    "disposable-token",
                    "kv/data/demo",
                    "FIELD",
                    NonZeroU64::new(7),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, VaultApiError::VersionUnavailable(7)));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn pinned_read_does_not_fall_back_to_v1_or_nested_fields() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());
        let mut body = pinned_response();
        body["data"]["data"] = serde_json::json!({ "data": { "FIELD": "nested-value" } });
        body["data"]["FIELD"] = "v1-fallback".into();
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/demo"))
            .and(query_param("version", "7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let err = client
            .read_secret_field_at_version(
                "disposable-token",
                "kv/data/demo",
                "FIELD",
                NonZeroU64::new(7),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn pinned_read_does_not_follow_redirect_to_latest() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/demo"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("Location", "/v1/kv/data/latest"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let err = client
            .read_secret_field_at_version(
                "disposable-token",
                "kv/data/demo",
                "FIELD",
                NonZeroU64::new(7),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::UnexpectedStatus(307)));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn read_secret_field_with_lease_returns_metadata() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/readonly"))
            .and(header("x-vault-token", "vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/abcd",
                "lease_duration": 60,
                "renewable": true,
                "data": {
                    "username": "v-root",
                    "password": "v-pass"
                }
            })))
            .mount(&server)
            .await;

        let result = client
            .read_secret_field_with_lease("vault-token", "database/creds/readonly", "password")
            .await
            .unwrap();
        assert_eq!(result.value, "v-pass");
        let lease = result.lease.expect("lease metadata should be present");
        assert_eq!(lease.lease_id, "database/creds/readonly/abcd");
        assert_eq!(lease.lease_duration_secs, 60);
        assert!(lease.renewable);
    }

    #[tokio::test]
    async fn read_secret_field_field_missing() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myapp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "data": { "OTHER_KEY": "x" } }
            })))
            .mount(&server)
            .await;

        let err = client
            .read_secret_field("vault-token", "secret/data/myapp", "DATABASE_URL")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn read_secret_field_maps_unauthorized() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myapp"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let err = client
            .read_secret_field("vault-token", "secret/data/myapp", "DATABASE_URL")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::Unauthorized));
    }

    #[tokio::test]
    async fn revoke_lease_posts_expected_payload() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/revoke"))
            .and(header("x-vault-token", "vault-token"))
            .and(body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1"
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        client
            .revoke_lease("vault-token", "database/creds/readonly/a1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn renew_lease_posts_expected_payload() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("x-vault-token", "vault-token"))
            .and(body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a2",
                "lease_duration": 120,
                "renewable": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        let renewed = client
            .renew_lease("vault-token", "database/creds/readonly/a1")
            .await
            .unwrap();
        assert_eq!(renewed.lease_id, "database/creds/readonly/a2");
        assert_eq!(renewed.lease_duration_secs, 120);
        assert!(renewed.renewable);
    }

    #[tokio::test]
    async fn renew_lease_maps_unauthorized() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let err = client
            .renew_lease("vault-token", "database/creds/readonly/a1")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::Unauthorized));
    }

    #[tokio::test]
    async fn renew_lease_maps_bad_request() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let err = client
            .renew_lease("vault-token", "database/creds/readonly/a1")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::BadRequest));
    }

    #[tokio::test]
    async fn renew_lease_maps_not_found() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = client
            .renew_lease("vault-token", "database/creds/readonly/a1")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn renew_lease_maps_rate_limit() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let err = client
            .renew_lease("vault-token", "database/creds/readonly/a1")
            .await
            .unwrap_err();
        assert!(matches!(err, VaultApiError::RateLimited));
    }
}
