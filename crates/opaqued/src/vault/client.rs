//! HashiCorp Vault HTTP client for secret-field reads.
//!
//! Supports extracting fields from both KV v1 and KV v2 style payloads.

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

    #[error("Vault API server error")]
    ServerError,

    #[error("unexpected Vault API response: status {0}")]
    UnexpectedStatus(u16),
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

/// Percent-encode each segment of a slash-delimited Vault path.
fn encode_vault_path(path: &str) -> String {
    path.split('/')
        .map(percent_encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

/// Extract a string field from KV v1/v2 style response payloads.
fn extract_field_value(body: &serde_json::Value, field: &str) -> Option<String> {
    // KV v2 style: { "data": { "data": { <field>: <value> } } }
    if let Some(v2) = body
        .get("data")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get(field))
    {
        return match v2 {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        };
    }

    // KV v1 style: { "data": { <field>: <value> } }
    if let Some(v1) = body.get("data").and_then(|v| v.get(field)) {
        return match v1 {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        };
    }

    None
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
    pub fn new() -> Self {
        let base_url = std::env::var(VAULT_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        validate_url_scheme(&base_url);
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

    /// Create a client at custom base URL (for tests).
    #[cfg(test)]
    pub fn with_base_url(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");
        Self { http, base_url }
    }

    /// Read a single secret field from Vault at the given path.
    pub async fn read_secret_field(
        &self,
        token: &str,
        path: &str,
        field: &str,
    ) -> Result<String, VaultApiError> {
        let path_trimmed = path.trim_matches('/');
        if path_trimmed.is_empty() {
            return Err(VaultApiError::NotFound("empty secret path".into()));
        }
        if field.is_empty() {
            return Err(VaultApiError::NotFound("empty secret field".into()));
        }

        let encoded_path = encode_vault_path(path_trimmed);
        let url = format!("{}/v1/{encoded_path}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(VaultApiError::Network)?;

        match resp.status().as_u16() {
            200 => {
                let body = resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(VaultApiError::Network)?;
                extract_field_value(&body, field).ok_or_else(|| {
                    VaultApiError::NotFound(format!("field '{field}' at path '{path_trimmed}'"))
                })
            }
            401 | 403 => Err(VaultApiError::Unauthorized),
            404 => Err(VaultApiError::NotFound(format!("path '{path_trimmed}'"))),
            429 => Err(VaultApiError::RateLimited),
            500..=599 => Err(VaultApiError::ServerError),
            other => Err(VaultApiError::UnexpectedStatus(other)),
        }
    }
}

impl Default for VaultClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
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
        validate_url_scheme("https://vault.example.com");
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8200");
        validate_url_scheme("http://127.0.0.1:8200");
    }

    #[test]
    #[should_panic(expected = "insecure HTTP URL rejected")]
    fn validate_url_scheme_rejects_remote_http() {
        validate_url_scheme("http://vault.example.com");
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
}
