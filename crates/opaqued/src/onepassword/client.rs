//! 1Password Connect Server API client.
//!
//! Wraps the REST endpoints needed to browse vaults/items and resolve
//! secret fields via a self-hosted 1Password Connect Server.
//!
//! **Never** leaks raw API error bodies to callers — all errors are
//! mapped to sanitized strings.

use serde::{Deserialize, Serialize};

/// Environment variable to set the 1Password Connect Server base URL.
pub const CONNECT_URL_ENV: &str = "OPAQUE_1PASSWORD_CONNECT_URL";

/// 1Password Connect API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum ConnectApiError {
    #[error("network error communicating with 1Password Connect")]
    Network(#[source] reqwest::Error),

    #[error("1Password Connect authentication failed (check bearer token)")]
    Unauthorized,

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("1Password Connect server error")]
    ServerError,

    #[error("unexpected 1Password Connect response: status {0}")]
    UnexpectedStatus(u16),
}

/// A 1Password vault.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Vault {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// A 1Password item summary (returned by list endpoints).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub category: String,
}

/// A 1Password item with field values.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Item {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub fields: Vec<Field>,
}

/// A single field on a 1Password item.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Field {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
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

/// 1Password Connect REST API client.
///
/// Follows the same pattern as `GitHubClient`: no stored token (passed
/// per-call), timeouts, and a user-agent header.
#[derive(Debug, Clone)]
pub struct OnePasswordClient {
    http: reqwest::Client,
    base_url: String,
}

impl OnePasswordClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client pointing at the given Connect Server URL.
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

    /// List all vaults accessible with the given token.
    pub async fn list_vaults(&self, token: &str) -> Result<Vec<Vault>, ConnectApiError> {
        let url = format!("{}/v1/vaults", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(ConnectApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<Vec<Vault>>()
                .await
                .map_err(ConnectApiError::Network),
            401 | 403 => Err(ConnectApiError::Unauthorized),
            404 => Err(ConnectApiError::NotFound("vaults endpoint".into())),
            500..=599 => Err(ConnectApiError::ServerError),
            other => Err(ConnectApiError::UnexpectedStatus(other)),
        }
    }

    /// List items in a vault (titles only, no field values).
    pub async fn list_items(
        &self,
        token: &str,
        vault_id: &str,
    ) -> Result<Vec<ItemSummary>, ConnectApiError> {
        let url = format!("{}/v1/vaults/{}/items", self.base_url, vault_id);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(ConnectApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp
                .json::<Vec<ItemSummary>>()
                .await
                .map_err(ConnectApiError::Network),
            401 | 403 => Err(ConnectApiError::Unauthorized),
            404 => Err(ConnectApiError::NotFound(format!("vault {vault_id}"))),
            500..=599 => Err(ConnectApiError::ServerError),
            other => Err(ConnectApiError::UnexpectedStatus(other)),
        }
    }

    /// Get a single item with all field values.
    pub async fn get_item(
        &self,
        token: &str,
        vault_id: &str,
        item_id: &str,
    ) -> Result<Item, ConnectApiError> {
        let url = format!("{}/v1/vaults/{}/items/{}", self.base_url, vault_id, item_id);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(ConnectApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp.json::<Item>().await.map_err(ConnectApiError::Network),
            401 | 403 => Err(ConnectApiError::Unauthorized),
            404 => Err(ConnectApiError::NotFound(format!(
                "item {item_id} in vault {vault_id}"
            ))),
            500..=599 => Err(ConnectApiError::ServerError),
            other => Err(ConnectApiError::UnexpectedStatus(other)),
        }
    }

    /// Resolve a vault title to its ID by listing all vaults and matching by name.
    pub async fn find_vault_by_name(
        &self,
        token: &str,
        name: &str,
    ) -> Result<String, ConnectApiError> {
        let vaults = self.list_vaults(token).await?;
        vaults
            .into_iter()
            .find(|v| v.name == name)
            .map(|v| v.id)
            .ok_or_else(|| ConnectApiError::NotFound(format!("vault '{name}'")))
    }

    /// Resolve an item title to its ID within a vault.
    pub async fn find_item_by_title(
        &self,
        token: &str,
        vault_id: &str,
        title: &str,
    ) -> Result<String, ConnectApiError> {
        let items = self.list_items(token, vault_id).await?;
        items
            .into_iter()
            .find(|i| i.title == title)
            .map(|i| i.id)
            .ok_or_else(|| ConnectApiError::NotFound(format!("item '{title}' in vault")))
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
        let client = OnePasswordClient::new("http://localhost:8080/");
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = OnePasswordClient::new("http://localhost:8080");
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = OnePasswordClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn vault_deserialize() {
        let json = r#"{"id":"abc123","name":"Personal","description":"My vault"}"#;
        let vault: Vault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.id, "abc123");
        assert_eq!(vault.name, "Personal");
        assert_eq!(vault.description.as_deref(), Some("My vault"));
    }

    #[test]
    fn vault_deserialize_no_description() {
        let json = r#"{"id":"abc123","name":"Personal"}"#;
        let vault: Vault = serde_json::from_str(json).unwrap();
        assert!(vault.description.is_none());
    }

    #[test]
    fn item_summary_deserialize() {
        let json = r#"{"id":"item1","title":"GitHub Token","category":"LOGIN"}"#;
        let item: ItemSummary = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "item1");
        assert_eq!(item.title, "GitHub Token");
        assert_eq!(item.category, "LOGIN");
    }

    #[test]
    fn item_deserialize_with_fields() {
        let json = r#"{
            "id": "item1",
            "title": "GitHub Token",
            "fields": [
                {"id": "f1", "label": "username", "value": "user@example.com"},
                {"id": "f2", "label": "password", "value": "secret123"}
            ]
        }"#;
        let item: Item = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "item1");
        assert_eq!(item.title, "GitHub Token");
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].label.as_deref(), Some("username"));
        assert_eq!(item.fields[1].label.as_deref(), Some("password"));
        assert_eq!(item.fields[1].value.as_deref(), Some("secret123"));
    }

    #[test]
    fn item_deserialize_empty_fields() {
        let json = r#"{"id": "item1", "title": "Empty"}"#;
        let item: Item = serde_json::from_str(json).unwrap();
        assert!(item.fields.is_empty());
    }

    #[test]
    fn field_deserialize_optional_values() {
        let json = r#"{"id": "f1"}"#;
        let field: Field = serde_json::from_str(json).unwrap();
        assert!(field.label.is_none());
        assert!(field.value.is_none());
    }

    #[test]
    fn connect_api_error_display() {
        let err = ConnectApiError::Unauthorized;
        assert!(format!("{err}").contains("authentication failed"));

        let err = ConnectApiError::NotFound("vault 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = ConnectApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = ConnectApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));
    }

    #[test]
    fn vaults_list_deserialize() {
        let json = r#"[
            {"id":"v1","name":"Personal","description":"My vault"},
            {"id":"v2","name":"Shared"}
        ]"#;
        let vaults: Vec<Vault> = serde_json::from_str(json).unwrap();
        assert_eq!(vaults.len(), 2);
        assert_eq!(vaults[0].name, "Personal");
        assert_eq!(vaults[1].name, "Shared");
    }

    #[test]
    fn items_list_deserialize() {
        let json = r#"[
            {"id":"i1","title":"Token","category":"LOGIN"},
            {"id":"i2","title":"API Key","category":"API_CREDENTIAL"}
        ]"#;
        let items: Vec<ItemSummary> = serde_json::from_str(json).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Token");
        assert_eq!(items[1].category, "API_CREDENTIAL");
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_vaults_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal", "description": "My vault"},
                {"id": "v2", "name": "Shared"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let vaults = client.list_vaults("test-token").await.unwrap();

        assert_eq!(vaults.len(), 2);
        assert_eq!(vaults[0].id, "v1");
        assert_eq!(vaults[0].name, "Personal");
        assert_eq!(vaults[0].description.as_deref(), Some("My vault"));
        assert_eq!(vaults[1].id, "v2");
        assert_eq!(vaults[1].name, "Shared");
        assert!(vaults[1].description.is_none());
    }

    #[tokio::test]
    async fn list_vaults_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let result = client.list_vaults("bad-token").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectApiError::Unauthorized));
    }

    #[tokio::test]
    async fn list_vaults_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let result = client.list_vaults("token").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectApiError::ServerError));
    }

    #[tokio::test]
    async fn list_items_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "i1", "title": "GitHub Token", "category": "LOGIN"},
                {"id": "i2", "title": "API Key", "category": "API_CREDENTIAL"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let items = client.list_items("test-token", "v1").await.unwrap();

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "GitHub Token");
        assert_eq!(items[1].title, "API Key");
        assert_eq!(items[1].category, "API_CREDENTIAL");
    }

    #[tokio::test]
    async fn list_items_vault_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults/nonexistent/items"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let result = client.list_items("token", "nonexistent").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_item_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items/i1"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "i1",
                "title": "GitHub Token",
                "fields": [
                    {"id": "f1", "label": "username", "value": "user@example.com"},
                    {"id": "f2", "label": "password", "value": "ghp_secret123"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let item = client.get_item("test-token", "v1", "i1").await.unwrap();

        assert_eq!(item.id, "i1");
        assert_eq!(item.title, "GitHub Token");
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].label.as_deref(), Some("username"));
        assert_eq!(item.fields[0].value.as_deref(), Some("user@example.com"));
        assert_eq!(item.fields[1].label.as_deref(), Some("password"));
        assert_eq!(item.fields[1].value.as_deref(), Some("ghp_secret123"));
    }

    #[tokio::test]
    async fn get_item_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let result = client.get_item("token", "v1", "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn find_vault_by_name_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal"},
                {"id": "v2", "name": "Work"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let vault_id = client.find_vault_by_name("token", "Work").await.unwrap();
        assert_eq!(vault_id, "v2");
    }

    #[tokio::test]
    async fn find_vault_by_name_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let result = client.find_vault_by_name("token", "Nonexistent").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn find_item_by_title_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "i1", "title": "GitHub Token", "category": "LOGIN"},
                {"id": "i2", "title": "API Key", "category": "API_CREDENTIAL"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let item_id = client
            .find_item_by_title("token", "v1", "API Key")
            .await
            .unwrap();
        assert_eq!(item_id, "i2");
    }

    /// Full end-to-end resolution chain:
    /// find_vault_by_name → find_item_by_title → get_item → extract field
    #[tokio::test]
    async fn full_resolution_chain() {
        let mock_server = MockServer::start().await;

        // Step 1: list vaults → find "Personal" → vault_id="v1"
        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "v1", "name": "Personal", "description": "My personal vault"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Step 2: list items in v1 → find "GitHub Token" → item_id="i1"
        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "i1", "title": "GitHub Token", "category": "LOGIN"}
            ])))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Step 3: get item i1 with fields → extract "password" field
        Mock::given(method("GET"))
            .and(path("/v1/vaults/v1/items/i1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "i1",
                "title": "GitHub Token",
                "fields": [
                    {"id": "f1", "label": "username", "value": "user@example.com"},
                    {"id": "f2", "label": "password", "value": "ghp_realtoken123"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let token = "test-connect-token";

        // Simulate the full resolution chain that OnePasswordResolver does:
        let vault_id = client.find_vault_by_name(token, "Personal").await.unwrap();
        assert_eq!(vault_id, "v1");

        let item_id = client
            .find_item_by_title(token, &vault_id, "GitHub Token")
            .await
            .unwrap();
        assert_eq!(item_id, "i1");

        let item = client.get_item(token, &vault_id, &item_id).await.unwrap();
        let password = item
            .fields
            .iter()
            .find(|f| f.label.as_deref() == Some("password"))
            .and_then(|f| f.value.as_deref())
            .unwrap();
        assert_eq!(password, "ghp_realtoken123");
    }

    /// Verify bearer token is sent correctly in the Authorization header.
    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let vaults = client.list_vaults("my-secret-token").await.unwrap();
        assert!(vaults.is_empty());
    }

    /// Verify the user-agent header is sent.
    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        client.list_vaults("token").await.unwrap();
    }

    /// Verify unexpected status codes are handled.
    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(418)) // I'm a teapot
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let result = client.list_vaults("token").await;
        assert!(matches!(
            result.unwrap_err(),
            ConnectApiError::UnexpectedStatus(418)
        ));
    }

    /// Verify 403 is treated as unauthorized (same as 401).
    #[tokio::test]
    async fn forbidden_treated_as_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/vaults"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = OnePasswordClient::new(&mock_server.uri());
        let result = client.list_vaults("token").await;
        assert!(matches!(result.unwrap_err(), ConnectApiError::Unauthorized));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://connect.1password.com");
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080");
        validate_url_scheme("http://127.0.0.1:9000/v1");
    }

    #[test]
    #[should_panic(expected = "insecure HTTP URL rejected")]
    fn validate_url_scheme_rejects_remote_http() {
        validate_url_scheme("http://connect.1password.com");
    }

    #[test]
    #[should_panic(expected = "unsupported URL scheme")]
    fn validate_url_scheme_rejects_ftp() {
        validate_url_scheme("ftp://example.com/file");
    }
}
