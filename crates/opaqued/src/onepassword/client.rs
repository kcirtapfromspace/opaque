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
    pub fn new(base_url: &str) -> Self {
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

    /// Create a client pointing at a custom base URL (for testing).
    #[cfg(test)]
    pub fn with_base_url(base_url: String) -> Self {
        Self::new(&base_url)
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
}
