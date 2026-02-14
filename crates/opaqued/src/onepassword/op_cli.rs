//! 1Password CLI (`op`) integration.
//!
//! Uses the locally installed `op` CLI to interact with 1Password via the
//! desktop app. Authentication is handled by the `op` CLI itself (biometric
//! via Touch ID on macOS, system auth on Linux).
//!
//! This is an alternative to the Connect Server client — no self-hosted
//! infrastructure required, just the 1Password desktop app with CLI
//! integration enabled.

use serde::Deserialize;
use std::process::Stdio;
use tokio::process::Command;

use super::client::{Field, Item, ItemSummary, Vault};

/// Environment variable to explicitly set the path to the `op` binary.
pub const OP_CLI_PATH_ENV: &str = "OPAQUE_1PASSWORD_CLI_PATH";

/// Error from the `op` CLI.
#[derive(Debug, thiserror::Error)]
pub enum OpCliError {
    #[error("op CLI not found (install 1Password CLI or set OPAQUE_1PASSWORD_CLI_PATH)")]
    NotFound,

    #[error("op CLI execution failed: {0}")]
    ExecFailed(String),

    #[error("op CLI returned an error: {0}")]
    CommandFailed(String),

    #[error("failed to parse op CLI output: {0}")]
    ParseError(String),
}

/// Client that shells out to the `op` CLI binary.
#[derive(Debug, Clone)]
pub struct OpCliClient {
    op_path: String,
}

impl OpCliClient {
    /// Create a new client, resolving the `op` binary path.
    ///
    /// Checks `OPAQUE_1PASSWORD_CLI_PATH` env var first, then searches PATH.
    pub fn new() -> Result<Self, OpCliError> {
        let op_path = Self::find_op_binary()?;
        Ok(Self { op_path })
    }

    /// Find the `op` binary path.
    fn find_op_binary() -> Result<String, OpCliError> {
        // Check env var override first.
        if let Ok(path) = std::env::var(OP_CLI_PATH_ENV)
            && std::path::Path::new(&path).exists()
        {
            return Ok(path);
        }

        // Search PATH using `which`.
        let output = std::process::Command::new("which")
            .arg("op")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| OpCliError::NotFound)?;

        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !path.is_empty() {
                return Ok(path);
            }
        }

        Err(OpCliError::NotFound)
    }

    /// Run an `op` command and return stdout as a string.
    async fn run(&self, args: &[&str]) -> Result<String, OpCliError> {
        let output = Command::new(&self.op_path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| OpCliError::ExecFailed(e.to_string()))?;

        if output.status.success() {
            String::from_utf8(output.stdout)
                .map_err(|e| OpCliError::ParseError(format!("non-UTF8 output: {e}")))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Sanitize the error — don't leak full stderr which may contain paths.
            let msg = stderr
                .lines()
                .find(|l| !l.is_empty())
                .unwrap_or("unknown error")
                .to_owned();
            Err(OpCliError::CommandFailed(msg))
        }
    }

    /// List all vaults.
    pub async fn list_vaults(&self) -> Result<Vec<Vault>, OpCliError> {
        let json = self.run(&["vault", "list", "--format", "json"]).await?;
        let raw: Vec<CliVault> =
            serde_json::from_str(&json).map_err(|e| OpCliError::ParseError(e.to_string()))?;
        Ok(raw.into_iter().map(Into::into).collect())
    }

    /// List items in a vault (by vault name).
    pub async fn list_items(&self, vault_name: &str) -> Result<Vec<ItemSummary>, OpCliError> {
        let json = self
            .run(&["item", "list", "--vault", vault_name, "--format", "json"])
            .await?;
        let raw: Vec<CliItemSummary> =
            serde_json::from_str(&json).map_err(|e| OpCliError::ParseError(e.to_string()))?;
        Ok(raw.into_iter().map(Into::into).collect())
    }

    /// Read a single field value directly using `op read`.
    ///
    /// This is the simplest way to get a secret — one command, one value.
    /// The URI format is `op://vault/item/field`.
    pub async fn read_field(
        &self,
        vault: &str,
        item: &str,
        field: &str,
    ) -> Result<String, OpCliError> {
        let uri = format!("op://{vault}/{item}/{field}");
        let value = self.run(&["read", &uri]).await?;
        Ok(value.trim_end().to_owned())
    }
}

// ---------------------------------------------------------------------------
// CLI JSON response types (mapped to shared types)
// ---------------------------------------------------------------------------

/// Vault as returned by `op vault list --format json`.
#[derive(Debug, Deserialize)]
struct CliVault {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
}

impl From<CliVault> for Vault {
    fn from(v: CliVault) -> Self {
        Vault {
            id: v.id,
            name: v.name,
            description: v.description,
        }
    }
}

/// Item summary as returned by `op item list --format json`.
#[derive(Debug, Deserialize)]
struct CliItemSummary {
    id: String,
    title: String,
    #[serde(default)]
    category: String,
}

impl From<CliItemSummary> for ItemSummary {
    fn from(i: CliItemSummary) -> Self {
        ItemSummary {
            id: i.id,
            title: i.title,
            category: i.category,
        }
    }
}

/// Item detail as returned by `op item get --format json`.
#[derive(Debug, Deserialize)]
struct CliItem {
    id: String,
    title: String,
    #[serde(default)]
    fields: Vec<CliField>,
}

impl From<CliItem> for Item {
    fn from(i: CliItem) -> Self {
        Item {
            id: i.id,
            title: i.title,
            fields: i.fields.into_iter().map(Into::into).collect(),
        }
    }
}

/// Field as returned by `op item get --format json`.
#[derive(Debug, Deserialize)]
struct CliField {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

impl From<CliField> for Field {
    fn from(f: CliField) -> Self {
        Field {
            id: f.id,
            label: f.label,
            value: f.value,
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
    fn cli_vault_to_vault() {
        let cv = CliVault {
            id: "v1".into(),
            name: "Personal".into(),
            description: Some("My vault".into()),
        };
        let v: Vault = cv.into();
        assert_eq!(v.id, "v1");
        assert_eq!(v.name, "Personal");
        assert_eq!(v.description.as_deref(), Some("My vault"));
    }

    #[test]
    fn cli_item_summary_to_item_summary() {
        let ci = CliItemSummary {
            id: "i1".into(),
            title: "Token".into(),
            category: "LOGIN".into(),
        };
        let i: ItemSummary = ci.into();
        assert_eq!(i.id, "i1");
        assert_eq!(i.title, "Token");
        assert_eq!(i.category, "LOGIN");
    }

    #[test]
    fn cli_item_to_item() {
        let ci = CliItem {
            id: "i1".into(),
            title: "Token".into(),
            fields: vec![
                CliField {
                    id: "f1".into(),
                    label: Some("password".into()),
                    value: Some("secret".into()),
                },
                CliField {
                    id: "f2".into(),
                    label: Some("username".into()),
                    value: Some("user@test.com".into()),
                },
            ],
        };
        let item: Item = ci.into();
        assert_eq!(item.id, "i1");
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].label.as_deref(), Some("password"));
        assert_eq!(item.fields[0].value.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_op_vault_list_json() {
        let json = r#"[
            {"id":"abc","name":"Personal","content_version":42},
            {"id":"def","name":"Work","description":"Work stuff"}
        ]"#;
        let vaults: Vec<CliVault> = serde_json::from_str(json).unwrap();
        assert_eq!(vaults.len(), 2);
        assert_eq!(vaults[0].name, "Personal");
        assert!(vaults[0].description.is_none());
        assert_eq!(vaults[1].name, "Work");
        assert_eq!(vaults[1].description.as_deref(), Some("Work stuff"));
    }

    #[test]
    fn parse_op_item_list_json() {
        let json = r#"[
            {"id":"i1","title":"GitHub Token","version":1,"vault":{"id":"v1","name":"Personal"},"category":"LOGIN"},
            {"id":"i2","title":"API Key","category":"API_CREDENTIAL"}
        ]"#;
        let items: Vec<CliItemSummary> = serde_json::from_str(json).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "GitHub Token");
        assert_eq!(items[0].category, "LOGIN");
    }

    #[test]
    fn parse_op_item_get_json() {
        let json = r#"{
            "id":"i1",
            "title":"GitHub Token",
            "category":"LOGIN",
            "fields":[
                {"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":"user@example.com"},
                {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"ghp_secret123"}
            ],
            "vault":{"id":"v1","name":"Personal"}
        }"#;
        let item: CliItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.title, "GitHub Token");
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].label.as_deref(), Some("username"));
        assert_eq!(item.fields[1].label.as_deref(), Some("password"));
        assert_eq!(item.fields[1].value.as_deref(), Some("ghp_secret123"));
    }

    #[test]
    fn op_cli_error_display() {
        let err = OpCliError::NotFound;
        assert!(format!("{err}").contains("not found"));

        let err = OpCliError::CommandFailed("auth required".into());
        assert!(format!("{err}").contains("auth required"));

        let err = OpCliError::ParseError("invalid json".into());
        assert!(format!("{err}").contains("invalid json"));
    }

    // -----------------------------------------------------------------------
    // Live integration tests (require `op` CLI + authenticated desktop app)
    // Run with: cargo test -p opaqued -- op_cli::tests::live --ignored --nocapture
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires authenticated 1Password desktop app"]
    async fn live_list_vaults() {
        let cli = OpCliClient::new().expect("op CLI not found");
        let vaults = cli.list_vaults().await.expect("failed to list vaults");
        assert!(!vaults.is_empty(), "expected at least one vault");
        for v in &vaults {
            println!("  vault: {} (id={})", v.name, v.id);
        }
    }

    #[tokio::test]
    #[ignore = "requires authenticated 1Password desktop app"]
    async fn live_list_items() {
        let cli = OpCliClient::new().expect("op CLI not found");
        let vaults = cli.list_vaults().await.expect("failed to list vaults");
        let first_vault = &vaults[0];
        println!("  listing items in vault: {}", first_vault.name);

        let items = cli
            .list_items(&first_vault.name)
            .await
            .expect("failed to list items");
        println!("  found {} items", items.len());
        for item in items.iter().take(5) {
            println!("    - {} ({})", item.title, item.category);
        }
    }

    #[tokio::test]
    #[ignore = "requires authenticated 1Password desktop app"]
    async fn live_read_field() {
        let cli = OpCliClient::new().expect("op CLI not found");
        // List vaults, pick first, list items, pick first LOGIN item, read username
        let vaults = cli.list_vaults().await.expect("failed to list vaults");
        let vault_name = &vaults[0].name;
        let items = cli
            .list_items(vault_name)
            .await
            .expect("failed to list items");

        // Find a LOGIN item that likely has a username field.
        let login_item = items.iter().find(|i| i.category == "LOGIN");
        if let Some(item) = login_item {
            println!("  reading 'username' from {}/{}", vault_name, item.title);
            match cli.read_field(vault_name, &item.title, "username").await {
                Ok(value) => {
                    // Don't print the actual value — just confirm it's non-empty.
                    assert!(!value.is_empty(), "expected non-empty username");
                    println!("  SUCCESS: got {} chars", value.len());
                }
                Err(e) => {
                    println!("  field read returned error (may not have username): {e}");
                }
            }
        } else {
            println!("  no LOGIN items found in vault '{vault_name}', skipping");
        }
    }
}
