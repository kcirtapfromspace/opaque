//! Credential-free parsing of the exact 1Password operation to authorize.
use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum BackendBinding {
    ConnectServer { api_url: String },
    Cli { executable: String },
}

#[derive(Serialize)]
pub(super) struct BoundAction {
    #[serde(flatten)]
    pub action: OnePasswordAction,
    pub backend: BackendBinding,
}

#[derive(Serialize)]
#[serde(tag = "action", content = "params")]
pub(super) enum OnePasswordAction {
    #[serde(rename = "onepassword.list_vaults.v1")]
    ListVaults {},
    #[serde(rename = "onepassword.list_items.v1")]
    ListItems { vault: String },
    #[serde(rename = "onepassword.read_field.v1")]
    ReadField {
        vault: String,
        item: String,
        field: String,
    },
}

impl OnePasswordAction {
    pub(super) fn parse(operation: &str, params: &Value) -> Result<Self, String> {
        let fields: &[&str] = match operation {
            "onepassword.list_vaults" => &[],
            "onepassword.list_items" => &["vault"],
            "onepassword.read_field" => &["vault", "item", "field"],
            _ => return Err("unknown 1Password operation".into()),
        };
        let params = params
            .as_object()
            .ok_or("1Password params must be an object")?;
        if params.keys().any(|key| !fields.contains(&key.as_str())) {
            return Err("unknown 1Password parameter".into());
        }
        Ok(match operation {
            "onepassword.list_vaults" => Self::ListVaults {},
            "onepassword.list_items" => Self::ListItems {
                vault: selector(params, "vault")?,
            },
            _ => Self::ReadField {
                vault: selector(params, "vault")?,
                item: selector(params, "item")?,
                field: selector(params, "field")?,
            },
        })
    }

    pub(super) fn target(&self) -> HashMap<String, String> {
        match self {
            Self::ListVaults {} => HashMap::new(),
            Self::ListItems { vault } => HashMap::from([("vault".into(), vault.clone())]),
            Self::ReadField { vault, item, field } => HashMap::from([
                ("vault".into(), vault.clone()),
                ("item".into(), item.clone()),
                ("field".into(), field.clone()),
            ]),
        }
    }

    pub(super) fn validate_cli_selectors(&self) -> Result<(), String> {
        // `op read` accepts an op:// URI, so delimiters must not change its
        // components. Connect uses exact name matching and has no URI grammar.
        match self {
            Self::ReadField { vault, item, field } => {
                for selector in [vault, item, field] {
                    if selector.contains(['/', '?', '#', '%']) {
                        return Err("1Password CLI selector contains a URI delimiter".into());
                    }
                }
            }
            Self::ListItems { vault } if vault.starts_with('-') => {
                return Err("1Password CLI vault selector cannot start with '-'".into());
            }
            _ => {}
        }
        Ok(())
    }
}

fn selector(params: &Map<String, Value>, key: &str) -> Result<String, String> {
    let value = params
        .get(key)
        .ok_or_else(|| format!("missing '{key}' parameter"))?
        .as_str()
        .ok_or_else(|| format!("'{key}' must be a string"))?;
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!("invalid '{key}' selector"));
    }
    Ok(value.to_owned())
}
