//! Credential-free parsing of exact Bitwarden selectors and listing scope.
use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Serialize)]
pub(super) struct BoundAction {
    #[serde(flatten)]
    pub action: BitwardenAction,
    pub api_url: String,
}

#[derive(Serialize)]
#[serde(tag = "action", content = "params")]
pub(super) enum BitwardenAction {
    #[serde(rename = "bitwarden.list_projects.v1")]
    ListProjects {},
    #[serde(rename = "bitwarden.list_secrets.v1")]
    ListSecrets { project: Option<String> },
    #[serde(rename = "bitwarden.read_secret.v1")]
    ReadSecret { secret_id: String },
}

impl BitwardenAction {
    pub(super) fn parse(operation: &str, params: &Value) -> Result<Self, String> {
        let fields: &[&str] = match operation {
            "bitwarden.list_projects" => &[],
            "bitwarden.list_secrets" => &["project"],
            "bitwarden.read_secret" => &["secret_id"],
            _ => return Err("unknown Bitwarden operation".into()),
        };
        let params = params
            .as_object()
            .ok_or("Bitwarden params must be an object")?;
        if params.keys().any(|key| !fields.contains(&key.as_str())) {
            return Err("unknown Bitwarden parameter".into());
        }
        Ok(match operation {
            "bitwarden.list_projects" => Self::ListProjects {},
            "bitwarden.list_secrets" => Self::ListSecrets {
                project: match params.get("project") {
                    None | Some(Value::Null) => None,
                    Some(_) => Some(selector(params, "project")?),
                },
            },
            _ => {
                let secret_id = selector(params, "secret_id")?;
                // Secret IDs are single path segments. Prevent URL parsing
                // from turning an approved ID into a different API request.
                if !secret_id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
                {
                    return Err("invalid 'secret_id' selector".into());
                }
                Self::ReadSecret { secret_id }
            }
        })
    }

    pub(super) fn target(&self) -> HashMap<String, String> {
        match self {
            Self::ListProjects {} | Self::ListSecrets { project: None } => HashMap::new(),
            Self::ListSecrets {
                project: Some(project),
            } => HashMap::from([("project".into(), project.clone())]),
            Self::ReadSecret { secret_id } => {
                HashMap::from([("secret_id".into(), secret_id.clone())])
            }
        }
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
