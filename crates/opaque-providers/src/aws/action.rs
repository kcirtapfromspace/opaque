//! Canonical AWS fixture actions. Preparation never resolves credentials.
use std::collections::HashMap;

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub(super) struct BoundAction {
    #[serde(flatten)]
    pub action: AwsAction,
    pub backend: &'static str,
    pub api_url: String,
}

// The immutable action owns the exact bytes sent to AWS. Its serialized
// authorization payload binds a digest, keeping secret bytes out of review.
pub(super) struct ConfidentialValue(String);

impl ConfidentialValue {
    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

impl Serialize for ConfidentialValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut hash = Sha256::new();
        hash.update(b"opaque:aws:write-value:v1\0");
        hash.update(self.0.as_bytes());
        serializer.serialize_str(&format!("{:x}", hash.finalize()))
    }
}

#[derive(Serialize)]
#[serde(tag = "action", content = "params")]
pub(super) enum AwsAction {
    #[serde(rename = "aws.get_caller_identity.v1")]
    GetCallerIdentity {},
    #[serde(rename = "aws.assume_role.v1")]
    AssumeRole {
        role_arn: String,
        session_name: String,
    },
    #[serde(rename = "aws.list_secrets.v1")]
    ListSecrets {},
    #[serde(rename = "aws.get_secret_value.v1")]
    GetSecretValue { secret_id: String },
    #[serde(rename = "aws.create_secret.v1")]
    CreateSecret {
        name: String,
        #[serde(rename = "value_sha256")]
        value: ConfidentialValue,
        description: Option<String>,
    },
    #[serde(rename = "aws.put_secret_value.v1")]
    PutSecretValue {
        secret_id: String,
        #[serde(rename = "value_sha256")]
        value: ConfidentialValue,
    },
    #[serde(rename = "aws.delete_secret.v1")]
    DeleteSecret {
        secret_id: String,
        force_delete_without_recovery: bool,
    },
    #[serde(rename = "aws.get_parameter.v1")]
    GetParameter { name: String, with_decryption: bool },
    #[serde(rename = "aws.put_parameter.v1")]
    PutParameter {
        name: String,
        #[serde(rename = "value_sha256")]
        value: ConfidentialValue,
        #[serde(rename = "type")]
        parameter_type: String,
        overwrite: bool,
    },
    #[serde(rename = "aws.get_parameters_by_path.v1")]
    GetParametersByPath {
        path: String,
        with_decryption: bool,
        recursive: bool,
    },
    #[serde(rename = "aws.delete_parameter.v1")]
    DeleteParameter { name: String },
}

impl AwsAction {
    pub(super) fn parse(operation: &str, params: &Value) -> Result<Self, String> {
        let fields: &[&str] = match operation {
            "aws.get_caller_identity" | "aws.list_secrets" => &[],
            "aws.assume_role" => &["role_arn", "session_name"],
            "aws.get_secret_value" | "aws.delete_secret" => &["secret_id"],
            "aws.create_secret" => &["name", "value", "description"],
            "aws.put_secret_value" => &["secret_id", "value"],
            "aws.get_parameter" => &["name", "with_decryption"],
            "aws.put_parameter" => &["name", "value", "type", "overwrite"],
            "aws.get_parameters_by_path" => &["path", "with_decryption"],
            "aws.delete_parameter" => &["name"],
            _ => return Err("unknown AWS operation".into()),
        };
        let params = params.as_object().ok_or("AWS params must be an object")?;
        if params.keys().any(|key| !fields.contains(&key.as_str())) {
            return Err("unknown AWS parameter".into());
        }
        Ok(match operation {
            "aws.get_caller_identity" => Self::GetCallerIdentity {},
            "aws.list_secrets" => Self::ListSecrets {},
            "aws.assume_role" => Self::AssumeRole {
                role_arn: selector(params, "role_arn")?,
                session_name: optional_string(params, "session_name")?
                    .unwrap_or("opaque-session")
                    .to_owned(),
            },
            "aws.get_secret_value" => Self::GetSecretValue {
                secret_id: selector(params, "secret_id")?,
            },
            "aws.create_secret" => Self::CreateSecret {
                name: selector(params, "name")?,
                value: ConfidentialValue(required_string(params, "value")?.to_owned()),
                description: optional_string(params, "description")?.map(str::to_owned),
            },
            "aws.put_secret_value" => Self::PutSecretValue {
                secret_id: selector(params, "secret_id")?,
                value: ConfidentialValue(required_string(params, "value")?.to_owned()),
            },
            "aws.delete_secret" => Self::DeleteSecret {
                secret_id: selector(params, "secret_id")?,
                force_delete_without_recovery: false,
            },
            "aws.get_parameter" => Self::GetParameter {
                name: selector(params, "name")?,
                with_decryption: optional_bool(params, "with_decryption", true)?,
            },
            "aws.put_parameter" => {
                let name = selector(params, "name")?;
                let value = ConfidentialValue(required_string(params, "value")?.to_owned());
                let parameter_type = optional_string(params, "type")?.unwrap_or("SecureString");
                if !matches!(parameter_type, "String" | "StringList" | "SecureString") {
                    return Err("invalid AWS parameter type".into());
                }
                Self::PutParameter {
                    name,
                    value,
                    parameter_type: parameter_type.into(),
                    overwrite: optional_bool(params, "overwrite", false)?,
                }
            }
            "aws.get_parameters_by_path" => Self::GetParametersByPath {
                path: selector(params, "path")?,
                with_decryption: optional_bool(params, "with_decryption", false)?,
                recursive: true,
            },
            _ => Self::DeleteParameter {
                name: selector(params, "name")?,
            },
        })
    }

    pub(super) fn target(&self) -> HashMap<String, String> {
        let mut target = HashMap::new();
        match self {
            Self::GetCallerIdentity {} | Self::ListSecrets {} => {}
            Self::AssumeRole {
                role_arn,
                session_name,
            } => {
                target.insert("role_arn".into(), role_arn.clone());
                target.insert("session_name".into(), session_name.clone());
            }
            Self::GetSecretValue { secret_id } | Self::PutSecretValue { secret_id, .. } => {
                target.insert("secret_id".into(), secret_id.clone());
            }
            Self::DeleteSecret {
                secret_id,
                force_delete_without_recovery,
            } => {
                target.insert("secret_id".into(), secret_id.clone());
                target.insert(
                    "force_delete_without_recovery".into(),
                    force_delete_without_recovery.to_string(),
                );
            }
            Self::CreateSecret { name, .. } | Self::DeleteParameter { name } => {
                target.insert("name".into(), name.clone());
            }
            Self::GetParameter {
                name,
                with_decryption,
            } => {
                target.insert("name".into(), name.clone());
                target.insert("with_decryption".into(), with_decryption.to_string());
            }
            Self::PutParameter {
                name,
                parameter_type,
                overwrite,
                ..
            } => {
                target.insert("name".into(), name.clone());
                target.insert("type".into(), parameter_type.clone());
                target.insert("overwrite".into(), overwrite.to_string());
            }
            Self::GetParametersByPath {
                path,
                with_decryption,
                recursive,
            } => {
                target.insert("path".into(), path.clone());
                target.insert("with_decryption".into(), with_decryption.to_string());
                target.insert("recursive".into(), recursive.to_string());
            }
        }
        target
    }
}

fn required_string<'a>(params: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .ok_or_else(|| format!("missing '{key}' parameter"))?
        .as_str()
        .ok_or_else(|| format!("'{key}' must be a string"))
}

fn selector(params: &Map<String, Value>, key: &str) -> Result<String, String> {
    let value = required_string(params, key)?;
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!("invalid '{key}' selector"));
    }
    Ok(value.to_owned())
}

fn optional_string<'a>(
    params: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(format!("'{key}' must be a string or null")),
    }
}

fn optional_bool(params: &Map<String, Value>, key: &str, default: bool) -> Result<bool, String> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(format!("'{key}' must be a boolean or null")),
    }
}
