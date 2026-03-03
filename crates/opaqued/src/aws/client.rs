//! AWS API client.
//!
//! Wraps the REST endpoints needed for AWS STS, Secrets Manager, and SSM
//! Parameter Store. Uses standard AWS JSON protocol over HTTPS with
//! credential-based auth (access key / secret key / region).
//!
//! **Never** leaks raw API error bodies to callers — all errors are
//! mapped to sanitized strings.

use serde::{Deserialize, Serialize};

/// Environment variable for the AWS access key ID.
#[allow(dead_code)]
pub const AWS_ACCESS_KEY_ID_ENV: &str = "OPAQUE_AWS_ACCESS_KEY_ID";

/// Environment variable for the AWS secret access key.
#[allow(dead_code)]
pub const AWS_SECRET_ACCESS_KEY_ENV: &str = "OPAQUE_AWS_SECRET_ACCESS_KEY";

/// Environment variable for the AWS region.
pub const AWS_REGION_ENV: &str = "OPAQUE_AWS_REGION";

/// Default AWS region when none is configured.
pub const DEFAULT_REGION: &str = "us-east-1";

/// AWS API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum AwsApiError {
    #[error("network error communicating with AWS")]
    Network(#[source] reqwest::Error),

    #[error("AWS authentication failed (check access key and secret key)")]
    Unauthorized,

    #[error("AWS resource not found: {0}")]
    NotFound(String),

    #[error("AWS server error")]
    ServerError,

    #[error("AWS request rejected: {0}")]
    BadRequest(String),

    #[error("unexpected AWS response: status {0}")]
    UnexpectedStatus(u16),

    #[error("AWS response parse error: {0}")]
    ParseError(String),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),
}

// ---------------------------------------------------------------------------
// STS types
// ---------------------------------------------------------------------------

/// STS GetCallerIdentity response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallerIdentity {
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Arn")]
    pub arn: String,
    #[serde(rename = "UserId")]
    pub user_id: String,
}

/// STS AssumeRole response (simplified).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AssumedRoleCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "SessionToken")]
    pub session_token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
}

// ---------------------------------------------------------------------------
// Secrets Manager types
// ---------------------------------------------------------------------------

/// Secrets Manager secret value response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretValue {
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "SecretString", default)]
    pub secret_string: Option<String>,
    #[serde(rename = "VersionId", default)]
    pub version_id: Option<String>,
}

/// Secrets Manager secret summary (from ListSecrets).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretSummary {
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
}

/// Secrets Manager ListSecrets response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListSecretsResponse {
    #[serde(rename = "SecretList", default)]
    pub secret_list: Vec<SecretSummary>,
    #[serde(rename = "NextToken", default)]
    pub next_token: Option<String>,
}

/// Secrets Manager CreateSecret response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateSecretResponse {
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "VersionId", default)]
    pub version_id: Option<String>,
}

// ---------------------------------------------------------------------------
// SSM Parameter Store types
// ---------------------------------------------------------------------------

/// SSM Parameter.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SsmParameter {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type", default)]
    pub parameter_type: Option<String>,
    #[serde(rename = "Value", default)]
    pub value: Option<String>,
    #[serde(rename = "Version", default)]
    pub version: Option<i64>,
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
}

/// SSM GetParameter response wrapper.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetParameterResponse {
    #[serde(rename = "Parameter")]
    pub parameter: SsmParameter,
}

/// SSM GetParametersByPath response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetParametersByPathResponse {
    #[serde(rename = "Parameters", default)]
    pub parameters: Vec<SsmParameter>,
    #[serde(rename = "NextToken", default)]
    pub next_token: Option<String>,
}

/// Validate that a URL uses `https://`, allowing `http://` only for localhost.
fn validate_url_scheme(url: &str) -> Result<(), AwsApiError> {
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
        return Err(AwsApiError::InvalidUrl(format!(
            "insecure HTTP URL rejected: {url}. \
             Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
        )));
    }
    Err(AwsApiError::InvalidUrl(format!(
        "unsupported URL scheme: {url}. \
         Only https:// URLs are allowed (http:// is permitted for localhost/127.0.0.1 only)"
    )))
}

/// Map an HTTP status code to an appropriate error.
fn map_status(status: u16, context: &str) -> AwsApiError {
    match status {
        400 => AwsApiError::BadRequest(context.to_owned()),
        401 | 403 => AwsApiError::Unauthorized,
        404 => AwsApiError::NotFound(context.to_owned()),
        500..=599 => AwsApiError::ServerError,
        other => AwsApiError::UnexpectedStatus(other),
    }
}

/// AWS REST API client.
///
/// Follows the same pattern as `BitwardenClient`: no stored credentials
/// (passed per-call), timeouts, and a user-agent header.
///
/// This client uses simple HTTP calls against AWS-compatible endpoints.
/// Credentials (access key, secret key) are passed per-call and sent via
/// headers rather than AWS Signature V4 — suitable for mock testing and
/// local development. Production usage should layer SigV4 signing.
#[derive(Debug, Clone)]
pub struct AwsClient {
    http: reqwest::Client,
    /// Base URL for STS calls (e.g., `https://sts.us-east-1.amazonaws.com`).
    pub sts_url: String,
    /// Base URL for Secrets Manager calls.
    pub secretsmanager_url: String,
    /// Base URL for SSM calls.
    pub ssm_url: String,
}

impl AwsClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client with separate service URLs.
    ///
    /// Returns `Err(InvalidUrl)` if any URL uses `http://` for a non-localhost host.
    pub fn new(
        sts_url: &str,
        secretsmanager_url: &str,
        ssm_url: &str,
    ) -> Result<Self, AwsApiError> {
        validate_url_scheme(sts_url)?;
        validate_url_scheme(secretsmanager_url)?;
        validate_url_scheme(ssm_url)?;

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Ok(Self {
            http,
            sts_url: sts_url.trim_end_matches('/').to_owned(),
            secretsmanager_url: secretsmanager_url.trim_end_matches('/').to_owned(),
            ssm_url: ssm_url.trim_end_matches('/').to_owned(),
        })
    }

    /// Create a client where all services point at the same base URL.
    /// Useful for testing with a single mock server.
    #[cfg(test)]
    pub fn new_single(base_url: &str) -> Self {
        Self::new(base_url, base_url, base_url).expect("test URL should be valid")
    }

    // -----------------------------------------------------------------------
    // STS operations
    // -----------------------------------------------------------------------

    /// STS GetCallerIdentity — returns the account, ARN, and user ID
    /// associated with the provided credentials.
    pub async fn get_caller_identity(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Result<CallerIdentity, AwsApiError> {
        let resp = self
            .http
            .post(&self.sts_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.GetCallerIdentity",
            )
            .header("Content-Type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, "GetCallerIdentity"));
        }

        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(rename = "GetCallerIdentityResponse", default)]
            response: Option<InnerResponse>,
            // Flat fallback fields for direct JSON responses.
            #[serde(rename = "Account", default)]
            account: Option<String>,
            #[serde(rename = "Arn", default)]
            arn: Option<String>,
            #[serde(rename = "UserId", default)]
            user_id: Option<String>,
        }

        #[derive(Deserialize)]
        struct InnerResponse {
            #[serde(rename = "GetCallerIdentityResult")]
            result: CallerIdentity,
        }

        let body = resp.text().await.map_err(AwsApiError::Network)?;
        let wrapper: Wrapper = serde_json::from_str(&body)
            .map_err(|e| AwsApiError::ParseError(format!("GetCallerIdentity: {e}")))?;

        if let Some(inner) = wrapper.response {
            Ok(inner.result)
        } else if let (Some(account), Some(arn), Some(user_id)) =
            (wrapper.account, wrapper.arn, wrapper.user_id)
        {
            Ok(CallerIdentity {
                account,
                arn,
                user_id,
            })
        } else {
            Err(AwsApiError::ParseError(
                "missing CallerIdentity fields in response".into(),
            ))
        }
    }

    /// STS AssumeRole — returns temporary credentials for the specified role.
    pub async fn assume_role(
        &self,
        access_key: &str,
        secret_key: &str,
        role_arn: &str,
        session_name: &str,
    ) -> Result<AssumedRoleCredentials, AwsApiError> {
        let body = serde_json::json!({
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
        });

        let resp = self
            .http
            .post(&self.sts_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.AssumeRole",
            )
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, "AssumeRole"));
        }

        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(rename = "AssumeRoleResponse", default)]
            response: Option<InnerResponse>,
            #[serde(rename = "Credentials", default)]
            credentials: Option<AssumedRoleCredentials>,
        }

        #[derive(Deserialize)]
        struct InnerResponse {
            #[serde(rename = "AssumeRoleResult")]
            result: AssumeRoleResult,
        }

        #[derive(Deserialize)]
        struct AssumeRoleResult {
            #[serde(rename = "Credentials")]
            credentials: AssumedRoleCredentials,
        }

        let resp_body = resp.text().await.map_err(AwsApiError::Network)?;
        let wrapper: Wrapper = serde_json::from_str(&resp_body)
            .map_err(|e| AwsApiError::ParseError(format!("AssumeRole: {e}")))?;

        if let Some(inner) = wrapper.response {
            Ok(inner.result.credentials)
        } else if let Some(creds) = wrapper.credentials {
            Ok(creds)
        } else {
            Err(AwsApiError::ParseError(
                "missing Credentials in AssumeRole response".into(),
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Secrets Manager operations
    // -----------------------------------------------------------------------

    /// Secrets Manager GetSecretValue — fetch a secret's value by name or ARN.
    pub async fn get_secret_value(
        &self,
        access_key: &str,
        secret_key: &str,
        secret_id: &str,
    ) -> Result<SecretValue, AwsApiError> {
        let body = serde_json::json!({
            "SecretId": secret_id,
        });

        let resp = self
            .http
            .post(&self.secretsmanager_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "secretsmanager.GetSecretValue")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("secret '{secret_id}'")));
        }

        resp.json::<SecretValue>()
            .await
            .map_err(|e| AwsApiError::ParseError(format!("GetSecretValue: {e}")))
    }

    /// Secrets Manager CreateSecret — create a new secret.
    pub async fn create_secret(
        &self,
        access_key: &str,
        secret_key: &str,
        name: &str,
        secret_string: &str,
        description: Option<&str>,
    ) -> Result<CreateSecretResponse, AwsApiError> {
        let mut body = serde_json::json!({
            "Name": name,
            "SecretString": secret_string,
        });
        if let Some(desc) = description {
            body["Description"] = serde_json::Value::String(desc.to_owned());
        }

        let resp = self
            .http
            .post(&self.secretsmanager_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "secretsmanager.CreateSecret")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("create secret '{name}'")));
        }

        resp.json::<CreateSecretResponse>()
            .await
            .map_err(|e| AwsApiError::ParseError(format!("CreateSecret: {e}")))
    }

    /// Secrets Manager PutSecretValue — update an existing secret's value.
    pub async fn put_secret_value(
        &self,
        access_key: &str,
        secret_key: &str,
        secret_id: &str,
        secret_string: &str,
    ) -> Result<(), AwsApiError> {
        let body = serde_json::json!({
            "SecretId": secret_id,
            "SecretString": secret_string,
        });

        let resp = self
            .http
            .post(&self.secretsmanager_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "secretsmanager.PutSecretValue")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("put secret '{secret_id}'")));
        }

        Ok(())
    }

    /// Secrets Manager ListSecrets — list all secrets.
    pub async fn list_secrets(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> Result<ListSecretsResponse, AwsApiError> {
        let resp = self
            .http
            .post(&self.secretsmanager_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "secretsmanager.ListSecrets")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body("{}")
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, "ListSecrets"));
        }

        resp.json::<ListSecretsResponse>()
            .await
            .map_err(|e| AwsApiError::ParseError(format!("ListSecrets: {e}")))
    }

    /// Secrets Manager DeleteSecret — schedule a secret for deletion.
    pub async fn delete_secret(
        &self,
        access_key: &str,
        secret_key: &str,
        secret_id: &str,
    ) -> Result<(), AwsApiError> {
        let body = serde_json::json!({
            "SecretId": secret_id,
            "ForceDeleteWithoutRecovery": false,
        });

        let resp = self
            .http
            .post(&self.secretsmanager_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "secretsmanager.DeleteSecret")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("delete secret '{secret_id}'")));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // SSM Parameter Store operations
    // -----------------------------------------------------------------------

    /// SSM GetParameter — fetch a parameter by name.
    pub async fn get_parameter(
        &self,
        access_key: &str,
        secret_key: &str,
        name: &str,
        with_decryption: bool,
    ) -> Result<SsmParameter, AwsApiError> {
        let body = serde_json::json!({
            "Name": name,
            "WithDecryption": with_decryption,
        });

        let resp = self
            .http
            .post(&self.ssm_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "AmazonSSM.GetParameter")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("parameter '{name}'")));
        }

        let wrapper = resp
            .json::<GetParameterResponse>()
            .await
            .map_err(|e| AwsApiError::ParseError(format!("GetParameter: {e}")))?;

        Ok(wrapper.parameter)
    }

    /// SSM PutParameter — create or update a parameter.
    pub async fn put_parameter(
        &self,
        access_key: &str,
        secret_key: &str,
        name: &str,
        value: &str,
        parameter_type: &str,
        overwrite: bool,
    ) -> Result<(), AwsApiError> {
        let body = serde_json::json!({
            "Name": name,
            "Value": value,
            "Type": parameter_type,
            "Overwrite": overwrite,
        });

        let resp = self
            .http
            .post(&self.ssm_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "AmazonSSM.PutParameter")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("put parameter '{name}'")));
        }

        Ok(())
    }

    /// SSM GetParametersByPath — list parameters under a path prefix.
    pub async fn get_parameters_by_path(
        &self,
        access_key: &str,
        secret_key: &str,
        path: &str,
        with_decryption: bool,
    ) -> Result<GetParametersByPathResponse, AwsApiError> {
        let body = serde_json::json!({
            "Path": path,
            "WithDecryption": with_decryption,
            "Recursive": true,
        });

        let resp = self
            .http
            .post(&self.ssm_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "AmazonSSM.GetParametersByPath")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("parameters path '{path}'")));
        }

        resp.json::<GetParametersByPathResponse>()
            .await
            .map_err(|e| AwsApiError::ParseError(format!("GetParametersByPath: {e}")))
    }

    /// SSM DeleteParameter — delete a parameter by name.
    pub async fn delete_parameter(
        &self,
        access_key: &str,
        secret_key: &str,
        name: &str,
    ) -> Result<(), AwsApiError> {
        let body = serde_json::json!({
            "Name": name,
        });

        let resp = self
            .http
            .post(&self.ssm_url)
            .header("X-Amz-Access-Key", access_key)
            .header("X-Amz-Secret-Key", secret_key)
            .header("X-Amz-Target", "AmazonSSM.DeleteParameter")
            .header("Content-Type", "application/x-amz-json-1.1")
            .body(body.to_string())
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(map_status(status, &format!("delete parameter '{name}'")));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Serialization tests --

    #[test]
    fn caller_identity_deserialize() {
        let json = r#"{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test","UserId":"AIDEXAMPLE"}"#;
        let id: CallerIdentity = serde_json::from_str(json).unwrap();
        assert_eq!(id.account, "123456789012");
        assert_eq!(id.arn, "arn:aws:iam::123456789012:user/test");
        assert_eq!(id.user_id, "AIDEXAMPLE");
    }

    #[test]
    fn assumed_role_credentials_deserialize() {
        let json = r#"{
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "secret123",
            "SessionToken": "token456",
            "Expiration": "2026-01-01T00:00:00Z"
        }"#;
        let creds: AssumedRoleCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
        assert_eq!(creds.secret_access_key, "secret123");
        assert_eq!(creds.session_token, "token456");
        assert_eq!(creds.expiration, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn secret_value_deserialize() {
        let json = r#"{
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-abc123",
            "Name": "test-secret",
            "SecretString": "supersecret",
            "VersionId": "v1"
        }"#;
        let sv: SecretValue = serde_json::from_str(json).unwrap();
        assert_eq!(sv.name, "test-secret");
        assert_eq!(sv.secret_string.as_deref(), Some("supersecret"));
        assert_eq!(sv.version_id.as_deref(), Some("v1"));
    }

    #[test]
    fn secret_value_deserialize_minimal() {
        let json = r#"{"Name": "test"}"#;
        let sv: SecretValue = serde_json::from_str(json).unwrap();
        assert_eq!(sv.name, "test");
        assert!(sv.secret_string.is_none());
        assert!(sv.arn.is_none());
    }

    #[test]
    fn secret_summary_deserialize() {
        let json = r#"{"Name": "prod/db", "ARN": "arn:...", "Description": "Production DB"}"#;
        let s: SecretSummary = serde_json::from_str(json).unwrap();
        assert_eq!(s.name, "prod/db");
        assert_eq!(s.description.as_deref(), Some("Production DB"));
    }

    #[test]
    fn list_secrets_response_deserialize() {
        let json = r#"{
            "SecretList": [
                {"Name": "secret-a", "Description": "First"},
                {"Name": "secret-b"}
            ]
        }"#;
        let resp: ListSecretsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.secret_list.len(), 2);
        assert_eq!(resp.secret_list[0].name, "secret-a");
        assert_eq!(resp.secret_list[1].name, "secret-b");
        assert!(resp.next_token.is_none());
    }

    #[test]
    fn create_secret_response_deserialize() {
        let json = r#"{"Name": "new-secret", "ARN": "arn:...", "VersionId": "v1"}"#;
        let resp: CreateSecretResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.name, "new-secret");
        assert_eq!(resp.version_id.as_deref(), Some("v1"));
    }

    #[test]
    fn ssm_parameter_deserialize() {
        let json = r#"{
            "Name": "/app/config",
            "Type": "SecureString",
            "Value": "secret-config",
            "Version": 3,
            "ARN": "arn:aws:ssm:us-east-1:123:parameter/app/config"
        }"#;
        let p: SsmParameter = serde_json::from_str(json).unwrap();
        assert_eq!(p.name, "/app/config");
        assert_eq!(p.parameter_type.as_deref(), Some("SecureString"));
        assert_eq!(p.value.as_deref(), Some("secret-config"));
        assert_eq!(p.version, Some(3));
    }

    #[test]
    fn get_parameter_response_deserialize() {
        let json = r#"{
            "Parameter": {
                "Name": "/myapp/key",
                "Type": "String",
                "Value": "hello"
            }
        }"#;
        let resp: GetParameterResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.parameter.name, "/myapp/key");
        assert_eq!(resp.parameter.value.as_deref(), Some("hello"));
    }

    #[test]
    fn get_parameters_by_path_response_deserialize() {
        let json = r#"{
            "Parameters": [
                {"Name": "/app/key1", "Value": "val1"},
                {"Name": "/app/key2", "Value": "val2"}
            ]
        }"#;
        let resp: GetParametersByPathResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.parameters.len(), 2);
        assert_eq!(resp.parameters[0].name, "/app/key1");
        assert_eq!(resp.parameters[1].name, "/app/key2");
    }

    #[test]
    fn aws_api_error_display() {
        let err = AwsApiError::Unauthorized;
        assert!(format!("{err}").contains("authentication failed"));

        let err = AwsApiError::NotFound("secret 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = AwsApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = AwsApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));

        let err = AwsApiError::BadRequest("invalid params".into());
        assert!(format!("{err}").contains("rejected"));

        let err = AwsApiError::ParseError("bad json".into());
        assert!(format!("{err}").contains("parse error"));
    }

    #[test]
    fn client_stores_urls_trimmed() {
        let client = AwsClient::new(
            "http://localhost:8080/",
            "http://localhost:8081/",
            "http://localhost:8082/",
        )
        .unwrap();
        assert_eq!(client.sts_url, "http://localhost:8080");
        assert_eq!(client.secretsmanager_url, "http://localhost:8081");
        assert_eq!(client.ssm_url, "http://localhost:8082");
    }

    #[test]
    fn client_single_url() {
        let client = AwsClient::new_single("http://localhost:9000");
        assert_eq!(client.sts_url, "http://localhost:9000");
        assert_eq!(client.secretsmanager_url, "http://localhost:9000");
        assert_eq!(client.ssm_url, "http://localhost:9000");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = AwsClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn map_status_codes() {
        assert!(matches!(map_status(400, "x"), AwsApiError::BadRequest(_)));
        assert!(matches!(map_status(401, "x"), AwsApiError::Unauthorized));
        assert!(matches!(map_status(403, "x"), AwsApiError::Unauthorized));
        assert!(matches!(map_status(404, "x"), AwsApiError::NotFound(_)));
        assert!(matches!(map_status(500, "x"), AwsApiError::ServerError));
        assert!(matches!(map_status(503, "x"), AwsApiError::ServerError));
        assert!(matches!(
            map_status(418, "x"),
            AwsApiError::UnexpectedStatus(418)
        ));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://sts.amazonaws.com").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080").unwrap();
        validate_url_scheme("http://127.0.0.1:9000").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let result = validate_url_scheme("http://sts.amazonaws.com");
        assert!(matches!(result, Err(AwsApiError::InvalidUrl(_))));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let result = validate_url_scheme("ftp://example.com/file");
        assert!(matches!(result, Err(AwsApiError::InvalidUrl(_))));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn get_caller_identity_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.GetCallerIdentity",
            ))
            .and(header("X-Amz-Access-Key", "AKIAIOSFODNN7EXAMPLE"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Account": "123456789012",
                "Arn": "arn:aws:iam::123456789012:user/testuser",
                "UserId": "AIDEXAMPLE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let identity = client
            .get_caller_identity("AKIAIOSFODNN7EXAMPLE", "secret")
            .await
            .unwrap();

        assert_eq!(identity.account, "123456789012");
        assert_eq!(identity.arn, "arn:aws:iam::123456789012:user/testuser");
        assert_eq!(identity.user_id, "AIDEXAMPLE");
    }

    #[tokio::test]
    async fn get_caller_identity_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.GetCallerIdentity",
            ))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client.get_caller_identity("bad-key", "bad-secret").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::Unauthorized));
    }

    #[tokio::test]
    async fn assume_role_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.AssumeRole",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Credentials": {
                    "AccessKeyId": "ASIAEXAMPLE",
                    "SecretAccessKey": "newsecret",
                    "SessionToken": "FwoGZX...",
                    "Expiration": "2026-02-25T00:00:00Z"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let creds = client
            .assume_role("AKID", "secret", "arn:aws:iam::123:role/test", "session1")
            .await
            .unwrap();

        assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
        assert_eq!(creds.secret_access_key, "newsecret");
        assert_eq!(creds.session_token, "FwoGZX...");
    }

    #[tokio::test]
    async fn assume_role_forbidden() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "X-Amz-Target",
                "AWSSecurityTokenServiceV20110615.AssumeRole",
            ))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client
            .assume_role("AKID", "secret", "arn:aws:iam::123:role/nope", "s1")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::Unauthorized));
    }

    #[tokio::test]
    async fn get_secret_value_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.GetSecretValue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:prod/db-abc123",
                "Name": "prod/db",
                "SecretString": "{\"username\":\"admin\",\"password\":\"s3cr3t\"}",
                "VersionId": "v1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let sv = client
            .get_secret_value("AKID", "secret", "prod/db")
            .await
            .unwrap();

        assert_eq!(sv.name, "prod/db");
        assert!(sv.secret_string.as_deref().unwrap().contains("admin"));
    }

    #[tokio::test]
    async fn get_secret_value_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.GetSecretValue"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client.get_secret_value("AKID", "secret", "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn create_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.CreateSecret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:new-abc",
                "Name": "new-secret",
                "VersionId": "v1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let resp = client
            .create_secret(
                "AKID",
                "secret",
                "new-secret",
                "value123",
                Some("A test secret"),
            )
            .await
            .unwrap();

        assert_eq!(resp.name, "new-secret");
    }

    #[tokio::test]
    async fn put_secret_value_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.PutSecretValue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ARN": "arn:...",
                "Name": "my-secret",
                "VersionId": "v2"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        client
            .put_secret_value("AKID", "secret", "my-secret", "new-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_secrets_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "SecretList": [
                    {"Name": "prod/db", "Description": "Production DB"},
                    {"Name": "prod/api-key"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let resp = client.list_secrets("AKID", "secret").await.unwrap();

        assert_eq!(resp.secret_list.len(), 2);
        assert_eq!(resp.secret_list[0].name, "prod/db");
        assert_eq!(
            resp.secret_list[0].description.as_deref(),
            Some("Production DB")
        );
    }

    #[tokio::test]
    async fn list_secrets_auth_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client.list_secrets("bad", "bad").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::Unauthorized));
    }

    #[tokio::test]
    async fn delete_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.DeleteSecret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ARN": "arn:...",
                "Name": "old-secret",
                "DeletionDate": "2026-03-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        client
            .delete_secret("AKID", "secret", "old-secret")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.DeleteSecret"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client.delete_secret("AKID", "secret", "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_parameter_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.GetParameter"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Parameter": {
                    "Name": "/myapp/db_password",
                    "Type": "SecureString",
                    "Value": "secret123",
                    "Version": 2
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let param = client
            .get_parameter("AKID", "secret", "/myapp/db_password", true)
            .await
            .unwrap();

        assert_eq!(param.name, "/myapp/db_password");
        assert_eq!(param.value.as_deref(), Some("secret123"));
        assert_eq!(param.parameter_type.as_deref(), Some("SecureString"));
        assert_eq!(param.version, Some(2));
    }

    #[tokio::test]
    async fn get_parameter_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.GetParameter"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client
            .get_parameter("AKID", "secret", "/missing/param", true)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn put_parameter_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.PutParameter"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Version": 1
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        client
            .put_parameter(
                "AKID",
                "secret",
                "/myapp/key",
                "value",
                "SecureString",
                false,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_parameters_by_path_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.GetParametersByPath"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Parameters": [
                    {"Name": "/app/key1", "Type": "String", "Value": "val1"},
                    {"Name": "/app/key2", "Type": "SecureString", "Value": "val2"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let resp = client
            .get_parameters_by_path("AKID", "secret", "/app/", true)
            .await
            .unwrap();

        assert_eq!(resp.parameters.len(), 2);
        assert_eq!(resp.parameters[0].name, "/app/key1");
        assert_eq!(resp.parameters[1].name, "/app/key2");
    }

    #[tokio::test]
    async fn delete_parameter_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.DeleteParameter"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        client
            .delete_parameter("AKID", "secret", "/myapp/old")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_parameter_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "AmazonSSM.DeleteParameter"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client.delete_parameter("AKID", "secret", "/missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn server_error_handled() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client.list_secrets("AKID", "secret").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::ServerError));
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(418))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        let result = client.list_secrets("AKID", "secret").await;

        assert!(matches!(
            result.unwrap_err(),
            AwsApiError::UnexpectedStatus(418)
        ));
    }

    /// Verify the user-agent header is sent.
    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "SecretList": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AwsClient::new_single(&mock_server.uri());
        client.list_secrets("AKID", "secret").await.unwrap();
    }
}
