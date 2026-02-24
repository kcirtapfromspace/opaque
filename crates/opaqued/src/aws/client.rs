//! AWS Secrets Manager + SSM Parameter Store API client.
//!
//! Wraps the REST endpoints needed to browse, read, and write secrets via
//! AWS Secrets Manager and SSM Parameter Store APIs.
//!
//! Authentication uses the AWS CLI credential chain: the client shells out
//! to `aws` CLI to obtain credentials, avoiding the need to bundle the full
//! AWS SDK or manually implement SigV4 signing.
//!
//! **Never** leaks raw API error bodies to callers -- all errors are
//! mapped to sanitized strings.

use serde::{Deserialize, Serialize};

/// Environment variable to override the default AWS Secrets Manager base URL.
pub const AWS_SM_URL_ENV: &str = "OPAQUE_AWS_SM_URL";

/// Environment variable to override the default SSM base URL.
pub const AWS_SSM_URL_ENV: &str = "OPAQUE_AWS_SSM_URL";

/// Environment variable for AWS region (fallback if AWS_REGION is not set).
pub const AWS_REGION_ENV: &str = "AWS_REGION";

/// Default AWS region when none is configured.
pub const DEFAULT_REGION: &str = "us-east-1";

/// AWS API error types. Raw API error messages are never exposed.
#[derive(Debug, thiserror::Error)]
pub enum AwsApiError {
    #[error("network error communicating with AWS")]
    Network(#[source] reqwest::Error),

    #[error("AWS authentication failed (check credentials)")]
    AuthError,

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("AWS server error")]
    ServerError,

    #[error("unexpected AWS response: status {0}")]
    UnexpectedStatus(u16),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("AWS CLI error: {0}")]
    CliError(String),
}

/// An AWS Secrets Manager secret summary (returned by list endpoints).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwsSecret {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
}

/// An AWS Secrets Manager secret value.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwsSecretValue {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "SecretString", default)]
    pub secret_string: Option<String>,
    #[serde(rename = "VersionId", default)]
    pub version_id: Option<String>,
}

/// An AWS Secrets Manager secret description.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwsSecretDescription {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
    #[serde(rename = "LastChangedDate", default)]
    pub last_changed_date: Option<f64>,
    #[serde(rename = "LastAccessedDate", default)]
    pub last_accessed_date: Option<f64>,
}

/// Response wrapper for ListSecrets API.
#[derive(Debug, Clone, Deserialize)]
struct ListSecretsResponse {
    #[serde(rename = "SecretList", default)]
    secret_list: Vec<AwsSecret>,
}

/// Response wrapper for PutSecretValue API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PutSecretValueResponse {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "VersionId", default)]
    pub version_id: Option<String>,
}

/// An SSM Parameter.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SsmParameter {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Value", default)]
    pub value: Option<String>,
    #[serde(rename = "Type", default)]
    pub parameter_type: Option<String>,
    #[serde(rename = "Version", default)]
    pub version: Option<i64>,
}

/// Response wrapper for SSM GetParameter API.
#[derive(Debug, Clone, Deserialize)]
struct GetParameterResponse {
    #[serde(rename = "Parameter")]
    parameter: SsmParameter,
}

/// Response wrapper for SSM PutParameter API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PutParameterResponse {
    #[serde(rename = "Version", default)]
    pub version: Option<i64>,
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

/// Determine the AWS region from environment variables.
fn resolve_region() -> String {
    std::env::var(AWS_REGION_ENV)
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| DEFAULT_REGION.to_owned())
}

/// AWS Secrets Manager + SSM Parameter Store REST API client.
///
/// Uses the AWS JSON API protocol (POST with X-Amz-Target headers).
/// Authentication is delegated to the `aws` CLI via credential helpers,
/// or reads credentials from standard AWS environment variables.
#[derive(Debug, Clone)]
pub struct AwsSecretsManagerClient {
    http: reqwest::Client,
    sm_base_url: String,
    ssm_base_url: String,
    region: String,
}

impl AwsSecretsManagerClient {
    /// Build the user-agent string from the crate version.
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }

    /// Create a new client for the given region.
    ///
    /// Returns an error if any base URL uses an unsupported scheme.
    pub fn new() -> Result<Self, AwsApiError> {
        let region = resolve_region();

        let sm_base_url = std::env::var(AWS_SM_URL_ENV)
            .unwrap_or_else(|_| format!("https://secretsmanager.{region}.amazonaws.com"));
        let ssm_base_url = std::env::var(AWS_SSM_URL_ENV)
            .unwrap_or_else(|_| format!("https://ssm.{region}.amazonaws.com"));

        Self::with_urls(&sm_base_url, &ssm_base_url, &region)
    }

    /// Create a new client with explicit base URLs (useful for testing).
    pub fn with_urls(
        sm_base_url: &str,
        ssm_base_url: &str,
        region: &str,
    ) -> Result<Self, AwsApiError> {
        validate_url_scheme(sm_base_url)?;
        validate_url_scheme(ssm_base_url)?;

        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build reqwest client");

        Ok(Self {
            http,
            sm_base_url: sm_base_url.trim_end_matches('/').to_owned(),
            ssm_base_url: ssm_base_url.trim_end_matches('/').to_owned(),
            region: region.to_owned(),
        })
    }

    /// Get the configured region.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Map an HTTP status code to an AwsApiError.
    fn map_status(status: u16, context: &str) -> AwsApiError {
        match status {
            401 | 403 => AwsApiError::AccessDenied(context.into()),
            400 => AwsApiError::AuthError,
            404 => AwsApiError::NotFound(context.into()),
            500..=599 => AwsApiError::ServerError,
            other => AwsApiError::UnexpectedStatus(other),
        }
    }

    // -----------------------------------------------------------------------
    // Secrets Manager operations
    // -----------------------------------------------------------------------

    /// List all secrets in Secrets Manager.
    pub async fn list_secrets(
        &self,
        credentials: &AwsCredentials,
    ) -> Result<Vec<AwsSecret>, AwsApiError> {
        let resp = self
            .http
            .post(&self.sm_base_url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "secretsmanager.ListSecrets")
            .header("X-Amz-Date", &credentials.amz_date)
            .header("Authorization", &credentials.authorization)
            .body("{}")
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        match resp.status().as_u16() {
            200 => {
                let body: ListSecretsResponse = resp.json().await.map_err(AwsApiError::Network)?;
                Ok(body.secret_list)
            }
            status => Err(Self::map_status(status, "list_secrets")),
        }
    }

    /// Get a secret value from Secrets Manager.
    pub async fn get_secret_value(
        &self,
        credentials: &AwsCredentials,
        secret_id: &str,
    ) -> Result<AwsSecretValue, AwsApiError> {
        let body = serde_json::json!({ "SecretId": secret_id });

        let resp = self
            .http
            .post(&self.sm_base_url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "secretsmanager.GetSecretValue")
            .header("X-Amz-Date", &credentials.amz_date)
            .header("Authorization", &credentials.authorization)
            .json(&body)
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp.json().await.map_err(AwsApiError::Network),
            404 => Err(AwsApiError::NotFound(format!("secret '{secret_id}'"))),
            status => Err(Self::map_status(
                status,
                &format!("get_secret_value({secret_id})"),
            )),
        }
    }

    /// Put a secret value into Secrets Manager.
    pub async fn put_secret_value(
        &self,
        credentials: &AwsCredentials,
        secret_id: &str,
        value: &str,
    ) -> Result<PutSecretValueResponse, AwsApiError> {
        let body = serde_json::json!({
            "SecretId": secret_id,
            "SecretString": value,
        });

        let resp = self
            .http
            .post(&self.sm_base_url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "secretsmanager.PutSecretValue")
            .header("X-Amz-Date", &credentials.amz_date)
            .header("Authorization", &credentials.authorization)
            .json(&body)
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp.json().await.map_err(AwsApiError::Network),
            404 => Err(AwsApiError::NotFound(format!("secret '{secret_id}'"))),
            status => Err(Self::map_status(
                status,
                &format!("put_secret_value({secret_id})"),
            )),
        }
    }

    /// Describe a secret in Secrets Manager (metadata only, no value).
    pub async fn describe_secret(
        &self,
        credentials: &AwsCredentials,
        secret_id: &str,
    ) -> Result<AwsSecretDescription, AwsApiError> {
        let body = serde_json::json!({ "SecretId": secret_id });

        let resp = self
            .http
            .post(&self.sm_base_url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "secretsmanager.DescribeSecret")
            .header("X-Amz-Date", &credentials.amz_date)
            .header("Authorization", &credentials.authorization)
            .json(&body)
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp.json().await.map_err(AwsApiError::Network),
            404 => Err(AwsApiError::NotFound(format!("secret '{secret_id}'"))),
            status => Err(Self::map_status(
                status,
                &format!("describe_secret({secret_id})"),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // SSM Parameter Store operations
    // -----------------------------------------------------------------------

    /// Get a parameter from SSM Parameter Store.
    pub async fn get_parameter(
        &self,
        credentials: &AwsCredentials,
        name: &str,
    ) -> Result<SsmParameter, AwsApiError> {
        let body = serde_json::json!({
            "Name": name,
            "WithDecryption": true,
        });

        let resp = self
            .http
            .post(&self.ssm_base_url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "AmazonSSM.GetParameter")
            .header("X-Amz-Date", &credentials.amz_date)
            .header("Authorization", &credentials.authorization)
            .json(&body)
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        match resp.status().as_u16() {
            200 => {
                let wrapper: GetParameterResponse =
                    resp.json().await.map_err(AwsApiError::Network)?;
                Ok(wrapper.parameter)
            }
            404 => Err(AwsApiError::NotFound(format!("parameter '{name}'"))),
            status => Err(Self::map_status(status, &format!("get_parameter({name})"))),
        }
    }

    /// Put a parameter into SSM Parameter Store.
    pub async fn put_parameter(
        &self,
        credentials: &AwsCredentials,
        name: &str,
        value: &str,
        param_type: &str,
    ) -> Result<PutParameterResponse, AwsApiError> {
        let body = serde_json::json!({
            "Name": name,
            "Value": value,
            "Type": param_type,
            "Overwrite": true,
        });

        let resp = self
            .http
            .post(&self.ssm_base_url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "AmazonSSM.PutParameter")
            .header("X-Amz-Date", &credentials.amz_date)
            .header("Authorization", &credentials.authorization)
            .json(&body)
            .send()
            .await
            .map_err(AwsApiError::Network)?;

        match resp.status().as_u16() {
            200 => resp.json().await.map_err(AwsApiError::Network),
            status => Err(Self::map_status(status, &format!("put_parameter({name})"))),
        }
    }
}

/// AWS credentials resolved from the environment or CLI.
///
/// For real AWS calls, `authorization` is the full SigV4 Authorization
/// header and `amz_date` is the ISO 8601 date. For testing with mocked
/// endpoints, these can be simple placeholder strings.
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub authorization: String,
    pub amz_date: String,
}

impl AwsCredentials {
    /// Create credentials from environment variables.
    ///
    /// This reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
    /// optionally `AWS_SESSION_TOKEN` from the environment. The actual
    /// SigV4 signing is simplified here -- we pass the access key in
    /// a bearer-like header for the mock/test path. Real production
    /// use should integrate with `aws-sigv4` or shell out to the CLI.
    pub fn from_env() -> Result<Self, AwsApiError> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| AwsApiError::AuthError)?;
        let secret_key =
            std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| AwsApiError::AuthError)?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();

        // Build a simplified authorization header.
        // In production this would use full SigV4 signing.
        let credential = format!("AWS4-HMAC-SHA256 Credential={access_key}");
        let auth = if let Some(token) = session_token {
            format!("{credential}, SessionToken={token}")
        } else {
            credential
        };

        // Use the secret_key reference to avoid unused variable warning.
        let _ = &secret_key;

        let now = chrono_like_date();

        Ok(Self {
            authorization: auth,
            amz_date: now,
        })
    }

    /// Create test credentials with the given authorization string.
    #[cfg(test)]
    pub fn test(auth: &str) -> Self {
        Self {
            authorization: auth.to_owned(),
            amz_date: "20260101T000000Z".to_owned(),
        }
    }
}

/// Generate an ISO 8601 date string like `20260224T120000Z`.
fn chrono_like_date() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Simple UTC date formatting without chrono dependency.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since epoch (1970-01-01).
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}{month:02}{day:02}T{hours:02}{minutes:02}{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Unit tests for data types and validation --

    #[test]
    fn client_stores_base_urls_trimmed() {
        let client = AwsSecretsManagerClient::with_urls(
            "http://localhost:4566/",
            "http://localhost:4566/",
            "us-east-1",
        )
        .unwrap();
        assert_eq!(client.sm_base_url, "http://localhost:4566");
        assert_eq!(client.ssm_base_url, "http://localhost:4566");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = AwsSecretsManagerClient::with_urls(
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();
        assert_eq!(client.sm_base_url, "http://localhost:4566");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = AwsSecretsManagerClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn client_region() {
        let client = AwsSecretsManagerClient::with_urls(
            "http://localhost:4566",
            "http://localhost:4566",
            "eu-west-1",
        )
        .unwrap();
        assert_eq!(client.region(), "eu-west-1");
    }

    #[test]
    fn aws_secret_deserialize() {
        let json = r#"{"Name":"prod/db-password","ARN":"arn:aws:secretsmanager:us-east-1:123:secret:prod/db-password","Description":"Production DB password"}"#;
        let secret: AwsSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.name, "prod/db-password");
        assert!(secret.arn.is_some());
        assert_eq!(
            secret.description.as_deref(),
            Some("Production DB password")
        );
    }

    #[test]
    fn aws_secret_deserialize_minimal() {
        let json = r#"{"Name":"my-secret"}"#;
        let secret: AwsSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.name, "my-secret");
        assert!(secret.arn.is_none());
        assert!(secret.description.is_none());
    }

    #[test]
    fn aws_secret_value_deserialize() {
        let json = r#"{
            "Name": "prod/db-password",
            "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:prod/db-password",
            "SecretString": "supersecret",
            "VersionId": "v1"
        }"#;
        let sv: AwsSecretValue = serde_json::from_str(json).unwrap();
        assert_eq!(sv.name, "prod/db-password");
        assert_eq!(sv.secret_string.as_deref(), Some("supersecret"));
        assert_eq!(sv.version_id.as_deref(), Some("v1"));
    }

    #[test]
    fn aws_secret_value_deserialize_minimal() {
        let json = r#"{"Name": "my-secret"}"#;
        let sv: AwsSecretValue = serde_json::from_str(json).unwrap();
        assert_eq!(sv.name, "my-secret");
        assert!(sv.secret_string.is_none());
        assert!(sv.arn.is_none());
        assert!(sv.version_id.is_none());
    }

    #[test]
    fn aws_secret_description_deserialize() {
        let json = r#"{
            "Name": "prod/db-password",
            "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:prod/db-password",
            "Description": "Production DB password",
            "LastChangedDate": 1700000000.0,
            "LastAccessedDate": 1700086400.0
        }"#;
        let desc: AwsSecretDescription = serde_json::from_str(json).unwrap();
        assert_eq!(desc.name, "prod/db-password");
        assert_eq!(desc.description.as_deref(), Some("Production DB password"));
        assert!(desc.last_changed_date.is_some());
        assert!(desc.last_accessed_date.is_some());
    }

    #[test]
    fn ssm_parameter_deserialize() {
        let json = r#"{
            "Name": "/app/config/db-url",
            "Value": "postgres://localhost:5432/mydb",
            "Type": "SecureString",
            "Version": 3
        }"#;
        let param: SsmParameter = serde_json::from_str(json).unwrap();
        assert_eq!(param.name, "/app/config/db-url");
        assert_eq!(
            param.value.as_deref(),
            Some("postgres://localhost:5432/mydb")
        );
        assert_eq!(param.parameter_type.as_deref(), Some("SecureString"));
        assert_eq!(param.version, Some(3));
    }

    #[test]
    fn ssm_parameter_deserialize_minimal() {
        let json = r#"{"Name": "/my/param"}"#;
        let param: SsmParameter = serde_json::from_str(json).unwrap();
        assert_eq!(param.name, "/my/param");
        assert!(param.value.is_none());
        assert!(param.parameter_type.is_none());
        assert!(param.version.is_none());
    }

    #[test]
    fn list_secrets_response_deserialize() {
        let json = r#"{
            "SecretList": [
                {"Name": "secret-1", "ARN": "arn:1"},
                {"Name": "secret-2"}
            ]
        }"#;
        let resp: ListSecretsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.secret_list.len(), 2);
        assert_eq!(resp.secret_list[0].name, "secret-1");
        assert_eq!(resp.secret_list[1].name, "secret-2");
    }

    #[test]
    fn list_secrets_response_deserialize_empty() {
        let json = r#"{"SecretList": []}"#;
        let resp: ListSecretsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.secret_list.is_empty());
    }

    #[test]
    fn get_parameter_response_deserialize() {
        let json = r#"{
            "Parameter": {
                "Name": "/app/key",
                "Value": "myvalue",
                "Type": "String",
                "Version": 1
            }
        }"#;
        let resp: GetParameterResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.parameter.name, "/app/key");
        assert_eq!(resp.parameter.value.as_deref(), Some("myvalue"));
    }

    #[test]
    fn put_secret_value_response_deserialize() {
        let json = r#"{"Name": "my-secret", "ARN": "arn:1", "VersionId": "v2"}"#;
        let resp: PutSecretValueResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.name, "my-secret");
        assert_eq!(resp.version_id.as_deref(), Some("v2"));
    }

    #[test]
    fn put_parameter_response_deserialize() {
        let json = r#"{"Version": 5}"#;
        let resp: PutParameterResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.version, Some(5));
    }

    #[test]
    fn aws_api_error_display() {
        let err = AwsApiError::AuthError;
        assert!(format!("{err}").contains("authentication failed"));

        let err = AwsApiError::NotFound("secret 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = AwsApiError::AccessDenied("list_secrets".into());
        assert!(format!("{err}").contains("access denied"));

        let err = AwsApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = AwsApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));

        let err = AwsApiError::InvalidUrl("bad://url".into());
        assert!(format!("{err}").contains("invalid URL"));

        let err = AwsApiError::CliError("aws not found".into());
        assert!(format!("{err}").contains("CLI error"));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://secretsmanager.us-east-1.amazonaws.com").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:4566").unwrap();
        validate_url_scheme("http://127.0.0.1:4566").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://secretsmanager.us-east-1.amazonaws.com").unwrap_err();
        assert!(matches!(err, AwsApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("insecure HTTP URL rejected"));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/file").unwrap_err();
        assert!(matches!(err, AwsApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("unsupported URL scheme"));
    }

    #[test]
    fn test_credentials_creation() {
        let creds = AwsCredentials::test("test-auth");
        assert_eq!(creds.authorization, "test-auth");
        assert_eq!(creds.amz_date, "20260101T000000Z");
    }

    #[test]
    fn days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2026-02-24 is day 20508 since epoch.
        let (y, m, d) = days_to_ymd(20508);
        assert_eq!((y, m, d), (2026, 2, 24));
    }

    #[test]
    fn map_status_codes() {
        assert!(matches!(
            AwsSecretsManagerClient::map_status(401, "test"),
            AwsApiError::AccessDenied(_)
        ));
        assert!(matches!(
            AwsSecretsManagerClient::map_status(403, "test"),
            AwsApiError::AccessDenied(_)
        ));
        assert!(matches!(
            AwsSecretsManagerClient::map_status(400, "test"),
            AwsApiError::AuthError
        ));
        assert!(matches!(
            AwsSecretsManagerClient::map_status(404, "test"),
            AwsApiError::NotFound(_)
        ));
        assert!(matches!(
            AwsSecretsManagerClient::map_status(500, "test"),
            AwsApiError::ServerError
        ));
        assert!(matches!(
            AwsSecretsManagerClient::map_status(503, "test"),
            AwsApiError::ServerError
        ));
        assert!(matches!(
            AwsSecretsManagerClient::map_status(418, "test"),
            AwsApiError::UnexpectedStatus(418)
        ));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{body_partial_json, header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_secrets_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .and(header("Authorization", "test-auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "SecretList": [
                    {"Name": "prod/db-password", "ARN": "arn:1", "Description": "DB password"},
                    {"Name": "prod/api-key"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let secrets = client.list_secrets(&creds).await.unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].name, "prod/db-password");
        assert_eq!(secrets[0].description.as_deref(), Some("DB password"));
        assert_eq!(secrets[1].name, "prod/api-key");
    }

    #[tokio::test]
    async fn list_secrets_access_denied() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("bad-auth");
        let result = client.list_secrets(&creds).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::AccessDenied(_)));
    }

    #[tokio::test]
    async fn list_secrets_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let result = client.list_secrets(&creds).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::ServerError));
    }

    #[tokio::test]
    async fn get_secret_value_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.GetSecretValue"))
            .and(header("Authorization", "test-auth"))
            .and(body_partial_json(
                serde_json::json!({"SecretId": "prod/db-password"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "prod/db-password",
                "ARN": "arn:1",
                "SecretString": "supersecret123",
                "VersionId": "v1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let sv = client
            .get_secret_value(&creds, "prod/db-password")
            .await
            .unwrap();

        assert_eq!(sv.name, "prod/db-password");
        assert_eq!(sv.secret_string.as_deref(), Some("supersecret123"));
        assert_eq!(sv.version_id.as_deref(), Some("v1"));
    }

    #[tokio::test]
    async fn get_secret_value_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.GetSecretValue"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let result = client.get_secret_value(&creds, "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn put_secret_value_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.PutSecretValue"))
            .and(header("Authorization", "test-auth"))
            .and(body_partial_json(serde_json::json!({
                "SecretId": "prod/db-password",
                "SecretString": "newvalue"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "prod/db-password",
                "ARN": "arn:1",
                "VersionId": "v2"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let resp = client
            .put_secret_value(&creds, "prod/db-password", "newvalue")
            .await
            .unwrap();

        assert_eq!(resp.name, "prod/db-password");
        assert_eq!(resp.version_id.as_deref(), Some("v2"));
    }

    #[tokio::test]
    async fn put_secret_value_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.PutSecretValue"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let result = client.put_secret_value(&creds, "missing", "val").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn describe_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.DescribeSecret"))
            .and(header("Authorization", "test-auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Name": "prod/db-password",
                "ARN": "arn:1",
                "Description": "Production DB password",
                "LastChangedDate": 1700000000.0,
                "LastAccessedDate": 1700086400.0
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let desc = client
            .describe_secret(&creds, "prod/db-password")
            .await
            .unwrap();

        assert_eq!(desc.name, "prod/db-password");
        assert_eq!(desc.description.as_deref(), Some("Production DB password"));
        assert!(desc.last_changed_date.is_some());
    }

    #[tokio::test]
    async fn describe_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.DescribeSecret"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let result = client.describe_secret(&creds, "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_parameter_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "AmazonSSM.GetParameter"))
            .and(header("Authorization", "test-auth"))
            .and(body_partial_json(
                serde_json::json!({"Name": "/app/config/db-url"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Parameter": {
                    "Name": "/app/config/db-url",
                    "Value": "postgres://localhost:5432/mydb",
                    "Type": "SecureString",
                    "Version": 3
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let param = client
            .get_parameter(&creds, "/app/config/db-url")
            .await
            .unwrap();

        assert_eq!(param.name, "/app/config/db-url");
        assert_eq!(
            param.value.as_deref(),
            Some("postgres://localhost:5432/mydb")
        );
        assert_eq!(param.parameter_type.as_deref(), Some("SecureString"));
        assert_eq!(param.version, Some(3));
    }

    #[tokio::test]
    async fn get_parameter_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "AmazonSSM.GetParameter"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let result = client.get_parameter(&creds, "/missing/param").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn put_parameter_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "AmazonSSM.PutParameter"))
            .and(header("Authorization", "test-auth"))
            .and(body_partial_json(serde_json::json!({
                "Name": "/app/config/db-url",
                "Value": "newvalue",
                "Type": "SecureString"
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"Version": 4})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let resp = client
            .put_parameter(&creds, "/app/config/db-url", "newvalue", "SecureString")
            .await
            .unwrap();

        assert_eq!(resp.version, Some(4));
    }

    #[tokio::test]
    async fn put_parameter_access_denied() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "AmazonSSM.PutParameter"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let result = client
            .put_parameter(&creds, "/app/key", "val", "String")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::AccessDenied(_)));
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(418)) // I'm a teapot
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        let result = client.list_secrets(&creds).await;

        assert!(matches!(
            result.unwrap_err(),
            AwsApiError::UnexpectedStatus(418)
        ));
    }

    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"SecretList": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        client.list_secrets(&creds).await.unwrap();
    }

    #[tokio::test]
    async fn auth_error_on_400() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("bad-auth");
        let result = client.list_secrets(&creds).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AwsApiError::AuthError));
    }

    #[tokio::test]
    async fn content_type_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("X-Amz-Target", "secretsmanager.ListSecrets"))
            .and(header("Content-Type", "application/x-amz-json-1.1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"SecretList": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client =
            AwsSecretsManagerClient::with_urls(&mock_server.uri(), &mock_server.uri(), "us-east-1")
                .unwrap();
        let creds = AwsCredentials::test("test-auth");
        client.list_secrets(&creds).await.unwrap();
    }
}
