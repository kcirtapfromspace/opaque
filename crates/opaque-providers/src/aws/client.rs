//! AWS regional client using the official AWS Signature V4 signer.
//!
//! Credentials are supplied explicitly; no SDK ambient credential chain, endpoint
//! overrides, redirect following or automatic request retry is enabled. STS uses
//! Query/XML; Secrets Manager and SSM use their AWS JSON protocols.

use opaque_core::resolver::{BaseResolver, SecretResolver};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

pub const AWS_ALLOW_INSECURE_ENV: &str = "OPAQUE_AWS_ALLOW_INSECURE";
pub const AWS_MOCK_URL_ENV: &str = "OPAQUE_AWS_MOCK_URL";
pub const AWS_REGION_ENV: &str = "OPAQUE_AWS_REGION";
pub const AWS_SESSION_TOKEN_REF_ENV: &str = "OPAQUE_AWS_SESSION_TOKEN_REF";
/// Public synthetic fixture values, never real AWS credentials.
pub const FIXTURE_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
pub const FIXTURE_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
pub const FIXTURE_SESSION_TOKEN: &str = "opaque-aws-fixture-session-token";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_COLLECTION_ITEMS: usize = 10_000;
const MAX_COLLECTION_PAGES: usize = 100;

/// Errors expose only fixed classifications, never response bodies, URLs or keys.
#[derive(Debug, thiserror::Error)]
pub enum AwsApiError {
    #[error("AWS fixture requires explicit loopback configuration and synthetic credentials")]
    MockOnly,
    #[error("invalid AWS region, endpoint or credential reference")]
    Configuration,
    #[error("AWS transport outcome unknown; no automatic retry was attempted")]
    Network,
    #[error("AWS authentication or authorization failed")]
    Unauthorized,
    #[error("AWS resource not found")]
    NotFound,
    #[error("AWS service unavailable; no automatic retry was attempted")]
    ServerError,
    #[error("AWS request rejected")]
    BadRequest,
    #[error("unexpected AWS response status {0}")]
    UnexpectedStatus(u16),
    #[error("invalid or oversized AWS response")]
    ParseError,
    #[error("AWS collection exceeds configured safety bounds")]
    CollectionLimit,
    #[error("AWS request signing failed")]
    Signing,
}

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
#[derive(Clone, Deserialize, Serialize)]
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
#[derive(Clone, Deserialize, Serialize)]
pub struct SecretValue {
    #[serde(rename = "ARN", default)]
    pub arn: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "SecretString", default)]
    pub secret_string: Option<String>,
    #[serde(rename = "SecretBinary", default)]
    pub secret_binary: Option<String>,
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
#[derive(Clone, Deserialize, Serialize)]
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
#[derive(Clone, Deserialize, Serialize)]
pub struct GetParameterResponse {
    #[serde(rename = "Parameter")]
    pub parameter: SsmParameter,
}

/// SSM GetParametersByPath response.
#[derive(Clone, Deserialize, Serialize)]
pub struct GetParametersByPathResponse {
    #[serde(rename = "Parameters", default)]
    pub parameters: Vec<SsmParameter>,
    #[serde(rename = "NextToken", default)]
    pub next_token: Option<String>,
}

macro_rules! redacted_debug {
    ($($name:ty),*) => {$ (
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )*};
}
redacted_debug!(
    AssumedRoleCredentials,
    SecretValue,
    SsmParameter,
    GetParameterResponse,
    GetParametersByPathResponse
);

impl SecretValue {
    pub fn into_secret_bytes(self) -> Result<Vec<u8>, AwsApiError> {
        use base64::Engine;
        match (self.secret_string, self.secret_binary) {
            (Some(value), None) => Ok(value.into_bytes()),
            (None, Some(value)) => base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| AwsApiError::ParseError),
            _ => Err(AwsApiError::ParseError),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AwsClient {
    http: reqwest::Client,
    region: String,
    sts_url: String,
    secretsmanager_url: String,
    ssm_url: String,
    fixture: bool,
    session_token_ref: Option<String>,
}

pub(super) fn valid_credential_ref(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return false;
    }
    if let Some(name) = value.strip_prefix("env:") {
        return !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    }
    value
        .strip_prefix("keychain:")
        .and_then(|v| v.split_once('/'))
        .is_some_and(|(service, account)| !service.is_empty() && !account.is_empty())
}

fn region_suffix(region: &str) -> Result<&'static str, AwsApiError> {
    let parts: Vec<_> = region.split('-').collect();
    if region.len() > 64
        || parts.len() < 3
        || parts.iter().any(|s| s.is_empty())
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !parts
            .last()
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()))
        || !matches!(
            parts[0],
            "af" | "ap" | "ca" | "cn" | "eu" | "il" | "me" | "mx" | "sa" | "us"
        )
        || region.starts_with("us-iso")
    {
        return Err(AwsApiError::Configuration);
    }
    Ok(if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    })
}

fn validate_fixture_url(value: &str) -> Result<String, AwsApiError> {
    let url = crate::endpoint::parse_endpoint(value).map_err(|_| AwsApiError::MockOnly)?;
    let literal = url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok());
    if !literal.is_some_and(|ip| ip.is_loopback())
        || !matches!(url.scheme(), "http" | "https")
        || url.path() != "/"
    {
        return Err(AwsApiError::MockOnly);
    }
    Ok(url.as_str().trim_end_matches('/').into())
}

impl AwsClient {
    fn http() -> Result<reqwest::Client, AwsApiError> {
        reqwest::Client::builder()
            .user_agent(concat!("opaqued/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| AwsApiError::Configuration)
    }
    /// Bind a production client to canonical AWS regional service origins.
    pub fn for_region(region: &str) -> Result<Self, AwsApiError> {
        let suffix = region_suffix(region)?;
        Ok(Self {
            http: Self::http()?,
            region: region.into(),
            sts_url: format!("https://sts.{region}.{suffix}"),
            secretsmanager_url: format!("https://secretsmanager.{region}.{suffix}"),
            ssm_url: format!("https://ssm.{region}.{suffix}"),
            fixture: false,
            session_token_ref: None,
        })
    }
    /// Explicit configuration only. Invalid fixture settings never fall back to AWS.
    pub fn from_env() -> Result<Option<Self>, AwsApiError> {
        let fixture_url = std::env::var(AWS_MOCK_URL_ENV).ok();
        let fixture_flag = std::env::var(AWS_ALLOW_INSECURE_ENV).ok();
        let mut client = if fixture_url.is_some() || fixture_flag.is_some() {
            if fixture_flag.as_deref() != Some("1") {
                return Err(AwsApiError::MockOnly);
            }
            let url = fixture_url.ok_or(AwsApiError::MockOnly)?;
            Self::new(&url, &url, &url)?
        } else if let Ok(region) = std::env::var(AWS_REGION_ENV) {
            Self::for_region(&region)?
        } else {
            return Ok(None);
        };
        if let Ok(reference) = std::env::var(AWS_SESSION_TOKEN_REF_ENV) {
            client = client.with_session_token_ref(&reference)?;
        }
        Ok(Some(client))
    }
    /// Backward-compatible fixture-only constructor. Production callers use from_env.
    pub fn from_mock_env() -> Result<Option<Self>, AwsApiError> {
        if std::env::var(AWS_ALLOW_INSECURE_ENV).as_deref() != Ok("1") {
            return Ok(None);
        }
        let url = std::env::var(AWS_MOCK_URL_ENV).map_err(|_| AwsApiError::MockOnly)?;
        Self::new(&url, &url, &url).map(Some)
    }
    /// Loopback fixture constructor; all calls still use real SigV4 and AWS protocols.
    pub fn new(
        sts_url: &str,
        secretsmanager_url: &str,
        ssm_url: &str,
    ) -> Result<Self, AwsApiError> {
        if !cfg!(test) && std::env::var(AWS_ALLOW_INSECURE_ENV).as_deref() != Ok("1") {
            return Err(AwsApiError::MockOnly);
        }
        Ok(Self {
            http: Self::http()?,
            region: "us-east-1".into(),
            sts_url: validate_fixture_url(sts_url)?,
            secretsmanager_url: validate_fixture_url(secretsmanager_url)?,
            ssm_url: validate_fixture_url(ssm_url)?,
            fixture: true,
            session_token_ref: None,
        })
    }
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new_single(url: &str) -> Self {
        Self::new(url, url, url).expect("literal loopback fixture")
    }
    pub fn fixture_only(&self) -> bool {
        self.fixture
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn backend(&self) -> &'static str {
        if self.fixture {
            "signed_loopback_fixture"
        } else {
            "aws_sigv4"
        }
    }
    pub fn session_token_ref(&self) -> Option<&str> {
        self.session_token_ref.as_deref()
    }
    pub fn with_session_token_ref(mut self, reference: &str) -> Result<Self, AwsApiError> {
        if !valid_credential_ref(reference) {
            return Err(AwsApiError::Configuration);
        }
        self.session_token_ref = Some(reference.into());
        Ok(self)
    }
    pub fn ensure_configuration(&self) -> Result<(), AwsApiError> {
        if self.fixture {
            if !cfg!(test) && std::env::var(AWS_ALLOW_INSECURE_ENV).as_deref() != Ok("1") {
                return Err(AwsApiError::MockOnly);
            }
            for url in [&self.sts_url, &self.secretsmanager_url, &self.ssm_url] {
                validate_fixture_url(url)?;
            }
        } else {
            region_suffix(&self.region)?;
        }
        Ok(())
    }
    /// Kept for callers migrating from the previous mock-only adapter.
    pub fn ensure_mock_configuration(&self) -> Result<(), AwsApiError> {
        self.ensure_configuration()
    }
    pub(super) fn endpoint_for_operation(&self, operation: &str) -> Option<&str> {
        match operation {
            "aws.get_caller_identity" | "aws.assume_role" => Some(&self.sts_url),
            "aws.list_secrets"
            | "aws.get_secret_value"
            | "aws.create_secret"
            | "aws.put_secret_value"
            | "aws.delete_secret" => Some(&self.secretsmanager_url),
            "aws.get_parameter"
            | "aws.put_parameter"
            | "aws.get_parameters_by_path"
            | "aws.delete_parameter" => Some(&self.ssm_url),
            _ => None,
        }
    }

    // Keep the signing inputs explicit so protocol tests can pin every SigV4 field.
    #[allow(clippy::too_many_arguments)]
    fn signed_request(
        &self,
        url: &str,
        service: &str,
        target: Option<&str>,
        body: Vec<u8>,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        time: SystemTime,
    ) -> Result<reqwest::Request, AwsApiError> {
        use aws_sigv4::{
            http_request::{SignableBody, SignableRequest, SigningSettings, sign},
            sign::v4,
        };
        self.ensure_configuration()?;
        if body.len() > 1024 * 1024 {
            return Err(AwsApiError::BadRequest);
        }
        if self.fixture
            && (access_key != FIXTURE_ACCESS_KEY
                || secret_key != FIXTURE_SECRET_KEY
                || session_token.is_some_and(|v| v != FIXTURE_SESSION_TOKEN))
        {
            return Err(AwsApiError::MockOnly);
        }
        if access_key.is_empty()
            || access_key.len() > 128
            || !access_key.bytes().all(|b| b.is_ascii_alphanumeric())
            || secret_key.is_empty()
            || secret_key.len() > 512
            || !secret_key.bytes().all(|b| (b'!'..=b'~').contains(&b))
            || session_token.is_some_and(|v| {
                v.is_empty() || v.len() > 16384 || !v.bytes().all(|b| (b'!'..=b'~').contains(&b))
            })
        {
            return Err(AwsApiError::Configuration);
        }
        let content_type = if service == "sts" {
            "application/x-www-form-urlencoded"
        } else {
            "application/x-amz-json-1.1"
        };
        let mut headers = vec![("content-type", content_type)];
        if let Some(target) = target {
            headers.push(("x-amz-target", target));
        }
        let credentials = aws_credential_types::Credentials::new(
            access_key,
            secret_key,
            session_token.map(str::to_owned),
            None,
            "opaque-explicit",
        );
        let identity = credentials.into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(service)
            .time(time)
            .settings(SigningSettings::default())
            .build()
            .map_err(|_| AwsApiError::Signing)?
            .into();
        // Precomputed payload hash keeps raw secret bodies out of SDK debug tracing,
        // including when LOG_SIGNABLE_BODY=true exists in the host environment.
        let signable = SignableRequest::new(
            "POST",
            url,
            headers.iter().copied(),
            SignableBody::Precomputed(format!("{:x}", Sha256::digest(&body))),
        )
        .map_err(|_| AwsApiError::Signing)?;
        let instructions = sign(signable, &params)
            .map_err(|_| AwsApiError::Signing)?
            .into_parts()
            .0;
        let mut request = self.http.post(url).body(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        for (name, value) in instructions.headers() {
            let mut value =
                reqwest::header::HeaderValue::from_str(value).map_err(|_| AwsApiError::Signing)?;
            if name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("x-amz-security-token")
            {
                value.set_sensitive(true);
            }
            request = request.header(name, value);
        }
        request.build().map_err(|_| AwsApiError::Signing)
    }

    async fn send(
        &self,
        service: &str,
        operation: &str,
        body: Vec<u8>,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Vec<u8>, AwsApiError> {
        self.ensure_configuration()?;
        let session = self
            .session_token_ref
            .as_ref()
            .map(|reference| {
                BaseResolver::new()
                    .resolve(reference)
                    .map_err(|_| AwsApiError::Configuration)
                    .and_then(|value| {
                        value
                            .as_str()
                            .map(|s| Zeroizing::new(s.to_owned()))
                            .ok_or(AwsApiError::Configuration)
                    })
            })
            .transpose()?;
        let (url, target) = match service {
            "sts" => (&self.sts_url, None),
            "secretsmanager" => (
                &self.secretsmanager_url,
                Some(format!("secretsmanager.{operation}")),
            ),
            "ssm" => (&self.ssm_url, Some(format!("AmazonSSM.{operation}"))),
            _ => return Err(AwsApiError::Configuration),
        };
        let request = self.signed_request(
            url,
            service,
            target.as_deref(),
            body,
            access_key,
            secret_key,
            session.as_ref().map(|v| v.as_str()),
            SystemTime::now(),
        )?;
        let mut response = self
            .http
            .execute(request)
            .await
            .map_err(|_| AwsApiError::Network)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(AwsApiError::ParseError);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| AwsApiError::Network)? {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(AwsApiError::ParseError);
            }
            bytes.extend_from_slice(&chunk);
        }
        if status != 200 {
            return Err(error_response(status, &bytes));
        }
        Ok(bytes)
    }
    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        service: &str,
        operation: &str,
        body: serde_json::Value,
        access: &str,
        secret: &str,
    ) -> Result<T, AwsApiError> {
        let bytes = serde_json::to_vec(&body).map_err(|_| AwsApiError::BadRequest)?;
        let bytes = self.send(service, operation, bytes, access, secret).await?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| AwsApiError::ParseError)?;
        if !value.is_object() || value.get("__type").is_some() || value.get("Error").is_some() {
            return Err(AwsApiError::ParseError);
        }
        serde_json::from_value(value).map_err(|_| AwsApiError::ParseError)
    }
    async fn sts<T: serde::de::DeserializeOwned>(
        &self,
        operation: &str,
        fields: &[(&str, &str)],
        access: &str,
        secret: &str,
    ) -> Result<T, AwsApiError> {
        let mut query = reqwest::Url::parse("https://sts.invalid/").expect("static URL");
        {
            let mut pairs = query.query_pairs_mut();
            pairs
                .append_pair("Action", operation)
                .append_pair("Version", "2011-06-15");
            for (key, value) in fields {
                pairs.append_pair(key, value);
            }
        }
        let bytes = self
            .send(
                "sts",
                operation,
                query.query().expect("query").as_bytes().to_vec(),
                access,
                secret,
            )
            .await?;
        quick_xml::de::from_reader(bytes.as_slice()).map_err(|_| AwsApiError::ParseError)
    }
    pub async fn get_caller_identity(
        &self,
        access: &str,
        secret: &str,
    ) -> Result<CallerIdentity, AwsApiError> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "GetCallerIdentityResult")]
            result: CallerIdentity,
        }
        Ok(self
            .sts::<Response>("GetCallerIdentity", &[], access, secret)
            .await?
            .result)
    }
    pub async fn assume_role(
        &self,
        access: &str,
        secret: &str,
        role_arn: &str,
        session_name: &str,
    ) -> Result<AssumedRoleCredentials, AwsApiError> {
        #[derive(Deserialize)]
        struct ResultBody {
            #[serde(rename = "Credentials")]
            credentials: AssumedRoleCredentials,
        }
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "AssumeRoleResult")]
            result: ResultBody,
        }
        Ok(self
            .sts::<Response>(
                "AssumeRole",
                &[("RoleArn", role_arn), ("RoleSessionName", session_name)],
                access,
                secret,
            )
            .await?
            .result
            .credentials)
    }
    pub async fn get_secret_value(
        &self,
        access: &str,
        secret: &str,
        secret_id: &str,
    ) -> Result<SecretValue, AwsApiError> {
        self.json(
            "secretsmanager",
            "GetSecretValue",
            serde_json::json!({"SecretId":secret_id}),
            access,
            secret,
        )
        .await
    }
    pub async fn create_secret(
        &self,
        access: &str,
        secret: &str,
        name: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<CreateSecretResponse, AwsApiError> {
        let mut body = serde_json::json!({"Name":name,"SecretString":value,"ClientRequestToken":uuid::Uuid::new_v4().to_string()});
        if let Some(description) = description {
            body["Description"] = description.into();
        }
        let response: CreateSecretResponse = self
            .json("secretsmanager", "CreateSecret", body, access, secret)
            .await?;
        if response.name != name || response.version_id.as_deref().is_none_or(str::is_empty) {
            return Err(AwsApiError::ParseError);
        }
        Ok(response)
    }
    pub async fn put_secret_value(
        &self,
        access: &str,
        secret: &str,
        secret_id: &str,
        value: &str,
    ) -> Result<(), AwsApiError> {
        let response: CreateSecretResponse = self.json("secretsmanager", "PutSecretValue", serde_json::json!({"SecretId":secret_id,"SecretString":value,"ClientRequestToken":uuid::Uuid::new_v4().to_string()}), access, secret).await?;
        if response.name.is_empty() || response.version_id.as_deref().is_none_or(str::is_empty) {
            return Err(AwsApiError::ParseError);
        }
        Ok(())
    }
    pub async fn delete_secret(
        &self,
        access: &str,
        secret: &str,
        secret_id: &str,
    ) -> Result<(), AwsApiError> {
        let response: serde_json::Value = self
            .json(
                "secretsmanager",
                "DeleteSecret",
                serde_json::json!({"SecretId":secret_id,"ForceDeleteWithoutRecovery":false}),
                access,
                secret,
            )
            .await?;
        if response
            .get("Name")
            .and_then(|v| v.as_str())
            .is_none_or(str::is_empty)
            || response
                .get("DeletionDate")
                .and_then(|v| v.as_f64())
                .is_none_or(|v| !v.is_finite() || v <= 0.0)
        {
            return Err(AwsApiError::ParseError);
        }
        Ok(())
    }
    pub async fn get_parameter(
        &self,
        access: &str,
        secret: &str,
        name: &str,
        with_decryption: bool,
    ) -> Result<SsmParameter, AwsApiError> {
        let response: GetParameterResponse = self
            .json(
                "ssm",
                "GetParameter",
                serde_json::json!({"Name":name,"WithDecryption":with_decryption}),
                access,
                secret,
            )
            .await?;
        Ok(response.parameter)
    }
    pub async fn put_parameter(
        &self,
        access: &str,
        secret: &str,
        name: &str,
        value: &str,
        parameter_type: &str,
        overwrite: bool,
    ) -> Result<(), AwsApiError> {
        let response: serde_json::Value = self.json("ssm", "PutParameter", serde_json::json!({"Name":name,"Value":value,"Type":parameter_type,"Overwrite":overwrite}), access, secret).await?;
        if response
            .get("Version")
            .and_then(|v| v.as_u64())
            .is_none_or(|v| v == 0)
        {
            return Err(AwsApiError::ParseError);
        }
        Ok(())
    }
    pub async fn delete_parameter(
        &self,
        access: &str,
        secret: &str,
        name: &str,
    ) -> Result<(), AwsApiError> {
        let response: serde_json::Value = self
            .json(
                "ssm",
                "DeleteParameter",
                serde_json::json!({"Name":name}),
                access,
                secret,
            )
            .await?;
        if !response.as_object().is_some_and(serde_json::Map::is_empty) {
            return Err(AwsApiError::ParseError);
        }
        Ok(())
    }
    pub async fn list_secrets(
        &self,
        access: &str,
        secret: &str,
    ) -> Result<ListSecretsResponse, AwsApiError> {
        let values = self
            .collect(
                "secretsmanager",
                "ListSecrets",
                serde_json::json!({"MaxResults":100}),
                "SecretList",
                access,
                secret,
            )
            .await?;
        let secret_list = serde_json::from_value(serde_json::Value::Array(values))
            .map_err(|_| AwsApiError::ParseError)?;
        Ok(ListSecretsResponse {
            secret_list,
            next_token: None,
        })
    }
    pub async fn get_parameters_by_path(
        &self,
        access: &str,
        secret: &str,
        path: &str,
        with_decryption: bool,
    ) -> Result<GetParametersByPathResponse, AwsApiError> {
        let values = self.collect("ssm", "GetParametersByPath", serde_json::json!({"Path":path,"WithDecryption":with_decryption,"Recursive":true,"MaxResults":10}), "Parameters", access, secret).await?;
        let parameters = serde_json::from_value(serde_json::Value::Array(values))
            .map_err(|_| AwsApiError::ParseError)?;
        Ok(GetParametersByPathResponse {
            parameters,
            next_token: None,
        })
    }
    async fn collect(
        &self,
        service: &str,
        operation: &str,
        mut body: serde_json::Value,
        field: &str,
        access: &str,
        secret: &str,
    ) -> Result<Vec<serde_json::Value>, AwsApiError> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut items = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            let mut total_bytes = 0usize;
            for _ in 0..MAX_COLLECTION_PAGES {
                let page: serde_json::Value = self
                    .json(service, operation, body.clone(), access, secret)
                    .await?;
                total_bytes = total_bytes.saturating_add(
                    serde_json::to_vec(&page)
                        .map_err(|_| AwsApiError::ParseError)?
                        .len(),
                );
                if total_bytes > 8 * 1024 * 1024 {
                    return Err(AwsApiError::CollectionLimit);
                }
                if page.as_object().is_none_or(|object| {
                    object.keys().any(|key| key != field && key != "NextToken")
                }) {
                    return Err(AwsApiError::ParseError);
                }
                if let Some(entries) = page.get(field) {
                    items.extend(
                        entries
                            .as_array()
                            .ok_or(AwsApiError::ParseError)?
                            .iter()
                            .cloned(),
                    );
                }
                if items.len() > MAX_COLLECTION_ITEMS {
                    return Err(AwsApiError::CollectionLimit);
                }
                match page.get("NextToken") {
                    None | Some(serde_json::Value::Null) => return Ok(items),
                    Some(serde_json::Value::String(token))
                        if !token.is_empty()
                            && token.len() <= 8192
                            && seen.insert(token.clone()) =>
                    {
                        body["NextToken"] = token.clone().into();
                    }
                    _ => return Err(AwsApiError::CollectionLimit),
                }
            }
            Err(AwsApiError::CollectionLimit)
        })
        .await
        .map_err(|_| AwsApiError::Network)?
    }
}

fn error_response(status: u16, bytes: &[u8]) -> AwsApiError {
    #[derive(Deserialize)]
    struct XmlError {
        #[serde(rename = "Code")]
        code: String,
    }
    #[derive(Deserialize)]
    struct XmlEnvelope {
        #[serde(rename = "Error")]
        error: XmlError,
    }
    let code = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("__type")
                .or_else(|| value.get("code"))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .or_else(|| {
            quick_xml::de::from_reader::<_, XmlEnvelope>(bytes)
                .ok()
                .map(|e| e.error.code)
        });
    match code.as_deref().map(|v| v.rsplit('#').next().unwrap_or(v)) {
        Some("ResourceNotFoundException" | "ParameterNotFound" | "ParameterVersionNotFound") => {
            AwsApiError::NotFound
        }
        Some(
            "AccessDenied"
            | "AccessDeniedException"
            | "InvalidClientTokenId"
            | "UnrecognizedClientException"
            | "ExpiredToken"
            | "ExpiredTokenException"
            | "SignatureDoesNotMatch",
        ) => AwsApiError::Unauthorized,
        Some("Throttling" | "ThrottlingException" | "TooManyRequestsException") => {
            AwsApiError::ServerError
        }
        _ => match status {
            400 => AwsApiError::BadRequest,
            401 | 403 => AwsApiError::Unauthorized,
            404 => AwsApiError::NotFound,
            429 | 500..=599 => AwsApiError::ServerError,
            n => AwsApiError::UnexpectedStatus(n),
        },
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "protocol_tests.rs"]
mod tests;
