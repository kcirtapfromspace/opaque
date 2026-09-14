//! Google Secret Manager REST v1 with fixed OAuth authority and deferred credentials.
use base64::Engine;
use opaque_core::resolver::{BaseResolver, SecretResolver};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashSet;
use std::io::Read;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub const GCP_SM_URL_ENV: &str = "OPAQUE_GCP_SM_URL";
pub const DEFAULT_BASE_URL: &str = "https://secretmanager.googleapis.com/v1";
pub const GCP_ACCESS_TOKEN_ENV: &str = "OPAQUE_GCP_ACCESS_TOKEN";
pub const GCP_SERVICE_ACCOUNT_KEY_ENV: &str = "OPAQUE_GCP_SERVICE_ACCOUNT_KEY";
pub const GCP_TOKEN_REF_ENV: &str = "OPAQUE_GCP_TOKEN_REF";
pub const GCP_SERVICE_ACCOUNT_REF_ENV: &str = "OPAQUE_GCP_SERVICE_ACCOUNT_REF";
const OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const MAX_BODY: usize = 256 * 1024;
const MAX_SECRET: usize = 64 * 1024;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug, thiserror::Error)]
pub enum GcpApiError {
    #[error("invalid GCP endpoint or selector: {0}")]
    InvalidUrl(String),
    #[error("network error communicating with GCP Secret Manager")]
    HttpError(#[source] reqwest::Error),
    #[error("GCP Secret Manager authentication failed")]
    AuthError(String),
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("GCP Secret Manager permission denied")]
    PermissionDenied,
    #[error("GCP Secret Manager server error")]
    ServerError,
    #[error("unexpected GCP Secret Manager response: status {0}")]
    UnexpectedStatus(u16),
    #[error("GCP returned invalid, oversized or incomplete data")]
    InvalidResponse,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpSecret {
    pub name: String,
    #[serde(default)]
    pub replication: Option<serde_json::Value>,
    #[serde(default, rename = "createTime")]
    pub create_time: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpSecretVersion {
    pub name: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default, rename = "createTime")]
    pub create_time: Option<String>,
}
#[derive(Clone, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct GcpSecretPayload {
    pub data: String,
    #[serde(default, rename = "dataCrc32c")]
    pub data_crc32c: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct GcpAccessSecretVersionResponse {
    #[serde(default)]
    pub name: Option<String>,
    pub payload: GcpSecretPayload,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpListSecretsResponse {
    #[serde(default)]
    pub secrets: Vec<GcpSecret>,
    #[serde(default, rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthBinding {
    AccessToken { credential_ref: String },
    ServiceAccount { credential_ref: String },
    ServiceAccountFile { path: String },
}
impl AuthBinding {
    pub fn refs(&self) -> Vec<String> {
        match self {
            Self::AccessToken { credential_ref } | Self::ServiceAccount { credential_ref } => {
                vec![credential_ref.clone()]
            }
            Self::ServiceAccountFile { path } => vec![format!("gcp-service-account-file:{path}")],
        }
    }
}
struct CachedToken {
    token: Zeroizing<String>,
    expires_at: Instant,
    credential_sha256: String,
}
#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}
#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    token_type: Option<String>,
}

pub fn validate_ref(value: &str) -> Result<(), String> {
    if let Some(name) = value.strip_prefix("env:") {
        if !name.is_empty()
            && name.len() <= 256
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Ok(());
        }
    } else if let Some(path) = value.strip_prefix("keychain:")
        && path.len() <= 512
        && path
            .split_once('/')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
        && path.bytes().all(|b| b.is_ascii_graphic())
    {
        return Ok(());
    }
    Err(
        "credential/value reference must be an explicit env:NAME or keychain:service/account"
            .into(),
    )
}
fn canonical_number(value: &str) -> bool {
    !value.starts_with('0')
        && value.len() <= 20
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|n| n > 0)
}
/// Canonical project numbers avoid an implicit project-ID-to-number mapping.
pub fn validate_project(value: &str) -> Result<(), GcpApiError> {
    if canonical_number(value) {
        Ok(())
    } else {
        Err(GcpApiError::InvalidUrl(
            "numeric project number required".into(),
        ))
    }
}
fn validate_returned_resource(
    value: &str,
    project: &str,
    secret: Option<&str>,
    versioned: bool,
    requested_version: Option<&str>,
) -> Result<(), GcpApiError> {
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() != if versioned { 6 } else { 4 }
        || parts[0] != "projects"
        || parts[1] != project
        || parts[2] != "secrets"
        || validate_secret(parts[3]).is_err()
        || secret.is_some_and(|expected| parts[3] != expected)
        || versioned && (parts[4] != "versions" || !canonical_number(parts[5]))
        || requested_version
            .is_some_and(|expected| canonical_number(expected) && parts[5] != expected)
    {
        return Err(GcpApiError::InvalidResponse);
    }
    Ok(())
}
pub fn validate_secret(value: &str) -> Result<(), GcpApiError> {
    if !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(GcpApiError::InvalidUrl("invalid secret ID".into()))
    }
}
pub fn validate_version(value: &str) -> Result<(), GcpApiError> {
    if canonical_number(value)
        || !value.is_empty()
            && value.len() <= 63
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(GcpApiError::InvalidUrl(
            "invalid version number or alias".into(),
        ))
    }
}
fn validate_url_scheme(value: &str) -> Result<(), GcpApiError> {
    let u =
        reqwest::Url::parse(value).map_err(|_| GcpApiError::InvalidUrl("invalid URL".into()))?;
    if u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || !(u.scheme() == "https"
            || cfg!(test)
                && u.scheme() == "http"
                && matches!(u.host_str(), Some("localhost" | "127.0.0.1")))
    {
        return Err(GcpApiError::InvalidUrl(
            "trusted HTTPS endpoint required".into(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct GcpSecretManagerClient {
    http: reqwest::Client,
    base_url: String,
    auth: AuthBinding,
    token_cache: std::sync::Arc<tokio::sync::Mutex<Option<CachedToken>>>,
    #[cfg(test)]
    token_endpoint_override: Option<String>,
}
impl std::fmt::Debug for GcpSecretManagerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpSecretManagerClient")
            .finish_non_exhaustive()
    }
}
impl GcpSecretManagerClient {
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }
    pub fn from_env() -> Result<Option<Self>, GcpApiError> {
        if ![
            GCP_TOKEN_REF_ENV,
            GCP_SERVICE_ACCOUNT_REF_ENV,
            GCP_SERVICE_ACCOUNT_KEY_ENV,
            GCP_ACCESS_TOKEN_ENV,
        ]
        .iter()
        .any(|n| std::env::var_os(n).is_some_and(|value| !value.is_empty()))
        {
            return Ok(None);
        }
        Self::new(&std::env::var(GCP_SM_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_URL.into()))
            .map(Some)
    }
    pub fn new(base_url: &str) -> Result<Self, GcpApiError> {
        let auth = if let Some(credential_ref) = std::env::var(GCP_SERVICE_ACCOUNT_REF_ENV)
            .ok()
            .filter(|value| !value.is_empty())
        {
            AuthBinding::ServiceAccount { credential_ref }
        } else if let Some(path) = std::env::var(GCP_SERVICE_ACCOUNT_KEY_ENV)
            .ok()
            .filter(|value| !value.is_empty())
        {
            if !std::path::Path::new(&path).is_absolute() {
                return Err(GcpApiError::AuthError("absolute key path required".into()));
            }
            AuthBinding::ServiceAccountFile { path }
        } else {
            AuthBinding::AccessToken {
                credential_ref: std::env::var(GCP_TOKEN_REF_ENV)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("env:{GCP_ACCESS_TOKEN_ENV}")),
            }
        };
        Self::with_auth(base_url, auth)
    }
    pub fn with_auth(base_url: &str, auth: AuthBinding) -> Result<Self, GcpApiError> {
        validate_url_scheme(base_url)?;
        let base_url = base_url.trim_end_matches('/').to_owned();
        if !cfg!(test) {
            validate_production_endpoint(&base_url)?;
        }
        match &auth {
            AuthBinding::AccessToken { credential_ref }
            | AuthBinding::ServiceAccount { credential_ref } => {
                validate_ref(credential_ref).map_err(GcpApiError::AuthError)?
            }
            AuthBinding::ServiceAccountFile { path } => {
                if !std::path::Path::new(path).is_absolute() {
                    return Err(GcpApiError::AuthError("absolute key path required".into()));
                }
            }
        }
        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(GcpApiError::HttpError)?;
        Ok(Self {
            http,
            base_url,
            auth,
            token_cache: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            #[cfg(test)]
            token_endpoint_override: None,
        })
    }
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    pub fn auth_binding(&self) -> &AuthBinding {
        &self.auth
    }
    pub fn token_endpoint(&self) -> &str {
        #[cfg(test)]
        if let Some(url) = &self.token_endpoint_override {
            return url;
        }
        OAUTH2_TOKEN_URL
    }
    fn credentials(&self) -> Result<Zeroizing<Vec<u8>>, GcpApiError> {
        let failed = || GcpApiError::AuthError("credential unavailable".into());
        match &self.auth {
            AuthBinding::AccessToken { credential_ref }
            | AuthBinding::ServiceAccount { credential_ref } => {
                let value = BaseResolver::new()
                    .resolve(credential_ref)
                    .map_err(|_| failed())?;
                if value.as_bytes().len() > MAX_SECRET {
                    return Err(failed());
                }
                Ok(Zeroizing::new(value.as_bytes().to_vec()))
            }
            AuthBinding::ServiceAccountFile { path } => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(path)
                        .map_err(|_| failed())?;
                    let meta = file.metadata().map_err(|_| failed())?;
                    if !meta.is_file()
                        || meta.mode() & 0o077 != 0
                        || meta.uid() != unsafe { libc::geteuid() }
                        || meta.len() > MAX_SECRET as u64
                    {
                        return Err(failed());
                    }
                    let mut bytes = Zeroizing::new(Vec::new());
                    file.take(MAX_SECRET as u64 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|_| failed())?;
                    if bytes.len() > MAX_SECRET {
                        return Err(failed());
                    }
                    Ok(bytes)
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err(failed())
                }
            }
        }
    }
    pub async fn get_access_token(&self) -> Result<Zeroizing<String>, GcpApiError> {
        let bytes = self.credentials()?;
        if matches!(self.auth, AuthBinding::AccessToken { .. }) {
            let token = std::str::from_utf8(&bytes)
                .map_err(|_| GcpApiError::AuthError("invalid token".into()))?;
            check_token(token)?;
            return Ok(Zeroizing::new(token.to_owned()));
        }
        use sha2::{Digest, Sha256};
        let fingerprint = format!("{:x}", Sha256::digest(&bytes));
        let mut cache = self.token_cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && cached.expires_at > Instant::now()
            && cached.credential_sha256 == fingerprint
        {
            return Ok(cached.token.clone());
        }
        let key: ServiceAccountKey = serde_json::from_slice(&bytes)
            .map_err(|_| GcpApiError::AuthError("invalid service account key".into()))?;
        if key
            .token_uri
            .as_deref()
            .is_some_and(|v| v != OAUTH2_TOKEN_URL)
            || !key.client_email.ends_with(".gserviceaccount.com")
            || key.client_email.len() > 320
        {
            return Err(GcpApiError::AuthError(
                "invalid service account authority".into(),
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| GcpApiError::AuthError("clock unavailable".into()))?
            .as_secs();
        let jwt = Zeroizing::new(create_jwt(&key.client_email, &key.private_key, now)?);
        let response = self
            .http
            .post(self.token_endpoint())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .send()
            .await
            .map_err(GcpApiError::HttpError)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(GcpApiError::AuthError("token exchange failed".into()));
        }
        let data: TokenResponse = read_json(response, 16 * 1024).await?;
        check_token(&data.access_token)?;
        if !(1..=86400).contains(&data.expires_in)
            || data
                .token_type
                .as_deref()
                .is_some_and(|v| !v.eq_ignore_ascii_case("bearer"))
        {
            return Err(GcpApiError::AuthError("invalid token response".into()));
        }
        let token = Zeroizing::new(data.access_token.clone());
        *cache = Some(CachedToken {
            token: token.clone(),
            expires_at: Instant::now() + Duration::from_secs(data.expires_in.saturating_sub(60)),
            credential_sha256: fingerprint,
        });
        Ok(token)
    }
    fn url(
        &self,
        project: &str,
        secret: Option<&str>,
        suffix: &str,
    ) -> Result<reqwest::Url, GcpApiError> {
        validate_project(project)?;
        if let Some(secret) = secret {
            validate_secret(secret)?;
        }
        reqwest::Url::parse(&format!(
            "{}/projects/{project}/secrets{}{suffix}",
            self.base_url,
            secret.map(|s| format!("/{s}")).unwrap_or_default()
        ))
        .map_err(|_| GcpApiError::InvalidUrl("invalid API path".into()))
    }
    async fn fetch<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, GcpApiError> {
        let response = request.send().await.map_err(GcpApiError::HttpError)?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            *self.token_cache.lock().await = None;
        }
        match response.status().as_u16() {
            200..=299 => read_json(response, MAX_BODY).await,
            401 => Err(GcpApiError::AuthError("rejected".into())),
            403 => Err(GcpApiError::PermissionDenied),
            404 => Err(GcpApiError::NotFound("requested resource".into())),
            500..=599 => Err(GcpApiError::ServerError),
            status => Err(GcpApiError::UnexpectedStatus(status)),
        }
    }
    pub async fn list_secrets(
        &self,
        token: &str,
        project: &str,
    ) -> Result<Vec<GcpSecret>, GcpApiError> {
        let base = self.url(project, None, "")?;
        let mut results = Vec::new();
        let mut page: Option<String> = None;
        let mut seen = HashSet::new();
        for _ in 0..40 {
            let mut url = base.clone();
            url.query_pairs_mut().append_pair("pageSize", "100");
            if let Some(p) = &page {
                url.query_pairs_mut().append_pair("pageToken", p);
            }
            let data: GcpListSecretsResponse =
                self.fetch(self.http.get(url).bearer_auth(token)).await?;
            if data.secrets.len() > 100 || results.len() + data.secrets.len() > 4000 {
                return Err(GcpApiError::InvalidResponse);
            }
            for secret in &data.secrets {
                validate_returned_resource(&secret.name, project, None, false, None)?;
            }
            results.extend(data.secrets);
            match data.next_page_token.filter(|v| !v.is_empty()) {
                None => return Ok(results),
                Some(next) => {
                    if next.len() > 4096
                        || next.chars().any(char::is_control)
                        || !seen.insert(next.clone())
                    {
                        return Err(GcpApiError::InvalidResponse);
                    }
                    page = Some(next);
                }
            }
        }
        Err(GcpApiError::InvalidResponse)
    }
    pub async fn get_secret(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
    ) -> Result<GcpSecret, GcpApiError> {
        let result: GcpSecret = self
            .fetch(
                self.http
                    .get(self.url(project, Some(secret_id), "")?)
                    .bearer_auth(token),
            )
            .await?;
        validate_returned_resource(&result.name, project, Some(secret_id), false, None)?;
        Ok(result)
    }
    pub async fn access_secret_version(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
        version: &str,
    ) -> Result<GcpAccessSecretVersionResponse, GcpApiError> {
        validate_version(version)?;
        let value: GcpAccessSecretVersionResponse = self
            .fetch(
                self.http
                    .get(self.url(
                        project,
                        Some(secret_id),
                        &format!("/versions/{version}:access"),
                    )?)
                    .bearer_auth(token),
            )
            .await?;
        let returned = value.name.as_deref().ok_or(GcpApiError::InvalidResponse)?;
        validate_returned_resource(returned, project, Some(secret_id), true, Some(version))?;
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&value.payload.data)
                .map_err(|_| GcpApiError::InvalidResponse)?,
        );
        if decoded.len() > MAX_SECRET {
            return Err(GcpApiError::InvalidResponse);
        }
        if let Some(checksum) = &value.payload.data_crc32c
            && checksum.parse::<u32>().ok() != Some(crc32c(&decoded))
        {
            return Err(GcpApiError::InvalidResponse);
        }
        Ok(value)
    }
    pub async fn add_secret_version(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
        value: &[u8],
    ) -> Result<GcpSecretVersion, GcpApiError> {
        let url = self.url(project, Some(secret_id), ":addVersion")?;
        if value.len() > MAX_SECRET {
            return Err(GcpApiError::InvalidResponse);
        }
        let payload = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(value));
        let body = Zeroizing::new(format!(
            "{{\"payload\":{{\"data\":\"{}\",\"dataCrc32c\":\"{}\"}}}}",
            payload.as_str(),
            crc32c(value)
        ));
        let result: GcpSecretVersion = self
            .fetch(
                self.http
                    .post(url)
                    .bearer_auth(token)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.as_bytes().to_vec()),
            )
            .await?;
        validate_returned_resource(&result.name, project, Some(secret_id), true, None)?;
        Ok(result)
    }
    pub async fn create_secret(
        &self,
        token: &str,
        project: &str,
        secret_id: &str,
    ) -> Result<GcpSecret, GcpApiError> {
        validate_secret(secret_id)?;
        let mut url = self.url(project, None, "")?;
        url.query_pairs_mut().append_pair("secretId", secret_id);
        let result: GcpSecret = self
            .fetch(
                self.http
                    .post(url)
                    .bearer_auth(token)
                    .json(&serde_json::json!({"replication":{"automatic":{}}})),
            )
            .await?;
        validate_returned_resource(&result.name, project, Some(secret_id), false, None)?;
        Ok(result)
    }
}
fn check_token(token: &str) -> Result<(), GcpApiError> {
    if token.is_empty() || token.len() > 8192 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(GcpApiError::AuthError("invalid token".into()));
    }
    Ok(())
}
async fn read_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max: usize,
) -> Result<T, GcpApiError> {
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(GcpApiError::InvalidResponse);
    }
    let mut data = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(GcpApiError::HttpError)? {
        if chunk.len() > max.saturating_sub(data.len()) {
            return Err(GcpApiError::InvalidResponse);
        }
        data.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&data).map_err(|_| GcpApiError::InvalidResponse)
}
fn create_jwt(email: &str, key: &str, now: u64) -> Result<String, GcpApiError> {
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(key.as_bytes())
        .map_err(|_| GcpApiError::AuthError("invalid RSA key".into()))?;
    jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),&serde_json::json!({"iss":email,"scope":"https://www.googleapis.com/auth/cloud-platform","aud":OAUTH2_TOKEN_URL,"iat":now,"exp":now+3600}),&key).map_err(|_|GcpApiError::AuthError("JWT signing failed".into()))
}
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78u32.wrapping_mul(crc & 1));
        }
    }
    !crc
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;

    #[test]
    fn client_stores_base_url_trimmed() {
        let client = GcpSecretManagerClient::new("http://localhost:8080/").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = GcpSecretManagerClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = GcpSecretManagerClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn gcp_secret_deserialize() {
        let json = r#"{"name":"projects/123456789012/secrets/my-secret","createTime":"2024-01-01T00:00:00Z"}"#;
        let secret: GcpSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.name, "projects/123456789012/secrets/my-secret");
        assert_eq!(secret.create_time.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn gcp_secret_deserialize_minimal() {
        let json = r#"{"name":"projects/123456789012/secrets/s"}"#;
        let secret: GcpSecret = serde_json::from_str(json).unwrap();
        assert_eq!(secret.name, "projects/123456789012/secrets/s");
        assert!(secret.create_time.is_none());
        assert!(secret.replication.is_none());
    }

    #[test]
    fn gcp_secret_version_deserialize() {
        let json = r#"{"name":"projects/123456789012/secrets/s/versions/1","state":"ENABLED","createTime":"2024-01-01T00:00:00Z"}"#;
        let version: GcpSecretVersion = serde_json::from_str(json).unwrap();
        assert_eq!(version.name, "projects/123456789012/secrets/s/versions/1");
        assert_eq!(version.state.as_deref(), Some("ENABLED"));
    }

    #[test]
    fn gcp_secret_payload_deserialize() {
        let json = r#"{"data":"c2VjcmV0"}"#;
        let payload: GcpSecretPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.data, "c2VjcmV0");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&payload.data)
            .unwrap();
        assert_eq!(decoded, b"secret");
    }

    #[test]
    fn gcp_access_response_deserialize() {
        let json = r#"{"name":"projects/123456789012/secrets/s/versions/1","payload":{"data":"c2VjcmV0"}}"#;
        let resp: GcpAccessSecretVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            resp.name.as_deref(),
            Some("projects/123456789012/secrets/s/versions/1")
        );
        assert_eq!(resp.payload.data, "c2VjcmV0");
    }

    #[test]
    fn gcp_list_secrets_response_deserialize() {
        let json = r#"{"secrets":[{"name":"projects/123456789012/secrets/a"},{"name":"projects/123456789012/secrets/b"}]}"#;
        let resp: GcpListSecretsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.secrets.len(), 2);
        assert_eq!(resp.secrets[0].name, "projects/123456789012/secrets/a");
        assert_eq!(resp.secrets[1].name, "projects/123456789012/secrets/b");
    }

    #[test]
    fn gcp_list_secrets_response_empty() {
        let json = r#"{}"#;
        let resp: GcpListSecretsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.secrets.is_empty());
    }

    #[test]
    fn gcp_api_error_display() {
        let err = GcpApiError::AuthError("token expired".into());
        assert!(format!("{err}").contains("authentication failed"));

        let err = GcpApiError::NotFound("secret my-secret".into());
        assert!(format!("{err}").contains("not found"));

        let err = GcpApiError::PermissionDenied;
        assert!(format!("{err}").contains("permission denied"));

        let err = GcpApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = GcpApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));

        let err = GcpApiError::InvalidUrl("bad://url".into());
        assert!(format!("{err}").contains("endpoint or selector"));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://secretmanager.googleapis.com/v1").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080").unwrap();
        validate_url_scheme("http://127.0.0.1:9000/v1").unwrap();
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://secretmanager.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, GcpApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("HTTPS"));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/file").unwrap_err();
        assert!(matches!(err, GcpApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("HTTPS"));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn list_secrets_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secrets": [
                    {"name": "projects/123456789012/secrets/db-password"},
                    {"name": "projects/123456789012/secrets/api-key"}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("test-token", "123456789012")
            .await
            .unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].name, "projects/123456789012/secrets/db-password");
        assert_eq!(secrets[1].name, "projects/123456789012/secrets/api-key");
    }

    #[tokio::test]
    async fn list_secrets_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("test-token", "123456789012")
            .await
            .unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn list_secrets_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("bad-token", "123456789012").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::AuthError(_)));
    }

    #[tokio::test]
    async fn list_secrets_permission_denied() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("token", "123456789012").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::PermissionDenied));
    }

    #[tokio::test]
    async fn list_secrets_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("token", "123456789012").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::ServerError));
    }

    #[tokio::test]
    async fn get_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets/my-secret"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/123456789012/secrets/my-secret",
                "createTime": "2024-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secret = client
            .get_secret("test-token", "123456789012", "my-secret")
            .await
            .unwrap();

        assert_eq!(secret.name, "projects/123456789012/secrets/my-secret");
        assert_eq!(secret.create_time.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.get_secret("token", "123456789012", "missing").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn access_secret_version_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/projects/123456789012/secrets/my-secret/versions/latest:access",
            ))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/123456789012/secrets/my-secret/versions/1",
                "payload": {
                    "data": "c2VjcmV0LXZhbHVl"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let resp = client
            .access_secret_version("test-token", "123456789012", "my-secret", "latest")
            .await
            .unwrap();

        assert_eq!(resp.payload.data, "c2VjcmV0LXZhbHVl");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&resp.payload.data)
            .unwrap();
        assert_eq!(decoded, b"secret-value");
    }

    #[tokio::test]
    async fn access_secret_version_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(
                "/projects/123456789012/secrets/my-secret/versions/99:access",
            ))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .access_secret_version("token", "123456789012", "my-secret", "99")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn add_secret_version_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/123456789012/secrets/my-secret:addVersion"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/123456789012/secrets/my-secret/versions/2",
                "state": "ENABLED"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let version = client
            .add_secret_version("test-token", "123456789012", "my-secret", b"new-value")
            .await
            .unwrap();

        assert_eq!(
            version.name,
            "projects/123456789012/secrets/my-secret/versions/2"
        );
        assert_eq!(version.state.as_deref(), Some("ENABLED"));
    }

    #[tokio::test]
    async fn add_secret_version_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/123456789012/secrets/missing:addVersion"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .add_secret_version("token", "123456789012", "missing", b"val")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn create_secret_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/123456789012/secrets"))
            .and(query_param("secretId", "new-secret"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/123456789012/secrets/new-secret",
                "createTime": "2024-06-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secret = client
            .create_secret("test-token", "123456789012", "new-secret")
            .await
            .unwrap();

        assert_eq!(secret.name, "projects/123456789012/secrets/new-secret");
    }

    #[tokio::test]
    async fn create_secret_permission_denied() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/projects/123456789012/secrets"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client
            .create_secret("token", "123456789012", "new-secret")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::PermissionDenied));
    }

    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"secrets": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let secrets = client
            .list_secrets("my-secret-token", "123456789012")
            .await
            .unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn user_agent_header_sent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"secrets": []})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        client.list_secrets("token", "123456789012").await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/projects/123456789012/secrets"))
            .respond_with(ResponseTemplate::new(418))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        let result = client.list_secrets("token", "123456789012").await;
        assert!(matches!(
            result.unwrap_err(),
            GcpApiError::UnexpectedStatus(418)
        ));
    }

    #[tokio::test]
    async fn oauth_token_exchange_success() {
        let _env_guard = test_env_lock();
        let mock_server = MockServer::start().await;

        // Mock the token endpoint.
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.exchanged-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(3)
            .mount(&mock_server)
            .await;

        // Create a temp key file with a test RSA key.
        let sa_key = serde_json::json!({
            "client_email": "test@project.iam.gserviceaccount.com",
            "private_key": include_str!("../../tests/fixtures/test_rsa_key.pem"),
            "token_uri": OAUTH2_TOKEN_URL
        });

        let tmp_dir =
            std::env::temp_dir().join(format!("opaque_gcp_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let key_path = tmp_dir.join("sa_key.json");
        std::fs::write(&key_path, serde_json::to_string(&sa_key).unwrap()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Set env vars for service account auth.
        unsafe {
            std::env::remove_var(GCP_ACCESS_TOKEN_ENV);
            std::env::set_var(GCP_SERVICE_ACCOUNT_KEY_ENV, key_path.to_str().unwrap());
        }

        let mut client = GcpSecretManagerClient::new(&mock_server.uri()).unwrap();
        client.token_endpoint_override = Some(format!("{}/token", mock_server.uri()));
        let token = client.get_access_token().await.unwrap();
        assert_eq!(token.as_str(), "ya29.exchanged-token");

        // A cloned handler shares the same session cache.
        let token2 = client.clone().get_access_token().await.unwrap();
        assert_eq!(token2.as_str(), "ya29.exchanged-token");

        // Expired sessions and changed credentials must each exchange again.
        client.token_cache.lock().await.as_mut().unwrap().expires_at = Instant::now();
        assert_eq!(
            client.get_access_token().await.unwrap().as_str(),
            "ya29.exchanged-token"
        );
        let mut rotated = sa_key.clone();
        rotated["client_email"] = serde_json::json!("rotated@project.iam.gserviceaccount.com");
        std::fs::write(&key_path, serde_json::to_string(&rotated).unwrap()).unwrap();
        assert_eq!(
            client.get_access_token().await.unwrap().as_str(),
            "ya29.exchanged-token"
        );

        // Cleanup.
        unsafe {
            std::env::remove_var(GCP_SERVICE_ACCOUNT_KEY_ENV);
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn direct_access_token_takes_priority() {
        let _env_guard = test_env_lock();
        let unique_token = format!("direct-token-{}", uuid::Uuid::new_v4().as_simple());
        unsafe {
            std::env::set_var(GCP_ACCESS_TOKEN_ENV, &unique_token);
        }

        let client = GcpSecretManagerClient::new("http://localhost:9999").unwrap();
        let token = client.get_access_token().await.unwrap();
        assert_eq!(token.as_str(), unique_token);

        unsafe {
            std::env::remove_var(GCP_ACCESS_TOKEN_ENV);
        }
    }

    #[tokio::test]
    async fn auth_error_when_no_credentials() {
        let _env_guard = test_env_lock();
        unsafe {
            std::env::remove_var(GCP_ACCESS_TOKEN_ENV);
            std::env::remove_var(GCP_SERVICE_ACCOUNT_KEY_ENV);
        }

        let client = GcpSecretManagerClient::new("http://localhost:9999").unwrap();
        let result = client.get_access_token().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GcpApiError::AuthError(_)));
    }
}

impl std::fmt::Debug for GcpSecretPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GcpSecretPayload([REDACTED])")
    }
}
impl std::fmt::Debug for GcpAccessSecretVersionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GcpAccessSecretVersionResponse([REDACTED])")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod boundary_tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };
    #[tokio::test]
    async fn pagination_encodes_tokens_and_rejects_repetition() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/projects/123456789012/secrets")).and(query_param("pageSize","100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"secrets":[{"name":"projects/123456789012/secrets/first"}],"nextPageToken":"next+page/&x=1"}))).with_priority(2).mount(&server).await;
        Mock::given(method("GET"))
            .and(query_param("pageToken", "next+page/&x=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"secrets":[{"name":"projects/123456789012/secrets/second"}]}),
            ))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = GcpSecretManagerClient::with_auth(
            &server.uri(),
            AuthBinding::AccessToken {
                credential_ref: "env:UNREAD".into(),
            },
        )
        .unwrap();
        assert_eq!(
            client
                .list_secrets("synthetic", "123456789012")
                .await
                .unwrap()
                .len(),
            2
        );
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nextPageToken":"loop"})))
            .mount(&server)
            .await;
        assert!(matches!(
            client.list_secrets("synthetic", "123456789012").await,
            Err(GcpApiError::InvalidResponse)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
    #[tokio::test]
    async fn redirects_checksums_and_oversized_payloads_fail_closed() {
        let server = MockServer::start().await;
        let trap = MockServer::start().await;
        let client = GcpSecretManagerClient::with_auth(
            &server.uri(),
            AuthBinding::AccessToken {
                credential_ref: "env:UNREAD".into(),
            },
        )
        .unwrap();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/stolen", trap.uri())),
            )
            .mount(&server)
            .await;
        assert!(
            client
                .get_secret("synthetic", "123456789012", "secret")
                .await
                .is_err()
        );
        assert!(trap.received_requests().await.unwrap().is_empty());
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"name":"projects/123456789012/secrets/secret/versions/1","payload":{"data":"c2VjcmV0","dataCrc32c":"1"}})),
            )
            .mount(&server)
            .await;
        assert!(matches!(
            client
                .access_secret_version("synthetic", "123456789012", "secret", "latest")
                .await,
            Err(GcpApiError::InvalidResponse)
        ));
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(MAX_BODY + 1)))
            .mount(&server)
            .await;
        assert!(matches!(
            client.list_secrets("synthetic", "123456789012").await,
            Err(GcpApiError::InvalidResponse)
        ));
    }
    #[test]
    fn secret_debug_is_redacted_and_crc_has_standard_value() {
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
        let payload = GcpSecretPayload {
            data: "synthetic-secret".into(),
            data_crc32c: None,
        };
        assert!(!format!("{payload:?}").contains("synthetic-secret"));
        for url in [
            "https://user:pass@secretmanager.googleapis.com/v1",
            "https://secretmanager.googleapis.com/v1?x=1",
            "http://127.0.0.1.evil.invalid/v1",
            "https://secretmanager.googleapis.com/v1#token",
        ] {
            assert!(validate_url_scheme(url).is_err());
        }
    }
    #[tokio::test]
    async fn credential_file_must_be_private_and_cannot_supply_token_endpoint() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("sa.json");
        std::fs::write(&file,serde_json::to_vec(&json!({"client_email":"test@project.iam.gserviceaccount.com","private_key":"synthetic-invalid-key","token_uri":"https://attacker.invalid/token"})).unwrap()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let client = GcpSecretManagerClient::with_auth(
            DEFAULT_BASE_URL,
            AuthBinding::ServiceAccountFile {
                path: file.to_str().unwrap().into(),
            },
        )
        .unwrap();
        assert!(client.credentials().is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            client.get_access_token().await,
            Err(GcpApiError::AuthError(_))
        ));
        let link = directory.path().join("link.json");
        symlink(&file, &link).unwrap();
        let linked = GcpSecretManagerClient::with_auth(
            DEFAULT_BASE_URL,
            AuthBinding::ServiceAccountFile {
                path: link.to_str().unwrap().into(),
            },
        )
        .unwrap();
        assert!(linked.credentials().is_err());
    }
    #[tokio::test]
    async fn invalid_ids_never_reach_http() {
        let server = MockServer::start().await;
        let client = GcpSecretManagerClient::with_auth(
            &server.uri(),
            AuthBinding::AccessToken {
                credential_ref: "env:UNREAD".into(),
            },
        )
        .unwrap();
        assert!(
            client
                .list_secrets("synthetic", "x?alt=json")
                .await
                .is_err()
        );
        assert!(
            client
                .access_secret_version("synthetic", "123456789012", "secret", "../../other")
                .await
                .is_err()
        );
        assert!(
            client
                .create_secret("synthetic", "123456789012", "x&secretId=other")
                .await
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn returned_resources_match_prepared_project_secret_and_version() {
        let server = MockServer::start().await;
        let client = GcpSecretManagerClient::with_auth(
            &server.uri(),
            AuthBinding::AccessToken {
                credential_ref: "env:UNUSED".into(),
            },
        )
        .unwrap();
        let expected = "123456789012";
        for name in [
            "projects/987654321098/secrets/secret",
            "projects/123456789012/secrets/other",
        ] {
            server.reset().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name":name})))
                .mount(&server)
                .await;
            assert!(matches!(
                client.get_secret("synthetic", expected, "secret").await,
                Err(GcpApiError::InvalidResponse)
            ));
            server.reset().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name":name})))
                .mount(&server)
                .await;
            assert!(matches!(
                client.create_secret("synthetic", expected, "secret").await,
                Err(GcpApiError::InvalidResponse)
            ));
        }
        for name in [
            "projects/987654321098/secrets/secret/versions/1",
            "projects/123456789012/secrets/other/versions/1",
            "projects/123456789012/secrets/secret/versions/latest",
        ] {
            server.reset().await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"name":name,"payload":{"data":"c3ludGhldGlj"}})),
                )
                .mount(&server)
                .await;
            assert!(matches!(
                client
                    .access_secret_version("synthetic", expected, "secret", "latest")
                    .await,
                Err(GcpApiError::InvalidResponse)
            ));
            server.reset().await;
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"name":name,"state":"ENABLED"})),
                )
                .mount(&server)
                .await;
            assert!(matches!(
                client
                    .add_secret_version("synthetic", expected, "secret", b"synthetic")
                    .await,
                Err(GcpApiError::InvalidResponse)
            ));
        }
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"secrets":[{"name":"projects/987654321098/secrets/secret"}]}),
            ))
            .mount(&server)
            .await;
        assert!(matches!(
            client.list_secrets("synthetic", expected).await,
            Err(GcpApiError::InvalidResponse)
        ));
        server.reset().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"name":"projects/123456789012/secrets/secret/versions/2","payload":{"data":"c3ludGhldGlj"}}))).mount(&server).await;
        assert!(matches!(
            client
                .access_secret_version("synthetic", expected, "secret", "1")
                .await,
            Err(GcpApiError::InvalidResponse)
        ));
    }
    #[test]
    fn numeric_projects_and_version_aliases_are_explicit() {
        assert!(validate_project("123456789012").is_ok());
        for value in [
            "my-project",
            "00123456789012",
            "0",
            "",
            "123/456",
            "18446744073709551616",
        ] {
            assert!(validate_project(value).is_err(), "{value}");
        }
        for value in ["1", "latest", "deploy_2026"] {
            assert!(validate_version(value).is_ok(), "{value}");
        }
        for value in ["01", "0", "-alias", "../version", "", "2alias"] {
            assert!(validate_version(value).is_err(), "{value}");
        }
    }

    #[test]
    fn explicit_references_tokens_and_selectors_reject_boundary_mutations() {
        for reference in [
            "env:".into(),
            format!("env:{}", "a".repeat(257)),
            "env:has-dash".into(),
            "keychain:missing".into(),
            "keychain:/a".into(),
            "keychain:s/".into(),
            format!("keychain:s/{}", "a".repeat(512)),
            "keychain:s/white space".into(),
            "raw-token".into(),
        ] {
            assert!(validate_ref(&reference).is_err());
        }
        for reference in ["env:NAME_1", "keychain:service/account"] {
            validate_ref(reference).unwrap();
        }
        for value in ["".into(), "a".repeat(8193), "contains space".into()] {
            assert!(matches!(
                check_token(&value),
                Err(GcpApiError::AuthError(_))
            ));
        }
        for secret in ["".into(), "a".repeat(256), "has.dot".into()] {
            assert!(matches!(
                validate_secret(&secret),
                Err(GcpApiError::InvalidUrl(_))
            ));
        }
        for version in ["a".repeat(64), "starts.with.dot".into()] {
            assert!(matches!(
                validate_version(&version),
                Err(GcpApiError::InvalidUrl(_))
            ));
        }
        for url in [
            "file:///private",
            "https://user@secretmanager.googleapis.com/v1",
            "https://:password@secretmanager.googleapis.com/v1",
            "https://secretmanager.googleapis.com/v1#fragment",
        ] {
            assert!(matches!(
                validate_url_scheme(url),
                Err(GcpApiError::InvalidUrl(_))
            ));
        }
    }

    #[test]
    fn returned_resource_identity_requires_every_requested_component() {
        let valid = "projects/123456789012/secrets/fixture/versions/2";
        validate_returned_resource(valid, "123456789012", Some("fixture"), true, Some("2"))
            .unwrap();
        for value in [
            "projects/123456789012/secrets/fixture",
            "folders/123456789012/secrets/fixture/versions/2",
            "projects/999999999999/secrets/fixture/versions/2",
            "projects/123456789012/keys/fixture/versions/2",
            "projects/123456789012/secrets/bad.name/versions/2",
            "projects/123456789012/secrets/other/versions/2",
            "projects/123456789012/secrets/fixture/aliases/2",
            "projects/123456789012/secrets/fixture/versions/latest",
            "projects/123456789012/secrets/fixture/versions/3",
        ] {
            assert!(
                matches!(
                    validate_returned_resource(
                        value,
                        "123456789012",
                        Some("fixture"),
                        true,
                        Some("2")
                    ),
                    Err(GcpApiError::InvalidResponse)
                ),
                "{value}"
            );
        }
        validate_returned_resource(valid, "123456789012", Some("fixture"), true, Some("latest"))
            .unwrap();
    }

    #[test]
    fn service_account_files_require_private_regular_bounded_custody() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service-account.json");
        let client = GcpSecretManagerClient::with_auth(
            DEFAULT_BASE_URL,
            AuthBinding::ServiceAccountFile {
                path: path.to_str().unwrap().into(),
            },
        )
        .unwrap();
        assert!(matches!(
            client.credentials(),
            Err(GcpApiError::AuthError(_))
        ));
        std::fs::write(&path, b"disposable key bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            client.credentials().unwrap().as_slice(),
            b"disposable key bytes"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            client.credentials(),
            Err(GcpApiError::AuthError(_))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![0; MAX_SECRET + 1]).unwrap();
        assert!(matches!(
            client.credentials(),
            Err(GcpApiError::AuthError(_))
        ));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(
            client.credentials(),
            Err(GcpApiError::AuthError(_))
        ));
    }

    #[tokio::test]
    async fn invalid_service_identity_and_oauth_success_never_populate_token_cache() {
        use std::os::unix::fs::PermissionsExt;
        let key = include_str!("../../tests/fixtures/test_rsa_key.pem");
        for field in 0..7 {
            let server = MockServer::start().await;
            let directory = tempfile::tempdir().unwrap();
            let file = directory.path().join("sa.json");
            let email = match field {
                0 => "foreign@example.test".into(),
                1 => format!("{}@x.gserviceaccount.com", "a".repeat(320)),
                _ => "fixture@project.iam.gserviceaccount.com".into(),
            };
            std::fs::write(
                &file,
                serde_json::to_vec(&json!({"client_email":email,"private_key":key})).unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            let mut client = GcpSecretManagerClient::with_auth(
                &server.uri(),
                AuthBinding::ServiceAccountFile {
                    path: file.to_str().unwrap().into(),
                },
            )
            .unwrap();
            client.token_endpoint_override = Some(format!("{}/token", server.uri()));
            if field >= 2 {
                let mut token =
                    json!({"access_token":"synthetic","expires_in":3600,"token_type":"Bearer"});
                match field {
                    2 => token["expires_in"] = 0.into(),
                    3 => token["expires_in"] = 86401.into(),
                    4 => token["token_type"] = "Basic".into(),
                    5 => token["access_token"] = "".into(),
                    _ => token["access_token"] = "contains space".into(),
                };
                Mock::given(method("POST"))
                    .and(path("/token"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(token))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            assert!(matches!(
                client.get_access_token().await,
                Err(GcpApiError::AuthError(_))
            ));
            assert!(client.token_cache.lock().await.is_none());
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), usize::from(field >= 2));
            assert!(
                requests
                    .iter()
                    .all(|request| request.url.path() == "/token")
            );
        }
    }

    #[tokio::test]
    async fn service_identity_change_invalidates_cached_token_before_reuse() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("sa.json");
        let server = MockServer::start().await;
        let mut client = GcpSecretManagerClient::with_auth(
            &server.uri(),
            AuthBinding::ServiceAccountFile {
                path: file.to_str().unwrap().into(),
            },
        )
        .unwrap();
        client.token_endpoint_override = Some(format!("{}/token", server.uri()));
        for name in ["first", "replacement"] {
            std::fs::write(&file,serde_json::to_vec(&json!({"client_email":format!("{name}@project.iam.gserviceaccount.com"),"private_key":include_str!("../../tests/fixtures/test_rsa_key.pem")})).unwrap()).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"access_token":name,"expires_in":3600})),
                )
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(client.get_access_token().await.unwrap().as_str(), name);
            assert_eq!(client.get_access_token().await.unwrap().as_str(), name);
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            let form = reqwest::Url::parse(&format!(
                "https://fixture.invalid/?{}",
                std::str::from_utf8(&requests[0].body).unwrap()
            ))
            .unwrap();
            let assertion = form
                .query_pairs()
                .find(|(key, _)| key == "assertion")
                .unwrap()
                .1
                .into_owned();
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(assertion.split('.').nth(1).unwrap())
                .unwrap();
            let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(
                claims["iss"],
                format!("{name}@project.iam.gserviceaccount.com")
            );
            assert_eq!(claims["aud"], OAUTH2_TOKEN_URL);
        }
    }
}

fn validate_production_endpoint(value: &str) -> Result<(), GcpApiError> {
    if value != DEFAULT_BASE_URL {
        return Err(GcpApiError::InvalidUrl(
            "only the global Google Secret Manager endpoint is supported".into(),
        ));
    }
    Ok(())
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[test]
fn production_endpoint_is_independent_of_fixture_transport() {
    assert!(validate_production_endpoint(DEFAULT_BASE_URL).is_ok());
    for endpoint in [
        "http://127.0.0.1:8000/v1",
        "https://other.googleapis.com/v1",
        "https://secretmanager.googleapis.com.evil.invalid/v1",
        "https://user@secretmanager.googleapis.com/v1",
    ] {
        assert!(validate_production_endpoint(endpoint).is_err());
    }
}
