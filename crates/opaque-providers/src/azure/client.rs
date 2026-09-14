//! Azure Key Vault data-plane client with fixed Entra authority and deferred secret refs.
use opaque_core::resolver::{BaseResolver, SecretResolver};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
pub const AZURE_VAULT_URL_ENV: &str = "OPAQUE_AZURE_VAULT_URL";
pub const AZURE_TENANT_ID_ENV: &str = "OPAQUE_AZURE_TENANT_ID";
pub const AZURE_CLIENT_ID_ENV: &str = "OPAQUE_AZURE_CLIENT_ID";
pub const AZURE_CLIENT_SECRET_ENV: &str = "OPAQUE_AZURE_CLIENT_SECRET";
pub const AZURE_CLIENT_SECRET_REF_ENV: &str = "OPAQUE_AZURE_CLIENT_SECRET_REF";
const API_VERSION: &str = "2025-07-01";
const MAX_BODY: usize = 256 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum AzureApiError {
    #[error("invalid Azure endpoint or selector: {0}")]
    InvalidUrl(String),
    #[error("network error communicating with Azure Key Vault")]
    HttpError(#[source] reqwest::Error),
    #[error("Azure AD authentication failed (check tenant, client ID, and secret)")]
    AuthError,
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("access forbidden (check Key Vault access policies)")]
    Forbidden,
    #[error("Azure Key Vault server error")]
    ServerError,
    #[error("unexpected Azure Key Vault response: status {0}")]
    UnexpectedStatus(u16),
    #[error("Azure returned invalid, oversized or incomplete data")]
    InvalidResponse,
}
#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    token_type: Option<String>,
}
struct CachedToken {
    access_token: Zeroizing<String>,
    expires_at: Instant,
    credential_sha256: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureAttributes {
    #[serde(default)]
    pub enabled: Option<bool>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureSecretItem {
    pub id: String,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct AzureSecret {
    pub id: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}
impl Drop for AzureSecret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
impl std::fmt::Debug for AzureSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureSecret").finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureKeyItem {
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureCertItem {
    pub id: String,
    #[serde(default)]
    pub attributes: Option<AzureAttributes>,
}
#[derive(Debug, Deserialize)]
struct ListResponse<T> {
    value: Vec<T>,
    #[serde(default, rename = "nextLink")]
    next_link: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct AuthBinding {
    pub tenant_id: String,
    pub client_id: String,
    pub credential_ref: String,
    pub token_endpoint: String,
    pub scope: String,
}
impl AuthBinding {
    pub fn refs(&self) -> Vec<String> {
        vec![self.credential_ref.clone()]
    }
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
pub fn validate_name(value: &str) -> Result<(), AzureApiError> {
    if value.is_empty()
        || value.len() > 127
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(AzureApiError::InvalidUrl("invalid resource name".into()));
    }
    Ok(())
}
pub fn validate_version(value: &str) -> Result<(), AzureApiError> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(AzureApiError::InvalidUrl("invalid version".into()));
    }
    Ok(())
}
pub fn validate_vault(value: &str) -> Result<(), AzureApiError> {
    if !(3..=24).contains(&value.len())
        || !value.as_bytes()[0].is_ascii_alphabetic()
        || value.ends_with('-')
        || value.contains("--")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(AzureApiError::InvalidUrl("invalid vault name".into()));
    }
    Ok(())
}
fn validate_url_scheme(value: &str) -> Result<(), AzureApiError> {
    let u =
        reqwest::Url::parse(value).map_err(|_| AzureApiError::InvalidUrl("invalid URL".into()))?;
    if u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
        || !(u.scheme() == "https"
            || cfg!(test)
                && u.scheme() == "http"
                && matches!(u.host_str(), Some("localhost" | "127.0.0.1")))
    {
        return Err(AzureApiError::InvalidUrl(
            "trusted HTTPS vault origin required".into(),
        ));
    }
    Ok(())
}
fn validate_production_endpoint(url: &reqwest::Url) -> Result<(), AzureApiError> {
    validate_url_scheme(url.as_str())?;
    let vault = url
        .host_str()
        .and_then(|s| s.strip_suffix(".vault.azure.net"))
        .ok_or_else(|| {
            AzureApiError::InvalidUrl("only public Azure Key Vault origins are supported".into())
        })?;
    validate_vault(vault)?;
    if url.scheme() != "https" || url.port().is_some() {
        return Err(AzureApiError::InvalidUrl(
            "unexpected vault transport".into(),
        ));
    }
    Ok(())
}
#[derive(Clone)]
pub struct AzureKeyVaultClient {
    http: reqwest::Client,
    base_url: String,
    auth: AuthBinding,
    cached_token: std::sync::Arc<tokio::sync::Mutex<Option<CachedToken>>>,
    #[cfg(test)]
    pub(crate) token_endpoint_override: Option<String>,
    #[cfg(test)]
    test_secret: Option<Zeroizing<String>>,
}
impl std::fmt::Debug for AzureKeyVaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKeyVaultClient")
            .finish_non_exhaustive()
    }
}
impl AzureKeyVaultClient {
    fn user_agent() -> String {
        format!("opaqued/{}", env!("CARGO_PKG_VERSION"))
    }
    pub fn from_env() -> Result<Option<Self>, AzureApiError> {
        let Some(base) = std::env::var(AZURE_VAULT_URL_ENV)
            .ok()
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let tenant = std::env::var(AZURE_TENANT_ID_ENV).map_err(|_| AzureApiError::AuthError)?;
        let client = std::env::var(AZURE_CLIENT_ID_ENV).map_err(|_| AzureApiError::AuthError)?;
        let credential_ref = std::env::var(AZURE_CLIENT_SECRET_REF_ENV)
            .unwrap_or_else(|_| format!("env:{AZURE_CLIENT_SECRET_ENV}"));
        Self::new(&base, tenant, client, credential_ref).map(Some)
    }
    /// The final argument is a credential reference, never the client secret.
    pub fn new(
        base_url: &str,
        tenant_id: String,
        client_id: String,
        credential_ref: String,
    ) -> Result<Self, AzureApiError> {
        validate_url_scheme(base_url)?;
        validate_ref(&credential_ref).map_err(|_| AzureApiError::AuthError)?;
        for id in [&tenant_id, &client_id] {
            if id.is_empty()
                || id.len() > 255
                || matches!(id.as_str(), "common" | "organizations" | "consumers")
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            {
                return Err(AzureApiError::AuthError);
            }
        }
        let url = reqwest::Url::parse(base_url)
            .map_err(|_| AzureApiError::InvalidUrl("invalid vault".into()))?;
        if !cfg!(test) {
            validate_production_endpoint(&url)?;
        }
        let http = reqwest::Client::builder()
            .user_agent(Self::user_agent())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(AzureApiError::HttpError)?;
        let auth = AuthBinding {
            token_endpoint: format!(
                "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            ),
            scope: "https://vault.azure.net/.default".into(),
            tenant_id,
            client_id,
            credential_ref,
        };
        Ok(Self {
            http,
            base_url: url.origin().ascii_serialization(),
            auth,
            cached_token: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            #[cfg(test)]
            token_endpoint_override: None,
            #[cfg(test)]
            test_secret: None,
        })
    }
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    pub fn auth_binding(&self) -> &AuthBinding {
        &self.auth
    }
    pub fn vault_name(&self) -> Option<&str> {
        self.base_url
            .strip_prefix("https://")
            .and_then(|s| s.strip_suffix(".vault.azure.net"))
    }
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_new(
        base: &str,
        tenant: String,
        client: String,
        secret: String,
    ) -> Result<Self, AzureApiError> {
        let mut c = Self::new(base, tenant, client, "env:OPAQUE_AZURE_TEST_SECRET".into())?;
        c.test_secret = Some(Zeroizing::new(secret));
        Ok(c)
    }
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn with_token_endpoint(mut self, endpoint: String) -> Self {
        self.token_endpoint_override = Some(endpoint);
        self
    }
    fn token_endpoint(&self) -> &str {
        #[cfg(test)]
        if let Some(url) = &self.token_endpoint_override {
            return url;
        }
        &self.auth.token_endpoint
    }
    fn credential(&self) -> Result<Zeroizing<String>, AzureApiError> {
        #[cfg(test)]
        if let Some(secret) = &self.test_secret {
            return Ok(secret.clone());
        }
        let value = BaseResolver::new()
            .resolve(&self.auth.credential_ref)
            .map_err(|_| AzureApiError::AuthError)?;
        let value = value.as_str().ok_or(AzureApiError::AuthError)?;
        if value.is_empty() || value.len() > 8192 {
            return Err(AzureApiError::AuthError);
        }
        Ok(Zeroizing::new(value.into()))
    }
    async fn get_access_token(&self) -> Result<Zeroizing<String>, AzureApiError> {
        use sha2::{Digest, Sha256};
        let secret = self.credential()?;
        let fingerprint = format!("{:x}", Sha256::digest(secret.as_bytes()));
        let mut cache = self.cached_token.lock().await;
        if let Some(cached) = cache.as_ref()
            && cached.expires_at > Instant::now()
            && cached.credential_sha256 == fingerprint
        {
            return Ok(cached.access_token.clone());
        }
        let response = self
            .http
            .post(self.token_endpoint())
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.auth.client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("scope", self.auth.scope.as_str()),
            ])
            .send()
            .await
            .map_err(AzureApiError::HttpError)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(AzureApiError::AuthError);
        }
        let data: TokenResponse = read_json(response, 16 * 1024).await?;
        if data.access_token.is_empty()
            || data.access_token.len() > 8192
            || !data.access_token.bytes().all(|b| b.is_ascii_graphic())
            || !(1..=86400).contains(&data.expires_in)
            || data
                .token_type
                .as_deref()
                .is_some_and(|v| !v.eq_ignore_ascii_case("bearer"))
        {
            return Err(AzureApiError::AuthError);
        }
        let token = Zeroizing::new(data.access_token.clone());
        *cache = Some(CachedToken {
            access_token: token.clone(),
            expires_at: Instant::now() + Duration::from_secs(data.expires_in.saturating_sub(60)),
            credential_sha256: fingerprint,
        });
        Ok(token)
    }
    fn api_url(&self, path: &str) -> String {
        format!("{}{path}?api-version={API_VERSION}", self.base_url)
    }
    fn map_status(status: u16, resource: &str) -> Result<(), AzureApiError> {
        match status {
            200..=299 => Ok(()),
            401 => Err(AzureApiError::AuthError),
            403 => Err(AzureApiError::Forbidden),
            404 => Err(AzureApiError::NotFound(resource.into())),
            500..=599 => Err(AzureApiError::ServerError),
            s => Err(AzureApiError::UnexpectedStatus(s)),
        }
    }
    async fn fetch<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, AzureApiError> {
        let response = request.send().await.map_err(AzureApiError::HttpError)?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            *self.cached_token.lock().await = None;
        }
        Self::map_status(response.status().as_u16(), "requested resource")?;
        read_json(response, MAX_BODY).await
    }
    fn next_page(&self, next: &str, path: &str) -> Result<reqwest::Url, AzureApiError> {
        if next.len() > 8192 {
            return Err(AzureApiError::InvalidResponse);
        }
        let url = reqwest::Url::parse(next).map_err(|_| AzureApiError::InvalidResponse)?;
        let base =
            reqwest::Url::parse(&self.base_url).map_err(|_| AzureApiError::InvalidResponse)?;
        if url.origin() != base.origin()
            || url.path() != path
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(AzureApiError::InvalidResponse);
        }
        let mut seen = HashSet::new();
        let mut api = false;
        for (key, value) in url.query_pairs() {
            if !seen.insert(key.to_string())
                || !matches!(
                    key.as_ref(),
                    "api-version" | "maxresults" | "skiptoken" | "$skiptoken"
                )
            {
                return Err(AzureApiError::InvalidResponse);
            }
            if key == "api-version" {
                if value != API_VERSION {
                    return Err(AzureApiError::InvalidResponse);
                }
                api = true;
            }
        }
        if !api {
            return Err(AzureApiError::InvalidResponse);
        }
        Ok(url)
    }
    async fn list<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>, AzureApiError> {
        let token = self.get_access_token().await?;
        let mut url =
            reqwest::Url::parse(&self.api_url(path)).map_err(|_| AzureApiError::InvalidResponse)?;
        url.query_pairs_mut().append_pair("maxresults", "25");
        let mut results = Vec::new();
        let mut seen = HashSet::new();
        for _ in 0..160 {
            if !seen.insert(url.to_string()) {
                return Err(AzureApiError::InvalidResponse);
            }
            let response: ListResponse<T> = self
                .fetch(self.http.get(url).bearer_auth(token.as_str()))
                .await?;
            if response.value.len() > 25 || results.len() + response.value.len() > 4000 {
                return Err(AzureApiError::InvalidResponse);
            }
            results.extend(response.value);
            match response.next_link.filter(|v| !v.is_empty()) {
                None => return Ok(results),
                Some(next) => url = self.next_page(&next, path)?,
            }
        }
        Err(AzureApiError::InvalidResponse)
    }
    pub async fn list_secrets(&self) -> Result<Vec<AzureSecretItem>, AzureApiError> {
        self.list("/secrets").await
    }
    pub async fn list_keys(&self) -> Result<Vec<AzureKeyItem>, AzureApiError> {
        self.list("/keys").await
    }
    pub async fn list_certificates(&self) -> Result<Vec<AzureCertItem>, AzureApiError> {
        self.list("/certificates").await
    }
    pub async fn get_secret(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<AzureSecret, AzureApiError> {
        validate_name(name)?;
        if let Some(v) = version {
            validate_version(v)?;
        }
        let url = self.api_url(&format!(
            "/secrets/{name}{}",
            version.map(|v| format!("/{v}")).unwrap_or_default()
        ));
        let token = self.get_access_token().await?;
        let result: AzureSecret = self
            .fetch(self.http.get(url).bearer_auth(token.as_str()))
            .await?;
        if result.value.as_ref().is_some_and(|s| s.len() > 25 * 1024) {
            return Err(AzureApiError::InvalidResponse);
        }
        self.validate_secret_response(&result.id, name, version)?;
        Ok(result)
    }
    pub async fn set_secret(&self, name: &str, value: &str) -> Result<AzureSecret, AzureApiError> {
        validate_name(name)?;
        if value.len() > 25 * 1024 {
            return Err(AzureApiError::InvalidResponse);
        }
        let token = self.get_access_token().await?;
        let encoded = Zeroizing::new(
            serde_json::to_string(value).map_err(|_| AzureApiError::InvalidResponse)?,
        );
        let body = Zeroizing::new(format!("{{\"value\":{}}}", encoded.as_str()));
        let mut response: AzureSecret = self
            .fetch(
                self.http
                    .put(self.api_url(&format!("/secrets/{name}")))
                    .bearer_auth(token.as_str())
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.as_bytes().to_vec()),
            )
            .await?;
        response.value.zeroize();
        response.value = None;
        self.validate_secret_response(&response.id, name, None)?;
        Ok(response)
    }
    fn validate_secret_response(
        &self,
        id: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<(), AzureApiError> {
        let url = reqwest::Url::parse(id).map_err(|_| AzureApiError::InvalidResponse)?;
        if self.resource_name(id, "secrets")? != name
            || url.path_segments().is_none_or(|parts| parts.count() != 3)
            || version.is_some_and(|v| url.path().rsplit('/').next() != Some(v))
        {
            return Err(AzureApiError::InvalidResponse);
        }
        Ok(())
    }
    /// Validate server-returned identifiers before projecting them to callers.
    pub fn resource_name(&self, id: &str, kind: &str) -> Result<String, AzureApiError> {
        let url = reqwest::Url::parse(id).map_err(|_| AzureApiError::InvalidResponse)?;
        let base =
            reqwest::Url::parse(&self.base_url).map_err(|_| AzureApiError::InvalidResponse)?;
        if url.origin() != base.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AzureApiError::InvalidResponse);
        }
        let parts: Vec<_> = url.path().split('/').collect();
        if !(3..=4).contains(&parts.len())
            || !parts[0].is_empty()
            || parts[1] != kind
            || validate_name(parts[2]).is_err()
            || parts.get(3).is_some_and(|v| validate_version(v).is_err())
        {
            return Err(AzureApiError::InvalidResponse);
        }
        Ok(parts[2].into())
    }
}
async fn read_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max: usize,
) -> Result<T, AzureApiError> {
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(AzureApiError::InvalidResponse);
    }
    let mut data = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(AzureApiError::HttpError)? {
        if chunk.len() > max.saturating_sub(data.len()) {
            return Err(AzureApiError::InvalidResponse);
        }
        data.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&data).map_err(|_| AzureApiError::InvalidResponse)
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Unit tests: URL validation, deserialization, error display
    // -----------------------------------------------------------------------

    #[test]
    fn client_stores_base_url_trimmed() {
        let client = AzureKeyVaultClient::test_new(
            "http://localhost:8080/",
            "tenant".into(),
            "client".into(),
            "secret".into(),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn client_base_url_no_trailing_slash() {
        let client = AzureKeyVaultClient::test_new(
            "http://localhost:8080",
            "tenant".into(),
            "client".into(),
            "secret".into(),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn user_agent_contains_version() {
        let ua = AzureKeyVaultClient::user_agent();
        assert!(ua.starts_with("opaqued/"));
    }

    #[test]
    fn client_debug_does_not_leak_secret() {
        let client = AzureKeyVaultClient::test_new(
            "http://localhost:8080",
            "tenant-123".into(),
            "client-456".into(),
            "super-secret".into(),
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("AzureKeyVaultClient"));
        assert!(!debug.contains("tenant-123"));
        assert!(!debug.contains("client-456"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn secret_item_deserialize() {
        let json = r#"{"id":"https://myvault.vault.azure.net/secrets/mysecret","attributes":{"enabled":true}}"#;
        let item: AzureSecretItem = serde_json::from_str(json).unwrap();
        assert!(item.id.contains("mysecret"));
        assert_eq!(item.attributes.unwrap().enabled, Some(true));
    }

    #[test]
    fn secret_deserialize_with_value() {
        let json = r#"{
            "id": "https://myvault.vault.azure.net/secrets/mysecret/version1",
            "value": "supersecret",
            "attributes": {"enabled": true}
        }"#;
        let secret: AzureSecret = serde_json::from_str(json).unwrap();
        assert!(secret.id.contains("mysecret"));
        assert_eq!(secret.value.as_deref(), Some("supersecret"));
    }

    #[test]
    fn secret_deserialize_minimal() {
        let json = r#"{"id": "https://myvault.vault.azure.net/secrets/test"}"#;
        let secret: AzureSecret = serde_json::from_str(json).unwrap();
        assert!(secret.value.is_none());
        assert!(secret.attributes.is_none());
    }

    #[test]
    fn key_item_deserialize() {
        let json =
            r#"{"kid":"https://myvault.vault.azure.net/keys/mykey","attributes":{"enabled":true}}"#;
        let item: AzureKeyItem = serde_json::from_str(json).unwrap();
        assert!(item.kid.contains("mykey"));
    }

    #[test]
    fn cert_item_deserialize() {
        let json = r#"{"id":"https://myvault.vault.azure.net/certificates/mycert","attributes":{"enabled":true}}"#;
        let item: AzureCertItem = serde_json::from_str(json).unwrap();
        assert!(item.id.contains("mycert"));
    }

    #[test]
    fn list_response_deserialize_secrets() {
        let json = r#"{
            "value": [
                {"id": "https://vault/secrets/a"},
                {"id": "https://vault/secrets/b"}
            ]
        }"#;
        let list: ListResponse<AzureSecretItem> = serde_json::from_str(json).unwrap();
        assert_eq!(list.value.len(), 2);
    }

    #[test]
    fn azure_api_error_display() {
        let err = AzureApiError::AuthError;
        assert!(format!("{err}").contains("authentication failed"));

        let err = AzureApiError::NotFound("secret 'test'".into());
        assert!(format!("{err}").contains("not found"));

        let err = AzureApiError::Forbidden;
        assert!(format!("{err}").contains("forbidden"));

        let err = AzureApiError::ServerError;
        assert!(format!("{err}").contains("server error"));

        let err = AzureApiError::UnexpectedStatus(418);
        assert!(format!("{err}").contains("418"));

        let err = AzureApiError::InvalidUrl("bad".into());
        assert!(format!("{err}").contains("endpoint or selector"));
    }

    #[test]
    fn validate_url_scheme_accepts_https() {
        validate_url_scheme("https://myvault.vault.azure.net").unwrap();
    }

    #[test]
    fn validate_url_scheme_accepts_localhost_http() {
        validate_url_scheme("http://localhost:8080").unwrap();
        assert!(validate_url_scheme("http://127.0.0.1:9000/api").is_err());
    }

    #[test]
    fn validate_url_scheme_rejects_remote_http() {
        let err = validate_url_scheme("http://myvault.vault.azure.net").unwrap_err();
        assert!(matches!(err, AzureApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("HTTPS"));
    }

    #[test]
    fn validate_url_scheme_rejects_ftp() {
        let err = validate_url_scheme("ftp://example.com/file").unwrap_err();
        assert!(matches!(err, AzureApiError::InvalidUrl(_)));
        assert!(format!("{err}").contains("HTTPS"));
    }

    #[test]
    fn api_url_includes_version() {
        let client = AzureKeyVaultClient::test_new(
            "http://localhost:8080",
            "t".into(),
            "c".into(),
            "s".into(),
        )
        .unwrap();
        let url = client.api_url("/secrets");
        assert_eq!(url, "http://localhost:8080/secrets?api-version=2025-07-01");
    }

    #[test]
    fn map_status_returns_correct_errors() {
        assert!(AzureKeyVaultClient::map_status(200, "x").is_ok());
        assert!(AzureKeyVaultClient::map_status(204, "x").is_ok());
        assert!(matches!(
            AzureKeyVaultClient::map_status(401, "x").unwrap_err(),
            AzureApiError::AuthError
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(403, "x").unwrap_err(),
            AzureApiError::Forbidden
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(404, "x").unwrap_err(),
            AzureApiError::NotFound(_)
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(500, "x").unwrap_err(),
            AzureApiError::ServerError
        ));
        assert!(matches!(
            AzureKeyVaultClient::map_status(418, "x").unwrap_err(),
            AzureApiError::UnexpectedStatus(418)
        ));
    }

    // -----------------------------------------------------------------------
    // Integration tests using wiremock
    // -----------------------------------------------------------------------

    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: start a mock server and create a client pointed at it,
    /// with OAuth token mocked.
    async fn setup_mock_client() -> (AzureKeyVaultClient, MockServer) {
        let mock_server = MockServer::start().await;

        // Mock the OAuth2 token endpoint.
        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fvault.azure.net%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock-azure-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let client = AzureKeyVaultClient::test_new(
            &mock_server.uri(),
            "test-tenant".into(),
            "test-client-id".into(),
            "test-client-secret".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        (client, mock_server)
    }

    #[tokio::test]
    async fn oauth_token_flow() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "my-azure-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AzureKeyVaultClient::test_new(
            &mock_server.uri(),
            "tenant".into(),
            "client-id".into(),
            "client-secret".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        let token = client.get_access_token().await.unwrap();
        assert_eq!(token.as_str(), "my-azure-token");

        // Second call should use cache (mock expects only 1 call).
        let token2 = client.get_access_token().await.unwrap();
        assert_eq!(token2.as_str(), "my-azure-token");
    }

    #[tokio::test]
    async fn oauth_token_auth_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "bad credentials"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = AzureKeyVaultClient::test_new(
            &mock_server.uri(),
            "tenant".into(),
            "bad-client".into(),
            "bad-secret".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        let result = client.get_access_token().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::AuthError));
    }

    #[tokio::test]
    async fn list_secrets_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "https://vault/secrets/secret1", "attributes": {"enabled": true}},
                    {"id": "https://vault/secrets/secret2", "attributes": {"enabled": false}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secrets = client.list_secrets().await.unwrap();
        assert_eq!(secrets.len(), 2);
        assert!(secrets[0].id.contains("secret1"));
        assert!(secrets[1].id.contains("secret2"));
    }

    #[tokio::test]
    async fn list_secrets_unauthorized() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::AuthError));
    }

    #[tokio::test]
    async fn list_secrets_forbidden() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::Forbidden));
    }

    #[tokio::test]
    async fn list_secrets_server_error() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::ServerError));
    }

    #[tokio::test]
    async fn get_secret_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets/my-secret"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": format!("{}/secrets/my-secret/version1", mock_server.uri()),
                "value": "the-secret-value",
                "attributes": {"enabled": true}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secret = client.get_secret("my-secret", None).await.unwrap();
        assert!(secret.id.contains("my-secret"));
        assert_eq!(secret.value.as_deref(), Some("the-secret-value"));
    }

    #[tokio::test]
    async fn get_secret_with_version() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets/my-secret/abc123"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": format!("{}/secrets/my-secret/abc123", mock_server.uri()),
                "value": "versioned-value"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secret = client
            .get_secret("my-secret", Some("abc123"))
            .await
            .unwrap();
        assert_eq!(secret.value.as_deref(), Some("versioned-value"));
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets/missing"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.get_secret("missing", None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn set_secret_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("PUT"))
            .and(path("/secrets/new-secret"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": format!("{}/secrets/new-secret/v1", mock_server.uri()),
                "value": "new-value",
                "attributes": {"enabled": true}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secret = client.set_secret("new-secret", "new-value").await.unwrap();
        assert!(secret.id.contains("new-secret"));
        assert!(
            secret.value.is_none(),
            "write responses must discard echoed secrets"
        );
    }

    #[tokio::test]
    async fn set_secret_forbidden() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("PUT"))
            .and(path("/secrets/restricted"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.set_secret("restricted", "val").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::Forbidden));
    }

    #[tokio::test]
    async fn list_keys_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/keys"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"kid": "https://vault/keys/key1", "attributes": {"enabled": true}},
                    {"kid": "https://vault/keys/key2", "attributes": {"enabled": true}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let keys = client.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].kid.contains("key1"));
        assert!(keys[1].kid.contains("key2"));
    }

    #[tokio::test]
    async fn list_keys_forbidden() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/keys"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_keys().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::Forbidden));
    }

    #[tokio::test]
    async fn list_certificates_success() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/certificates"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "https://vault/certificates/cert1", "attributes": {"enabled": true}}
                ]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let certs = client.list_certificates().await.unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].id.contains("cert1"));
    }

    #[tokio::test]
    async fn list_certificates_server_error() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/certificates"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_certificates().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AzureApiError::ServerError));
    }

    #[tokio::test]
    async fn bearer_auth_header_sent() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header("Authorization", "Bearer mock-azure-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let secrets = client.list_secrets().await.unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn user_agent_header_sent() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header(
                "user-agent",
                &format!("opaqued/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        client.list_secrets().await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_status_code() {
        let (client, mock_server) = setup_mock_client().await;

        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .respond_with(ResponseTemplate::new(418)) // I'm a teapot
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = client.list_secrets().await;
        assert!(matches!(
            result.unwrap_err(),
            AzureApiError::UnexpectedStatus(418)
        ));
    }

    #[tokio::test]
    async fn token_cached_across_calls() {
        let mock_server = MockServer::start().await;

        // Token endpoint should be called only once.
        Mock::given(method("POST"))
            .and(path("/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "cached-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Two API calls should both use the cached token.
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", "2025-07-01"))
            .and(header("Authorization", "Bearer cached-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": []
            })))
            .expect(2)
            .mount(&mock_server)
            .await;

        let client =
            AzureKeyVaultClient::test_new(&mock_server.uri(), "t".into(), "c".into(), "s".into())
                .unwrap()
                .with_token_endpoint(format!("{}/oauth2/v2.0/token", mock_server.uri()));

        client.list_secrets().await.unwrap();
        client.list_secrets().await.unwrap();
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
    async fn client() -> (AzureKeyVaultClient, MockServer) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"synthetic","expires_in":3600})),
            )
            .mount(&server)
            .await;
        let client = AzureKeyVaultClient::test_new(
            &server.uri(),
            "tenant".into(),
            "client".into(),
            "synthetic".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/token", server.uri()));
        (client, server)
    }
    #[tokio::test]
    async fn follows_only_same_vault_same_collection_continuations() {
        let (client, server) = client().await;
        let trap = MockServer::start().await;
        Mock::given(method("GET")).and(path("/secrets")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"value":[{"id":"first"}],"nextLink":format!("{}/secrets?api-version={API_VERSION}&skiptoken=next",server.uri())}))).with_priority(2).mount(&server).await;
        Mock::given(method("GET"))
            .and(query_param("skiptoken", "next"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"value":[{"id":"second"}]})),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        assert_eq!(client.list_secrets().await.unwrap().len(), 2);
        for next in [
            format!("{}/secrets?api-version={API_VERSION}", trap.uri()),
            format!("{}/keys?api-version={API_VERSION}", server.uri()),
            format!(
                "{}/secrets?api-version={API_VERSION}&api-version=7.0",
                server.uri()
            ),
            format!("{}/secrets?api-version={API_VERSION}#x", server.uri()),
        ] {
            assert!(client.next_page(&next, "/secrets").is_err());
        }
        assert!(trap.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn malicious_continuation_and_redirect_do_not_receive_bearer() {
        let (client, server) = client().await;
        let trap = MockServer::start().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"value":[],"nextLink":format!("{}/secrets?api-version={API_VERSION}",trap.uri())}))).mount(&server).await;
        assert!(matches!(
            client.list_secrets().await,
            Err(AzureApiError::InvalidResponse)
        ));
        assert!(trap.received_requests().await.unwrap().is_empty());
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Location", format!("{}/stolen", trap.uri())),
            )
            .mount(&server)
            .await;
        assert!(client.get_secret("secret", None).await.is_err());
        assert!(trap.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn expired_token_refreshes_and_auth_errors_never_echo_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"synthetic","expires_in":30})),
            )
            .expect(2)
            .mount(&server)
            .await;
        let client = AzureKeyVaultClient::test_new(
            &server.uri(),
            "tenant".into(),
            "client".into(),
            "synthetic".into(),
        )
        .unwrap()
        .with_token_endpoint(format!("{}/token", server.uri()));
        client.get_access_token().await.unwrap();
        client.get_access_token().await.unwrap();
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401).set_body_string("synthetic-secret-do-not-disclose"),
            )
            .mount(&server)
            .await;
        let err = client.get_access_token().await.unwrap_err();
        assert!(!format!("{err:?} {err}").contains("do-not-disclose"));
    }
    #[tokio::test]
    async fn invalid_ids_and_oversized_writes_fail_before_auth() {
        let (client, server) = client().await;
        assert!(client.get_secret("../other", None).await.is_err());
        assert!(client.get_secret("secret", Some("x?alt=y")).await.is_err());
        assert!(
            client
                .set_secret("secret", &"x".repeat(25 * 1024 + 1))
                .await
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn oversized_json_and_repeated_pages_fail_instead_of_partial_success() {
        let (client, server) = client().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(MAX_BODY + 1)))
            .mount(&server)
            .await;
        assert!(matches!(
            client.list_secrets().await,
            Err(AzureApiError::InvalidResponse)
        ));
        server.reset().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"value":[],"nextLink":format!("{}/secrets?api-version={API_VERSION}&skiptoken=loop",server.uri())}))).mount(&server).await;
        assert!(matches!(
            client.list_secrets().await,
            Err(AzureApiError::InvalidResponse)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
    #[tokio::test]
    async fn response_resource_and_requested_version_must_match() {
        let (client, server) = client().await;
        client.get_access_token().await.unwrap();
        for id in [
            "https://other.vault.azure.net/secrets/secret/v1".to_owned(),
            format!("{}/secrets/other/v1", server.uri()),
            format!("{}/secrets/secret/v2", server.uri()),
        ] {
            server.reset().await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"id":id,"value":"synthetic-do-not-disclose"})),
                )
                .mount(&server)
                .await;
            let err = client.get_secret("secret", Some("v1")).await.unwrap_err();
            assert!(matches!(err, AzureApiError::InvalidResponse));
            assert!(!format!("{err:?} {err}").contains("do-not-disclose"));
        }
    }
    #[tokio::test]
    async fn get_and_set_responses_require_provider_version() {
        let (client, server) = client().await;
        client.get_access_token().await.unwrap();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"id":format!("{}/secrets/secret",server.uri()),"value":"synthetic"}),
            ))
            .mount(&server)
            .await;
        assert!(matches!(
            client.get_secret("secret", None).await,
            Err(AzureApiError::InvalidResponse)
        ));
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"id":format!("{}/secrets/secret",server.uri()),"value":"synthetic"}),
            ))
            .mount(&server)
            .await;
        assert!(matches!(
            client.set_secret("secret", "synthetic").await,
            Err(AzureApiError::InvalidResponse)
        ));
    }
    #[test]
    fn tenant_and_url_injection_fail_at_construction() {
        for tenant in [
            "../other",
            "tenant?x",
            "tenant#x",
            "common",
            "organizations",
        ] {
            assert!(
                AzureKeyVaultClient::new(
                    "https://vault.vault.azure.net",
                    tenant.into(),
                    "client".into(),
                    "env:UNREAD".into()
                )
                .is_err()
            );
        }
        for url in [
            "https://user:pass@vault.vault.azure.net",
            "https://vault.vault.azure.net?x=y",
            "https://vault.vault.azure.net/path",
            "http://127.0.0.1.evil.invalid",
        ] {
            assert!(validate_url_scheme(url).is_err());
        }
    }

    #[test]
    fn explicit_reference_selector_and_tenant_limits_reject_each_boundary() {
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
            assert!(validate_ref(&reference).is_err(), "{reference}");
        }
        for reference in ["env:NAME_1", "keychain:service/account"] {
            validate_ref(reference).unwrap();
        }
        for name in ["".into(), "a".repeat(128), "has_underscore".into()] {
            assert!(matches!(
                validate_name(&name),
                Err(AzureApiError::InvalidUrl(_))
            ));
        }
        for version in ["".into(), "a".repeat(129), "has-dash".into()] {
            assert!(matches!(
                validate_version(&version),
                Err(AzureApiError::InvalidUrl(_))
            ));
        }
        for vault in ["ab", "1vault", "vault-", "va--ult", "va_ult"] {
            assert!(matches!(
                validate_vault(vault),
                Err(AzureApiError::InvalidUrl(_))
            ));
        }
        for id in [
            "".to_owned(),
            "a".repeat(256),
            "contains space".into(),
            "consumers".into(),
        ] {
            for tenant in [true, false] {
                assert!(matches!(
                    AzureKeyVaultClient::new(
                        "https://fixture.vault.azure.net",
                        if tenant { id.clone() } else { "tenant".into() },
                        if tenant { "client".into() } else { id.clone() },
                        "env:UNREAD".into()
                    ),
                    Err(AzureApiError::AuthError)
                ));
            }
        }
    }

    #[tokio::test]
    async fn continuation_and_resource_identity_matrices_never_accept_foreign_authority() {
        let (client, server) = client().await;
        for suffix in [
            "?api-version=7.4&api-version=7.4",
            "?api-version=7.4&foreign=x",
            "?api-version=wrong",
            "?skiptoken=x",
            "?api-version=7.4#fragment",
        ] {
            let suffix = suffix.replace("7.4", API_VERSION);
            assert!(matches!(
                client.next_page(&format!("{}/secrets{suffix}", server.uri()), "/secrets"),
                Err(AzureApiError::InvalidResponse)
            ));
        }
        for value in [
            "x".repeat(8193),
            format!("{}/keys?api-version=7.4", server.uri()),
            format!("http://user@{}/secrets?api-version=7.4", server.address()),
            format!(
                "http://:password@{}/secrets?api-version=7.4",
                server.address()
            ),
        ] {
            assert!(matches!(
                client.next_page(&value.replace("7.4", API_VERSION), "/secrets"),
                Err(AzureApiError::InvalidResponse)
            ));
        }
        let valid = format!(
            "{}/secrets?api-version={API_VERSION}&skiptoken=opaque%2Ftoken",
            server.uri()
        );
        assert_eq!(
            client.next_page(&valid, "/secrets").unwrap().as_str(),
            valid
        );
        for suffix in [
            "/secrets/name/version?x=1",
            "/secrets/name/version#fragment",
            "/keys/name/version",
            "/secrets/name/bad-version",
            "/secrets/name/version/extra",
            "/secrets/has_underscore/version",
        ] {
            assert!(
                matches!(
                    client.resource_name(&format!("{}{suffix}", server.uri()), "secrets"),
                    Err(AzureApiError::InvalidResponse)
                ),
                "{suffix}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalid_oauth_success_never_populates_cache_or_reaches_vault() {
        for body in [
            json!({"access_token":"","expires_in":3600}),
            json!({"access_token":"a".repeat(8193),"expires_in":3600}),
            json!({"access_token":"has space","expires_in":3600}),
            json!({"access_token":"valid","expires_in":0}),
            json!({"access_token":"valid","expires_in":86401}),
            json!({"access_token":"valid","expires_in":3600,"token_type":"Basic"}),
        ] {
            let (client, server) = client().await;
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
            assert!(matches!(
                client.list_secrets().await,
                Err(AzureApiError::AuthError)
            ));
            assert!(client.cached_token.lock().await.is_none());
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].url.path(), "/token");
        }
    }

    #[tokio::test]
    async fn oversized_collection_and_secret_payload_do_not_produce_partial_success() {
        let (client, server) = client().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"value":vec![json!({"id":format!("{}/secrets/name",server.uri())});26]}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        assert!(matches!(
            client.list_secrets().await,
            Err(AzureApiError::InvalidResponse)
        ));
        Mock::given(method("GET")).and(path("/secrets/name")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":format!("{}/secrets/name/version",server.uri()),"value":"x".repeat(25*1024+1)}))).expect(1).mount(&server).await;
        assert!(matches!(
            client.get_secret("name", None).await,
            Err(AzureApiError::InvalidResponse)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[test]
fn production_vault_guard_is_independent_of_fixture_transport() {
    assert!(
        validate_production_endpoint(
            &reqwest::Url::parse("https://my-vault.vault.azure.net").unwrap()
        )
        .is_ok()
    );
    for endpoint in [
        "http://127.0.0.1:8000",
        "https://my-vault.vault.azure.net.evil.invalid",
        "https://evil.invalid",
        "https://user@my-vault.vault.azure.net",
        "https://my-vault.vault.azure.net:444",
        "http://my-vault.vault.azure.net",
        "https://my-vault.vault.azure.net/path",
        "https://my-vault.vault.azure.net?x=y",
    ] {
        assert!(
            validate_production_endpoint(&reqwest::Url::parse(endpoint).unwrap()).is_err(),
            "{endpoint}"
        );
    }
}
