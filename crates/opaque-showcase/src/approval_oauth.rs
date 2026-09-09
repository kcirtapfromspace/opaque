//! GitHub OAuth or Dex OIDC identity for a reviewed synthetic demo task.
//!
//! The caller must hold each non-cloneable challenge in a one-use transaction
//! bound to the browser session, resource-token JTI, persona, task, manifest
//! digest, policy generation, and task expiry. Consume it before `finish`, then
//! recheck that binding before recording approval. An ID token is never resource
//! authority and this module never calls the metrics gateway with one.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Client, Response, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const CHALLENGE_LIFETIME_SECS: u64 = 300;
const MAX_JSON_BYTES: usize = 128 * 1024;
const MAX_ID_TOKEN_BYTES: usize = 32 * 1024;
const CLOCK_SKEW_SECS: u64 = 30;
const GITHUB_ISSUER: &str = "https://github.com";
const GITHUB_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER: &str = "https://api.github.com/user";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    Oidc,
    GitHub,
}

// These types deliberately do not implement Debug: an accidental diagnostic
// must not print a client secret, PKCE verifier, nonce, or authorization code.
pub(crate) struct OAuthProvider {
    config: OAuthConfig,
    client: Client,
}

struct OAuthConfig {
    kind: ProviderKind,
    issuer: Url,
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
    redirect_uri: Url,
}

pub(crate) struct OAuthChallenge {
    pub authorization_url: String,
    pub state: String,
    verifier: Zeroizing<String>,
    issued_at: u64,
    token_endpoint: Url,
    flow: OAuthFlow,
}

enum OAuthFlow {
    Oidc {
        nonce: Zeroizing<String>,
        jwks_uri: Url,
        auth_method: TokenAuthMethod,
    },
    GitHub {
        user_endpoint: Url,
    },
}

#[derive(Clone, Copy)]
enum TokenAuthMethod {
    Public,
    Basic,
    Post,
}

pub(crate) struct OAuthIdentity {
    pub kind: &'static str,
    pub issuer: String,
    pub subject: String,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    // Do not deserialize, retain, log, or forward access/refresh tokens.
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    scope: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    #[serde(rename = "type")]
    account_type: String,
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nonce: String,
    #[serde(default)]
    azp: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl OAuthProvider {
    pub fn label(&self) -> &'static str {
        match self.config.kind {
            ProviderKind::GitHub => "GitHub",
            ProviderKind::Oidc => "Dex / GitHub",
        }
    }

    pub fn proof_kind(&self) -> &'static str {
        match self.config.kind {
            ProviderKind::GitHub => "github_oauth",
            ProviderKind::Oidc => "oidc",
        }
    }

    pub fn validate_redirect_origin(&self, origin: &str) -> Result<(), String> {
        let origin = Url::parse(origin).map_err(|_| "Invalid approval origin")?;
        if self.config.redirect_uri.origin() != origin.origin() {
            return Err("OAuth callback must use the configured approval origin".into());
        }
        Ok(())
    }

    /// No network work during application construction. A partial or unsafe
    /// configuration is an error; no client ID means the optional method is off.
    pub fn from_env() -> Result<Option<Self>, String> {
        let client_id = env_value("OPAQUE_DEMO_OAUTH_CLIENT_ID")?;
        let issuer = env_value("OPAQUE_DEMO_OAUTH_ISSUER")?;
        let client_secret = env_value("OPAQUE_DEMO_OAUTH_CLIENT_SECRET")?;
        let redirect_uri = env_value("OPAQUE_DEMO_OAUTH_REDIRECT_URI")?;
        let provider = env_value("OPAQUE_DEMO_OAUTH_PROVIDER")?;
        if client_id.is_none()
            && issuer.is_none()
            && client_secret.is_none()
            && redirect_uri.is_none()
            && provider.is_none()
        {
            return Ok(None);
        }
        let client_id = client_id.ok_or("OPAQUE_DEMO_OAUTH_CLIENT_ID is required")?;
        let redirect_uri = redirect_uri.ok_or("OPAQUE_DEMO_OAUTH_REDIRECT_URI is required")?;
        let config = match provider.as_deref().unwrap_or("oidc") {
            "github" => {
                if issuer.is_some() {
                    return Err("GitHub uses fixed endpoints; omit OPAQUE_DEMO_OAUTH_ISSUER".into());
                }
                OAuthConfig::github(
                    client_id,
                    client_secret
                        .ok_or("OPAQUE_DEMO_OAUTH_CLIENT_SECRET is required for GitHub")?,
                    redirect_uri,
                )?
            }
            "oidc" => OAuthConfig::new(
                issuer.ok_or("OPAQUE_DEMO_OAUTH_ISSUER is required")?,
                client_id,
                client_secret,
                redirect_uri,
            )?,
            _ => return Err("OPAQUE_DEMO_OAUTH_PROVIDER must be github or oidc".into()),
        };
        Ok(Some(Self {
            config,
            client: bounded_client()?,
        }))
    }

    pub async fn start(&self) -> Result<OAuthChallenge, String> {
        if self.config.kind == ProviderKind::GitHub {
            return self.github_challenge();
        }
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.as_str().trim_end_matches('/')
        );
        let discovery: Discovery = read_json(
            self.client
                .get(discovery_url)
                .send()
                .await
                .map_err(|_| provider_unavailable())?,
        )
        .await?;
        self.challenge_from_discovery(discovery)
    }

    fn challenge_from_discovery(&self, discovery: Discovery) -> Result<OAuthChallenge, String> {
        let (mut authorization_url, token_endpoint, jwks_uri, token_auth_method) =
            self.config.validate_discovery(discovery)?;
        let state = random_token()?;
        let nonce = Zeroizing::new(random_token()?);
        let verifier = Zeroizing::new(random_token()?);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", self.config.redirect_uri.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", "openid")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            // The approval button reviewed the exact task before this redirect.
            // Explicit Dex consent keeps an existing IdP session visible to the user.
            .append_pair("prompt", "consent");
        Ok(OAuthChallenge {
            authorization_url: authorization_url.into(),
            state,
            verifier,
            issued_at: now()?,
            token_endpoint,
            flow: OAuthFlow::Oidc {
                nonce,
                jwks_uri,
                auth_method: token_auth_method,
            },
        })
    }

    fn github_challenge(&self) -> Result<OAuthChallenge, String> {
        let state = random_token()?;
        let verifier = Zeroizing::new(random_token()?);
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut authorization_url = Url::parse(GITHUB_AUTHORIZE).expect("fixed GitHub URL");
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", self.config.redirect_uri.as_str())
            .append_pair("scope", "")
            .append_pair("state", &state)
            .append_pair("code_challenge", &digest)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account")
            .append_pair("allow_signup", "false");
        Ok(OAuthChallenge {
            authorization_url: authorization_url.into(),
            state,
            verifier,
            issued_at: now()?,
            token_endpoint: Url::parse(GITHUB_TOKEN).expect("fixed GitHub URL"),
            flow: OAuthFlow::GitHub {
                user_endpoint: Url::parse(GITHUB_USER).expect("fixed GitHub URL"),
            },
        })
    }

    /// Takes ownership so a transaction cannot be retried after an uncertain
    /// token exchange. The caller removes the transaction before calling this.
    pub async fn finish(
        &self,
        challenge: OAuthChallenge,
        code: &str,
        state: &str,
    ) -> Result<OAuthIdentity, String> {
        validate_challenge(&challenge, code, state, now()?)?;
        let (jwks_uri, token_auth_method) = match (&challenge.flow, self.config.kind) {
            (OAuthFlow::GitHub { user_endpoint }, ProviderKind::GitHub) => {
                return self
                    .finish_github(&challenge, code, state, user_endpoint)
                    .await;
            }
            (
                OAuthFlow::Oidc {
                    jwks_uri,
                    auth_method,
                    ..
                },
                ProviderKind::Oidc,
            ) => (jwks_uri, auth_method),
            _ => return Err("OAuth response does not match the configured provider".into()),
        };
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("code_verifier", challenge.verifier.as_str()),
        ];
        let mut request = self.client.post(challenge.token_endpoint.clone());
        match token_auth_method {
            TokenAuthMethod::Public => fields.push(("client_id", &self.config.client_id)),
            TokenAuthMethod::Basic => {
                // RFC 6749 section 2.3.1 requires form encoding before Basic auth.
                let client_id = form_component(&self.config.client_id);
                let secret = Zeroizing::new(form_component(
                    self.config
                        .client_secret
                        .as_ref()
                        .ok_or("OAuth client is unavailable")?,
                ));
                request = request.basic_auth(client_id, Some(secret.as_str()));
            }
            TokenAuthMethod::Post => {
                fields.push(("client_id", &self.config.client_id));
                fields.push((
                    "client_secret",
                    self.config
                        .client_secret
                        .as_ref()
                        .ok_or("OAuth client is unavailable")?
                        .as_str(),
                ));
            }
        }
        let response = request
            .form(&fields)
            .send()
            .await
            .map_err(|_| provider_unavailable())?;
        let token: TokenResponse = read_json(response).await?;
        let id_token = Zeroizing::new(token.id_token);
        if id_token.len() > MAX_ID_TOKEN_BYTES {
            return Err(invalid_identity());
        }
        let keys: JwkSet = read_json(
            self.client
                .get(jwks_uri.clone())
                .send()
                .await
                .map_err(|_| provider_unavailable())?,
        )
        .await?;
        let verified_at = now()?;
        // Network time never extends the approval transaction's lifetime.
        validate_challenge(&challenge, code, state, verified_at)?;
        verify_id_token(&self.config, &challenge, &id_token, &keys, verified_at)
    }

    async fn finish_github(
        &self,
        challenge: &OAuthChallenge,
        code: &str,
        state: &str,
        user_endpoint: &Url,
    ) -> Result<OAuthIdentity, String> {
        let secret = self
            .config
            .client_secret
            .as_ref()
            .ok_or("GitHub client is unavailable")?;
        let response = self
            .client
            .post(challenge.token_endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("code", code),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("code_verifier", challenge.verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|_| provider_unavailable())?;
        let response: GitHubTokenResponse = read_json(response).await?;
        let token = validate_github_token(response)?;
        let response = self
            .client
            .get(user_endpoint.clone())
            .bearer_auth(token.as_str())
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|_| provider_unavailable())?;
        // Defend against an existing app grant silently restoring broader scopes.
        if response
            .headers()
            .get_all("x-oauth-scopes")
            .iter()
            .any(|scope| scope.as_bytes() != b"")
        {
            return Err(github_scope_error());
        }
        let user: GitHubUser = read_json(response).await?;
        validate_challenge(challenge, code, state, now()?)?;
        if user.id == 0 || user.account_type != "User" {
            return Err(invalid_identity());
        }
        Ok(OAuthIdentity {
            kind: "github_oauth",
            issuer: GITHUB_ISSUER.into(),
            subject: user.id.to_string(),
        })
    }
}

impl OAuthConfig {
    fn new(
        issuer: String,
        client_id: String,
        secret: Option<String>,
        redirect_uri: String,
    ) -> Result<Self, String> {
        let issuer_url = secure_url(&issuer)?;
        // Preserve exact OIDC issuer comparison instead of silently normalizing it.
        if issuer_url.as_str() != issuer
            || client_id.is_empty()
            || client_id.len() > 256
            || client_id.chars().any(char::is_control)
            || secret
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 4096)
        {
            return Err("Invalid OAuth client configuration".into());
        }
        let redirect_uri = secure_url(&redirect_uri)?;
        if redirect_uri.path() != "/approval/callback" {
            return Err("OAuth redirect URI must use /approval/callback".into());
        }
        Ok(Self {
            kind: ProviderKind::Oidc,
            issuer: issuer_url,
            client_id,
            client_secret: secret.map(Zeroizing::new),
            redirect_uri,
        })
    }

    fn github(client_id: String, secret: String, redirect_uri: String) -> Result<Self, String> {
        let mut config = Self::new(
            format!("{GITHUB_ISSUER}/"),
            client_id,
            Some(secret),
            redirect_uri,
        )?;
        config.kind = ProviderKind::GitHub;
        Ok(config)
    }

    fn validate_discovery(
        &self,
        document: Discovery,
    ) -> Result<(Url, Url, Url, TokenAuthMethod), String> {
        if document.issuer != self.issuer.as_str()
            || !document
                .response_types_supported
                .iter()
                .any(|item| item == "code")
            || !document
                .id_token_signing_alg_values_supported
                .iter()
                .any(|item| item == "RS256")
            || !document
                .code_challenge_methods_supported
                .iter()
                .any(|item| item == "S256")
        {
            return Err("OAuth provider does not match the required Dex OIDC configuration".into());
        }
        let auth_methods = document
            .token_endpoint_auth_methods_supported
            .unwrap_or_else(|| vec!["client_secret_basic".into()]);
        let auth_method = if self.client_secret.is_none() {
            // Dex public static clients support PKCE without a client secret,
            // including Dex versions that omit `none` in this discovery list.
            TokenAuthMethod::Public
        } else if auth_methods
            .iter()
            .any(|item| item == "client_secret_basic")
        {
            TokenAuthMethod::Basic
        } else if auth_methods.iter().any(|item| item == "client_secret_post") {
            TokenAuthMethod::Post
        } else {
            return Err("OAuth provider does not support this client authentication method".into());
        };
        Ok((
            issuer_endpoint(&self.issuer, &document.authorization_endpoint)?,
            issuer_endpoint(&self.issuer, &document.token_endpoint)?,
            issuer_endpoint(&self.issuer, &document.jwks_uri)?,
            auth_method,
        ))
    }
}

fn verify_id_token(
    config: &OAuthConfig,
    challenge: &OAuthChallenge,
    token: &str,
    keys: &JwkSet,
    timestamp: u64,
) -> Result<OAuthIdentity, String> {
    let header = decode_header(token).map_err(|_| invalid_identity())?;
    // Fixed algorithm and pinned JWKS prevent algorithm/key URL substitution.
    if header.alg != Algorithm::RS256
        || token.len() > MAX_ID_TOKEN_BYTES
        || header.crit.is_some()
        || header.enc.is_some()
        || header.zip.is_some()
    {
        return Err(invalid_identity());
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(invalid_identity)?;
    let mut matching = keys
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid));
    let key = matching.next().ok_or_else(invalid_identity)?;
    if matching.next().is_some()
        || !matches!(key.algorithm, AlgorithmParameters::RSA(_))
        || key
            .common
            .key_algorithm
            .is_some_and(|algorithm| algorithm != KeyAlgorithm::RS256)
        || key
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| *usage != PublicKeyUse::Signature)
        || key
            .common
            .key_operations
            .as_ref()
            .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
    {
        return Err(invalid_identity());
    }
    let key = DecodingKey::from_jwk(key).map_err(|_| invalid_identity())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat", "nonce"]);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[&config.client_id]);
    let claims = decode::<IdClaims>(token, &key, &validation)
        .map_err(|_| invalid_identity())?
        .claims;
    validate_claims(config, challenge, &claims, timestamp)?;
    Ok(OAuthIdentity {
        kind: "oidc",
        issuer: claims.iss,
        subject: claims.sub,
    })
}

fn validate_claims(
    config: &OAuthConfig,
    challenge: &OAuthChallenge,
    claims: &IdClaims,
    timestamp: u64,
) -> Result<(), String> {
    let OAuthFlow::Oidc { nonce, .. } = &challenge.flow else {
        return Err(invalid_identity());
    };
    let audience_ok = match &claims.aud {
        Audience::One(aud) => aud == &config.client_id,
        Audience::Many(aud) => {
            !aud.is_empty()
                && aud.iter().any(|item| item == &config.client_id)
                && (aud.len() == 1 || claims.azp.as_deref() == Some(config.client_id.as_str()))
        }
    };
    if claims.iss != config.issuer.as_str()
        || !audience_ok
        || claims
            .azp
            .as_ref()
            .is_some_and(|azp| azp != &config.client_id)
        || claims.nonce != nonce.as_str()
        || claims.sub.is_empty()
        || claims.sub.len() > 1024
        || claims.sub.chars().any(char::is_control)
        || claims.exp <= timestamp
        || claims.exp <= claims.iat
        || claims.iat > timestamp.saturating_add(CLOCK_SKEW_SECS)
        || claims.iat.saturating_add(CLOCK_SKEW_SECS) < challenge.issued_at
    {
        return Err(invalid_identity());
    }
    Ok(())
}

fn validate_challenge(
    challenge: &OAuthChallenge,
    code: &str,
    state: &str,
    timestamp: u64,
) -> Result<(), String> {
    if state != challenge.state
        || code.is_empty()
        || code.len() > 4096
        || code.chars().any(char::is_control)
        || timestamp < challenge.issued_at
        || timestamp >= challenge.issued_at.saturating_add(CHALLENGE_LIFETIME_SECS)
    {
        return Err("OAuth approval has expired or does not match this transaction".into());
    }
    Ok(())
}

fn secure_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "Invalid OAuth URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("OAuth URLs require HTTPS without credentials, query, or fragment".into());
    }
    Ok(url)
}

fn issuer_endpoint(issuer: &Url, value: &str) -> Result<Url, String> {
    let endpoint = secure_url(value)?;
    let prefix = format!("{}/", issuer.path().trim_end_matches('/'));
    if endpoint.origin() != issuer.origin()
        || !endpoint.path().starts_with(&prefix)
        || endpoint.path().contains('%')
    {
        return Err("OAuth endpoint is outside the configured issuer".into());
    }
    Ok(endpoint)
}

fn bounded_client() -> Result<Client, String> {
    Client::builder()
        .user_agent("Opaque-Demo-Approval")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .https_only(true)
        .build()
        .map_err(|_| "OAuth HTTP client is unavailable".into())
}

async fn read_json<T: serde::de::DeserializeOwned>(mut response: Response) -> Result<T, String> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_JSON_BYTES as u64)
    {
        return Err(provider_unavailable());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| provider_unavailable())? {
        if bytes.len().saturating_add(chunk.len()) > MAX_JSON_BYTES {
            return Err(provider_unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| provider_unavailable())
}

fn form_component(value: &str) -> String {
    // reqwest::Url reexports the same URL parser used for the request encoding.
    let mut url = Url::parse("https://invalid.example/").expect("constant valid URL");
    url.query_pairs_mut().append_pair("v", value);
    url.query().expect("query inserted")[2..].into()
}

fn env_value(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Err(format!("{name} must not be empty")),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(format!("{name} is invalid")),
    }
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "OAuth randomness is unavailable")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| "OAuth clock is unavailable".into())
}

fn provider_unavailable() -> String {
    "OAuth provider is unavailable; start a new approval".into()
}

fn validate_github_token(response: GitHubTokenResponse) -> Result<Zeroizing<String>, String> {
    let token = Zeroizing::new(response.access_token);
    if response
        .scope
        .as_ref()
        .is_some_and(|scope| !scope.is_empty())
    {
        return Err(github_scope_error());
    }
    if response.error.is_some()
        || !response.token_type.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 4096
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
        || response.expires_in == Some(0)
    {
        return Err(invalid_identity());
    }
    Ok(token)
}

fn github_scope_error() -> String {
    "GitHub returned permissions beyond public identity. Use a dedicated approval OAuth app or remove this app's existing authorization before retrying.".into()
}
fn invalid_identity() -> String {
    "OAuth identity verification failed; start a new approval".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        encoding::{AsDer, Pkcs8V1Der},
        rsa::{KeyPair, KeySize},
    };
    use jsonwebtoken::{EncodingKey, Header, encode, jwk::Jwk};
    use serde_json::{Value, json};
    use std::sync::OnceLock;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, header, method, path},
    };

    fn config() -> OAuthConfig {
        OAuthConfig::new(
            "https://issuer.example/api/dex".into(),
            "opaque-browser".into(),
            None,
            "https://demo.opaque.info/approval/callback".into(),
        )
        .unwrap()
    }

    fn challenge(timestamp: u64) -> OAuthChallenge {
        OAuthChallenge {
            authorization_url: "https://issuer.example/api/dex/auth".into(),
            state: "transaction-state".into(),
            verifier: Zeroizing::new("test-pkce-verifier".into()),
            issued_at: timestamp,
            token_endpoint: Url::parse("https://issuer.example/api/dex/token").unwrap(),
            flow: OAuthFlow::Oidc {
                nonce: Zeroizing::new("transaction-nonce".into()),
                jwks_uri: Url::parse("https://issuer.example/api/dex/keys").unwrap(),
                auth_method: TokenAuthMethod::Public,
            },
        }
    }

    fn claims(timestamp: u64) -> Value {
        json!({"iss":"https://issuer.example/api/dex", "sub":"dex-subject", "aud":"opaque-browser",
            "iat":timestamp, "exp":timestamp+600, "nonce":"transaction-nonce"})
    }

    fn signing_key() -> &'static (EncodingKey, Jwk) {
        static KEY: OnceLock<(EncodingKey, Jwk)> = OnceLock::new();
        KEY.get_or_init(|| {
            // Runtime-only private material: never a checked-in key fixture.
            let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
            let der: Pkcs8V1Der<'static> = pair.as_der().unwrap();
            let pem = Zeroizing::new(format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(der.as_ref())
            ));
            let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
            let mut jwk = Jwk::from_encoding_key(&key, Algorithm::RS256).unwrap();
            jwk.common.key_id = Some("test-key".into());
            jwk.common.public_key_use = Some(PublicKeyUse::Signature);
            (key, jwk)
        })
    }

    fn signed(claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".into());
        encode(&header, claims, &signing_key().0).unwrap()
    }

    fn keys() -> JwkSet {
        JwkSet {
            keys: vec![signing_key().1.clone()],
        }
    }

    fn discovery() -> Discovery {
        serde_json::from_value(json!({
            "issuer":"https://issuer.example/api/dex",
            "authorization_endpoint":"https://issuer.example/api/dex/auth",
            "token_endpoint":"https://issuer.example/api/dex/token",
            "jwks_uri":"https://issuer.example/api/dex/keys",
            "response_types_supported":["code"],
            "id_token_signing_alg_values_supported":["RS256"],
            "code_challenge_methods_supported":["S256"]
        }))
        .unwrap()
    }

    #[test]
    fn issuer_and_redirect_configuration_require_exact_safe_https() {
        for issuer in [
            "http://issuer.example/api/dex",
            "https://user:password@issuer.example/api/dex",
            "https://issuer.example/api/dex?next=elsewhere",
            "https://issuer.example/api/dex#fragment",
            "https://ISSUER.example/api/dex",
        ] {
            assert!(
                OAuthConfig::new(
                    issuer.into(),
                    "client".into(),
                    None,
                    "https://demo.opaque.info/approval/callback".into()
                )
                .is_err()
            );
        }
        assert!(
            OAuthConfig::new(
                "https://issuer.example/api/dex".into(),
                "client".into(),
                None,
                "https://demo.opaque.info/somewhere-else".into()
            )
            .is_err()
        );
        assert!(config().validate_discovery(discovery()).is_ok());
    }

    #[test]
    fn discovery_rejects_issuer_mixup_external_endpoints_and_missing_pkce() {
        let config = config();
        let mut document = discovery();
        document.issuer.push('/');
        assert!(config.validate_discovery(document).is_err());
        for endpoint in [
            "https://attacker.example/token",
            "http://issuer.example/api/dex/token",
            "https://issuer.example:8443/api/dex/token",
            "https://issuer.example/api/dexevil/token",
            "https://issuer.example/token",
            "https://issuer.example/api/dex/%2f..%2ftoken",
        ] {
            let mut document = discovery();
            document.token_endpoint = endpoint.into();
            assert!(config.validate_discovery(document).is_err(), "{endpoint}");
        }
        let mut document = discovery();
        document.code_challenge_methods_supported = vec!["plain".into()];
        assert!(config.validate_discovery(document).is_err());
        let mut document = discovery();
        document.id_token_signing_alg_values_supported = vec!["HS256".into()];
        assert!(config.validate_discovery(document).is_err());
    }

    #[test]
    fn state_expiry_and_code_checked_before_exchange() {
        let challenge = challenge(1_000);
        assert!(validate_challenge(&challenge, "code", "transaction-state", 1_000).is_ok());
        assert!(validate_challenge(&challenge, "code", "other-state", 1_000).is_err());
        assert!(validate_challenge(&challenge, "", "transaction-state", 1_000).is_err());
        assert!(validate_challenge(&challenge, "code\n", "transaction-state", 1_000).is_err());
        assert!(validate_challenge(&challenge, "code", "transaction-state", 999).is_err());
        assert!(validate_challenge(&challenge, "code", "transaction-state", 1_300).is_err());
    }

    #[test]
    fn authorization_request_uses_unique_bound_state_nonce_and_s256() {
        let provider = OAuthProvider {
            config: config(),
            client: bounded_client().unwrap(),
        };
        let challenge = provider.challenge_from_discovery(discovery()).unwrap();
        let another = provider.challenge_from_discovery(discovery()).unwrap();
        let url = Url::parse(&challenge.authorization_url).unwrap();
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let OAuthFlow::Oidc { nonce, .. } = &challenge.flow else {
            panic!("OIDC challenge");
        };
        let OAuthFlow::Oidc {
            nonce: another_nonce,
            ..
        } = &another.flow
        else {
            panic!("OIDC challenge");
        };
        assert_eq!(params["state"], challenge.state);
        assert_eq!(params["nonce"], nonce.as_str());
        assert_eq!(
            params["code_challenge"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(challenge.verifier.as_bytes()))
        );
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["scope"], "openid");
        assert_eq!(params["response_type"], "code");
        assert_eq!(
            params["redirect_uri"],
            "https://demo.opaque.info/approval/callback"
        );
        assert_eq!(params["client_id"], "opaque-browser");
        assert_ne!(challenge.state, another.state);
        assert_ne!(nonce, another_nonce);
        assert_ne!(challenge.verifier, another.verifier);
        assert_ne!(challenge.state, nonce.as_str());
        assert!(!params.contains_key("code_verifier"));
        assert!(
            provider
                .validate_redirect_origin("https://demo.opaque.info")
                .is_ok()
        );
        assert!(
            provider
                .validate_redirect_origin("https://other.example")
                .is_err()
        );
        assert!(
            provider
                .validate_redirect_origin("https://demo.opaque.info:8443")
                .is_err()
        );
    }

    #[test]
    fn signature_and_all_identity_bindings_are_required() {
        let timestamp = now().unwrap();
        let config = config();
        let challenge = challenge(timestamp);
        let claims = claims(timestamp);
        let identity =
            verify_id_token(&config, &challenge, &signed(&claims), &keys(), timestamp).unwrap();
        assert_eq!(identity.subject, "dex-subject");
        assert_eq!(identity.issuer, config.issuer.as_str());
        for (name, bad) in [
            ("iss", json!("https://other.example/api/dex")),
            ("sub", json!("")),
            ("aud", json!("opaque-broker")),
            ("aud", json!([])),
            ("nonce", json!("other-nonce")),
            ("azp", json!("another-client")),
            ("exp", json!(timestamp)),
            ("iat", json!(timestamp + 31)),
            ("iat", json!(timestamp - 31)),
            ("aud", json!(["opaque-browser", "another-client"])),
        ] {
            let mut bad_claims = claims.clone();
            bad_claims[name] = bad;
            assert!(
                verify_id_token(
                    &config,
                    &challenge,
                    &signed(&bad_claims),
                    &keys(),
                    timestamp
                )
                .is_err(),
                "{name}"
            );
        }
        for name in ["iss", "sub", "aud", "exp", "iat", "nonce"] {
            let mut bad_claims = claims.clone();
            bad_claims.as_object_mut().unwrap().remove(name);
            assert!(
                verify_id_token(
                    &config,
                    &challenge,
                    &signed(&bad_claims),
                    &keys(),
                    timestamp
                )
                .is_err(),
                "missing {name}"
            );
        }
        let mut multiple = claims.clone();
        multiple["aud"] = json!(["opaque-browser", "another-client"]);
        multiple["azp"] = json!("opaque-browser");
        assert!(
            verify_id_token(&config, &challenge, &signed(&multiple), &keys(), timestamp).is_ok()
        );
        let token = signed(&claims);
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut tampered = claims.clone();
        tampered["sub"] = json!("attacker");
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap());
        assert!(
            verify_id_token(&config, &challenge, &parts.join("."), &keys(), timestamp).is_err()
        );
    }

    #[test]
    fn pinned_signing_key_rejects_algorithm_confusion_and_duplicate_key_ids() {
        let timestamp = now().unwrap();
        let config = config();
        let challenge = challenge(timestamp);
        let claims = claims(timestamp);
        let token = signed(&claims);
        let mut untrusted_keys = keys();
        untrusted_keys.keys.push(untrusted_keys.keys[0].clone());
        assert!(verify_id_token(&config, &challenge, &token, &untrusted_keys, timestamp).is_err());
        let mut encryption_key = keys();
        encryption_key.keys[0].common.public_key_use = Some(PublicKeyUse::Encryption);
        assert!(verify_id_token(&config, &challenge, &token, &encryption_key, timestamp).is_err());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key".into());
        let symmetric = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"not-a-provider-key"),
        )
        .unwrap();
        assert!(verify_id_token(&config, &challenge, &symmetric, &keys(), timestamp).is_err());
        assert!(
            verify_id_token(
                &config,
                &challenge,
                &token,
                &JwkSet { keys: vec![] },
                timestamp
            )
            .is_err()
        );
        let mut critical = Header::new(Algorithm::RS256);
        critical.kid = Some("test-key".into());
        critical.crit = Some(vec!["unsupported-critical-extension".into()]);
        let critical_token = encode(&critical, &claims, &signing_key().0).unwrap();
        assert!(verify_id_token(&config, &challenge, &critical_token, &keys(), timestamp).is_err());
    }

    #[tokio::test]
    async fn exchanges_code_with_verifier_and_validates_signed_id_token() {
        let server = MockServer::start().await;
        let timestamp = now().unwrap();
        let provider = OAuthProvider {
            config: config(),
            client: Client::new(),
        };
        let mut challenge = challenge(timestamp);
        // HTTP is only injected into this local test. Production endpoints and
        // the production client independently require HTTPS.
        challenge.token_endpoint = Url::parse(&format!("{}/token", server.uri())).unwrap();
        let OAuthFlow::Oidc { jwks_uri, .. } = &mut challenge.flow else {
            panic!("OIDC challenge");
        };
        *jwks_uri = Url::parse(&format!("{}/keys", server.uri())).unwrap();
        Mock::given(method("POST")).and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=provider-code"))
            .and(body_string_contains("code_verifier=test-pkce-verifier"))
            .and(body_string_contains("client_id=opaque-browser"))
            .and(body_string_contains("redirect_uri=https%3A%2F%2Fdemo.opaque.info%2Fapproval%2Fcallback"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id_token":signed(&claims(timestamp)), "access_token":"must-not-be-forwarded", "refresh_token":"must-not-be-stored"
            }))).expect(1).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(keys()))
            .expect(1)
            .mount(&server)
            .await;
        let identity = provider
            .finish(challenge, "provider-code", "transaction-state")
            .await
            .unwrap();
        assert_eq!(identity.subject, "dex-subject");
        server.verify().await;
    }

    #[tokio::test]
    async fn provider_errors_never_expose_response_bodies_and_body_is_bounded() {
        let server = MockServer::start().await;
        Mock::given(path("/error"))
            .respond_with(ResponseTemplate::new(400).set_body_string("SECRET-TOKEN-DETAILS"))
            .mount(&server)
            .await;
        Mock::given(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_JSON_BYTES + 1]))
            .mount(&server)
            .await;
        for path in ["error", "large"] {
            let response = Client::new()
                .get(format!("{}/{path}", server.uri()))
                .send()
                .await
                .unwrap();
            let result = read_json::<Value>(response).await;
            assert_eq!(result.unwrap_err(), provider_unavailable());
        }
    }

    #[test]
    fn random_values_have_pkce_entropy_and_basic_credentials_are_form_encoded() {
        let first = random_token().unwrap();
        let second = random_token().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(first).unwrap().len(), 32);
        assert_eq!(form_component("client:secret +/"), "client%3Asecret+%2B%2F");
    }

    fn github_provider() -> OAuthProvider {
        OAuthProvider {
            config: OAuthConfig::github(
                "github-approval-client".into(),
                "ephemeral-test-client-secret".into(),
                "https://demo.opaque.info/approval/callback".into(),
            )
            .unwrap(),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("Opaque-Demo-Approval")
                .build()
                .unwrap(),
        }
    }

    fn local_github_challenge(provider: &OAuthProvider, server: &MockServer) -> OAuthChallenge {
        let mut challenge = provider.github_challenge().unwrap();
        challenge.token_endpoint = Url::parse(&format!("{}/token", server.uri())).unwrap();
        challenge.flow = OAuthFlow::GitHub {
            user_endpoint: Url::parse(&format!("{}/user", server.uri())).unwrap(),
        };
        challenge
    }

    #[test]
    fn github_authorization_pins_endpoints_and_requests_only_public_identity() {
        let provider = github_provider();
        let challenge = provider.github_challenge().unwrap();
        let url = Url::parse(&challenge.authorization_url).unwrap();
        assert_eq!(url.origin().ascii_serialization(), GITHUB_ISSUER);
        assert_eq!(url.path(), "/login/oauth/authorize");
        assert_eq!(challenge.token_endpoint.as_str(), GITHUB_TOKEN);
        let OAuthFlow::GitHub { user_endpoint } = &challenge.flow else {
            panic!("GitHub flow");
        };
        assert_eq!(user_endpoint.as_str(), GITHUB_USER);
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["scope"], "");
        assert_eq!(params["state"], challenge.state);
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["code_challenge"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(challenge.verifier.as_bytes()))
        );
        assert_eq!(params["prompt"], "select_account");
        assert!(!params.contains_key("client_secret"));
        assert!(!params.contains_key("code_verifier"));
        assert_eq!(provider.label(), "GitHub");
        assert_eq!(provider.proof_kind(), "github_oauth");
        assert!(
            OAuthConfig::github(
                "client".into(),
                "".into(),
                "https://demo.opaque.info/approval/callback".into()
            )
            .is_err()
        );
    }

    #[test]
    fn github_token_requires_bearer_without_scope_escalation() {
        let valid = json!({"access_token":"ephemeral-test-token","token_type":"bearer","scope":""});
        assert!(validate_github_token(serde_json::from_value(valid.clone()).unwrap()).is_ok());
        let mut absent = valid.clone();
        absent.as_object_mut().unwrap().remove("scope");
        assert!(validate_github_token(serde_json::from_value(absent).unwrap()).is_ok());
        for (key, value) in [
            ("scope", json!("repo")),
            ("scope", json!("read:user")),
            ("scope", json!("user:email")),
            ("scope", json!(" ")),
            ("token_type", json!("mac")),
            ("access_token", json!("")),
            ("access_token", json!("bad\ntoken")),
            ("expires_in", json!(0)),
            ("error", json!("access_denied")),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(
                validate_github_token(serde_json::from_value(invalid).unwrap()).is_err(),
                "{key}"
            );
        }
    }

    #[tokio::test]
    async fn github_exchanges_code_with_secret_pkce_and_revalidates_stable_user_id() {
        let server = MockServer::start().await;
        let provider = github_provider();
        let challenge = local_github_challenge(&provider, &server);
        let state = challenge.state.clone();
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("accept", "application/json"))
            .and(body_string_contains("client_id=github-approval-client"))
            .and(body_string_contains(
                "client_secret=ephemeral-test-client-secret",
            ))
            .and(body_string_contains("code=github-code"))
            .and(body_string_contains(format!(
                "code_verifier={}",
                challenge.verifier.as_str()
            )))
            .and(body_string_contains(
                "redirect_uri=https%3A%2F%2Fdemo.opaque.info%2Fapproval%2Fcallback",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"access_token":"ephemeral-test-token","token_type":"bearer","scope":""}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/user"))
            .and(header("authorization","Bearer ephemeral-test-token"))
            .and(header("user-agent","Opaque-Demo-Approval"))
            .respond_with(ResponseTemplate::new(200).insert_header("x-oauth-scopes","")
                .set_body_json(json!({"id":123456,"login":"renameable-login","type":"User","email":"ignored@example.test"})))
            .expect(1).mount(&server).await;
        let identity = provider
            .finish(challenge, "github-code", &state)
            .await
            .unwrap();
        assert_eq!(identity.kind, "github_oauth");
        assert_eq!(identity.issuer, GITHUB_ISSUER);
        assert_eq!(identity.subject, "123456");
        server.verify().await;
    }

    #[tokio::test]
    async fn github_rejects_invalid_user_or_scoped_identity_response() {
        for (user, scope, status) in [
            (json!({"id":0,"type":"User"}), "", 200),
            (json!({"id":1,"type":"Bot"}), "", 200),
            (json!({"id":"1","type":"User"}), "", 200),
            (json!({"id":1,"type":"User"}), "repo", 200),
            (json!({"id":1,"type":"User"}), "", 401),
        ] {
            let server = MockServer::start().await;
            let provider = github_provider();
            let challenge = local_github_challenge(&provider, &server);
            let state = challenge.state.clone();
            Mock::given(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"access_token":"ephemeral-test-token","token_type":"bearer","scope":""}),
                ))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(path("/user"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("x-oauth-scopes", scope)
                        .set_body_json(user),
                )
                .expect(1)
                .mount(&server)
                .await;
            assert!(
                provider
                    .finish(challenge, "github-code", &state)
                    .await
                    .is_err()
            );
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn github_refuses_redirected_code_exchange_and_provider_mixup() {
        let server = MockServer::start().await;
        let provider = github_provider();
        let challenge = local_github_challenge(&provider, &server);
        let state = challenge.state.clone();
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/leak", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/leak"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        assert!(
            provider
                .finish(challenge, "github-code", &state)
                .await
                .is_err()
        );
        let oidc_challenge = self::challenge(now().unwrap());
        assert!(
            provider
                .finish(oidc_challenge, "code", "transaction-state")
                .await
                .is_err()
        );
        server.verify().await;
    }
}
