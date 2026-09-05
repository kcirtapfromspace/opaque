//! OAuth access-token validation for the metrics resource server.
//!
//! This is a deliberately narrow static-key resource-server profile, not an
//! authorization server or OIDC login verifier. The trusted configuration pins
//! one RSA public key; JWT headers never select keys or cause network access.
//! Key rotation requires replacing trusted configuration and the verifier.
//! Call `verify_bearer` on each request and `check_access` before each stream
//! event. Never pass the client's bearer token through to a metrics provider.
//!
//! References: [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)
//! (access-token type and claims), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)
//! (resource audience), and [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
//! This static profile requires the exact short `at+jwt` type and a single
//! audience string; it intentionally accepts fewer representations than the
//! general JWT access-token profile.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use opaque_core::tenant::TenantId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const METRIC_SCOPES: [&str; 19] = [
    "portfolio:read",
    "portfolio:measure:manual_review_count",
    "portfolio:measure:identity_mismatch_count",
    "portfolio:measure:application_count",
    "portfolio:measure:manual_review_rate_percent",
    "portfolio:measure:identity_mismatch_rate_percent",
    "portfolio:measure:mean_processing_seconds",
    "organization:activity:read",
    "metrics:read",
    "metrics:stream",
    "metrics:explain",
    "metrics:metric:requests_per_second",
    "metrics:metric:error_rate_percent",
    "metrics:metric:p95_latency_ms",
    "metrics:metric:active_sessions",
    "metrics:metric:credit_applications_per_minute",
    "metrics:metric:manual_review_rate_percent",
    "metrics:metric:identity_mismatch_rate_percent",
    "metrics:metric:average_credit_score",
];
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_REVOKED_JTIS: usize = 65_536;

fn default_token_ttl() -> u64 {
    900
}

/// Trusted deployment configuration. This object is never accepted over MCP.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub issuer: String,
    pub resource_audience: String,
    /// Public PEM loaded from operator-controlled local configuration.
    pub public_key_pem: String,
    pub admissions: Vec<Admission>,
    #[serde(default)]
    pub revoked_jtis: BTreeSet<String>,
    #[serde(default = "default_token_ttl")]
    pub max_token_ttl_secs: u64,
    /// Optional tolerance for iat/nbf only. Expiration is always exclusive.
    #[serde(default)]
    pub clock_skew_secs: u64,
    /// Explicit fixture option; HTTP is still restricted to literal loopback.
    #[serde(default)]
    pub allow_loopback_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub tenant_id: TenantId,
    pub subject: String,
    pub scopes: BTreeSet<String>,
}

/// Produced only after signature, claim, admission and revocation checks.
/// Private fields and the verifier-instance binding prevent callers from
/// manufacturing authority or passing another verifier's result as local.
#[derive(Debug, Clone)]
pub struct VerifiedAccess {
    authority: Arc<()>,
    tenant_id: TenantId,
    subject: String,
    client_id: String,
    scopes: BTreeSet<String>,
    expires_at: i64,
    not_before: i64,
    jti: String,
}

impl VerifiedAccess {
    pub fn tenant_id(&self) -> &str {
        self.tenant_id.as_str()
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn jti(&self) -> &str {
        &self.jti
    }
    pub fn require_scope(&self, scope: &str) -> Result<(), AuthError> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(AuthError::InsufficientScope)
        }
    }
}

/// Errors contain no bearer token, unverified claim text, or provider detail.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid metrics authorization configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("a bearer access token is required")]
    MissingBearer,
    #[error("invalid or expired metrics access token")]
    InvalidToken,
    #[error("tenant or subject is not admitted to this metrics resource")]
    NotAdmitted,
    #[error("access token lacks an admitted metric scope")]
    InsufficientScope,
    #[error("metrics access token has been revoked")]
    Revoked,
    #[error("metrics authorization state is unavailable")]
    Unavailable,
}

impl AuthError {
    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::MissingBearer | Self::InvalidToken | Self::Revoked => 401,
            Self::NotAdmitted | Self::InsufficientScope => 403,
            Self::Unavailable => 503,
            Self::InvalidConfig(_) => 500,
        }
    }
}

pub struct AuthVerifier {
    authority: Arc<()>,
    issuer: String,
    audience: String,
    key: DecodingKey,
    validation: Validation,
    admissions: BTreeMap<(TenantId, String), BTreeSet<String>>,
    revoked_jtis: RwLock<BTreeSet<String>>,
    max_token_ttl_secs: i64,
    clock_skew_secs: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedHeader {
    typ: String,
    alg: String,
    /// Informational only: even a valid kid never selects a different key.
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct AccessClaims {
    iss: String,
    /// A single exact resource. Arrays, even singleton arrays, are rejected.
    aud: String,
    sub: String,
    client_id: String,
    tenant_id: TenantId,
    scope: String,
    jti: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
}

impl AuthVerifier {
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        validate_url(&config.issuer, config.allow_loopback_http)?;
        validate_url(&config.resource_audience, config.allow_loopback_http)?;
        if !(1..=900).contains(&config.max_token_ttl_secs) || config.clock_skew_secs > 30 {
            return Err(AuthError::InvalidConfig(
                "token lifetime or clock tolerance is excessive",
            ));
        }
        if config.public_key_pem.len() > 16 * 1024
            || config.public_key_pem.contains("PRIVATE KEY")
            || !(config
                .public_key_pem
                .starts_with("-----BEGIN PUBLIC KEY-----")
                || config
                    .public_key_pem
                    .starts_with("-----BEGIN RSA PUBLIC KEY-----"))
        {
            return Err(AuthError::InvalidConfig(
                "one pinned RSA public PEM is required",
            ));
        }
        let key = DecodingKey::from_rsa_pem(config.public_key_pem.as_bytes())
            .map_err(|_| AuthError::InvalidConfig("pinned RSA public PEM is invalid"))?;
        if config.admissions.is_empty() || config.admissions.len() > 1024 {
            return Err(AuthError::InvalidConfig(
                "admission mapping is empty or too large",
            ));
        }
        let mut admissions = BTreeMap::new();
        let tenant = &config.admissions[0].tenant_id;
        for admission in &config.admissions {
            if &admission.tenant_id != tenant
                || !valid_identifier(&admission.subject, 255)
                || admission.scopes.is_empty()
                || admission
                    .scopes
                    .iter()
                    .any(|scope| !METRIC_SCOPES.contains(&scope.as_str()))
                || admissions
                    .insert(
                        (admission.tenant_id.clone(), admission.subject.clone()),
                        admission.scopes.clone(),
                    )
                    .is_some()
            {
                return Err(AuthError::InvalidConfig(
                    "admissions must name unique subjects in one tenant with concrete metric scopes",
                ));
            }
        }
        if config.revoked_jtis.len() > MAX_REVOKED_JTIS
            || config
                .revoked_jtis
                .iter()
                .any(|jti| !valid_identifier(jti, 128))
        {
            return Err(AuthError::InvalidConfig("revocation set is invalid"));
        }
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "exp"]);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.resource_audience]);
        validation.leeway = 0;
        // Signature, issuer and audience validation remain enabled. Time is
        // checked below against one explicit clock for requests and streams,
        // with an exclusive expiry and a bounded issued-token lifetime.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        Ok(Self {
            authority: Arc::new(()),
            issuer: config.issuer,
            audience: config.resource_audience,
            key,
            validation,
            admissions,
            revoked_jtis: RwLock::new(config.revoked_jtis),
            max_token_ttl_secs: config.max_token_ttl_secs as i64,
            clock_skew_secs: config.clock_skew_secs as i64,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn resource_audience(&self) -> &str {
        &self.audience
    }

    pub fn verify_bearer(&self, authorization: Option<&str>) -> Result<VerifiedAccess, AuthError> {
        self.verify_bearer_at(authorization, now()?)
    }

    pub fn verify_bearer_at(
        &self,
        authorization: Option<&str>,
        now: i64,
    ) -> Result<VerifiedAccess, AuthError> {
        let authorization = authorization.ok_or(AuthError::MissingBearer)?;
        if authorization.len() > MAX_TOKEN_BYTES + 7 {
            return Err(AuthError::InvalidToken);
        }
        let (scheme, token) = authorization
            .split_once(' ')
            .ok_or(AuthError::MissingBearer)?;
        if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
            return Err(AuthError::MissingBearer);
        }
        if token.len() > MAX_TOKEN_BYTES
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(AuthError::InvalidToken);
        }
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) || parts[0].len() > 2048 {
            return Err(AuthError::InvalidToken);
        }
        let header: PinnedHeader = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|_| AuthError::InvalidToken)?,
        )
        .map_err(|_| AuthError::InvalidToken)?;
        if header.typ != "at+jwt"
            || header.alg != "RS256"
            || header
                .kid
                .as_ref()
                .is_some_and(|kid| !valid_identifier(kid, 128))
        {
            return Err(AuthError::InvalidToken);
        }
        let claims = decode::<AccessClaims>(token, &self.key, &self.validation)
            .map_err(|_| AuthError::InvalidToken)?
            .claims;
        if claims.iss != self.issuer
            || claims.aud != self.audience
            || !valid_identifier(&claims.sub, 255)
            || !valid_identifier(&claims.client_id, 256)
            || !valid_identifier(&claims.jti, 128)
            || claims.iat < 0
            || claims.exp <= claims.iat
            || claims
                .exp
                .checked_sub(claims.iat)
                .is_none_or(|ttl| ttl > self.max_token_ttl_secs)
            || claims.nbf.is_some_and(|nbf| nbf < 0 || nbf >= claims.exp)
        {
            return Err(AuthError::InvalidToken);
        }
        let scopes = parse_scopes(&claims.scope)?;
        let access = VerifiedAccess {
            authority: self.authority.clone(),
            tenant_id: claims.tenant_id,
            subject: claims.sub,
            client_id: claims.client_id,
            scopes,
            expires_at: claims.exp,
            not_before: claims.nbf.unwrap_or(claims.iat).max(claims.iat),
            jti: claims.jti,
        };
        self.check_access_at(&access, now)?;
        Ok(access)
    }

    /// Recheck immediately before each query and outgoing stream event.
    pub fn check_access(&self, access: &VerifiedAccess) -> Result<(), AuthError> {
        self.check_access_at(access, now()?)
    }

    pub fn check_access_at(&self, access: &VerifiedAccess, now: i64) -> Result<(), AuthError> {
        if !Arc::ptr_eq(&self.authority, &access.authority) {
            return Err(AuthError::NotAdmitted);
        }
        if now < 0
            || now >= access.expires_at
            || now
                .checked_add(self.clock_skew_secs)
                .is_none_or(|latest| access.not_before > latest)
        {
            return Err(AuthError::InvalidToken);
        }
        let admitted = self
            .admissions
            .get(&(access.tenant_id.clone(), access.subject.clone()))
            .ok_or(AuthError::NotAdmitted)?;
        if !access.scopes.is_subset(admitted) {
            return Err(AuthError::InsufficientScope);
        }
        if self
            .revoked_jtis
            .read()
            .map_err(|_| AuthError::Unavailable)?
            .contains(&access.jti)
        {
            return Err(AuthError::Revoked);
        }
        Ok(())
    }

    /// Trusted operator hook. Revocation is monotonic for this process;
    /// persist revoked JTIs in AuthConfig to retain them across restarts.
    pub fn revoke_jti(&self, jti: &str) -> Result<(), AuthError> {
        if !valid_identifier(jti, 128) {
            return Err(AuthError::InvalidToken);
        }
        let mut revoked = self
            .revoked_jtis
            .write()
            .map_err(|_| AuthError::Unavailable)?;
        if revoked.len() >= MAX_REVOKED_JTIS && !revoked.contains(jti) {
            return Err(AuthError::Unavailable);
        }
        revoked.insert(jti.to_owned());
        Ok(())
    }
}

fn now() -> Result<i64, AuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .ok_or(AuthError::Unavailable)
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
}

fn parse_scopes(value: &str) -> Result<BTreeSet<String>, AuthError> {
    if value.is_empty() || value.len() > 1024 {
        return Err(AuthError::InsufficientScope);
    }
    let mut scopes = BTreeSet::new();
    for scope in value.split(' ') {
        if !METRIC_SCOPES.contains(&scope) || !scopes.insert(scope.to_owned()) {
            return Err(AuthError::InsufficientScope);
        }
    }
    Ok(scopes)
}

fn validate_url(value: &str, allow_loopback: bool) -> Result<(), AuthError> {
    let invalid = || {
        AuthError::InvalidConfig(
            "issuer and resource must be exact HTTPS URLs, or explicitly enabled loopback fixtures",
        )
    };
    if value.len() > 2048 || !valid_identifier(value, 2048) {
        return Err(invalid());
    }
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && allow_loopback && loopback))
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};

    // Existing repository fixture key: public test material, never production.
    const PRIVATE_FIXTURE: &str = include_str!("../../opaqued/tests/fixtures/test_rsa_key.pem");
    const PUBLIC_FIXTURE: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+m4fkcL6cuTGRLTSSrF\n7zfrwFFnYRJG1yVmmCwn4q0PXhuWmUu9mo2wg9ftf9BLFspkMqyzxpdfzGTan6J9\n5w7Ad7gbP5R2aDGnVJRTX9dph3cKBgwnDsUa751mYWfr1rsTnoiMIDWzOGsRSdOi\nRzZGCYo3yo4YNB+sNIOFMQ/tc3X558HGCZl3boecDmlwt1lHebe6/+kXRTYLLpIl\nf7u1mw98TYtOenu2SIUOrJKY9VGluMxvGH9e4SExpZaG61wTNsosD20tEBkWUjCo\nxo01adXNjPYKx/mJB3NgCIWacU4NwbZxVRUg5HYR85cq+5I2oNQDwuyNDv7kZQfA\nywIDAQAB\n-----END PUBLIC KEY-----\n";
    const NOW: i64 = 1_800_000_000;

    fn config() -> AuthConfig {
        AuthConfig {
            issuer: "https://issuer.example".into(),
            resource_audience: "https://metrics.example/mcp".into(),
            public_key_pem: PUBLIC_FIXTURE.into(),
            admissions: vec![Admission {
                tenant_id: TenantId::parse("customer-a").unwrap(),
                subject: "customer-a-user".into(),
                scopes: METRIC_SCOPES
                    .iter()
                    .map(|scope| scope.to_string())
                    .collect(),
            }],
            revoked_jtis: BTreeSet::new(),
            max_token_ttl_secs: 900,
            clock_skew_secs: 0,
            allow_loopback_http: false,
        }
    }

    fn claims() -> Value {
        json!({
            "iss": "https://issuer.example", "aud": "https://metrics.example/mcp",
            "sub": "customer-a-user", "client_id": "metrics-chat-fixture",
            "tenant_id": "customer-a", "scope": "metrics:read metrics:metric:requests_per_second",
            "jti": "fixture-token-01", "iat": NOW, "exp": NOW + 600, "nbf": NOW,
        })
    }

    fn header() -> Header {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("fixture-only".into());
        header
    }

    fn signed_with_header(claims: &Value, header: &Header) -> String {
        format!(
            "Bearer {}",
            encode(
                header,
                claims,
                &EncodingKey::from_rsa_pem(PRIVATE_FIXTURE.as_bytes()).unwrap()
            )
            .unwrap()
        )
    }

    fn signed(claims: &Value) -> String {
        signed_with_header(claims, &header())
    }

    fn raw_signed(header: &str, claims: &str) -> String {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = jsonwebtoken::crypto::sign(
            message.as_bytes(),
            &EncodingKey::from_rsa_pem(PRIVATE_FIXTURE.as_bytes()).unwrap(),
            Algorithm::RS256,
        )
        .unwrap();
        format!("Bearer {message}.{signature}")
    }

    #[test]
    fn verified_access_contains_only_exact_admitted_authority() {
        let verifier = AuthVerifier::new(config()).unwrap();
        let access = verifier
            .verify_bearer_at(Some(&signed(&claims())), NOW)
            .unwrap();
        assert_eq!(access.tenant_id(), "customer-a");
        assert_eq!(access.subject(), "customer-a-user");
        assert_eq!(access.expires_at(), NOW + 600);
        assert_eq!(access.jti(), "fixture-token-01");
        access.require_scope("metrics:read").unwrap();
        access
            .require_scope("metrics:metric:requests_per_second")
            .unwrap();
        assert_eq!(
            access.require_scope("metrics:explain"),
            Err(AuthError::InsufficientScope)
        );
        assert_eq!(
            access.require_scope("metrics:stream"),
            Err(AuthError::InsufficientScope)
        );
        assert_eq!(access.scopes().len(), 2);
        verifier.check_access_at(&access, NOW + 1).unwrap();
        // Even an identically configured verifier cannot import an authority
        // object as a replacement for validating its own request bearer.
        assert_eq!(
            AuthVerifier::new(config())
                .unwrap()
                .check_access_at(&access, NOW),
            Err(AuthError::NotAdmitted)
        );
    }

    #[test]
    fn wrong_audience_issuer_tenant_subject_or_scope_is_rejected() {
        let verifier = AuthVerifier::new(config()).unwrap();
        for (field, value) in [
            ("iss", json!("https://other-issuer.example")),
            ("aud", json!("https://other-resource.example/mcp")),
            (
                "aud",
                json!([
                    "https://metrics.example/mcp",
                    "https://other-resource.example/mcp"
                ]),
            ),
            ("aud", json!(["https://metrics.example/mcp"])),
            ("tenant_id", json!("customer-b")),
            ("sub", json!("customer-b-user")),
            ("scope", json!("metrics:*")),
            ("scope", json!("openid metrics:read")),
            ("scope", json!("metrics:metric:other_metric")),
            ("scope", json!("metrics:read metrics:read")),
            ("scope", json!(" metrics:read")),
            ("scope", json!("metrics:read\nmetrics:stream")),
            ("scope", json!("")),
        ] {
            let mut changed = claims();
            changed[field] = value;
            assert!(
                verifier
                    .verify_bearer_at(Some(&signed(&changed)), NOW)
                    .is_err(),
                "accepted invalid {field}"
            );
        }
        let mut restricted = config();
        restricted.admissions[0].scopes = BTreeSet::from(["metrics:read".into()]);
        assert_eq!(
            AuthVerifier::new(restricted)
                .unwrap()
                .verify_bearer_at(Some(&signed(&claims())), NOW)
                .unwrap_err(),
            AuthError::InsufficientScope
        );
        let mut explain = claims();
        explain["scope"] = json!("metrics:read metrics:explain");
        verifier
            .verify_bearer_at(Some(&signed(&explain)), NOW)
            .unwrap()
            .require_scope("metrics:explain")
            .unwrap();
    }

    #[test]
    fn token_type_algorithm_signature_and_embedded_key_overrides_are_rejected() {
        let verifier = AuthVerifier::new(config()).unwrap();
        for typ in [
            None,
            Some("JWT"),
            Some("id+jwt"),
            Some("at+JWT"),
            Some("application/at+jwt"),
        ] {
            let mut changed = header();
            changed.typ = typ.map(str::to_owned);
            assert!(
                verifier
                    .verify_bearer_at(Some(&signed_with_header(&claims(), &changed)), NOW)
                    .is_err()
            );
        }
        for algorithm in [Algorithm::RS384, Algorithm::RS512] {
            let mut changed = header();
            changed.alg = algorithm;
            assert!(
                verifier
                    .verify_bearer_at(Some(&signed_with_header(&claims(), &changed)), NOW)
                    .is_err()
            );
        }
        let mut hmac = Header::new(Algorithm::HS256);
        hmac.typ = Some("at+jwt".into());
        let hmac_token = format!(
            "Bearer {}",
            encode(
                &hmac,
                &claims(),
                &EncodingKey::from_secret(PUBLIC_FIXTURE.as_bytes())
            )
            .unwrap()
        );
        assert!(verifier.verify_bearer_at(Some(&hmac_token), NOW).is_err());
        for field in 0..3 {
            let mut changed = header();
            match field {
                0 => changed.jku = Some("https://attacker.invalid/jwks".into()),
                1 => changed.x5u = Some("https://attacker.invalid/key".into()),
                _ => changed.crit = Some(vec!["unsupported".into()]),
            }
            assert!(
                verifier
                    .verify_bearer_at(Some(&signed_with_header(&claims(), &changed)), NOW)
                    .is_err()
            );
        }
        let mut tampered = signed(&claims()).into_bytes();
        let index = tampered.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        assert!(
            verifier
                .verify_bearer_at(Some(std::str::from_utf8(&tampered).unwrap()), NOW)
                .is_err()
        );
        // kid is never an authority source or remote lookup instruction.
        let mut informational = header();
        informational.kid = Some("another-informational-id".into());
        verifier
            .verify_bearer_at(Some(&signed_with_header(&claims(), &informational)), NOW)
            .unwrap();
    }

    #[test]
    fn duplicate_or_missing_signed_claims_are_not_accepted() {
        let verifier = AuthVerifier::new(config()).unwrap();
        for field in [
            "iss",
            "aud",
            "sub",
            "client_id",
            "tenant_id",
            "scope",
            "jti",
            "iat",
            "exp",
        ] {
            let mut missing = claims();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                verifier
                    .verify_bearer_at(Some(&signed(&missing)), NOW)
                    .is_err(),
                "accepted missing {field}"
            );
        }
        let payload = serde_json::to_string(&claims()).unwrap();
        let duplicate_aud = format!(
            "{{\"aud\":\"https://metrics.example/mcp\",{}",
            &payload[1..]
        );
        assert!(
            verifier
                .verify_bearer_at(
                    Some(&raw_signed(
                        r#"{"typ":"at+jwt","alg":"RS256"}"#,
                        &duplicate_aud
                    )),
                    NOW
                )
                .is_err()
        );
        let duplicate_header = r#"{"typ":"JWT","typ":"at+jwt","alg":"RS256"}"#;
        assert!(
            verifier
                .verify_bearer_at(Some(&raw_signed(duplicate_header, &payload)), NOW)
                .is_err()
        );
    }

    #[test]
    fn expiry_issued_time_not_before_and_max_lifetime_have_exact_bounds() {
        let verifier = AuthVerifier::new(config()).unwrap();
        let access = verifier
            .verify_bearer_at(Some(&signed(&claims())), NOW)
            .unwrap();
        verifier.check_access_at(&access, NOW + 599).unwrap();
        assert_eq!(
            verifier.check_access_at(&access, NOW + 600),
            Err(AuthError::InvalidToken)
        );
        for (field, value) in [
            ("iat", NOW + 1),
            ("iat", -1),
            ("exp", NOW),
            ("exp", NOW + 901),
            ("nbf", NOW + 1),
            ("nbf", NOW + 600),
            ("nbf", -1),
        ] {
            let mut changed = claims();
            changed[field] = json!(value);
            assert!(
                verifier
                    .verify_bearer_at(Some(&signed(&changed)), NOW)
                    .is_err(),
                "accepted invalid {field}={value}"
            );
        }
        let mut config = config();
        config.clock_skew_secs = 2;
        let verifier = AuthVerifier::new(config).unwrap();
        let mut skewed = claims();
        skewed["iat"] = json!(NOW + 2);
        skewed["nbf"] = json!(NOW + 2);
        verifier
            .verify_bearer_at(Some(&signed(&skewed)), NOW)
            .unwrap();
        // Tolerance never extends an expired stream or request.
        assert_eq!(
            verifier
                .verify_bearer_at(Some(&signed(&claims())), NOW + 600)
                .unwrap_err(),
            AuthError::InvalidToken
        );
    }

    #[test]
    fn revocation_stops_existing_stream_access_and_new_requests() {
        let verifier = AuthVerifier::new(config()).unwrap();
        let token = signed(&claims());
        let access = verifier.verify_bearer_at(Some(&token), NOW).unwrap();
        verifier.check_access_at(&access, NOW + 1).unwrap();
        verifier.revoke_jti(access.jti()).unwrap();
        assert_eq!(
            verifier.check_access_at(&access, NOW + 1),
            Err(AuthError::Revoked)
        );
        assert_eq!(
            verifier
                .verify_bearer_at(Some(&token), NOW + 1)
                .unwrap_err(),
            AuthError::Revoked
        );
        let mut persisted = config();
        persisted.revoked_jtis.insert(access.jti().into());
        assert_eq!(
            AuthVerifier::new(persisted)
                .unwrap()
                .verify_bearer_at(Some(&token), NOW + 1)
                .unwrap_err(),
            AuthError::Revoked
        );
        let mut another = claims();
        another["jti"] = "fixture-token-02".into();
        verifier
            .verify_bearer_at(Some(&signed(&another)), NOW + 1)
            .unwrap();
    }

    #[test]
    fn malformed_authorization_headers_and_oversized_tokens_fail_closed() {
        let verifier = AuthVerifier::new(config()).unwrap();
        for value in [
            None,
            Some(""),
            Some("Basic abc"),
            Some("Bearer"),
            Some("Bearer "),
            Some("Bearer a.b.c"),
            Some("Bearer  a.b.c"),
            Some("Bearer a.b.c\n"),
            Some("Bearer a.b.c, Bearer d.e.f"),
        ] {
            assert!(verifier.verify_bearer_at(value, NOW).is_err());
        }
        assert!(
            verifier
                .verify_bearer_at(
                    Some(&format!("Bearer {}", "a".repeat(MAX_TOKEN_BYTES + 1))),
                    NOW
                )
                .is_err()
        );
        let valid = signed(&claims()).replacen("Bearer", "bEaReR", 1);
        verifier.verify_bearer_at(Some(&valid), NOW).unwrap();
        assert_eq!(AuthError::InvalidToken.http_status_code(), 401);
        assert_eq!(AuthError::InsufficientScope.http_status_code(), 403);
    }

    #[test]
    fn configuration_requires_one_tenant_explicit_scopes_and_public_pinned_key() {
        for case in 0..8 {
            let mut changed = config();
            match case {
                0 => changed.public_key_pem = PRIVATE_FIXTURE.into(),
                1 => changed.issuer = "http://issuer.example".into(),
                2 => changed.resource_audience = "https://metrics.example/mcp?tenant=other".into(),
                3 => changed.max_token_ttl_secs = 901,
                4 => changed.clock_skew_secs = 31,
                5 => {
                    changed.admissions[0].scopes.insert("metrics:*".into());
                }
                6 => changed.admissions.push(changed.admissions[0].clone()),
                _ => {
                    let mut other = changed.admissions[0].clone();
                    other.tenant_id = TenantId::parse("customer-b").unwrap();
                    changed.admissions.push(other);
                }
            }
            assert!(
                AuthVerifier::new(changed).is_err(),
                "accepted invalid config {case}"
            );
        }
        let mut fixture = config();
        fixture.issuer = "http://127.0.0.1:18080".into();
        assert!(AuthVerifier::new(fixture.clone()).is_err());
        fixture.allow_loopback_http = true;
        AuthVerifier::new(fixture).unwrap();
    }
}
