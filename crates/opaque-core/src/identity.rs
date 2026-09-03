//! Phase 1 identity substrate: principals, roles, and delegation tokens.
//!
//! Introduces a real principal model on top of the Phase 0 enclave:
//!
//! - **Human** principals are established by OIDC login (issuer + subject
//!   from a verified ID token). The browser/IdP step is the proof — nothing
//!   a local client process claims about itself is trusted, because agents
//!   drive the same CLI binary.
//! - **Agent** principals are workload identities (the tool acting on
//!   someone's behalf), never authority-bearing on their own.
//! - **Service** principals are config-declared identities for autonomous
//!   (no-human) operation, opted into by policy.
//!
//! Delegation is expressed as a daemon-signed token binding an agent (`act`)
//! to the principal it works on behalf of (`sub`) — RFC 8693-shaped claims
//! over an Ed25519 signature. Roles are resolved from the identity store at
//! verification time, not frozen into the token, so revocation and role edits
//! take effect immediately.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from principal construction and validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IdentityError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} too long: {actual} chars (max {max})")]
    TooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    #[error("{field} contains invalid characters")]
    InvalidCharset { field: &'static str },
    #[error("issuer must be an https:// URL (or http://localhost for tests)")]
    InvalidIssuer,
    #[error("invalid principal id: {0:?}")]
    InvalidPrincipalId(String),
    #[error("unknown role: {0:?}")]
    UnknownRole(String),
    #[error("unknown access mode: {0:?}")]
    UnknownAccessMode(String),
}

/// Errors from delegation-token encoding and verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported token version")]
    UnsupportedVersion,
    #[error("signature verification failed")]
    BadSignature,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("token claims invalid: {0}")]
    InvalidClaims(String),
}

// ---------------------------------------------------------------------------
// Principal id
// ---------------------------------------------------------------------------

/// Stable, opaque principal identifier: `hum_`/`agt_`/`svc_` + 32 hex chars.
///
/// Assigned by the identity store the first time a principal is seen and
/// never reused. Human principals are additionally unique on `(iss, sub)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Generate a fresh id for the given principal kind.
    pub fn generate(kind: &PrincipalKind) -> Self {
        let prefix = match kind {
            PrincipalKind::Human { .. } => "hum",
            PrincipalKind::Agent { .. } => "agt",
            PrincipalKind::Service { .. } => "svc",
        };
        Self(format!("{prefix}_{}", uuid::Uuid::new_v4().simple()))
    }

    /// Parse and validate an id in `hum_|agt_|svc_ + 32 lowercase hex` form.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let valid = s.split_once('_').is_some_and(|(prefix, rest)| {
            matches!(prefix, "hum" | "agt" | "svc")
                && rest.len() == 32
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        });
        if valid {
            Ok(Self(s.to_string()))
        } else {
            Err(IdentityError::InvalidPrincipalId(s.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if this id names a human principal.
    pub fn is_human(&self) -> bool {
        self.0.starts_with("hum_")
    }

    /// True if this id names a service principal.
    pub fn is_service(&self) -> bool {
        self.0.starts_with("svc_")
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = IdentityError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<PrincipalId> for String {
    fn from(id: PrincipalId) -> String {
        id.0
    }
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// Coarse-grained roles a principal can hold, beyond the Human/Agent
/// client-type distinction (which is audit-only, never a security gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Manage identity: assign roles, register service principals, logout others.
    Admin,
    /// May confirm out-of-band approvals.
    Approver,
    /// May run operations (the default working role).
    Operator,
    /// Read-only access to audit and configuration.
    Auditor,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::Admin, Role::Approver, Role::Operator, Role::Auditor];

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Approver => "approver",
            Role::Operator => "operator",
            Role::Auditor => "auditor",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = IdentityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "approver" => Ok(Role::Approver),
            "operator" => Ok(Role::Operator),
            "auditor" => Ok(Role::Auditor),
            other => Err(IdentityError::UnknownRole(other.to_string())),
        }
    }
}

/// Render a role set as a stable, comma-separated string (storage/display).
pub fn roles_to_string(roles: &BTreeSet<Role>) -> String {
    roles.iter().map(Role::as_str).collect::<Vec<_>>().join(",")
}

/// Parse a comma-separated role list; whitespace-tolerant, rejects unknowns.
pub fn roles_from_string(s: &str) -> Result<BTreeSet<Role>, IdentityError> {
    let mut roles = BTreeSet::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        roles.insert(part.parse::<Role>()?);
    }
    Ok(roles)
}

// ---------------------------------------------------------------------------
// Access modes
// ---------------------------------------------------------------------------

/// The three enterprise access modes for agent operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Agent acts on behalf of an authenticated human; effective permission
    /// is the intersection of what the agent session and the human may do,
    /// and out-of-band approval remains required.
    Delegated,
    /// Agent acts as a config-declared service principal with no human in
    /// the loop; must be opted into by policy.
    Autonomous,
    /// Step-up emergency access: requires an approver distinct from the
    /// delegating human (segregation of duties).
    BreakGlass,
}

impl AccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessMode::Delegated => "delegated",
            AccessMode::Autonomous => "autonomous",
            AccessMode::BreakGlass => "break_glass",
        }
    }
}

impl fmt::Display for AccessMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AccessMode {
    type Err = IdentityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "delegated" => Ok(AccessMode::Delegated),
            "autonomous" => Ok(AccessMode::Autonomous),
            "break_glass" => Ok(AccessMode::BreakGlass),
            other => Err(IdentityError::UnknownAccessMode(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

const MAX_ISS_LEN: usize = 255;
const MAX_SUB_LEN: usize = 255;
const MAX_EMAIL_LEN: usize = 254;
const MAX_NAME_LEN: usize = 128;
const MAX_TOOL_LEN: usize = 64;

/// What kind of thing a principal is, with its identifying attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A human, identified by a verified OIDC (issuer, subject) pair.
    Human {
        iss: String,
        sub: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// An agent workload (e.g. "claude-code", "codex"). Never authority-bearing.
    Agent { tool: String },
    /// A config-declared service principal for autonomous operation.
    Service { name: String },
}

impl PrincipalKind {
    /// Validate field lengths, charsets, and issuer shape.
    pub fn validate(&self) -> Result<(), IdentityError> {
        match self {
            PrincipalKind::Human {
                iss,
                sub,
                email,
                name,
            } => {
                validate_issuer(iss)?;
                validate_str("sub", sub, MAX_SUB_LEN)?;
                if let Some(email) = email {
                    validate_str("email", email, MAX_EMAIL_LEN)?;
                    if !email.contains('@') {
                        return Err(IdentityError::InvalidCharset { field: "email" });
                    }
                }
                if let Some(name) = name {
                    validate_str("name", name, MAX_NAME_LEN)?;
                }
                Ok(())
            }
            PrincipalKind::Agent { tool } => validate_token_ident("tool", tool, MAX_TOOL_LEN),
            PrincipalKind::Service { name } => validate_token_ident("name", name, MAX_TOOL_LEN),
        }
    }

    /// Short human-readable label for audit lines and UI.
    pub fn display_label(&self) -> String {
        match self {
            PrincipalKind::Human {
                email, name, sub, ..
            } => email
                .clone()
                .or_else(|| name.clone())
                .unwrap_or_else(|| sub.clone()),
            PrincipalKind::Agent { tool } => format!("agent:{tool}"),
            PrincipalKind::Service { name } => format!("service:{name}"),
        }
    }
}

/// A registered principal with its role assignments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    #[serde(flatten)]
    pub kind: PrincipalKind,
    #[serde(default)]
    pub roles: BTreeSet<Role>,
    /// Unix seconds when this principal was first registered.
    pub created_at: i64,
    /// Unix seconds when this principal last authenticated or acted.
    pub last_seen: i64,
    /// Disabled principals fail all identity checks (revocation switch).
    #[serde(default)]
    pub disabled: bool,
}

impl Principal {
    pub fn display_label(&self) -> String {
        self.kind.display_label()
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}

fn validate_str(field: &'static str, value: &str, max: usize) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { field });
    }
    if value.chars().count() > max {
        return Err(IdentityError::TooLong {
            field,
            max,
            actual: value.chars().count(),
        });
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(IdentityError::InvalidCharset { field });
    }
    Ok(())
}

fn validate_token_ident(field: &'static str, value: &str, max: usize) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { field });
    }
    if value.len() > max {
        return Err(IdentityError::TooLong {
            field,
            max,
            actual: value.len(),
        });
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(IdentityError::InvalidCharset { field });
    }
    Ok(())
}

/// Issuers must be https URLs; plain-http is tolerated only for loopback
/// (mock IdPs in tests / local development).
fn validate_issuer(iss: &str) -> Result<(), IdentityError> {
    validate_str("iss", iss, MAX_ISS_LEN)?;
    let ok = iss.starts_with("https://")
        || iss.starts_with("http://127.0.0.1")
        || iss.starts_with("http://localhost");
    if ok {
        Ok(())
    } else {
        Err(IdentityError::InvalidIssuer)
    }
}

// ---------------------------------------------------------------------------
// Delegation tokens
// ---------------------------------------------------------------------------

/// Token format version tag (also the signature domain separator).
const TOKEN_PREFIX: &str = "opqd1";
const SIG_DOMAIN: &[u8] = b"opaque-delegation-v1:";
/// Hard ceiling on encoded claim size — prevents absurd tokens.
const MAX_CLAIMS_LEN: usize = 4096;

/// Claims bound into a daemon-signed delegation token (RFC 8693-shaped).
///
/// `sub` is the principal the agent acts on behalf of: a human principal in
/// delegated / break-glass mode, a service principal in autonomous mode.
/// `act` is the acting agent workload principal. Roles are intentionally NOT
/// in the token — they are resolved from the identity store at verification
/// time so revocation is immediate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationClaims {
    /// Session id (unique per agent session; audit correlation key).
    pub jti: String,
    /// Principal the agent acts on behalf of.
    pub sub: PrincipalId,
    /// Acting agent workload principal.
    pub act: PrincipalId,
    /// Access mode this delegation was granted under.
    pub mode: AccessMode,
    /// Issued-at, unix seconds.
    pub iat: i64,
    /// Expiry, unix seconds.
    pub exp: i64,
}

impl DelegationClaims {
    fn validate(&self) -> Result<(), TokenError> {
        if self.jti.is_empty() || self.jti.len() > 128 {
            return Err(TokenError::InvalidClaims("bad jti".into()));
        }
        if self.exp <= self.iat {
            return Err(TokenError::InvalidClaims("exp <= iat".into()));
        }
        match self.mode {
            AccessMode::Autonomous => {
                if !self.sub.is_service() {
                    return Err(TokenError::InvalidClaims(
                        "autonomous delegation requires a service principal subject".into(),
                    ));
                }
            }
            AccessMode::Delegated | AccessMode::BreakGlass => {
                if !self.sub.is_human() {
                    return Err(TokenError::InvalidClaims(
                        "delegated access requires a human principal subject".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Sign delegation claims into a compact token: `opqd1.<claims>.<sig>`
/// (base64url, no padding). The signature covers a domain-separated message
/// so it can never be confused with any other Ed25519 use in the system.
pub fn sign_delegation_token(
    claims: &DelegationClaims,
    key: &SigningKey,
) -> Result<String, TokenError> {
    claims.validate()?;
    let claims_json =
        serde_json::to_vec(claims).map_err(|e| TokenError::InvalidClaims(e.to_string()))?;
    if claims_json.len() > MAX_CLAIMS_LEN {
        return Err(TokenError::InvalidClaims("claims too large".into()));
    }
    let mut msg = Vec::with_capacity(SIG_DOMAIN.len() + claims_json.len());
    msg.extend_from_slice(SIG_DOMAIN);
    msg.extend_from_slice(&claims_json);
    let sig = key.sign(&msg);
    Ok(format!(
        "{TOKEN_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(&claims_json),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    ))
}

/// Verify a delegation token's structure, signature, and time window.
///
/// Returns the verified claims. The caller must still resolve `sub`/`act`
/// against the identity store (existence, not disabled, session not revoked).
pub fn verify_delegation_token(
    token: &str,
    key: &VerifyingKey,
    now_unix: i64,
) -> Result<DelegationClaims, TokenError> {
    let mut parts = token.split('.');
    let (prefix, claims_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(p), Some(c), Some(s), None) => (p, c, s),
            _ => return Err(TokenError::Malformed),
        };
    if prefix != TOKEN_PREFIX {
        return Err(TokenError::UnsupportedVersion);
    }
    if claims_b64.len() > MAX_CLAIMS_LEN * 2 {
        return Err(TokenError::Malformed);
    }
    let claims_json = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| TokenError::Malformed)?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| TokenError::Malformed)?
        .try_into()
        .map_err(|_| TokenError::Malformed)?;

    let mut msg = Vec::with_capacity(SIG_DOMAIN.len() + claims_json.len());
    msg.extend_from_slice(SIG_DOMAIN);
    msg.extend_from_slice(&claims_json);
    key.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| TokenError::BadSignature)?;

    // Only after the signature checks out do we interpret the claims.
    let claims: DelegationClaims =
        serde_json::from_slice(&claims_json).map_err(|_| TokenError::Malformed)?;
    claims.validate()?;
    if now_unix >= claims.exp {
        return Err(TokenError::Expired);
    }
    // Small clock-skew allowance for iat.
    if now_unix + 60 < claims.iat {
        return Err(TokenError::NotYetValid);
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Principal context (attached to requests by the daemon)
// ---------------------------------------------------------------------------

/// The verified identity context the daemon attaches to an operation request
/// after validating a delegation token against the identity store.
///
/// Populated exclusively from daemon-side state — never from client-supplied
/// request fields. `sub_roles` is resolved fresh from the identity store on
/// every request (not read from the token), so role edits and revocation take
/// effect immediately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalContext {
    /// The principal the operation is performed on behalf of.
    pub sub: PrincipalId,
    /// Display label for `sub` (email for humans, `service:<name>`).
    pub sub_label: String,
    /// Roles `sub` holds, resolved from the store at request time.
    #[serde(default)]
    pub sub_roles: BTreeSet<Role>,
    /// Team namespaces `sub` belongs to under the applied federation bundle
    /// (empty when no bundle governs the daemon). Resolved daemon-side at
    /// request time, never client-supplied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_teams: Vec<String>,
    /// The acting agent workload principal.
    pub act: PrincipalId,
    /// Display label for `act` (e.g. `agent:claude-code`).
    pub act_label: String,
    /// Access mode of the delegation.
    pub mode: AccessMode,
    /// Delegation session id (audit correlation key).
    pub jti: String,
    /// The human login session this delegation is bound to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_session_id: Option<String>,
}

/// Current unix time in seconds (shared convention for identity timestamps).
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn human_kind() -> PrincipalKind {
        PrincipalKind::Human {
            iss: "https://idp.example.com".into(),
            sub: "user-123".into(),
            email: Some("dev@example.com".into()),
            name: Some("Dev Example".into()),
        }
    }

    fn claims(mode: AccessMode, sub: PrincipalId) -> DelegationClaims {
        DelegationClaims {
            jti: "sess-1".into(),
            sub,
            act: PrincipalId::generate(&PrincipalKind::Agent {
                tool: "claude-code".into(),
            }),
            mode,
            iat: 1_000,
            exp: 2_000,
        }
    }

    fn human_id() -> PrincipalId {
        PrincipalId::generate(&human_kind())
    }

    fn service_id() -> PrincipalId {
        PrincipalId::generate(&PrincipalKind::Service { name: "ci".into() })
    }

    // -- principal ids ------------------------------------------------------

    #[test]
    fn principal_id_generate_matches_kind_prefix() {
        assert!(human_id().is_human());
        assert!(service_id().is_service());
        let agt = PrincipalId::generate(&PrincipalKind::Agent {
            tool: "codex".into(),
        });
        assert!(agt.as_str().starts_with("agt_"));
    }

    #[test]
    fn principal_id_roundtrips_through_serde() {
        let id = human_id();
        let json = serde_json::to_string(&id).unwrap();
        let back: PrincipalId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn principal_id_rejects_bad_forms() {
        for bad in [
            "",
            "hum_",
            "hum_short",
            "usr_0123456789abcdef0123456789abcdef",
            "hum_0123456789ABCDEF0123456789ABCDEF",
            "hum_0123456789abcdef0123456789abcdeg",
            "hum-0123456789abcdef0123456789abcdef",
        ] {
            assert!(PrincipalId::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn principal_id_serde_rejects_invalid() {
        let err = serde_json::from_str::<PrincipalId>("\"nope\"");
        assert!(err.is_err());
    }

    // -- roles --------------------------------------------------------------

    #[test]
    fn roles_string_roundtrip_is_stable() {
        let mut roles = BTreeSet::new();
        roles.insert(Role::Operator);
        roles.insert(Role::Admin);
        let s = roles_to_string(&roles);
        assert_eq!(s, "admin,operator");
        assert_eq!(roles_from_string(&s).unwrap(), roles);
        assert_eq!(roles_from_string(" admin , operator ,").unwrap(), roles);
    }

    #[test]
    fn roles_from_string_rejects_unknown() {
        assert!(roles_from_string("admin,root").is_err());
    }

    #[test]
    fn role_serde_uses_snake_case() {
        assert_eq!(
            serde_json::to_string(&Role::Approver).unwrap(),
            "\"approver\""
        );
    }

    // -- principal validation ----------------------------------------------

    #[test]
    fn human_kind_validates() {
        human_kind().validate().unwrap();
    }

    #[test]
    fn human_kind_rejects_http_nonlocal_issuer() {
        let kind = PrincipalKind::Human {
            iss: "http://idp.example.com".into(),
            sub: "u".into(),
            email: None,
            name: None,
        };
        assert!(matches!(kind.validate(), Err(IdentityError::InvalidIssuer)));
    }

    #[test]
    fn loopback_http_issuer_allowed_for_tests() {
        let kind = PrincipalKind::Human {
            iss: "http://127.0.0.1:9999".into(),
            sub: "u".into(),
            email: None,
            name: None,
        };
        kind.validate().unwrap();
    }

    #[test]
    fn control_chars_rejected_in_name() {
        let kind = PrincipalKind::Human {
            iss: "https://idp.example.com".into(),
            sub: "u".into(),
            email: None,
            name: Some("evil\nname".into()),
        };
        assert!(kind.validate().is_err());
    }

    #[test]
    fn agent_tool_charset_enforced() {
        assert!(
            PrincipalKind::Agent {
                tool: "claude code".into()
            }
            .validate()
            .is_err()
        );
        PrincipalKind::Agent {
            tool: "claude-code".into(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn display_label_prefers_email() {
        assert_eq!(human_kind().display_label(), "dev@example.com");
        assert_eq!(
            PrincipalKind::Service { name: "ci".into() }.display_label(),
            "service:ci"
        );
    }

    #[test]
    fn principal_serde_flattens_kind() {
        let p = Principal {
            id: human_id(),
            kind: human_kind(),
            roles: BTreeSet::from([Role::Operator]),
            created_at: 1,
            last_seen: 2,
            disabled: false,
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["kind"], "human");
        assert_eq!(json["iss"], "https://idp.example.com");
        let back: Principal = serde_json::from_value(json).unwrap();
        assert_eq!(p, back);
    }

    // -- delegation tokens --------------------------------------------------

    #[test]
    fn token_roundtrip_delegated() {
        let key = test_key();
        let c = claims(AccessMode::Delegated, human_id());
        let token = sign_delegation_token(&c, &key).unwrap();
        assert!(token.starts_with("opqd1."));
        let out = verify_delegation_token(&token, &key.verifying_key(), 1_500).unwrap();
        assert_eq!(out, c);
    }

    #[test]
    fn token_roundtrip_autonomous_requires_service_sub() {
        let key = test_key();
        let ok = claims(AccessMode::Autonomous, service_id());
        let token = sign_delegation_token(&ok, &key).unwrap();
        verify_delegation_token(&token, &key.verifying_key(), 1_500).unwrap();

        let bad = claims(AccessMode::Autonomous, human_id());
        assert!(matches!(
            sign_delegation_token(&bad, &key),
            Err(TokenError::InvalidClaims(_))
        ));
    }

    #[test]
    fn delegated_mode_rejects_service_sub() {
        let key = test_key();
        let bad = claims(AccessMode::Delegated, service_id());
        assert!(sign_delegation_token(&bad, &key).is_err());
    }

    #[test]
    fn token_expiry_enforced() {
        let key = test_key();
        let token =
            sign_delegation_token(&claims(AccessMode::Delegated, human_id()), &key).unwrap();
        assert!(matches!(
            verify_delegation_token(&token, &key.verifying_key(), 2_000),
            Err(TokenError::Expired)
        ));
    }

    #[test]
    fn token_iat_future_rejected() {
        let key = test_key();
        let token =
            sign_delegation_token(&claims(AccessMode::Delegated, human_id()), &key).unwrap();
        assert!(matches!(
            verify_delegation_token(&token, &key.verifying_key(), 100),
            Err(TokenError::NotYetValid)
        ));
    }

    #[test]
    fn token_tamper_detected() {
        let key = test_key();
        let token =
            sign_delegation_token(&claims(AccessMode::Delegated, human_id()), &key).unwrap();
        // Flip a character inside the claims segment.
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        let mut claims_seg = parts[1].clone().into_bytes();
        claims_seg[4] = if claims_seg[4] == b'A' { b'B' } else { b'A' };
        parts[1] = String::from_utf8(claims_seg).unwrap();
        let tampered = parts.join(".");
        assert!(matches!(
            verify_delegation_token(&tampered, &key.verifying_key(), 1_500),
            Err(TokenError::Malformed) | Err(TokenError::BadSignature)
        ));
    }

    #[test]
    fn token_wrong_key_rejected() {
        let key = test_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let token =
            sign_delegation_token(&claims(AccessMode::Delegated, human_id()), &key).unwrap();
        assert!(matches!(
            verify_delegation_token(&token, &other.verifying_key(), 1_500),
            Err(TokenError::BadSignature)
        ));
    }

    #[test]
    fn token_malformed_shapes_rejected() {
        let key = test_key().verifying_key();
        for bad in [
            "",
            "opqd1",
            "opqd1.abc",
            "opqd2.a.b",
            "opqd1.a.b.c",
            "opqd1.!!.??",
        ] {
            assert!(
                verify_delegation_token(bad, &key, 0).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn access_mode_parse_display() {
        for mode in [
            AccessMode::Delegated,
            AccessMode::Autonomous,
            AccessMode::BreakGlass,
        ] {
            assert_eq!(mode.as_str().parse::<AccessMode>().unwrap(), mode);
        }
        assert!("root".parse::<AccessMode>().is_err());
    }
}
