//! Phase 1 identity substrate — daemon side.
//!
//! Wires the core principal model (`opaque_core::identity`) into the daemon:
//! a persistent identity store (SQLite), an Ed25519 delegation signing key,
//! a hand-rolled OIDC relying party (discovery + PKCE + JWKS verification),
//! and the browser-login attempt lifecycle.
//!
//! Trust model reminder: agents drive the same CLI binary humans use, so
//! nothing a client process sends is proof of humanity. The proof of a human
//! is the browser/IdP authentication step — the authorization code lands on a
//! daemon-owned loopback listener and is exchanged and verified entirely
//! inside the daemon. The CLI only ever sees an authorization URL to display
//! and an attempt id to poll.

pub mod keys;
pub mod login;
pub mod oidc;
pub mod store;

use std::path::Path;
use std::sync::Arc;

use opaque_core::identity::{Role, roles_from_string};
use serde::Deserialize;
use tracing::{info, warn};

use login::LoginAttempts;
use oidc::OidcClient;
use store::IdentityStore;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `[identity]` section of the daemon config.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// OIDC issuer URL (https, or loopback http for tests).
    pub issuer: String,

    /// OAuth client id registered at the IdP (public client, PKCE).
    pub client_id: String,

    /// Expected `aud` of ID tokens. Defaults to `client_id`.
    #[serde(default)]
    pub audience: Option<String>,

    /// Fixed loopback redirect port. Defaults to an ephemeral port
    /// (RFC 8252 §7.3); set this if the IdP requires an exact redirect URI.
    #[serde(default)]
    pub redirect_port: Option<u16>,

    /// Human login session TTL in seconds (default 12h, clamped 5m..=7d).
    #[serde(default)]
    pub session_ttl_secs: Option<u64>,

    /// When non-empty, only emails under these domains may log in.
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,

    /// When true, agent operations will require a valid delegation bound to
    /// an authenticated principal (enforced from Stage C onward).
    #[serde(default)]
    pub required: bool,

    /// Config-declared service principals for autonomous operation.
    #[serde(default)]
    pub service_principals: Vec<ServicePrincipalConfig>,
}

/// One config-declared service principal.
#[derive(Debug, Clone, Deserialize)]
pub struct ServicePrincipalConfig {
    /// Service name (charset-limited; see `opaque_core::identity`).
    pub name: String,
    /// Roles granted to the service principal (e.g. `["operator"]`).
    #[serde(default)]
    pub roles: Vec<String>,
}

impl IdentityConfig {
    /// Expected audience for ID tokens.
    pub fn audience(&self) -> &str {
        self.audience.as_deref().unwrap_or(&self.client_id)
    }

    /// Human session TTL, defaulted and clamped.
    pub fn session_ttl_secs(&self) -> u64 {
        self.session_ttl_secs.unwrap_or(43_200).clamp(300, 604_800)
    }

    /// Validate semantic invariants (issuer shape, client id present).
    pub fn validate(&self) -> Result<(), String> {
        // Reuse the core issuer rules by validating a synthetic human kind.
        let probe = opaque_core::identity::PrincipalKind::Human {
            iss: self.issuer.clone(),
            sub: "probe".into(),
            email: None,
            name: None,
        };
        probe
            .validate()
            .map_err(|e| format!("invalid [identity] issuer: {e}"))?;
        if self.issuer.ends_with('/') {
            return Err("invalid [identity] issuer: must not end with '/'".into());
        }
        if self.client_id.trim().is_empty() {
            return Err("invalid [identity] client_id: empty".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

/// Live identity state hung off `DaemonState` when `[identity]` is configured.
pub struct IdentityRuntime {
    pub config: IdentityConfig,
    pub store: IdentityStore,
    /// Delegation-token signing key.
    pub signing: ed25519_dalek::SigningKey,
    /// Shared HTTP client for IdP traffic.
    pub http: reqwest::Client,
    /// Cached OIDC discovery + JWKS state (populated on first login).
    pub(crate) oidc: tokio::sync::Mutex<Option<Arc<OidcClient>>>,
    /// Pending browser-login attempts.
    pub(crate) attempts: LoginAttempts,
}

impl IdentityRuntime {
    /// Initialize the identity runtime: validate config, open the store,
    /// load or create the signing key, and upsert config-declared service
    /// principals. `state_dir` is `~/.opaque` (the audit.db directory).
    pub fn initialize(config: IdentityConfig, state_dir: &Path) -> Result<Self, String> {
        config.validate()?;

        let store = IdentityStore::open(&state_dir.join("identity.db"))
            .map_err(|e| format!("failed to open identity store: {e}"))?;
        let signing = keys::load_or_create_signing_key(&state_dir.join("identity.key"))
            .map_err(|e| format!("failed to load identity signing key: {e}"))?;

        // Upsert service principals from config. Invalid entries are skipped
        // with a warning — a config typo must not take the daemon down.
        for sp in &config.service_principals {
            let roles = match roles_from_string(&sp.roles.join(",")) {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        "skipping service principal '{}': invalid roles: {e}",
                        sp.name
                    );
                    continue;
                }
            };
            match store.upsert_service(&sp.name) {
                Ok(principal) => {
                    if let Err(e) = store.set_roles(&principal.id, &roles) {
                        warn!("failed to set roles for service '{}': {e}", sp.name);
                    }
                }
                Err(e) => warn!("skipping service principal '{}': {e}", sp.name),
            }
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("failed to build http client: {e}"))?;

        info!(
            "identity runtime initialized (issuer: {}, {} service principals, required: {})",
            config.issuer,
            config.service_principals.len(),
            config.required,
        );

        Ok(Self {
            config,
            store,
            signing,
            http,
            oidc: tokio::sync::Mutex::new(None),
            attempts: LoginAttempts::default(),
        })
    }

    /// Discovery, cached after the first successful fetch.
    pub(crate) async fn oidc_client(&self) -> Result<Arc<OidcClient>, String> {
        let mut guard = self.oidc.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        let client = OidcClient::discover(
            &self.config.issuer,
            self.config.client_id.clone(),
            self.config.audience().to_owned(),
            self.http.clone(),
        )
        .await?;
        let client = Arc::new(client);
        *guard = Some(client.clone());
        Ok(client)
    }

    /// The `identity` object for `whoami` / `identity.login_status` payloads:
    /// the current (latest active) human session, or `None` when logged out.
    pub fn current_identity_json(&self) -> Option<serde_json::Value> {
        let session = self.store.current_human_session().ok().flatten()?;
        let principal = self
            .store
            .get_principal(&session.principal_id)
            .ok()
            .flatten()?;
        Some(serde_json::json!({
            "principal_id": principal.id.as_str(),
            "label": principal.display_label(),
            "email": match &principal.kind {
                opaque_core::identity::PrincipalKind::Human { email, .. } => email.clone(),
                _ => None,
            },
            "roles": principal.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "session_id": session.id,
            "session_expires_at_utc_ms": session.expires_at * 1000,
            "issuer": session.idp_issuer,
        }))
    }

    /// The principal behind the current active human session, if any.
    pub fn current_human_principal(&self) -> Option<opaque_core::identity::Principal> {
        let session = self.store.current_human_session().ok().flatten()?;
        self.store
            .get_principal(&session.principal_id)
            .ok()
            .flatten()
    }

    /// True when the current human session's principal holds `role`.
    pub fn current_human_has_role(&self, role: Role) -> bool {
        self.current_human_principal()
            .is_some_and(|p| !p.disabled && p.has_role(role))
    }
}
