//! The broker owns resource authorization and the identity store. This narrow
//! endpoint accepts only original OAuth tokens for checks or self-revocation.
//!
//! `identity/` (`opaqued::identity::IdentityRuntime`) stays in the `opaqued`
//! binary crate — it is not part of this extraction, and it never will be
//! nameable from another crate. This file's only dependency on it is
//! [`IdentityAuthority`], a narrow trait covering exactly the
//! `IdentityRuntime` operations `ResourceAuthority` calls (principal lookup,
//! provisioning-scope authorization, resource-token revocation bookkeeping,
//! and identity-lifecycle audit emission). `opaqued` implements it for its
//! real `IdentityRuntime` — the same "narrow trait defined by the crate that
//! needs it, foreign crate implements it" direction as
//! `crate::task_facade::BoundedWorkFacade`.
use opaque_core::{
    identity::{Principal, PrincipalId, Role},
    resource_auth::{
        AuthConfig, AuthError, AuthVerifier, METRIC_SCOPES, ResourceAccess, ResourceEnvelope,
        ResourceRequest, ResourceResponse,
    },
    tenant::TenantBinding,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

/// The `IdentityRuntime` surface `ResourceAuthority` needs. See the module
/// doc for why this is a trait rather than a direct dependency.
pub trait IdentityAuthority: Send + Sync {
    /// `IdentityConfig.issuer` (`ResourceAuthority::new` requires this to
    /// match `ResourceAuthorityConfig.auth.issuer` exactly).
    fn config_issuer(&self) -> &str;
    /// `IdentityConfig.required`.
    fn config_required(&self) -> bool;
    /// `IdentityConfig.persona.max_age_secs`, when `[identity.persona]` is
    /// configured.
    fn persona_max_age_secs(&self) -> Option<u64>;
    /// Mirrors `IdentityRuntime::principal_permitted`.
    fn principal_permitted(&self, principal: &Principal) -> bool;
    /// Mirrors `IdentityStore::get_human_by_subject`.
    fn get_human_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<Principal>, String>;
    /// Mirrors `IdentityStore::resource_token_revoked`.
    fn resource_token_revoked(&self, issuer: &str, audience: &str, jti: &str)
    -> Result<bool, String>;
    /// Mirrors `IdentityStore::revoke_resource_token`.
    fn revoke_resource_token(
        &self,
        issuer: &str,
        audience: &str,
        jti: &str,
        expires_at: i64,
    ) -> Result<(), String>;
    /// Mirrors `IdentityStore::authorize_scopes`, minus its
    /// `permitted: impl Fn(&Principal) -> bool` parameter — every real
    /// caller passes `principal_permitted` for that, so implementations
    /// supply it internally instead of requiring this trait to plumb a
    /// non-object-safe generic closure through.
    fn authorize_scopes(
        &self,
        binding: &TenantBinding,
        recipient: &PrincipalId,
        now: i64,
        persona_max_age_secs: u64,
    ) -> Result<BTreeSet<String>, String>;
    /// Mirrors `IdentityRuntime::emit_audit`.
    fn emit_audit(&self, event: opaque_core::audit::AuditEvent);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAuthorityConfig {
    pub socket_path: PathBuf,
    /// Provision this dedicated random 32-byte key to the gateway via custody.
    /// Never point at the broad daemon token or an identity signing key.
    pub credential_file: PathBuf,
    pub allowed_gateway_uids: BTreeSet<u32>,
    pub binding: TenantBinding,
    pub auth: AuthConfig,
    /// Every token scope must be covered by a currently held broker role.
    pub role_scopes: BTreeMap<Role, BTreeSet<String>>,
    #[serde(default)]
    pub fixture_mode: bool,
}

pub struct ResourceAuthority {
    config: ResourceAuthorityConfig,
    verifier: AuthVerifier,
    identity: Arc<dyn IdentityAuthority>,
    key: zeroize::Zeroizing<Vec<u8>>,
    /// Whether `[provisioning]` is configured. Only ever checked for
    /// presence (`.is_some()` on the old `Option<ProvisioningConfig>`
    /// field), never for its contents, so a plain `bool` carries the same
    /// information without needing to name the concrete, `opaqued`-local
    /// `ProvisioningConfig` type.
    provisioning_enabled: bool,
}
impl ResourceAuthority {
    pub fn new(
        config: ResourceAuthorityConfig,
        identity: Arc<dyn IdentityAuthority>,
        tenant: Option<&TenantBinding>,
        provisioning_enabled: bool,
    ) -> Result<Arc<Self>, String> {
        config.binding.validate().map_err(|e| e.to_string())?;
        if !identity.config_required() || identity.config_issuer() != config.auth.issuer {
            return Err(
                "resource authority requires the same required broker identity issuer".into(),
            );
        }
        if config.fixture_mode {
            if std::env::var("OPAQUE_RESOURCE_AUTHORITY_FIXTURE").as_deref() != Ok("1") {
                return Err("resource fixture requires OPAQUE_RESOURCE_AUTHORITY_FIXTURE=1".into());
            }
        } else {
            // A production gateway cannot share broker custody through its UID.
            if config
                .allowed_gateway_uids
                .iter()
                .any(|uid| *uid == 0 || *uid == unsafe { libc::geteuid() })
            {
                return Err("production gateways require a separate unprivileged UID".into());
            }
            tenant
                .ok_or("resource authority requires isolated tenant custody")?
                .require_same(&config.binding)
                .map_err(|e| e.to_string())?;
            if config.auth.allow_loopback_http {
                return Err("production resource authority requires HTTPS".into());
            }
        }
        if let Some(tenant) = tenant {
            tenant
                .require_same(&config.binding)
                .map_err(|e| e.to_string())?;
        }
        if config
            .auth
            .admissions
            .iter()
            .any(|a| a.tenant_id != config.binding.tenant_id)
            || config.allowed_gateway_uids.is_empty()
            || config.allowed_gateway_uids.len() > 16
            || config.role_scopes.is_empty()
            || config.role_scopes.values().any(|scopes| {
                scopes.is_empty()
                    || scopes
                        .iter()
                        .any(|scope| !METRIC_SCOPES.contains(&scope.as_str()))
            })
            || !config.socket_path.is_absolute()
            || !config.credential_file.is_absolute()
            || config.socket_path == config.credential_file
        {
            return Err("invalid resource tenant, socket, gateways or exact role scopes".into());
        }
        let verifier = AuthVerifier::new(config.auth.clone()).map_err(|e| e.to_string())?;
        let mut key_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&config.credential_file)
            .map_err(|_| "resource credential unavailable")?;
        let metadata = key_file
            .metadata()
            .map_err(|_| "resource credential unavailable")?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o027 != 0
            || metadata.len() != 32
        {
            return Err(
                "resource credential must be a broker-owned private 32-byte file (0600 or 0640)"
                    .into(),
            );
        }
        let mut key = zeroize::Zeroizing::new(vec![0; 32]);
        std::io::Read::read_exact(&mut key_file, &mut key)
            .map_err(|_| "resource credential unavailable")?;
        Ok(Arc::new(Self {
            config,
            verifier,
            identity,
            key,
            provisioning_enabled,
        }))
    }

    /// Build a `ResourceAuthority` directly from already-validated parts,
    /// bypassing `new()`'s production validation (file-based key loading,
    /// gateway-UID isolation, HTTPS enforcement). `ResourceAuthority`'s
    /// fields are otherwise private, which is normally fine — but
    /// `opaqued`'s cross-crate `resource_authority_provisioning_tests`
    /// needs to build a fixture instance directly (synthetic all-zero key,
    /// no file I/O, no production gateway restrictions) the way this
    /// module's own former inline test did before the `opaque-bounded-work`
    /// extraction moved that test to a different crate. Test-only in
    /// practice, but not `#[cfg(test)]`-gated: `opaqued`'s test build is a
    /// *different* crate's test build, and `#[cfg(test)]` on a dependency
    /// item is never visible there.
    pub fn from_parts(
        config: ResourceAuthorityConfig,
        identity: Arc<dyn IdentityAuthority>,
        key: zeroize::Zeroizing<Vec<u8>>,
        provisioning_enabled: bool,
    ) -> Result<Self, String> {
        let verifier = AuthVerifier::new(config.auth.clone()).map_err(|e| e.to_string())?;
        Ok(Self {
            config,
            verifier,
            identity,
            key,
            provisioning_enabled,
        })
    }

    /// The tenant binding this authority enforces. `pub` for the same
    /// cross-crate-test reason as [`Self::from_parts`]/[`Self::authorize`]:
    /// `opaqued`'s `resource_authority_provisioning_tests` builds
    /// `ResourceRequest`s against it directly.
    pub fn binding(&self) -> &TenantBinding {
        &self.config.binding
    }

    /// Authorize (or self-revoke) one resource-gateway bearer token.
    ///
    /// `pub` (rather than its pre-move private visibility) for the same
    /// reason as [`Self::from_parts`]: `opaqued`'s
    /// `resource_authority_provisioning_tests` calls this directly to drive
    /// the authorization decision without speaking the length-prefixed wire
    /// protocol `connection()` implements over a `UnixStream`.
    pub fn authorize(&self, request: &ResourceRequest) -> Result<ResourceAccess, AuthError> {
        self.config
            .binding
            .require_same(&request.binding)
            .map_err(|_| AuthError::NotAdmitted)?;
        if request.issuer != self.verifier.issuer()
            || request.audience != self.verifier.resource_audience()
        {
            return Err(AuthError::NotAdmitted);
        }
        if request.revoke {
            // Self-denial needs cryptographic token identity, not permission to
            // keep using it. Do this before live principal/role checks so an
            // administrator restoring membership cannot undo a user's logout.
            let token = self
                .verifier
                .revocable_bearer(Some(&request.authorization))?;
            self.identity
                .revoke_resource_token(
                    self.verifier.issuer(),
                    self.verifier.resource_audience(),
                    &token.jti,
                    token.expires_at,
                )
                .map_err(|_| AuthError::Unavailable)?;
            return Ok(token);
        }
        // Reverify original signature/issuer/audience/client/admission/expiry.
        let access = self.verifier.verify_bearer(Some(&request.authorization))?;
        let principal = self
            .identity
            .get_human_by_subject(self.verifier.issuer(), access.subject())
            .map_err(|_| AuthError::Unavailable)?
            .ok_or(AuthError::NotAdmitted)?;
        if !self.identity.principal_permitted(&principal) {
            return Err(AuthError::NotAdmitted);
        }
        let scopes: BTreeSet<_> = if self.provisioning_enabled && !principal.has_role(Role::Admin) {
            let max_age = self
                .identity
                .persona_max_age_secs()
                .ok_or(AuthError::Unavailable)?;
            self.identity
                .authorize_scopes(
                    &self.config.binding,
                    &principal.id,
                    opaque_core::identity::now_unix(),
                    max_age,
                )
                .map_err(|_| AuthError::NotAdmitted)?
        } else {
            principal
                .roles
                .iter()
                .filter_map(|role| self.config.role_scopes.get(role))
                .flatten()
                .cloned()
                .collect()
        };
        if !access.scopes().is_subset(&scopes) {
            return Err(AuthError::InsufficientScope);
        }
        if self
            .identity
            .resource_token_revoked(
                self.verifier.issuer(),
                self.verifier.resource_audience(),
                access.jti(),
            )
            .map_err(|_| AuthError::Unavailable)?
        {
            return Err(AuthError::Revoked);
        }
        Ok(ResourceAccess::from(&access))
    }

    /// Bind before daemon readiness so bad custody/configuration fails startup.
    /// An existing socket is never removed implicitly: an operator must retire
    /// an old listener, preventing this process from replacing a running broker.
    pub fn bind(&self) -> std::io::Result<UnixListener> {
        let parent = self
            .config
            .socket_path
            .parent()
            .ok_or_else(|| std::io::Error::other("invalid resource socket path"))?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(std::io::Error::other(
                "resource socket requires a broker-owned directory without group/other writes",
            ));
        }
        let listener = UnixListener::bind(&self.config.socket_path)?;
        std::fs::set_permissions(
            &self.config.socket_path,
            std::fs::Permissions::from_mode(0o660),
        )?;
        Ok(listener)
    }
    pub async fn serve(
        self: Arc<Self>,
        listener: UnixListener,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let capacity = Arc::new(tokio::sync::Semaphore::new(32));
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                result = listener.accept() => {
                    let Ok((stream, _)) = result else { break; };
                    let Ok(peer) = opaque_core::peer::peer_info_from_fd(stream.as_raw_fd()) else { continue; };
                    if !self.config.allowed_gateway_uids.contains(&peer.uid) { continue; }
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                    let this = self.clone();
                    tokio::spawn(async move { let _permit = permit; let _ = tokio::time::timeout(std::time::Duration::from_secs(2), this.connection(stream)).await; });
                }
            }
        }
        // This listener exclusively created the path and kept it open.
        let _ = std::fs::remove_file(&self.config.socket_path);
    }
    async fn connection(&self, mut stream: tokio::net::UnixStream) -> std::io::Result<()> {
        let length = stream.read_u32().await? as usize;
        if length > 32 * 1024 {
            return Ok(());
        }
        let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
        stream.read_exact(&mut bytes).await?;
        let envelope: ResourceEnvelope = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let result = envelope
            .authenticate(&self.key)
            .and_then(|_| self.authorize(&envelope.request));
        use opaque_core::audit::{AuditEvent, AuditEventKind};
        self.identity.emit_audit(
            AuditEvent::new(if result.is_ok() {
                AuditEventKind::OperationSucceeded
            } else {
                AuditEventKind::PolicyDenied
            })
            .with_operation(if envelope.request.revoke {
                "resource.token.revoke"
            } else {
                "resource.token.check"
            })
            .with_outcome(if result.is_ok() { "allowed" } else { "denied" })
            .with_detail(format!(
                "tenant={} broker={}",
                self.config.binding.tenant_id, self.config.binding.broker_id
            )),
        );
        let response = match result {
            Ok(access) => ResourceResponse {
                binding: self.config.binding.clone(),
                access: Some(access),
                error: None,
            },
            Err(error) => ResourceResponse::denied(self.config.binding.clone(), error),
        };
        let bytes = serde_json::to_vec(&response)?;
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        Ok(())
    }
}
