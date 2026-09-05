//! The broker owns resource authorization and the identity store. This narrow
//! endpoint accepts only original OAuth tokens for checks or self-revocation.
use crate::identity::IdentityRuntime;
use opaque_core::{
    identity::Role,
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
    identity: Arc<IdentityRuntime>,
    key: zeroize::Zeroizing<Vec<u8>>,
    provisioning: Option<crate::identity::provisioning::ProvisioningConfig>,
}
impl ResourceAuthority {
    pub fn new(
        config: ResourceAuthorityConfig,
        identity: Arc<IdentityRuntime>,
        tenant: Option<&TenantBinding>,
        provisioning: Option<crate::identity::provisioning::ProvisioningConfig>,
    ) -> Result<Arc<Self>, String> {
        config.binding.validate().map_err(|e| e.to_string())?;
        if !identity.config.required || identity.config.issuer != config.auth.issuer {
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
            provisioning,
        }))
    }

    fn authorize(&self, request: &ResourceRequest) -> Result<ResourceAccess, AuthError> {
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
                .store
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
            .store
            .get_human_by_subject(self.verifier.issuer(), access.subject())
            .map_err(|_| AuthError::Unavailable)?
            .ok_or(AuthError::NotAdmitted)?;
        if !self.identity.principal_permitted(&principal) {
            return Err(AuthError::NotAdmitted);
        }
        let scopes: BTreeSet<_> = if self.provisioning.is_some() && !principal.has_role(Role::Admin)
        {
            let max_age = self
                .identity
                .config
                .persona
                .as_ref()
                .ok_or(AuthError::Unavailable)?
                .max_age_secs;
            self.identity
                .store
                .authorize_scopes(
                    &self.config.binding,
                    &principal.id,
                    opaque_core::identity::now_unix(),
                    max_age,
                    |p| self.identity.principal_permitted(p),
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
            .store
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

#[cfg(test)]
mod provisioning_tests {
    use super::*;
    use crate::identity::{
        IdentityConfig,
        persona::VerifiedPersonaClaims,
        provisioning::{AccessGrant, AccessProfile, Mandate, ProvisioningConfig},
        store::DelegationRecord,
    };
    use opaque_core::{
        identity::{AccessMode, PrincipalId, now_unix},
        resource_auth::Admission,
        tenant::TenantId,
    };
    use serde_json::json;

    const ISSUER: &str = "https://issuer.example";
    const AUDIENCE: &str = "https://metrics.example/mcp";
    // Existing, deliberately public test key; never a runtime credential.
    const PRIVATE_KEY: &str = include_str!("../tests/fixtures/test_rsa_key.pem");
    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+m4fkcL6cuTGRLTSSrF\n7zfrwFFnYRJG1yVmmCwn4q0PXhuWmUu9mo2wg9ftf9BLFspkMqyzxpdfzGTan6J9\n5w7Ad7gbP5R2aDGnVJRTX9dph3cKBgwnDsUa751mYWfr1rsTnoiMIDWzOGsRSdOi\nRzZGCYo3yo4YNB+sNIOFMQ/tc3X558HGCZl3boecDmlwt1lHebe6/+kXRTYLLpIl\nf7u1mw98TYtOenu2SIUOrJKY9VGluMxvGH9e4SExpZaG61wTNsosD20tEBkWUjCo\nxo01adXNjPYKx/mJB3NgCIWacU4NwbZxVRUg5HYR85cq+5I2oNQDwuyNDv7kZQfA\nywIDAQAB\n-----END PUBLIC KEY-----\n";

    fn provisioning() -> ProvisioningConfig {
        ProvisioningConfig {
            profiles: vec![AccessProfile {
                id: "onboarded-metrics".into(),
                revision: 1,
                eligible_group: "Engineering".into(),
                scopes: BTreeSet::from([
                    "metrics:read".into(),
                    "metrics:metric:requests_per_second".into(),
                ]),
                max_ttl_secs: 600,
                max_mandate_ttl_secs: 3600,
                max_issuances: 4,
            }],
        }
    }

    fn identity_config() -> IdentityConfig {
        serde_json::from_value(json!({
            "issuer":ISSUER,"client_id":"identity-client","required":true,
            "allowed_subjects":["admin","new-hire"],
            "persona":{"groups_claim":"groups","max_age_secs":300},
            "service_principals":[{"name":"onboarding","roles":[]}]
        }))
        .unwrap()
    }

    fn authority(identity: Arc<IdentityRuntime>, binding: TenantBinding) -> ResourceAuthority {
        let all: BTreeSet<String> = METRIC_SCOPES
            .iter()
            .map(|scope| scope.to_string())
            .collect();
        let auth = AuthConfig {
            issuer: ISSUER.into(),
            resource_audience: AUDIENCE.into(),
            public_key_pem: PUBLIC_KEY.into(),
            admissions: vec![Admission {
                tenant_id: binding.tenant_id.clone(),
                subject: "new-hire".into(),
                client_id: "metrics-client".into(),
                scopes: all.clone(),
            }],
            revoked_jtis: BTreeSet::new(),
            max_token_ttl_secs: 900,
            clock_skew_secs: 0,
            allow_loopback_http: false,
        };
        ResourceAuthority {
            verifier: AuthVerifier::new(auth.clone()).unwrap(),
            identity,
            config: ResourceAuthorityConfig {
                socket_path: PathBuf::from("/unused/resource.sock"),
                credential_file: PathBuf::from("/unused/gateway.key"),
                allowed_gateway_uids: BTreeSet::from([7382]),
                binding,
                auth,
                // Deliberately broad legacy role mapping: provisioning must
                // take precedence for this non-admin Operator.
                role_scopes: BTreeMap::from([(Role::Operator, all.clone()), (Role::Admin, all)]),
                fixture_mode: false,
            },
            key: zeroize::Zeroizing::new(vec![0; 32]),
            provisioning: Some(provisioning()),
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        authority: ResourceAuthority,
        admin: PrincipalId,
        service: PrincipalId,
        recipient: PrincipalId,
        session: String,
        delegation: String,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let rt =
                Arc::new(IdentityRuntime::initialize(identity_config(), directory.path()).unwrap());
            rt.store.sync_profiles(&provisioning()).unwrap();
            let admin = rt
                .store
                .upsert_human(ISSUER, "admin", None, None, &BTreeSet::from([Role::Admin]))
                .unwrap()
                .id;
            let recipient = rt
                .store
                .upsert_human(
                    ISSUER,
                    "new-hire",
                    None,
                    None,
                    &BTreeSet::from([Role::Operator]),
                )
                .unwrap()
                .id;
            let service = rt
                .store
                .get_service_by_name("onboarding")
                .unwrap()
                .unwrap()
                .id;
            let actor = rt.store.upsert_agent("onboarding-agent").unwrap().id;
            let now = now_unix();
            let session = rt
                .store
                .create_human_session(&admin, 3600, ISSUER)
                .unwrap()
                .id;
            let delegation = uuid::Uuid::new_v4().to_string();
            rt.store
                .record_delegation(&DelegationRecord {
                    jti: delegation.clone(),
                    sub_principal: service.clone(),
                    act_principal: actor,
                    mode: AccessMode::Autonomous,
                    human_session_id: None,
                    approved_by: Some(admin.clone()),
                    created_at: now,
                    expires_at: now + 3600,
                    revoked_at: None,
                })
                .unwrap();
            let persona = VerifiedPersonaClaims::test_claims(
                ISSUER,
                "new-hire",
                rt.config.persona.as_ref().unwrap(),
                &["Engineering"],
                now,
            );
            rt.store
                .record_persona_snapshot(&recipient, &persona, now)
                .unwrap();
            let binding = TenantBinding::new(
                TenantId::parse("engineering").unwrap(),
                uuid::Uuid::new_v4(),
            )
            .unwrap();
            Self {
                directory,
                authority: authority(rt, binding),
                admin,
                service,
                recipient,
                session,
                delegation,
            }
        }

        fn request(&self, scope: &str, jti: &str) -> ResourceRequest {
            let now = now_unix();
            let claims = json!({"iss":ISSUER,"aud":AUDIENCE,"sub":"new-hire","client_id":"metrics-client","tenant_id":"engineering","scope":scope,"jti":jti,"iat":now,"nbf":now,"exp":now+600});
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.typ = Some("at+jwt".into());
            let token = jsonwebtoken::encode(
                &header,
                &claims,
                &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
            )
            .unwrap();
            ResourceRequest {
                binding: self.authority.config.binding.clone(),
                issuer: ISSUER.into(),
                audience: AUDIENCE.into(),
                authorization: format!("Bearer {token}"),
                revoke: false,
            }
        }

        fn grant(&self) -> (Mandate, AccessGrant) {
            let rt = &self.authority.identity;
            let now = now_unix();
            let binding = &self.authority.config.binding;
            let epoch = rt
                .store
                .provisioning_profile("onboarded-metrics")
                .unwrap()
                .1;
            let parent = rt
                .store
                .create_mandate(
                    binding,
                    &self.admin,
                    &self.service,
                    "onboarded-metrics",
                    epoch,
                    rt.store.provisioning_principal_epoch(&self.admin).unwrap(),
                    &self.session,
                    now + 1800,
                    4,
                    "fixture-fido-key",
                    now,
                    |p| rt.principal_permitted(p),
                )
                .unwrap();
            let grant = rt
                .store
                .issue_access(
                    binding,
                    &parent.id,
                    &self.service,
                    &self.delegation,
                    &self.recipient,
                    &uuid::Uuid::new_v4().to_string(),
                    now + 600,
                    now,
                    300,
                    |p| rt.principal_permitted(p),
                )
                .unwrap();
            (parent, grant)
        }

        fn restart(&mut self) {
            let rt = Arc::new(
                IdentityRuntime::initialize(identity_config(), self.directory.path()).unwrap(),
            );
            rt.store.sync_profiles(&provisioning()).unwrap();
            rt.store
                .sync_provisioning_admission(|p| rt.principal_permitted(p), now_unix())
                .unwrap();
            self.authority = authority(rt, self.authority.config.binding.clone());
        }
    }

    #[test]
    fn signed_resource_tokens_need_exact_live_provisioning_scopes_despite_operator_role() {
        let f = Fixture::new();
        let request = f.request(
            "metrics:read metrics:metric:requests_per_second",
            "provisioned-read",
        );
        assert!(matches!(
            f.authority.authorize(&request),
            Err(AuthError::InsufficientScope)
        ));
        let (parent, _) = f.grant();
        assert!(f.authority.authorize(&request).is_ok());
        let broad = f.request("metrics:read metrics:explain", "outside-grant");
        assert!(matches!(
            f.authority.authorize(&broad),
            Err(AuthError::InsufficientScope)
        ));
        f.authority
            .identity
            .store
            .revoke_mandate(&f.authority.config.binding, &parent.id, now_unix())
            .unwrap();
        assert!(matches!(
            f.authority.authorize(&request),
            Err(AuthError::InsufficientScope)
        ));
    }

    #[test]
    fn access_and_token_self_revocation_remain_denied_across_restart_and_new_grants() {
        let mut f = Fixture::new();
        let (_, grant) = f.grant();
        let mut request = f.request(
            "metrics:read metrics:metric:requests_per_second",
            "revocation-survives-restart",
        );
        assert!(f.authority.authorize(&request).is_ok());
        f.authority
            .identity
            .store
            .revoke_access(&f.authority.config.binding, &grant.id, now_unix())
            .unwrap();
        assert!(f.authority.authorize(&request).is_err());
        f.restart();
        assert!(f.authority.authorize(&request).is_err());
        // A token can revoke itself while access is already withdrawn.
        request.revoke = true;
        assert!(f.authority.authorize(&request).is_ok());
        request.revoke = false;
        f.grant();
        assert!(matches!(
            f.authority.authorize(&request),
            Err(AuthError::Revoked)
        ));
        f.restart();
        assert!(matches!(
            f.authority.authorize(&request),
            Err(AuthError::Revoked)
        ));
    }
}
