//! `resource_authority.rs`'s provisioning-scope integration test, formerly
//! an inline `#[cfg(test)] mod` inside that file. Moved here (and wired via
//! `main.rs`'s `#[cfg(test)] mod resource_authority_provisioning_tests;`,
//! the exact same pattern already established by
//! `provisioning_api_tests.rs`) by the `opaque-bounded-work` extraction:
//! `ResourceAuthority` now lives in a different crate and depends on
//! `identity::IdentityRuntime` only through the narrow
//! `opaque_bounded_work::resource_authority::IdentityAuthority` trait, but
//! this test exercises the *real*, SQLite-backed provisioning/mandate/
//! revocation logic in `IdentityStore` — replacing it with a test double
//! implementing that trait would test something materially weaker than the
//! original (mandate creation, revocation, epoch/persona drift, and restart
//! persistence are exactly the behavior under test). A same-crate test with
//! real `IdentityRuntime` access is the only way to keep that.
//!
//! Two small adaptations versus the pre-move test:
//! - `ResourceAuthority::from_parts`/`::authorize`/`::binding` are new,
//!   `pub` methods `opaque-bounded-work` added to let a cross-crate test
//!   build a fixture instance and drive it directly (its own struct fields
//!   are otherwise private). See their doc comments in
//!   `opaque_bounded_work::resource_authority`.
//! - `Fixture` keeps its own `Arc<IdentityRuntime>` (`rt`) alongside the
//!   `ResourceAuthority` (`authority`) built from a trait-object clone of
//!   the *same* `Arc` — both point at the same underlying `IdentityStore`,
//!   so mutating through `rt.store` is immediately visible to `authority`,
//!   preserving the original test's exact behavior. Before this move,
//!   `ResourceAuthority.identity: Arc<IdentityRuntime>` gave direct
//!   `.store` access from `f.authority.identity`; now that field is a
//!   private `Arc<dyn IdentityAuthority>`, so bodies that need raw store
//!   access (`revoke_mandate`, `revoke_access`) go through `f.rt` instead.

use std::{collections::BTreeSet, sync::Arc};
use std::{collections::BTreeMap, path::PathBuf};

use opaque_bounded_work::resource_authority::{
    IdentityAuthority, ResourceAuthority, ResourceAuthorityConfig,
};
use opaque_core::{
    identity::{AccessMode, PrincipalId, Role, now_unix},
    resource_auth::{Admission, AuthConfig, AuthError, METRIC_SCOPES, ResourceRequest},
    tenant::{TenantBinding, TenantId},
};
use serde_json::json;

use crate::identity::{
    IdentityConfig, IdentityRuntime,
    persona::VerifiedPersonaClaims,
    provisioning::{AccessGrant, AccessProfile, Mandate, ProvisioningConfig},
    store::DelegationRecord,
};

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
    let config = ResourceAuthorityConfig {
        socket_path: PathBuf::from("/unused/resource.sock"),
        credential_file: PathBuf::from("/unused/gateway.key"),
        allowed_gateway_uids: BTreeSet::from([7382]),
        binding,
        auth,
        // Deliberately broad legacy role mapping: provisioning must
        // take precedence for this non-admin Operator.
        role_scopes: BTreeMap::from([(Role::Operator, all.clone()), (Role::Admin, all)]),
        fixture_mode: false,
    };
    ResourceAuthority::from_parts(
        config,
        identity as Arc<dyn IdentityAuthority>,
        zeroize::Zeroizing::new(vec![0; 32]),
        true,
    )
    .unwrap()
}

struct Fixture {
    directory: tempfile::TempDir,
    authority: ResourceAuthority,
    rt: Arc<IdentityRuntime>,
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
        let binding =
            TenantBinding::new(TenantId::parse("engineering").unwrap(), uuid::Uuid::new_v4())
                .unwrap();
        Self {
            directory,
            authority: authority(rt.clone(), binding),
            rt,
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
            binding: self.authority.binding().clone(),
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            authorization: format!("Bearer {token}"),
            revoke: false,
        }
    }

    fn grant(&self) -> (Mandate, AccessGrant) {
        let rt = &self.rt;
        let now = now_unix();
        let binding = self.authority.binding();
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
        let rt =
            Arc::new(IdentityRuntime::initialize(identity_config(), self.directory.path()).unwrap());
        rt.store.sync_profiles(&provisioning()).unwrap();
        rt.store
            .sync_provisioning_admission(|p| rt.principal_permitted(p), now_unix())
            .unwrap();
        self.authority = authority(rt.clone(), self.authority.binding().clone());
        self.rt = rt;
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
    f.rt
        .store
        .revoke_mandate(f.authority.binding(), &parent.id, now_unix())
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
    f.rt
        .store
        .revoke_access(f.authority.binding(), &grant.id, now_unix())
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
