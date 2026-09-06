//! Human-authorized, persona-bound provisioning. The agent proposes a named
//! profile; only the broker decides whether a durable child grant may exist.
use std::{collections::HashMap, sync::Mutex};

use opaque_core::{
    audit::AuditEventKind,
    enclave_facade::EnclaveFacade,
    identity::{
        AccessMode, Principal, PrincipalContext, PrincipalId, PrincipalKind, Role, now_unix,
    },
    operation::{ClientIdentity, ClientType},
    proto::{Request, Response},
    tenant::TenantBinding,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    DaemonConfig, DaemonState,
    identity::{IdentityRuntime, provisioning::ProvisioningConfig},
};
use opaque_approval::fido2::{Fido2Assertion, Fido2PrincipalBinding};

const CHALLENGE_TTL: i64 = 120;
const MAX_PENDING: usize = 128;

#[derive(Default)]
pub struct Challenges(Mutex<HashMap<String, Pending>>);

struct Pending {
    uid: u32,
    expires_at: i64,
    challenge: String,
    binding: Fido2PrincipalBinding,
    human_session_id: String,
    issuer_epoch: i64,
    action: PendingAction,
}

enum PendingAction {
    Bind {
        credential_id: String,
    },
    Mandate {
        service: PrincipalId,
        profile_id: String,
        profile_epoch: i64,
        expires_at: i64,
        max_issuances: u32,
    },
}

impl Challenges {
    fn insert(&self, pending: Pending) -> Result<String, String> {
        let mut entries = self.0.lock().map_err(|_| "challenge store unavailable")?;
        entries.retain(|_, p| p.expires_at > now_unix());
        if entries.len() >= MAX_PENDING {
            return Err("too many pending provisioning reviews".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        entries.insert(id.clone(), pending);
        Ok(id)
    }

    // Consume before cryptographic verification: invalid, expired and repeated
    // submissions can never reuse a human-authorized enrollment window.
    fn take(&self, id: &str, uid: u32) -> Result<Pending, String> {
        let mut entries = self.0.lock().map_err(|_| "challenge store unavailable")?;
        let pending = entries
            .get(id)
            .ok_or("unknown or consumed provisioning challenge")?;
        if pending.uid != uid {
            return Err("provisioning challenge belongs to another peer".into());
        }
        let pending = entries.remove(id).ok_or("challenge already consumed")?;
        if pending.expires_at <= now_unix() {
            return Err("provisioning challenge expired; request fresh review".into());
        }
        Ok(pending)
    }
}

/// Synchronize policy removals even when provisioning has been disabled. A
/// later configuration restore cannot revive grants from an earlier epoch.
pub fn initialize(
    config: &DaemonConfig,
    rt: Option<&IdentityRuntime>,
    binding: Option<&TenantBinding>,
) -> Result<(), String> {
    if let Some(provisioning) = &config.provisioning {
        let rt = rt.ok_or("provisioning requires broker identity")?;
        if binding.is_none()
            || !rt.config.required
            || !config.enforce_agent_sessions
            || !config.require_seal
            || !config.approval.fido2
            || rt.config.persona.is_none()
            || config.resource_authority.is_none()
            || rt.config.allowed_subjects.is_empty()
            || config.approval.session_factor
                != Some(opaque_core::operation::ApprovalFactor::PairedWorkstation)
            || config.workstation_approvers.is_empty()
        {
            return Err("provisioning requires isolated tenant custody, sealed configuration, required identity with explicit subjects and persona freshness, enforced agent sessions, FIDO2, an enrolled paired workstation selected for session review, and a resource authority".into());
        }
        provisioning.validate()?;
        if !rt
            .store
            .list_principals()?
            .iter()
            .any(|p| p.id.is_human() && p.has_role(Role::Admin) && rt.principal_permitted(p))
        {
            return Err(
                "bootstrap an admitted human administrator before enabling persona provisioning"
                    .into(),
            );
        }
    }
    if let Some(rt) = rt {
        rt.store.sync_profiles(
            config
                .provisioning
                .as_ref()
                .unwrap_or(&ProvisioningConfig { profiles: vec![] }),
        )?;
        rt.store
            .sync_provisioning_admission(|p| rt.principal_permitted(p), now_unix())?;
    }
    Ok(())
}

#[derive(Clone)]
struct Admin {
    principal: Principal,
    session_id: String,
    epoch: i64,
}

fn admin(rt: &IdentityRuntime, ctx: Option<&PrincipalContext>) -> Result<Admin, String> {
    let p = rt
        .current_human_principal()
        .filter(|p| p.has_role(Role::Admin))
        .ok_or("an active admitted human administrator login is required")?;
    if ctx.is_some_and(|c| {
        c.sub != p.id || c.mode == AccessMode::Autonomous || !c.sub_roles.contains(&Role::Admin)
    }) {
        return Err("this workload cannot use another principal's administrative session".into());
    }
    let session = rt
        .store
        .current_human_session()?
        .ok_or("human session missing")?;
    if session.principal_id != p.id {
        return Err("human session changed".into());
    }
    let max_age = rt
        .config
        .persona
        .as_ref()
        .ok_or("persona verification unavailable")?
        .max_age_secs;
    if !rt
        .store
        .persona_snapshot(&p.id)?
        .is_some_and(|snapshot| snapshot.is_fresh(now_unix(), max_age))
    {
        return Err("administrator persona is stale; complete a fresh IdP login".into());
    }
    Ok(Admin {
        epoch: rt.store.provisioning_principal_epoch(&p.id)?,
        principal: p,
        session_id: session.id,
    })
}

fn unchanged(
    rt: &IdentityRuntime,
    expected: &Admin,
    ctx: Option<&PrincipalContext>,
) -> Result<(), String> {
    let current = admin(rt, ctx)?;
    if current.principal.id != expected.principal.id
        || current.session_id != expected.session_id
        || current.epoch != expected.epoch
    {
        return Err("administrator authority changed; request a new review".into());
    }
    Ok(())
}

fn principal_binding(
    admin: &Admin,
    tenant: &TenantBinding,
) -> Result<Fido2PrincipalBinding, String> {
    let PrincipalKind::Human { iss, sub, .. } = &admin.principal.kind else {
        return Err("human identity required".into());
    };
    Ok(Fido2PrincipalBinding {
        principal_id: admin.principal.id.clone(),
        issuer: iss.clone(),
        subject: sub.clone(),
        tenant_id: tenant.tenant_id.to_string(),
        broker_id: tenant.broker_id.to_string(),
    })
}

fn parse<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, String> {
    serde_json::from_value(params).map_err(|_| "invalid provisioning parameters".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindStart {
    credential_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MandateStart {
    service: String,
    profile_id: String,
    ttl_secs: u64,
    max_issuances: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    challenge_id: String,
    assertion: Fido2Assertion,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    mandate_id: String,
    recipient_issuer: String,
    recipient_subject: String,
    ttl_secs: u64,
    request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    kind: String,
    id: String,
}

fn expiry(ttl: u64) -> Result<i64, String> {
    now_unix()
        .checked_add(i64::try_from(ttl).map_err(|_| "invalid TTL")?)
        .filter(|_| ttl > 0)
        .ok_or_else(|| "invalid TTL".into())
}

pub async fn handle(
    state: &DaemonState,
    req: Request,
    peer: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    ctx: Option<PrincipalContext>,
) -> Response {
    let method = req.method.clone();
    let result = handle_inner(
        state,
        &method,
        req.params,
        peer,
        client_type,
        session_id,
        ctx,
    )
    .await;
    let (kind, outcome, detail) = match &result {
        Ok(value) => (
            AuditEventKind::OperationSucceeded,
            "ok",
            Some(value.to_string()),
        ),
        Err(error) => (
            AuditEventKind::OperationFailed,
            "denied",
            Some(error.clone()),
        ),
    };
    // Challenges/assertions are ephemeral ceremony material, never audit them.
    let detail = if method.ends_with("_start") {
        Some("provisioning review challenge".into())
    } else {
        detail
    };
    crate::emit_daemon_method_audit(state, kind, &method, peer, client_type, outcome, detail);
    match result {
        Ok(value) => Response::ok(req.id, value),
        Err(error) => Response::err(Some(req.id), "provisioning_denied", error),
    }
}

async fn handle_inner(
    state: &DaemonState,
    method: &str,
    params: Value,
    peer: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    ctx: Option<PrincipalContext>,
) -> Result<Value, String> {
    let _config = state
        .config
        .provisioning
        .as_ref()
        .ok_or("delegated provisioning is disabled")?;
    let rt = state.identity.as_ref().ok_or("identity unavailable")?;
    let tenant = state
        .tenant
        .as_ref()
        .ok_or("tenant custody unavailable")?
        .binding();
    let fido = state.fido2.as_ref().ok_or("FIDO2 unavailable")?;
    let max_age = rt
        .config
        .persona
        .as_ref()
        .ok_or("persona freshness unavailable")?
        .max_age_secs;
    match method {
        "identity.provisioning.bind_start" | "identity.provisioning.mandate_start" => {
            let acting = admin(rt, ctx.as_ref())?;
            let binding = principal_binding(&acting, tenant)?;
            let (action, review, allowed) = if method.ends_with("bind_start") {
                let args: BindStart = parse(params)?;
                let credential = fido
                    .list_credentials()
                    .map_err(|_| "credential store unavailable")?
                    .into_iter()
                    .find(|c| c.credential_id == args.credential_id)
                    .ok_or("register the FIDO2 credential before binding it")?;
                if credential
                    .principal_binding
                    .as_ref()
                    .is_some_and(|b| b != &binding)
                {
                    return Err("credential already belongs to another identity".into());
                }
                let review = format!(
                    "Bind registered FIDO2 credential\n{}IdP issuer: {}\nIdP subject: {}\nPrincipal: {}\nCredential: {}",
                    tenant.approval_context(),
                    binding.issuer,
                    binding.subject,
                    binding.principal_id,
                    credential.credential_id
                );
                (
                    PendingAction::Bind {
                        credential_id: args.credential_id.clone(),
                    },
                    review,
                    vec![args.credential_id],
                )
            } else {
                let args: MandateStart = parse(params)?;
                let service = rt
                    .store
                    .get_service_by_name(&args.service)?
                    .filter(|p| rt.principal_permitted(p))
                    .ok_or("unknown or unadmitted provisioning service")?;
                let (profile, epoch) = rt.store.provisioning_profile(&args.profile_id)?;
                if args.ttl_secs == 0
                    || args.ttl_secs > profile.max_mandate_ttl_secs
                    || args.max_issuances == 0
                    || args.max_issuances > profile.max_issuances
                {
                    return Err("mandate exceeds profile lifetime or issuance limit".into());
                }
                let expires_at = expiry(args.ttl_secs)?;
                let allowed: Vec<_> = fido
                    .list_credentials()
                    .map_err(|_| "credential store unavailable")?
                    .into_iter()
                    .filter(|c| c.principal_binding.as_ref() == Some(&binding))
                    .map(|c| c.credential_id)
                    .collect();
                if allowed.is_empty() {
                    return Err("bind a FIDO2 credential to this administrator first".into());
                }
                let review = format!(
                    "Authorize provisioning mandate\n{}Human issuer: {}\nIdP issuer: {}\nIdP subject: {}\nService: {} ({})\nProfile: {}\nProfile revision: {} / epoch {}\nEligible IdP group: {}\nScopes: {}\nMaximum access lifetime: {} seconds\nMandate expires at Unix: {}\nCumulative issuance limit: {}\nRedelegation: forbidden",
                    tenant.approval_context(),
                    acting.principal.id,
                    binding.issuer,
                    binding.subject,
                    service.display_label(),
                    service.id,
                    profile.id,
                    profile.revision,
                    epoch,
                    profile.eligible_group,
                    profile
                        .scopes
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    profile.max_ttl_secs,
                    expires_at,
                    args.max_issuances
                );
                (
                    PendingAction::Mandate {
                        service: service.id,
                        profile_id: profile.id,
                        profile_epoch: epoch,
                        expires_at,
                        max_issuances: args.max_issuances,
                    },
                    review,
                    allowed,
                )
            };
            state
                .request_control_approval(
                    peer,
                    client_type,
                    method,
                    "Authorize scoped IdP provisioning",
                    &review,
                )
                .await
                .map_err(|_| "fresh out-of-band human approval required")?;
            if crate::resolve_principal_context(state, session_id).await? != ctx {
                return Err("workload authority changed during review".into());
            }
            unchanged(rt, &acting, ctx.as_ref())?;
            let (challenge, rp_id) = fido.binding_challenge()?;
            let expires_at = now_unix() + CHALLENGE_TTL;
            let id = state.provisioning_challenges.insert(Pending {
                uid: peer.uid,
                expires_at,
                challenge: challenge.clone(),
                binding,
                human_session_id: acting.session_id,
                issuer_epoch: acting.epoch,
                action,
            })?;
            Ok(
                json!({"challenge_id":id,"challenge":challenge,"rp_id":rp_id,"allowed_credentials":allowed,"user_verification":"required","expires_at":expires_at,"review":review}),
            )
        }
        "identity.provisioning.bind_complete" | "identity.provisioning.mandate_complete" => {
            let args: Complete = parse(params)?;
            let acting = admin(rt, ctx.as_ref())?;
            let pending = state
                .provisioning_challenges
                .take(&args.challenge_id, peer.uid)?;
            if pending.binding != principal_binding(&acting, tenant)?
                || pending.human_session_id != acting.session_id
                || pending.issuer_epoch != acting.epoch
            {
                return Err("authority changed since review; request a fresh challenge".into());
            }
            match pending.action {
                PendingAction::Bind { credential_id } if method.ends_with("bind_complete") => {
                    if args.assertion.credential_id != credential_id {
                        return Err("credential differs from human-reviewed binding".into());
                    }
                    let credential = fido.bind_credential(
                        &args.assertion,
                        &pending.challenge,
                        &pending.binding,
                    )?;
                    unchanged(rt, &acting, ctx.as_ref())?;
                    Ok(
                        json!({"credential_id":credential.credential_id,"principal_id":acting.principal.id,"binding":pending.binding,"provenance":"human_fido2_binding"}),
                    )
                }
                PendingAction::Mandate {
                    service,
                    profile_id,
                    profile_epoch,
                    expires_at,
                    max_issuances,
                } if method.ends_with("mandate_complete") => {
                    let credential = fido.verify_bound_assertion(
                        &args.assertion,
                        &pending.challenge,
                        &pending.binding,
                    )?;
                    unchanged(rt, &acting, ctx.as_ref())?;
                    let mandate = rt.store.create_mandate(
                        tenant,
                        &acting.principal.id,
                        &service,
                        &profile_id,
                        profile_epoch,
                        acting.epoch,
                        &acting.session_id,
                        expires_at,
                        max_issuances,
                        &credential.credential_id,
                        now_unix(),
                        |p| rt.principal_permitted(p),
                    )?;
                    Ok(json!({"mandate":mandate,"provenance":"human_fido2_mandate"}))
                }
                _ => Err("challenge belongs to another ceremony".into()),
            }
        }
        "identity.provisioning.issue" => {
            let args: Issue = parse(params)?;
            let context = ctx
                .as_ref()
                .filter(|c| c.mode == AccessMode::Autonomous && c.sub.is_service())
                .ok_or("issuance requires an authenticated autonomous service delegation")?;
            if args.recipient_issuer != rt.config.issuer {
                return Err("recipient issuer is outside this broker's IdP".into());
            }
            let recipient = rt
                .store
                .get_human_by_subject(&args.recipient_issuer, &args.recipient_subject)?
                .ok_or("recipient must complete IdP enrollment first")?;
            let issued_at = now_unix();
            let expires_at = issued_at
                .checked_add(i64::try_from(args.ttl_secs).map_err(|_| "invalid TTL")?)
                .filter(|_| args.ttl_secs > 0)
                .ok_or("invalid TTL")?;
            let grant = rt.store.issue_access(
                tenant,
                &args.mandate_id,
                &context.sub,
                &context.jti,
                &recipient.id,
                &args.request_id,
                expires_at,
                issued_at,
                max_age,
                |p| rt.principal_permitted(p),
            )?;
            Ok(
                json!({"grant":grant,"actor":context.act,"service":context.sub,"delegation_id":context.jti,"provenance":"delegated_policy"}),
            )
        }
        "identity.provisioning.list" => {
            let is_admin = admin(rt, ctx.as_ref()).is_ok();
            let service = ctx
                .as_ref()
                .filter(|c| c.mode == AccessMode::Autonomous && c.sub.is_service())
                .map(|c| &c.sub);
            if !is_admin && service.is_none() {
                return Err(
                    "an administrator or authenticated provisioning service is required".into(),
                );
            }
            let mandates = rt
                .store
                .list_mandates(tenant)?
                .into_iter()
                .filter(|m| is_admin || service == Some(&m.service))
                .collect::<Vec<_>>();
            let grants = rt
                .store
                .list_access_grants(tenant)?
                .into_iter()
                .filter(|g| mandates.iter().any(|m| m.id == g.parent_id))
                .collect::<Vec<_>>();
            Ok(json!({"mandates":mandates,"grants":grants}))
        }
        "identity.provisioning.show" => {
            let args: Revoke = parse(params)?;
            let (mandate, grant) = match args.kind.as_str() {
                "mandate" => (rt.store.get_mandate(tenant, &args.id)?, None),
                "access" => {
                    let grant = rt.store.get_access_grant(tenant, &args.id)?;
                    (rt.store.get_mandate(tenant, &grant.parent_id)?, Some(grant))
                }
                _ => return Err("kind must be mandate or access".into()),
            };
            if admin(rt, ctx.as_ref()).is_err()
                && !ctx
                    .as_ref()
                    .is_some_and(|c| c.mode == AccessMode::Autonomous && c.sub == mandate.service)
            {
                return Err(
                    "only an administrator or the owning service may inspect this grant".into(),
                );
            }
            let profile = rt
                .store
                .provisioning_profile_at(&mandate.profile_id, mandate.profile_epoch)?;
            Ok(json!({"mandate":mandate,"grant":grant,"approved_profile":profile}))
        }
        "identity.provisioning.revoke" => {
            let acting = admin(rt, ctx.as_ref())?;
            let args: Revoke = parse(params)?;
            match args.kind.as_str() {
                "mandate" => rt.store.revoke_mandate(tenant, &args.id, now_unix())?,
                "access" => rt.store.revoke_access(tenant, &args.id, now_unix())?,
                _ => return Err("revocation kind must be mandate or access".into()),
            }
            Ok(json!({"id":args.id,"kind":args.kind,"revoked":true,"actor":acting.principal.id}))
        }
        _ => Err("unknown provisioning method".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending(uid: u32, expires_at: i64) -> Pending {
        Pending {
            uid,
            expires_at,
            challenge: "one-shot".into(),
            binding: Fido2PrincipalBinding {
                principal_id: PrincipalId::parse("hum_11111111111111111111111111111111").unwrap(),
                issuer: "https://idp.example.com".into(),
                subject: "alice".into(),
                tenant_id: "test".into(),
                broker_id: uuid::Uuid::new_v4().to_string(),
            },
            human_session_id: "login".into(),
            issuer_epoch: 1,
            action: PendingAction::Bind {
                credential_id: "key".into(),
            },
        }
    }
    #[test]
    fn challenges_are_peer_bound_and_single_use() {
        let challenges = Challenges::default();
        let id = challenges.insert(pending(42, now_unix() + 60)).unwrap();
        assert!(challenges.take(&id, 43).is_err());
        assert!(challenges.take(&id, 42).is_ok());
        assert!(challenges.take(&id, 42).is_err());
    }
    #[test]
    fn challenge_expiry_and_restart_require_fresh_review() {
        let challenges = Challenges::default();
        let id = challenges.insert(pending(42, now_unix())).unwrap();
        assert!(challenges.take(&id, 42).is_err());
        assert!(Challenges::default().take(&id, 42).is_err());
    }
    #[test]
    fn parameters_reject_claims_and_redelegation() {
        assert!(parse::<Issue>(json!({"mandate_id":"m","recipient_issuer":"i","recipient_subject":"s","ttl_secs":60,"request_id":"r","groups":["admin"]})).is_err());
        assert!(parse::<MandateStart>(json!({"service":"s","profile_id":"p","ttl_secs":60,"max_issuances":1,"redelegation":true})).is_err());
        assert!(expiry(0).is_err());
        assert!(expiry(u64::MAX).is_err());
    }
}
