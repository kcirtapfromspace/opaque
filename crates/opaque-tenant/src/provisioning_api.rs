//! Shared protocol types for human-authorized, persona-bound provisioning:
//! the peer-bound challenge ledger, wire DTOs, and the pure principal-binding
//! derivation used by the `identity.provisioning.*` RPC ceremony.
//!
//! ## Why this is a partial extraction
//!
//! The RPC dispatch itself (`handle`/`handle_inner`, plus the `admin`/
//! `unchanged` authority checks and startup `initialize` validation) stays in
//! `opaqued::provisioning_api`. It is irreducibly coupled to the concrete,
//! SQLite-backed `opaqued::identity::IdentityRuntime` (persona freshness,
//! mandate/grant storage, principal admission) and `opaqued::DaemonConfig` —
//! both daemon-private types that are *not* moving out of the kernel crate
//! (see the project refactor plan: "`identity/` ... referenced by
//! `provisioning_api.rs` but not itself moving"). `opaqued` is a binary-only
//! crate with no `lib.rs`, and giving it one so this crate could depend on
//! `IdentityRuntime` would create a real cycle (`opaque-tenant` depended on
//! by `opaqued`'s binary, depending back on `opaqued`'s library) — the same
//! reasoning documented on `opaque_core::enclave_facade::EnclaveFacade`.
//!
//! Trait-erasing `IdentityRuntime`'s full surface (principal/session/persona
//! lookups, mandate and access-grant CRUD, provisioning-profile lookups —
//! roughly two dozen operations, each with its own opaqued-local return type)
//! into `opaque-core` would amount to re-hosting the identity substrate
//! itself, which the plan explicitly scopes out of this extraction. Instead,
//! this module holds exactly the slice of the original `provisioning_api.rs`
//! that has zero dependency on `DaemonState`/`DaemonConfig`/`IdentityRuntime`
//! — the challenge lifecycle, wire types, and pure derivations — so it can be
//! shared and unit-tested independently. `opaqued::provisioning_api` imports
//! these and keeps the identity-coupled orchestration.

use std::collections::HashMap;
use std::sync::Mutex;

use opaque_approval::fido2::{Fido2Assertion, Fido2PrincipalBinding};
use opaque_core::identity::{Principal, PrincipalId, PrincipalKind, now_unix};
use opaque_core::tenant::TenantBinding;
use serde::Deserialize;
use serde_json::Value;

const MAX_PENDING: usize = 128;

/// Peer-bound, single-use, TTL-expiring provisioning review challenges.
#[derive(Default)]
pub struct Challenges(Mutex<HashMap<String, Pending>>);

pub struct Pending {
    pub uid: u32,
    pub expires_at: i64,
    pub challenge: String,
    pub binding: Fido2PrincipalBinding,
    pub human_session_id: String,
    pub issuer_epoch: i64,
    pub action: PendingAction,
}

pub enum PendingAction {
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
    pub fn insert(&self, pending: Pending) -> Result<String, String> {
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
    pub fn take(&self, id: &str, uid: u32) -> Result<Pending, String> {
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

/// A verified, unstale administrator snapshot taken when a provisioning
/// ceremony's "start" RPC issues its challenge, re-checked unchanged at
/// "complete" so authority cannot drift mid-ceremony.
#[derive(Clone)]
pub struct Admin {
    pub principal: Principal,
    pub session_id: String,
    pub epoch: i64,
}

pub fn principal_binding(
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

pub fn parse<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, String> {
    serde_json::from_value(params).map_err(|_| "invalid provisioning parameters".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindStart {
    pub credential_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MandateStart {
    pub service: String,
    pub profile_id: String,
    pub ttl_secs: u64,
    pub max_issuances: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Complete {
    pub challenge_id: String,
    pub assertion: Fido2Assertion,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    pub mandate_id: String,
    pub recipient_issuer: String,
    pub recipient_subject: String,
    pub ttl_secs: u64,
    pub request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    pub kind: String,
    pub id: String,
}

pub fn expiry(ttl: u64) -> Result<i64, String> {
    now_unix()
        .checked_add(i64::try_from(ttl).map_err(|_| "invalid TTL")?)
        .filter(|_| ttl > 0)
        .ok_or_else(|| "invalid TTL".into())
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
        assert!(parse::<Issue>(serde_json::json!({"mandate_id":"m","recipient_issuer":"i","recipient_subject":"s","ttl_secs":60,"request_id":"r","groups":["admin"]})).is_err());
        assert!(parse::<MandateStart>(serde_json::json!({"service":"s","profile_id":"p","ttl_secs":60,"max_issuances":1,"redelegation":true})).is_err());
        assert!(expiry(0).is_err());
        assert!(expiry(u64::MAX).is_err());
    }
}
