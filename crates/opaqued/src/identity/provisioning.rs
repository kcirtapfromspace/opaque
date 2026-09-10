//! Durable, delegated issuance of narrowly scoped read access. Neither a
//! mandate nor an access grant changes a principal's roles.

use std::collections::{BTreeMap, BTreeSet};

use opaque_core::identity::{Principal, PrincipalId, PrincipalKind, Role, now_unix};
use opaque_core::resource_auth::METRIC_SCOPES;
use opaque_core::tenant::TenantBinding;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::persona;
use super::store::{IdentityStore, row_to_principal};

const MAX_ACCESS_TTL: u64 = 86_400;
const MAX_MANDATE_TTL: u64 = 7 * 86_400;
const MAX_ISSUANCES: u32 = 10_000;
const MAX_PROFILES: usize = 64;
const PRINCIPAL_COLUMNS: &str =
    "id,kind,iss,sub,email,display_name,tool,service_name,roles,created_at,last_seen,disabled";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningConfig {
    #[serde(default)]
    pub profiles: Vec<AccessProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessProfile {
    pub id: String,
    pub revision: u64,
    pub eligible_group: String,
    pub scopes: BTreeSet<String>,
    pub max_ttl_secs: u64,
    pub max_mandate_ttl_secs: u64,
    pub max_issuances: u32,
}

impl ProvisioningConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.profiles.len() > MAX_PROFILES {
            return Err("too many provisioning profiles".into());
        }
        let mut ids = BTreeSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            if !ids.insert(&profile.id) {
                return Err("duplicate provisioning profile".into());
            }
        }
        Ok(())
    }
}

impl AccessProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.eligible_group.is_empty()
            || self.eligible_group.len() > 128
            || self.eligible_group.trim() != self.eligible_group
            || self.eligible_group.chars().any(char::is_control)
            || !(1..=MAX_ACCESS_TTL).contains(&self.max_ttl_secs)
            || !(1..=MAX_MANDATE_TTL).contains(&self.max_mandate_ttl_secs)
            || !(1..=MAX_ISSUANCES).contains(&self.max_issuances)
            || self.scopes.is_empty()
            || self.scopes.iter().any(|scope| {
                !scope.starts_with("metrics:") || !METRIC_SCOPES.contains(&scope.as_str())
            })
        {
            return Err("invalid read-only metrics provisioning profile".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub id: String,
    pub binding: TenantBinding,
    pub issuer: PrincipalId,
    pub service: PrincipalId,
    pub profile_id: String,
    pub profile_epoch: i64,
    pub expires_at: i64,
    pub max_issuances: u32,
    pub issued_count: u32,
    pub approved_credential_id: String,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessGrant {
    pub id: String,
    pub parent_id: String,
    pub recipient: PrincipalId,
    pub actor: PrincipalId,
    pub delegation_id: String,
    pub profile_id: String,
    pub profile_epoch: i64,
    pub persona_revision: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS provisioning_profiles (
 id TEXT PRIMARY KEY, epoch INTEGER NOT NULL CHECK(epoch > 0),
 fingerprint TEXT NOT NULL, profile_json TEXT NOT NULL, active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS provisioning_profile_history (
 id TEXT NOT NULL, epoch INTEGER NOT NULL, profile_json TEXT NOT NULL,
 PRIMARY KEY(id,epoch)
);
INSERT OR IGNORE INTO provisioning_profile_history SELECT id,epoch,profile_json FROM provisioning_profiles WHERE active=1;
CREATE TABLE IF NOT EXISTS provisioning_principal_epochs (
 principal_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL CHECK(epoch > 0)
);
INSERT OR IGNORE INTO provisioning_principal_epochs SELECT id,1 FROM principals;
CREATE TABLE IF NOT EXISTS provisioning_mandates (
 id TEXT PRIMARY KEY, binding TEXT NOT NULL, issuer TEXT NOT NULL, service TEXT NOT NULL,
 profile_id TEXT NOT NULL, profile_epoch INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 max_issuances INTEGER NOT NULL, issued_count INTEGER NOT NULL DEFAULT 0,
 approved_credential_id TEXT NOT NULL, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS provisioning_mandates_binding ON provisioning_mandates(binding);
CREATE TABLE IF NOT EXISTS provisioning_access (
 id TEXT PRIMARY KEY, parent_id TEXT NOT NULL, recipient TEXT NOT NULL,
 profile_id TEXT NOT NULL, profile_epoch INTEGER NOT NULL, persona_revision INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, revoked_at INTEGER, actor TEXT NOT NULL, delegation_id TEXT NOT NULL,
 request_id TEXT NOT NULL, request_fingerprint TEXT NOT NULL,
 UNIQUE(parent_id,request_id)
);
CREATE INDEX IF NOT EXISTS provisioning_access_recipient ON provisioning_access(recipient);
CREATE TABLE IF NOT EXISTS provisioning_recipient_denials (
 parent_id TEXT NOT NULL, recipient TEXT NOT NULL, revoked_at INTEGER NOT NULL,
 PRIMARY KEY(parent_id,recipient)
);
CREATE TABLE IF NOT EXISTS provisioning_credential_denials (
 binding TEXT NOT NULL, credential_id TEXT NOT NULL, revoked_at INTEGER NOT NULL,
 PRIMARY KEY(binding,credential_id)
);
CREATE TRIGGER IF NOT EXISTS provisioning_principal_insert AFTER INSERT ON principals BEGIN
 INSERT INTO provisioning_principal_epochs(principal_id,epoch) VALUES(NEW.id,1)
 ON CONFLICT(principal_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER IF NOT EXISTS provisioning_principal_update AFTER UPDATE ON principals
WHEN OLD.roles IS NOT NEW.roles OR OLD.disabled IS NOT NEW.disabled OR OLD.kind IS NOT NEW.kind
 OR OLD.iss IS NOT NEW.iss OR OLD.sub IS NOT NEW.sub OR OLD.service_name IS NOT NEW.service_name
BEGIN
 UPDATE provisioning_principal_epochs SET epoch=epoch+1 WHERE principal_id=OLD.id;
 UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER))
 WHERE issuer=OLD.id OR service=OLD.id;
 UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER))
 WHERE recipient=OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS provisioning_principal_delete AFTER DELETE ON principals BEGIN
 UPDATE provisioning_principal_epochs SET epoch=epoch+1 WHERE principal_id=OLD.id;
 UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER))
 WHERE issuer=OLD.id OR service=OLD.id;
 UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER))
 WHERE recipient=OLD.id;
END;
"#;

pub(super) fn ensure_schema(conn: &Connection) -> Result<(), String> {
    db(conn.execute_batch(SCHEMA))
}

fn db<T>(value: rusqlite::Result<T>) -> Result<T, String> {
    value.map_err(|_| "provisioning store unavailable".into())
}

fn binding_key(binding: &TenantBinding) -> Result<String, String> {
    binding
        .validate()
        .map_err(|_| "invalid provisioning boundary")?;
    serde_json::to_string(binding).map_err(|_| "invalid provisioning boundary".into())
}

fn uuid(value: &str) -> Result<(), String> {
    if Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value) {
        Ok(())
    } else {
        Err("provisioning identifiers require a canonical UUID".into())
    }
}

fn checked_expiry(now: i64, expires_at: i64, max_ttl: u64) -> Result<(), String> {
    if now < 0
        || expires_at <= now
        || expires_at
            .checked_sub(now)
            .is_none_or(|ttl| ttl as u64 > max_ttl)
    {
        Err("provisioning expiry exceeds its approved limit".into())
    } else {
        Ok(())
    }
}

fn principal(conn: &Connection, id: &PrincipalId) -> Result<Option<Principal>, String> {
    db(conn
        .query_row(
            &format!("SELECT {PRINCIPAL_COLUMNS} FROM principals WHERE id=?1"),
            [id.as_str()],
            row_to_principal,
        )
        .optional())
}

fn admitted(
    conn: &Connection,
    id: &PrincipalId,
    permitted: &impl Fn(&Principal) -> bool,
) -> Result<Option<Principal>, String> {
    Ok(principal(conn, id)?.filter(|p| !p.disabled && permitted(p)))
}

fn active_profile(conn: &Connection, id: &str) -> Result<(AccessProfile, i64), String> {
    let (json, epoch): (String, i64) = db(conn.query_row(
        "SELECT profile_json,epoch FROM provisioning_profiles WHERE id=?1 AND active=1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ))?;
    let profile: AccessProfile =
        serde_json::from_str(&json).map_err(|_| "invalid stored provisioning profile")?;
    profile.validate()?;
    if profile.id != id || epoch <= 0 {
        return Err("invalid stored provisioning profile".into());
    }
    Ok((profile, epoch))
}

fn mandate_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Mandate> {
    let invalid = || rusqlite::Error::InvalidQuery;
    Ok(Mandate {
        id: row.get(0)?,
        binding: serde_json::from_str(&row.get::<_, String>(1)?).map_err(|_| invalid())?,
        issuer: PrincipalId::parse(&row.get::<_, String>(2)?).map_err(|_| invalid())?,
        service: PrincipalId::parse(&row.get::<_, String>(3)?).map_err(|_| invalid())?,
        profile_id: row.get(4)?,
        profile_epoch: row.get(5)?,
        expires_at: row.get(6)?,
        max_issuances: row.get(7)?,
        issued_count: row.get(8)?,
        approved_credential_id: row.get(9)?,
        revoked_at: row.get(10)?,
    })
}

const MANDATE_COLUMNS: &str = "id,binding,issuer,service,profile_id,profile_epoch,expires_at,max_issuances,issued_count,approved_credential_id,revoked_at";

fn read_mandate(conn: &Connection, binding: &TenantBinding, id: &str) -> Result<Mandate, String> {
    uuid(id)?;
    db(conn.query_row(
        &format!("SELECT {MANDATE_COLUMNS} FROM provisioning_mandates WHERE id=?1 AND binding=?2"),
        params![id, binding_key(binding)?],
        mandate_row,
    ))
}

fn access_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccessGrant> {
    Ok(AccessGrant {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        recipient: PrincipalId::parse(&row.get::<_, String>(2)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        profile_id: row.get(3)?,
        profile_epoch: row.get(4)?,
        persona_revision: row.get(5)?,
        expires_at: row.get(6)?,
        revoked_at: row.get(7)?,
        actor: PrincipalId::parse(&row.get::<_, String>(8)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        delegation_id: row.get(9)?,
    })
}

const ACCESS_COLUMNS: &str = "a.id,a.parent_id,a.recipient,a.profile_id,a.profile_epoch,a.persona_revision,a.expires_at,a.revoked_at,a.actor,a.delegation_id";

fn live_parent(
    conn: &Connection,
    parent: &Mandate,
    now: i64,
    permitted: &impl Fn(&Principal) -> bool,
) -> Result<AccessProfile, String> {
    if parent.revoked_at.is_some() || parent.expires_at <= now {
        return Err("provisioning mandate inactive".into());
    }
    let issuer =
        admitted(conn, &parent.issuer, permitted)?.ok_or("provisioning issuer not admitted")?;
    let service =
        admitted(conn, &parent.service, permitted)?.ok_or("provisioning service not admitted")?;
    if !matches!(issuer.kind, PrincipalKind::Human { .. })
        || !issuer.has_role(Role::Admin)
        || !matches!(service.kind, PrincipalKind::Service { .. })
    {
        return Err("provisioning authority no longer admitted".into());
    }
    let (profile, epoch) = active_profile(conn, &parent.profile_id)?;
    if epoch != parent.profile_epoch {
        return Err("provisioning policy changed".into());
    }
    Ok(profile)
}

impl IdentityStore {
    /// Always run on startup, including with an empty configuration when this
    /// capability is disabled. Historical epochs and revocations are retained.
    pub fn sync_profiles(&self, config: &ProvisioningConfig) -> Result<(), String> {
        config.validate()?;
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let previous: BTreeMap<String, (i64, String, bool)> = {
            let mut stmt =
                db(tx.prepare("SELECT id,epoch,fingerprint,active FROM provisioning_profiles"))?;
            db(
                db(stmt.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?)))))?
                    .collect(),
            )?
        };
        let now = now_unix();
        for profile in &config.profiles {
            let json =
                serde_json::to_string(profile).map_err(|_| "invalid provisioning profile")?;
            let fingerprint = format!("{:x}", Sha256::digest(json.as_bytes()));
            let old = previous.get(&profile.id);
            if old.is_some_and(|(_, digest, active)| *active && *digest == fingerprint) {
                continue;
            }
            let epoch = match old {
                Some((epoch, ..)) => epoch
                    .checked_add(1)
                    .ok_or("provisioning policy epoch exhausted")?,
                None => 1,
            };
            db(tx.execute(
                "INSERT INTO provisioning_profile_history(id,epoch,profile_json) VALUES(?1,?2,?3)",
                params![profile.id, epoch, json],
            ))?;
            db(tx.execute("INSERT INTO provisioning_profiles(id,epoch,fingerprint,profile_json,active) VALUES(?1,?2,?3,?4,1) ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch,fingerprint=excluded.fingerprint,profile_json=excluded.profile_json,active=1",params![profile.id,epoch,fingerprint,json]))?;
            db(tx.execute("UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?1) WHERE profile_id=?2",params![now,profile.id]))?;
        }
        for (id, (epoch, _, active)) in previous {
            if active && !config.profiles.iter().any(|p| p.id == id) {
                db(tx.execute(
                    "UPDATE provisioning_profiles SET active=0,epoch=?1 WHERE id=?2",
                    params![
                        epoch
                            .checked_add(1)
                            .ok_or("provisioning policy epoch exhausted")?,
                        id
                    ],
                ))?;
                db(tx.execute("UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?1) WHERE profile_id=?2",params![now,id]))?;
            }
        }
        db(tx.commit())
    }

    /// Persist loss of configured admission before serving requests. Restoring
    /// an issuer, subject or service to a config never restores old authority.
    pub fn sync_provisioning_admission(
        &self,
        permitted: impl Fn(&Principal) -> bool,
        now: i64,
    ) -> Result<(), String> {
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let all: Vec<Principal> = {
            let mut stmt = db(tx.prepare(&format!("SELECT {PRINCIPAL_COLUMNS} FROM principals")))?;
            db(db(stmt.query_map([], row_to_principal))?.collect())?
        };
        for p in all {
            if p.disabled || !permitted(&p) {
                db(tx.execute("UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?1) WHERE issuer=?2 OR service=?2",params![now,p.id.as_str()]))?;
                db(tx.execute("UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,?1) WHERE recipient=?2",params![now,p.id.as_str()]))?;
                db(tx.execute(
                    "UPDATE provisioning_principal_epochs SET epoch=epoch+1 WHERE principal_id=?1",
                    [p.id.as_str()],
                ))?;
            }
        }
        db(tx.execute("UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?1) WHERE NOT EXISTS(SELECT 1 FROM principals p WHERE p.id=issuer) OR NOT EXISTS(SELECT 1 FROM principals p WHERE p.id=service)",[now]))?;
        db(tx.execute("UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,?1) WHERE NOT EXISTS(SELECT 1 FROM principals p WHERE p.id=recipient)",[now]))?;
        db(tx.commit())
    }

    pub fn provisioning_profile(&self, id: &str) -> Result<(AccessProfile, i64), String> {
        let conn = self.lock();
        ensure_schema(&conn)?;
        active_profile(&conn, id)
    }

    /// Historical approval terms are evidence only and cannot activate access.
    pub fn provisioning_profile_at(&self, id: &str, epoch: i64) -> Result<AccessProfile, String> {
        let conn = self.lock();
        ensure_schema(&conn)?;
        let json: String = db(conn.query_row(
            "SELECT profile_json FROM provisioning_profile_history WHERE id=?1 AND epoch=?2",
            params![id, epoch],
            |r| r.get(0),
        ))?;
        let profile: AccessProfile =
            serde_json::from_str(&json).map_err(|_| "invalid historical provisioning profile")?;
        profile.validate()?;
        if profile.id != id {
            return Err("invalid historical provisioning profile".into());
        }
        Ok(profile)
    }

    pub fn provisioning_principal_epoch(&self, id: &PrincipalId) -> Result<i64, String> {
        let conn = self.lock();
        ensure_schema(&conn)?;
        db(conn.query_row(
            "SELECT epoch FROM provisioning_principal_epochs WHERE principal_id=?1",
            [id.as_str()],
            |row| row.get(0),
        ))
    }

    /// The caller consumes a server-verified, fresh bound FIDO assertion. The
    /// observed policy and issuer epochs come from that exact reviewed request.
    #[allow(clippy::too_many_arguments)]
    pub fn create_mandate(
        &self,
        binding: &TenantBinding,
        issuer: &PrincipalId,
        service: &PrincipalId,
        profile_id: &str,
        expected_profile_epoch: i64,
        expected_issuer_epoch: i64,
        human_session_id: &str,
        expires_at: i64,
        max_issuances: u32,
        credential_id: &str,
        now: i64,
        permitted: impl Fn(&Principal) -> bool,
    ) -> Result<Mandate, String> {
        let key = binding_key(binding)?;
        if credential_id.is_empty()
            || credential_id.len() > 512
            || credential_id.chars().any(char::is_control)
        {
            return Err("invalid approved credential identity".into());
        }
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        // Key verification happens before this transaction. Removal may race
        // that ceremony, so check a durable denial under the same writer lock
        // as mandate insertion. Re-enrollment cannot restore a removed key ID.
        let credential_denied: bool = db(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM provisioning_credential_denials WHERE binding=?1 AND credential_id=?2)",
            params![key, credential_id],
            |row| row.get(0),
        ))?;
        if credential_denied {
            return Err("approving credential was revoked; enroll a new credential".into());
        }
        let (profile, epoch) = active_profile(&tx, profile_id)?;
        let issuer_epoch: i64 = db(tx.query_row(
            "SELECT epoch FROM provisioning_principal_epochs WHERE principal_id=?1",
            [issuer.as_str()],
            |r| r.get(0),
        ))?;
        if expected_profile_epoch != epoch || expected_issuer_epoch != issuer_epoch {
            return Err("provisioning review changed before approval".into());
        }
        let session_live:bool=db(tx.query_row("SELECT EXISTS(SELECT 1 FROM human_sessions s JOIN principals p ON p.id=s.principal_id WHERE s.id=?1 AND s.principal_id=?2 AND s.revoked_at IS NULL AND s.expires_at>?3 AND s.idp_issuer=p.iss)",params![human_session_id,issuer.as_str(),now],|r|r.get(0)))?;
        if !session_live {
            return Err("provisioning approval login expired or was revoked".into());
        }
        checked_expiry(now, expires_at, profile.max_mandate_ttl_secs)?;
        if max_issuances == 0 || max_issuances > profile.max_issuances {
            return Err("provisioning issuance allowance exceeds profile".into());
        }
        let parent = Mandate {
            id: Uuid::new_v4().to_string(),
            binding: binding.clone(),
            issuer: issuer.clone(),
            service: service.clone(),
            profile_id: profile_id.into(),
            profile_epoch: epoch,
            expires_at,
            max_issuances,
            issued_count: 0,
            approved_credential_id: credential_id.into(),
            revoked_at: None,
        };
        live_parent(&tx, &parent, now, &permitted)?;
        db(tx.execute("INSERT INTO provisioning_mandates(id,binding,issuer,service,profile_id,profile_epoch,expires_at,max_issuances,issued_count,approved_credential_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0,?9)",params![parent.id,key,issuer.as_str(),service.as_str(),profile_id,epoch,expires_at,max_issuances,credential_id]))?;
        db(tx.commit())?;
        Ok(parent)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_access(
        &self,
        binding: &TenantBinding,
        parent_id: &str,
        service: &PrincipalId,
        delegation_jti: &str,
        recipient: &PrincipalId,
        request_id: &str,
        expires_at: i64,
        now: i64,
        persona_max_age_secs: u64,
        permitted: impl Fn(&Principal) -> bool,
    ) -> Result<AccessGrant, String> {
        uuid(request_id)?;
        let requested_ttl = expires_at
            .checked_sub(now)
            .filter(|ttl| now >= 0 && *ttl > 0)
            .ok_or("provisioning expiry must have a positive bounded lifetime")?;
        // RPC retries recompute a proposed expiry from the same requested TTL.
        // Bind that request intent, while returning the first persisted expiry
        // unchanged. A retry must never extend authority or spend another slot.
        let request_fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(service, delegation_jti, recipient, requested_ttl))
                    .map_err(|_| "invalid issuance request")?
            )
        );
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let parent = read_mandate(&tx, binding, parent_id)?;
        if parent.service != *service {
            return Err("provisioning service does not own mandate".into());
        }
        let actor_id:String=db(tx.query_row("SELECT act_principal FROM delegations WHERE jti=?1 AND sub_principal=?2 AND mode='autonomous' AND revoked_at IS NULL AND expires_at>?3",params![delegation_jti,service.as_str(),now],|r|r.get(0)))?;
        let actor =
            PrincipalId::parse(&actor_id).map_err(|_| "invalid provisioning delegation actor")?;
        if principal(&tx, &actor)?
            .is_none_or(|p| p.disabled || !matches!(p.kind, PrincipalKind::Agent { .. }))
        {
            return Err("provisioning delegation actor unavailable".into());
        }
        let denied:bool=db(tx.query_row("SELECT EXISTS(SELECT 1 FROM provisioning_recipient_denials WHERE parent_id=?1 AND recipient=?2)",params![parent_id,recipient.as_str()],|r|r.get(0)))?;
        if denied {
            return Err("recipient access revoked under this mandate; a fresh human-approved mandate is required".into());
        }
        let profile = live_parent(&tx, &parent, now, &permitted)?;
        let target =
            admitted(&tx, recipient, &permitted)?.ok_or("provisioning recipient not admitted")?;
        if !matches!(target.kind, PrincipalKind::Human { .. }) {
            return Err("provisioning recipient must be an exact human principal".into());
        }
        let snapshot = persona::read_snapshot(&tx, recipient)?.ok_or("verified persona absent")?;
        if !snapshot.is_fresh(now, persona_max_age_secs)
            || !snapshot.groups.contains(&profile.eligible_group)
            || !super::lifecycle::provisioning_group_permitted(
                &tx,
                recipient,
                &profile.eligible_group,
            )?
        {
            return Err("verified persona is stale or outside eligible group".into());
        }
        let previous:Option<(AccessGrant,String)>=db(tx.query_row(&format!("SELECT {ACCESS_COLUMNS},a.request_fingerprint FROM provisioning_access a WHERE a.parent_id=?1 AND a.request_id=?2"),params![parent_id,request_id],|r|Ok((access_row(r)?,r.get(10)?))).optional())?;
        if let Some((grant, fingerprint)) = previous {
            if fingerprint != request_fingerprint {
                return Err("issuance request ID already used for different access".into());
            }
            if grant.revoked_at.is_some()
                || grant.expires_at <= now
                || grant.persona_revision != snapshot.revision
            {
                return Err(
                    "previous issuance is no longer active; request ID remains consumed".into(),
                );
            }
            return Ok(grant);
        }
        checked_expiry(now, expires_at, profile.max_ttl_secs)?;
        if expires_at > parent.expires_at {
            return Err("access outlives its provisioning mandate".into());
        }
        if parent.issued_count >= parent.max_issuances {
            return Err("provisioning issuance allowance exhausted".into());
        }
        let grant = AccessGrant {
            id: Uuid::new_v4().to_string(),
            parent_id: parent_id.into(),
            recipient: recipient.clone(),
            actor,
            delegation_id: delegation_jti.into(),
            profile_id: profile.id,
            profile_epoch: parent.profile_epoch,
            persona_revision: snapshot.revision,
            expires_at,
            revoked_at: None,
        };
        if db(tx.execute("UPDATE provisioning_mandates SET issued_count=issued_count+1 WHERE id=?1 AND revoked_at IS NULL AND issued_count<max_issuances",[parent_id]))? !=1 {return Err("provisioning issuance allowance exhausted".into());}
        db(tx.execute("INSERT INTO provisioning_access(id,parent_id,recipient,profile_id,profile_epoch,persona_revision,expires_at,request_id,request_fingerprint,actor,delegation_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![grant.id,parent_id,recipient.as_str(),grant.profile_id,grant.profile_epoch,grant.persona_revision,expires_at,request_id,request_fingerprint,grant.actor.as_str(),grant.delegation_id]))?;
        db(tx.commit())?;
        Ok(grant)
    }

    pub fn authorize_scopes(
        &self,
        binding: &TenantBinding,
        recipient: &PrincipalId,
        now: i64,
        persona_max_age_secs: u64,
        permitted: impl Fn(&Principal) -> bool,
    ) -> Result<BTreeSet<String>, String> {
        let key = binding_key(binding)?;
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let grants: Vec<AccessGrant> = {
            let mut stmt=db(tx.prepare(&format!("SELECT {ACCESS_COLUMNS} FROM provisioning_access a JOIN provisioning_mandates m ON m.id=a.parent_id WHERE m.binding=?1 AND a.recipient=?2 AND a.revoked_at IS NULL")))?;
            db(db(stmt.query_map(params![key, recipient.as_str()], access_row))?.collect())?
        };
        let target = admitted(&tx, recipient, &permitted)?
            .filter(|p| matches!(p.kind, PrincipalKind::Human { .. }));
        let snapshot = persona::read_snapshot(&tx, recipient)?;
        let mut scopes = BTreeSet::new();
        for grant in grants {
            let result = (|| -> Result<AccessProfile, String> {
                if target.is_none() || grant.expires_at <= now {
                    return Err("access inactive".into());
                }
                let parent = read_mandate(&tx, binding, &grant.parent_id)?;
                let profile = live_parent(&tx, &parent, now, &permitted)?;
                let persona = snapshot.as_ref().ok_or("verified persona absent")?;
                if grant.profile_epoch != parent.profile_epoch
                    || grant.profile_id != parent.profile_id
                    || persona.revision != grant.persona_revision
                    || !persona.is_fresh(now, persona_max_age_secs)
                    || !persona.groups.contains(&profile.eligible_group)
                    || !super::lifecycle::provisioning_group_permitted(
                        &tx,
                        recipient,
                        &profile.eligible_group,
                    )?
                {
                    return Err("access eligibility changed".into());
                }
                Ok(profile)
            })();
            match result {
                Ok(profile) => scopes.extend(profile.scopes),
                Err(_) => {
                    db(tx.execute("UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,?1) WHERE id=?2",params![now,grant.id]))?;
                }
            }
        }
        db(tx.commit())?;
        Ok(scopes)
    }

    pub fn get_mandate(&self, binding: &TenantBinding, id: &str) -> Result<Mandate, String> {
        let conn = self.lock();
        ensure_schema(&conn)?;
        read_mandate(&conn, binding, id)
    }

    pub fn list_mandates(&self, binding: &TenantBinding) -> Result<Vec<Mandate>, String> {
        let conn = self.lock();
        ensure_schema(&conn)?;
        let mut stmt = db(conn.prepare(&format!(
            "SELECT {MANDATE_COLUMNS} FROM provisioning_mandates WHERE binding=?1 ORDER BY id"
        )))?;
        db(db(stmt.query_map([binding_key(binding)?], mandate_row))?.collect())
    }

    pub fn get_access_grant(
        &self,
        binding: &TenantBinding,
        id: &str,
    ) -> Result<AccessGrant, String> {
        uuid(id)?;
        let conn = self.lock();
        ensure_schema(&conn)?;
        db(conn.query_row(&format!("SELECT {ACCESS_COLUMNS} FROM provisioning_access a JOIN provisioning_mandates m ON m.id=a.parent_id WHERE m.binding=?1 AND a.id=?2"),params![binding_key(binding)?,id],access_row))
    }

    pub fn list_access_grants(&self, binding: &TenantBinding) -> Result<Vec<AccessGrant>, String> {
        let conn = self.lock();
        ensure_schema(&conn)?;
        let mut stmt=db(conn.prepare(&format!("SELECT {ACCESS_COLUMNS} FROM provisioning_access a JOIN provisioning_mandates m ON m.id=a.parent_id WHERE m.binding=?1 ORDER BY a.id")))?;
        db(db(stmt.query_map([binding_key(binding)?], access_row))?.collect())
    }

    pub fn revoke_mandate(
        &self,
        binding: &TenantBinding,
        id: &str,
        now: i64,
    ) -> Result<(), String> {
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        read_mandate(&tx, binding, id)?;
        db(tx.execute(
            "UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?1) WHERE id=?2",
            params![now, id],
        ))?;
        db(tx.execute(
            "UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,?1) WHERE parent_id=?2",
            params![now, id],
        ))?;
        db(tx.commit())
    }

    pub fn revoke_access(&self, binding: &TenantBinding, id: &str, now: i64) -> Result<(), String> {
        uuid(id)?;
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let grant=db(tx.query_row(&format!("SELECT {ACCESS_COLUMNS} FROM provisioning_access a JOIN provisioning_mandates m ON m.id=a.parent_id WHERE m.binding=?1 AND a.id=?2"),params![binding_key(binding)?,id],access_row))?;
        db(tx.execute("INSERT OR IGNORE INTO provisioning_recipient_denials(parent_id,recipient,revoked_at) VALUES(?1,?2,?3)",params![grant.parent_id,grant.recipient.as_str(),now]))?;
        db(tx.execute("UPDATE provisioning_access SET revoked_at=COALESCE(revoked_at,?1) WHERE parent_id=?2 AND recipient=?3",params![now,grant.parent_id,grant.recipient.as_str()]))?;
        db(tx.commit())
    }

    pub fn revoke_by_credential(
        &self,
        binding: &TenantBinding,
        credential_id: &str,
        now: i64,
    ) -> Result<(), String> {
        let key = binding_key(binding)?;
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let tx = db(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        // Persist first, even when no mandate exists yet. A verified assertion
        // waiting to insert its mandate must observe this denial, and a crash
        // before the separate credential-file removal must remain fail closed.
        db(tx.execute(
            "INSERT OR IGNORE INTO provisioning_credential_denials(binding,credential_id,revoked_at) VALUES(?1,?2,?3)",
            params![key, credential_id, now],
        ))?;
        db(tx.execute("UPDATE provisioning_mandates SET revoked_at=COALESCE(revoked_at,?1) WHERE binding=?2 AND approved_credential_id=?3",params![now,key,credential_id]))?;
        db(tx.commit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::persona::{PersonaConfig, VerifiedPersonaClaims};
    use crate::identity::store::DelegationRecord;
    use opaque_core::identity::AccessMode;
    use opaque_core::tenant::TenantId;
    use std::sync::Arc;

    fn profile() -> AccessProfile {
        AccessProfile {
            id: "engineering-metrics".into(),
            revision: 1,
            eligible_group: "Engineering".into(),
            scopes: ["metrics:read", "metrics:metric:error_rate_percent"]
                .map(str::to_owned)
                .into_iter()
                .collect(),
            max_ttl_secs: 1800,
            max_mandate_ttl_secs: 7200,
            max_issuances: 10,
        }
    }

    fn config() -> ProvisioningConfig {
        ProvisioningConfig {
            profiles: vec![profile()],
        }
    }

    struct Fixture {
        store: Arc<IdentityStore>,
        binding: TenantBinding,
        issuer: PrincipalId,
        service: PrincipalId,
        recipient: PrincipalId,
        actor: PrincipalId,
        delegation: String,
        session: String,
        now: i64,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_store(IdentityStore::open_in_memory().unwrap())
        }

        fn with_store(store: IdentityStore) -> Self {
            store.sync_profiles(&config()).unwrap();
            store
                .sync_persona_policy(Some(&PersonaConfig {
                    groups_claim: "groups".into(),
                    max_age_secs: 300,
                }))
                .unwrap();
            let issuer = store
                .upsert_human(
                    "https://idp.example",
                    "admin",
                    None,
                    None,
                    &BTreeSet::from([Role::Admin]),
                )
                .unwrap()
                .id;
            let service = store.upsert_service("onboarding").unwrap().id;
            let recipient = store
                .upsert_human(
                    "https://idp.example",
                    "new-hire",
                    None,
                    None,
                    &BTreeSet::new(),
                )
                .unwrap()
                .id;
            let actor = store.upsert_agent("provisioner").unwrap().id;
            let now = now_unix();
            let session = store
                .create_human_session(&issuer, 7200, "https://idp.example")
                .unwrap()
                .id;
            let delegation = Uuid::new_v4().to_string();
            store
                .record_delegation(&DelegationRecord {
                    jti: delegation.clone(),
                    sub_principal: service.clone(),
                    act_principal: actor.clone(),
                    mode: AccessMode::Autonomous,
                    human_session_id: None,
                    approved_by: Some(issuer.clone()),
                    created_at: now,
                    expires_at: now + 1800,
                    revoked_at: None,
                })
                .unwrap();
            let fixture = Self {
                store: Arc::new(store),
                binding: TenantBinding::new(
                    TenantId::parse("engineering").unwrap(),
                    Uuid::new_v4(),
                )
                .unwrap(),
                issuer,
                service,
                recipient,
                actor,
                delegation,
                session,
                now,
            };
            fixture.snapshot(&["Engineering"], now);
            fixture
        }

        fn snapshot(&self, groups: &[&str], now: i64) {
            let claims =
                serde_json::json!({"groups":groups,"iat":now,"auth_time":now,"exp":now+3600});
            let verified = VerifiedPersonaClaims::from_verified_claims(
                "https://idp.example",
                "new-hire",
                &PersonaConfig {
                    groups_claim: "groups".into(),
                    max_age_secs: 300,
                },
                claims.as_object().unwrap(),
                now,
            )
            .unwrap();
            self.store
                .record_persona_snapshot(&self.recipient, &verified, now)
                .unwrap();
        }

        fn mandate(&self, max: u32) -> Mandate {
            self.try_mandate(max, "credential-1").unwrap()
        }

        fn try_mandate(&self, max: u32, credential_id: &str) -> Result<Mandate, String> {
            self.store.create_mandate(
                &self.binding,
                &self.issuer,
                &self.service,
                "engineering-metrics",
                self.store
                    .provisioning_profile("engineering-metrics")
                    .unwrap()
                    .1,
                self.store
                    .provisioning_principal_epoch(&self.issuer)
                    .unwrap(),
                &self.session,
                self.now + 3600,
                max,
                credential_id,
                self.now,
                |_| true,
            )
        }

        fn issue(&self, mandate: &Mandate, request: &str) -> Result<AccessGrant, String> {
            self.store.issue_access(
                &self.binding,
                &mandate.id,
                &self.service,
                &self.delegation,
                &self.recipient,
                request,
                self.now + 600,
                self.now,
                300,
                |_| true,
            )
        }

        fn scopes(&self) -> BTreeSet<String> {
            self.store
                .authorize_scopes(&self.binding, &self.recipient, self.now, 300, |_| true)
                .unwrap()
        }
    }

    #[test]
    fn profiles_reject_role_write_unknown_scope_unbounded_limits_and_duplicates() {
        assert!(config().validate().is_ok());
        for scope in [
            "admin",
            "roles:write",
            "portfolio:read",
            "metrics:metric:unreviewed",
        ] {
            let mut p = profile();
            p.scopes = BTreeSet::from([scope.into()]);
            assert!(p.validate().is_err());
        }
        for ttl in [0, MAX_ACCESS_TTL + 1, u64::MAX] {
            let mut p = profile();
            p.max_ttl_secs = ttl;
            assert!(p.validate().is_err());
        }
        let mut p = profile();
        p.max_issuances = MAX_ISSUANCES + 1;
        assert!(p.validate().is_err());
        assert!(
            ProvisioningConfig {
                profiles: vec![profile(), profile()]
            }
            .validate()
            .is_err()
        );
        assert!(serde_json::from_value::<AccessProfile>(serde_json::json!({"id":"x","revision":1,"eligible_group":"Engineering","scopes":["metrics:read"],"max_ttl_secs":1,"max_mandate_ttl_secs":1,"max_issuances":1,"role":"admin"})).is_err());
    }

    #[test]
    fn grants_confer_only_profile_scopes_and_never_modify_roles() {
        let f = Fixture::new();
        let parent = f.mandate(2);
        assert!(f.scopes().is_empty());
        let grant = f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
        assert_eq!(f.scopes(), profile().scopes);
        assert_eq!(grant.actor, f.actor);
        assert_eq!(grant.delegation_id, f.delegation);
        assert!(
            f.store
                .get_principal(&f.recipient)
                .unwrap()
                .unwrap()
                .roles
                .is_empty()
        );
        assert_eq!(
            f.store
                .get_mandate(&f.binding, &parent.id)
                .unwrap()
                .issued_count,
            1
        );
    }

    #[test]
    fn concurrent_budget_and_request_replay_never_replenish_allowance() {
        let f = Arc::new(Fixture::new());
        let parent = Arc::new(f.mandate(2));
        let handles = (0..12)
            .map(|_| {
                let f = f.clone();
                let parent = parent.clone();
                std::thread::spawn(move || f.issue(&parent, &Uuid::new_v4().to_string()))
            })
            .collect::<Vec<_>>();
        let granted = handles
            .into_iter()
            .filter_map(|h| h.join().unwrap().ok())
            .collect::<Vec<_>>();
        assert_eq!(granted.len(), 2);
        assert_eq!(
            f.store
                .get_mandate(&f.binding, &parent.id)
                .unwrap()
                .issued_count,
            2
        );

        let other = f.mandate(2);
        let request = Uuid::new_v4().to_string();
        let first = f.issue(&other, &request).unwrap();
        assert_eq!(f.issue(&other, &request).unwrap(), first);
        assert!(
            f.store
                .issue_access(
                    &f.binding,
                    &other.id,
                    &f.service,
                    &f.delegation,
                    &f.recipient,
                    &request,
                    f.now + 601,
                    f.now,
                    300,
                    |_| true
                )
                .is_err()
        );
        assert_eq!(
            f.store
                .get_mandate(&f.binding, &other.id)
                .unwrap()
                .issued_count,
            1
        );
    }

    #[test]
    fn explicit_access_revocation_fences_reissue_until_new_human_mandate() {
        let f = Fixture::new();
        let parent = f.mandate(3);
        let request = Uuid::new_v4().to_string();
        let first = f.issue(&parent, &request).unwrap();
        let sibling = f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
        f.store.revoke_access(&f.binding, &first.id, f.now).unwrap();
        assert!(f.issue(&parent, &request).is_err());
        assert!(f.issue(&parent, &Uuid::new_v4().to_string()).is_err());
        assert!(
            f.store
                .get_access_grant(&f.binding, &sibling.id)
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(f.scopes().is_empty());
        assert_eq!(
            f.store
                .get_mandate(&f.binding, &parent.id)
                .unwrap()
                .issued_count,
            2
        );
        let fresh = f.mandate(1);
        assert!(f.issue(&fresh, &Uuid::new_v4().to_string()).is_ok());
    }

    #[test]
    fn delayed_identical_rpc_retry_returns_original_expiry_without_new_issuance() {
        let f = Fixture::new();
        let parent = f.mandate(2);
        let request = Uuid::new_v4().to_string();
        let original = f.issue(&parent, &request).unwrap();
        let retried = f
            .store
            .issue_access(
                &f.binding,
                &parent.id,
                &f.service,
                &f.delegation,
                &f.recipient,
                &request,
                f.now + 605,
                f.now + 5,
                300,
                |_| true,
            )
            .unwrap();
        assert_eq!(retried, original);
        assert_eq!(retried.expires_at, f.now + 600);
        assert_eq!(
            f.store
                .get_mandate(&f.binding, &parent.id)
                .unwrap()
                .issued_count,
            1
        );
        assert!(
            f.store
                .issue_access(
                    &f.binding,
                    &parent.id,
                    &f.service,
                    &f.delegation,
                    &f.recipient,
                    &request,
                    f.now + 606,
                    f.now + 5,
                    300,
                    |_| true
                )
                .is_err()
        );
        assert!(
            f.store
                .issue_access(
                    &f.binding,
                    &parent.id,
                    &f.service,
                    &f.delegation,
                    &f.recipient,
                    &request,
                    f.now + 5,
                    f.now + 5,
                    300,
                    |_| true
                )
                .is_err()
        );
        assert_eq!(
            f.store
                .get_mandate(&f.binding, &parent.id)
                .unwrap()
                .issued_count,
            1
        );
    }

    #[test]
    fn persona_removal_and_return_cannot_restore_a_grant() {
        let f = Fixture::new();
        let parent = f.mandate(3);
        let grant = f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
        f.snapshot(&[], f.now + 1);
        f.snapshot(&["Engineering"], f.now + 2);
        assert!(
            f.store
                .authorize_scopes(&f.binding, &f.recipient, f.now + 2, 300, |_| true)
                .unwrap()
                .is_empty()
        );
        assert!(
            f.store
                .get_access_grant(&f.binding, &grant.id)
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            f.store
                .issue_access(
                    &f.binding,
                    &parent.id,
                    &f.service,
                    &f.delegation,
                    &f.recipient,
                    &Uuid::new_v4().to_string(),
                    f.now + 600,
                    f.now + 2,
                    300,
                    |_| true
                )
                .is_ok()
        );
    }

    #[test]
    fn stale_persona_denies_and_refresh_does_not_revive_observed_revocation() {
        let f = Fixture::new();
        let parent = f.mandate(2);
        f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
        assert!(
            f.store
                .authorize_scopes(&f.binding, &f.recipient, f.now + 301, 300, |_| true)
                .unwrap()
                .is_empty()
        );
        f.snapshot(&["Engineering"], f.now + 301);
        assert!(
            f.store
                .authorize_scopes(&f.binding, &f.recipient, f.now + 301, 300, |_| true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn policy_change_remove_and_restore_never_restore_old_grants() {
        for remove in [false, true] {
            let f = Fixture::new();
            let parent = f.mandate(2);
            f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
            let mut changed = config();
            if remove {
                changed.profiles.clear();
            } else {
                changed.profiles[0].scopes.insert("metrics:explain".into());
            }
            f.store.sync_profiles(&changed).unwrap();
            f.store.sync_profiles(&config()).unwrap();
            assert!(f.scopes().is_empty());
            assert!(f.issue(&parent, &Uuid::new_v4().to_string()).is_err());
            assert!(
                f.store
                    .provisioning_profile("engineering-metrics")
                    .unwrap()
                    .1
                    > parent.profile_epoch
            );
            assert_eq!(
                f.store
                    .provisioning_profile_at(&parent.profile_id, parent.profile_epoch)
                    .unwrap(),
                profile()
            );
        }
    }

    #[test]
    fn issuer_role_and_disable_restore_preserve_revocation_and_review_epoch() {
        for disabled in [false, true] {
            let f = Fixture::new();
            let parent = f.mandate(2);
            f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
            let old_epoch = f.store.provisioning_principal_epoch(&f.issuer).unwrap();
            if disabled {
                f.store.set_disabled(&f.issuer, true).unwrap();
                f.store.set_disabled(&f.issuer, false).unwrap();
            } else {
                f.store.set_roles(&f.issuer, &BTreeSet::new()).unwrap();
                f.store
                    .set_roles(&f.issuer, &BTreeSet::from([Role::Admin]))
                    .unwrap();
            }
            assert!(f.scopes().is_empty());
            assert!(f.issue(&parent, &Uuid::new_v4().to_string()).is_err());
            assert!(
                f.store
                    .create_mandate(
                        &f.binding,
                        &f.issuer,
                        &f.service,
                        "engineering-metrics",
                        parent.profile_epoch,
                        old_epoch,
                        &f.session,
                        f.now + 3600,
                        1,
                        "credential-1",
                        f.now,
                        |_| true
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn recipient_disable_and_config_readmission_do_not_resurrect_access() {
        let f = Fixture::new();
        let parent = f.mandate(2);
        f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
        f.store.set_disabled(&f.recipient, true).unwrap();
        f.store.set_disabled(&f.recipient, false).unwrap();
        assert!(f.scopes().is_empty());
        let second = f.mandate(2);
        f.issue(&second, &Uuid::new_v4().to_string()).unwrap();
        f.store
            .sync_provisioning_admission(|p| p.id != f.service, f.now)
            .unwrap();
        f.store
            .sync_provisioning_admission(|_| true, f.now)
            .unwrap();
        assert!(f.scopes().is_empty());
        assert!(f.issue(&second, &Uuid::new_v4().to_string()).is_err());
    }

    #[test]
    fn restart_retains_budget_epochs_and_revocation_fences() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.db");
        let f = Fixture::with_store(IdentityStore::open(&path).unwrap());
        let parent = f.mandate(2);
        let grant = f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
        let reopened = IdentityStore::open(&path).unwrap();
        reopened.sync_profiles(&config()).unwrap();
        assert_eq!(
            reopened
                .authorize_scopes(&f.binding, &f.recipient, f.now, 300, |_| true)
                .unwrap(),
            profile().scopes
        );
        reopened
            .revoke_access(&f.binding, &grant.id, f.now)
            .unwrap();
        drop(reopened);
        let reopened = IdentityStore::open(&path).unwrap();
        reopened.sync_profiles(&config()).unwrap();
        assert_eq!(
            reopened
                .get_mandate(&f.binding, &parent.id)
                .unwrap()
                .issued_count,
            1
        );
        assert!(
            reopened
                .issue_access(
                    &f.binding,
                    &parent.id,
                    &f.service,
                    &f.delegation,
                    &f.recipient,
                    &Uuid::new_v4().to_string(),
                    f.now + 600,
                    f.now,
                    300,
                    |_| true
                )
                .is_err()
        );
    }

    #[test]
    fn wrong_binding_service_delegation_and_recipient_fail_without_issuance() {
        let f = Fixture::new();
        let parent = f.mandate(2);
        let other =
            TenantBinding::new(TenantId::parse("engineering").unwrap(), Uuid::new_v4()).unwrap();
        assert!(
            f.store
                .issue_access(
                    &other,
                    &parent.id,
                    &f.service,
                    &f.delegation,
                    &f.recipient,
                    &Uuid::new_v4().to_string(),
                    f.now + 600,
                    f.now,
                    300,
                    |_| true
                )
                .is_err()
        );
        assert!(f.store.get_mandate(&other, &parent.id).is_err());
        assert!(f.store.revoke_mandate(&other, &parent.id, f.now).is_err());
        assert!(
            f.store
                .issue_access(
                    &f.binding,
                    &parent.id,
                    &f.issuer,
                    &f.delegation,
                    &f.recipient,
                    &Uuid::new_v4().to_string(),
                    f.now + 600,
                    f.now,
                    300,
                    |_| true
                )
                .is_err()
        );
        assert!(
            f.store
                .issue_access(
                    &f.binding,
                    &parent.id,
                    &f.service,
                    &f.delegation,
                    &f.service,
                    &Uuid::new_v4().to_string(),
                    f.now + 600,
                    f.now,
                    300,
                    |_| true
                )
                .is_err()
        );
        f.store
            .lock()
            .execute(
                "UPDATE delegations SET revoked_at=?1 WHERE jti=?2",
                params![f.now, f.delegation],
            )
            .unwrap();
        assert!(f.issue(&parent, &Uuid::new_v4().to_string()).is_err());
        assert_eq!(
            f.store
                .get_mandate(&f.binding, &parent.id)
                .unwrap()
                .issued_count,
            0
        );
    }

    #[test]
    fn revoked_login_or_credential_cannot_create_or_retain_authority() {
        let f = Fixture::new();
        let parent = f.mandate(2);
        f.issue(&parent, &Uuid::new_v4().to_string()).unwrap();
        f.store
            .revoke_by_credential(&f.binding, "credential-1", f.now)
            .unwrap();
        assert!(f.scopes().is_empty());
        f.store.revoke_all_human_sessions().unwrap();
        assert!(
            f.store
                .create_mandate(
                    &f.binding,
                    &f.issuer,
                    &f.service,
                    "engineering-metrics",
                    parent.profile_epoch,
                    f.store.provisioning_principal_epoch(&f.issuer).unwrap(),
                    &f.session,
                    f.now + 3600,
                    1,
                    "credential-2",
                    f.now,
                    |_| true
                )
                .is_err()
        );
    }

    #[test]
    fn credential_removal_during_verified_ceremony_blocks_late_commit_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.db");
        let f = Arc::new(Fixture::with_store(IdentityStore::open(&path).unwrap()));
        let verified = Arc::new(std::sync::Barrier::new(2));
        let removed = Arc::new(std::sync::Barrier::new(2));
        let ceremony = {
            let f = f.clone();
            let verified = verified.clone();
            let removed = removed.clone();
            std::thread::spawn(move || {
                // The API has already verified possession and retained the
                // credential ID; revocation lands before its store commit.
                verified.wait();
                removed.wait();
                f.try_mandate(1, "credential-1")
            })
        };
        verified.wait();
        f.store
            .revoke_by_credential(&f.binding, "credential-1", f.now)
            .unwrap();
        removed.wait();
        assert!(ceremony.join().unwrap().is_err());
        assert!(f.store.list_mandates(&f.binding).unwrap().is_empty());

        let binding = f.binding.clone();
        drop(f);
        let mut reopened = Fixture::with_store(IdentityStore::open(&path).unwrap());
        reopened.binding = binding;
        assert!(reopened.try_mandate(1, "credential-1").is_err());
        assert!(reopened.try_mandate(1, "new-credential").is_ok());
    }

    #[test]
    fn racing_credential_removal_never_leaves_a_live_mandate() {
        for _ in 0..16 {
            let f = Arc::new(Fixture::new());
            let start = Arc::new(std::sync::Barrier::new(2));
            let ceremony = {
                let f = f.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    f.try_mandate(1, "credential-1")
                })
            };
            start.wait();
            f.store
                .revoke_by_credential(&f.binding, "credential-1", f.now)
                .unwrap();
            let outcome = ceremony.join().unwrap();
            let mandates = f.store.list_mandates(&f.binding).unwrap();
            assert!(mandates.iter().all(|mandate| mandate.revoked_at.is_some()));
            if let Ok(mandate) = outcome {
                assert!(f.issue(&mandate, &Uuid::new_v4().to_string()).is_err());
            }
        }
    }
}
