//! Fresh IdP persona evidence. Only the signed OIDC verifier constructs claims;
//! RPC inputs never supply groups, timestamps or snapshot revisions.

use opaque_core::identity::PrincipalId;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::store::IdentityStore;

const MAX_GROUPS: usize = 128;
const MAX_GROUP_BYTES: usize = 256;
const MAX_TOTAL_GROUP_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaConfig {
    pub groups_claim: String,
    pub max_age_secs: u64,
}

impl PersonaConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=3600).contains(&self.max_age_secs) {
            return Err("invalid [identity.persona] max_age_secs: expected 1..=3600".into());
        }
        let name = self.groups_claim.as_bytes();
        if name.is_empty()
            || name.len() > 128
            || !name[0].is_ascii_alphabetic()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte))
            || matches!(
                self.groups_claim.as_str(),
                "iss"
                    | "sub"
                    | "aud"
                    | "exp"
                    | "iat"
                    | "nbf"
                    | "auth_time"
                    | "nonce"
                    | "azp"
                    | "email"
                    | "email_verified"
                    | "name"
            )
        {
            return Err("invalid [identity.persona] groups_claim".into());
        }
        Ok(())
    }
}

/// Constructor is restricted to the identity implementation. This evidence is
/// produced from claims already verified for signature, issuer, audience/nonce.
#[derive(Debug, Clone)]
pub struct VerifiedPersonaClaims {
    issuer: String,
    subject: String,
    groups: Vec<String>,
    issued_at: i64,
    expires_at: i64,
    auth_time: i64,
    max_age_secs: u64,
    policy_fingerprint: String,
}

impl VerifiedPersonaClaims {
    /// Synthetic evidence for daemon integration tests only. Production callers
    /// must use the signed OIDC verifier; this constructor is absent in builds.
    #[cfg(test)]
    pub(crate) fn test_claims(
        issuer: &str,
        subject: &str,
        config: &PersonaConfig,
        groups: &[&str],
        now: i64,
    ) -> Self {
        let mut claims = serde_json::json!({
            "iat": now, "exp": now + 3600, "auth_time": now
        });
        claims[&config.groups_claim] = serde_json::json!(groups);
        Self::from_verified_claims(issuer, subject, config, claims.as_object().unwrap(), now)
            .expect("valid synthetic persona fixture")
    }

    pub(super) fn from_verified_claims(
        issuer: &str,
        subject: &str,
        config: &PersonaConfig,
        claims: &serde_json::Map<String, serde_json::Value>,
        now: i64,
    ) -> Result<Self, String> {
        config.validate()?;
        let integer = |key: &str| {
            claims
                .get(key)
                .and_then(serde_json::Value::as_i64)
                .ok_or_else(|| "id_token missing or invalid persona timestamp".to_string())
        };
        let groups = claims
            .get(&config.groups_claim)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "id_token missing or invalid persona groups".to_string())?;
        if groups.len() > MAX_GROUPS {
            return Err("id_token persona groups exceed limits".into());
        }
        let groups = groups
            .iter()
            .map(|group| {
                group
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "id_token persona groups must be exact strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let verified = Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            groups: normalize_groups(&groups)?,
            issued_at: integer("iat")?,
            expires_at: integer("exp")?,
            auth_time: integer("auth_time")?,
            max_age_secs: config.max_age_secs,
            policy_fingerprint: policy_fingerprint(Some(config))?,
        };
        if !verified.valid_at(now) {
            return Err(
                "id_token persona authentication or issuance is stale, expired or future".into(),
            );
        }
        Ok(verified)
    }

    fn valid_at(&self, now: i64) -> bool {
        self.auth_time >= 0
            && self.auth_time <= self.issued_at
            && self.issued_at <= now
            && self.expires_at > now
            && self.expires_at > self.issued_at
            && now - self.auth_time <= self.max_age_secs as i64
            && now - self.issued_at <= self.max_age_secs as i64
    }
}

fn policy_fingerprint(config: Option<&PersonaConfig>) -> Result<String, String> {
    if let Some(config) = config {
        config.validate()?;
    }
    // An explicitly versioned serialization of this fixed two-field config is
    // deterministic; no group membership, identity data or credentials enter it.
    let encoded =
        serde_json::to_vec(&config).map_err(|_| "persona policy cannot be encoded".to_string())?;
    let mut hash = Sha256::new();
    hash.update(b"opaque.persona-policy.v1\0");
    hash.update(encoded);
    Ok(format!("{:x}", hash.finalize()))
}

fn normalize_groups(groups: &[String]) -> Result<Vec<String>, String> {
    if groups.len() > MAX_GROUPS
        || groups.iter().any(|group| {
            group.is_empty() || group.len() > MAX_GROUP_BYTES || group.chars().any(char::is_control)
        })
        || groups.iter().map(String::len).sum::<usize>() > MAX_TOTAL_GROUP_BYTES
    {
        return Err("persona groups exceed bounds or contain invalid strings".into());
    }
    // Canonicalize set order and duplicate membership only. Case, whitespace and
    // punctuation remain exact IdP identifiers; no trimming or role inference.
    let mut normalized = groups.to_vec();
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonaSnapshot {
    pub principal_id: PrincipalId,
    pub groups: Vec<String>,
    pub observed_at: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revision: i64,
}

impl PersonaSnapshot {
    /// Recheck at every provisioning boundary; a login session's longer TTL
    /// never extends the freshness of these independently bounded claims.
    pub fn is_fresh(&self, now: i64, max_age_secs: u64) -> bool {
        if !(1..=3600).contains(&max_age_secs)
            || self.revision < 1
            || self.issued_at < 0
            || self.issued_at > self.observed_at
            || self.observed_at > now
            || self.expires_at <= self.observed_at
        {
            return false;
        }
        let max_age = max_age_secs as i64;
        self.observed_at
            .checked_add(max_age)
            .zip(self.issued_at.checked_add(max_age))
            .is_some_and(|(observation_limit, issuance_limit)| {
                now <= observation_limit.min(issuance_limit).min(self.expires_at)
            })
    }
}

pub(super) fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS persona_snapshots (
            principal_id TEXT PRIMARY KEY,
            groups_json TEXT NOT NULL,
            observed_at INTEGER NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revision INTEGER NOT NULL CHECK (revision >= 1)
        );
        CREATE TABLE IF NOT EXISTS identity_persona_policy (
            singleton INTEGER PRIMARY KEY CHECK (singleton=1),
            fingerprint TEXT NOT NULL
        );",
    )
    .map_err(|_| "persona schema unavailable".to_string())
}

/// Shared with the provisioning engine so it can read under its transaction's
/// existing identity-store lock, without a second lock or authorization cache.
pub(super) fn read_snapshot(
    conn: &Connection,
    principal_id: &PrincipalId,
) -> Result<Option<PersonaSnapshot>, String> {
    ensure_schema(conn)?;
    let row = conn
        .query_row(
            "SELECT groups_json, observed_at, issued_at, expires_at, revision
             FROM persona_snapshots WHERE principal_id=?1",
            params![principal_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| "persona snapshot unavailable".to_string())?;
    let Some((groups_json, observed_at, issued_at, expires_at, revision)) = row else {
        return Ok(None);
    };
    if groups_json.len() > MAX_TOTAL_GROUP_BYTES * 2 + MAX_GROUPS * 3 + 2 {
        return Err("invalid stored persona snapshot".into());
    }
    let groups: Vec<String> = serde_json::from_str(&groups_json)
        .map_err(|_| "invalid stored persona groups".to_string())?;
    let invalidated = observed_at == 0 && issued_at == 0 && expires_at == 0;
    if normalize_groups(&groups)? != groups
        || revision < 1
        || (!invalidated && (issued_at < 0 || issued_at > observed_at || expires_at <= observed_at))
    {
        return Err("invalid stored persona snapshot".into());
    }
    Ok(Some(PersonaSnapshot {
        principal_id: principal_id.clone(),
        groups,
        observed_at,
        issued_at,
        expires_at,
        revision,
    }))
}

impl IdentityStore {
    /// Retain monotonically increasing generations across policy changes,
    /// disable/restore and first startup with preexisting persona snapshots.
    pub fn sync_persona_policy(&self, config: Option<&PersonaConfig>) -> Result<(), String> {
        let fingerprint = policy_fingerprint(config)?;
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "persona policy transaction unavailable".to_string())?;
        let previous: Option<String> = transaction
            .query_row(
                "SELECT fingerprint FROM identity_persona_policy WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| "persona policy unavailable".to_string())?;
        if previous.as_deref() != Some(&fingerprint) {
            let exhausted: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM persona_snapshots WHERE revision=?1)",
                    params![i64::MAX],
                    |row| row.get(0),
                )
                .map_err(|_| "persona revisions unavailable".to_string())?;
            if exhausted {
                return Err("persona revision exhausted".into());
            }
            transaction.execute(
                "UPDATE persona_snapshots SET revision=revision+1, observed_at=0, issued_at=0, expires_at=0", [],
            ).map_err(|_| "persona snapshots could not be invalidated".to_string())?;
            transaction
                .execute(
                    "INSERT INTO identity_persona_policy (singleton,fingerprint) VALUES (1,?1)
                 ON CONFLICT(singleton) DO UPDATE SET fingerprint=excluded.fingerprint",
                    params![fingerprint],
                )
                .map_err(|_| "persona policy could not be stored".to_string())?;
        }
        transaction
            .commit()
            .map_err(|_| "persona policy could not be committed".to_string())
    }

    pub fn record_persona_snapshot(
        &self,
        principal_id: &PrincipalId,
        claims: &VerifiedPersonaClaims,
        observed_at: i64,
    ) -> Result<PersonaSnapshot, String> {
        if !claims.valid_at(observed_at) {
            return Err("verified persona claims are no longer fresh".into());
        }
        let mut conn = self.lock();
        ensure_schema(&conn)?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "persona transaction unavailable".to_string())?;
        let current_policy: Option<String> = transaction
            .query_row(
                "SELECT fingerprint FROM identity_persona_policy WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| "persona policy unavailable".to_string())?;
        if current_policy.as_deref() != Some(&claims.policy_fingerprint) {
            return Err("verified persona policy is no longer current".into());
        }
        let admitted: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM principals
                 WHERE id=?1 AND kind='human' AND iss=?2 AND sub=?3 AND disabled=0)",
                params![principal_id.as_str(), claims.issuer, claims.subject],
                |row| row.get(0),
            )
            .map_err(|_| "persona principal unavailable".to_string())?;
        if !admitted {
            return Err("persona claims do not belong to an enabled human principal".into());
        }
        let previous = read_snapshot(&transaction, principal_id)?;
        if previous.as_ref().is_some_and(|previous| {
            claims.issued_at < previous.issued_at || observed_at < previous.observed_at
        }) {
            return Err("older persona evidence cannot replace a newer snapshot".into());
        }
        let revision = match previous {
            None => 1,
            Some(previous) if previous.groups == claims.groups => previous.revision,
            Some(previous) => previous
                .revision
                .checked_add(1)
                .ok_or_else(|| "persona revision exhausted".to_string())?,
        };
        let groups_json = serde_json::to_string(&claims.groups)
            .map_err(|_| "persona groups cannot be encoded".to_string())?;
        transaction
            .execute(
                "INSERT INTO persona_snapshots
                 (principal_id,groups_json,observed_at,issued_at,expires_at,revision)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(principal_id) DO UPDATE SET groups_json=excluded.groups_json,
                 observed_at=excluded.observed_at, issued_at=excluded.issued_at,
                 expires_at=excluded.expires_at, revision=excluded.revision",
                params![
                    principal_id.as_str(),
                    groups_json,
                    observed_at,
                    claims.issued_at,
                    claims.expires_at,
                    revision
                ],
            )
            .map_err(|_| "persona snapshot could not be persisted".to_string())?;
        transaction
            .commit()
            .map_err(|_| "persona snapshot could not be committed".to_string())?;
        Ok(PersonaSnapshot {
            principal_id: principal_id.clone(),
            groups: claims.groups.clone(),
            observed_at,
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            revision,
        })
    }

    pub fn persona_snapshot(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<PersonaSnapshot>, String> {
        read_snapshot(&self.lock(), principal_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const ISSUER: &str = "https://idp.example.com";
    const NOW: i64 = 10_000;

    fn config() -> PersonaConfig {
        PersonaConfig {
            groups_claim: "groups".into(),
            max_age_secs: 60,
        }
    }

    fn verified(groups: &[&str], now: i64) -> VerifiedPersonaClaims {
        VerifiedPersonaClaims::from_verified_claims(
            ISSUER,
            "subject",
            &config(),
            serde_json::json!({"groups":groups,"iat":now,"exp":now+600,"auth_time":now})
                .as_object()
                .unwrap(),
            now,
        )
        .unwrap()
    }

    fn principal(store: &IdentityStore, subject: &str) -> PrincipalId {
        store.sync_persona_policy(Some(&config())).unwrap();
        store
            .upsert_human(ISSUER, subject, None, None, &BTreeSet::new())
            .unwrap()
            .id
    }

    #[test]
    fn persona_config_rejects_unsafe_claim_names_and_freshness_ranges() {
        for groups_claim in [
            "",
            "aud",
            "iat",
            "groups[0]",
            "groups\n",
            "/groups",
            " groups",
            "grøups",
        ] {
            assert!(
                PersonaConfig {
                    groups_claim: groups_claim.into(),
                    ..config()
                }
                .validate()
                .is_err()
            );
        }
        for max_age_secs in [0, 3601, u64::MAX] {
            assert!(
                PersonaConfig {
                    max_age_secs,
                    ..config()
                }
                .validate()
                .is_err()
            );
        }
        for groups_claim in ["groups", "team.groups", "Organization_Groups-v2"] {
            assert!(
                PersonaConfig {
                    groups_claim: groups_claim.into(),
                    ..config()
                }
                .validate()
                .is_ok()
            );
        }
        assert!(
            serde_json::from_value::<PersonaConfig>(serde_json::json!({
                "groups_claim":"groups","max_age_secs":60,"accept_unsigned":true
            }))
            .is_err()
        );
    }

    #[test]
    fn claims_require_recent_signed_timestamps_and_bounded_exact_groups() {
        let valid = serde_json::json!({"groups":["Team","team","team"],"iat":NOW,"exp":NOW+60,"auth_time":NOW-60});
        let accepted = VerifiedPersonaClaims::from_verified_claims(
            ISSUER,
            "subject",
            &config(),
            valid.as_object().unwrap(),
            NOW,
        )
        .unwrap();
        assert_eq!(accepted.groups, vec!["Team", "team"]);
        let mut invalid = Vec::new();
        for field in ["groups", "iat", "exp", "auth_time"] {
            let mut claims = valid.clone();
            claims.as_object_mut().unwrap().remove(field);
            invalid.push(claims);
        }
        for (field, value) in [
            ("iat", serde_json::json!(NOW + 1)),
            ("iat", serde_json::json!(NOW - 61)),
            ("iat", serde_json::json!("10000")),
            ("auth_time", serde_json::json!(NOW + 1)),
            ("auth_time", serde_json::json!(NOW - 61)),
            ("auth_time", serde_json::json!(-1)),
            ("exp", serde_json::json!(NOW)),
            ("groups", serde_json::json!("team")),
            ("groups", serde_json::json!(["team", 42])),
            ("groups", serde_json::json!([""])),
            ("groups", serde_json::json!(["team\nadmin"])),
            (
                "groups",
                serde_json::json!(["x".repeat(MAX_GROUP_BYTES + 1)]),
            ),
            ("groups", serde_json::json!(vec!["team"; MAX_GROUPS + 1])),
            (
                "groups",
                serde_json::json!(vec!["x".repeat(MAX_GROUP_BYTES); MAX_GROUPS]),
            ),
        ] {
            let mut claims = valid.clone();
            claims[field] = value;
            invalid.push(claims);
        }
        for claims in invalid {
            assert!(
                VerifiedPersonaClaims::from_verified_claims(
                    ISSUER,
                    "subject",
                    &config(),
                    claims.as_object().unwrap(),
                    NOW
                )
                .is_err()
            );
        }
    }

    #[test]
    fn group_revision_survives_restart_and_removal_readdition() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.db");
        let store = IdentityStore::open(&path).unwrap();
        let id = principal(&store, "subject");
        assert!(store.persona_snapshot(&id).unwrap().is_none());
        let first = store
            .record_persona_snapshot(&id, &verified(&["b", "a"], NOW), NOW)
            .unwrap();
        assert_eq!(first.groups, vec!["a", "b"]);
        assert_eq!(first.revision, 1);
        let unchanged = store
            .record_persona_snapshot(&id, &verified(&["a", "b", "b"], NOW + 1), NOW + 1)
            .unwrap();
        assert_eq!(unchanged.revision, 1);
        assert_eq!(unchanged.observed_at, NOW + 1);
        let removed = store
            .record_persona_snapshot(&id, &verified(&[], NOW + 2), NOW + 2)
            .unwrap();
        assert_eq!(removed.revision, 2);
        drop(store);
        let store = IdentityStore::open(&path).unwrap();
        assert_eq!(store.persona_snapshot(&id).unwrap().unwrap().revision, 2);
        let restored = store
            .record_persona_snapshot(&id, &verified(&["b", "a"], NOW + 3), NOW + 3)
            .unwrap();
        assert_eq!(restored.revision, 3);
        assert!(
            store
                .record_persona_snapshot(&id, &verified(&["other"], NOW + 2), NOW + 4)
                .is_err()
        );
        assert_eq!(store.persona_snapshot(&id).unwrap().unwrap().revision, 3);
    }

    #[test]
    fn snapshot_freshness_uses_observation_issuance_and_token_expiry() {
        let store = IdentityStore::open_in_memory().unwrap();
        let id = principal(&store, "subject");
        let snapshot = store
            .record_persona_snapshot(&id, &verified(&["reviewer"], NOW), NOW + 5)
            .unwrap();
        assert!(!snapshot.is_fresh(NOW + 4, 60));
        assert!(snapshot.is_fresh(NOW + 60, 60));
        assert!(!snapshot.is_fresh(NOW + 61, 60));
        let expires = PersonaSnapshot {
            expires_at: NOW + 10,
            ..snapshot.clone()
        };
        assert!(expires.is_fresh(NOW + 10, 60));
        assert!(!expires.is_fresh(NOW + 11, 60));
        assert!(!snapshot.is_fresh(NOW + 5, 0));
        assert!(!snapshot.is_fresh(NOW + 5, u64::MAX));
        assert!(
            store
                .record_persona_snapshot(&id, &verified(&[], NOW), NOW + 61)
                .is_err()
        );
    }

    #[test]
    fn verified_claims_cannot_move_to_other_or_disabled_principals() {
        let store = IdentityStore::open_in_memory().unwrap();
        let id = principal(&store, "subject");
        let other = principal(&store, "other");
        assert!(
            store
                .record_persona_snapshot(&other, &verified(&["reviewer"], NOW), NOW)
                .is_err()
        );
        store.set_disabled(&id, true).unwrap();
        assert!(
            store
                .record_persona_snapshot(&id, &verified(&["reviewer"], NOW), NOW)
                .is_err()
        );
        assert!(store.persona_snapshot(&id).unwrap().is_none());
    }

    #[test]
    fn policy_change_disable_restore_and_untracked_old_policy_invalidate_without_resetting_revision()
     {
        let store = IdentityStore::open_in_memory().unwrap();
        let id = principal(&store, "subject");
        let original = verified(&["reviewers"], NOW);
        store.record_persona_snapshot(&id, &original, NOW).unwrap();
        store.sync_persona_policy(Some(&config())).unwrap();
        assert_eq!(store.persona_snapshot(&id).unwrap().unwrap().revision, 1);

        let changed = PersonaConfig {
            max_age_secs: 120,
            ..config()
        };
        store.sync_persona_policy(Some(&changed)).unwrap();
        let invalidated = store.persona_snapshot(&id).unwrap().unwrap();
        assert_eq!(invalidated.revision, 2);
        assert_eq!(
            (
                invalidated.observed_at,
                invalidated.issued_at,
                invalidated.expires_at
            ),
            (0, 0, 0)
        );
        assert!(!invalidated.is_fresh(NOW, 120));
        assert!(store.record_persona_snapshot(&id, &original, NOW).is_err());

        store.sync_persona_policy(None).unwrap();
        store.sync_persona_policy(Some(&config())).unwrap();
        assert_eq!(store.persona_snapshot(&id).unwrap().unwrap().revision, 4);
        let refreshed = store
            .record_persona_snapshot(&id, &verified(&["reviewers"], NOW + 1), NOW + 1)
            .unwrap();
        assert_eq!(refreshed.revision, 4);
        assert!(refreshed.is_fresh(NOW + 1, 60));

        store
            .sync_persona_policy(Some(&PersonaConfig {
                groups_claim: "other_groups".into(),
                ..config()
            }))
            .unwrap();
        assert_eq!(store.persona_snapshot(&id).unwrap().unwrap().revision, 5);
        store
            .lock()
            .execute("DELETE FROM identity_persona_policy", [])
            .unwrap();
        store.sync_persona_policy(Some(&config())).unwrap();
        assert_eq!(store.persona_snapshot(&id).unwrap().unwrap().revision, 6);
    }
}
