//! Persistent identity store: principals, human login sessions, delegations.
//!
//! A small SQLite database at `<state_dir>/identity.db` (mode 0600), sibling
//! to `audit.db`. Schema is `CREATE TABLE IF NOT EXISTS` like the audit sink —
//! no migration framework exists in this codebase. Rows convert to/from the
//! shared `opaque_core::identity` types.
//!
//! Liveness vs. record: human sessions and delegations are *records* with
//! expiry/revocation columns; in-memory agent-session liveness stays where it
//! is (fail closed on daemon restart).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

use opaque_core::identity::{
    AccessMode, Principal, PrincipalId, PrincipalKind, Role, now_unix, roles_from_string,
    roles_to_string,
};
use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS principals (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    iss          TEXT,
    sub          TEXT,
    email        TEXT,
    display_name TEXT,
    tool         TEXT,
    service_name TEXT,
    roles        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    disabled     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_principals_human
    ON principals(iss, sub) WHERE kind = 'human';
CREATE UNIQUE INDEX IF NOT EXISTS idx_principals_agent
    ON principals(tool) WHERE kind = 'agent';
CREATE UNIQUE INDEX IF NOT EXISTS idx_principals_service
    ON principals(service_name) WHERE kind = 'service';

CREATE TABLE IF NOT EXISTS human_sessions (
    id           TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    idp_issuer   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_active
    ON human_sessions(expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS delegations (
    jti              TEXT PRIMARY KEY,
    sub_principal    TEXT NOT NULL,
    act_principal    TEXT NOT NULL,
    mode             TEXT NOT NULL,
    human_session_id TEXT,
    approved_by      TEXT,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    revoked_at       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_delegations_sub ON delegations(sub_principal);

-- Resource revocations live with broker identity; gateways never open this DB.
CREATE TABLE IF NOT EXISTS resource_revocations (
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NOT NULL,
    PRIMARY KEY (issuer, audience, jti)
);
"#;

/// A human login session row.
#[derive(Debug, Clone)]
pub struct HumanSession {
    pub id: String,
    pub principal_id: PrincipalId,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub idp_issuer: String,
}

/// A delegation record (the audit-side trace of an agent session grant).
#[derive(Debug, Clone)]
pub struct DelegationRecord {
    pub jti: String,
    pub sub_principal: PrincipalId,
    pub act_principal: PrincipalId,
    pub mode: AccessMode,
    pub human_session_id: Option<String>,
    pub approved_by: Option<PrincipalId>,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

/// Thread-safe handle to the identity database.
pub struct IdentityStore {
    conn: Mutex<Connection>,
}

impl IdentityStore {
    /// Open (creating if necessary) the identity DB at `path`, mode 0600.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA_SQL).map_err(|e| e.to_string())?;
        super::lifecycle::ensure_schema(&conn)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory store for tests.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA_SQL).map_err(|e| e.to_string())?;
        super::lifecycle::ensure_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // -- principals ---------------------------------------------------------

    /// Upsert a human principal by (iss, sub). Refreshes email/display name
    /// and `last_seen` on every login. Returns the stored principal.
    pub fn upsert_human(
        &self,
        iss: &str,
        sub: &str,
        email: Option<&str>,
        name: Option<&str>,
        initial_roles: &BTreeSet<Role>,
    ) -> Result<Principal, String> {
        let kind = PrincipalKind::Human {
            iss: iss.to_owned(),
            sub: sub.to_owned(),
            email: email.map(str::to_owned),
            name: name.map(str::to_owned),
        };
        kind.validate().map_err(|e| e.to_string())?;

        let now = now_unix();
        let conn = self.lock();
        let managed: bool = conn
            .query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_config)", [], |r| {
                r.get(0)
            })
            .map_err(|_| "lifecycle configuration unavailable")?;
        if managed {
            let admitted: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_subjects r JOIN lifecycle_config c ON c.issuer=?1 AND c.suspended=0 JOIN principals p ON p.id=r.principal_id AND p.disabled=0 WHERE r.subject=?2 AND r.deleted=0 AND r.active=1)",params![iss,sub],|r|r.get(0)).map_err(|_|"lifecycle admission unavailable")?;
            if !admitted {
                return Err("identity must be actively provisioned before login".into());
            }
        }
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM principals WHERE kind='human' AND iss=?1 AND sub=?2",
                params![iss, sub],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;

        let id = match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE principals SET email=?1, display_name=?2, last_seen=?3 WHERE id=?4",
                    params![email, name, now, id],
                )
                .map_err(|e| e.to_string())?;
                id
            }
            None => {
                let id = PrincipalId::generate(&kind);
                conn.execute(
                    "INSERT INTO principals \
                     (id, kind, iss, sub, email, display_name, roles, created_at, last_seen) \
                     VALUES (?1,'human',?2,?3,?4,?5,?6,?7,?7)",
                    params![
                        id.as_str(),
                        iss,
                        sub,
                        email,
                        name,
                        roles_to_string(initial_roles),
                        now
                    ],
                )
                .map_err(|e| e.to_string())?;
                id.as_str().to_owned()
            }
        };
        drop(conn);
        self.get_principal_by_str(&id)?
            .ok_or_else(|| "principal vanished during upsert".into())
    }

    /// Upsert an agent workload principal by tool name.
    pub fn upsert_agent(&self, tool: &str) -> Result<Principal, String> {
        let kind = PrincipalKind::Agent {
            tool: tool.to_owned(),
        };
        kind.validate().map_err(|e| e.to_string())?;
        let now = now_unix();
        let conn = self.lock();
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM principals WHERE kind='agent' AND tool=?1",
                params![tool],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let id = match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE principals SET last_seen=?1 WHERE id=?2",
                    params![now, id],
                )
                .map_err(|e| e.to_string())?;
                id
            }
            None => {
                let id = PrincipalId::generate(&kind);
                conn.execute(
                    "INSERT INTO principals (id, kind, tool, roles, created_at, last_seen) \
                     VALUES (?1,'agent',?2,'',?3,?3)",
                    params![id.as_str(), tool, now],
                )
                .map_err(|e| e.to_string())?;
                id.as_str().to_owned()
            }
        };
        drop(conn);
        self.get_principal_by_str(&id)?
            .ok_or_else(|| "principal vanished during upsert".into())
    }

    /// Upsert a service principal by name (roles set separately).
    pub fn upsert_service(&self, name: &str) -> Result<Principal, String> {
        let kind = PrincipalKind::Service {
            name: name.to_owned(),
        };
        kind.validate().map_err(|e| e.to_string())?;
        let now = now_unix();
        let conn = self.lock();
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM principals WHERE kind='service' AND service_name=?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let id = match existing {
            Some(id) => {
                conn.execute(
                    "UPDATE principals SET last_seen=?1 WHERE id=?2",
                    params![now, id],
                )
                .map_err(|e| e.to_string())?;
                id
            }
            None => {
                let id = PrincipalId::generate(&kind);
                conn.execute(
                    "INSERT INTO principals (id, kind, service_name, roles, created_at, last_seen) \
                     VALUES (?1,'service',?2,'',?3,?3)",
                    params![id.as_str(), name, now],
                )
                .map_err(|e| e.to_string())?;
                id.as_str().to_owned()
            }
        };
        drop(conn);
        self.get_principal_by_str(&id)?
            .ok_or_else(|| "principal vanished during upsert".into())
    }

    pub fn get_principal(&self, id: &PrincipalId) -> Result<Option<Principal>, String> {
        self.get_principal_by_str(id.as_str())
    }

    /// Exact issuer+subject lookup; OAuth access never bootstraps an identity.
    pub fn get_human_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<Principal>, String> {
        self.lock().query_row(
            "SELECT id, kind, iss, sub, email, display_name, tool, service_name, roles, created_at, last_seen, disabled FROM principals WHERE kind='human' AND iss=?1 AND sub=?2",
            params![issuer, subject], row_to_principal,
        ).optional().map_err(|e| e.to_string())
    }

    pub fn resource_token_revoked(
        &self,
        issuer: &str,
        audience: &str,
        jti: &str,
    ) -> Result<bool, String> {
        self.lock().query_row(
            "SELECT EXISTS(SELECT 1 FROM resource_revocations WHERE issuer=?1 AND audience=?2 AND jti=?3)",
            params![issuer, audience, jti], |row| row.get(0),
        ).map_err(|e| e.to_string())
    }

    /// Monotonic and durable. Scoped by issuer and resource, with expiry only
    /// for retention metadata; checks never forget a revoked token on restart.
    pub fn revoke_resource_token(
        &self,
        issuer: &str,
        audience: &str,
        jti: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        self.lock().execute(
            "INSERT INTO resource_revocations(issuer,audience,jti,expires_at,revoked_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(issuer,audience,jti) DO UPDATE SET expires_at=MAX(expires_at,excluded.expires_at)",
            params![issuer, audience, jti, expires_at, now_unix()],
        ).map(|_| ()).map_err(|e| e.to_string())
    }

    /// Look up a service principal by its configured name.
    pub fn get_service_by_name(&self, name: &str) -> Result<Option<Principal>, String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, kind, iss, sub, email, display_name, tool, service_name, \
                    roles, created_at, last_seen, disabled \
             FROM principals WHERE kind='service' AND service_name=?1",
            params![name],
            row_to_principal,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    fn get_principal_by_str(&self, id: &str) -> Result<Option<Principal>, String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, kind, iss, sub, email, display_name, tool, service_name, \
                    roles, created_at, last_seen, disabled \
             FROM principals WHERE id=?1",
            params![id],
            row_to_principal,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// All principals, stable order (created_at, id).
    pub fn list_principals(&self) -> Result<Vec<Principal>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, iss, sub, email, display_name, tool, service_name, \
                        roles, created_at, last_seen, disabled \
                 FROM principals ORDER BY created_at, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], row_to_principal)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Enable or disable a principal (revocation switch).
    #[cfg(test)]
    pub fn set_disabled(&self, id: &PrincipalId, disabled: bool) -> Result<(), String> {
        let conn = self.lock();
        let n = conn
            .execute(
                "UPDATE principals SET disabled=?1 WHERE id=?2",
                params![disabled as i64, id.as_str()],
            )
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("no such principal".into());
        }
        Ok(())
    }

    /// Replace a principal's role set.
    pub fn set_roles(&self, id: &PrincipalId, roles: &BTreeSet<Role>) -> Result<(), String> {
        let conn = self.lock();
        let n = conn
            .execute(
                "UPDATE principals SET roles=?1 WHERE id=?2",
                params![roles_to_string(roles), id.as_str()],
            )
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("no such principal".into());
        }
        Ok(())
    }

    /// Apply exactly the reviewed role replacement under one writer lock.
    /// Concurrent approvals cannot remove both remaining admins or overwrite
    /// an intervening role change with an obsolete review.
    /// `permitted` must inspect immutable runtime membership configuration only;
    /// it must not call back into this store while its writer lock is held.
    pub fn set_reviewed_roles(
        &self,
        actor: &PrincipalId,
        id: &PrincipalId,
        expected: &str,
        roles: &BTreeSet<Role>,
        permitted: impl Fn(&Principal) -> bool,
    ) -> Result<(), String> {
        let mut conn = self.lock();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let eligible_admins = {
            let mut statement = transaction.prepare(
                "SELECT id, kind, iss, sub, email, display_name, tool, service_name, \
                        roles, created_at, last_seen, disabled \
                 FROM principals WHERE kind='human' AND disabled=0 AND instr(',' || roles || ',', ',admin,') > 0",
            ).map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], row_to_principal)
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
                .into_iter()
                .filter(|principal| permitted(principal))
                .map(|principal| principal.id)
                .collect::<Vec<_>>()
        };
        let authorized = eligible_admins.contains(actor);
        let current: Option<String> = transaction
            .query_row(
                "SELECT roles FROM principals WHERE id=?1",
                params![id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(current) = current else {
            return Err("no such principal".into());
        };
        if !authorized || current != expected {
            return Err("reviewed identity authority changed".into());
        }
        if eligible_admins.contains(id)
            && !roles.contains(&Role::Admin)
            && eligible_admins.len() <= 1
        {
            return Err("cannot remove the last admitted human admin".into());
        }
        transaction
            .execute(
                "UPDATE principals SET roles=?1 WHERE id=?2",
                params![roles_to_string(roles), id.as_str()],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    /// Number of (non-disabled) human principals — bootstrap check.
    pub fn count_humans(&self) -> Result<u64, String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM principals WHERE kind='human' AND disabled=0",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n as u64)
        .map_err(|e| e.to_string())
    }

    /// Number of enabled principals holding `role`.
    #[cfg(test)]
    pub fn count_with_role(&self, role: Role) -> Result<u64, String> {
        let principals = self.list_principals()?;
        Ok(principals
            .iter()
            .filter(|p| !p.disabled && p.has_role(role))
            .count() as u64)
    }

    // -- human sessions -----------------------------------------------------

    /// Create a login session for `principal`, valid for `ttl_secs`.
    #[cfg(test)]
    pub fn create_human_session(
        &self,
        principal: &PrincipalId,
        ttl_secs: u64,
        idp_issuer: &str,
    ) -> Result<HumanSession, String> {
        self.create_human_session_at_revision(
            principal,
            ttl_secs,
            idp_issuer,
            self.lifecycle_revision()?,
        )
    }

    pub fn create_human_session_at_revision(
        &self,
        principal: &PrincipalId,
        ttl_secs: u64,
        idp_issuer: &str,
        expected_revision: i64,
    ) -> Result<HumanSession, String> {
        if !principal.is_human() {
            return Err("sessions can only be created for human principals".into());
        }
        let now = now_unix();
        let session = HumanSession {
            id: format!("hses_{}", uuid::Uuid::new_v4().simple()),
            principal_id: principal.clone(),
            created_at: now,
            expires_at: now + ttl_secs as i64,
            revoked_at: None,
            idp_issuer: idp_issuer.to_owned(),
        };
        let conn = self.lock();
        let revision: i64 = conn
            .query_row(
                "SELECT revision FROM lifecycle_config WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "lifecycle state unavailable")?
            .unwrap_or(0);
        let enabled: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM principals WHERE id=?1 AND iss=?2 AND disabled=0)",
                params![principal.as_str(), idp_issuer],
                |r| r.get(0),
            )
            .map_err(|_| "principal unavailable")?;
        if revision != expected_revision || !enabled {
            return Err("identity lifecycle changed during login; start a fresh login".into());
        }
        conn.execute(
            "INSERT INTO human_sessions (id, principal_id, created_at, expires_at, idp_issuer) \
             VALUES (?1,?2,?3,?4,?5)",
            params![
                session.id,
                session.principal_id.as_str(),
                session.created_at,
                session.expires_at,
                session.idp_issuer
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(session)
    }

    /// The latest unexpired, unrevoked human session, if any.
    pub fn current_human_session(&self) -> Result<Option<HumanSession>, String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, principal_id, created_at, expires_at, revoked_at, idp_issuer \
             FROM human_sessions \
             WHERE revoked_at IS NULL AND expires_at > ?1 \
             ORDER BY created_at DESC, rowid DESC LIMIT 1",
            params![now_unix()],
            row_to_session,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Fetch one session by id (regardless of state).
    pub fn get_human_session(&self, id: &str) -> Result<Option<HumanSession>, String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, principal_id, created_at, expires_at, revoked_at, idp_issuer \
             FROM human_sessions WHERE id=?1",
            params![id],
            row_to_session,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Revoke all active human sessions; returns how many were revoked.
    pub fn revoke_all_human_sessions(&self) -> Result<u64, String> {
        let conn = self.lock();
        conn.execute(
            "UPDATE human_sessions SET revoked_at=?1 \
             WHERE revoked_at IS NULL AND expires_at > ?1",
            params![now_unix()],
        )
        .map(|n| n as u64)
        .map_err(|e| e.to_string())
    }

    // -- delegations --------------------------------------------------------

    /// Record an issued delegation (Stage C mints the matching token).
    pub fn record_delegation(&self, d: &DelegationRecord) -> Result<(), String> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO delegations \
             (jti, sub_principal, act_principal, mode, human_session_id, approved_by, \
              created_at, expires_at, revoked_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                d.jti,
                d.sub_principal.as_str(),
                d.act_principal.as_str(),
                d.mode.as_str(),
                d.human_session_id,
                d.approved_by.as_ref().map(|p| p.as_str().to_owned()),
                d.created_at,
                d.expires_at,
                d.revoked_at
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_delegation(&self, jti: &str) -> Result<Option<DelegationRecord>, String> {
        let conn = self.lock();
        conn.query_row(
            "SELECT jti, sub_principal, act_principal, mode, human_session_id, approved_by, \
                    created_at, expires_at, revoked_at \
             FROM delegations WHERE jti=?1",
            params![jti],
            row_to_delegation,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Revoke one delegation; returns true if a live row was revoked.
    pub fn revoke_delegation(&self, jti: &str) -> Result<bool, String> {
        let conn = self.lock();
        let n = conn
            .execute(
                "UPDATE delegations SET revoked_at=?1 WHERE jti=?2 AND revoked_at IS NULL",
                params![now_unix(), jti],
            )
            .map_err(|e| e.to_string())?;
        Ok(n > 0)
    }

    /// All delegation records, newest first.
    pub fn list_delegations(&self) -> Result<Vec<DelegationRecord>, String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT jti, sub_principal, act_principal, mode, human_session_id, approved_by, \
                        created_at, expires_at, revoked_at \
                 FROM delegations ORDER BY created_at DESC, jti",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], row_to_delegation)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned mutex means a panic mid-write; the connection itself is
        // still usable and refusing all identity ops would fail the daemon
        // open-endedly. Recover the guard.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub(super) fn row_to_principal(row: &rusqlite::Row<'_>) -> rusqlite::Result<Principal> {
    let id: String = row.get(0)?;
    let kind_s: String = row.get(1)?;
    let iss: Option<String> = row.get(2)?;
    let sub: Option<String> = row.get(3)?;
    let email: Option<String> = row.get(4)?;
    let display_name: Option<String> = row.get(5)?;
    let tool: Option<String> = row.get(6)?;
    let service_name: Option<String> = row.get(7)?;
    let roles_s: String = row.get(8)?;
    let created_at: i64 = row.get(9)?;
    let last_seen: i64 = row.get(10)?;
    let disabled: i64 = row.get(11)?;

    let invalid = |msg: &str| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            msg.to_string().into(),
        )
    };

    let kind = match kind_s.as_str() {
        "human" => PrincipalKind::Human {
            iss: iss.ok_or_else(|| invalid("human row missing iss"))?,
            sub: sub.ok_or_else(|| invalid("human row missing sub"))?,
            email,
            name: display_name,
        },
        "agent" => PrincipalKind::Agent {
            tool: tool.ok_or_else(|| invalid("agent row missing tool"))?,
        },
        "service" => PrincipalKind::Service {
            name: service_name.ok_or_else(|| invalid("service row missing name"))?,
        },
        other => return Err(invalid(&format!("unknown principal kind {other:?}"))),
    };

    Ok(Principal {
        id: PrincipalId::parse(&id).map_err(|e| invalid(&e.to_string()))?,
        kind,
        roles: roles_from_string(&roles_s).map_err(|e| invalid(&e.to_string()))?,
        created_at,
        last_seen,
        disabled: disabled != 0,
    })
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<HumanSession> {
    let principal_id: String = row.get(1)?;
    Ok(HumanSession {
        id: row.get(0)?,
        principal_id: PrincipalId::parse(&principal_id).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                e.to_string().into(),
            )
        })?,
        created_at: row.get(2)?,
        expires_at: row.get(3)?,
        revoked_at: row.get(4)?,
        idp_issuer: row.get(5)?,
    })
}

fn row_to_delegation(row: &rusqlite::Row<'_>) -> rusqlite::Result<DelegationRecord> {
    let conv_err = |idx: usize, e: String| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, e.into())
    };
    let sub_s: String = row.get(1)?;
    let act_s: String = row.get(2)?;
    let mode_s: String = row.get(3)?;
    let approved_s: Option<String> = row.get(5)?;
    Ok(DelegationRecord {
        jti: row.get(0)?,
        sub_principal: PrincipalId::parse(&sub_s).map_err(|e| conv_err(1, e.to_string()))?,
        act_principal: PrincipalId::parse(&act_s).map_err(|e| conv_err(2, e.to_string()))?,
        mode: mode_s
            .parse::<AccessMode>()
            .map_err(|e| conv_err(3, e.to_string()))?,
        human_session_id: row.get(4)?,
        approved_by: approved_s
            .map(|s| PrincipalId::parse(&s).map_err(|e| conv_err(5, e.to_string())))
            .transpose()?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        revoked_at: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> IdentityStore {
        IdentityStore::open_in_memory().unwrap()
    }

    fn admin_roles() -> BTreeSet<Role> {
        BTreeSet::from([Role::Admin, Role::Approver, Role::Operator])
    }

    #[test]
    fn upsert_human_is_idempotent_on_iss_sub() {
        let s = store();
        let p1 = s
            .upsert_human(
                "https://idp.example.com",
                "u-1",
                Some("a@example.com"),
                Some("A"),
                &admin_roles(),
            )
            .unwrap();
        let p2 = s
            .upsert_human(
                "https://idp.example.com",
                "u-1",
                Some("a2@example.com"),
                None,
                &BTreeSet::new(),
            )
            .unwrap();
        assert_eq!(p1.id, p2.id);
        // Email refreshed, roles NOT overwritten by later upserts.
        assert_eq!(
            p2.kind,
            PrincipalKind::Human {
                iss: "https://idp.example.com".into(),
                sub: "u-1".into(),
                email: Some("a2@example.com".into()),
                name: None,
            }
        );
        assert!(p2.has_role(Role::Admin));
        assert_eq!(s.count_humans().unwrap(), 1);
    }

    #[test]
    fn distinct_subs_get_distinct_principals() {
        let s = store();
        let p1 = s
            .upsert_human("https://idp.example.com", "u-1", None, None, &admin_roles())
            .unwrap();
        let p2 = s
            .upsert_human(
                "https://idp.example.com",
                "u-2",
                None,
                None,
                &BTreeSet::new(),
            )
            .unwrap();
        assert_ne!(p1.id, p2.id);
        assert_eq!(s.count_humans().unwrap(), 2);
        assert!(!p2.has_role(Role::Admin));
    }

    #[test]
    fn upsert_agent_and_service_unique_on_name() {
        let s = store();
        let a1 = s.upsert_agent("claude-code").unwrap();
        let a2 = s.upsert_agent("claude-code").unwrap();
        assert_eq!(a1.id, a2.id);
        let svc1 = s.upsert_service("ci").unwrap();
        let svc2 = s.upsert_service("ci").unwrap();
        assert_eq!(svc1.id, svc2.id);
        assert_ne!(a1.id.as_str(), svc1.id.as_str());
        assert_eq!(s.list_principals().unwrap().len(), 2);
    }

    #[test]
    fn concurrent_reviewed_changes_keep_one_admin_and_refuse_stale_reviews() {
        let store = std::sync::Arc::new(store());
        let first = store
            .upsert_human(
                "https://idp.example.com",
                "admin-a",
                None,
                None,
                &admin_roles(),
            )
            .unwrap();
        let second = store
            .upsert_human(
                "https://idp.example.com",
                "admin-b",
                None,
                None,
                &admin_roles(),
            )
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for principal in [first, second] {
            let store = store.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store.set_reviewed_roles(
                    &principal.id,
                    &principal.id,
                    &roles_to_string(&principal.roles),
                    &BTreeSet::from([Role::Operator]),
                    |_| true,
                )
            }));
        }
        let successes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
        assert_eq!(store.count_with_role(Role::Admin).unwrap(), 1);
        let admin = store
            .list_principals()
            .unwrap()
            .into_iter()
            .find(|principal| principal.has_role(Role::Admin))
            .unwrap();
        assert!(
            store
                .set_reviewed_roles(&admin.id, &admin.id, "operator", &admin_roles(), |_| true)
                .is_err()
        );
    }

    #[test]
    fn reviewed_roles_preserve_last_human_admin_despite_service_agent_or_disabled_admins() {
        let store = store();
        let admin = store
            .upsert_human(
                "https://idp.example.com",
                "human-admin",
                None,
                None,
                &admin_roles(),
            )
            .unwrap();
        let service = store.upsert_service("automation-admin").unwrap();
        let agent = store.upsert_agent("agent-admin").unwrap();
        for principal in [&service, &agent] {
            store.set_roles(&principal.id, &admin_roles()).unwrap();
        }
        let disabled = store
            .upsert_human(
                "https://idp.example.com",
                "disabled-admin",
                None,
                None,
                &admin_roles(),
            )
            .unwrap();
        store.set_disabled(&disabled.id, true).unwrap();
        let result = store.set_reviewed_roles(
            &admin.id,
            &admin.id,
            &roles_to_string(&admin.roles),
            &BTreeSet::from([Role::Operator]),
            |_| true,
        );
        assert!(result.unwrap_err().contains("last admitted human admin"));
        assert_eq!(
            store.get_principal(&admin.id).unwrap().unwrap().roles,
            admin.roles
        );
        // Non-human admin roles cannot substitute for the acting human either.
        for actor in [&service, &agent] {
            assert!(
                store
                    .set_reviewed_roles(
                        &actor.id,
                        &admin.id,
                        &roles_to_string(&admin.roles),
                        &BTreeSet::from([Role::Operator]),
                        |_| true,
                    )
                    .unwrap_err()
                    .contains("authority changed")
            );
        }
    }

    #[test]
    fn reviewed_roles_ignore_removed_subjects_and_reject_removed_acting_admin() {
        let store = store();
        let admitted = store
            .upsert_human(
                "https://idp.example.com",
                "admitted-admin",
                None,
                None,
                &admin_roles(),
            )
            .unwrap();
        let removed = store
            .upsert_human(
                "https://idp.example.com",
                "removed-admin",
                None,
                None,
                &admin_roles(),
            )
            .unwrap();
        // This mirrors current broker issuer/subject membership admission,
        // rather than trusting the membership present when the row was made.
        let permitted = |principal: &Principal| {
            matches!(
                &principal.kind, PrincipalKind::Human { iss, sub, .. }
                    if iss == "https://idp.example.com" && sub == "admitted-admin"
            )
        };
        let replacement = BTreeSet::from([Role::Operator]);
        assert!(
            store
                .set_reviewed_roles(
                    &admitted.id,
                    &admitted.id,
                    &roles_to_string(&admitted.roles),
                    &replacement,
                    permitted,
                )
                .unwrap_err()
                .contains("last admitted human admin")
        );
        assert!(
            store
                .set_reviewed_roles(
                    &removed.id,
                    &admitted.id,
                    &roles_to_string(&admitted.roles),
                    &replacement,
                    permitted,
                )
                .unwrap_err()
                .contains("authority changed")
        );
        assert_eq!(
            store.get_principal(&admitted.id).unwrap().unwrap().roles,
            admitted.roles
        );
        // An admitted human may still remove roles from a departed member.
        store
            .set_reviewed_roles(
                &admitted.id,
                &removed.id,
                &roles_to_string(&removed.roles),
                &replacement,
                permitted,
            )
            .unwrap();
        assert_eq!(
            store.get_principal(&removed.id).unwrap().unwrap().roles,
            replacement
        );
    }

    #[test]
    fn set_roles_roundtrip_and_missing_principal_errors() {
        let s = store();
        let p = s.upsert_service("ci").unwrap();
        s.set_roles(&p.id, &BTreeSet::from([Role::Operator]))
            .unwrap();
        let got = s.get_principal(&p.id).unwrap().unwrap();
        assert!(got.has_role(Role::Operator));
        assert!(!got.has_role(Role::Admin));

        let ghost = PrincipalId::parse("svc_00000000000000000000000000000000").unwrap();
        assert!(s.set_roles(&ghost, &BTreeSet::new()).is_err());
    }

    #[test]
    fn session_lifecycle_current_expiry_revocation() {
        let s = store();
        let p = s
            .upsert_human("https://idp.example.com", "u-1", None, None, &admin_roles())
            .unwrap();

        assert!(s.current_human_session().unwrap().is_none());
        let sess = s
            .create_human_session(&p.id, 3600, "https://idp.example.com")
            .unwrap();
        assert!(sess.id.starts_with("hses_"));

        let current = s.current_human_session().unwrap().unwrap();
        assert_eq!(current.id, sess.id);
        assert_eq!(current.principal_id, p.id);

        let revoked = s.revoke_all_human_sessions().unwrap();
        assert_eq!(revoked, 1);
        assert!(s.current_human_session().unwrap().is_none());
        // Row still exists as a record.
        assert!(
            s.get_human_session(&sess.id)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    #[test]
    fn session_for_service_principal_rejected() {
        let s = store();
        let svc = s.upsert_service("ci").unwrap();
        assert!(s.create_human_session(&svc.id, 60, "https://x").is_err());
    }

    #[test]
    fn delegation_record_roundtrip_and_revoke() {
        let s = store();
        let hum = s
            .upsert_human("https://idp.example.com", "u-1", None, None, &admin_roles())
            .unwrap();
        let agt = s.upsert_agent("claude-code").unwrap();
        let d = DelegationRecord {
            jti: "sess-1".into(),
            sub_principal: hum.id.clone(),
            act_principal: agt.id.clone(),
            mode: AccessMode::Delegated,
            human_session_id: Some("hses_x".into()),
            approved_by: None,
            created_at: now_unix(),
            expires_at: now_unix() + 600,
            revoked_at: None,
        };
        s.record_delegation(&d).unwrap();
        let got = s.get_delegation("sess-1").unwrap().unwrap();
        assert_eq!(got.sub_principal, hum.id);
        assert_eq!(got.mode, AccessMode::Delegated);
        assert!(s.revoke_delegation("sess-1").unwrap());
        assert!(!s.revoke_delegation("sess-1").unwrap());
        assert_eq!(s.list_delegations().unwrap().len(), 1);
        assert!(s.list_delegations().unwrap()[0].revoked_at.is_some());
    }

    #[test]
    fn count_with_role_counts_enabled_only() {
        let s = store();
        s.upsert_human("https://idp.example.com", "u-1", None, None, &admin_roles())
            .unwrap();
        let p2 = s
            .upsert_human("https://idp.example.com", "u-2", None, None, &admin_roles())
            .unwrap();
        assert_eq!(s.count_with_role(Role::Admin).unwrap(), 2);
        // Disable p2 directly.
        {
            let conn = s.lock();
            conn.execute(
                "UPDATE principals SET disabled=1 WHERE id=?1",
                params![p2.id.as_str()],
            )
            .unwrap();
        }
        assert_eq!(s.count_with_role(Role::Admin).unwrap(), 1);
    }

    #[test]
    fn open_creates_file_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.db");
        let _s = IdentityStore::open(&path).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;

    #[test]
    fn issuer_subject_lookup_is_exact_and_reads_live_principal_state() {
        let store = IdentityStore::open_in_memory().unwrap();
        let principal = store
            .upsert_human(
                "https://idp.example",
                "subject",
                Some("user@example.com"),
                None,
                &BTreeSet::from([Role::Operator]),
            )
            .unwrap();
        assert!(
            store
                .get_human_by_subject("https://other.example", "subject")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_human_by_subject("https://idp.example", "other")
                .unwrap()
                .is_none()
        );
        store.set_roles(&principal.id, &BTreeSet::new()).unwrap();
        store.set_disabled(&principal.id, true).unwrap();
        let current = store
            .get_human_by_subject("https://idp.example", "subject")
            .unwrap()
            .unwrap();
        assert!(current.disabled);
        assert!(current.roles.is_empty());
    }

    #[test]
    fn resource_revocation_is_durable_monotonic_and_issuer_resource_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.db");
        {
            let store = IdentityStore::open(&path).unwrap();
            assert!(
                !store
                    .resource_token_revoked("issuer", "resource", "token")
                    .unwrap()
            );
            store
                .revoke_resource_token("issuer", "resource", "token", 900)
                .unwrap();
            store
                .revoke_resource_token("issuer", "resource", "token", 100)
                .unwrap();
        }
        let reopened = IdentityStore::open(&path).unwrap();
        assert!(
            reopened
                .resource_token_revoked("issuer", "resource", "token")
                .unwrap()
        );
        assert!(
            !reopened
                .resource_token_revoked("other", "resource", "token")
                .unwrap()
        );
        assert!(
            !reopened
                .resource_token_revoked("issuer", "other", "token")
                .unwrap()
        );
        assert!(
            !reopened
                .resource_token_revoked("issuer", "resource", "other")
                .unwrap()
        );
        let expiry: i64 = reopened
            .lock()
            .query_row("SELECT expires_at FROM resource_revocations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(expiry, 900);
    }
}
