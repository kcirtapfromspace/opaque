//! Single-writer SQLite MCP invocation ledger. No charge is ever refunded.
use super::{Action, now, transport::Outcome, unavailable};
use opaque_core::bundle::{BundleState, VerifiedBundle};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::Mutex,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub invocation_id: String,
    pub action_digest: String,
    pub request_context_digest: String,
    pub registry_digest: String,
    pub route: String,
    pub tool: String,
    pub schema_digest: String,
    pub credential_ref: String,
    pub output_policy: String,
    pub expires_at: i64,
    pub state: String,
    pub attempt_charged: bool,
    pub revoked: bool,
    pub code: String,
    pub response_sha256: Option<String>,
    pub response_bytes: Option<usize>,
    pub fixture_only: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    owner: String,
    action: Action,
    receipt: Receipt,
}
pub struct Ledger {
    db: Option<Mutex<Connection>>,
    lock: File,
}
impl Drop for Ledger {
    fn drop(&mut self) {
        drop(self.db.take());
        unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
    }
}
impl Ledger {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| unavailable())?;
        let metadata = file.metadata().map_err(|_| unavailable())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(unavailable());
        }
        let canonical = path.canonicalize().map_err(|_| unavailable())?;
        let mut lock_name = canonical.as_os_str().to_os_string();
        lock_name.push(".writer.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(Path::new(&lock_name))
            .map_err(|_| unavailable())?;
        let lm = lock.metadata().map_err(|_| unavailable())?;
        if !lm.is_file()
            || lm.nlink() != 1
            || lm.mode() & 0o077 != 0
            || lm.uid() != unsafe { libc::geteuid() }
        {
            return Err(unavailable());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(unavailable());
        }
        let db = Connection::open(canonical).map_err(|_| unavailable())?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| unavailable())?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS mcp_invocations (id TEXT PRIMARY KEY,record TEXT NOT NULL); CREATE TABLE IF NOT EXISTS mcp_registry (singleton INTEGER PRIMARY KEY CHECK(singleton=1),record TEXT NOT NULL);").map_err(|_|unavailable())?;
        let integrity: String = db
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(|_| unavailable())?;
        if integrity != "ok" {
            return Err(unavailable());
        }
        let rows: Vec<(String, String)> = db
            .prepare("SELECT id,record FROM mcp_invocations")
            .map_err(|_| unavailable())?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|_| unavailable())?
            .collect::<Result<_, _>>()
            .map_err(|_| unavailable())?;
        for (id, text) in rows {
            let mut r = decode(&id, &text)?;
            if matches!(r.receipt.state.as_str(), "reviewing" | "reserved") {
                r.receipt.state = if r.receipt.attempt_charged {
                    "unknown"
                } else {
                    "cancelled"
                }
                .into();
                r.receipt.code = "interrupted".into();
                save(&db, &r)?;
            }
        }
        Ok(Self {
            db: Some(Mutex::new(db)),
            lock,
        })
    }
    fn db(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.db
            .as_ref()
            .ok_or_else(unavailable)?
            .lock()
            .map_err(|_| unavailable())
    }
    pub fn apply_registry(&self, verified: &VerifiedBundle) -> Result<(), String> {
        let db = self.db()?;
        let prior: Option<String> = db
            .query_row(
                "SELECT record FROM mcp_registry WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| unavailable())?;
        let prior = prior
            .map(|s| serde_json::from_str::<BundleState>(&s))
            .transpose()
            .map_err(|_| unavailable())?;
        if prior
            .as_ref()
            .is_some_and(|p| p.org != verified.payload.org)
        {
            return Err(unavailable());
        }
        opaque_core::bundle::check_rollback(verified, prior.as_ref()).map_err(|_| unavailable())?;
        let state = BundleState {
            org: verified.payload.org.clone(),
            version: verified.payload.version,
            digest: verified.digest.clone(),
            applied_at: now(),
        };
        db.execute("INSERT INTO mcp_registry VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET record=excluded.record",[serde_json::to_string(&state).map_err(|_|unavailable())?]).map_err(|_|unavailable())?;
        Ok(())
    }
    pub fn claim(&self, owner: &str, action: &Action) -> Result<Receipt, String> {
        if owner.is_empty() || owner.len() > 512 || now() >= action.expires_at {
            return Err(unavailable());
        }
        let db = self.db()?;
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM mcp_invocations", [], |r| r.get(0))
            .map_err(|_| unavailable())?;
        if count >= 10000 {
            return Err(unavailable());
        }
        let receipt = Receipt {
            invocation_id: action.invocation_id.clone(),
            action_digest: action.digest(),
            request_context_digest: action.request_context_digest.clone(),
            registry_digest: action.registry_digest.clone(),
            route: action.call.route().alias.clone(),
            tool: action.call.route().tool.clone(),
            schema_digest: super::digest(&action.call.route().input_schema),
            credential_ref: action.credential_ref.clone(),
            output_policy: "withhold".into(),
            expires_at: action.expires_at,
            state: "reviewing".into(),
            attempt_charged: false,
            revoked: false,
            code: "approval_pending".into(),
            response_sha256: None,
            response_bytes: None,
            fixture_only: action.fixture_origin.is_some(),
        };
        let record = Record {
            owner: owner.into(),
            action: action.clone(),
            receipt: receipt.clone(),
        };
        db.execute(
            "INSERT INTO mcp_invocations VALUES(?1,?2)",
            params![
                action.invocation_id,
                serde_json::to_string(&record).map_err(|_| unavailable())?
            ],
        )
        .map_err(|_| unavailable())?;
        Ok(receipt)
    }
    pub fn get(&self, owner: &str, id: &str) -> Result<Receipt, String> {
        Ok(load(&*self.db()?, owner, id)?.receipt)
    }
    pub fn revoke(&self, owner: &str, id: &str) -> Result<Receipt, String> {
        let db = self.db()?;
        let mut r = load(&db, owner, id)?;
        r.receipt.revoked = true;
        if r.receipt.state == "reviewing" {
            r.receipt.state = "revoked".into();
            r.receipt.code = "revoked".into();
        }
        save(&db, &r)?;
        Ok(r.receipt)
    }
    pub fn reserve(&self, owner: &str, action: &Action) -> Result<(), String> {
        let db = self.db()?;
        let mut r = load(&db, owner, &action.invocation_id)?;
        active(&r, action)?;
        if r.receipt.state != "reviewing" {
            return Err(unavailable());
        }
        r.receipt.state = "reserved".into();
        r.receipt.attempt_charged = true;
        r.receipt.code = "attempt_reserved".into();
        save(&db, &r)
    }
    pub fn authorize_dispatch(&self, owner: &str, action: &Action) -> Result<(), String> {
        let r = load(&*self.db()?, owner, &action.invocation_id)?;
        active(&r, action)?;
        if r.receipt.state != "reserved" {
            return Err(unavailable());
        }
        Ok(())
    }
    pub fn finish(
        &self,
        owner: &str,
        action: &Action,
        outcome: &Outcome,
    ) -> Result<Receipt, String> {
        let db = self.db()?;
        let mut r = load(&db, owner, &action.invocation_id)?;
        if r.action != *action || r.receipt.state != "reserved" {
            return Err(unavailable());
        }
        r.receipt.state = outcome.state.into();
        r.receipt.code = outcome.code.into();
        r.receipt.response_sha256 = outcome.response_sha256.clone();
        r.receipt.response_bytes = outcome.response_bytes;
        save(&db, &r)?;
        Ok(r.receipt)
    }
    pub fn guard<'a>(&'a self, owner: &str, id: &str) -> Guard<'a> {
        Guard {
            ledger: self,
            owner: owner.into(),
            id: id.into(),
        }
    }
    fn interrupt(&self, owner: &str, id: &str) {
        if let Ok(db) = self.db()
            && let Ok(mut r) = load(&db, owner, id)
            && matches!(r.receipt.state.as_str(), "reviewing" | "reserved")
        {
            r.receipt.state = if r.receipt.attempt_charged {
                "unknown"
            } else {
                "cancelled"
            }
            .into();
            r.receipt.code = "interrupted".into();
            let _ = save(&db, &r);
        }
    }
}
pub struct Guard<'a> {
    ledger: &'a Ledger,
    owner: String,
    id: String,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.ledger.interrupt(&self.owner, &self.id);
    }
}
fn active(r: &Record, a: &Action) -> Result<(), String> {
    if r.action != *a || r.receipt.revoked || now() >= a.expires_at {
        return Err(unavailable());
    }
    Ok(())
}
fn decode(id: &str, text: &str) -> Result<Record, String> {
    if text.len() > 256 * 1024 {
        return Err(unavailable());
    }
    let r: Record = serde_json::from_str(text).map_err(|_| unavailable())?;
    let a = &r.action;
    let receipt = &r.receipt;
    let charged = matches!(
        receipt.state.as_str(),
        "reserved" | "accepted" | "rejected" | "unknown"
    );
    if r.owner.is_empty()
        || r.owner.len() > 512
        || a.invocation_id != id
        || receipt.invocation_id != id
        || receipt.action_digest != a.digest()
        || receipt.expires_at != a.expires_at
        || receipt.request_context_digest != a.request_context_digest
        || receipt.registry_digest != a.registry_digest
        || receipt.route != a.call.route().alias
        || receipt.tool != a.call.route().tool
        || receipt.schema_digest != super::digest(&a.call.route().input_schema)
        || receipt.credential_ref != a.credential_ref
        || receipt.output_policy != "withhold"
        || receipt.fixture_only != a.fixture_origin.is_some()
        || receipt.attempt_charged != charged
        || !matches!(
            receipt.state.as_str(),
            "reviewing"
                | "reserved"
                | "accepted"
                | "rejected"
                | "unknown"
                | "cancelled"
                | "revoked"
        )
        || receipt
            .response_sha256
            .as_ref()
            .is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        || receipt
            .response_bytes
            .is_some_and(|b| b > a.call.route().max_response_bytes)
        || receipt.response_bytes.is_some() != receipt.response_sha256.is_some()
    {
        return Err(unavailable());
    }
    Ok(r)
}
fn load(db: &Connection, owner: &str, id: &str) -> Result<Record, String> {
    let text: String = db
        .query_row(
            "SELECT record FROM mcp_invocations WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .map_err(|_| unavailable())?;
    let r = decode(id, &text)?;
    if r.owner != owner {
        return Err(unavailable());
    }
    Ok(r)
}
fn save(db: &Connection, r: &Record) -> Result<(), String> {
    db.execute(
        "UPDATE mcp_invocations SET record=?2 WHERE id=?1",
        params![
            r.action.invocation_id,
            serde_json::to_string(r).map_err(|_| unavailable())?
        ],
    )
    .map_err(|_| unavailable())?;
    Ok(())
}
