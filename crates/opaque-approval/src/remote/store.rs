//! Durable approval rounds. An unfinished
//! round is cancelled on restart; a signed decision is never resumed as work.
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Mutex;

use opaque_core::tenant::TenantBinding;
use opaque_core::workstation::{SignedWorkstationReceipt, WorkstationReview};
use rusqlite::{Connection, OptionalExtension, params};

pub struct RemoteStore {
    connection: Mutex<Connection>,
    lock: File,
    tenant: TenantBinding,
    broker: String,
}

impl Drop for RemoteStore {
    fn drop(&mut self) {
        // No worker can still hold this store when its final Arc is dropped.
        // Release SQLite before the process-wide writer lock.
        if let Ok(connection) = self.connection.get_mut() {
            let replacement = Connection::open_in_memory().expect("close remote approval database");
            let old = std::mem::replace(connection, replacement);
            drop(old);
        }
        // SAFETY: this object owns the valid descriptor.
        unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn err<E>(_: E) -> String {
    "remote approval ledger unavailable".into()
}

fn private_file(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(err)?;
    let meta = file.metadata().map_err(err)?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err("remote approval ledger requires private regular files".into());
    }
    Ok(file)
}

impl RemoteStore {
    pub fn open(path: &Path, tenant: TenantBinding, broker: String) -> Result<Self, String> {
        tenant.validate().map_err(err)?;
        let parent = path
            .parent()
            .ok_or("remote approval ledger needs a parent")?;
        let meta = std::fs::symlink_metadata(parent).map_err(err)?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err("remote approval ledger requires an owner-only directory".into());
        }
        let file = private_file(path)?;
        if file.metadata().map_err(err)?.len() > 256 * 1024 * 1024 {
            return Err("remote approval ledger exceeds storage limit".into());
        }
        let canonical = path.canonicalize().map_err(err)?;
        let lock = private_file(&canonical.with_extension("writer.lock"))?;
        // SAFETY: the owned descriptor remains alive for the store lifetime.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("remote approval ledger already has a writer".into());
        }
        let setup = || -> Result<Connection, String> {
            let connection = Connection::open(&canonical).map_err(err)?;
            let opened = std::fs::metadata(&canonical).map_err(err)?;
            let original = file.metadata().map_err(err)?;
            if opened.ino() != original.ino() || opened.dev() != original.dev() {
                return Err("remote approval ledger replaced during open".into());
            }
            connection
                .busy_timeout(std::time::Duration::from_secs(2))
                .map_err(err)?;
            connection
                .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
                .map_err(err)?;
            let check: String = connection
                .query_row("PRAGMA quick_check", [], |r| r.get(0))
                .map_err(err)?;
            let version: i64 = connection
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(err)?;
            if check != "ok" || !matches!(version, 0 | 1) {
                return Err("invalid remote approval ledger".into());
            }
            let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], |r| r.get(0)).map_err(err)?;
            if (version == 0 && tables != 0) || (version == 1 && tables != 2) {
                return Err("invalid remote approval ledger schema".into());
            }
            // Retain the v1 notice/attempt columns so historical decision ledgers
            // remain readable. New rounds never use them for delivery state.
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS binding (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS rounds (
                   id TEXT PRIMARY KEY, review TEXT NOT NULL, expires INTEGER NOT NULL,
                   state TEXT NOT NULL, receipt TEXT, notice TEXT NOT NULL, attempts INTEGER NOT NULL,
                   retry_at INTEGER NOT NULL);
                 PRAGMA user_version=1;"
            ).map_err(err)?;
            let binding = serde_json::to_string(&(&tenant, &broker)).map_err(err)?;
            connection
                .execute("INSERT OR IGNORE INTO binding VALUES (1, ?1)", [&binding])
                .map_err(err)?;
            let persisted: String = connection
                .query_row("SELECT value FROM binding WHERE id=1", [], |r| r.get(0))
                .map_err(err)?;
            if persisted != binding {
                return Err("remote approval ledger belongs to another broker".into());
            }
            // This process cannot recover the caller or native review ceremony.
            connection.execute("UPDATE rounds SET state='cancelled_restart', notice='cancelled' WHERE state='pending'", []).map_err(err)?;
            Ok(connection)
        };
        match setup() {
            Ok(connection) => Ok(Self {
                connection: Mutex::new(connection),
                lock,
                tenant,
                broker,
            }),
            Err(error) => {
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
                Err(error)
            }
        }
    }

    pub fn enqueue(&self, review: &WorkstationReview, now: i64) -> Result<(), String> {
        review.validate(&self.broker, now).map_err(err)?;
        let authority = review
            .challenge
            .authority
            .as_ref()
            .ok_or("remote approval requires current authority")?;
        self.tenant
            .require_same(&authority.binding.tenant)
            .map_err(err)?;
        let payload = serde_json::to_string(review).map_err(err)?;
        let mut connection = self.connection.lock().map_err(err)?;
        let tx = connection.transaction().map_err(err)?;
        let count: i64 = tx
            .query_row("SELECT count(*) FROM rounds", [], |r| r.get(0))
            .map_err(err)?;
        // Explicit failure instead of silently evicting authorization evidence.
        let pages: u64 = tx
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(err)?;
        let page_size: u64 = tx
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(err)?;
        if count >= 10_000 || pages.saturating_mul(page_size) > 255 * 1024 * 1024 {
            return Err("remote approval ledger retention capacity reached".into());
        }
        tx.execute(
            "INSERT INTO rounds VALUES (?1,?2,?3,'pending',NULL,?4,0,0)",
            params![
                review.challenge.approval_id,
                payload,
                review.challenge.expires_at,
                "disabled"
            ],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }

    pub fn cancel(&self, id: &str) -> Result<(), String> {
        self.connection.lock().map_err(err)?
            .execute("UPDATE rounds SET state='cancelled', notice='cancelled' WHERE id=?1 AND state='pending'", [id]).map_err(err)?;
        Ok(())
    }

    pub fn accept(&self, receipt: &SignedWorkstationReceipt) -> Result<(), String> {
        receipt.verify().map_err(err)?;
        let challenge = &receipt.review.challenge;
        if challenge.broker_id != self.broker {
            return Err("wrong approval broker".into());
        }
        self.tenant
            .require_same(
                &challenge
                    .authority
                    .as_ref()
                    .ok_or("missing authority")?
                    .binding
                    .tenant,
            )
            .map_err(err)?;
        let encoded_review = serde_json::to_string(&receipt.review).map_err(err)?;
        let encoded_receipt = serde_json::to_string(receipt).map_err(err)?;
        let connection = self.connection.lock().map_err(err)?;
        let changed = connection
            .execute(
                "UPDATE rounds SET state='decided', receipt=?1, notice='cancelled'
             WHERE id=?2 AND review=?3 AND state='pending' AND expires>?4",
                params![
                    encoded_receipt,
                    challenge.approval_id,
                    encoded_review,
                    receipt.accepted_at
                ],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("approval round already consumed or cancelled".into());
        }
        Ok(())
    }

    pub fn receipt(&self, id: &str) -> Result<Option<SignedWorkstationReceipt>, String> {
        let payload: Option<String> = self
            .connection
            .lock()
            .map_err(err)?
            .query_row(
                "SELECT receipt FROM rounds WHERE id=?1 AND state='decided'",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        payload
            .map(|payload| {
                if payload.len() > 256 * 1024 {
                    return Err("oversized approval receipt".into());
                }
                let receipt: SignedWorkstationReceipt =
                    serde_json::from_str(&payload).map_err(err)?;
                receipt.verify().map_err(err)?;
                if receipt.review.challenge.broker_id != self.broker
                    || receipt.review.challenge.approval_id != id
                {
                    return Err("invalid receipt binding".into());
                }
                self.tenant
                    .require_same(
                        &receipt
                            .review
                            .challenge
                            .authority
                            .as_ref()
                            .ok_or("missing authority")?
                            .binding
                            .tenant,
                    )
                    .map_err(err)?;
                Ok(receipt)
            })
            .transpose()
    }
}
