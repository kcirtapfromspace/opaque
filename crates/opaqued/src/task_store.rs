//! Durable, single-writer authority ledger for bounded publish tasks.
//!
//! A reservation commits before provider dispatch and is never refunded. The
//! process-wide mutex serializes approval claims, revocation, and reservations;
//! an OS lock prevents another daemon from recovering this live ledger. On
//! restart an interrupted reservation becomes unknown, never pending.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use opaque_core::task::{
    SlotOutcome, SlotState, TaskApprovalMode, TaskManifest, TaskRecord, TaskSlot, TaskState,
    TaskValidationError,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TaskStoreError {
    #[error("task ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("task ledger database failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("task ledger serialization failed")]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] TaskValidationError),
    #[error("task ledger is already open by another writer")]
    Locked,
    #[error("task ledger lock was poisoned")]
    Poisoned,
    #[error("task ledger integrity check failed")]
    Corrupt,
    #[error("task not found")]
    NotFound,
    #[error("task belongs to a different owner")]
    OwnerMismatch,
    #[error("task has expired")]
    Expired,
    #[error("task has been revoked")]
    Revoked,
    #[error("task has already been claimed; inspect its receipt instead of starting another run")]
    AlreadyClaimed,
    #[error("task has not passed its trusted approval gate")]
    NotApproved,
    #[error("approved manifest digest does not match this task")]
    DigestMismatch,
    #[error("task slot not found")]
    SlotNotFound,
    #[error("task slot is already charged and cannot be reused")]
    SlotConsumed,
    #[error("request does not own this reservation")]
    RequestMismatch,
    #[error("task transition is not permitted")]
    InvalidTransition,
    #[error("invalid task owner, request ID, or timestamp")]
    InvalidInput,
    #[error("task list cursor was not found for this owner")]
    InvalidCursor,
    #[error("task receipt exceeds the safe page size")]
    ReceiptTooLarge,
}

pub struct TaskStore {
    tenant: Option<opaque_core::tenant::TenantBinding>,
    // Option lets Drop close SQLite before explicitly releasing the writer
    // lock, including when a concurrently forked child inherited its fd.
    connection: Option<Mutex<Connection>>,
    // macOS flock and SQLite locks interfere on a shared inode, so use a
    // canonical-path sidecar lock. Hard-linked databases are rejected.
    _writer_lock: WriterLock,
}

impl Drop for TaskStore {
    fn drop(&mut self) {
        // The final owner has exclusive access: no ledger operation can still
        // hold a connection guard. Close SQLite before admitting a new writer.
        drop(self.connection.take());
        // WriterLock drops next, after SQLite is closed.
    }
}

/// Unlock on both normal store teardown and errors during initialization.
struct WriterLock(File);

impl Drop for WriterLock {
    fn drop(&mut self) {
        // Closing our fd alone is insufficient after another thread forks:
        // the child shares its open file description until exec/exit, even
        // with O_CLOEXEC. Explicit unlock releases that shared lock now.
        // SAFETY: the File still owns this descriptor throughout Drop.
        let result = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        if result != 0 {
            tracing::error!(error = %std::io::Error::last_os_error(), "task ledger writer unlock failed");
        }
    }
}

impl TaskStore {
    pub fn open(path: &Path) -> Result<Self, TaskStoreError> {
        Self::open_for_tenant(path, None)
    }

    pub fn open_for_tenant(
        path: &Path,
        tenant: Option<opaque_core::tenant::TenantBinding>,
    ) -> Result<Self, TaskStoreError> {
        if tenant
            .as_ref()
            .is_some_and(|binding| binding.validate().is_err())
        {
            return Err(TaskStoreError::InvalidInput);
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let database_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        if database_file.metadata()?.nlink() != 1 || !database_file.metadata()?.is_file() {
            return Err(TaskStoreError::Corrupt);
        }
        let canonical = path.canonicalize()?;
        let mut lock_name = canonical.as_os_str().to_os_string();
        lock_name.push(".writer.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(std::path::PathBuf::from(lock_name))?;
        // SAFETY: file owns an open descriptor and the flags are valid flock
        // operations. The descriptor stays alive as long as the store.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::WouldBlock {
                Err(TaskStoreError::Locked)
            } else {
                Err(TaskStoreError::Io(error))
            };
        }
        let writer_lock = WriterLock(file);
        writer_lock
            .0
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        database_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        drop(database_file);
        let mut connection = Connection::open(canonical)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )?;
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(TaskStoreError::Corrupt);
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0 | 1) {
            return Err(TaskStoreError::Corrupt);
        }
        let task_table_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'bounded_tasks')",
            [], |row| row.get(0),
        )?;
        let existing_tables: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        // An established ledger whose table disappeared is not a fresh
        // ledger. Never recover missing authority history as an empty budget.
        if (version == 1 && !task_table_exists) || (version == 0 && existing_tables != 0) {
            return Err(TaskStoreError::Corrupt);
        }
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS bounded_tasks (
                 id TEXT PRIMARY KEY NOT NULL,
                 owner_key TEXT NOT NULL,
                 record TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS bounded_tasks_owner ON bounded_tasks(owner_key);
             PRAGMA user_version = 1;",
        )?;

        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let records = load_all(&tx)?;
        for mut record in records {
            // Validate the entire database before publishing an available
            // ledger. A malformed row must not silently lose authority use.
            verify_record(&record)?;
            verify_tenant(&record, tenant.as_ref())?;
            if record.state == TaskState::Running {
                for slot in &mut record.slots {
                    if slot.state == SlotState::Reserved {
                        slot.state = SlotState::Unknown;
                        // The exact interruption time is not knowable. Leave
                        // finished_at absent rather than inventing evidence.
                        slot.outcome = Some(SlotOutcome {
                            provider_run_id: None,
                            inference_receipt: None,
                            state: SlotState::Unknown,
                            code: "interrupted".into(),
                        });
                    }
                }
                record.state = TaskState::Partial;
                save_record(&tx, &record)?;
            } else if record
                .slots
                .iter()
                .any(|slot| slot.state == SlotState::Reserved)
            {
                // Revocation/expiry may have happened while a write was in
                // flight. Preserve that terminal task status and uncertainty.
                for slot in &mut record.slots {
                    if slot.state == SlotState::Reserved {
                        slot.state = SlotState::Unknown;
                        slot.outcome = Some(SlotOutcome {
                            provider_run_id: None,
                            inference_receipt: None,
                            state: SlotState::Unknown,
                            code: "interrupted".into(),
                        });
                    }
                }
                save_record(&tx, &record)?;
            }
        }
        tx.commit()?;
        Ok(Self {
            tenant,
            connection: Some(Mutex::new(connection)),
            _writer_lock: writer_lock,
        })
    }

    pub fn create(
        &self,
        owner: &str,
        manifest: TaskManifest,
        now: i64,
    ) -> Result<TaskRecord, TaskStoreError> {
        validate_owner(owner)?;
        self.validate_owner_boundary(owner)?;
        validate_now(now)?;
        let manifest = manifest.canonicalized()?;
        let expires_at = now
            .checked_add(manifest.expires_in_secs as i64)
            .ok_or(TaskStoreError::InvalidInput)?;
        let id = uuid::Uuid::new_v4().to_string();
        let record = TaskRecord {
            id: id.clone(),
            manifest_digest: manifest.digest()?,
            slots: manifest
                .actions
                .iter()
                .enumerate()
                .map(|(index, action)| TaskSlot {
                    id: slot_id(&id, index),
                    action: action.clone(),
                    state: SlotState::Pending,
                    request_id: None,
                    reserved_at: None,
                    finished_at: None,
                    outcome: None,
                })
                .collect(),
            manifest,
            owner_key: owner.into(),
            tenant: self.tenant.clone(),
            created_at: now,
            expires_at,
            approved_at: None,
            approval_mode: None,
            state: TaskState::Planned,
            release_observation: None,
        };
        verify_record(&record)?;
        verify_tenant(&record, self.tenant.as_ref())?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO bounded_tasks (id, owner_key, record) VALUES (?1, ?2, ?3)",
            params![record.id, record.owner_key, serde_json::to_string(&record)?],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn get(&self, id: &str, owner: &str, now: i64) -> Result<TaskRecord, TaskStoreError> {
        self.mutate(id, owner, now, |record| Ok(record.clone()))
    }

    pub fn record_release_observation(
        &self,
        id: &str,
        owner: &str,
        observation: opaque_core::release::ReleaseObservation,
        now: i64,
    ) -> Result<TaskRecord, TaskStoreError> {
        self.mutate(id, owner, now, |record| {
            if observation.checked_at > now {
                return Err(TaskStoreError::InvalidInput);
            }
            let mut observation = observation;
            if let Some(previous) = &record.release_observation {
                if observation.checked_at < previous.checked_at {
                    return Ok(record.clone());
                }
                // Never erase already observed execution or contradictory evidence
                // with a late empty/list response or a concurrent older observation.
                if previous.state == opaque_core::release::ReleaseObservationState::Ambiguous {
                    return Ok(record.clone());
                }
                if previous.run_id.is_some() && observation.run_id != previous.run_id {
                    observation.state = opaque_core::release::ReleaseObservationState::Ambiguous;
                    observation.code = "run_correlation_ambiguous".into();
                    observation.run_id = None;
                    observation.run_url = None;
                    observation.observed_commit_sha = None;
                    observation.run_attempt = None;
                } else if matches!(
                    previous.state,
                    opaque_core::release::ReleaseObservationState::Succeeded
                        | opaque_core::release::ReleaseObservationState::Failed
                ) && observation.state
                    == opaque_core::release::ReleaseObservationState::Running
                {
                    return Ok(record.clone());
                }
            }
            record.release_observation = Some(observation);
            record.validate_release_observation()?;
            Ok(record.clone())
        })
    }

    pub fn list(&self, owner: &str, now: i64) -> Result<Vec<TaskRecord>, TaskStoreError> {
        validate_owner(owner)?;
        self.validate_owner_boundary(owner)?;
        validate_now(now)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut records = {
            let mut statement = tx.prepare(
                "SELECT id, owner_key, record FROM bounded_tasks WHERE owner_key = ?1 ORDER BY rowid DESC",
            )?;
            let rows = statement.query_map([owner], row_columns)?;
            rows.map(|row| decode_row(row?))
                .collect::<Result<Vec<_>, TaskStoreError>>()?
        };
        for record in &mut records {
            verify_tenant(record, self.tenant.as_ref())?;
            if refresh_expiry(record, now) {
                save_record(&tx, record)?;
            }
        }
        tx.commit()?;
        Ok(records)
    }

    /// Page complete receipts within the IPC frame budget. The cursor is an
    /// existing task ID, so newer insertions do not shift previously seen
    /// pages. The 512-byte margin covers envelope metadata and RPC framing.
    pub fn list_page(
        &self,
        owner: &str,
        now: i64,
        cursor: Option<&str>,
    ) -> Result<(Vec<TaskRecord>, bool, Option<String>), TaskStoreError> {
        const PAGE_LIMIT: usize = 96 * 1024;
        let records = self.list(owner, now)?;
        let start = if let Some(cursor) = cursor {
            records
                .iter()
                .position(|record| record.id == cursor)
                .map(|index| index + 1)
                .ok_or(TaskStoreError::InvalidCursor)?
        } else {
            0
        };
        let total_remaining = records.len() - start;
        let mut page = Vec::new();
        let mut bytes = 512;
        for record in records.into_iter().skip(start) {
            let size = serde_json::to_vec(&record)?.len() + 1;
            if bytes + size > PAGE_LIMIT {
                if page.is_empty() {
                    return Err(TaskStoreError::ReceiptTooLarge);
                }
                break;
            }
            bytes += size;
            page.push(record);
        }
        let has_more = page.len() < total_remaining;
        let next_cursor = if has_more {
            page.last().map(|record| record.id.clone())
        } else {
            None
        };
        Ok((page, has_more, next_cursor))
    }

    /// Commit the one allowed execution claim before presenting any approval
    /// prompt. Competing workers can inspect the receipt but cannot prompt.
    pub fn claim(&self, id: &str, owner: &str, now: i64) -> Result<TaskRecord, TaskStoreError> {
        self.mutate(id, owner, now, |record| {
            check_active(record)?;
            if record.state != TaskState::Planned {
                return Err(TaskStoreError::AlreadyClaimed);
            }
            record.state = TaskState::Running;
            Ok(record.clone())
        })
    }

    /// Internal broker transition, called only after the existing trusted
    /// approval factor has approved this exact digest. Never expose as IPC.
    pub fn approve(
        &self,
        id: &str,
        owner: &str,
        digest: &str,
        mode: TaskApprovalMode,
        now: i64,
    ) -> Result<TaskRecord, TaskStoreError> {
        self.mutate(id, owner, now, |record| {
            check_active(record)?;
            if record.manifest_digest != digest {
                return Err(TaskStoreError::DigestMismatch);
            }
            if record.state != TaskState::Running || record.approved_at.is_some() {
                return Err(TaskStoreError::InvalidTransition);
            }
            if now < record.created_at {
                return Err(TaskStoreError::InvalidInput);
            }
            record.approved_at = Some(now);
            record.approval_mode = Some(mode);
            Ok(record.clone())
        })
    }

    /// Commit one irreversible charge before attempting a provider operation.
    pub fn reserve_slot(
        &self,
        id: &str,
        owner: &str,
        slot: &str,
        request: &str,
        now: i64,
    ) -> Result<TaskSlot, TaskStoreError> {
        validate_request(request)?;
        self.mutate(id, owner, now, |record| {
            check_active(record)?;
            if record.state != TaskState::Running || record.approved_at.is_none() {
                return Err(TaskStoreError::NotApproved);
            }
            if now < record.approved_at.unwrap_or(record.created_at) {
                return Err(TaskStoreError::InvalidInput);
            }
            let slot = record
                .slots
                .iter_mut()
                .find(|candidate| candidate.id == slot)
                .ok_or(TaskStoreError::SlotNotFound)?;
            if slot.state != SlotState::Pending {
                return Err(TaskStoreError::SlotConsumed);
            }
            slot.state = SlotState::Reserved;
            slot.request_id = Some(request.into());
            slot.reserved_at = Some(now);
            Ok(slot.clone())
        })
    }

    /// Record a sanitized result exactly once. A revocation/expiry cannot
    /// erase the result of an operation that was already reserved.
    pub fn finalize_slot(
        &self,
        id: &str,
        owner: &str,
        slot: &str,
        request: &str,
        outcome: SlotOutcome,
        now: i64,
    ) -> Result<TaskRecord, TaskStoreError> {
        validate_request(request)?;
        outcome.validate()?;
        self.mutate(id, owner, now, |record| {
            let slot = record
                .slots
                .iter_mut()
                .find(|candidate| candidate.id == slot)
                .ok_or(TaskStoreError::SlotNotFound)?;
            if slot.state != SlotState::Reserved {
                return Err(TaskStoreError::SlotConsumed);
            }
            if slot.request_id.as_deref() != Some(request) {
                return Err(TaskStoreError::RequestMismatch);
            }
            if now < slot.reserved_at.unwrap_or(record.created_at) {
                return Err(TaskStoreError::InvalidInput);
            }
            outcome.validate_for_action(&slot.action)?;
            slot.state = outcome.state;
            slot.finished_at = Some(now);
            slot.outcome = Some(outcome);
            if record.state == TaskState::Running
                && record.slots.iter().all(|slot| slot.state.is_terminal())
            {
                record.state = if record
                    .slots
                    .iter()
                    .all(|slot| slot.state == SlotState::ApiAccepted)
                {
                    TaskState::Completed
                } else {
                    TaskState::Partial
                };
            }
            Ok(record.clone())
        })
    }

    /// Last serialized authority fence before a prepared provider write. A
    /// revocation ordered before this call blocks dispatch. A write authorized
    /// here is in flight and revocation cannot promise to cancel its network
    /// side effect. Call this only after source resolution and revalidation.
    pub fn authorize_dispatch(
        &self,
        id: &str,
        owner: &str,
        slot: &str,
        request: &str,
        now: i64,
    ) -> Result<(), TaskStoreError> {
        validate_request(request)?;
        self.mutate(id, owner, now, |record| {
            check_active(record)?;
            if record.state != TaskState::Running || record.approved_at.is_none() {
                return Err(TaskStoreError::NotApproved);
            }
            let slot = record
                .slots
                .iter()
                .find(|candidate| candidate.id == slot)
                .ok_or(TaskStoreError::SlotNotFound)?;
            if slot.state != SlotState::Reserved {
                return Err(TaskStoreError::SlotConsumed);
            }
            if slot.request_id.as_deref() != Some(request) {
                return Err(TaskStoreError::RequestMismatch);
            }
            if now < slot.reserved_at.unwrap_or(record.created_at) {
                return Err(TaskStoreError::InvalidInput);
            }
            Ok(())
        })
    }

    /// Close a run after approval denial, preflight failure, or a completed
    /// batch. Pending slots remain visibly unattempted and cannot be resumed.
    pub fn finish_run(
        &self,
        id: &str,
        owner: &str,
        now: i64,
    ) -> Result<TaskRecord, TaskStoreError> {
        self.mutate(id, owner, now, |record| {
            if record.state == TaskState::Planned {
                return Err(TaskStoreError::InvalidTransition);
            }
            for slot in &mut record.slots {
                if slot.state == SlotState::Reserved {
                    slot.state = SlotState::Unknown;
                    slot.finished_at = Some(now.max(slot.reserved_at.unwrap_or(now)));
                    slot.outcome = Some(SlotOutcome {
                        provider_run_id: None,
                        inference_receipt: None,
                        state: SlotState::Unknown,
                        code: "interrupted".into(),
                    });
                }
            }
            if record.state == TaskState::Running {
                record.state = if record
                    .slots
                    .iter()
                    .all(|slot| slot.state == SlotState::ApiAccepted)
                {
                    TaskState::Completed
                } else {
                    TaskState::Partial
                };
            }
            Ok(record.clone())
        })
    }

    pub fn revoke(&self, id: &str, owner: &str, now: i64) -> Result<TaskRecord, TaskStoreError> {
        self.mutate(id, owner, now, |record| {
            if matches!(record.state, TaskState::Planned | TaskState::Running) {
                record.state = TaskState::Revoked;
            }
            Ok(record.clone())
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, TaskStoreError> {
        self.connection
            .as_ref()
            .ok_or(TaskStoreError::Poisoned)?
            .lock()
            .map_err(|_| TaskStoreError::Poisoned)
    }

    fn validate_owner_boundary(&self, owner: &str) -> Result<(), TaskStoreError> {
        if let Some(tenant) = &self.tenant {
            let prefix = format!(
                "tenant:{}:broker:{}:uid:",
                tenant.tenant_id, tenant.broker_id
            );
            if !owner.starts_with(&prefix) {
                return Err(TaskStoreError::OwnerMismatch);
            }
        }
        Ok(())
    }

    fn mutate<T>(
        &self,
        id: &str,
        owner: &str,
        now: i64,
        operation: impl FnOnce(&mut TaskRecord) -> Result<T, TaskStoreError>,
    ) -> Result<T, TaskStoreError> {
        validate_owner(owner)?;
        self.validate_owner_boundary(owner)?;
        validate_now(now)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load_record(&tx, id)?;
        verify_tenant(&record, self.tenant.as_ref())?;
        if record.owner_key != owner {
            return Err(TaskStoreError::OwnerMismatch);
        }
        refresh_expiry(&mut record, now);
        let before_operation = record.clone();
        let result = operation(&mut record);
        // Failed transitions roll back their own edits while preserving a
        // newly observed expiry. There is no error path that refunds a slot.
        let persisted = if result.is_ok() {
            &record
        } else {
            &before_operation
        };
        save_record(&tx, persisted)?;
        tx.commit()?;
        result
    }
}

fn validate_now(now: i64) -> Result<(), TaskStoreError> {
    if now < 0 {
        return Err(TaskStoreError::InvalidInput);
    }
    Ok(())
}

fn validate_owner(owner: &str) -> Result<(), TaskStoreError> {
    if owner.is_empty() || owner.len() > 1024 || !owner.bytes().all(|b| (b'!'..=b'~').contains(&b))
    {
        return Err(TaskStoreError::InvalidInput);
    }
    Ok(())
}

fn validate_request(request: &str) -> Result<(), TaskStoreError> {
    if request.is_empty()
        || request.len() > 128
        || !request
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(TaskStoreError::InvalidInput);
    }
    Ok(())
}

fn slot_id(task: &str, index: usize) -> String {
    format!("{task}:{:02}", index + 1)
}

fn refresh_expiry(record: &mut TaskRecord, now: i64) -> bool {
    if now >= record.expires_at && matches!(record.state, TaskState::Planned | TaskState::Running) {
        record.state = TaskState::Expired;
        true
    } else {
        false
    }
}

fn check_active(record: &TaskRecord) -> Result<(), TaskStoreError> {
    match record.state {
        TaskState::Expired => Err(TaskStoreError::Expired),
        TaskState::Revoked => Err(TaskStoreError::Revoked),
        _ => Ok(()),
    }
}

fn row_columns(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, String, String)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}

fn decode_row(
    (id, owner, encoded): (String, String, String),
) -> Result<TaskRecord, TaskStoreError> {
    let record: TaskRecord = serde_json::from_str(&encoded).map_err(|_| TaskStoreError::Corrupt)?;
    if record.id != id || record.owner_key != owner {
        return Err(TaskStoreError::Corrupt);
    }
    verify_record(&record)?;
    Ok(record)
}

fn load_record(connection: &Connection, id: &str) -> Result<TaskRecord, TaskStoreError> {
    let columns = connection
        .query_row(
            "SELECT id, owner_key, record FROM bounded_tasks WHERE id = ?1",
            [id],
            row_columns,
        )
        .optional()?
        .ok_or(TaskStoreError::NotFound)?;
    decode_row(columns)
}

fn load_all(connection: &Connection) -> Result<Vec<TaskRecord>, TaskStoreError> {
    let mut statement = connection.prepare("SELECT id, owner_key, record FROM bounded_tasks")?;
    let rows = statement.query_map([], row_columns)?;
    rows.map(|row| decode_row(row?)).collect()
}

fn save_record(connection: &Connection, record: &TaskRecord) -> Result<(), TaskStoreError> {
    verify_record(record)?;
    if connection.execute(
        "UPDATE bounded_tasks SET record = ?1 WHERE id = ?2 AND owner_key = ?3",
        params![serde_json::to_string(record)?, record.id, record.owner_key],
    )? != 1
    {
        return Err(TaskStoreError::Corrupt);
    }
    Ok(())
}

/// Structural corruption is fatal; recovery must never guess that permission
/// is available. This is not a tamper seal against a user who can rewrite the
/// database and daemon configuration together.
fn verify_record(record: &TaskRecord) -> Result<(), TaskStoreError> {
    let corrupt = || TaskStoreError::Corrupt;
    record
        .validate_tenant_and_inference_receipts()
        .map_err(|_| corrupt())?;
    record
        .validate_release_observation()
        .map_err(|_| corrupt())?;
    let canonical = record.manifest.canonicalized().map_err(|_| corrupt())?;
    if record.manifest != canonical
        || record.manifest_digest != canonical.digest().map_err(|_| corrupt())?
        || uuid::Uuid::parse_str(&record.id).is_err()
        || validate_owner(&record.owner_key).is_err()
        || record.created_at < 0
        || record
            .created_at
            .checked_add(record.manifest.expires_in_secs as i64)
            != Some(record.expires_at)
        || record.slots.len() != record.manifest.actions.len()
        || (record.approved_at.is_none() && record.approval_mode.is_some())
        || record
            .approved_at
            .is_some_and(|at| at < record.created_at || at >= record.expires_at)
    {
        return Err(corrupt());
    }
    for (index, (slot, action)) in record
        .slots
        .iter()
        .zip(&record.manifest.actions)
        .enumerate()
    {
        if slot.id != slot_id(&record.id, index) || &slot.action != action {
            return Err(corrupt());
        }
        if slot.state == SlotState::Pending {
            if slot.request_id.is_some()
                || slot.reserved_at.is_some()
                || slot.finished_at.is_some()
                || slot.outcome.is_some()
            {
                return Err(corrupt());
            }
        } else {
            let approved_at = record.approved_at.ok_or_else(corrupt)?;
            let reserved_at = slot.reserved_at.ok_or_else(corrupt)?;
            if reserved_at < approved_at
                || reserved_at >= record.expires_at
                || slot
                    .request_id
                    .as_deref()
                    .is_none_or(|id| validate_request(id).is_err())
                || slot.finished_at.is_some_and(|at| at < reserved_at)
            {
                return Err(corrupt());
            }
            if slot.state == SlotState::Reserved {
                if slot.outcome.is_some() || slot.finished_at.is_some() {
                    return Err(corrupt());
                }
            } else {
                let outcome = slot.outcome.as_ref().ok_or_else(corrupt)?;
                if outcome.state != slot.state
                    || outcome.validate().is_err()
                    || (slot.finished_at.is_none()
                        && !(slot.state == SlotState::Unknown && outcome.code == "interrupted"))
                {
                    return Err(corrupt());
                }
            }
        }
    }
    match record.state {
        TaskState::Planned
            if record.approved_at.is_some()
                || record
                    .slots
                    .iter()
                    .any(|slot| slot.state != SlotState::Pending) =>
        {
            return Err(corrupt());
        }
        TaskState::Completed
            if record
                .slots
                .iter()
                .any(|slot| slot.state != SlotState::ApiAccepted) =>
        {
            return Err(corrupt());
        }
        TaskState::Partial
            if record
                .slots
                .iter()
                .any(|slot| slot.state == SlotState::Reserved) =>
        {
            return Err(corrupt());
        }
        _ => {}
    }
    Ok(())
}

fn verify_tenant(
    record: &TaskRecord,
    tenant: Option<&opaque_core::tenant::TenantBinding>,
) -> Result<(), TaskStoreError> {
    if record.tenant.as_ref() != tenant {
        return Err(TaskStoreError::OwnerMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::task::PublishAction;
    use std::sync::{Arc, Barrier};

    const NOW: i64 = 1_800_000_000;
    const OWNER: &str = "uid:501:workspace:opaque";

    fn tenant(id: &str) -> opaque_core::tenant::TenantBinding {
        opaque_core::tenant::TenantBinding::new(
            opaque_core::tenant::TenantId::parse(id).unwrap(),
            uuid::Uuid::new_v4(),
        )
        .unwrap()
    }

    fn inference_manifest(binding: &opaque_core::tenant::TenantBinding) -> TaskManifest {
        serde_json::from_value(serde_json::json!({
            "schema_version": 3, "title": "Three public inference requests",
            "expires_in_secs": 600, "github_api_url": "", "vault_api_url": "",
            "actions": (1..=3).map(|ordinal| serde_json::json!({
                "operation": opaque_core::inference::INFERENCE_OPERATION, "ordinal": ordinal,
                "tenant": binding, "profile_id": "public-demo", "profile_sha256": "a".repeat(64),
                "model_id": "fixed-model", "model_artifact_sha256": "b".repeat(64),
                "source_id": "public-data", "source_snapshot_sha256": "c".repeat(64),
                "prompt_sha256": "d".repeat(64), "options": opaque_core::inference::InferenceOptions::default()
            })).collect::<Vec<_>>()
        })).unwrap()
    }

    #[test]
    fn tenant_ledger_refuses_foreign_owner_actions_approval_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tasks.db");
        let a = tenant("tenant-a");
        let b = tenant("tenant-b");
        let owner = a.owner_key(501, None);
        let foreign = b.owner_key(501, None);
        let store = TaskStore::open_for_tenant(&path, Some(a.clone())).unwrap();
        let task = store.create(&owner, inference_manifest(&a), NOW).unwrap();
        assert_eq!(task.tenant.as_ref(), Some(&a));
        assert!(store.create(&owner, inference_manifest(&b), NOW).is_err());
        assert!(store.create(&foreign, inference_manifest(&a), NOW).is_err());
        assert!(store.get(&task.id, &foreign, NOW).is_err());
        assert!(store.list(&foreign, NOW).is_err());
        assert!(store.claim(&task.id, &foreign, NOW).is_err());
        assert!(store.revoke(&task.id, &foreign, NOW).is_err());
        store.claim(&task.id, &owner, NOW).unwrap();
        assert!(matches!(
            store.approve(
                &task.id,
                &owner,
                &inference_manifest(&b).digest().unwrap(),
                TaskApprovalMode::PairedWorkstation,
                NOW
            ),
            Err(TaskStoreError::DigestMismatch)
        ));
        store
            .approve(
                &task.id,
                &owner,
                &task.manifest_digest,
                TaskApprovalMode::PairedWorkstation,
                NOW,
            )
            .unwrap();
        assert!(
            store
                .reserve_slot(&task.id, &foreign, &task.slots[0].id, "foreign", NOW)
                .is_err()
        );
        store
            .reserve_slot(&task.id, &owner, &task.slots[0].id, "request", NOW)
            .unwrap();
        assert!(
            store
                .authorize_dispatch(&task.id, &foreign, &task.slots[0].id, "request", NOW)
                .is_err()
        );
        drop(store);
        assert!(TaskStore::open_for_tenant(&path, Some(b)).is_err());
        assert!(TaskStore::open_for_tenant(&path, Some(tenant("tenant-a"))).is_err());
        assert!(TaskStore::open(&path).is_err());
        let store = TaskStore::open_for_tenant(&path, Some(a)).unwrap();
        let recovered = store.get(&task.id, &owner, NOW).unwrap();
        assert_eq!(recovered.state, TaskState::Partial);
        assert_eq!(recovered.slots[0].state, SlotState::Unknown);
        assert_eq!(
            recovered.slots[0]
                .action
                .as_inference()
                .unwrap()
                .options
                .max_output_tokens,
            96
        );
        assert_eq!(
            recovered.approval_mode,
            Some(TaskApprovalMode::PairedWorkstation)
        );
        assert!(store.claim(&task.id, &owner, NOW).is_err());
        assert!(
            store
                .reserve_slot(&task.id, &owner, &task.slots[1].id, "resume", NOW)
                .is_err()
        );
    }

    #[test]
    fn inference_ledger_refuses_fabricated_completion_and_cross_slot_evidence() {
        use opaque_core::inference::{InferenceReceipt, InferenceReceiptCode};
        let directory = tempfile::tempdir().unwrap();
        let binding = tenant("tenant-a");
        let owner = binding.owner_key(501, None);
        let store =
            TaskStore::open_for_tenant(&directory.path().join("tasks.db"), Some(binding.clone()))
                .unwrap();
        let task = store
            .create(&owner, inference_manifest(&binding), NOW)
            .unwrap();
        store.claim(&task.id, &owner, NOW).unwrap();
        store
            .approve(
                &task.id,
                &owner,
                &task.manifest_digest,
                TaskApprovalMode::Native,
                NOW,
            )
            .unwrap();
        let slot = &task.slots[0];
        store
            .reserve_slot(&task.id, &owner, &slot.id, "request", NOW)
            .unwrap();
        assert!(
            store
                .finalize_slot(&task.id, &owner, &slot.id, "request", accepted(), NOW)
                .is_err()
        );
        assert_eq!(
            store.get(&task.id, &owner, NOW).unwrap().slots[0].state,
            SlotState::Reserved
        );
        let action = slot.action.as_inference().unwrap();
        let mut outcome = SlotOutcome {
            state: SlotState::ApiAccepted,
            code: "api_accepted".into(),
            provider_run_id: None,
            inference_receipt: Some(InferenceReceipt {
                tenant: binding,
                profile_sha256: action.profile_sha256.clone(),
                prompt_sha256: action.prompt_sha256.clone(),
                code: InferenceReceiptCode::CompletionObserved,
                reserved_output_tokens: 96,
                input_tokens: 50,
                observed_output_tokens: Some(4),
                output_sha256: Some(opaque_core::inference::sha256(b"Public output.")),
                output_text: Some("Public output.".into()),
                duration_ms: 1,
                completed_at: NOW + 1,
            }),
        };
        let mut changed = outcome.clone();
        changed.inference_receipt.as_mut().unwrap().tenant.broker_id = uuid::Uuid::new_v4();
        assert!(
            store
                .finalize_slot(&task.id, &owner, &slot.id, "request", changed, NOW + 1)
                .is_err()
        );
        let mut changed = outcome.clone();
        changed.inference_receipt.as_mut().unwrap().prompt_sha256 = "e".repeat(64);
        assert!(
            store
                .finalize_slot(&task.id, &owner, &slot.id, "request", changed, NOW + 1)
                .is_err()
        );
        assert!(
            store
                .finalize_slot(&task.id, &owner, &slot.id, "request", outcome.clone(), NOW)
                .is_err()
        );
        outcome.inference_receipt.as_mut().unwrap().completed_at = NOW;
        let completed = store
            .finalize_slot(&task.id, &owner, &slot.id, "request", outcome, NOW)
            .unwrap();
        assert_eq!(completed.slots[0].state, SlotState::ApiAccepted);
        assert!(
            store
                .reserve_slot(&task.id, &owner, &slot.id, "again", NOW)
                .is_err()
        );
        let page = store.list_page(&owner, NOW, None).unwrap();
        assert_eq!(page.0[0], completed);
        assert!(serde_json::to_vec(&completed).unwrap().len() < 96 * 1024);
    }

    #[test]
    fn tenant_ledger_does_not_adopt_legacy_history_or_foreign_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tasks.db");
        let binding = tenant("tenant-a");
        let owner = binding.owner_key(501, None);
        let legacy = TaskStore::open(&path).unwrap();
        legacy.create(OWNER, manifest(1), NOW).unwrap();
        drop(legacy);
        assert!(TaskStore::open_for_tenant(&path, Some(binding.clone())).is_err());
        let path = directory.path().join("tenant.db");
        let store = TaskStore::open_for_tenant(&path, Some(binding.clone())).unwrap();
        let task = store
            .create(&owner, inference_manifest(&binding), NOW)
            .unwrap();
        let mut corrupt = task.clone();
        corrupt.tenant = Some(tenant("tenant-b"));
        let connection = store.connection().unwrap();
        connection
            .execute(
                "UPDATE bounded_tasks SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&corrupt).unwrap(), task.id],
            )
            .unwrap();
        drop(connection);
        assert!(store.get(&task.id, &owner, NOW).is_err());
        assert!(store.list(&owner, NOW).is_err());
        assert!(store.claim(&task.id, &owner, NOW).is_err());
    }

    fn manifest(count: usize) -> TaskManifest {
        TaskManifest {
            schema_version: 1,
            title: "Publish dogfood marker".into(),
            expires_in_secs: 600,
            github_api_url: "https://api.github.com".into(),
            vault_api_url: "https://vault.example.com".into(),
            actions: (0..count)
                .map(|index| PublishAction {
                    repo: format!("thinkstudio/repo-{index}"),
                    repository_id: index as u64 + 1,
                    secret_name: "DOGFOOD_MARKER".into(),
                    value_ref: "vault:kv/data/demo?version=7#MARKER".into(),
                    github_token_ref: Some("keychain:opaque/github-pat".into()),
                })
                .map(Into::into)
                .collect(),
        }
    }

    fn fixture() -> (tempfile::TempDir, TaskStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = TaskStore::open(&directory.path().join("tasks.sqlite3")).unwrap();
        (directory, store)
    }

    fn approved(store: &TaskStore, count: usize) -> TaskRecord {
        let task = store.create(OWNER, manifest(count), NOW).unwrap();
        store.claim(&task.id, OWNER, NOW).unwrap();
        store
            .approve(
                &task.id,
                OWNER,
                &task.manifest_digest,
                TaskApprovalMode::Native,
                NOW,
            )
            .unwrap()
    }

    fn accepted() -> SlotOutcome {
        SlotOutcome {
            provider_run_id: None,
            inference_receipt: None,
            state: SlotState::ApiAccepted,
            code: "api_accepted".into(),
        }
    }

    #[test]
    fn hundred_workers_cannot_exceed_six_slots_or_repeat_any_slot() {
        let (_directory, store) = fixture();
        let task = approved(&store, 6);
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(100));
        let workers: Vec<_> = (0..100)
            .map(|index| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                let task = task.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .reserve_slot(
                            &task.id,
                            OWNER,
                            &task.slots[index % 6].id,
                            &format!("request-{index}"),
                            NOW + 1,
                        )
                        .is_ok()
                })
            })
            .collect();
        let successes = workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>();
        assert_eq!(successes, 6);
        let receipt = store.get(&task.id, OWNER, NOW + 2).unwrap();
        assert!(
            receipt
                .slots
                .iter()
                .all(|slot| slot.state == SlotState::Reserved)
        );
        for slot in receipt.slots {
            assert!(matches!(
                store.reserve_slot(
                    &task.id,
                    OWNER,
                    &slot.id,
                    slot.request_id.as_deref().unwrap(),
                    NOW + 3
                ),
                Err(TaskStoreError::SlotConsumed)
            ));
            assert!(matches!(
                store.reserve_slot(&task.id, OWNER, &slot.id, "new-agent-session", NOW + 3),
                Err(TaskStoreError::SlotConsumed)
            ));
        }
    }

    #[test]
    fn only_one_worker_can_claim_approval_and_claim_is_not_approval() {
        let (_directory, store) = fixture();
        let task = store.create(OWNER, manifest(1), NOW).unwrap();
        let store = Arc::new(store);
        let workers: Vec<_> = (0..32)
            .map(|_| {
                let store = Arc::clone(&store);
                let task = task.clone();
                std::thread::spawn(move || store.claim(&task.id, OWNER, NOW).is_ok())
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>(),
            1
        );
        assert!(matches!(
            store.reserve_slot(&task.id, OWNER, &task.slots[0].id, "request", NOW),
            Err(TaskStoreError::NotApproved)
        ));
        assert!(matches!(
            store.approve(
                &task.id,
                OWNER,
                "wrong-digest",
                TaskApprovalMode::Native,
                NOW
            ),
            Err(TaskStoreError::DigestMismatch)
        ));
        store
            .approve(
                &task.id,
                OWNER,
                &task.manifest_digest,
                TaskApprovalMode::Native,
                NOW,
            )
            .unwrap();
        assert!(matches!(
            store.approve(
                &task.id,
                OWNER,
                &task.manifest_digest,
                TaskApprovalMode::Native,
                NOW
            ),
            Err(TaskStoreError::InvalidTransition)
        ));
    }

    #[test]
    fn completed_receipt_is_durable_and_finalization_is_exactly_once() {
        let (directory, store) = fixture();
        let task = approved(&store, 1);
        let slot = &task.slots[0].id;
        store
            .reserve_slot(&task.id, OWNER, slot, "original", NOW + 1)
            .unwrap();
        assert!(matches!(
            store.finalize_slot(&task.id, OWNER, slot, "other", accepted(), NOW + 2),
            Err(TaskStoreError::RequestMismatch)
        ));
        let receipt = store
            .finalize_slot(&task.id, OWNER, slot, "original", accepted(), NOW + 2)
            .unwrap();
        assert_eq!(receipt.state, TaskState::Completed);
        assert!(matches!(
            store.finalize_slot(&task.id, OWNER, slot, "original", accepted(), NOW + 2),
            Err(TaskStoreError::SlotConsumed)
        ));
        drop(store);
        let reopened = TaskStore::open(&directory.path().join("tasks.sqlite3")).unwrap();
        assert_eq!(reopened.get(&task.id, OWNER, NOW + 900).unwrap(), receipt);
        assert!(reopened.claim(&task.id, OWNER, NOW + 900).is_err());
    }

    #[test]
    fn approval_mode_is_recorded_only_by_approval_and_survives_restart() {
        for mode in [TaskApprovalMode::Native, TaskApprovalMode::InsecureTest] {
            let (directory, store) = fixture();
            let task = store.create(OWNER, manifest(1), NOW).unwrap();
            assert!(task.approval_mode.is_none());
            let claimed = store.claim(&task.id, OWNER, NOW).unwrap();
            assert!(claimed.approval_mode.is_none());
            assert!(store.approve(&task.id, OWNER, "wrong", mode, NOW).is_err());
            assert!(
                store
                    .get(&task.id, OWNER, NOW)
                    .unwrap()
                    .approval_mode
                    .is_none()
            );
            let receipt = store
                .approve(&task.id, OWNER, &task.manifest_digest, mode, NOW)
                .unwrap();
            assert_eq!(receipt.approval_mode, Some(mode));
            let other_mode = match mode {
                TaskApprovalMode::Native | TaskApprovalMode::PairedWorkstation => {
                    TaskApprovalMode::InsecureTest
                }
                TaskApprovalMode::InsecureTest => TaskApprovalMode::Native,
            };
            assert!(
                store
                    .approve(&task.id, OWNER, &task.manifest_digest, other_mode, NOW)
                    .is_err()
            );
            assert_eq!(
                store.get(&task.id, OWNER, NOW).unwrap().approval_mode,
                Some(mode)
            );
            store.finish_run(&task.id, OWNER, NOW + 1).unwrap();
            drop(store);
            let reopened = TaskStore::open(&directory.path().join("tasks.sqlite3")).unwrap();
            assert_eq!(
                reopened
                    .get(&task.id, OWNER, NOW + 2)
                    .unwrap()
                    .approval_mode,
                Some(mode)
            );
        }
    }

    #[test]
    fn legacy_receipt_without_approval_mode_remains_explicitly_unknown() {
        let (directory, store) = fixture();
        let task = approved(&store, 1);
        store.finish_run(&task.id, OWNER, NOW + 1).unwrap();
        let receipt = store.get(&task.id, OWNER, NOW + 1).unwrap();
        drop(store);
        let path = directory.path().join("tasks.sqlite3");
        let connection = Connection::open(&path).unwrap();
        let mut legacy = serde_json::to_value(receipt).unwrap();
        legacy.as_object_mut().unwrap().remove("approval_mode");
        connection
            .execute("UPDATE bounded_tasks SET record = ?1", [legacy.to_string()])
            .unwrap();
        drop(connection);
        let reopened = TaskStore::open(&path).unwrap();
        let receipt = reopened.get(&task.id, OWNER, NOW + 2).unwrap();
        assert_eq!(receipt.approved_at, Some(NOW));
        assert!(receipt.approval_mode.is_none());
    }

    #[test]
    fn restart_changes_reserved_to_unknown_and_never_reopens_pending_authority() {
        let (directory, store) = fixture();
        let task = approved(&store, 2);
        store
            .reserve_slot(&task.id, OWNER, &task.slots[0].id, "interrupted", NOW + 1)
            .unwrap();
        drop(store);
        let reopened = TaskStore::open(&directory.path().join("tasks.sqlite3")).unwrap();
        let receipt = reopened.get(&task.id, OWNER, NOW + 2).unwrap();
        assert_eq!(receipt.state, TaskState::Partial);
        assert_eq!(receipt.slots[0].state, SlotState::Unknown);
        assert_eq!(
            receipt.slots[0].outcome.as_ref().unwrap().code,
            "interrupted"
        );
        assert_eq!(receipt.slots[1].state, SlotState::Pending);
        assert!(reopened.claim(&task.id, OWNER, NOW + 3).is_err());
        for slot in &task.slots {
            assert!(
                reopened
                    .reserve_slot(&task.id, OWNER, &slot.id, "new-session", NOW + 3)
                    .is_err()
            );
        }
        assert!(
            reopened
                .finalize_slot(
                    &task.id,
                    OWNER,
                    &task.slots[0].id,
                    "interrupted",
                    accepted(),
                    NOW + 3
                )
                .is_err()
        );
    }

    #[test]
    fn explicit_unknown_and_rejection_are_permanently_charged() {
        let (_directory, store) = fixture();
        let task = approved(&store, 2);
        for (slot, outcome) in task.slots.iter().zip([
            SlotOutcome {
                provider_run_id: None,
                inference_receipt: None,
                state: SlotState::Unknown,
                code: "transport_unknown".into(),
            },
            SlotOutcome {
                provider_run_id: None,
                inference_receipt: None,
                state: SlotState::Rejected,
                code: "provider_rejected".into(),
            },
        ]) {
            store
                .reserve_slot(&task.id, OWNER, &slot.id, "request", NOW)
                .unwrap();
            store
                .finalize_slot(&task.id, OWNER, &slot.id, "request", outcome, NOW + 1)
                .unwrap();
            assert!(
                store
                    .reserve_slot(&task.id, OWNER, &slot.id, "retry", NOW + 2)
                    .is_err()
            );
        }
        assert_eq!(
            store.get(&task.id, OWNER, NOW + 2).unwrap().state,
            TaskState::Partial
        );
    }

    #[test]
    fn owner_binding_applies_to_reads_and_every_mutation() {
        let (_directory, store) = fixture();
        let task = approved(&store, 1);
        let wrong = "uid:501:workspace:another";
        assert!(store.list(wrong, NOW).unwrap().is_empty());
        assert!(matches!(
            store.get(&task.id, wrong, NOW),
            Err(TaskStoreError::OwnerMismatch)
        ));
        assert!(matches!(
            store.claim(&task.id, wrong, NOW),
            Err(TaskStoreError::OwnerMismatch)
        ));
        assert!(matches!(
            store.approve(
                &task.id,
                wrong,
                &task.manifest_digest,
                TaskApprovalMode::Native,
                NOW
            ),
            Err(TaskStoreError::OwnerMismatch)
        ));
        assert!(matches!(
            store.reserve_slot(&task.id, wrong, &task.slots[0].id, "r", NOW),
            Err(TaskStoreError::OwnerMismatch)
        ));
        assert!(matches!(
            store.finalize_slot(&task.id, wrong, &task.slots[0].id, "r", accepted(), NOW),
            Err(TaskStoreError::OwnerMismatch)
        ));
        assert!(matches!(
            store.finish_run(&task.id, wrong, NOW),
            Err(TaskStoreError::OwnerMismatch)
        ));
        assert!(matches!(
            store.revoke(&task.id, wrong, NOW),
            Err(TaskStoreError::OwnerMismatch)
        ));
        assert_eq!(
            store.get(&task.id, OWNER, NOW).unwrap().state,
            TaskState::Running
        );
    }

    #[test]
    fn expiry_at_exact_deadline_blocks_claim_approval_and_reservation() {
        let (_directory, store) = fixture();
        let planned = store.create(OWNER, manifest(1), NOW).unwrap();
        assert!(matches!(
            store.claim(&planned.id, OWNER, planned.expires_at),
            Err(TaskStoreError::Expired)
        ));
        let waiting = store.create(OWNER, manifest(1), NOW).unwrap();
        store.claim(&waiting.id, OWNER, NOW).unwrap();
        assert!(matches!(
            store.approve(
                &waiting.id,
                OWNER,
                &waiting.manifest_digest,
                TaskApprovalMode::Native,
                waiting.expires_at
            ),
            Err(TaskStoreError::Expired)
        ));
        let task = approved(&store, 2);
        store
            .reserve_slot(
                &task.id,
                OWNER,
                &task.slots[0].id,
                "in-flight",
                task.expires_at - 1,
            )
            .unwrap();
        assert!(matches!(
            store.reserve_slot(&task.id, OWNER, &task.slots[1].id, "late", task.expires_at),
            Err(TaskStoreError::Expired)
        ));
        let receipt = store
            .finalize_slot(
                &task.id,
                OWNER,
                &task.slots[0].id,
                "in-flight",
                accepted(),
                task.expires_at + 1,
            )
            .unwrap();
        assert_eq!(receipt.state, TaskState::Expired);
        assert_eq!(receipt.slots[0].state, SlotState::ApiAccepted);
        assert_eq!(receipt.slots[1].state, SlotState::Pending);
    }

    #[test]
    fn revocation_preserves_inflight_evidence_and_blocks_future_reservations() {
        let (_directory, store) = fixture();
        let task = approved(&store, 2);
        store
            .reserve_slot(&task.id, OWNER, &task.slots[0].id, "in-flight", NOW)
            .unwrap();
        let revoked = store.revoke(&task.id, OWNER, NOW + 1).unwrap();
        assert_eq!(revoked.slots[0].state, SlotState::Reserved);
        assert!(matches!(
            store.reserve_slot(&task.id, OWNER, &task.slots[1].id, "after-revoke", NOW + 1),
            Err(TaskStoreError::Revoked)
        ));
        let receipt = store
            .finalize_slot(
                &task.id,
                OWNER,
                &task.slots[0].id,
                "in-flight",
                accepted(),
                NOW + 2,
            )
            .unwrap();
        assert_eq!(receipt.state, TaskState::Revoked);
        assert_eq!(receipt.slots[0].state, SlotState::ApiAccepted);
        assert!(store.claim(&task.id, OWNER, NOW + 3).is_err());
    }

    #[test]
    fn revocation_and_reservation_have_one_transactional_order() {
        let (_directory, store) = fixture();
        let task = approved(&store, 1);
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(2));
        let worker = {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let task = task.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.reserve_slot(&task.id, OWNER, &task.slots[0].id, "racing", NOW)
            })
        };
        barrier.wait();
        store.revoke(&task.id, OWNER, NOW).unwrap();
        let result = worker.join().unwrap();
        let receipt = store.get(&task.id, OWNER, NOW).unwrap();
        assert_eq!(receipt.state, TaskState::Revoked);
        if result.is_ok() {
            assert_eq!(receipt.slots[0].state, SlotState::Reserved);
        } else {
            assert!(matches!(result, Err(TaskStoreError::Revoked)));
            assert_eq!(receipt.slots[0].state, SlotState::Pending);
        }
        assert!(matches!(
            store.reserve_slot(&task.id, OWNER, &task.slots[0].id, "later", NOW),
            Err(TaskStoreError::Revoked)
        ));
    }

    #[test]
    fn partial_run_requires_new_task_and_fresh_approval() {
        let (_directory, store) = fixture();
        let task = store.create(OWNER, manifest(1), NOW).unwrap();
        store.claim(&task.id, OWNER, NOW).unwrap();
        let receipt = store.finish_run(&task.id, OWNER, NOW + 1).unwrap();
        assert_eq!(receipt.state, TaskState::Partial);
        assert!(receipt.approved_at.is_none());
        assert!(store.claim(&task.id, OWNER, NOW + 2).is_err());
        assert!(
            store
                .approve(
                    &task.id,
                    OWNER,
                    &task.manifest_digest,
                    TaskApprovalMode::Native,
                    NOW + 2
                )
                .is_err()
        );
        let replacement = store.create(OWNER, task.manifest, NOW + 3).unwrap();
        assert_ne!(replacement.id, task.id);
        assert_eq!(replacement.state, TaskState::Planned);
        assert!(
            store
                .reserve_slot(
                    &replacement.id,
                    OWNER,
                    &replacement.slots[0].id,
                    "r",
                    NOW + 3
                )
                .is_err()
        );
    }

    #[test]
    fn dispatch_fence_observes_revoke_expiry_and_reservation_owner() {
        let (_directory, store) = fixture();
        let task = approved(&store, 1);
        let slot = &task.slots[0].id;
        assert!(
            store
                .authorize_dispatch(&task.id, OWNER, slot, "r", NOW)
                .is_err()
        );
        store.reserve_slot(&task.id, OWNER, slot, "r", NOW).unwrap();
        assert!(matches!(
            store.authorize_dispatch(&task.id, OWNER, slot, "other", NOW),
            Err(TaskStoreError::RequestMismatch)
        ));
        store
            .authorize_dispatch(&task.id, OWNER, slot, "r", NOW)
            .unwrap();
        store.revoke(&task.id, OWNER, NOW + 1).unwrap();
        assert!(matches!(
            store.authorize_dispatch(&task.id, OWNER, slot, "r", NOW + 1),
            Err(TaskStoreError::Revoked)
        ));

        let task = approved(&store, 1);
        let slot = &task.slots[0].id;
        store.reserve_slot(&task.id, OWNER, slot, "r", NOW).unwrap();
        assert!(matches!(
            store.authorize_dispatch(&task.id, OWNER, slot, "r", task.expires_at),
            Err(TaskStoreError::Expired)
        ));
    }

    #[test]
    fn cancellation_seals_reserved_slots_and_preserves_terminal_task_state() {
        for revoke in [false, true] {
            let (_directory, store) = fixture();
            let task = approved(&store, 2);
            store
                .reserve_slot(&task.id, OWNER, &task.slots[0].id, "r", NOW)
                .unwrap();
            if revoke {
                store.revoke(&task.id, OWNER, NOW + 1).unwrap();
            }
            let receipt = store.finish_run(&task.id, OWNER, NOW + 2).unwrap();
            assert_eq!(
                receipt.state,
                if revoke {
                    TaskState::Revoked
                } else {
                    TaskState::Partial
                }
            );
            assert_eq!(receipt.approved_at, Some(NOW));
            assert_eq!(receipt.slots[0].state, SlotState::Unknown);
            assert_eq!(
                receipt.slots[0].outcome.as_ref().unwrap().code,
                "interrupted"
            );
            assert_eq!(receipt.slots[1].state, SlotState::Pending);
            assert!(
                store
                    .authorize_dispatch(&task.id, OWNER, &task.slots[0].id, "r", NOW + 3)
                    .is_err()
            );
            assert!(
                store
                    .reserve_slot(&task.id, OWNER, &task.slots[1].id, "new", NOW + 3)
                    .is_err()
            );
        }
    }

    #[test]
    fn malformed_or_semantically_corrupt_ledgers_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let malformed = directory.path().join("malformed.sqlite3");
        std::fs::write(&malformed, b"this is not a database").unwrap();
        assert!(TaskStore::open(&malformed).is_err());

        let path = directory.path().join("tasks.sqlite3");
        let store = TaskStore::open(&path).unwrap();
        let task = approved(&store, 1);
        drop(store);
        let connection = Connection::open(&path).unwrap();
        let mut corrupted = serde_json::to_value(task).unwrap();
        corrupted["manifest"]["actions"][0]["value_ref"] =
            "vault:kv/data/demo?version=8#MARKER".into();
        connection
            .execute(
                "UPDATE bounded_tasks SET record = ?1",
                [corrupted.to_string()],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Corrupt)
        ));
    }

    #[test]
    fn missing_table_in_an_established_ledger_is_not_recreated() {
        let (directory, store) = fixture();
        approved(&store, 1);
        drop(store);
        let path = directory.path().join("tasks.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection.execute("DROP TABLE bounded_tasks", []).unwrap();
        drop(connection);
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Corrupt)
        ));
    }

    fn maximum_manifest() -> TaskManifest {
        let mut manifest = manifest(32);
        manifest.title = "\\".repeat(160);
        manifest.expires_in_secs = 3600;
        manifest.github_api_url = format!("https://api.github.com/{}", "p".repeat(2025));
        manifest.vault_api_url = manifest.github_api_url.clone();
        for (index, action) in manifest.actions.iter_mut().enumerate() {
            let action = action.as_publish_mut().unwrap();
            action.repo = format!("{}/{}", "o".repeat(39), "r".repeat(100));
            action.repository_id = u64::MAX - index as u64;
            action.secret_name = format!("S{index:02}{}", "S".repeat(97));
            action.value_ref = format!(
                "vault:{}/data/{}?version=9223372036854775807#{}",
                "m".repeat(32),
                "p".repeat(474),
                "F".repeat(128)
            );
            action.github_token_ref = Some(format!("keychain:{}p", "p-".repeat(59)));
        }
        manifest
    }

    #[test]
    fn maximum_charged_receipt_and_pagination_fit_ipc_without_losing_older_tasks() {
        let (_directory, store) = fixture();
        let owner = "\\".repeat(1024);
        let now = i64::MAX - 3600;
        let task = store.create(&owner, maximum_manifest(), now).unwrap();
        store.claim(&task.id, &owner, now).unwrap();
        store
            .approve(
                &task.id,
                &owner,
                &task.manifest_digest,
                TaskApprovalMode::Native,
                now,
            )
            .unwrap();
        let request = "r".repeat(128);
        for slot in &task.slots {
            store
                .reserve_slot(&task.id, &owner, &slot.id, &request, now)
                .unwrap();
            store
                .finalize_slot(&task.id, &owner, &slot.id, &request, accepted(), now)
                .unwrap();
        }
        let newer = store.create(&owner, maximum_manifest(), now).unwrap();
        let (page, has_more, cursor) = store.list_page(&owner, now, None).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, newer.id);
        assert!(has_more);
        assert_eq!(cursor.as_deref(), Some(newer.id.as_str()));
        let wire = serde_json::to_vec(&serde_json::json!({"id":1,"result":{"tasks":page,"has_more":has_more,"next_cursor":cursor}})).unwrap();
        assert!(wire.len() < 96 * 1024, "page is {} bytes", wire.len());

        // A new arrival between pages cannot duplicate or skip older records.
        store.create(&owner, maximum_manifest(), now).unwrap();
        let (page, has_more, cursor) = store.list_page(&owner, now, Some(&newer.id)).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, task.id);
        assert_eq!(page[0].state, TaskState::Completed);
        assert!(!has_more);
        assert!(cursor.is_none());
        let wire = serde_json::to_vec(&serde_json::json!({"id":1,"result":{"tasks":page,"has_more":has_more,"next_cursor":cursor}})).unwrap();
        assert!(
            wire.len() < 96 * 1024,
            "charged page is {} bytes",
            wire.len()
        );
        assert!(wire.len() < opaque_core::MAX_FRAME_LENGTH);
        assert!(matches!(
            store.list_page(&owner, now, Some("missing")),
            Err(TaskStoreError::InvalidCursor)
        ));
        assert!(matches!(
            store.list_page(OWNER, now, Some(&task.id)),
            Err(TaskStoreError::InvalidCursor)
        ));
    }

    #[test]
    fn second_writer_and_alternate_hardlink_cannot_recover_live_reservations() {
        let (directory, store) = fixture();
        let task = approved(&store, 1);
        store
            .reserve_slot(&task.id, OWNER, &task.slots[0].id, "r", NOW)
            .unwrap();
        let path = directory.path().join("tasks.sqlite3");
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Locked)
        ));
        let alias = directory.path().join("alias.sqlite3");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(
            TaskStore::open(&alias),
            Err(TaskStoreError::Corrupt)
        ));
        assert_eq!(
            store.get(&task.id, OWNER, NOW).unwrap().slots[0].state,
            SlotState::Reserved
        );
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn drop_unlocks_while_forked_child_still_holds_inherited_descriptor() {
        struct Child {
            pid: libc::pid_t,
            release_fd: libc::c_int,
        }
        impl Drop for Child {
            fn drop(&mut self) {
                // Always release and reap the child, including on assertion
                // failure. The child performs no Rust/SQLite work after fork.
                let byte = 1_u8;
                // SAFETY: these descriptors and pid are owned by this guard.
                unsafe {
                    libc::write(self.release_fd, std::ptr::addr_of!(byte).cast(), 1);
                    libc::close(self.release_fd);
                    loop {
                        if libc::waitpid(self.pid, std::ptr::null_mut(), 0) >= 0
                            || std::io::Error::last_os_error().kind()
                                != std::io::ErrorKind::Interrupted
                        {
                            break;
                        }
                    }
                }
            }
        }

        let (directory, store) = fixture();
        let path = directory.path().join("tasks.sqlite3");
        let task = approved(&store, 1);
        store
            .reserve_slot(&task.id, OWNER, &task.slots[0].id, "in-flight", NOW)
            .unwrap();
        let mut descriptors = [-1; 2];
        // SAFETY: pipe receives space for two fds; fork's child branch below
        // uses only async-signal-safe syscalls until _exit, with no Rust drops.
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::close(descriptors[1]);
                let mut byte = 0_u8;
                while libc::read(descriptors[0], std::ptr::addr_of_mut!(byte).cast(), 1) < 0 {}
                libc::_exit(0);
            }
        }
        if pid < 0 {
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            panic!("fork failed");
        }
        // SAFETY: the parent retains only its pipe writer; Child owns cleanup.
        unsafe {
            libc::close(descriptors[0]);
        }
        let _child = Child {
            pid,
            release_fd: descriptors[1],
        };
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Locked)
        ));
        drop(store);
        // The child remains blocked on its pipe and still owns the inherited
        // lock fd. Reopening must nevertheless be immediate and exclusive.
        let reopened = TaskStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(&task.id, OWNER, NOW).unwrap().slots[0].state,
            SlotState::Unknown
        );
        assert!(matches!(
            TaskStore::open(&path),
            Err(TaskStoreError::Locked)
        ));
    }
    #[test]
    fn release_observations_preserve_authority_provenance_and_ambiguity_across_restart() {
        use opaque_core::release::{
            ReleaseCorrelation, ReleaseObservation, ReleaseObservationState,
        };
        let (directory, store) = fixture();
        let manifest: TaskManifest = serde_json::from_value(serde_json::json!({
            "schema_version":2,"title":"Staging artifact","expires_in_secs":600,
            "github_api_url":"https://api.github.com", "actions":[{
                "operation":"github.dispatch_staging_workflow", "repo":"owner/app", "repository_id":42,
                "workflow_path":".github/workflows/staging.yml", "workflow_id":7,"workflow_ref":"main",
                "approved_commit_sha":"a".repeat(40),"workflow_sha256":"b".repeat(64),
                "image_repository":"ghcr.io/owner/app","image_digest":format!("sha256:{}","c".repeat(64)),
                "environment":"staging","github_token_ref":"keychain:opaque/github-pat"
            }]
        })).unwrap();
        let task = store.create("owner", manifest, 100).unwrap();
        let observation = ReleaseObservation {
            state: ReleaseObservationState::Succeeded,
            code: "workflow_succeeded".into(),
            run_id: Some(17),
            run_url: Some("https://api.github.com/repos/owner/app/actions/runs/17".into()),
            observed_commit_sha: Some("a".repeat(40)),
            checked_at: 110,
            run_attempt: Some(1),
            correlation: ReleaseCorrelation::DispatchResponse,
        };
        assert!(
            store
                .record_release_observation(&task.id, "owner", observation.clone(), 110)
                .is_err()
        );
        store.claim(&task.id, "owner", 101).unwrap();
        store
            .approve(
                &task.id,
                "owner",
                &task.manifest_digest,
                TaskApprovalMode::PairedWorkstation,
                102,
            )
            .unwrap();
        let request = uuid::Uuid::new_v4().to_string();
        store
            .reserve_slot(&task.id, "owner", &task.slots[0].id, &request, 103)
            .unwrap();
        store
            .finalize_slot(
                &task.id,
                "owner",
                &task.slots[0].id,
                &request,
                SlotOutcome {
                    state: SlotState::ApiAccepted,
                    code: "api_accepted".into(),
                    provider_run_id: Some(17),
                    inference_receipt: None,
                },
                104,
            )
            .unwrap();
        let finished = store.finish_run(&task.id, "owner", 105).unwrap();
        let observed = store
            .record_release_observation(&task.id, "owner", observation.clone(), 110)
            .unwrap();
        assert_eq!(observed.slots, finished.slots);
        assert_eq!(observed.manifest_digest, finished.manifest_digest);
        assert_eq!(
            observed.approval_mode,
            Some(TaskApprovalMode::PairedWorkstation)
        );
        assert!(store.claim(&task.id, "owner", 111).is_err());
        assert!(
            store
                .record_release_observation(&task.id, "other", observation.clone(), 111)
                .is_err()
        );
        let mut wrong = observation.clone();
        wrong.correlation = ReleaseCorrelation::TaskTitle;
        assert!(
            store
                .record_release_observation(&task.id, "owner", wrong, 111)
                .is_err()
        );
        let missing = ReleaseObservation {
            state: ReleaseObservationState::Pending,
            code: "run_not_observed".into(),
            run_id: None,
            run_url: None,
            observed_commit_sha: None,
            checked_at: 111,
            run_attempt: None,
            correlation: ReleaseCorrelation::DispatchResponse,
        };
        let ambiguous = store
            .record_release_observation(&task.id, "owner", missing, 111)
            .unwrap();
        assert_eq!(
            ambiguous.release_observation.as_ref().unwrap().state,
            ReleaseObservationState::Ambiguous
        );
        let mut newer = observation;
        newer.checked_at = 112;
        assert_eq!(
            store
                .record_release_observation(&task.id, "owner", newer, 112)
                .unwrap()
                .release_observation,
            ambiguous.release_observation
        );
        drop(store);
        let reopened = TaskStore::open(&directory.path().join("tasks.sqlite3")).unwrap();
        let final_record = reopened.get(&task.id, "owner", 113).unwrap();
        assert_eq!(final_record.slots, finished.slots);
        assert_eq!(
            final_record.release_observation,
            ambiguous.release_observation
        );
        assert_eq!(
            final_record.approval_mode,
            Some(TaskApprovalMode::PairedWorkstation)
        );
    }
}
