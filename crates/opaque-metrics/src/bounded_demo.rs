//! A fixture-only, persistent, single-use aggregate task. This is deliberately
//! not a production approval protocol or a substitute for the broker ledger.
use crate::{
    auth::VerifiedAccess,
    metrics::{MetricsEvidence, MetricsQuery, MetricsSourceConfig},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};
use uuid::Uuid;

pub const METRIC: &str = "manual_review_rate_percent";
pub fn query() -> MetricsQuery {
    MetricsQuery {
        window_secs: 60,
        metrics: vec![METRIC.into()],
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub operation: String,
    pub tenant_id: String,
    pub source_id: String,
    pub source_profile_sha256: String,
    pub metrics: Vec<String>,
    pub window_secs: u32,
    pub max_uses: u32,
    pub created_at: i64,
    pub expires_at: i64,
    pub subject: String,
    pub client_id: String,
    pub persona_generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Planned,
    Approved,
    Reserved,
    Completed,
    Unknown,
    Revoked,
    Expired,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub kind: String,
    pub approved_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<ApprovalVerification>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalVerification {
    pub issuer: Option<String>,
    pub subject: String,
    pub credential_sha256: Option<String>,
    pub user_verified: Option<bool>,
}
impl Approval {
    fn is_verified(&self) -> bool {
        self.verification.as_ref().is_some_and(|verification| {
            !verification.subject.is_empty()
                && match self.kind.as_str() {
                    "webauthn" => {
                        verification.user_verified == Some(true)
                            && verification.issuer.is_none()
                            && verification
                                .credential_sha256
                                .as_ref()
                                .is_some_and(|digest| {
                                    digest.len() == 64
                                        && digest.bytes().all(|byte| {
                                            byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                                        })
                                })
                    }
                    "oidc" => {
                        verification.user_verified.is_none()
                            && verification.credential_sha256.is_none()
                            && verification.issuer.as_ref().is_some_and(|issuer| {
                                reqwest::Url::parse(issuer).is_ok_and(|url| {
                                    url.scheme() == "https" && url.host_str().is_some()
                                })
                            })
                    }
                    "github_oauth" => {
                        verification.user_verified.is_none()
                            && verification.credential_sha256.is_none()
                            && verification.issuer.as_deref() == Some("https://github.com")
                            && verification
                                .subject
                                .bytes()
                                .all(|byte| byte.is_ascii_digit())
                    }
                    _ => false,
                }
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub evidence: String,
    pub completed_at: i64,
    pub evidence_sha256: String,
    pub result: MetricsEvidence,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub task_id: String,
    pub manifest_sha256: String,
    pub state: TaskState,
    pub consumed: bool,
    pub manifest: Manifest,
    pub approval: Option<Approval>,
    pub receipt: Option<Receipt>,
    pub simulation: bool,
    pub notice: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskReference {
    pub task_id: String,
    pub manifest_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    task: Task,
    authorizing_jti: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Forbidden,
    Conflict,
}
pub struct Store {
    connection: Connection,
    profile_sha256: String,
}
fn hash(value: &impl Serialize) -> Result<String, Error> {
    serde_json::to_vec(value)
        .map(|v| format!("{:x}", Sha256::digest(v)))
        .map_err(|_| Error::Unavailable)
}
impl Store {
    pub fn open(directory: &Path, source: &MetricsSourceConfig) -> Result<Self, Error> {
        if !source.allowed_metrics.iter().any(|m| m == METRIC) || source.max_window_secs < 60 {
            return Err(Error::Unavailable);
        }
        let profile_sha256 = hash(
            &serde_json::json!({"tenant_id":source.tenant_id,"source_id":source.source_id,
            "base_url":source.base_url,"credential_env":source.credential_env,"allowed_metrics":source.allowed_metrics,
            "max_window_secs":source.max_window_secs,"max_staleness_secs":source.max_staleness_secs,
            "allow_loopback_http":source.allow_loopback_http}),
        )?;
        let path = directory.join("bounded-demo.sqlite3");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| Error::Unavailable)?;
        let connection = Connection::open(path).map_err(|_| Error::Unavailable)?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS task (id INTEGER PRIMARY KEY CHECK(id=1), record TEXT NOT NULL);")
            .map_err(|_| Error::Unavailable)?;
        let mut store = Self {
            connection,
            profile_sha256,
        };
        store.change(|record| {
            if let Some(record) = record
                && record.task.state == TaskState::Reserved
            {
                record.task.state = TaskState::Unknown;
                record.task.receipt = None;
            }
            Ok(())
        })?;
        Ok(store)
    }
    fn change<T>(
        &mut self,
        op: impl FnOnce(&mut Option<Record>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Unavailable)?;
        let raw: Option<String> = transaction
            .query_row("SELECT record FROM task WHERE id=1", [], |row| row.get(0))
            .optional()
            .map_err(|_| Error::Unavailable)?;
        let mut record: Option<Record> = raw
            .map(|raw| serde_json::from_str(&raw).map_err(|_| Error::Unavailable))
            .transpose()?;
        if let Some(record) = &record
            && (record.task.manifest.source_profile_sha256 != self.profile_sha256
                || record.task.manifest_sha256 != hash(&record.task.manifest)?
                || record.task.manifest.operation != "metrics.aggregate.read"
                || record.task.manifest.metrics != [METRIC]
                || record.task.manifest.window_secs != 60
                || record.task.manifest.max_uses != 1
                || !record.task.simulation
                || record.task.manifest.expires_at <= record.task.manifest.created_at
                || record.task.manifest.expires_at - record.task.manifest.created_at > 300
                || (matches!(
                    record.task.state,
                    TaskState::Reserved | TaskState::Completed | TaskState::Unknown
                ) && !record.task.consumed)
                || (record.task.receipt.is_some() && record.task.state != TaskState::Completed))
        {
            return Err(Error::Unavailable);
        }
        let result = op(&mut record)?;
        if let Some(record) = record {
            let encoded = serde_json::to_string(&record).map_err(|_| Error::Unavailable)?;
            transaction.execute("INSERT INTO task(id,record) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET record=excluded.record", params![encoded]).map_err(|_| Error::Unavailable)?;
        }
        transaction.commit().map_err(|_| Error::Unavailable)?;
        Ok(result)
    }
    fn owner(record: &Record, access: &VerifiedAccess) -> Result<(), Error> {
        if record.task.manifest.tenant_id != access.tenant_id()
            || record.task.manifest.subject != access.subject()
            || record.task.manifest.client_id != access.client_id()
            || record.authorizing_jti != access.jti()
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    fn reference(record: &Record, reference: &TaskReference) -> Result<(), Error> {
        if record.task.task_id != reference.task_id
            || record.task.manifest_sha256 != reference.manifest_sha256
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn invalidate(record: &mut Record, epoch: u64, now: i64) {
        if record.task.manifest.persona_generation != epoch {
            record.task.state = TaskState::Revoked;
            record.task.receipt = None;
        } else if record.task.manifest.expires_at <= now
            && matches!(
                record.task.state,
                TaskState::Planned
                    | TaskState::Approved
                    | TaskState::Reserved
                    | TaskState::Completed
            )
        {
            record.task.state = TaskState::Expired;
            record.task.receipt = None;
        }
    }
    pub fn current(
        &mut self,
        access: &VerifiedAccess,
        epoch: u64,
        now: i64,
        source: &MetricsSourceConfig,
    ) -> Result<Task, Error> {
        let profile = self.profile_sha256.clone();
        self.change(|record| {
            if record.is_none() {
                if access.expires_at() <= now { return Err(Error::Forbidden); }
                let manifest = Manifest { operation: "metrics.aggregate.read".into(), tenant_id: access.tenant_id().into(), source_id: source.source_id.clone(),
                    source_profile_sha256: profile, metrics: vec![METRIC.into()], window_secs: 60, max_uses: 1,
                    created_at: now, expires_at: (now + 300).min(access.expires_at()), subject: access.subject().into(), client_id: access.client_id().into(), persona_generation: epoch };
                *record = Some(Record { authorizing_jti: access.jti().into(), task: Task { task_id: Uuid::new_v4().to_string(), manifest_sha256: hash(&manifest)?,
                    manifest, state: TaskState::Planned, consumed: false, approval: None, receipt: None, simulation: true,
                    notice: "One read of synthetic aggregate data. Approval verifies a passkey or configured OAuth identity; production tenant membership and broker-signed approval are not demonstrated.".into() } });
            }
            let record = record.as_mut().ok_or(Error::Unavailable)?;
            Self::owner(record, access)?;
            Self::invalidate(record, epoch, now);
            Ok(record.task.clone())
        })
    }
    pub fn transition(
        &mut self,
        access: &VerifiedAccess,
        epoch: u64,
        now: i64,
        reference: &TaskReference,
        target: TaskState,
    ) -> Result<Task, Error> {
        self.transition_with_approval(access, epoch, now, reference, target, None)
    }
    pub fn approve_verified(
        &mut self,
        access: &VerifiedAccess,
        epoch: u64,
        now: i64,
        reference: &TaskReference,
        approval: Approval,
    ) -> Result<Task, Error> {
        if approval.approved_at != now || !approval.is_verified() {
            return Err(Error::Forbidden);
        }
        self.transition_with_approval(
            access,
            epoch,
            now,
            reference,
            TaskState::Approved,
            Some(approval),
        )
    }
    fn transition_with_approval(
        &mut self,
        access: &VerifiedAccess,
        epoch: u64,
        now: i64,
        reference: &TaskReference,
        target: TaskState,
        approval: Option<Approval>,
    ) -> Result<Task, Error> {
        // Commit invalidation independently, including when the subsequent
        // requested transition is denied. A denied request cannot revive a task.
        self.change(|record| {
            let record = record.as_mut().ok_or(Error::Conflict)?;
            Self::owner(record, access)?;
            Self::reference(record, reference)?;
            Self::invalidate(record, epoch, now);
            Ok(())
        })?;
        self.change(|record| {
            let record = record.as_mut().ok_or(Error::Conflict)?;
            Self::owner(record, access)?;
            Self::reference(record, reference)?;
            match target {
                TaskState::Approved if record.task.state == TaskState::Planned => {
                    record.task.approval = Some(approval.ok_or(Error::Forbidden)?);
                }
                TaskState::Reserved
                    if record.task.state == TaskState::Approved
                        && !record.task.consumed
                        && record
                            .task
                            .approval
                            .as_ref()
                            .is_some_and(Approval::is_verified) =>
                {
                    record.task.consumed = true;
                }
                TaskState::Revoked => {
                    record.task.receipt = None;
                }
                _ => return Err(Error::Conflict),
            }
            record.task.state = target;
            Ok(record.task.clone())
        })
    }
    pub fn finish(
        &mut self,
        reference: &TaskReference,
        now: i64,
        evidence: Option<MetricsEvidence>,
    ) -> Result<Task, Error> {
        self.change(|record| {
            let record = record.as_mut().ok_or(Error::Conflict)?;
            Self::reference(record, reference)?;
            if record.task.state != TaskState::Reserved {
                return Ok(record.task.clone());
            }
            if now >= record.task.manifest.expires_at {
                record.task.state = TaskState::Expired;
            } else if let Some(result) = evidence {
                if result.tenant_id != record.task.manifest.tenant_id
                    || result.source_id != record.task.manifest.source_id
                    || result.window_secs != 60
                    || result.metrics.len() != 1
                    || result.metrics[0].name != METRIC
                {
                    return Err(Error::Unavailable);
                }
                record.task.receipt = Some(Receipt {
                    evidence: "synthetic_source_observed".into(),
                    completed_at: now,
                    evidence_sha256: hash(&result)?,
                    result,
                });
                record.task.state = TaskState::Completed;
            } else {
                record.task.state = TaskState::Unknown;
            }
            Ok(record.task.clone())
        })
    }
    pub fn revoke_for_identity_change(&mut self) -> Result<(), Error> {
        self.change(|record| {
            if let Some(record) = record {
                record.task.state = TaskState::Revoked;
                record.task.receipt = None;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_approval_metadata_requires_pinned_issuer_and_stable_numeric_identity() {
        let approval = Approval {
            kind: "github_oauth".into(),
            approved_at: 100,
            verification: Some(ApprovalVerification {
                issuer: Some("https://github.com".into()),
                subject: "12345".into(),
                credential_sha256: None,
                user_verified: None,
            }),
        };
        assert!(approval.is_verified());
        for mutation in 0..5 {
            let mut changed = approval.clone();
            let verification = changed.verification.as_mut().unwrap();
            match mutation {
                0 => verification.issuer = Some("https://foreign.example".into()),
                1 => verification.subject = "mutable-github-handle".into(),
                2 => verification.subject.clear(),
                3 => verification.user_verified = Some(true),
                _ => verification.credential_sha256 = Some("a".repeat(64)),
            }
            assert!(!changed.is_verified());
        }
    }
}
