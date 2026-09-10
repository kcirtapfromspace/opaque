//! Enrolled broker inventory. A collector trusts an operator-enrolled key and
//! verifies a signed, challenge-bound software report. No unregistered endpoint
//! discovery or hardware measurement is inferred from these reports.
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use opaque_core::{
    attest::{ReportPayload, verify_report},
    tenant::TenantBinding,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub mod reporter;
type Result<T> = std::result::Result<T, String>;
const MAX_BATCH: usize = 128;
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS brokers(tenant TEXT NOT NULL,broker TEXT NOT NULL,key TEXT NOT NULL,epoch INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,expected_policy_version INTEGER,expected_policy_digest TEXT,last_contact INTEGER,report TEXT,challenge TEXT,challenge_expires INTEGER,ack_seq INTEGER,coverage_start INTEGER,latest_receipt_digest TEXT,PRIMARY KEY(tenant,broker));
CREATE TABLE IF NOT EXISTS broker_evidence(tenant TEXT NOT NULL,broker TEXT NOT NULL,observed_head INTEGER,health TEXT NOT NULL,PRIMARY KEY(tenant,broker));
INSERT OR IGNORE INTO broker_evidence SELECT tenant,broker,json_extract(report,'$.evidence.audit_head'),'unknown' FROM brokers;
CREATE TABLE IF NOT EXISTS enrollment_keys(key TEXT PRIMARY KEY,tenant TEXT NOT NULL,broker TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,broker TEXT NOT NULL,epoch INTEGER NOT NULL,action TEXT NOT NULL,occurred_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fleet_receipts(tenant TEXT NOT NULL,broker TEXT NOT NULL,epoch INTEGER NOT NULL,last_sequence INTEGER NOT NULL,first_sequence INTEGER NOT NULL,batch_digest TEXT NOT NULL,received_at INTEGER NOT NULL,PRIMARY KEY(tenant,broker,epoch,last_sequence));
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub binding: TenantBinding,
    pub public_key: String,
    #[serde(default)]
    pub expected_policy_version: Option<u64>,
    #[serde(default)]
    pub expected_policy_digest: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub binding: TenantBinding,
    pub epoch: u64,
    pub nonce: String,
    pub expires_at: i64,
    pub acknowledged_sequence: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEntry {
    pub sequence: u64,
    pub event_id: String,
    pub record_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub audit_head: Option<u64>,
    pub export_entries: Vec<ExportEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub schema_version: u32,
    pub challenge: Challenge,
    pub evidence: Evidence,
    pub report: String,
}
impl Heartbeat {
    /// Existing attestation signatures bind this exact tenant, broker, key
    /// epoch, nonce and evidence by hashing them into the attestation nonce.
    pub fn nonce_for(challenge: &Challenge, evidence: &Evidence) -> Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"opaque.fleet.heartbeat.v1\0");
        hash.update(serde_json::to_vec(&(challenge, evidence)).map_err(|_| "invalid heartbeat")?);
        Ok(format!("{:x}", hash.finalize()))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgment {
    pub binding: TenantBinding,
    pub epoch: u64,
    pub received_at: i64,
    pub acknowledged_sequence: Option<u64>,
    pub receipt_digest: Option<String>,
    pub evidence_health: String,
}

pub struct FleetStore {
    conn: Mutex<Connection>,
}
fn sql<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|_| "fleet store unavailable".into())
}
fn key(text: &str) -> Result<ed25519_dalek::VerifyingKey> {
    opaque_core::bundle::parse_anchor(text).map_err(|_| "invalid enrolled public key".into())
}
fn digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn binding_parts(binding: &TenantBinding) -> Result<(String, String)> {
    binding
        .validate()
        .map_err(|_| "invalid tenant/broker binding")?;
    Ok((binding.tenant_id.to_string(), binding.broker_id.to_string()))
}
fn now() -> i64 {
    opaque_core::identity::now_unix()
}

impl FleetStore {
    /// Store directory is a private operator custody boundary, not a shared
    /// tenant data directory. CLI mutations never go through the read API.
    pub fn open(directory: &Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        if !directory.is_absolute() {
            return Err("fleet directory must be absolute".into());
        }
        if !directory.exists() {
            std::fs::create_dir(directory).map_err(|_| "fleet directory unavailable")?;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "fleet directory unavailable")?;
        }
        let meta =
            std::fs::symlink_metadata(directory).map_err(|_| "fleet directory unavailable")?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7077 != 0 {
            return Err("fleet directory must be privately owned".into());
        }
        let db_path = directory.join("fleet.db");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&db_path)
            .map_err(|_| "fleet database unavailable")?;
        let meta = file.metadata().map_err(|_| "fleet database unavailable")?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7077 != 0
        {
            return Err("fleet database must be privately owned".into());
        }
        let conn = sql(Connection::open(db_path))?;
        sql(conn.execute_batch(SCHEMA))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| "fleet state poisoned".into())
    }
    /// Initial enrollment requires a unique operator-pinned key. The first
    /// accepted report proves possession; labels cannot enroll a broker.
    pub fn enroll(&self, enrollment: &Enrollment, rotate: bool, now: i64) -> Result<u64> {
        let (tenant, broker) = binding_parts(&enrollment.binding)?;
        if !digest(&enrollment.public_key) {
            return Err("enrolled key must be canonical lowercase hex".into());
        }
        key(&enrollment.public_key)?;
        if enrollment
            .expected_policy_version
            .is_some_and(|v| v == 0 || v > i64::MAX as u64)
            || enrollment
                .expected_policy_digest
                .as_ref()
                .is_some_and(|d| !digest(d))
        {
            return Err("invalid expected policy".into());
        }
        let mut conn = self.lock()?;
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let existing: Option<(u64, bool)> = sql(tx
            .query_row(
                "SELECT epoch,revoked FROM brokers WHERE tenant=?1 AND broker=?2",
                params![tenant, broker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let epoch = match (existing, rotate) {
            (None, false) => 1,
            (Some((epoch, false)), true) => epoch
                .checked_add(1)
                .filter(|e| *e <= i64::MAX as u64)
                .ok_or("enrollment epoch exhausted")?,
            _ => return Err("enrollment exists, is revoked, or rotation target is missing".into()),
        };
        let reused: bool = sql(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM enrollment_keys WHERE key=?1)",
            [&enrollment.public_key],
            |r| r.get(0),
        ))?;
        if reused {
            return Err("enrollment key has already been used; generate a fresh key".into());
        }
        let count: i64 = sql(tx.query_row("SELECT COUNT(*) FROM brokers", [], |r| r.get(0)))?;
        if count >= 10_000 && !rotate {
            return Err("fleet enrollment capacity reached".into());
        }
        sql(tx.execute(
            "INSERT INTO enrollment_keys VALUES(?1,?2,?3)",
            params![enrollment.public_key, tenant, broker],
        ))?;
        sql(tx.execute("INSERT INTO brokers(tenant,broker,key,epoch,expected_policy_version,expected_policy_digest) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(tenant,broker) DO UPDATE SET key=excluded.key,epoch=excluded.epoch,expected_policy_version=excluded.expected_policy_version,expected_policy_digest=excluded.expected_policy_digest,last_contact=NULL,report=NULL,challenge=NULL,challenge_expires=NULL,ack_seq=NULL,coverage_start=NULL,latest_receipt_digest=NULL",params![tenant,broker,enrollment.public_key,epoch,enrollment.expected_policy_version,enrollment.expected_policy_digest]))?;
        sql(tx.execute("INSERT INTO enrollment_events(tenant,broker,epoch,action,occurred_at) VALUES(?1,?2,?3,?4,?5)",params![tenant,broker,epoch,if rotate{"rotate"}else{"enroll"},now]))?;
        sql(tx.execute("INSERT INTO broker_evidence VALUES(?1,?2,NULL,'unknown') ON CONFLICT(tenant,broker) DO UPDATE SET observed_head=NULL,health='unknown'",params![tenant,broker]))?;
        sql(tx.commit())?;
        Ok(epoch)
    }
    pub fn revoke(&self, binding: &TenantBinding, now: i64) -> Result<()> {
        let (tenant, broker) = binding_parts(binding)?;
        let mut conn = self.lock()?;
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if sql(tx.execute("UPDATE brokers SET revoked=1,challenge=NULL,challenge_expires=NULL WHERE tenant=?1 AND broker=?2 AND revoked=0",params![tenant,broker]))?!=1{return Err("active enrollment unavailable".into());}
        sql(tx.execute("INSERT INTO enrollment_events(tenant,broker,epoch,action,occurred_at) SELECT tenant,broker,epoch,'revoke',?3 FROM brokers WHERE tenant=?1 AND broker=?2",params![tenant,broker,now]))?;
        sql(tx.commit())?;
        Ok(())
    }
    pub fn challenge(&self, binding: &TenantBinding, now: i64) -> Result<Challenge> {
        if now < 0 {
            return Err("invalid collector clock".into());
        }
        let (tenant, broker) = binding_parts(binding)?;
        let mut conn = self.lock()?;
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let (epoch,revoked,prior,expires,ack):(u64,bool,Option<String>,Option<i64>,Option<u64>)=sql(tx.query_row("SELECT epoch,revoked,challenge,challenge_expires,ack_seq FROM brokers WHERE tenant=?1 AND broker=?2",params![tenant,broker],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))))?;
        if revoked {
            return Err("enrollment revoked".into());
        }
        let last_contact: Option<i64> = sql(tx.query_row(
            "SELECT last_contact FROM brokers WHERE tenant=?1 AND broker=?2",
            params![tenant, broker],
            |row| row.get(0),
        ))?;
        if last_contact.is_some_and(|last| now < last) {
            return Err("collector clock regressed".into());
        }
        let expires_at = now.checked_add(60).ok_or("collector clock overflow")?;
        let challenge = if let (Some(nonce), Some(expires_at)) = (prior, expires)
            && now < expires_at
        {
            Challenge {
                binding: binding.clone(),
                epoch,
                nonce,
                expires_at,
                acknowledged_sequence: ack,
            }
        } else {
            Challenge {
                binding: binding.clone(),
                epoch,
                nonce: uuid::Uuid::new_v4().simple().to_string(),
                expires_at,
                acknowledged_sequence: ack,
            }
        };
        sql(tx.execute(
            "UPDATE brokers SET challenge=?3,challenge_expires=?4 WHERE tenant=?1 AND broker=?2",
            params![tenant, broker, challenge.nonce, challenge.expires_at],
        ))?;
        sql(tx.commit())?;
        Ok(challenge)
    }
    pub fn accept(
        &self,
        binding: &TenantBinding,
        heartbeat: &Heartbeat,
        now: i64,
    ) -> Result<Acknowledgment> {
        let (tenant, broker) = binding_parts(binding)?;
        if heartbeat.schema_version != 1
            || heartbeat.challenge.binding != *binding
            || heartbeat.evidence.export_entries.len() > MAX_BATCH
            || heartbeat.report.len() > 128 * 1024
        {
            return Err("invalid heartbeat envelope".into());
        }
        let mut conn = self.lock()?;
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let (epoch,revoked,public_key,nonce,expires,prior_ack):(u64,bool,String,Option<String>,Option<i64>,Option<u64>)=sql(tx.query_row("SELECT epoch,revoked,key,challenge,challenge_expires,ack_seq FROM brokers WHERE tenant=?1 AND broker=?2",params![tenant,broker],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))))?;
        if revoked
            || epoch != heartbeat.challenge.epoch
            || nonce.as_deref() != Some(&heartbeat.challenge.nonce)
            || expires != Some(heartbeat.challenge.expires_at)
            || now < 0
            || now >= heartbeat.challenge.expires_at
            || prior_ack != heartbeat.challenge.acknowledged_sequence
        {
            return Err("heartbeat challenge expired, consumed, replaced or revoked".into());
        }
        let expected_nonce = Heartbeat::nonce_for(&heartbeat.challenge, &heartbeat.evidence)?;
        let verified = verify_report(
            &heartbeat.report,
            &key(&public_key)?,
            &expected_nonce,
            now,
            60,
        )
        .map_err(|_| "heartbeat signature, binding or freshness rejected")?;
        if verified.payload.issued_at > now
            || verified.payload.issued_at < heartbeat.challenge.expires_at - 60
        {
            return Err("broker clock is outside challenge window".into());
        }
        let batch = &heartbeat.evidence.export_entries;
        let mut ack = prior_ack;
        let mut receipt_digest = None;
        let previous_head: Option<u64> = sql(tx.query_row(
            "SELECT observed_head FROM broker_evidence WHERE tenant=?1 AND broker=?2",
            params![tenant, broker],
            |row| row.get(0),
        ))?;
        let head = heartbeat.evidence.audit_head;
        if head.is_some_and(|value| value > i64::MAX as u64) {
            return Err("audit head exceeds bounds".into());
        }
        let mut evidence_health = match head {
            None if previous_head.is_some() => "unavailable",
            None => "unknown",
            Some(value)
                if previous_head.is_some_and(|old| value < old)
                    || prior_ack.is_some_and(|ack| value < ack) =>
            {
                "regressed"
            }
            Some(_) => "ok",
        };
        if let Some(first) = batch.first() {
            if first.sequence == 0 {
                return Err("invalid export sequence".into());
            }
            for (offset, item) in batch.iter().enumerate() {
                if first.sequence.checked_add(offset as u64) != Some(item.sequence)
                    || item.sequence > i64::MAX as u64
                    || !digest(&item.record_hash)
                    || uuid::Uuid::parse_str(&item.event_id).is_err()
                {
                    return Err("invalid export evidence sequence".into());
                }
            }
            let last = batch.last().unwrap().sequence;
            if head.is_none_or(|value| value < last) {
                evidence_health = "regressed";
            }
            if evidence_health == "ok"
                && prior_ack
                    .and_then(|ack| ack.checked_add(1))
                    .is_some_and(|next| first.sequence != next)
            {
                evidence_health = "gap";
            }
        } else if evidence_health == "ok" && head.is_some_and(|head| head > prior_ack.unwrap_or(0))
        {
            evidence_health = "gap";
        }
        if let Some(first) = batch.first()
            && evidence_health == "ok"
        {
            let last = batch.last().unwrap().sequence;
            let hash = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(batch).map_err(|_| "invalid export evidence")?)
            );
            sql(tx.execute(
                "INSERT INTO fleet_receipts VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![tenant, broker, epoch, last, first.sequence, hash, now],
            ))?;
            // Keep a bounded recent receipt window; the durable frontier survives.
            sql(tx.execute("DELETE FROM fleet_receipts WHERE tenant=?1 AND broker=?2 AND rowid NOT IN(SELECT rowid FROM fleet_receipts WHERE tenant=?1 AND broker=?2 ORDER BY rowid DESC LIMIT 1000)",params![tenant,broker]))?;
            sql(tx.execute("UPDATE brokers SET coverage_start=COALESCE(coverage_start,?3) WHERE tenant=?1 AND broker=?2",params![tenant,broker,first.sequence]))?;
            ack = Some(last);
            receipt_digest = Some(hash);
        }
        let observed_head = previous_head.into_iter().chain(head).max();
        sql(tx.execute(
            "UPDATE broker_evidence SET observed_head=?3,health=?4 WHERE tenant=?1 AND broker=?2",
            params![tenant, broker, observed_head, evidence_health],
        ))?;
        sql(tx.execute("UPDATE brokers SET last_contact=?3,report=?4,challenge=NULL,challenge_expires=NULL,ack_seq=?5,latest_receipt_digest=COALESCE(?6,latest_receipt_digest) WHERE tenant=?1 AND broker=?2",params![tenant,broker,now,serde_json::to_string(heartbeat).map_err(|_|"invalid heartbeat")?,ack,receipt_digest]))?;
        sql(tx.commit())?;
        Ok(Acknowledgment {
            binding: binding.clone(),
            epoch,
            received_at: now,
            acknowledged_sequence: ack,
            receipt_digest,
            evidence_health: evidence_health.into(),
        })
    }
    pub fn inventory(
        &self,
        tenant: &str,
        now: i64,
        fresh_secs: u64,
        offline_secs: u64,
    ) -> Result<Value> {
        opaque_core::tenant::TenantId::parse(tenant).map_err(|_| "invalid tenant")?;
        if fresh_secs == 0 || offline_secs <= fresh_secs || offline_secs > 86400 {
            return Err("invalid fleet freshness windows".into());
        }
        let conn = self.lock()?;
        let mut statement=sql(conn.prepare("SELECT broker,key,epoch,revoked,expected_policy_version,expected_policy_digest,last_contact,report,ack_seq,coverage_start,latest_receipt_digest FROM brokers WHERE tenant=?1 ORDER BY broker"))?;
        let rows = sql(statement.query_map([tenant], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<u64>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<u64>>(8)?,
                r.get::<_, Option<u64>>(9)?,
                r.get::<_, Option<String>>(10)?,
            ))
        }))?;
        let mut brokers = Vec::new();
        for row in rows {
            let (
                broker,
                key,
                epoch,
                revoked,
                expected_version,
                expected_digest,
                last,
                encoded,
                ack,
                coverage_start,
                receipt_digest,
            ) = sql(row)?;
            let (last_known_head, evidence_health): (Option<u64>, String) = sql(conn.query_row(
                "SELECT observed_head,health FROM broker_evidence WHERE tenant=?1 AND broker=?2",
                params![tenant, broker],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ))?;
            let heartbeat: Option<Heartbeat> = encoded
                .map(|s| serde_json::from_str(&s))
                .transpose()
                .map_err(|_| "stored fleet report invalid")?;
            let report: Option<ReportPayload> = heartbeat
                .as_ref()
                .map(|h| {
                    verify_report(
                        &h.report,
                        &self::key(&key)?,
                        &Heartbeat::nonce_for(&h.challenge, &h.evidence)?,
                        last.unwrap_or(0),
                        60,
                    )
                    .map(|r| r.payload)
                    .map_err(|_| "stored report failed verification".to_string())
                })
                .transpose()?;
            let age = last
                .and_then(|time| now.checked_sub(time))
                .filter(|age| *age >= 0);
            let status = if revoked {
                "revoked"
            } else {
                match age {
                    None => "unknown",
                    Some(age) if age >= offline_secs as i64 => "offline",
                    Some(age) if age > fresh_secs as i64 => "stale",
                    Some(_) => "fresh",
                }
            };
            let policy = report.as_ref().and_then(|r| r.federation.as_ref());
            let policy_status =
                if report.is_none() || (expected_version.is_none() && expected_digest.is_none()) {
                    "unknown"
                } else if policy.is_none() {
                    "drift"
                } else if policy.is_some_and(|p| {
                    expected_version.is_none_or(|v| v == p.version)
                        && expected_digest.as_ref().is_none_or(|d| d == &p.digest)
                }) {
                    "matches"
                } else {
                    "drift"
                };
            let head = heartbeat.as_ref().and_then(|h| h.evidence.audit_head);
            let lag = if evidence_health == "ok" {
                head.zip(ack).and_then(|(h, a)| h.checked_sub(a))
            } else {
                None
            };
            brokers.push(json!({"tenant_id":tenant,"broker_id":broker,"enrollment_epoch":epoch,"public_key":key,"status":status,"last_contact":last,"contact_age_secs":age,"daemon_version":report.as_ref().map(|r|&r.daemon_version),"last_observed_posture":report.as_ref().map(|r|json!({"custody_ok":r.trust_domain.custody_ok,"audit_chain_ok":r.audit.chain_ok,"trust_domain_enforced":r.trust_domain.enforce,"measurement":"software"})),"current_posture":if status=="fresh"{report.as_ref().map(|r|if r.integrity_ok(){"healthy"}else{"unhealthy"})}else{None},"policy":policy,"policy_status":policy_status,"audit_head":head,"last_known_audit_head":last_known_head,"evidence_health":evidence_health,"acknowledged_evidence_sequence":ack,"evidence_export_lag_records":lag,"evidence_coverage_start":coverage_start,"latest_receipt_digest":receipt_digest,"full_audit_export_lag":Value::Null}));
        }
        Ok(
            json!({"schema_version":1,"scope":"enrolled_brokers_only","tenant_id":tenant,"observed_at":now,"brokers":brokers,"evidence_contract":"authenticated receipt of compact audit event IDs, sequence numbers and record hashes; not full audit payload ingestion"}),
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCredentials {
    pub read_token_file: PathBuf,
    pub report_token_file: PathBuf,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub listen: SocketAddr,
    pub tenants: BTreeMap<String, TenantCredentials>,
    pub fresh_secs: u64,
    pub offline_secs: u64,
}
type TenantTokenHashes = BTreeMap<String, ([u8; 32], [u8; 32])>;
#[derive(Clone)]
struct Api {
    store: Arc<FleetStore>,
    tokens: Arc<TenantTokenHashes>,
    fresh_secs: u64,
    offline_secs: u64,
}

pub fn read_private_file(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "private file unavailable")?;
    let meta = f.metadata().map_err(|_| "private file unavailable")?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7077 != 0
        || meta.len() > max
    {
        return Err("file must be a bounded, owned private regular file".into());
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .map_err(|_| "private file unavailable")?;
    Ok(bytes)
}
fn token_hash(path: &Path) -> Result<[u8; 32]> {
    let b = read_private_file(path, 256)?;
    if b.len() < 32
        || b.len() > 128
        || !b
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(b))
    {
        return Err("token must contain 32..128 random URL-safe bytes without whitespace".into());
    }
    Ok(Sha256::digest(b).into())
}

pub async fn serve(store: Arc<FleetStore>, config: CollectorConfig) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|_| "collector listener unavailable")?;
    serve_listener(store, config, listener).await
}
pub async fn serve_listener(
    store: Arc<FleetStore>,
    config: CollectorConfig,
    listener: tokio::net::TcpListener,
) -> Result<()> {
    if !config.listen.ip().is_loopback()
        || !listener
            .local_addr()
            .map_err(|_| "invalid listener")?
            .ip()
            .is_loopback()
        || config.tenants.is_empty()
        || config.tenants.len() > 1000
        || config.fresh_secs == 0
        || config.offline_secs <= config.fresh_secs
        || config.offline_secs > 86400
    {
        return Err(
            "collector requires loopback TLS-ingress deployment and bounded tenants/freshness"
                .into(),
        );
    }
    let mut tokens = BTreeMap::new();
    let mut unique = std::collections::BTreeSet::new();
    for (tenant, credentials) in config.tenants {
        opaque_core::tenant::TenantId::parse(&tenant).map_err(|_| "invalid configured tenant")?;
        let reader = token_hash(&credentials.read_token_file)?;
        let reporter = token_hash(&credentials.report_token_file)?;
        if !unique.insert(reader) || !unique.insert(reporter) {
            return Err("tenant and role credentials must all be distinct".into());
        }
        tokens.insert(tenant, (reader, reporter));
    }
    let api = Api {
        store,
        tokens: Arc::new(tokens),
        fresh_secs: config.fresh_secs,
        offline_secs: config.offline_secs,
    };
    axum::serve(listener, Router::new().fallback(http).with_state(api))
        .await
        .map_err(|_| "collector stopped".into())
}
async fn http(State(api): State<Api>, request: Request) -> Response {
    let outcome = http_inner(api, request).await;
    let mut response = match outcome {
        Ok(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Err((status, message)) => (status, axum::Json(json!({"error":message}))).into_response(),
    };
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}
async fn http_inner(
    api: Api,
    request: Request,
) -> std::result::Result<Value, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let chunks = parts
        .uri
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let deny = || {
        (
            StatusCode::UNAUTHORIZED,
            "tenant-scoped credential required".into(),
        )
    };
    if chunks.len() < 4
        || chunks[0] != "v1"
        || chunks[1] != "tenants"
        || chunks[3] != "brokers"
        || parts.uri.query().is_some()
        || parts.headers.contains_key("origin")
    {
        return Err(deny());
    }
    let read = parts.method == "GET" && chunks.len() == 4;
    let credentials = api.tokens.get(chunks[2]).ok_or_else(deny)?;
    let expected = if read { &credentials.0 } else { &credentials.1 };
    let values = parts.headers.get_all("authorization");
    let token = values
        .iter()
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| s.len() <= 128)
        .ok_or_else(deny)?;
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if values.iter().count() != 1
        || actual
            .iter()
            .zip(expected)
            .fold(0u8, |v, (a, b)| v | (a ^ b))
            != 0
    {
        return Err(deny());
    }
    if read {
        return api
            .store
            .inventory(chunks[2], now(), api.fresh_secs, api.offline_secs)
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e));
    }
    if parts.method != "POST" || chunks.len() != 6 {
        return Err((StatusCode::NOT_FOUND, "route unavailable".into()));
    }
    let binding = TenantBinding::new(
        opaque_core::tenant::TenantId::parse(chunks[2])
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        uuid::Uuid::parse_str(chunks[4])
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid broker".into()))?,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if binding.broker_id.to_string() != chunks[4] {
        return Err((
            StatusCode::BAD_REQUEST,
            "noncanonical broker identity".into(),
        ));
    }
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        to_bytes(body, 256 * 1024),
    )
    .await
    .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "request timeout".into()))?
    .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "body bound exceeded".into()))?;
    match chunks[5] {
        "challenge" if bytes.is_empty() => api
            .store
            .challenge(&binding, now())
            .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
        "heartbeat" => serde_json::from_slice::<Heartbeat>(&bytes)
            .map_err(|_| "invalid heartbeat".into())
            .and_then(|h| api.store.accept(&binding, &h, now()))
            .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string())),
        _ => return Err((StatusCode::NOT_FOUND, "route unavailable".into())),
    }
    .map_err(|e| (StatusCode::CONFLICT, e))
}
