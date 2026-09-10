//! SIEM export: streaming the tamper-evident audit chain off the box.
//!
//! The pump tails the SQLite audit CHAIN — not the live event stream — so
//! every exported record carries its `sequence_number` and `record_hash`,
//! allowing custody-side verification and keyless artifact comparison. The HMAC
//! alone is not public-key verification of producer identity. Delivery is
//! at-least-once per transport with a persisted cursor apiece (one dead
//! transport never stalls the others); consumers dedupe on
//! `(sequence_number, record_hash)`.
//!
//! Transports:
//! - **spool** — append-only JSONL file (Splunk UF / filebeat tail it)
//! - **webhook** — batched JSON POST to an HTTPS endpoint
//! - **syslog** — RFC 5424 over TCP or TLS with octet-counting framing
//!   (RFC 6587); TLS trust comes from a configured CA file (enterprise
//!   syslog is private-PKI country), never an insecure skip
//!
//! The pump also runs the independent integrity detector: an operation that
//! SUCCEEDED whose chain shows a required approval that was never granted
//! raises an `audit.alert` event — which lands in the chain and is exported
//! like everything else.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditLevel, AuditSink};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// `[export]` daemon config.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExportConfig {
    /// Append-only JSONL spool file.
    #[serde(default)]
    pub spool_path: Option<PathBuf>,

    /// HTTPS endpoint receiving batched JSON arrays of records.
    #[serde(default)]
    pub webhook_url: Option<String>,

    /// Optional Authorization header value for the webhook (e.g.
    /// `Bearer <token>`). The config file is sealed and custody-owned.
    #[serde(default)]
    pub webhook_authorization: Option<String>,

    /// Syslog destination: `tcp://host:port` or `tls://host:port`.
    #[serde(default)]
    pub syslog_addr: Option<String>,

    /// PEM CA file that vouches for the syslog server (required for tls://).
    #[serde(default)]
    pub syslog_ca_file: Option<PathBuf>,

    /// Poll interval in seconds (default 2).
    #[serde(default)]
    pub poll_secs: Option<u64>,

    /// Max records per delivery batch (default 256).
    #[serde(default)]
    pub batch_size: Option<usize>,
}

impl ExportConfig {
    pub fn configured(&self) -> bool {
        self.spool_path.is_some() || self.webhook_url.is_some() || self.syslog_addr.is_some()
    }
}

/// One exported audit record: the chained columns plus the chain fields that
/// make it externally verifiable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    /// Export schema tag.
    pub schema: String,
    /// Insertion order in the chain (the pump cursor).
    pub rowid: i64,
    pub event_id: String,
    pub sequence_number: i64,
    pub ts_utc_ms: i64,
    pub level: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_json: Option<String>,
    /// HMAC chain hash of this record — the external verifiability anchor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
}

const EXPORT_SCHEMA: &str = "opaque.audit.v1";

/// Read chain rows with `rowid > after`, oldest first.
pub fn read_rows_after(
    db_path: &Path,
    after: i64,
    limit: usize,
) -> Result<Vec<ExportRecord>, String> {
    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("open audit db: {e}"))?;
    let mut stmt = conn
        .prepare(
            "SELECT rowid, event_id, sequence_number, ts_utc_ms, level, kind, request_id, \
             approval_id, client_json, operation, safety, target_json, outcome, latency_ms, \
             secret_names, policy_decision, detail, workspace_json, request_hash, \
             approver_json, record_hash \
             FROM audit_events WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2",
        )
        .map_err(|e| format!("prepare export query: {e}"))?;
    let rows = stmt
        .query_map(rusqlite::params![after, limit as i64], |r| {
            Ok(ExportRecord {
                schema: EXPORT_SCHEMA.into(),
                rowid: r.get(0)?,
                event_id: r.get(1)?,
                sequence_number: r.get(2)?,
                ts_utc_ms: r.get(3)?,
                level: r.get(4)?,
                kind: r.get(5)?,
                request_id: r.get(6)?,
                approval_id: r.get(7)?,
                client_json: r.get(8)?,
                operation: r.get(9)?,
                safety: r.get(10)?,
                target_json: r.get(11)?,
                outcome: r.get(12)?,
                latency_ms: r.get(13)?,
                secret_names: r.get(14)?,
                policy_decision: r.get(15)?,
                detail: r.get(16)?,
                workspace_json: r.get(17)?,
                request_hash: r.get(18)?,
                approver_json: r.get(19)?,
                record_hash: r.get(20)?,
            })
        })
        .map_err(|e| format!("export query: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("export row: {e}"))?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------------

/// Per-transport export cursors, persisted in the custody set so delivery
/// resumes exactly where it stopped across daemon restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursors {
    #[serde(default)]
    pub spool: i64,
    #[serde(default)]
    pub webhook: i64,
    #[serde(default)]
    pub syslog: i64,
    /// The integrity detector's own frontier (it must see each row once).
    #[serde(default)]
    pub detector: i64,
    #[serde(default)]
    pub detector_state: Option<ApprovalDetector>,
}

pub fn cursor_path(home: &Path) -> PathBuf {
    home.join(".opaque").join("export.cursor")
}

pub fn load_cursors(path: &Path) -> std::io::Result<Cursors> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Cursors::default()),
        Err(e) => return Err(e),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("cursor is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(std::io::Error::other("cursor exceeds limit"));
    }
    let cursors: Cursors = serde_json::from_slice(&bytes)
        .map_err(|_| std::io::Error::other("invalid cursor state"))?;
    if [
        cursors.spool,
        cursors.webhook,
        cursors.syslog,
        cursors.detector,
    ]
    .iter()
    .any(|v| *v < 0)
        || cursors
            .detector_state
            .as_ref()
            .is_some_and(|state| !state.valid(cursors.detector))
    {
        return Err(std::io::Error::other("inconsistent detector cursor state"));
    }
    Ok(cursors)
}

/// One atomic, durable replacement binds the detector frontier and pending state.
/// A single daemon pump owns this file; concurrent writers are unsupported.
pub fn save_cursors(path: &Path, cursors: &Cursors) -> std::io::Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(cursors)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(std::io::Error::other("cursor exceeds limit"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(
        ".export-cursor-{}",
        AuditEvent::new(AuditEventKind::AuditAlert).event_id
    ));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

/// Append records as JSONL to the spool file (0600, created on first use).
pub fn deliver_spool(path: &Path, batch: &[ExportRecord]) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("spool dir: {e}"))?;
    }
    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("spool open: {e}"))?
        }
        #[cfg(not(unix))]
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("spool open: {e}"))?
    };
    let mut buf = Vec::with_capacity(batch.len() * 512);
    for record in batch {
        serde_json::to_writer(&mut buf, record).map_err(|e| format!("spool encode: {e}"))?;
        buf.push(b'\n');
    }
    file.write_all(&buf)
        .map_err(|e| format!("spool write: {e}"))?;
    file.flush().map_err(|e| format!("spool flush: {e}"))?;
    Ok(())
}

/// POST a batch as a JSON array. Success = 2xx.
pub async fn deliver_webhook(
    client: &reqwest::Client,
    url: &str,
    authorization: Option<&str>,
    batch: &[ExportRecord],
) -> Result<(), String> {
    let mut req = client.post(url).json(batch);
    if let Some(auth) = authorization {
        req = req.header("Authorization", auth);
    }
    let resp = req.send().await.map_err(|e| format!("webhook send: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("webhook HTTP {}", resp.status()));
    }
    Ok(())
}

/// RFC 5424 syslog line for a record, framed with RFC 6587 octet counting.
pub fn syslog_frame(record: &ExportRecord, hostname: &str) -> Result<Vec<u8>, String> {
    // PRI: facility 13 (log audit) — severity from the record level.
    let severity = match record.level.as_str() {
        "error" => 3,
        "warn" => 4,
        _ => 6,
    };
    let pri = 13 * 8 + severity;

    // RFC 5424 TIMESTAMP from ts_utc_ms without a date dependency: audit
    // timestamps are unix ms; render as epoch-relative ISO via chrono-free
    // math (days since epoch → civil date, Howard Hinnant's algorithm).
    let (secs, millis) = (record.ts_utc_ms / 1000, record.ts_utc_ms % 1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (h, m, sec) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    let timestamp = format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{sec:02}.{millis:03}Z");

    let msg = serde_json::to_string(record).map_err(|e| format!("syslog encode: {e}"))?;
    let line = format!(
        "<{pri}>1 {timestamp} {hostname} opaqued - {} - {msg}",
        record.sequence_number
    );
    // Octet-counting framing: "LEN SP LINE".
    Ok(format!("{} {line}", line.len()).into_bytes())
}

/// A syslog connection (TCP or TLS over TCP), reconnected per batch attempt.
pub struct SyslogTarget {
    addr: String,
    tls: bool,
    tls_config: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
    server_name: Option<tokio_rustls::rustls::pki_types::ServerName<'static>>,
    hostname: String,
}

impl std::fmt::Debug for SyslogTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogTarget")
            .field("addr", &self.addr)
            .field("tls", &self.tls)
            .finish()
    }
}

impl SyslogTarget {
    /// Parse `tcp://host:port` or `tls://host:port` (TLS requires a CA file).
    pub fn new(addr: &str, ca_file: Option<&Path>) -> Result<Self, String> {
        let hostname = gethostname();
        if let Some(rest) = addr.strip_prefix("tcp://") {
            return Ok(Self {
                addr: rest.to_owned(),
                tls: false,
                tls_config: None,
                server_name: None,
                hostname,
            });
        }
        let Some(rest) = addr.strip_prefix("tls://") else {
            return Err(format!(
                "syslog_addr must be tcp://host:port or tls://host:port, got {addr:?}"
            ));
        };
        let ca_file = ca_file.ok_or("tls:// syslog requires export.syslog_ca_file (PEM)")?;
        let pem = std::fs::read(ca_file)
            .map_err(|e| format!("syslog CA {} unreadable: {e}", ca_file.display()))?;
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let mut added = 0usize;
        for cert in rustls_pemfile_certs(&pem)? {
            roots
                .add(cert)
                .map_err(|e| format!("syslog CA cert rejected: {e}"))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!(
                "syslog CA {} contains no certificates",
                ca_file.display()
            ));
        }
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let host = rest
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(rest)
            .to_owned();
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| format!("syslog host is not a valid TLS server name: {e}"))?;
        Ok(Self {
            addr: rest.to_owned(),
            tls: true,
            tls_config: Some(Arc::new(config)),
            server_name: Some(server_name),
            hostname,
        })
    }

    /// Deliver a batch over a fresh connection.
    pub async fn deliver(&self, batch: &[ExportRecord]) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;

        let mut frames = Vec::new();
        for record in batch {
            frames.extend_from_slice(&syslog_frame(record, &self.hostname)?);
        }

        let stream = tokio::net::TcpStream::connect(&self.addr)
            .await
            .map_err(|e| format!("syslog connect {}: {e}", self.addr))?;
        if self.tls {
            let connector = tokio_rustls::TlsConnector::from(
                self.tls_config.clone().expect("tls config present"),
            );
            let mut tls = connector
                .connect(self.server_name.clone().expect("server name"), stream)
                .await
                .map_err(|e| format!("syslog TLS handshake: {e}"))?;
            tls.write_all(&frames)
                .await
                .map_err(|e| format!("syslog write: {e}"))?;
            tls.flush()
                .await
                .map_err(|e| format!("syslog flush: {e}"))?;
            let _ = tls.shutdown().await;
        } else {
            let mut stream = stream;
            stream
                .write_all(&frames)
                .await
                .map_err(|e| format!("syslog write: {e}"))?;
            stream
                .flush()
                .await
                .map_err(|e| format!("syslog flush: {e}"))?;
        }
        Ok(())
    }
}

/// Minimal PEM certificate extraction (no extra dependency): collects the
/// base64 payloads between CERTIFICATE markers.
fn rustls_pemfile_certs(
    pem: &[u8],
) -> Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>, String> {
    use base64::Engine;
    let text = std::str::from_utf8(pem).map_err(|e| format!("CA file is not UTF-8: {e}"))?;
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64.clear();
        } else if line == "-----END CERTIFICATE-----" {
            in_cert = false;
            let der = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| format!("bad base64 in CA file: {e}"))?;
            certs.push(tokio_rustls::rustls::pki_types::CertificateDer::from(der));
        } else if in_cert {
            b64.push_str(line);
        }
    }
    Ok(certs)
}

fn gethostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "-".into())
}

// ---------------------------------------------------------------------------
// Integrity detector
// ---------------------------------------------------------------------------

mod detector;
pub use detector::{ApprovalDetector, Finding};

// ---------------------------------------------------------------------------
// Pump
// ---------------------------------------------------------------------------

/// Everything the export pump needs.
pub struct ExportPump {
    pub config: ExportConfig,
    pub db_path: PathBuf,
    pub cursor_file: PathBuf,
    pub audit: Arc<dyn AuditSink>,
    pub syslog: Option<SyslogTarget>,
    pub http: reqwest::Client,
}

impl ExportPump {
    pub fn new(
        config: ExportConfig,
        db_path: PathBuf,
        cursor_file: PathBuf,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, String> {
        if config.batch_size.is_some_and(|n| !(1..=1024).contains(&n))
            || config.poll_secs.is_some_and(|n| !(1..=3600).contains(&n))
        {
            return Err("invalid export batch or polling limit".into());
        }
        let syslog = match &config.syslog_addr {
            Some(addr) => Some(SyslogTarget::new(addr, config.syslog_ca_file.as_deref())?),
            None => None,
        };
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| format!("webhook client: {e}"))?;
        Ok(Self {
            config,
            db_path,
            cursor_file,
            audit,
            syslog,
            http,
        })
    }

    /// One pump cycle: advance each configured transport independently, then
    /// run the detector on rows it has not yet seen. Returns how many
    /// (transport, record) deliveries happened, for tests and logging.
    pub async fn run_once(&self, detector: &mut ApprovalDetector) -> Result<usize, String> {
        let batch_size = self.config.batch_size.unwrap_or(256);
        let mut cursors = load_cursors(&self.cursor_file)
            .map_err(|e| format!("export cursors unreadable: {e}"))?;
        let original_cursors = cursors.clone();
        let mut delivered = 0usize;
        let mut failed_transports = std::collections::BTreeSet::new();

        if let Some(spool) = &self.config.spool_path {
            let batch = read_rows_after(&self.db_path, cursors.spool, batch_size)?;
            if !batch.is_empty() {
                match deliver_spool(spool, &batch) {
                    Ok(()) => {
                        cursors.spool = batch.last().expect("nonempty").rowid;
                        delivered += batch.len();
                    }
                    Err(e) => {
                        warn!("export spool delivery failed: {e}");
                        failed_transports.insert("spool".to_string());
                    }
                }
            }
        }

        if let Some(url) = &self.config.webhook_url {
            let batch = read_rows_after(&self.db_path, cursors.webhook, batch_size)?;
            if !batch.is_empty() {
                match deliver_webhook(
                    &self.http,
                    url,
                    self.config.webhook_authorization.as_deref(),
                    &batch,
                )
                .await
                {
                    Ok(()) => {
                        cursors.webhook = batch.last().expect("nonempty").rowid;
                        delivered += batch.len();
                    }
                    Err(e) => {
                        warn!("export webhook delivery failed: {e}");
                        failed_transports.insert("webhook".to_string());
                    }
                }
            }
        }

        if let Some(target) = &self.syslog {
            let batch = read_rows_after(&self.db_path, cursors.syslog, batch_size)?;
            if !batch.is_empty() {
                match target.deliver(&batch).await {
                    Ok(()) => {
                        cursors.syslog = batch.last().expect("nonempty").rowid;
                        delivered += batch.len();
                    }
                    Err(e) => {
                        warn!("export syslog delivery failed: {e}");
                        failed_transports.insert("syslog".to_string());
                    }
                }
            }
        }

        // Pending requirements and this frontier are one durable snapshot.
        // The caller's memory is a view only; disk is authoritative after errors.
        let legacy_gap = cursors.detector > 0 && cursors.detector_state.is_none();
        let mut state = cursors.detector_state.take().unwrap_or_default();
        self.deliver_findings(&state.outbox).await?;
        state.outbox.clear();
        let batch = read_rows_after(&self.db_path, cursors.detector, batch_size)?;
        for (index, record) in batch.iter().enumerate() {
            if index == 0 && legacy_gap {
                let finding = state.coverage_gap("restart_coverage_gap", record);
                state.outbox.push(finding);
            }
            let findings = state.observe_findings(record);
            state.outbox.extend(findings);
        }
        if let Some(last) = batch.last() {
            cursors.detector = last.rowid;
        }
        // Only transitions into a failed transport emit a finding. Repeated
        // failed polling cannot recursively generate an alert for its own alert.
        if failed_transports != state.failed_transports {
            let anchor = if let Some(last) = batch.last() {
                Some(last.clone())
            } else {
                read_rows_after(&self.db_path, state.last_rowid.saturating_sub(1), 1)?
                    .into_iter()
                    .next()
            };
            for transport in failed_transports.difference(&state.failed_transports) {
                if let Some(record) = &anchor {
                    state.outbox.push(Finding::new(
                        &format!("export_{transport}_failed"),
                        record,
                        None,
                    ));
                }
            }
            state.failed_transports = failed_transports;
        }
        // Legacy state with no new rows remains explicitly absent until the
        // first observed record can anchor a coverage finding.
        if !legacy_gap || !batch.is_empty() {
            cursors.detector_state = Some(state.clone());
        }
        if cursors != original_cursors {
            save_cursors(&self.cursor_file, &cursors)
                .map_err(|_| "export cursors persist failed".to_string())?;
        }
        self.deliver_findings(&state.outbox).await?;
        let acknowledged = !state.outbox.is_empty();
        state.outbox.clear();
        if acknowledged && cursors.detector_state.is_some() {
            cursors.detector_state = Some(state.clone());
            save_cursors(&self.cursor_file, &cursors)
                .map_err(|_| "export cursors persist failed".to_string())?;
        }
        *detector = state;
        Ok(delivered)
    }

    /// Replay-safe alert outbox. The deterministic event ID is looked up in
    /// the durable sink before emission; a crash after commit and before cursor
    /// acknowledgment does not append the same finding again.
    async fn deliver_findings(&self, findings: &[Finding]) -> Result<(), String> {
        if findings.is_empty() {
            return Ok(());
        }
        let connection = rusqlite::Connection::open_with_flags(
            &self.db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|_| "detector audit lookup failed".to_string())?;
        for finding in findings {
            let detail =
                serde_json::to_string(finding).map_err(|_| "detector finding encoding failed")?;
            let existing: Option<(String, Option<String>)> = {
                use rusqlite::OptionalExtension;
                connection
                    .query_row(
                        "SELECT kind, detail FROM audit_events WHERE event_id = ?1",
                        [finding.event_id()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(|_| "detector audit lookup failed".to_string())?
            };
            if let Some((kind, previous)) = existing {
                if kind != "audit.alert" || previous.as_deref() != Some(&detail) {
                    return Err("detector finding identity conflict".into());
                }
                continue;
            }
            let source_retained: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM audit_events WHERE sequence_number = ?1)",
                    [finding.sequence],
                    |row| row.get(0),
                )
                .map_err(|_| "detector evidence lookup failed")?;
            if !source_retained {
                // If the source/old alert was pruned during a long outage, we
                // cannot distinguish never delivered from delivered then pruned.
                // Keep the outbox and fail visibly instead of reusing an event ID.
                return Err("detector outbox evidence no longer retained; delivery unknown".into());
            }
            let mut event = AuditEvent::new(AuditEventKind::AuditAlert)
                .with_operation("export_detector")
                .with_outcome(&finding.rule)
                .with_level(AuditLevel::Error)
                .with_detail(detail);
            event.event_id = finding
                .event_id()
                .parse()
                .map_err(|_| "invalid finding identity")?;
            self.audit.emit(event);
        }
        drop(connection);
        let audit = self.audit.clone();
        tokio::task::spawn_blocking(move || audit.flush(std::time::Duration::from_secs(5)))
            .await
            .map_err(|_| "detector audit acknowledgment failed")?
            .map_err(|_| "detector audit acknowledgment failed".to_string())
    }

    /// Run the pump forever (spawned as a daemon task).
    pub async fn run(self) {
        let poll = std::time::Duration::from_secs(self.config.poll_secs.unwrap_or(2));
        let mut detector = ApprovalDetector::default();
        info!(
            spool = self.config.spool_path.is_some(),
            webhook = self.config.webhook_url.is_some(),
            syslog = self.config.syslog_addr.is_some(),
            "audit export pump started"
        );
        loop {
            if let Err(e) = self.run_once(&mut detector).await {
                warn!("export pump cycle failed: {e}");
            }
            tokio::time::sleep(poll).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::audit::SqliteAuditSink;

    fn seed_db(dir: &Path) -> PathBuf {
        let db = dir.join("audit.db");
        let sink = SqliteAuditSink::new(db.clone(), 90).unwrap();
        sink.emit(
            AuditEvent::new(AuditEventKind::RequestReceived)
                .with_operation("test.noop")
                .with_outcome("received"),
        );
        sink.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded)
                .with_operation("test.noop")
                .with_outcome("ok"),
        );
        drop(sink); // flush + chain
        db
    }

    fn pump_for(dir: &Path, config: ExportConfig, db: PathBuf) -> ExportPump {
        ExportPump::new(
            config,
            db,
            dir.join("export.cursor"),
            Arc::new(opaque_core::audit::TracingAuditEmitter::new()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn spool_export_carries_chain_fields_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let db = seed_db(dir.path());
        let spool = dir.path().join("audit.jsonl");
        let pump = pump_for(
            dir.path(),
            ExportConfig {
                spool_path: Some(spool.clone()),
                ..Default::default()
            },
            db.clone(),
        );

        let mut detector = ApprovalDetector::default();
        let delivered = pump.run_once(&mut detector).await.unwrap();
        assert_eq!(delivered, 2);

        let lines: Vec<String> = std::fs::read_to_string(&spool)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(lines.len(), 2);
        let first: ExportRecord = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(first.schema, "opaque.audit.v1");
        assert_eq!(first.sequence_number, 0);
        let hash = first.record_hash.expect("record hash exported");
        assert_eq!(hash.len(), 64, "hmac-sha256 hex");

        // The exported hash IS the chain hash — externally verifiable.
        let conn = rusqlite::Connection::open(&db).unwrap();
        let db_hash: String = conn
            .query_row(
                "SELECT record_hash FROM audit_events WHERE sequence_number = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hash, db_hash);

        // Idempotent: nothing new → nothing delivered.
        assert_eq!(pump.run_once(&mut detector).await.unwrap(), 0);

        // New rows resume after the cursor.
        let sink = SqliteAuditSink::new(db, 90).unwrap();
        sink.emit(AuditEvent::new(AuditEventKind::OperationStarted).with_operation("x"));
        drop(sink);
        assert_eq!(pump.run_once(&mut detector).await.unwrap(), 1);
        assert_eq!(
            std::fs::read_to_string(&spool).unwrap().lines().count(),
            3,
            "no duplicates in the spool"
        );
    }

    #[tokio::test]
    async fn json_export_cursor_and_chain_survive_partial_and_full_retention() {
        for prune_all in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("audit.db");
            let sink = SqliteAuditSink::new(db.clone(), 0).unwrap();
            let mut first = AuditEvent::new(AuditEventKind::RequestReceived);
            first.ts_utc_ms = 1;
            sink.emit(first);
            let mut second = AuditEvent::new(AuditEventKind::RequestReceived);
            if prune_all {
                second.ts_utc_ms = 2;
            }
            sink.emit(second);
            sink.close().unwrap();
            let spool = dir.path().join("audit.jsonl");
            let pump = pump_for(
                dir.path(),
                ExportConfig {
                    spool_path: Some(spool.clone()),
                    ..Default::default()
                },
                db.clone(),
            );
            let mut detector = ApprovalDetector::default();
            assert_eq!(pump.run_once(&mut detector).await.unwrap(), 2);
            let initial = std::fs::read_to_string(&spool).unwrap();
            let old: Vec<ExportRecord> = initial
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let reopened = SqliteAuditSink::new(db.clone(), 1).unwrap();
            reopened.emit(
                AuditEvent::new(AuditEventKind::OperationStarted).with_operation("after-retention"),
            );
            reopened.close().unwrap();
            assert!(opaque_core::audit::verify_audit_chain(&db).unwrap().ok);
            assert_eq!(
                pump.run_once(&mut detector).await.unwrap(),
                1,
                "existing cursors must see the next row after a full prune"
            );
            assert_eq!(pump.run_once(&mut detector).await.unwrap(), 0);
            let exported = std::fs::read_to_string(&spool).unwrap();
            assert!(exported.starts_with(&initial));
            let records: Vec<ExportRecord> = exported
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(records.len(), 3);
            assert_eq!(records[2].sequence_number, 2);
            assert!(records[2].rowid > old[1].rowid);
            let retained = read_rows_after(&db, 0, 10).unwrap();
            for record in retained {
                let original = records
                    .iter()
                    .find(|candidate| candidate.event_id == record.event_id)
                    .unwrap();
                assert_eq!(
                    original.record_hash, record.record_hash,
                    "retention must preserve externally exported authenticators"
                );
            }
        }
    }

    #[tokio::test]
    async fn webhook_failure_holds_cursor_then_delivers() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let db = seed_db(dir.path());
        let server = MockServer::start().await;

        // First: endpoint down (500) — cursor must not advance.
        Mock::given(method("POST"))
            .and(path("/ingest"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let pump = pump_for(
            dir.path(),
            ExportConfig {
                webhook_url: Some(format!("{}/ingest", server.uri())),
                webhook_authorization: Some("Bearer test-token".into()),
                ..Default::default()
            },
            db,
        );
        let mut detector = ApprovalDetector::default();
        assert_eq!(pump.run_once(&mut detector).await.unwrap(), 0);
        server.verify().await;
        server.reset().await;

        // Then: endpoint healthy — the SAME rows deliver (at-least-once).
        Mock::given(method("POST"))
            .and(path("/ingest"))
            .and(wiremock::matchers::header(
                "Authorization",
                "Bearer test-token",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(pump.run_once(&mut detector).await.unwrap(), 2);
        server.verify().await;
    }

    #[tokio::test]
    async fn syslog_tcp_delivers_rfc5424_octet_frames() {
        let dir = tempfile::tempdir().unwrap();
        let db = seed_db(dir.path());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8(buf).unwrap()
        });

        let pump = pump_for(
            dir.path(),
            ExportConfig {
                syslog_addr: Some(format!("tcp://{addr}")),
                ..Default::default()
            },
            db,
        );
        let mut detector = ApprovalDetector::default();
        assert_eq!(pump.run_once(&mut detector).await.unwrap(), 2);

        let text = received.await.unwrap();
        // Octet framing: "LEN <PRI>1 TIMESTAMP ..." — parse the first frame.
        let (len_str, rest) = text.split_once(' ').expect("octet count");
        let len: usize = len_str.parse().expect("numeric length");
        let frame = &rest[..len];
        assert!(frame.starts_with("<110>1 ") || frame.starts_with("<108>1 "));
        assert!(frame.contains(" opaqued "));
        assert!(frame.contains("\"schema\":\"opaque.audit.v1\""));
        assert!(frame.contains("record_hash"));
        // Timestamp is RFC 3339 UTC.
        let ts = frame.split_whitespace().nth(1).unwrap();
        assert!(ts.ends_with('Z') && ts.contains('T'), "bad timestamp {ts}");
    }

    #[test]
    fn syslog_target_parsing_and_tls_requirements() {
        assert!(SyslogTarget::new("tcp://127.0.0.1:6514", None).is_ok());
        // tls:// without a CA fails closed.
        let err = SyslogTarget::new("tls://siem.example.com:6514", None).unwrap_err();
        assert!(err.contains("syslog_ca_file"), "{err}");
        // Unknown scheme rejected.
        assert!(SyslogTarget::new("udp://x:514", None).is_err());
    }

    #[test]
    fn syslog_timestamp_math_is_correct() {
        let mut record = ExportRecord {
            schema: EXPORT_SCHEMA.into(),
            rowid: 1,
            event_id: "e".into(),
            sequence_number: 9,
            ts_utc_ms: 1_700_000_000_123, // 2023-11-14T22:13:20.123Z
            level: "info".into(),
            kind: "request.received".into(),
            request_id: None,
            approval_id: None,
            client_json: None,
            operation: None,
            safety: None,
            target_json: None,
            outcome: None,
            latency_ms: None,
            secret_names: None,
            policy_decision: None,
            detail: None,
            workspace_json: None,
            request_hash: None,
            approver_json: None,
            record_hash: None,
        };
        let frame = String::from_utf8(syslog_frame(&record, "host1").unwrap()).unwrap();
        assert!(
            frame.contains("2023-11-14T22:13:20.123Z"),
            "epoch math wrong: {frame}"
        );
        // Leap-day sanity: 2024-02-29T00:00:00Z.
        record.ts_utc_ms = 1_709_164_800_000;
        let frame = String::from_utf8(syslog_frame(&record, "host1").unwrap()).unwrap();
        assert!(frame.contains("2024-02-29T00:00:00.000Z"), "{frame}");
    }
}
