//! Broker-owned periodic reporting. Only compact audit identity/hash metadata
//! is exported here; full audit export remains the existing separate transport.
use super::*;
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReporterConfig {
    pub collector_url: String,
    pub token_file: PathBuf,
    pub interval_secs: u64,
}
pub struct Reporter {
    client: reqwest::Client,
    base: reqwest::Url,
    token: zeroize::Zeroizing<String>,
    binding: TenantBinding,
    attestor: Arc<crate::attest::AttestationService>,
    audit_db: PathBuf,
    interval: u64,
}
impl Reporter {
    pub fn new(
        config: ReporterConfig,
        binding: TenantBinding,
        attestor: Arc<crate::attest::AttestationService>,
        state_dir: &Path,
    ) -> Result<Self> {
        binding_parts(&binding)?;
        let base =
            reqwest::Url::parse(&config.collector_url).map_err(|_| "invalid collector URL")?;
        let loopback = base
            .host_str()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !(base.scheme() == "https" || (base.scheme() == "http" && loopback))
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
            || !(1..=3600).contains(&config.interval_secs)
        {
            return Err("collector requires HTTPS root URL, or explicit loopback HTTP, and interval 1..3600".into());
        }
        if config.token_file.parent() != Some(state_dir) {
            return Err("fleet reporting credential must be directly inside broker custody".into());
        }
        let bytes = zeroize::Zeroizing::new(read_private_file(&config.token_file, 256)?);
        let token = std::str::from_utf8(&bytes).map_err(|_| "invalid reporter credential")?;
        if token.len() < 32
            || token.len() > 128
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err("invalid reporter credential".into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| "reporter client unavailable")?;
        Ok(Self {
            client,
            base,
            token: zeroize::Zeroizing::new(token.to_owned()),
            binding,
            attestor,
            audit_db: state_dir.join("audit.db"),
            interval: config.interval_secs,
        })
    }
    async fn response<T: serde::de::DeserializeOwned>(
        mut response: reqwest::Response,
    ) -> Result<T> {
        if !response.status().is_success() {
            return Err(format!(
                "collector refused report: HTTP {}",
                response.status().as_u16()
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "collector response unavailable")?
        {
            if bytes.len() + chunk.len() > 256 * 1024 {
                return Err("collector response exceeds bound".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| "invalid collector response".into())
    }
    pub async fn run_once(&self) -> Result<Acknowledgment> {
        let prefix = format!(
            "v1/tenants/{}/brokers/{}/",
            self.binding.tenant_id, self.binding.broker_id
        );
        let challenge: Challenge = Self::response(
            self.client
                .post(
                    self.base
                        .join(&(prefix.clone() + "challenge"))
                        .map_err(|_| "invalid collector path")?,
                )
                .bearer_auth(self.token.as_str())
                .send()
                .await
                .map_err(|_| "collector challenge unavailable")?,
        )
        .await?;
        if challenge.binding != self.binding
            || challenge.epoch == 0
            || challenge.expires_at <= now()
            || challenge.expires_at > now() + 90
            || challenge.nonce.len() != 32
            || !challenge.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("collector returned invalid challenge binding".into());
        }
        let evidence = read_evidence(&self.audit_db, challenge.acknowledged_sequence)?;
        let report = self
            .attestor
            .report(&Heartbeat::nonce_for(&challenge, &evidence)?)?;
        let heartbeat = Heartbeat {
            schema_version: 1,
            challenge: challenge.clone(),
            evidence,
            report,
        };
        let ack: Acknowledgment = Self::response(
            self.client
                .post(
                    self.base
                        .join(&(prefix + "heartbeat"))
                        .map_err(|_| "invalid collector path")?,
                )
                .bearer_auth(self.token.as_str())
                .json(&heartbeat)
                .send()
                .await
                .map_err(|_| "collector report unavailable")?,
        )
        .await?;
        if !matches!(
            ack.evidence_health.as_str(),
            "ok" | "unknown" | "unavailable" | "regressed" | "gap"
        ) {
            return Err("unknown evidence health".into());
        }
        let expected = if ack.evidence_health == "ok" {
            heartbeat
                .evidence
                .export_entries
                .last()
                .map(|entry| entry.sequence)
                .or(challenge.acknowledged_sequence)
        } else {
            challenge.acknowledged_sequence
        };
        if ack.binding != self.binding
            || ack.epoch != challenge.epoch
            || ack.acknowledged_sequence != expected
            || ack.received_at < now() - 60
            || ack.received_at > now() + 30
        {
            return Err("collector acknowledgment binding invalid".into());
        }
        if !heartbeat.evidence.export_entries.is_empty() && ack.evidence_health == "ok" {
            let digest = format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&heartbeat.evidence.export_entries)
                        .map_err(|_| "invalid evidence")?
                )
            );
            if ack.receipt_digest.as_deref() != Some(&digest) {
                return Err("collector acknowledgment digest invalid".into());
            }
        }
        if ack.evidence_health != "ok" {
            tracing::warn!(health=%ack.evidence_health,"fleet contact accepted with incomplete evidence");
        }
        Ok(ack)
    }
    pub async fn run(self) {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(self.interval));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            if let Err(error) = self.run_once().await {
                tracing::warn!(%error,"fleet report failed; collector freshness will age");
            }
        }
    }
}
fn read_evidence(path: &Path, after: Option<u64>) -> Result<Evidence> {
    let conn = sql(Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ))?;
    let head: Option<u64> = sql(conn.query_row(
        "SELECT MAX(sequence_number) FROM audit_events",
        [],
        |r| r.get(0),
    ))?;
    let mut statement=sql(conn.prepare("SELECT sequence_number,event_id,record_hash FROM audit_events WHERE sequence_number>?1 ORDER BY sequence_number LIMIT ?2"))?;
    let entries = sql(
        statement.query_map(params![after.unwrap_or(0), MAX_BATCH], |r| {
            Ok(ExportEntry {
                sequence: r.get(0)?,
                event_id: r.get(1)?,
                record_hash: r.get(2)?,
            })
        }),
    )?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|_| "audit metadata unavailable")?;
    Ok(Evidence {
        audit_head: head,
        export_entries: entries,
    })
}
