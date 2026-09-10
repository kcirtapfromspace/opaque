//! Server-side read-only collector client. Browser credentials authenticate
//! this dashboard; the tenant collector credential never reaches the page.
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetConfig {
    collector_url: String,
    tenant_id: String,
    read_token_file: PathBuf,
}

#[derive(Clone)]
pub struct FleetClient {
    client: reqwest::Client,
    url: reqwest::Url,
    tenant: String,
    token_file: PathBuf,
}

#[derive(Deserialize, Serialize)]
pub struct Snapshot {
    schema_version: u32,
    scope: String,
    tenant_id: String,
    observed_at: i64,
    brokers: Vec<Broker>,
    evidence_contract: String,
}
#[derive(Deserialize, Serialize)]
struct Broker {
    tenant_id: String,
    broker_id: String,
    enrollment_epoch: u64,
    status: String,
    last_contact: Option<i64>,
    contact_age_secs: Option<u64>,
    daemon_version: Option<String>,
    current_posture: Option<String>,
    policy: Option<Policy>,
    policy_status: String,
    audit_head: Option<u64>,
    last_known_audit_head: Option<u64>,
    acknowledged_evidence_sequence: Option<u64>,
    evidence_health: String,
    evidence_export_lag_records: Option<u64>,
    evidence_coverage_start: Option<u64>,
}
#[derive(Deserialize, Serialize)]
struct Policy {
    org: String,
    version: u64,
    digest: String,
}

fn private_bytes(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "fleet configuration or credential unavailable")?;
    let meta = file
        .metadata()
        .map_err(|_| "fleet configuration unavailable")?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.len() > limit
    {
        return Err("fleet configuration requires private bounded regular files".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "fleet configuration unavailable")?;
    if bytes.len() as u64 > limit {
        return Err("fleet configuration exceeds limit".into());
    }
    Ok(bytes)
}
impl FleetClient {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let config: FleetConfig = serde_json::from_slice(&private_bytes(path, 16384)?)
            .map_err(|_| "invalid fleet configuration")?;
        opaque_core::tenant::TenantId::parse(&config.tenant_id)
            .map_err(|_| "invalid fleet tenant")?;
        let mut url = reqwest::Url::parse(&config.collector_url)
            .map_err(|_| "invalid fleet collector URL")?;
        let loopback = url
            .host_str()
            .and_then(|v| v.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || !config.read_token_file.is_absolute()
        {
            return Err(
                "fleet collector requires HTTPS or literal loopback HTTP and a private token file"
                    .into(),
            );
        }
        url.set_path(&format!("/v1/tenants/{}/brokers", config.tenant_id));
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(2))
            .build()
            .map_err(|_| "fleet client unavailable")?;
        Ok(Self {
            client,
            url,
            tenant: config.tenant_id,
            token_file: config.read_token_file,
        })
    }
    pub async fn snapshot(&self) -> Result<Snapshot, String> {
        let token = String::from_utf8(private_bytes(&self.token_file, 4096)?)
            .map_err(|_| "invalid fleet read credential")?;
        let token = token.trim_end_matches('\n');
        if token.is_empty() || !token.bytes().all(|b| (b'!'..=b'~').contains(&b)) {
            return Err("invalid fleet read credential".into());
        }
        let mut response = self
            .client
            .get(self.url.clone())
            .header(reqwest::header::CACHE_CONTROL, "no-cache")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| "fleet collector unavailable")?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|v| v > 1024 * 1024)
            || !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
                })
        {
            return Err("fleet collector did not return a valid inventory".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "fleet inventory incomplete")?
        {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err("fleet inventory exceeds limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let snapshot: Snapshot =
            serde_json::from_slice(&bytes).map_err(|_| "invalid fleet inventory")?;
        let now = opaque_core::identity::now_unix();
        if snapshot.schema_version != 1
            || snapshot.scope != "enrolled_brokers_only"
            || snapshot.tenant_id != self.tenant
            || snapshot.observed_at.abs_diff(now) > 60
            || snapshot.brokers.len() > 1000
            || snapshot.evidence_contract.len() > 1024
        {
            return Err("fleet inventory scope or version mismatch".into());
        }
        for broker in &snapshot.brokers {
            if broker.tenant_id != self.tenant
                || uuid::Uuid::parse_str(&broker.broker_id).is_err()
                || !matches!(
                    broker.status.as_str(),
                    "fresh" | "stale" | "offline" | "unknown" | "revoked"
                )
                || !matches!(
                    broker.evidence_health.as_str(),
                    "ok" | "unknown" | "unavailable" | "regressed" | "gap"
                )
                || broker.evidence_health != "ok" && broker.evidence_export_lag_records.is_some()
                || broker
                    .daemon_version
                    .as_ref()
                    .is_some_and(|v| v.len() > 128)
                || !matches!(
                    broker.policy_status.as_str(),
                    "matches" | "drift" | "unknown"
                )
                || broker
                    .current_posture
                    .as_ref()
                    .is_some_and(|v| !matches!(v.as_str(), "healthy" | "unhealthy"))
                || broker.status != "fresh" && broker.current_posture.is_some()
                || broker.policy.as_ref().is_some_and(|p| {
                    p.org.len() > 128
                        || opaque_core::workstation::decode_hex::<32>(&p.digest).is_err()
                })
            {
                return Err("fleet inventory contains invalid broker evidence".into());
            }
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::*};
    fn client(server: &MockServer) -> (tempfile::TempDir, FleetClient) {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("read.token");
        std::fs::write(&token, "fixture-fleet-read-secret").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = dir.path().join("fleet.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "collector_url":server.uri(),"tenant_id":"fixture","read_token_file":token
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let client = FleetClient::from_file(&config).unwrap();
        (dir, client)
    }
    fn body() -> serde_json::Value {
        serde_json::json!({
            "schema_version":1,"scope":"enrolled_brokers_only","tenant_id":"fixture","observed_at":opaque_core::identity::now_unix(),"brokers":[],
            "evidence_contract":"Compact record evidence only","extra_secret":"must-not-reach-browser"
        })
    }
    #[tokio::test]
    async fn read_credential_stays_server_side_and_unknown_fields_are_dropped() {
        let server = MockServer::start().await;
        let (_dir, client) = client(&server);
        Mock::given(method("GET"))
            .and(path("/v1/tenants/fixture/brokers"))
            .and(header("authorization", "Bearer fixture-fleet-read-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body()))
            .expect(1)
            .mount(&server)
            .await;
        let output = serde_json::to_string(&client.snapshot().await.unwrap()).unwrap();
        assert!(!output.contains("fixture-fleet-read-secret"));
        assert!(!output.contains("extra_secret"));
        assert!(!output.contains("must-not"));
    }
    #[tokio::test]
    async fn wrong_tenant_and_stale_healthy_inventory_fail_closed() {
        let server = MockServer::start().await;
        let (_dir, client) = client(&server);
        let mut wrong = body();
        wrong["tenant_id"] = "foreign".into();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(wrong))
            .mount(&server)
            .await;
        assert!(client.snapshot().await.is_err());
        server.reset().await;
        let mut stale = body();
        stale["brokers"] = serde_json::json!([{
            "tenant_id":"fixture","broker_id":uuid::Uuid::new_v4(),"enrollment_epoch":1,"status":"stale",
            "current_posture":"healthy","policy_status":"unknown","evidence_health":"unknown"
        }]);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(stale))
            .mount(&server)
            .await;
        assert!(client.snapshot().await.is_err());
    }
}
