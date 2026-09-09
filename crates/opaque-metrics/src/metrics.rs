//! Aggregate metrics from a trusted tenant-to-source mapping.
//!
//! The HTTP/MCP boundary supplies `verified_tenant` only after authentication.
//! A query cannot choose a tenant, URL, credential, SQL statement, or raw rows.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub const METRIC_NAMES: &[&str] = &[
    "requests_per_second",
    "error_rate_percent",
    "p95_latency_ms",
    "active_sessions",
    "credit_applications_per_minute",
    "manual_review_rate_percent",
    "identity_mismatch_rate_percent",
    "average_credit_score",
];
const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_SAMPLE_COUNT: u64 = 1_000_000_000_000;
const CLOCK_SKEW_SECS: i64 = 5;
const MAX_PROVIDER_REQUESTS: usize = 8;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSourceConfig {
    pub tenant_id: String,
    pub source_id: String,
    pub base_url: String,
    pub credential_env: String,
    pub allowed_metrics: Vec<String>,
    #[serde(default)]
    pub allowed_portfolio_measures: Vec<crate::portfolio::Measure>,
    /// Maximum window for the legacy scalar metrics endpoint. Portfolio history
    /// is separately enabled by allowed_portfolio_measures and fixed WINDOWS.
    pub max_window_secs: u32,
    pub max_staleness_secs: u32,
    #[serde(default)]
    pub allow_loopback_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsQuery {
    pub window_secs: u32,
    pub metrics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricRow {
    pub name: String,
    pub value: f64,
    /// Number of samples represented by the aggregate, not customer records.
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsEvidence {
    pub tenant_id: String,
    pub source_id: String,
    pub window_secs: u32,
    /// Source's aggregate snapshot time, in Unix seconds.
    pub as_of: i64,
    /// Source's latest included event time, in Unix seconds.
    pub watermark: i64,
    /// Gateway receipt time, in Unix seconds.
    pub observed_at: i64,
    pub metrics: Vec<MetricRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSnapshot {
    tenant_id: String,
    window_secs: u32,
    as_of: i64,
    watermark: i64,
    metrics: Vec<MetricRow>,
}

/// Stable errors intentionally omit provider payloads, URLs and credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MetricsError {
    #[error("invalid trusted metrics source configuration")]
    Configuration,
    #[error("tenant has no authorized metrics source")]
    TenantUnavailable,
    #[error("query exceeds the authorized metric or window scope")]
    InvalidQuery,
    #[error("metrics source rejected the query")]
    SourceRejected,
    #[error("metrics source is unavailable")]
    SourceUnavailable,
    #[error("metrics source request capacity reached")]
    SourceBusy,
    #[error("metrics source returned invalid or stale evidence")]
    InvalidEvidence,
}

struct TrustedSource {
    config: MetricsSourceConfig,
    query_url: reqwest::Url,
    authorization: HeaderValue,
}

pub struct MetricsClient {
    http: reqwest::Client,
    sources: BTreeMap<String, TrustedSource>,
    // Independent from browser-chat admission: nested chat MCP reads must not
    // need another permit from the already occupied chat pool.
    capacity: tokio::sync::Semaphore,
}

impl MetricsClient {
    pub async fn query_portfolio(
        &self,
        verified_tenant: &str,
        query: crate::portfolio::PortfolioQuery,
    ) -> Result<crate::portfolio::PortfolioEvidence, MetricsError> {
        let source = self
            .sources
            .get(verified_tenant)
            .ok_or(MetricsError::TenantUnavailable)?;
        query
            .validate(&source.config.allowed_portfolio_measures)
            .map_err(|_| MetricsError::InvalidQuery)?;
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| MetricsError::SourceBusy)?;
        let mut url = source.query_url.clone();
        url.set_path("/v1/portfolio/query");
        let mut response = self
            .http
            .post(url)
            .header(AUTHORIZATION, source.authorization.clone())
            .json(&query)
            .send()
            .await
            .map_err(|_| MetricsError::SourceUnavailable)?;
        if response.status().is_client_error() {
            return Err(MetricsError::SourceRejected);
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(MetricsError::SourceUnavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY_BYTES as u64)
        {
            return Err(MetricsError::InvalidEvidence);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| MetricsError::SourceUnavailable)?
        {
            if chunk.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
                return Err(MetricsError::InvalidEvidence);
            }
            bytes.extend_from_slice(&chunk);
        }
        let snapshot: crate::portfolio::PortfolioSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| MetricsError::InvalidEvidence)?;
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MetricsError::InvalidEvidence)?
            .as_secs() as i64;
        snapshot
            .validate(
                verified_tenant,
                &query,
                &source.config.allowed_portfolio_measures,
                observed_at,
                source.config.max_staleness_secs,
            )
            .map_err(|_| MetricsError::InvalidEvidence)?;
        Ok(crate::portfolio::PortfolioEvidence {
            snapshot,
            source_id: source.config.source_id.clone(),
            observed_at,
            coverage: "complete".into(),
        })
    }
    /// Resolve each source credential at startup, before any caller request.
    /// The resulting client retains authority from this trusted configuration.
    pub fn new(configs: Vec<MetricsSourceConfig>) -> Result<Self, MetricsError> {
        Self::from_configs(configs, |name| std::env::var(name).ok())
    }

    fn from_configs(
        configs: Vec<MetricsSourceConfig>,
        mut credential: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, MetricsError> {
        if configs.is_empty() || configs.len() > 128 {
            return Err(MetricsError::Configuration);
        }
        let mut sources = BTreeMap::new();
        for config in configs {
            let query_url = validate_config(&config)?;
            if sources.contains_key(&config.tenant_id) {
                return Err(MetricsError::Configuration);
            }
            let secret = Zeroizing::new(
                credential(&config.credential_env).ok_or(MetricsError::Configuration)?,
            );
            // RFC 6750 b64token: do not accept whitespace, newlines or arbitrary
            // headers from a mistaken environment variable.
            if secret.is_empty()
                || secret.len() > 4096
                || !secret
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
            {
                return Err(MetricsError::Configuration);
            }
            let bearer = Zeroizing::new(format!("Bearer {}", secret.as_str()));
            let mut authorization =
                HeaderValue::from_str(&bearer).map_err(|_| MetricsError::Configuration)?;
            authorization.set_sensitive(true);
            sources.insert(
                config.tenant_id.clone(),
                TrustedSource {
                    config,
                    query_url,
                    authorization,
                },
            );
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| MetricsError::Configuration)?;
        Ok(Self {
            http,
            sources,
            capacity: tokio::sync::Semaphore::new(MAX_PROVIDER_REQUESTS),
        })
    }

    /// `verified_tenant` must originate in the server's verified auth context,
    /// never an MCP argument or an unverified token claim.
    pub async fn query(
        &self,
        verified_tenant: &str,
        request: MetricsQuery,
    ) -> Result<MetricsEvidence, MetricsError> {
        let source = self
            .sources
            .get(verified_tenant)
            .ok_or(MetricsError::TenantUnavailable)?;
        let requested = validate_query(&source.config, &request)?;
        let _permit = self
            .capacity
            .try_acquire()
            .map_err(|_| MetricsError::SourceBusy)?;
        let mut response = self
            .http
            .post(source.query_url.clone())
            .header(AUTHORIZATION, source.authorization.clone())
            .json(&request)
            .send()
            .await
            .map_err(|_| MetricsError::SourceUnavailable)?;
        if response.status().is_client_error() {
            return Err(MetricsError::SourceRejected);
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(MetricsError::SourceUnavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY_BYTES as u64)
        {
            return Err(MetricsError::InvalidEvidence);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| MetricsError::SourceUnavailable)?
        {
            if chunk.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
                return Err(MetricsError::InvalidEvidence);
            }
            bytes.extend_from_slice(&chunk);
        }
        let snapshot: SourceSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| MetricsError::InvalidEvidence)?;
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MetricsError::InvalidEvidence)?
            .as_secs() as i64;
        validate_snapshot(&source.config, &request, &requested, &snapshot, observed_at)?;
        Ok(MetricsEvidence {
            tenant_id: source.config.tenant_id.clone(),
            source_id: source.config.source_id.clone(),
            window_secs: snapshot.window_secs,
            as_of: snapshot.as_of,
            watermark: snapshot.watermark,
            observed_at,
            metrics: snapshot.metrics,
        })
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
}

fn validate_config(config: &MetricsSourceConfig) -> Result<reqwest::Url, MetricsError> {
    let invalid = || MetricsError::Configuration;
    let mut url = reqwest::Url::parse(&config.base_url).map_err(|_| invalid())?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if config.base_url.len() > 2048
        || !valid_id(&config.tenant_id)
        || !valid_id(&config.source_id)
        || config.credential_env.is_empty()
        || config.credential_env.len() > 128
        || config.credential_env.as_bytes()[0].is_ascii_digit()
        || !config
            .credential_env
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || !(1..=3600).contains(&config.max_window_secs)
        || !(1..=300).contains(&config.max_staleness_secs)
        || config.allowed_metrics.is_empty()
        || config.allowed_metrics.len() > METRIC_NAMES.len()
        || config
            .allowed_metrics
            .iter()
            .any(|name| !METRIC_NAMES.contains(&name.as_str()))
        || config.allowed_metrics.iter().collect::<BTreeSet<_>>().len()
            != config.allowed_metrics.len()
        || config.allowed_portfolio_measures.len() > 6
        || config
            .allowed_portfolio_measures
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != config.allowed_portfolio_measures.len()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !(url.scheme() == "https"
            || url.scheme() == "http" && loopback && config.allow_loopback_http)
    {
        return Err(invalid());
    }
    url.set_path("/v1/metrics/query");
    Ok(url)
}

fn validate_query<'a>(
    config: &MetricsSourceConfig,
    request: &'a MetricsQuery,
) -> Result<BTreeSet<&'a str>, MetricsError> {
    let requested: BTreeSet<_> = request.metrics.iter().map(String::as_str).collect();
    if request.window_secs == 0
        || request.window_secs > config.max_window_secs
        || requested.is_empty()
        || request.metrics.len() > METRIC_NAMES.len()
        || requested.len() != request.metrics.len()
        || request
            .metrics
            .iter()
            .any(|name| !config.allowed_metrics.contains(name))
    {
        return Err(MetricsError::InvalidQuery);
    }
    Ok(requested)
}

fn validate_snapshot(
    config: &MetricsSourceConfig,
    request: &MetricsQuery,
    requested: &BTreeSet<&str>,
    snapshot: &SourceSnapshot,
    observed_at: i64,
) -> Result<(), MetricsError> {
    let names: BTreeSet<_> = snapshot
        .metrics
        .iter()
        .map(|row| row.name.as_str())
        .collect();
    if snapshot.tenant_id != config.tenant_id
        || snapshot.window_secs != request.window_secs
        || snapshot.as_of < i64::from(request.window_secs)
        || snapshot.as_of > observed_at.saturating_add(CLOCK_SKEW_SECS)
        || snapshot.watermark <= 0
        || snapshot.watermark > snapshot.as_of
        || snapshot.watermark < observed_at.saturating_sub(i64::from(config.max_staleness_secs))
        || &names != requested
        || names.len() != snapshot.metrics.len()
        || snapshot.metrics.iter().any(|row| {
            !row.value.is_finite()
                || row.value < 0.0
                || row.value > 1_000_000_000_000_000.0
                || row.count > MAX_SAMPLE_COUNT
                || matches!(
                    row.name.as_str(),
                    "error_rate_percent"
                        | "manual_review_rate_percent"
                        | "identity_mismatch_rate_percent"
                ) && row.value > 100.0
                || row.name == "average_credit_score" && row.value > 850.0
                || row.name == "active_sessions" && row.value.fract() != 0.0
        })
    {
        return Err(MetricsError::InvalidEvidence);
    }
    Ok(())
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
