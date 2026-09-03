//! Federation: fetching, verifying, and applying signed policy bundles.
//!
//! The daemon is configured with trust anchors (org signing public keys) and
//! a bundle source — a local path or an HTTPS URL. On startup and on a
//! refresh interval it loads the bundle, verifies the Ed25519 signature and
//! anti-rollback version (state persisted in the custody set), and hot-swaps
//! the policy engine. When a bundle governs the daemon, bundle rules are
//! authoritative — local `[[rules]]` are the fallback only until the first
//! bundle ever applies (and never under `require_bundle`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditLevel, AuditSink};
use opaque_core::bundle::{self, BundleError, BundleState, Team, VerifiedBundle, parse_anchor};
use opaque_core::policy::PolicyEngine;
use serde::Deserialize;
use tracing::{info, warn};

/// `[federation]` daemon config.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FederationConfig {
    /// Org signing public keys, hex (multiple = rotation window).
    #[serde(default)]
    pub trust_anchors: Vec<String>,

    /// Local bundle file to load.
    #[serde(default)]
    pub bundle_path: Option<PathBuf>,

    /// HTTPS URL to fetch the bundle from. Takes effect alongside
    /// `bundle_path` (URL wins when both are set and reachable; the path
    /// serves as an offline fallback).
    #[serde(default)]
    pub bundle_url: Option<String>,

    /// Fail closed: refuse to start until a valid, unexpired bundle applies.
    #[serde(default)]
    pub require_bundle: bool,

    /// Re-fetch interval in seconds (default 300; 0 disables refresh).
    #[serde(default)]
    pub refresh_secs: Option<u64>,
}

impl FederationConfig {
    pub fn configured(&self) -> bool {
        self.bundle_path.is_some() || self.bundle_url.is_some()
    }

    pub fn anchors(&self) -> std::io::Result<Vec<ed25519_dalek::VerifyingKey>> {
        self.trust_anchors
            .iter()
            .map(|hex| {
                parse_anchor(hex).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("federation.trust_anchors entry is not a valid key: {hex:?}"),
                    )
                })
            })
            .collect()
    }
}

/// The currently applied bundle context, shared with request handling (teams
/// for namespace resolution, org for audit).
#[derive(Debug, Default)]
pub struct FederationStatus {
    inner: std::sync::RwLock<Option<Applied>>,
}

#[derive(Debug, Clone)]
pub struct Applied {
    pub org: String,
    pub version: u64,
    pub digest: String,
    pub teams: Vec<Team>,
}

impl FederationStatus {
    pub fn current(&self) -> Option<Applied> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set(&self, applied: Applied) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(applied);
    }

    /// Teams the given principal label belongs to under the applied bundle.
    pub fn teams_of(&self, principal_label: &str) -> Vec<String> {
        self.current()
            .map(|a| {
                a.teams
                    .iter()
                    .filter(|t| {
                        t.members
                            .iter()
                            .any(|m| m.eq_ignore_ascii_case(principal_label))
                    })
                    .map(|t| t.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Where the anti-rollback state lives (inside the custody set).
pub fn state_path(home: &Path) -> PathBuf {
    home.join(".opaque").join("bundle.state")
}

/// Fetch the raw bundle text from the configured source.
///
/// URL first (central control), file as fallback — a fetch failure with a
/// configured path degrades to the path so a network blip cannot strip
/// policy from a running fleet.
async fn fetch_bundle_text(config: &FederationConfig) -> Result<(String, String), String> {
    if let Some(url) = &config.bundle_url {
        match fetch_url(url).await {
            Ok(text) => return Ok((text, format!("url:{url}"))),
            Err(e) => {
                if config.bundle_path.is_none() {
                    return Err(format!("bundle fetch from {url} failed: {e}"));
                }
                warn!("bundle fetch from {url} failed ({e}); falling back to bundle_path");
            }
        }
    }
    if let Some(path) = &config.bundle_path {
        return std::fs::read_to_string(path)
            .map(|text| (text, format!("file:{}", path.display())))
            .map_err(|e| format!("bundle read from {} failed: {e}", path.display()));
    }
    Err("no bundle source configured".into())
}

async fn fetch_url(url: &str) -> Result<String, String> {
    if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") {
        return Err("bundle_url must be https:// (or http://127.0.0.1 for tests)".into());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    // A bundle is capped at ~1 MiB of payload; 4 MiB of transport is generous.
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("bundle response too large".into());
    }
    String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The stable context for applying bundles: trust anchors, rollback state
/// location, and the components a successful apply mutates.
pub struct BundleApplier {
    pub anchors: Vec<ed25519_dalek::VerifyingKey>,
    pub state_file: PathBuf,
    pub enclave: Arc<crate::enclave::Enclave>,
    pub status: Arc<FederationStatus>,
    pub audit: Arc<dyn AuditSink>,
}

impl BundleApplier {
    /// Verify + rollback-check + apply one bundle text. On success the policy
    /// is swapped, state persisted, status updated, and the application
    /// audited.
    ///
    /// `strict_expiry` controls staleness: the first bundle under
    /// `require_bundle` must be unexpired; refreshes of a running daemon
    /// accept staleness with a warning (an outage must not strip policy).
    pub fn apply_text(
        &self,
        text: &str,
        source: &str,
        strict_expiry: bool,
    ) -> Result<VerifiedBundle, String> {
        let (anchors, state_file, enclave, status, audit) = (
            &self.anchors[..],
            self.state_file.as_path(),
            self.enclave.as_ref(),
            self.status.as_ref(),
            &self.audit,
        );
        let verified = if strict_expiry {
            bundle::verify_bundle(text, anchors, now_unix()).map_err(|e| e.to_string())?
        } else {
            let v =
                bundle::verify_bundle_allow_expired(text, anchors).map_err(|e| e.to_string())?;
            if let Some(exp) = v.payload.expires_at
                && now_unix() >= exp
            {
                warn!(
                    "bundle v{} for org {} is EXPIRED (at {exp}) — applying anyway on refresh; \
                 the org should publish a fresh bundle",
                    v.payload.version, v.payload.org
                );
            }
            v
        };

        let prior =
            bundle::load_state(state_file).map_err(|e| format!("bundle state unreadable: {e}"))?;
        bundle::check_rollback(&verified, prior.as_ref()).map_err(|e| {
            // A refused rollback is a SECURITY event, not a fetch hiccup.
            audit.emit(
                AuditEvent::new(AuditEventKind::FederationBundleRejected)
                    .with_operation("federation_refresh")
                    .with_outcome(match e {
                        BundleError::Rollback { .. } => "rollback_refused",
                        BundleError::VersionReuse { .. } => "version_reuse_refused",
                        _ => "rejected",
                    })
                    .with_level(AuditLevel::Error)
                    .with_detail(format!("source={source}: {e}")),
            );
            e.to_string()
        })?;

        // Idempotent re-apply: same version+digest already active → nothing to do.
        if let (Some(prior), applied) = (&prior, status.current())
            && prior.version == verified.payload.version
            && prior.digest == verified.digest
            && applied.is_some()
        {
            return Ok(verified);
        }

        let engine = PolicyEngine::with_rules(verified.payload.rules.clone());
        let rule_count = enclave.swap_policy(engine);

        bundle::save_state(
            state_file,
            &BundleState {
                org: verified.payload.org.clone(),
                version: verified.payload.version,
                digest: verified.digest.clone(),
                applied_at: now_unix(),
            },
        )
        .map_err(|e| format!("bundle state persist failed: {e}"))?;

        status.set(Applied {
            org: verified.payload.org.clone(),
            version: verified.payload.version,
            digest: verified.digest.clone(),
            teams: verified.payload.teams.clone(),
        });

        info!(
            org = %verified.payload.org,
            version = verified.payload.version,
            rules = rule_count,
            teams = verified.payload.teams.len(),
            %source,
            "federation bundle applied"
        );
        audit.emit(
            AuditEvent::new(AuditEventKind::FederationBundleApplied)
                .with_operation("federation_refresh")
                .with_outcome("applied")
                .with_detail(format!(
                    "org={} version={} digest={} rules={} teams={} source={source}",
                    verified.payload.org,
                    verified.payload.version,
                    &verified.digest[..16.min(verified.digest.len())],
                    rule_count,
                    verified.payload.teams.len(),
                )),
        );

        Ok(verified)
    }

    /// Load and apply the bundle from the configured source (startup + refresh).
    pub async fn load_and_apply(
        &self,
        config: &FederationConfig,
        strict_expiry: bool,
    ) -> Result<(), String> {
        let (text, source) = fetch_bundle_text(config).await?;
        self.apply_text(&text, &source, strict_expiry).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use opaque_core::bundle::{BundlePayload, sign_bundle};
    use opaque_core::operation::{
        ApprovalFactor, ApprovalRequirement, OperationDef, OperationSafety,
    };
    use opaque_core::policy::PolicyRule;

    fn test_enclave() -> crate::enclave::Enclave {
        let mut registry = opaque_core::operation::OperationRegistry::new();
        registry
            .register(OperationDef {
                name: "test.noop".into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Never,
                default_factors: vec![ApprovalFactor::LocalBio],
                description: "noop".into(),
                params_schema: None,
                allowed_target_keys: vec![],
                secret_ref_param_keys: vec![],
            })
            .unwrap();
        crate::enclave::Enclave::builder()
            .registry(registry)
            .policy(PolicyEngine::new())
            .approval_gate(Box::new(crate::enclave::InsecureAutoApproveGate))
            .audit(Arc::new(opaque_core::audit::TracingAuditEmitter::new()))
            .build()
            .unwrap()
    }

    fn payload_with_rules(version: u64) -> BundlePayload {
        let rule: PolicyRule = toml_edit::de::from_str(
            r#"
            name = "bundle-allows-noop"
            operation_pattern = "test.noop"
            allow = true
            "#,
        )
        .unwrap();
        BundlePayload {
            org: "acme".into(),
            version,
            issued_at: now_unix() - 10,
            expires_at: None,
            key_id: String::new(),
            teams: vec![Team {
                name: "platform".into(),
                members: vec!["alice@acme.com".into()],
            }],
            rules: vec![rule],
        }
    }

    fn test_applier(dir: &std::path::Path, key: &SigningKey) -> BundleApplier {
        BundleApplier {
            anchors: vec![key.verifying_key()],
            state_file: dir.join("bundle.state"),
            enclave: Arc::new(test_enclave()),
            status: Arc::new(FederationStatus::default()),
            audit: Arc::new(opaque_core::audit::TracingAuditEmitter::new()),
        }
    }

    #[test]
    fn apply_swaps_policy_persists_state_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let applier = test_applier(dir.path(), &key);
        let state_file = applier.state_file.clone();
        let status = applier.status.clone();

        let text = sign_bundle(&payload_with_rules(1), &key).unwrap();
        applier.apply_text(&text, "test", true).unwrap();

        let applied = status.current().expect("status set");
        assert_eq!(applied.org, "acme");
        assert_eq!(applied.version, 1);
        assert_eq!(status.teams_of("alice@acme.com"), vec!["platform"]);
        assert_eq!(status.teams_of("Alice@Acme.com"), vec!["platform"]);
        assert!(status.teams_of("bob@acme.com").is_empty());

        let state = bundle::load_state(&state_file).unwrap().expect("state");
        assert_eq!(state.version, 1);

        // A newer version applies over it…
        let text2 = sign_bundle(&payload_with_rules(2), &key).unwrap();
        applier.apply_text(&text2, "test", true).unwrap();
        assert_eq!(status.current().unwrap().version, 2);

        // …and the old version is refused as a rollback.
        let err = applier.apply_text(&text, "test", true).unwrap_err();
        assert!(err.contains("rollback"), "{err}");
        assert_eq!(status.current().unwrap().version, 2, "status unchanged");
    }

    #[test]
    fn unsigned_or_wrong_key_bundle_never_applies() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let wrong = SigningKey::from_bytes(&[9u8; 32]);
        let applier = test_applier(dir.path(), &key);
        let state_file = applier.state_file.clone();
        let status = applier.status.clone();

        let text = sign_bundle(&payload_with_rules(1), &wrong).unwrap();
        let err = applier.apply_text(&text, "test", true).unwrap_err();
        assert!(err.contains("signature"), "{err}");
        assert!(status.current().is_none());
        assert!(bundle::load_state(&state_file).unwrap().is_none());
    }

    #[tokio::test]
    async fn url_fetch_falls_back_to_path() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let text = sign_bundle(&payload_with_rules(1), &key).unwrap();
        let path = dir.path().join("policy.bundle");
        std::fs::write(&path, &text).unwrap();

        let config = FederationConfig {
            trust_anchors: vec![],
            // Unreachable local port → falls back to the file.
            bundle_url: Some("http://127.0.0.1:9".into()),
            bundle_path: Some(path),
            require_bundle: false,
            refresh_secs: None,
        };
        let (got, source) = fetch_bundle_text(&config).await.unwrap();
        assert_eq!(got, text);
        assert!(source.starts_with("file:"));
    }

    #[test]
    fn anchors_parse_and_reject_garbage() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let hex: String = key
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let config = FederationConfig {
            trust_anchors: vec![hex],
            ..Default::default()
        };
        assert_eq!(config.anchors().unwrap().len(), 1);

        let bad = FederationConfig {
            trust_anchors: vec!["nothex".into()],
            ..Default::default()
        };
        assert!(bad.anchors().is_err());
    }
}
