//! Continuous integrity attestation and verify-before-trust key release.
//!
//! Two halves:
//!
//! 1. **Posture reporting** — the daemon re-verifies its own custody set and
//!    audit chain on an interval, records the result in the tamper-evident
//!    chain (so "was this daemon healthy at time T?" is answerable from the
//!    log), and can produce an [`opaque_core::attest`] report signed with its
//!    attestation key and bound to a caller-supplied nonce.
//!
//! 2. **Key release** — the verify-before-trust seam. Before receiving
//!    custody material, the daemon proves its posture to a verifier: the
//!    verifier issues a nonce, the daemon answers with a freshly signed
//!    report, and only a report that verifies against the ENROLLED key and
//!    satisfies the verifier's posture policy earns the key material. This
//!    is where a KMS release policy or a SPIFFE/SPIRE SVID exchange slots in
//!    for hardware-rooted deployments; the protocol shape is the same.
//!
//! Honesty: this is software attestation. It proves a holder of the enrolled
//! key claims this posture, freshly — not a hardware measurement. What it
//! buys is that a daemon whose custody was tampered with cannot silently
//! collect fresh keys, because the report it must produce carries the
//! violations.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use opaque_core::attest::{
    AuditPosture, FederationPosture, ReportPayload, TrustDomainPosture, sign_report,
};
use opaque_core::audit::{AuditEvent, AuditEventKind, AuditLevel, AuditSink};
use opaque_core::trust_domain::{SystemFs, verify_custody};
use serde::Deserialize;
use tracing::warn;

/// `[attestation]` daemon config.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AttestationConfig {
    /// Re-verify posture every N seconds and record it in the audit chain
    /// (default 900; 0 disables the periodic task — reports are still
    /// available on demand).
    #[serde(default)]
    pub interval_secs: Option<u64>,

    /// Verifier that must approve this daemon's posture before releasing
    /// custody key material (verify-before-trust). Absent = no key release.
    #[serde(default)]
    pub key_release_url: Option<String>,

    /// Optional bearer credential presented to the verifier. Identity, not
    /// authorization: the release decision rests on the signed report.
    #[serde(default)]
    pub key_release_authorization: Option<String>,
}

/// Everything needed to produce a posture report.
pub struct AttestationService {
    signing_key: SigningKey,
    home: PathBuf,
    config_path: PathBuf,
    audit_db: PathBuf,
    daemon_version: String,
    enforce: bool,
    factors: Vec<String>,
    federation: Arc<crate::federation::FederationStatus>,
}

impl std::fmt::Debug for AttestationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationService")
            .field("public_key", &self.public_key_hex())
            .field("enforce", &self.enforce)
            .finish()
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl AttestationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signing_key: SigningKey,
        home: PathBuf,
        config_path: PathBuf,
        audit_db: PathBuf,
        daemon_version: String,
        enforce: bool,
        factors: Vec<String>,
        federation: Arc<crate::federation::FederationStatus>,
    ) -> Self {
        Self {
            signing_key,
            home,
            config_path,
            audit_db,
            daemon_version,
            enforce,
            factors,
            federation,
        }
    }

    /// The attestation public key (hex) — what a verifier enrolls.
    pub fn public_key_hex(&self) -> String {
        hex(self.signing_key.verifying_key().as_bytes())
    }

    /// Observe posture right now: custody + chain + federation.
    ///
    /// Read-only by design — unlike the startup check it never tightens
    /// modes, so a report describes what IS, not what the act of reporting
    /// made true.
    pub fn observe(&self) -> (TrustDomainPosture, AuditPosture) {
        let uid = unsafe { libc::geteuid() };
        let set = opaque_core::trust_domain::custody_paths(
            &self.home,
            &self.config_path,
            self.audit_db.parent().unwrap_or_else(|| Path::new(".")),
        );
        let violations = verify_custody(&set, uid, &SystemFs);
        let trust_domain = TrustDomainPosture {
            enforce: self.enforce,
            custody_ok: violations.is_empty(),
            custody_violations: violations.iter().map(|v| v.to_string()).collect(),
        };

        let audit = match opaque_core::audit::verify_audit_chain(&self.audit_db) {
            Ok(v) => AuditPosture {
                chain_ok: v.ok,
                records: v.records_checked,
                detail: v.detail,
            },
            Err(e) => AuditPosture {
                chain_ok: false,
                records: 0,
                detail: Some(format!("chain verification failed: {e}")),
            },
        };

        (trust_domain, audit)
    }

    /// Build and sign a report answering `nonce`.
    pub fn report(&self, nonce: &str) -> Result<String, String> {
        let (trust_domain, audit) = self.observe();
        let payload = ReportPayload {
            nonce: nonce.to_owned(),
            issued_at: now_unix(),
            daemon_version: self.daemon_version.clone(),
            uid: unsafe { libc::geteuid() },
            trust_domain,
            audit,
            federation: self.federation.current().map(|a| FederationPosture {
                org: a.org,
                version: a.version,
                digest: a.digest,
            }),
            factors: self.factors.clone(),
        };
        sign_report(&payload, &self.signing_key).map_err(|e| e.to_string())
    }

    /// Record the current posture in the tamper-evident chain.
    pub fn record_posture(&self, audit: &Arc<dyn AuditSink>, reason: &str) {
        let (td, chain) = self.observe();
        let healthy = td.custody_ok && chain.chain_ok;
        let detail = format!(
            "reason={reason} enforce={} custody_ok={} chain_ok={} records={}{}{}",
            td.enforce,
            td.custody_ok,
            chain.chain_ok,
            chain.records,
            if td.custody_violations.is_empty() {
                String::new()
            } else {
                format!(" violations=[{}]", td.custody_violations.join("; "))
            },
            chain
                .detail
                .as_ref()
                .map(|d| format!(" chain_detail={d}"))
                .unwrap_or_default(),
        );
        if !healthy {
            warn!("ATTESTATION: posture unhealthy — {detail}");
        }
        audit.emit(
            AuditEvent::new(AuditEventKind::TrustDomainPosture)
                .with_operation("attestation")
                .with_outcome(if healthy { "healthy" } else { "unhealthy" })
                .with_level(if healthy {
                    AuditLevel::Info
                } else {
                    AuditLevel::Error
                })
                .with_detail(detail),
        );
    }

    /// Periodic re-verification task.
    pub async fn run_periodic(self: Arc<Self>, audit: Arc<dyn AuditSink>, interval_secs: u64) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // startup already recorded posture
        loop {
            tick.tick().await;
            self.record_posture(&audit, "interval");
        }
    }
}

// ---------------------------------------------------------------------------
// Key release (verify-before-trust)
// ---------------------------------------------------------------------------

/// The verifier's challenge.
#[derive(Debug, Deserialize)]
pub struct ReleaseChallenge {
    /// Hex nonce the report must answer.
    pub nonce: String,
}

/// The verifier's response once the report satisfies its policy.
#[derive(Debug, Deserialize)]
pub struct ReleaseResponse {
    /// Released key material, base64url (no padding).
    pub key_material: String,
}

/// Client for the verify-before-trust exchange.
///
/// `GET  <url>/challenge` → `{"nonce": "<hex>"}`
/// `POST <url>/release`   → `{"report": "opqa1..."}` → `{"key_material": "<b64url>"}`
///
/// The daemon never sees the release policy: it proves posture and either
/// receives material or does not. A verifier that releases to an unhealthy
/// report is misconfigured on the verifier's side — which is exactly where
/// that decision belongs.
pub struct KeyReleaseClient {
    url: String,
    authorization: Option<String>,
    http: reqwest::Client,
}

impl KeyReleaseClient {
    pub fn new(url: String, authorization: Option<String>) -> Result<Self, String> {
        if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") {
            return Err(
                "attestation.key_release_url must be https:// (or http://127.0.0.1 for tests)"
                    .into(),
            );
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| format!("key release client: {e}"))?;
        Ok(Self {
            url,
            authorization,
            http,
        })
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.authorization {
            Some(value) => req.header("Authorization", value),
            None => req,
        }
    }

    /// Run the full exchange; returns the released key material.
    pub async fn release(&self, service: &AttestationService) -> Result<Vec<u8>, String> {
        use base64::Engine;

        let challenge: ReleaseChallenge = self
            .auth(self.http.get(format!("{}/challenge", self.url)))
            .send()
            .await
            .map_err(|e| format!("release challenge request: {e}"))?
            .error_for_status()
            .map_err(|e| format!("release challenge rejected: {e}"))?
            .json()
            .await
            .map_err(|e| format!("release challenge decode: {e}"))?;

        if challenge.nonce.len() < 16 || !challenge.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("verifier issued an unusable nonce (expected >=16 hex chars)".into());
        }

        let report = service.report(&challenge.nonce)?;
        let resp = self
            .auth(self.http.post(format!("{}/release", self.url)))
            .json(&serde_json::json!({ "report": report }))
            .send()
            .await
            .map_err(|e| format!("release request: {e}"))?;
        if !resp.status().is_success() {
            // A refusal is the system working — surface it as such.
            return Err(format!(
                "verifier refused key release: HTTP {} (posture rejected or key not enrolled)",
                resp.status()
            ));
        }
        let released: ReleaseResponse = resp
            .json()
            .await
            .map_err(|e| format!("release response decode: {e}"))?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&released.key_material)
            .map_err(|e| format!("released key material is not base64url: {e}"))
    }
}

/// Load (or create) the daemon's attestation signing key from the custody set.
#[cfg(test)]
pub fn load_or_create_key(home: &Path) -> std::io::Result<SigningKey> {
    load_or_create_key_in(&home.join(".opaque"))
}

pub fn load_or_create_key_in(state_dir: &Path) -> std::io::Result<SigningKey> {
    let path = state_dir.join("attestation.key");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = opaque_core::keyfile::load_or_create_key_file(&path)?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::attest::{AttestError, verify_report};
    use opaque_core::audit::SqliteAuditSink;

    const NONCE: &str = "0011223344556677889900aabbccddee";

    fn test_service(dir: &Path, enforce: bool) -> AttestationService {
        // A real audit db with a valid chain.
        let audit_db = dir.join(".opaque").join("audit.db");
        std::fs::create_dir_all(audit_db.parent().unwrap()).unwrap();
        let sink = SqliteAuditSink::new(audit_db.clone(), 90).unwrap();
        sink.emit(AuditEvent::new(AuditEventKind::RequestReceived).with_operation("test.noop"));
        drop(sink);

        let config_path = dir.join(".opaque").join("config.toml");
        std::fs::write(&config_path, "").unwrap();

        // Mirror the modes the daemon's startup custody pass establishes;
        // without this the fixture reports violations the real daemon would
        // already have tightened, and the test would assert on noise.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(dir.join(".opaque"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        AttestationService::new(
            SigningKey::from_bytes(&[21u8; 32]),
            dir.to_path_buf(),
            config_path,
            audit_db,
            "0.1.0+test".into(),
            enforce,
            vec!["local_bio".into()],
            Arc::new(crate::federation::FederationStatus::default()),
        )
    }

    #[test]
    fn report_is_signed_nonce_bound_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let service = test_service(dir.path(), true);

        let report = service.report(NONCE).unwrap();
        let key = service.signing_key.verifying_key();
        let verified = verify_report(&report, &key, NONCE, now_unix(), 300).unwrap();

        assert!(verified.payload.audit.chain_ok, "seeded chain must verify");
        assert_eq!(verified.payload.audit.records, 1);
        assert!(verified.payload.trust_domain.enforce);
        assert_eq!(verified.payload.daemon_version, "0.1.0+test");
        assert_eq!(verified.payload.factors, vec!["local_bio"]);

        // Replaying the same report against a different nonce fails.
        let err = verify_report(&report, &key, "ffffffffffffffff", now_unix(), 300).unwrap_err();
        assert!(matches!(err, AttestError::NonceMismatch { .. }));
    }

    #[test]
    fn report_carries_custody_violations_truthfully() {
        let dir = tempfile::tempdir().unwrap();
        let service = test_service(dir.path(), true);

        // Plant a violation the report must not hide: a symlinked chain key.
        let key_path = dir.path().join(".opaque").join("audit.hmac");
        let _ = std::fs::remove_file(&key_path);
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &key_path).unwrap();

        let report = service.report(NONCE).unwrap();
        let verified = verify_report(
            &report,
            &service.signing_key.verifying_key(),
            NONCE,
            now_unix(),
            300,
        )
        .unwrap();

        assert!(!verified.payload.trust_domain.custody_ok);
        assert!(
            !verified.payload.healthy_for_release(),
            "an unhealthy daemon must not pass a release policy"
        );
        assert!(
            verified
                .payload
                .trust_domain
                .custody_violations
                .iter()
                .any(|v| v.contains("symlink")),
            "violations: {:?}",
            verified.payload.trust_domain.custody_violations
        );
    }

    /// The full verify-before-trust exchange against a REFERENCE VERIFIER
    /// that enforces exactly what a KMS/SPIRE release policy would: known
    /// key, fresh nonce it issued, healthy posture.
    #[tokio::test]
    async fn key_release_requires_enrolled_key_fresh_nonce_and_healthy_posture() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let service = test_service(dir.path(), true);
        let enrolled = service.signing_key.verifying_key();
        let verifier_nonce = "a1b2c3d4e5f60718293a4b5c6d7e8f90";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kms/challenge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "nonce": verifier_nonce
            })))
            .mount(&server)
            .await;

        // The reference verifier: signature + nonce + freshness + posture.
        Mock::given(method("POST"))
            .and(path("/kms/release"))
            .respond_with(move |req: &Request| {
                let body: serde_json::Value = req.body_json().unwrap();
                let report = body["report"].as_str().unwrap_or_default();
                match verify_report(report, &enrolled, verifier_nonce, now_unix(), 300) {
                    Ok(v) if v.payload.healthy_for_release() => {
                        ResponseTemplate::new(200).set_body_json(serde_json::json!({
                            // "wrapped" custody material
                            "key_material": "c2VjcmV0LWtleS1tYXRlcmlhbA"
                        }))
                    }
                    Ok(_) => ResponseTemplate::new(403),
                    Err(_) => ResponseTemplate::new(401),
                }
            })
            .mount(&server)
            .await;

        let client = KeyReleaseClient::new(format!("{}/kms", server.uri()), None).unwrap();
        let material = client.release(&service).await.unwrap();
        assert_eq!(material, b"secret-key-material");

        // Now break custody: the SAME daemon, same key, must be refused.
        let key_path = dir.path().join(".opaque").join("audit.hmac");
        let _ = std::fs::remove_file(&key_path);
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &key_path).unwrap();

        let err = client.release(&service).await.unwrap_err();
        assert!(err.contains("refused"), "{err}");
        assert!(err.contains("403"), "posture refusal, not auth: {err}");
    }

    #[tokio::test]
    async fn key_release_refuses_unenrolled_daemon() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let service = test_service(dir.path(), true);
        // The verifier enrolled a DIFFERENT daemon's key.
        let enrolled = SigningKey::from_bytes(&[99u8; 32]).verifying_key();
        let verifier_nonce = "a1b2c3d4e5f60718293a4b5c6d7e8f90";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kms/challenge"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "nonce": verifier_nonce })),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/kms/release"))
            .respond_with(move |req: &Request| {
                let body: serde_json::Value = req.body_json().unwrap();
                let report = body["report"].as_str().unwrap_or_default();
                match verify_report(report, &enrolled, verifier_nonce, now_unix(), 300) {
                    Ok(v) if v.payload.healthy_for_release() => ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "key_material": "AAAA" })),
                    Ok(_) => ResponseTemplate::new(403),
                    Err(_) => ResponseTemplate::new(401),
                }
            })
            .mount(&server)
            .await;

        let client = KeyReleaseClient::new(format!("{}/kms", server.uri()), None).unwrap();
        let err = client.release(&service).await.unwrap_err();
        assert!(err.contains("401"), "unenrolled key must fail auth: {err}");
    }

    #[tokio::test]
    async fn key_release_rejects_unusable_verifier_nonce() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let service = test_service(dir.path(), true);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kms/challenge"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "nonce": "short" })),
            )
            .mount(&server)
            .await;

        let client = KeyReleaseClient::new(format!("{}/kms", server.uri()), None).unwrap();
        let err = client.release(&service).await.unwrap_err();
        assert!(err.contains("unusable nonce"), "{err}");
    }

    #[test]
    fn key_release_url_must_be_https() {
        assert!(KeyReleaseClient::new("http://kms.example.com".into(), None).is_err());
        assert!(KeyReleaseClient::new("https://kms.example.com".into(), None).is_ok());
        assert!(KeyReleaseClient::new("http://127.0.0.1:8080".into(), None).is_ok());
    }

    #[test]
    fn attestation_key_persists_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_key(dir.path()).unwrap();
        let second = load_or_create_key(dir.path()).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(".opaque").join("attestation.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
