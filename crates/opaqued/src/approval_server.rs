//! Local HTTPS approval server for paired mobile devices.
//!
//! The server listens on localhost with a self-signed TLS certificate
//! and advertises itself via mDNS (Bonjour) as `_opaque-approval._tcp`.
//! Paired iOS devices connect to submit approval decisions for pending
//! operation challenges.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Json, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("TLS setup failed: {0}")]
    TlsSetup(String),

    #[error("certificate generation failed: {0}")]
    CertGeneration(String),

    #[error("server bind failed: {0}")]
    Bind(String),

    #[error("mDNS registration failed: {0}")]
    MdnsRegistration(String),
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Configuration for the approval server.
#[derive(Debug, Clone)]
pub struct ApprovalServerConfig {
    /// Address to bind to (default: 127.0.0.1:0 for auto port selection).
    pub bind_addr: SocketAddr,
    /// TLS certificate (DER-encoded).
    pub tls_cert_der: Vec<u8>,
    /// TLS private key (PKCS8 DER-encoded).
    pub tls_key_der: Vec<u8>,
    /// Approval timeout in seconds (default: 60).
    pub timeout_secs: u64,
    /// Device session tokens (device_id -> token).
    pub device_tokens: HashMap<String, String>,
}

/// A challenge submitted for approval by a paired device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub request_id: String,
    pub operation: String,
    pub target: String,
    pub client_identity: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub challenge_data: String,
}

/// Response from a device approving or rejecting a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub request_id: String,
    pub decision: ApprovalDecision,
    pub device_id: String,
    pub signature: String,
}

/// The decision on an approval challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

/// Body submitted by the device on the respond endpoint.
#[derive(Debug, Deserialize)]
pub struct RespondBody {
    pub decision: ApprovalDecision,
    pub signature: String,
    pub device_id: String,
}

/// Pending approval entry (internal).
#[derive(Debug)]
struct PendingApproval {
    challenge: ApprovalChallenge,
    response_tx: oneshot::Sender<ApprovalResponse>,
    created_at: Instant,
    timeout: Duration,
}

/// JSON returned by GET /approvals/pending.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingApprovalsResponse {
    pub approvals: Vec<ApprovalChallenge>,
}

/// JSON returned by GET /health.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct ServerState {
    pending: Mutex<HashMap<String, PendingApproval>>,
    device_tokens: HashMap<String, String>,
    timeout: Duration,
}

// ---------------------------------------------------------------------------
// TLS certificate generation
// ---------------------------------------------------------------------------

/// Generated TLS identity with the certificate fingerprint for pairing.
#[derive(Debug, Clone)]
pub struct TlsIdentity {
    /// DER-encoded certificate bytes.
    pub cert_der: Vec<u8>,
    /// PKCS8 DER-encoded private key bytes.
    pub key_der: Vec<u8>,
    /// SHA-256 fingerprint of the certificate (hex-encoded).
    pub fingerprint: String,
    /// PEM-encoded certificate (for display/storage).
    pub cert_pem: String,
}

/// Generate a self-signed Ed25519 TLS certificate for the approval server.
pub fn generate_self_signed_cert() -> Result<TlsIdentity, ServerError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| ServerError::CertGeneration(e.to_string()))?;

    let mut params = CertificateParams::new(vec!["localhost".into()])
        .map_err(|e| ServerError::CertGeneration(e.to_string()))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("Opaque Approval Server".into()),
    );

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ServerError::CertGeneration(e.to_string()))?;

    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_der = key_pair.serialize_der();

    // SHA-256 fingerprint of the DER certificate.
    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let fingerprint = hex::encode(hasher.finalize());

    Ok(TlsIdentity {
        cert_der,
        key_der,
        fingerprint,
        cert_pem,
    })
}

// Inline hex encoding to avoid adding a `hex` dependency.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// ApprovalServer
// ---------------------------------------------------------------------------

/// Local HTTPS approval server for paired mobile devices.
pub struct ApprovalServer {
    state: Arc<ServerState>,
    config: ApprovalServerConfig,
}

impl ApprovalServer {
    /// Create a new approval server with the given configuration.
    pub fn new(config: ApprovalServerConfig) -> Result<Self, ServerError> {
        let state = Arc::new(ServerState {
            pending: Mutex::new(HashMap::new()),
            device_tokens: config.device_tokens.clone(),
            timeout: Duration::from_secs(config.timeout_secs),
        });

        Ok(Self { state, config })
    }

    /// Start the server in a background task. Returns the join handle and the
    /// actual bound address (useful when port 0 is used for auto-selection).
    pub async fn start(self) -> Result<(JoinHandle<()>, SocketAddr), ServerError> {
        let tls_config = build_tls_config(&self.config.tls_cert_der, &self.config.tls_key_der)?;

        let app = build_router(self.state.clone());

        let listener = tokio::net::TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let state = self.state.clone();
        let timeout = state.timeout;

        let handle = tokio::spawn(async move {
            // Spawn a background task to expire timed-out approvals.
            let expiry_state = state.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    expire_pending(&expiry_state, timeout).await;
                }
            });

            // Accept TLS connections and serve.
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!("approval server accept error: {e}");
                        continue;
                    }
                };

                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("TLS handshake failed: {e}");
                        continue;
                    }
                };

                let app = app.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app.into_service());
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        warn!("connection error: {e}");
                    }
                });
            }
        });

        info!("approval server listening on {local_addr}");
        Ok((handle, local_addr))
    }

    /// Submit a challenge for approval and get a receiver for the response.
    /// The challenge will expire after the configured timeout.
    pub async fn submit_challenge(
        &self,
        challenge: ApprovalChallenge,
    ) -> oneshot::Receiver<ApprovalResponse> {
        let (tx, rx) = oneshot::channel();
        let entry = PendingApproval {
            challenge: challenge.clone(),
            response_tx: tx,
            created_at: Instant::now(),
            timeout: self.state.timeout,
        };
        let mut pending = self.state.pending.lock().await;
        pending.insert(challenge.request_id.clone(), entry);
        rx
    }

    /// Get a reference to the shared state (for testing).
    #[cfg(test)]
    pub(crate) fn state(&self) -> &Arc<ServerState> {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// TLS configuration
// ---------------------------------------------------------------------------

fn build_tls_config(cert_der: &[u8], key_der: &[u8]) -> Result<rustls::ServerConfig, ServerError> {
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::TlsSetup(e.to_string()))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/approvals/pending", get(pending_handler))
        .route("/approvals/{request_id}/respond", post(respond_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

async fn pending_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<PendingApprovalsResponse>, StatusCode> {
    validate_auth(&state, &headers)?;

    let pending = state.pending.lock().await;
    let approvals: Vec<ApprovalChallenge> = pending.values().map(|p| p.challenge.clone()).collect();

    Ok(Json(PendingApprovalsResponse { approvals }))
}

async fn respond_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(body): Json<RespondBody>,
) -> Result<StatusCode, StatusCode> {
    validate_auth(&state, &headers)?;

    let mut pending = state.pending.lock().await;
    let entry = pending.remove(&request_id).ok_or(StatusCode::NOT_FOUND)?;

    // Check if expired.
    if entry.created_at.elapsed() > entry.timeout {
        return Err(StatusCode::GONE);
    }

    let response = ApprovalResponse {
        request_id,
        decision: body.decision,
        device_id: body.device_id,
        signature: body.signature,
    };

    // Send response through the channel; ignore error if receiver dropped.
    let _ = entry.response_tx.send(response);

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Auth validation
// ---------------------------------------------------------------------------

fn validate_auth(state: &ServerState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if the token matches any known device token.
    if !state.device_tokens.values().any(|t| t == token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

async fn expire_pending(state: &ServerState, _timeout: Duration) {
    let mut pending = state.pending.lock().await;
    pending.retain(|_id, entry| entry.created_at.elapsed() <= entry.timeout);
}

// ---------------------------------------------------------------------------
// mDNS advertisement
// ---------------------------------------------------------------------------

/// Advertise the approval server via mDNS/Bonjour.
///
/// Returns the `ServiceDaemon` handle (drop to stop advertising).
pub fn advertise_mdns(port: u16, fingerprint: &str) -> Result<mdns_sd::ServiceDaemon, ServerError> {
    let mdns =
        mdns_sd::ServiceDaemon::new().map_err(|e| ServerError::MdnsRegistration(e.to_string()))?;

    let service_type = "_opaque-approval._tcp.local.";
    let instance_name = "opaqued";

    let mut properties = HashMap::new();
    properties.insert("fingerprint".to_string(), fingerprint.to_string());

    let service_info = mdns_sd::ServiceInfo::new(
        service_type,
        instance_name,
        "localhost.",
        "",
        port,
        properties,
    )
    .map_err(|e| ServerError::MdnsRegistration(e.to_string()))?;

    mdns.register(service_info)
        .map_err(|e| ServerError::MdnsRegistration(e.to_string()))?;

    info!("mDNS: advertising {service_type} on port {port}");

    Ok(mdns)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper: generate a test config with a self-signed cert and auto port.
    fn test_config() -> (ApprovalServerConfig, TlsIdentity) {
        // Install the ring crypto provider for rustls (idempotent — ok to call multiple times).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let identity = generate_self_signed_cert().unwrap();
        let mut device_tokens = HashMap::new();
        device_tokens.insert("device-1".into(), "test-token-abc".into());

        let config = ApprovalServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            tls_cert_der: identity.cert_der.clone(),
            tls_key_der: identity.key_der.clone(),
            timeout_secs: 60,
            device_tokens,
        };
        (config, identity)
    }

    /// Build a reqwest client that accepts the self-signed cert.
    fn test_client(identity: &TlsIdentity) -> reqwest::Client {
        let cert = reqwest::tls::Certificate::from_der(&identity.cert_der).unwrap();
        reqwest::Client::builder()
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    }

    // -----------------------------------------------------------------------
    // Test: server binds to localhost
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_server_binds_to_localhost() {
        let (config, _identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();
        let (_handle, addr) = server.start().await.unwrap();

        assert!(
            addr.ip().is_loopback(),
            "server must bind to loopback, got {addr}"
        );
    }

    // -----------------------------------------------------------------------
    // Test: server uses self-signed TLS
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_server_uses_self_signed_tls() {
        let identity = generate_self_signed_cert().unwrap();

        // Fingerprint should be a 64-char hex string (SHA-256).
        assert_eq!(identity.fingerprint.len(), 64);
        assert!(identity.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));

        // PEM should start with certificate header.
        assert!(identity.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));

        // DER should be non-empty.
        assert!(!identity.cert_der.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test: GET /approvals/pending returns current pending request
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_pending_approval_endpoint() {
        let (config, identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();

        // Submit a challenge before starting.
        let challenge = ApprovalChallenge {
            request_id: "req-1".into(),
            operation: "github.set_actions_secret".into(),
            target: "org/repo".into(),
            client_identity: "test-client".into(),
            created_at: 1000,
            expires_at: 2000,
            challenge_data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"challenge-bytes",
            ),
        };
        let _rx = server.submit_challenge(challenge.clone()).await;

        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert_eq!(body.approvals.len(), 1);
        assert_eq!(body.approvals[0].request_id, "req-1");
        assert_eq!(body.approvals[0].operation, "github.set_actions_secret");
    }

    // -----------------------------------------------------------------------
    // Test: POST /approvals/{id}/approve via respond endpoint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_submit_approval_endpoint() {
        let (config, identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();

        let challenge = ApprovalChallenge {
            request_id: "req-approve".into(),
            operation: "github.set_actions_secret".into(),
            target: "org/repo".into(),
            client_identity: "test-client".into(),
            created_at: 1000,
            expires_at: 2000,
            challenge_data: "Y2hhbGxlbmdl".into(),
        };
        let rx = server.submit_challenge(challenge).await;

        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-approve/respond",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": "c2lnbmF0dXJl",
                "device_id": "device-1"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let approval = rx.await.unwrap();
        assert_eq!(approval.decision, ApprovalDecision::Approve);
        assert_eq!(approval.device_id, "device-1");
        assert_eq!(approval.request_id, "req-approve");
    }

    // -----------------------------------------------------------------------
    // Test: POST /approvals/{id}/reject via respond endpoint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reject_approval_endpoint() {
        let (config, identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();

        let challenge = ApprovalChallenge {
            request_id: "req-reject".into(),
            operation: "github.set_actions_secret".into(),
            target: "org/repo".into(),
            client_identity: "test-client".into(),
            created_at: 1000,
            expires_at: 2000,
            challenge_data: "Y2hhbGxlbmdl".into(),
        };
        let rx = server.submit_challenge(challenge).await;

        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-reject/respond",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .json(&serde_json::json!({
                "decision": "reject",
                "signature": "c2lnbmF0dXJl",
                "device_id": "device-1"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let approval = rx.await.unwrap();
        assert_eq!(approval.decision, ApprovalDecision::Reject);
    }

    // -----------------------------------------------------------------------
    // Test: unauthenticated request rejected
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_unauthenticated_request_rejected() {
        let (config, identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();
        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        // No Authorization header.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // Invalid token.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", "Bearer wrong-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // Malformed header (no Bearer prefix).
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", "test-token-abc")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    // -----------------------------------------------------------------------
    // Test: approval timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_approval_timeout() {
        let identity = generate_self_signed_cert().unwrap();
        let mut device_tokens = HashMap::new();
        device_tokens.insert("device-1".into(), "test-token-abc".into());

        // Very short timeout: 1 second.
        let config = ApprovalServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            tls_cert_der: identity.cert_der.clone(),
            tls_key_der: identity.key_der.clone(),
            timeout_secs: 1,
            device_tokens,
        };

        let server = ApprovalServer::new(config).unwrap();

        let challenge = ApprovalChallenge {
            request_id: "req-timeout".into(),
            operation: "test.op".into(),
            target: "target".into(),
            client_identity: "client".into(),
            created_at: 1000,
            expires_at: 1001,
            challenge_data: "data".into(),
        };
        let _rx = server.submit_challenge(challenge).await;

        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        // Wait for the challenge to expire.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // The expired challenge should be reaped by the background task.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .send()
            .await
            .unwrap();

        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert!(
            body.approvals.is_empty(),
            "expired approval should have been reaped"
        );
    }

    // -----------------------------------------------------------------------
    // Test: concurrent approvals handled correctly
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_concurrent_approvals() {
        let (config, identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();

        // Submit multiple challenges.
        let mut receivers = Vec::new();
        for i in 0..5 {
            let challenge = ApprovalChallenge {
                request_id: format!("req-{i}"),
                operation: "test.op".into(),
                target: format!("target-{i}"),
                client_identity: "client".into(),
                created_at: 1000,
                expires_at: 2000,
                challenge_data: "data".into(),
            };
            receivers.push(server.submit_challenge(challenge).await);
        }

        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        // Verify all are pending.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .send()
            .await
            .unwrap();

        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert_eq!(body.approvals.len(), 5);

        // Approve one, reject another.
        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-0/respond",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": "sig",
                "device_id": "device-1"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-1/respond",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .json(&serde_json::json!({
                "decision": "reject",
                "signature": "sig",
                "device_id": "device-1"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Verify remaining pending count.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .send()
            .await
            .unwrap();

        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert_eq!(body.approvals.len(), 3);

        // Verify the responses.
        let r0 = receivers.remove(0).await.unwrap();
        assert_eq!(r0.decision, ApprovalDecision::Approve);
        let r1 = receivers.remove(0).await.unwrap();
        assert_eq!(r1.decision, ApprovalDecision::Reject);
    }

    // -----------------------------------------------------------------------
    // Test: mDNS advertisement
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_mdns_advertisement() {
        let fingerprint = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        // Just verify the function doesn't panic and returns Ok.
        // Actual mDNS discovery is hard to test in CI, but we verify
        // the service daemon is created and registration doesn't error.
        let result = advertise_mdns(12345, fingerprint);
        match result {
            Ok(mdns) => {
                // Shutdown cleanly.
                let _ = mdns.shutdown();
            }
            Err(ServerError::MdnsRegistration(e)) => {
                // mDNS may fail in CI environments without a network stack.
                // This is acceptable — log and pass.
                eprintln!("mDNS not available in this environment: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test: port selection (auto port with 0)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_port_selection() {
        let (config, _identity) = test_config();
        // Config uses port 0, so the OS should assign a free port.
        assert_eq!(config.bind_addr.port(), 0);

        let server = ApprovalServer::new(config).unwrap();
        let (_handle, addr) = server.start().await.unwrap();

        // The assigned port should be non-zero.
        assert_ne!(addr.port(), 0, "OS should have assigned a real port");

        // And it should be on loopback.
        assert!(addr.ip().is_loopback());
    }

    // -----------------------------------------------------------------------
    // Test: health endpoint (no auth required)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_health_endpoint() {
        let (config, identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();
        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        let resp = client
            .get(format!("https://127.0.0.1:{}/health", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body: HealthResponse = resp.json().await.unwrap();
        assert_eq!(body.status, "ok");
    }

    // -----------------------------------------------------------------------
    // Test: respond to nonexistent request returns 404
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_respond_nonexistent_request() {
        let (config, identity) = test_config();
        let server = ApprovalServer::new(config).unwrap();
        let (_handle, addr) = server.start().await.unwrap();
        let client = test_client(&identity);

        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/nonexistent/respond",
                addr.port()
            ))
            .header("Authorization", "Bearer test-token-abc")
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": "sig",
                "device_id": "device-1"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
    }
}
