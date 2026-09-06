//! Vault signs SSH certificates; the broker retains task authority and the
//! ephemeral key. The host independently enforces each signed, single-use grant.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use opaque_core::identity::{PrincipalContext, now_unix};
use opaque_core::inference::{sha256, valid_sha256};
use opaque_core::operation::ClientIdentity;
use opaque_core::ssh::{
    SSH_FIXED_COMMAND, SSH_OPERATION, SshHealthAction, SshReceipt, SshReceiptCode, canonical_ip,
    valid_ssh_label,
};
use opaque_core::task::{SlotOutcome, SlotState, TaskAction, TaskManifest};
use opaque_core::tenant::TenantBinding;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;

use crate::sandbox::resolve::CompositeResolver;
use opaque_core::resolver::SecretResolver;

const CONTROL_DOMAIN: &[u8] = b"opaque.ssh-control.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"opaque.ssh-receipt.v1\0";
const MAX_WIRE_BYTES: usize = 32 * 1024;

fn unavailable() -> String {
    "SSH profile or authenticated host evidence unavailable".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshProfileConfig {
    pub profile_id: String,
    pub destination_host: String,
    pub destination_port: u16,
    pub host_public_key: String,
    pub host_key_sha256: String,
    pub principal: String,
    pub login_user: String,
    pub source_address: String,
    pub max_session_secs: u32,
    pub vault_url: String,
    pub vault_mount: String,
    pub vault_role: String,
    pub vault_token_ref: String,
    pub vault_ca_public_key: String,
    pub vault_ca_sha256: String,
    pub control_url: String,
    /// Additional public TLS CA for the host control endpoint and Vault.
    #[serde(default)]
    pub tls_ca_pem: Option<String>,
    pub receipt_public_key_hex: String,
    /// A separate broker-owned Ed25519 task-grant key, never the Vault CA key.
    pub grant_signing_key_path: PathBuf,
    #[serde(default)]
    pub allow_loopback_http: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustedSshProfile {
    pub tenant: TenantBinding,
    #[serde(flatten)]
    pub config: SshProfileConfig,
}
impl std::ops::Deref for TrustedSshProfile {
    type Target = SshProfileConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}
impl SshProfileConfig {
    pub fn bind(&self, tenant: &TenantBinding) -> Result<TrustedSshProfile, String> {
        let profile = TrustedSshProfile {
            tenant: tenant.clone(),
            config: self.clone(),
        };
        profile.validate()?;
        profile.signing_key()?;
        Ok(profile)
    }
}

fn public_key(value: &str) -> Result<ssh_key::PublicKey, String> {
    let key = ssh_key::PublicKey::from_openssh(value).map_err(|_| unavailable())?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(unavailable());
    }
    Ok(key)
}
fn key_digest(value: &str) -> Result<String, String> {
    Ok(sha256(
        &public_key(value)?.to_bytes().map_err(|_| unavailable())?,
    ))
}
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(unavailable());
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| unavailable())?;
    }
    Ok(result)
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

impl TrustedSshProfile {
    pub fn validate(&self) -> Result<(), String> {
        self.tenant.validate().map_err(|_| unavailable())?;
        for base in [&self.vault_url, &self.control_url] {
            let url = reqwest::Url::parse(base).map_err(|_| unavailable())?;
            let loopback = url.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            });
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || !(url.scheme() == "https"
                    || self.allow_loopback_http && loopback && url.scheme() == "http")
            {
                return Err(unavailable());
            }
        }
        if !valid_ssh_label(&self.profile_id)
            || !canonical_ip(&self.destination_host)
            || self.destination_port == 0
            || !canonical_ip(&self.source_address)
            || !valid_ssh_label(&self.principal)
            || !valid_ssh_label(&self.login_user)
            || self.login_user == "root"
            || !(1..=30).contains(&self.max_session_secs)
            || !valid_ssh_label(&self.vault_mount)
            || !valid_ssh_label(&self.vault_role)
            || !valid_sha256(&self.host_key_sha256)
            || key_digest(&self.host_public_key)? != self.host_key_sha256
            || key_digest(&self.vault_ca_public_key)? != self.vault_ca_sha256
            || !self.grant_signing_key_path.is_absolute()
            || self.vault_token_ref.len() > 512
            || !["env:", "keychain:", "vault:"]
                .iter()
                .any(|prefix| self.vault_token_ref.starts_with(prefix))
            || opaque_core::validate::InputValidator::validate_secret_ref_names(
                std::slice::from_ref(&self.vault_token_ref),
            )
            .is_err()
        {
            return Err(unavailable());
        }
        VerifyingKey::from_bytes(&decode_hex::<32>(&self.receipt_public_key_hex)?)
            .map_err(|_| unavailable())?;
        if let Some(pem) = &self.tls_ca_pem {
            if pem.len() > 16384 || pem.contains("PRIVATE KEY") {
                return Err(unavailable());
            }
            reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|_| unavailable())?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let mut bytes = b"opaque.ssh-profile.v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| unavailable())?);
        Ok(sha256(&bytes))
    }
    fn signing_key(&self) -> Result<SigningKey, String> {
        super::validate_path_chain(&self.grant_signing_key_path).map_err(|_| unavailable())?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.grant_signing_key_path)
            .map_err(|_| unavailable())?;
        let meta = file.metadata().map_err(|_| unavailable())?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.len() != 32
        {
            return Err(unavailable());
        }
        let mut bytes = zeroize::Zeroizing::new([0; 32]);
        file.read_exact(bytes.as_mut()).map_err(|_| unavailable())?;
        Ok(SigningKey::from_bytes(&bytes))
    }
    fn http(&self) -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5));
        if let Some(pem) = &self.tls_ca_pem {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|_| unavailable())?,
            );
        }
        builder.build().map_err(|_| unavailable())
    }
}

pub fn health_manifest(
    profile: &TrustedSshProfile,
    title: String,
    expires_in_secs: u64,
    principal: &PrincipalContext,
    client: &ClientIdentity,
) -> Result<TaskManifest, String> {
    let action = SshHealthAction {
        operation: SSH_OPERATION.into(),
        tenant: profile.tenant.clone(),
        subject: principal.sub.clone(),
        delegation_id: principal.jti.clone(),
        workload_uid: client.uid,
        workload_exe_sha256: client.exe_sha256.clone(),
        profile_id: profile.profile_id.clone(),
        profile_sha256: profile.digest()?,
        destination_host: profile.destination_host.clone(),
        destination_port: profile.destination_port,
        host_key_sha256: profile.host_key_sha256.clone(),
        principal: profile.principal.clone(),
        login_user: profile.login_user.clone(),
        source_address: profile.source_address.clone(),
        command: SSH_FIXED_COMMAND.into(),
        max_session_secs: profile.max_session_secs,
        grant_id: uuid::Uuid::new_v4().to_string(),
        vault_role: profile.vault_role.clone(),
        vault_ca_sha256: profile.vault_ca_sha256.clone(),
        vault_token_ref: profile.vault_token_ref.clone(),
    };
    let manifest = TaskManifest {
        schema_version: 4,
        title,
        expires_in_secs,
        github_api_url: String::new(),
        vault_api_url: String::new(),
        actions: vec![TaskAction::SshHealth(action)],
    };
    manifest.validate().map_err(|_| unavailable())?;
    Ok(manifest)
}

pub fn prepare_ssh_manifest(
    manifest: &mut TaskManifest,
    profile: &TrustedSshProfile,
) -> Result<(), String> {
    manifest.validate().map_err(|_| unavailable())?;
    if !manifest.is_ssh() || manifest.actions.len() != 1 {
        return Err(unavailable());
    }
    let action = manifest.actions[0].as_ssh().ok_or_else(unavailable)?;
    validate_profile_action(action, profile)
}

fn validate_profile_action(
    action: &SshHealthAction,
    profile: &TrustedSshProfile,
) -> Result<(), String> {
    action.validate().map_err(|_| unavailable())?;
    if action.tenant != profile.tenant
        || action.profile_id != profile.profile_id
        || action.profile_sha256 != profile.digest()?
        || action.destination_host != profile.destination_host
        || action.destination_port != profile.destination_port
        || action.host_key_sha256 != profile.host_key_sha256
        || action.principal != profile.principal
        || action.login_user != profile.login_user
        || action.source_address != profile.source_address
        || action.max_session_secs != profile.max_session_secs
        || action.vault_role != profile.vault_role
        || action.vault_ca_sha256 != profile.vault_ca_sha256
        || action.vault_token_ref != profile.vault_token_ref
    {
        return Err(unavailable());
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEnvelope {
    payload: String,
    signature: String,
}

fn sign_control(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    expires_at: i64,
    operation: &str,
) -> Result<SignedEnvelope, String> {
    let payload = serde_json::to_vec(&json!({"action":operation,"manifest":action,"expires_at":expires_at,"issued_at":now_unix(),"nonce":uuid::Uuid::new_v4().to_string()})).map_err(|_| unavailable())?;
    let mut message = CONTROL_DOMAIN.to_vec();
    message.extend(&payload);
    Ok(SignedEnvelope {
        payload: STANDARD.encode(payload),
        signature: hex(&profile.signing_key()?.sign(&message).to_bytes()),
    })
}

fn verify_envelope(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    expires_at: i64,
    bytes: &[u8],
) -> Result<(Value, String), String> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(unavailable());
    }
    let envelope: SignedEnvelope = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| unavailable())?;
    if payload.len() > MAX_WIRE_BYTES {
        return Err(unavailable());
    }
    let mut message = RECEIPT_DOMAIN.to_vec();
    message.extend(&payload);
    VerifyingKey::from_bytes(&decode_hex::<32>(&profile.receipt_public_key_hex)?)
        .map_err(|_| unavailable())?
        .verify(
            &message,
            &Signature::from_bytes(&decode_hex::<64>(&envelope.signature)?),
        )
        .map_err(|_| unavailable())?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HostEnvelope {
        manifest: SshHealthAction,
        expires_at: i64,
        response: Value,
    }
    let decoded: HostEnvelope = serde_json::from_slice(&payload).map_err(|_| unavailable())?;
    if decoded.manifest != *action || decoded.expires_at != expires_at {
        return Err(unavailable());
    }
    Ok((decoded.response, sha256(bytes)))
}

async fn bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_WIRE_BYTES as u64)
    {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len() + chunk.len() > MAX_WIRE_BYTES {
            return Err(unavailable());
        }
        bytes.extend(chunk);
    }
    Ok(bytes)
}

async fn control(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    expires_at: i64,
    operation: &str,
) -> Result<(), String> {
    let envelope = sign_control(profile, action, expires_at, operation)?;
    let response = profile
        .http()?
        .post(format!(
            "{}/v1/ssh-control",
            profile.control_url.trim_end_matches('/')
        ))
        .timeout(Duration::from_secs(2))
        .json(&envelope)
        .send()
        .await
        .map_err(|_| unavailable())?;
    let bytes = bounded_response(response).await?;
    let (response, _) = verify_envelope(profile, action, expires_at, &bytes)?;
    let expected = if operation == "grant" {
        "granted"
    } else {
        "revoked"
    };
    if response.get("status").and_then(Value::as_str) != Some(expected) {
        return Err(unavailable());
    }
    Ok(())
}

pub async fn revoke_ssh_grant(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    expires_at: i64,
) -> Result<(), String> {
    validate_profile_action(action, profile)?;
    control(profile, action, expires_at, "revoke").await
}

/// Cancellation can interrupt any await, including an ACK after a grant was
/// installed. Try to close that authority; the host still bounds network loss.
struct HostGrantCleanup {
    profile: TrustedSshProfile,
    action: SshHealthAction,
    expires_at: i64,
    armed: bool,
}
impl Drop for HostGrantCleanup {
    fn drop(&mut self) {
        if self.armed
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let profile = self.profile.clone();
            let action = self.action.clone();
            let expires_at = self.expires_at;
            runtime.spawn(async move {
                let _ = control(&profile, &action, expires_at, "revoke").await;
            });
        }
    }
}

fn forced_command(action: &SshHealthAction) -> String {
    format!(
        "/usr/bin/python3 -I /opt/opaque-ssh/host_guard.py enter {}",
        action.grant_id
    )
}
fn source_cidr(action: &SshHealthAction) -> String {
    format!(
        "{}/{}",
        action.source_address,
        if action.source_address.contains(':') {
            128
        } else {
            32
        }
    )
}

fn validate_certificate(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    public: &ssh_key::PublicKey,
    expires_at: i64,
    value: &str,
) -> Result<(), String> {
    if value.len() > 16384 {
        return Err(unavailable());
    }
    let certificate =
        ssh_key::Certificate::from_openssh(value.trim()).map_err(|_| unavailable())?;
    let ca = public_key(&profile.vault_ca_public_key)?;
    certificate
        .validate_at(
            now_unix() as u64,
            [&ca.fingerprint(ssh_key::HashAlg::Sha256)],
        )
        .map_err(|_| unavailable())?;
    let expected = BTreeMap::from([
        ("force-command".into(), forced_command(action)),
        ("source-address".into(), source_cidr(action)),
    ]);
    if certificate.cert_type() != ssh_key::certificate::CertType::User
        || certificate.public_key() != public.key_data()
        || certificate.key_id() != action.grant_id
        || certificate.valid_principals() != [action.principal.clone()]
        || certificate.valid_before() > expires_at as u64
        || certificate.valid_after() < now_unix().saturating_sub(60) as u64
        || !certificate.extensions().is_empty()
        || certificate.critical_options().0 != expected
    {
        return Err(unavailable());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum SignFailure {
    Rejected,
    Unknown,
}

async fn vault_certificate(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    public: &ssh_key::PublicKey,
    expires_at: i64,
) -> Result<String, SignFailure> {
    let token = CompositeResolver::new(crate::default_secret_resolvers())
        .resolve(&profile.vault_token_ref)
        .map_err(|_| SignFailure::Rejected)?;
    token.mlock();
    request_certificate(
        profile,
        action,
        public,
        expires_at,
        token.as_str().ok_or(SignFailure::Rejected)?,
    )
    .await
}

async fn request_certificate(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    public: &ssh_key::PublicKey,
    expires_at: i64,
    token: &str,
) -> Result<String, SignFailure> {
    let ttl = expires_at - now_unix();
    if !(1..=300).contains(&ttl) {
        return Err(SignFailure::Rejected);
    }
    let response = profile.http().map_err(|_|SignFailure::Rejected)?.post(format!("{}/v1/{}/sign/{}", profile.vault_url.trim_end_matches('/'), profile.vault_mount, profile.vault_role))
        .header("X-Vault-Token", token)
        .json(&json!({"public_key":public.to_openssh().map_err(|_| SignFailure::Rejected)?,"cert_type":"user","valid_principals":action.principal,"key_id":action.grant_id,"ttl":format!("{ttl}s"),"critical_options":{"force-command":forced_command(action),"source-address":source_cidr(action)},"extensions":{}}))
        .send().await.map_err(|_| SignFailure::Unknown)?;
    if response.status().is_client_error() {
        return Err(SignFailure::Rejected);
    }
    let bytes = bounded_response(response)
        .await
        .map_err(|_| SignFailure::Unknown)?;
    let response: Value = serde_json::from_slice(&bytes).map_err(|_| SignFailure::Unknown)?;
    let certificate = response
        .get("data")
        .and_then(|data| data.get("signed_key"))
        .and_then(Value::as_str)
        .ok_or(SignFailure::Unknown)?;
    validate_certificate(profile, action, public, expires_at, certificate)
        .map_err(|_| SignFailure::Unknown)?;
    Ok(certificate.into())
}

fn outcome(state: SlotState, code: &str) -> SlotOutcome {
    SlotOutcome {
        state,
        code: code.into(),
        provider_run_id: None,
        inference_receipt: None,
        ssh_receipt: None,
    }
}

fn host_outcome(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    expires_at: i64,
    bytes: &[u8],
) -> Result<SlotOutcome, String> {
    let (response, signed_receipt_sha256) = verify_envelope(profile, action, expires_at, bytes)?;
    let receipt = response.get("receipt").ok_or_else(unavailable)?;
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(unavailable)?;
    let (code, state, outcome_code) = match status {
        "completed" => (
            SshReceiptCode::HealthObserved,
            SlotState::ApiAccepted,
            "api_accepted",
        ),
        "denied" | "failed" => (
            SshReceiptCode::Denied,
            SlotState::Rejected,
            "provider_rejected",
        ),
        "timeout" => (
            SshReceiptCode::TimedOut,
            SlotState::Unknown,
            "transport_unknown",
        ),
        "expired" => (SshReceiptCode::Expired, SlotState::Rejected, "expired"),
        "revoked" => (SshReceiptCode::Revoked, SlotState::Rejected, "revoked"),
        _ => return Err(unavailable()),
    };
    if receipt.get("grant_id").and_then(Value::as_str) != Some(&action.grant_id)
        || receipt.get("principal").and_then(Value::as_str) != Some(&action.principal)
        || receipt.get("operation").and_then(Value::as_str) != Some(SSH_FIXED_COMMAND)
    {
        return Err(unavailable());
    }
    let timestamp = |field: &str| {
        receipt
            .get(field)
            .and_then(Value::as_f64)
            .filter(|n| n.is_finite() && *n > 0.0 && *n < i64::MAX as f64)
            .map(|n| n as i64)
            .ok_or_else(unavailable)
    };
    let completed = code == SshReceiptCode::HealthObserved;
    if completed {
        let output = response
            .get("output_text")
            .and_then(Value::as_str)
            .ok_or_else(unavailable)?;
        if receipt.get("result_code").and_then(Value::as_str) != Some("ok")
            || receipt.get("status").and_then(Value::as_str) != Some("completed")
            || receipt.get("output_complete").and_then(Value::as_bool) != Some(true)
            || receipt.get("output_bytes").and_then(Value::as_u64) != Some(output.len() as u64)
            || receipt
                .get("finished_at")
                .and_then(Value::as_f64)
                .is_none_or(|time| time >= expires_at as f64)
        {
            return Err(unavailable());
        }
        let health: Value = serde_json::from_str(output).map_err(|_| unavailable())?;
        if health != json!({"service":"fixture-api", "status":"ok", "version":"1"}) {
            return Err(unavailable());
        }
    }
    let ssh = SshReceipt {
        tenant: action.tenant.clone(),
        profile_sha256: action.profile_sha256.clone(),
        grant_id: action.grant_id.clone(),
        host_key_sha256: action.host_key_sha256.clone(),
        code,
        host: action.destination_host.clone(),
        principal: action.principal.clone(),
        operation: SSH_OPERATION.into(),
        started_at: timestamp("started_at")?,
        completed_at: timestamp("finished_at")?,
        output_sha256: if completed {
            receipt
                .get("output_sha256")
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        },
        output_text: if completed {
            response
                .get("output_text")
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        },
        signed_receipt_sha256,
    };
    if ssh.completed_at > expires_at || ssh.completed_at > now_unix() + 1 {
        return Err(unavailable());
    }
    ssh.validate(action).map_err(|_| unavailable())?;
    let mut result = outcome(state, outcome_code);
    result.ssh_receipt = Some(ssh);
    Ok(result)
}

/// Killing the broker's SSH process never claims to recall a remote command.
/// The host's independently enforced deadline remains authoritative on outages.
struct SshChild {
    child: tokio::process::Child,
    pid: u32,
    completed: bool,
}
impl Drop for SshChild {
    fn drop(&mut self) {
        if !self.completed {
            unsafe {
                libc::kill(-(self.pid as i32), libc::SIGKILL);
            }
            let _ = self.child.start_kill();
        }
    }
}

fn write_private(path: &Path, value: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| unavailable())?;
    file.write_all(value).map_err(|_| unavailable())?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_profile() -> TrustedSshProfile {
    let host =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let ca =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let host_public_key = host.public_key().to_openssh().unwrap();
    let vault_ca_public_key = ca.public_key().to_openssh().unwrap();
    let receipt = SigningKey::generate(&mut rand::rngs::OsRng);
    TrustedSshProfile {
        tenant: serde_json::from_value(json!({"schema_version":1,"tenant_id":"tenant-a","broker_id":"00000000-0000-4000-8000-000000000001"})).unwrap(),
        config: SshProfileConfig {
            profile_id: "fixture-health".into(), destination_host: "192.0.2.1".into(), destination_port: 22,
            host_key_sha256: key_digest(&host_public_key).unwrap(), host_public_key,
            principal: "fixture-health".into(), login_user: "opaque".into(), source_address: "192.0.2.2".into(), max_session_secs: 30,
            vault_url: "https://vault.example.test".into(), vault_mount: "ssh".into(), vault_role: "fixture-health".into(),
            vault_token_ref: "env:VAULT_SIGNER_TOKEN".into(), vault_ca_sha256: key_digest(&vault_ca_public_key).unwrap(), vault_ca_public_key,
            control_url: "https://192.0.2.1:8443".into(), tls_ca_pem: None,
            receipt_public_key_hex: hex(&receipt.verifying_key().to_bytes()),
            grant_signing_key_path: "/nonexistent/opaque-test-grant-key".into(), allow_loopback_http: false,
        },
    }
}

pub async fn execute_ssh_action<F, Fut>(
    action: &SshHealthAction,
    profile: &TrustedSshProfile,
    expires_at: i64,
    before_dispatch: F,
) -> SlotOutcome
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<(), SlotOutcome>>,
{
    let reject = || outcome(SlotState::Rejected, "source_unavailable");
    let unknown = || outcome(SlotState::Unknown, "transport_unknown");
    if validate_profile_action(action, profile).is_err() {
        return reject();
    }
    if let Err(reason) = before_dispatch().await {
        return reason;
    }
    let key = match ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
    {
        Ok(key) => key,
        Err(_) => return reject(),
    };
    let cert = match vault_certificate(profile, action, key.public_key(), expires_at).await {
        Ok(cert) => cert,
        Err(SignFailure::Rejected) => return reject(),
        Err(SignFailure::Unknown) => return unknown(),
    };
    if let Err(reason) = before_dispatch().await {
        return reason;
    }
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(_) => return reject(),
    };
    let key_path = directory.path().join("key");
    let certificate_path = directory.path().join("key-cert.pub");
    let known_hosts = directory.path().join("known_hosts");
    let encoded = match key.to_openssh(ssh_key::LineEnding::LF) {
        Ok(key) => key,
        Err(_) => return reject(),
    };
    let known = format!("opaque-approved-host {}\n", profile.host_public_key.trim());
    if write_private(&key_path, encoded.as_bytes()).is_err()
        || write_private(&certificate_path, cert.as_bytes()).is_err()
        || write_private(&known_hosts, known.as_bytes()).is_err()
    {
        return reject();
    }
    let mut cleanup = HostGrantCleanup {
        profile: profile.clone(),
        action: action.clone(),
        expires_at,
        armed: true,
    };
    if control(profile, action, expires_at, "grant").await.is_err() {
        return unknown();
    }
    let result = run_ssh(
        profile,
        action,
        expires_at,
        &key_path,
        &certificate_path,
        &known_hosts,
        &before_dispatch,
    )
    .await;
    // Close unused authentication authority on all exits; failure never refunds.
    let _ = control(profile, action, expires_at, "revoke").await;
    cleanup.armed = false;
    result.unwrap_or_else(|_| unknown())
}

async fn run_ssh<F, Fut>(
    profile: &TrustedSshProfile,
    action: &SshHealthAction,
    expires_at: i64,
    key: &Path,
    certificate: &Path,
    known_hosts: &Path,
    check: &F,
) -> Result<SlotOutcome, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<(), SlotOutcome>>,
{
    if check().await.is_err() {
        return Err(unavailable());
    }
    let mut command = tokio::process::Command::new("/usr/bin/ssh");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .process_group(0)
        .args([
            "-F",
            "/dev/null",
            "-T",
            "-p",
            &action.destination_port.to_string(),
            "-i",
        ])
        .arg(key)
        .arg("-o")
        .arg(format!("CertificateFile={}", certificate.display()))
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .args([
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "HostKeyAlias=opaque-approved-host",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "ServerAliveInterval=1",
            "-o",
            "ServerAliveCountMax=2",
        ])
        .arg(format!("{}@{}", action.login_user, action.destination_host))
        .arg(SSH_FIXED_COMMAND);
    let child = command.spawn().map_err(|_| unavailable())?;
    let mut child = SshChild {
        pid: child.id().ok_or_else(unavailable)?,
        child,
        completed: false,
    };
    let mut stdout = child.child.stdout.take().ok_or_else(unavailable)?;
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(u64::from(action.max_session_secs) + 4);
    loop {
        if now_unix() >= expires_at
            || tokio::time::Instant::now() >= deadline
            || check().await.is_err()
        {
            return Err(unavailable());
        }
        tokio::select! {
            read = stdout.read(&mut buffer) => {
                let count = read.map_err(|_| unavailable())?;
                if count == 0 { break; }
                if bytes.len()+count > MAX_WIRE_BYTES { return Err(unavailable()); }
                bytes.extend_from_slice(&buffer[..count]);
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
    let status = tokio::time::timeout(Duration::from_secs(1), child.child.wait())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    child.completed = true;
    if check().await.is_err() {
        return Err(unavailable());
    }
    let result = host_outcome(profile, action, expires_at, &bytes)?;
    if status.success() != (result.state == SlotState::ApiAccepted) {
        return Err(unavailable());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_action(profile: &TrustedSshProfile) -> SshHealthAction {
        let principal: PrincipalContext = serde_json::from_value(json!({
            "sub":"hum_00000000000000000000000000000001", "sub_label":"fixture",
            "sub_roles":[], "act":"agt_00000000000000000000000000000001", "act_label":"fixture",
            "mode":"delegated", "jti":"test-session"
        }))
        .unwrap();
        let client = ClientIdentity {
            uid: 1000,
            gid: 1000,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        };
        health_manifest(
            profile,
            "Read fixture health".into(),
            60,
            &principal,
            &client,
        )
        .unwrap()
        .actions[0]
            .as_ssh()
            .unwrap()
            .clone()
    }

    fn signed_response(
        profile: &mut TrustedSshProfile,
        action: &SshHealthAction,
        expiry: i64,
        response: Value,
    ) -> Vec<u8> {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        profile.config.receipt_public_key_hex = hex(&key.verifying_key().to_bytes());
        let payload =
            serde_json::to_vec(&json!({"manifest":action,"expires_at":expiry,"response":response}))
                .unwrap();
        let mut message = RECEIPT_DOMAIN.to_vec();
        message.extend(&payload);
        serde_json::to_vec(&SignedEnvelope {
            payload: STANDARD.encode(payload),
            signature: hex(&key.sign(&message).to_bytes()),
        })
        .unwrap()
    }

    #[test]
    fn host_evidence_rejects_tamper_cross_grant_truncated_output_and_expired_success() {
        let mut profile = test_profile();
        let action = test_action(&profile);
        let now = now_unix();
        let expiry = now + 60;
        let output = "{\"service\":\"fixture-api\",\"status\":\"ok\",\"version\":\"1\"}\n";
        let response = json!({"status":"completed", "output_text":output, "receipt":{
            "grant_id":action.grant_id,"principal":action.principal,"operation":SSH_FIXED_COMMAND,
            "host":"fixture-a", "status":"completed", "result_code":"ok", "started_at":now-1,
            "finished_at":now, "output_sha256":sha256(output.as_bytes()),"output_bytes":output.len(),"output_complete":true
        }});
        let bytes = signed_response(&mut profile, &action, expiry, response.clone());
        let result = host_outcome(&profile, &action, expiry, &bytes).unwrap();
        assert_eq!(result.state, SlotState::ApiAccepted);
        let mut other = action.clone();
        other.grant_id = uuid::Uuid::new_v4().to_string();
        assert!(host_outcome(&profile, &other, expiry, &bytes).is_err());
        assert!(host_outcome(&profile, &action, expiry + 1, &bytes).is_err());
        let mut envelope: Value = serde_json::from_slice(&bytes).unwrap();
        envelope["signature"] = "0".repeat(128).into();
        assert!(
            host_outcome(
                &profile,
                &action,
                expiry,
                &serde_json::to_vec(&envelope).unwrap()
            )
            .is_err()
        );
        for (field, value) in [
            ("output_complete", json!(false)),
            ("output_bytes", json!(1)),
            ("output_sha256", json!("a".repeat(64))),
            ("finished_at", json!(expiry as f64 + 0.1)),
        ] {
            let mut invalid = response.clone();
            invalid["receipt"][field] = value;
            let bytes = signed_response(&mut profile, &action, expiry, invalid);
            assert!(
                host_outcome(&profile, &action, expiry, &bytes).is_err(),
                "accepted {field}"
            );
        }
        let mut invalid = response;
        invalid["output_text"] = "healthy".into();
        let bytes = signed_response(&mut profile, &action, expiry, invalid);
        assert!(host_outcome(&profile, &action, expiry, &bytes).is_err());
    }

    #[test]
    fn certificate_must_have_exact_pinned_ca_key_principal_lifetime_and_controls() {
        let mut profile = test_profile();
        let ca = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let subject =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        profile.config.vault_ca_public_key = ca.public_key().to_openssh().unwrap();
        profile.config.vault_ca_sha256 = key_digest(&profile.vault_ca_public_key).unwrap();
        let action = test_action(&profile);
        let now = now_unix();
        let expiry = now + 60;
        for case in [
            "valid",
            "principal",
            "command",
            "source",
            "extension",
            "expiry",
            "key_id",
            "host_type",
            "empty_principals",
        ] {
            let mut builder = ssh_key::certificate::Builder::new(
                vec![42; 16],
                subject.public_key().key_data().clone(),
                (now - 1) as u64,
                (if case == "expiry" { expiry + 1 } else { expiry }) as u64,
            )
            .unwrap();
            builder
                .key_id(if case == "key_id" {
                    "other"
                } else {
                    &action.grant_id
                })
                .unwrap();
            builder
                .cert_type(if case == "host_type" {
                    ssh_key::certificate::CertType::Host
                } else {
                    ssh_key::certificate::CertType::User
                })
                .unwrap();
            if case == "empty_principals" {
                builder.all_principals_valid().unwrap();
            } else {
                builder
                    .valid_principal(if case == "principal" {
                        "other"
                    } else {
                        &action.principal
                    })
                    .unwrap();
            }
            builder
                .critical_option(
                    "force-command",
                    if case == "command" {
                        "id".into()
                    } else {
                        forced_command(&action)
                    },
                )
                .unwrap();
            builder
                .critical_option(
                    "source-address",
                    if case == "source" {
                        "0.0.0.0/0".into()
                    } else {
                        source_cidr(&action)
                    },
                )
                .unwrap();
            if case == "extension" {
                builder.extension("permit-pty", "").unwrap();
            }
            let cert = builder.sign(&ca).unwrap().to_openssh().unwrap();
            let result =
                validate_certificate(&profile, &action, subject.public_key(), expiry, &cert);
            assert_eq!(result.is_ok(), case == "valid", "{case}");
            if case == "valid" {
                let foreign = test_profile();
                assert!(
                    validate_certificate(&foreign, &action, subject.public_key(), expiry, &cert)
                        .is_err()
                );
                assert!(
                    validate_certificate(&profile, &action, ca.public_key(), expiry, &cert)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn trusted_profile_and_action_cannot_redirect_authority() {
        let profile = test_profile();
        let action = test_action(&profile);
        validate_profile_action(&action, &profile).unwrap();
        for field in [
            "destination_host",
            "principal",
            "vault_role",
            "vault_token_ref",
        ] {
            let mut value = serde_json::to_value(&action).unwrap();
            value[field] = (match field {
                "destination_host" => "192.0.2.3",
                "vault_token_ref" => "env:OTHER_TOKEN",
                _ => "other",
            })
            .into();
            let changed = serde_json::from_value(value).unwrap();
            assert!(
                validate_profile_action(&changed, &profile).is_err(),
                "accepted {field}"
            );
        }
        for url in [
            "http://vault.example.test",
            "https://user@vault.example.test",
            "https://vault.example.test/path",
            "https://vault.example.test/?token=x",
        ] {
            let mut changed = profile.clone();
            changed.config.vault_url = url.into();
            assert!(changed.validate().is_err());
        }
        let mut changed = profile.clone();
        changed.config.allow_loopback_http = true;
        changed.config.vault_url = "http://127.0.0.1:1234".into();
        changed.validate().unwrap();
        changed.config.vault_url = "http://192.0.2.1".into();
        assert!(changed.validate().is_err());
    }

    #[tokio::test]
    async fn rejected_dispatch_has_no_signer_or_host_effects() {
        let server = wiremock::MockServer::start().await;
        let mut profile = test_profile();
        profile.config.allow_loopback_http = true;
        profile.config.vault_url = server.uri();
        profile.config.control_url = server.uri();
        let action = test_action(&profile);
        let result = execute_ssh_action(&action, &profile, now_unix() + 60, || async {
            Err(outcome(SlotState::Rejected, "revoked"))
        })
        .await;
        assert_eq!(result.code, "revoked");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn lost_signer_response_is_unknown_and_never_contacts_host_control() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let host = wiremock::MockServer::start().await;
        let mut profile = test_profile();
        profile.config.allow_loopback_http = true;
        profile.config.vault_url = url;
        profile.config.control_url = host.uri();
        let action = test_action(&profile);
        let subject =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let count = stream.read(&mut request).await.unwrap();
            assert!(
                String::from_utf8_lossy(&request[..count])
                    .starts_with("POST /v1/ssh/sign/fixture-health ")
            );
            // Signing may have succeeded; its promised response is truncated.
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{").await.unwrap();
        });
        assert_eq!(
            request_certificate(
                &profile,
                &action,
                subject.public_key(),
                now_unix() + 60,
                "fixture-only-token"
            )
            .await
            .unwrap_err(),
            SignFailure::Unknown
        );
        accepted.await.unwrap();
        assert!(host.received_requests().await.unwrap().is_empty());
    }

    /// Invoked only by the disposable Vault/OpenSSH runner. This uses synthetic
    /// identity and a test authorization callback, never production approval.
    #[tokio::test]
    #[ignore = "requires scripts/ssh_vault_dogfood.py private disposable services"]
    async fn live_vault_host_execution() {
        #[derive(Deserialize)]
        struct LiveProfile {
            tenant: TenantBinding,
            #[serde(flatten)]
            config: SshProfileConfig,
        }
        let path = std::env::var("OPAQUE_SSH_LIVE_PROFILE").expect("private fixture profile path");
        let input: LiveProfile = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let profile = input
            .config
            .bind(&input.tenant)
            .expect("valid private fixture profile");
        if let Ok(output) = std::env::var("OPAQUE_SSH_LIVE_PREPARE") {
            std::fs::write(
                output,
                serde_json::to_vec(&json!({"profile_sha256":profile.digest().unwrap()})).unwrap(),
            )
            .unwrap();
            return;
        }
        let action = test_action(&profile);
        let expiry = now_unix() + 60;
        let result = execute_ssh_action(&action, &profile, expiry, || async { Ok(()) }).await;
        assert_eq!(
            result.state,
            SlotState::ApiAccepted,
            "broker execution outcome: {}",
            result.code
        );
        assert_eq!(
            result.ssh_receipt.as_ref().unwrap().code,
            SshReceiptCode::HealthObserved
        );
        let replay = execute_ssh_action(&action, &profile, expiry, || async { Ok(()) }).await;
        assert_ne!(
            replay.state,
            SlotState::ApiAccepted,
            "single-use grant executed again"
        );
        if let Ok(path) = std::env::var("OPAQUE_SSH_LIVE_RESULT") {
            std::fs::write(path,serde_json::to_vec(&json!({"broker_health_observed":true,"grant_replay_denied":true,"receipt":result.ssh_receipt})).unwrap()).unwrap();
        }
    }
}
