//! Operation registry, request envelope, and client identity types.
//!
//! Every valid operation in AgentPass is registered here with its safety class
//! and required approval factors. The [`OperationRequest`] is the canonical
//! envelope that flows through the entire enforcement funnel.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Safety classification
// ---------------------------------------------------------------------------

/// Safety classification for an operation.
///
/// Determines what kinds of clients may invoke the operation and what
/// sanitization rules apply to the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationSafety {
    /// Uses secrets internally but cannot return them.
    /// Example: `github.set_actions_secret`.
    Safe,

    /// May return credential-like material in the response.
    /// Disabled for LLM/agent clients by default.
    /// Example: `ecr:GetAuthorizationToken`.
    SensitiveOutput,

    /// Explicitly returns plaintext secret values.
    /// Never exposed to MCP/agent clients.
    /// Example: debug/admin "reveal secret" (human-only, if ever).
    Reveal,
}

impl fmt::Display for OperationSafety {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Safe => write!(f, "SAFE"),
            Self::SensitiveOutput => write!(f, "SENSITIVE_OUTPUT"),
            Self::Reveal => write!(f, "REVEAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Approval factors and requirements
// ---------------------------------------------------------------------------

/// A single approval factor that can satisfy an approval requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalFactor {
    /// Native OS biometric/password prompt (macOS LocalAuthentication, Linux polkit).
    LocalBio,

    /// Second-device approval via paired iOS device (Face ID).
    IosFaceId,

    /// Hardware security key or passkey (FIDO2/WebAuthn).
    Fido2,
}

impl fmt::Display for ApprovalFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalBio => write!(f, "local_bio"),
            Self::IosFaceId => write!(f, "ios_faceid"),
            Self::Fido2 => write!(f, "fido2"),
        }
    }
}

/// When approval is required for an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    /// Approval is required every time.
    Always,

    /// Approval is required only on first use for a (client, operation, target) tuple.
    /// Subsequent uses within the lease TTL are allowed without re-approval.
    FirstUse,

    /// No approval is required (safe introspection operations).
    Never,
}

// ---------------------------------------------------------------------------
// Operation definition & registry
// ---------------------------------------------------------------------------

/// A registered operation definition.
///
/// Each operation known to the daemon has exactly one of these in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationDef {
    /// Canonical operation name, e.g. `"github.set_actions_secret"`.
    pub name: String,

    /// Safety classification.
    pub safety: OperationSafety,

    /// Default approval requirement for this operation.
    /// Policy rules may override this to be stricter, never weaker.
    pub default_approval: ApprovalRequirement,

    /// Default set of acceptable approval factors.
    /// Policy rules may require additional factors.
    pub default_factors: Vec<ApprovalFactor>,

    /// Human-readable description shown in audit logs and approval prompts.
    pub description: String,
}

/// Error returned by [`OperationRegistry`] methods.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistryError {
    #[error("operation already registered: {0}")]
    AlreadyRegistered(String),

    #[error("unknown operation: {0}")]
    UnknownOperation(String),
}

/// Central registry of all valid operations.
///
/// Operations must be registered at daemon startup before any requests are
/// processed. The registry is immutable after initialization.
#[derive(Debug, Clone)]
pub struct OperationRegistry {
    ops: HashMap<String, OperationDef>,
}

impl OperationRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            ops: HashMap::new(),
        }
    }

    /// Register an operation definition. Returns an error if the name is
    /// already registered.
    pub fn register(&mut self, def: OperationDef) -> Result<(), RegistryError> {
        if self.ops.contains_key(&def.name) {
            return Err(RegistryError::AlreadyRegistered(def.name.clone()));
        }
        self.ops.insert(def.name.clone(), def);
        Ok(())
    }

    /// Look up an operation by name.
    pub fn get(&self, name: &str) -> Result<&OperationDef, RegistryError> {
        self.ops
            .get(name)
            .ok_or_else(|| RegistryError::UnknownOperation(name.to_owned()))
    }

    /// Iterate over all registered operations.
    pub fn iter(&self) -> impl Iterator<Item = &OperationDef> {
        self.ops.values()
    }

    /// Number of registered operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

impl Default for OperationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Client identity
// ---------------------------------------------------------------------------

/// Verified identity of a connecting client, derived from OS-level peer
/// credentials and executable introspection.
///
/// All fields except the raw secret-adjacent data implement `Debug` and
/// `Display` safely.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Unix UID of the connecting process.
    pub uid: u32,

    /// Unix GID of the connecting process.
    pub gid: u32,

    /// PID of the connecting process (may be `None` on some platforms).
    pub pid: Option<i32>,

    /// Filesystem path to the executable.
    pub exe_path: Option<PathBuf>,

    /// SHA-256 digest of the executable binary (hex-encoded).
    pub exe_sha256: Option<String>,

    /// macOS code signature Team ID, if available.
    pub codesign_team_id: Option<String>,
}

// Custom Debug that never leaks anything unexpected.
impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("pid", &self.pid)
            .field("exe_path", &self.exe_path)
            .field(
                "exe_sha256",
                &self.exe_sha256.as_deref().map(|h| {
                    if h.len() > 16 {
                        format!("{}...", &h[..16])
                    } else {
                        h.to_owned()
                    }
                }),
            )
            .field("codesign_team_id", &self.codesign_team_id)
            .finish()
    }
}

impl fmt::Display for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "uid={} gid={}", self.uid, self.gid)?;
        if let Some(pid) = self.pid {
            write!(f, " pid={pid}")?;
        }
        if let Some(ref exe) = self.exe_path {
            write!(f, " exe={}", exe.display())?;
        }
        if let Some(ref team) = self.codesign_team_id {
            write!(f, " team={team}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Client type (derived from identity + policy)
// ---------------------------------------------------------------------------

/// The type of client making the request, inferred from policy/identity.
/// Determines what operations are permissible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    /// A human-operated CLI client.
    Human,

    /// An LLM/agent tool (MCP server, Codex tool, etc.).
    Agent,
}

// ---------------------------------------------------------------------------
// Operation request envelope
// ---------------------------------------------------------------------------

/// The canonical request envelope that flows through the entire enforcement
/// funnel. Every field is set before the request enters the enclave.
#[derive(Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    /// Unique request identifier (UUID v4).
    pub request_id: Uuid,

    /// Verified client identity (populated by the daemon, not the client).
    pub client_identity: ClientIdentity,

    /// Inferred client type.
    pub client_type: ClientType,

    /// Canonical operation name (e.g. `"github.set_actions_secret"`).
    pub operation: String,

    /// Operation-specific target fields (repo, cluster, namespace, etc.).
    /// Stored as a flat string map for policy matching.
    pub target: HashMap<String, String>,

    /// Names of secrets referenced by this operation (not values).
    pub secret_ref_names: Vec<String>,

    /// When this request was created (daemon-side).
    pub created_at: SystemTime,

    /// When this request expires (for timeout/lease purposes).
    pub expires_at: Option<SystemTime>,

    /// Operation-specific parameters (non-secret).
    pub params: serde_json::Value,
}

// Custom Debug to avoid any accidental secret leakage.
impl fmt::Debug for OperationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationRequest")
            .field("request_id", &self.request_id)
            .field("client_identity", &self.client_identity)
            .field("client_type", &self.client_type)
            .field("operation", &self.operation)
            .field("target", &self.target)
            .field("secret_ref_names", &self.secret_ref_names)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            // Deliberately omit params to avoid logging secret-adjacent data.
            .field("params", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = OperationRegistry::new();
        reg.register(OperationDef {
            name: "github.set_actions_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Actions secret".into(),
        })
        .unwrap();

        assert_eq!(reg.len(), 1);
        let def = reg.get("github.set_actions_secret").unwrap();
        assert_eq!(def.safety, OperationSafety::Safe);
    }

    #[test]
    fn registry_rejects_duplicate() {
        let mut reg = OperationRegistry::new();
        let def = OperationDef {
            name: "test.op".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Never,
            default_factors: vec![],
            description: "test".into(),
        };
        reg.register(def.clone()).unwrap();
        assert!(reg.register(def).is_err());
    }

    #[test]
    fn registry_unknown_operation() {
        let reg = OperationRegistry::new();
        assert!(reg.get("nope").is_err());
    }

    #[test]
    fn client_identity_debug_truncates_hash() {
        let id = ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(12345),
            exe_path: Some("/usr/bin/test".into()),
            exe_sha256: Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into()),
            codesign_team_id: None,
        };
        let dbg = format!("{id:?}");
        // The full hash should NOT appear in debug output.
        assert!(!dbg.contains("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"));
        assert!(dbg.contains("abcdef0123456789..."));
    }

    #[test]
    fn operation_request_debug_redacts_params() {
        let req = OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: ClientType::Agent,
            operation: "test.op".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({"secret": "super_secret_value"}),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("super_secret_value"));
        assert!(dbg.contains("<redacted>"));
    }
}
