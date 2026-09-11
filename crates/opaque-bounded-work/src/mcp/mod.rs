//! Signed registry admission and permanently charged, single-attempt MCP calls.
//! No server-supplied text crosses this boundary; receipts report evidence only.
pub mod store;
pub mod transport;

use opaque_core::{
    bundle,
    mcp::{PreparedCall, Registry},
    tenant::TenantBinding,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub fn unavailable() -> String {
    "MCP invocation unavailable; inspect its receipt before creating new work".into()
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn digest(value: &impl Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("MCP JSON serializes"))
    )
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bundle_path: PathBuf,
    pub org: String,
    pub trust_anchors: Vec<String>,
    /// Lookup values are private broker-owned files, never agent bearer tokens.
    pub credentials: BTreeMap<String, PathBuf>,
    /// Explicit disposable HTTP fixture only. Daemon additionally requires its
    /// insecure test approval backend and startup opt-in; never production.
    #[serde(default)]
    pub fixture_origin: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallInput {
    pub invocation_id: String,
    pub route: String,
    pub arguments: serde_json::Map<String, serde_json::Value>,
    pub expires_in_secs: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub invocation_id: String,
    pub call: PreparedCall,
    pub registry_org: String,
    pub registry_version: u64,
    pub registry_digest: String,
    pub registry_expires_at: i64,
    pub tenant: Option<TenantBinding>,
    pub credential_ref: String,
    pub expires_at: i64,
    pub fixture_origin: Option<String>,
    pub policy_digest: String,
    /// Verified peer, principal/session, client type and workspace at review.
    pub request_context_digest: String,
}
impl Action {
    pub fn digest(&self) -> String {
        digest(self)
    }
    pub fn target(&self) -> HashMap<String, String> {
        let route = self.call.route();
        let mut target = HashMap::from([
            ("invocation_id".into(), self.invocation_id.clone()),
            ("route".into(), route.alias.clone()),
            ("server_id".into(), route.server_id.clone()),
            (
                "endpoint".into(),
                format!("https://{}{}", route.endpoint.host, route.endpoint.path),
            ),
            ("tool".into(), route.tool.clone()),
            ("protocol_version".into(), route.protocol_version.clone()),
            ("policy_digest".into(), self.policy_digest.clone()),
            (
                "request_context_digest".into(),
                self.request_context_digest.clone(),
            ),
            ("registry_digest".into(), self.registry_digest.clone()),
            ("registry_version".into(), self.registry_version.to_string()),
            ("schema_digest".into(), digest(&route.input_schema)),
            (
                "arguments".into(),
                serde_json::to_string(self.call.arguments()).expect("arguments serialize"),
            ),
            ("output_policy".into(), route.output_policy.as_str().into()),
            ("credential_ref".into(), self.credential_ref.clone()),
            (
                "max_request_bytes".into(),
                route.max_request_bytes.to_string(),
            ),
            (
                "max_response_bytes".into(),
                route.max_response_bytes.to_string(),
            ),
            ("timeout_ms".into(), route.timeout_ms.to_string()),
            ("expires_at".into(), self.expires_at.to_string()),
            ("attempt_limit".into(), "1".into()),
            (
                "fixture_origin".into(),
                self.fixture_origin
                    .clone()
                    .unwrap_or_else(|| "disabled".into()),
            ),
        ]);
        if route.upstream_input_schema.is_some() {
            target.insert(
                "upstream_schema_digest".into(),
                digest(route.upstream_schema()),
            );
        }
        if let Some(projection) = &route.output_projection {
            target.insert("output_projection_digest".into(), digest(projection));
            target.insert(
                "output_projection".into(),
                serde_json::to_string(projection).expect("projection serializes"),
            );
        }
        target
    }
}

/// The durable receipt is always available to its owner. Projected values are
/// ephemeral and only emitted with a current disclosure authorization; receipt
/// reads never replay them. Debug intentionally omits these potentially sensitive values.
#[derive(Serialize)]
pub struct InvocationResult {
    pub receipt: store::Receipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<&'static str>,
}
impl std::ops::Deref for InvocationResult {
    type Target = store::Receipt;
    fn deref(&self) -> &Self::Target {
        &self.receipt
    }
}
impl std::fmt::Debug for InvocationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvocationResult")
            .field("receipt", &self.receipt)
            .field("disclosure", &self.disclosure)
            .finish_non_exhaustive()
    }
}
impl InvocationResult {
    pub fn has_disclosable_values(&self) -> bool {
        self.output.is_some()
            || self.receipt.response_sha256.is_some()
            || self.receipt.response_bytes.is_some()
    }
    pub fn withhold_authority_changed(&mut self) {
        self.output = None;
        self.receipt.response_sha256 = None;
        self.receipt.response_bytes = None;
        self.disclosure = Some("withheld_authority_changed");
    }
}

pub struct Gateway {
    config: Config,
    pub ledger: store::Ledger,
    tenant: Option<TenantBinding>,
}
impl Gateway {
    pub fn fixture_only(&self) -> bool {
        self.config.fixture_origin.is_some()
    }
    pub fn new(
        config: Config,
        path: &Path,
        tenant: Option<TenantBinding>,
        fixture_allowed: bool,
    ) -> Result<Self, String> {
        if config.fixture_origin.is_some() && !fixture_allowed {
            return Err(unavailable());
        }
        if let Some(origin) = &config.fixture_origin {
            transport::validate_fixture_origin(origin)?;
        }
        if !config.bundle_path.is_absolute()
            || config.credentials.is_empty()
            || config.credentials.len() > 128
            || config
                .credentials
                .values()
                .any(|p| !p.is_absolute() || p.to_str().is_none())
        {
            return Err(unavailable());
        }
        let gateway = Self {
            config,
            ledger: store::Ledger::open(path)?,
            tenant,
        };
        gateway.registry()?;
        Ok(gateway)
    }
    fn registry(&self) -> Result<(Registry, bundle::VerifiedBundle), String> {
        let bytes = private_read(&self.config.bundle_path, 2 * 1024 * 1024, false)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| unavailable())?;
        let anchors = self
            .config
            .trust_anchors
            .iter()
            .map(|s| bundle::parse_anchor(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| unavailable())?;
        let signed = bundle::verify_bundle(text, &anchors, now()).map_err(|_| unavailable())?;
        if signed.payload.org != self.config.org
            || signed.payload.issued_at > now()
            || signed.payload.expires_at.is_none()
        {
            return Err(unavailable());
        }
        let registry = Registry::from_document(
            signed
                .payload
                .mcp_registry
                .as_ref()
                .ok_or_else(unavailable)?,
        )
        .map_err(|_| unavailable())?;
        if registry
            .routes()
            .iter()
            .any(|r| !self.config.credentials.contains_key(&r.credential_binding))
        {
            return Err(unavailable());
        }
        self.ledger.apply_registry(&signed)?;
        Ok((registry, signed))
    }
    pub fn catalog(&self) -> Result<serde_json::Value, String> {
        let (registry, signed) = self.registry()?;
        let tools:Vec<_>=registry.routes().into_iter().map(|r| { let mut entry = serde_json::json!({
            "name":format!("opaque_mcp_tool_{}",r.alias),"description":"One broker-approved invocation; arbitrary upstream output is withheld. Reuse the invocation ID only to inspect its receipt, never to retry.",
            "inputSchema":{"type":"object","additionalProperties":false,"required":["invocation_id","arguments","expires_in_secs"],"properties":{
                "invocation_id":{"type":"string","minLength":36,"maxLength":36},"expires_in_secs":{"type":"integer","minimum":1,"maximum":300},"arguments":r.input_schema.clone()}},
            "route":r.alias,"registry_digest":signed.digest,
            "secret_ref":format!("file:{}",self.config.credentials[&r.credential_binding].display()),
            "policy_target":{"route":r.alias,"server_id":r.server_id,"endpoint":format!("https://{}{}",r.endpoint.host,r.endpoint.path),"tool":r.tool,"protocol_version":r.protocol_version,"registry_digest":signed.digest,"registry_version":signed.payload.version.to_string(),"schema_digest":digest(&r.input_schema),"output_policy":r.output_policy.as_str(),"credential_ref":format!("file:{}",self.config.credentials[&r.credential_binding].display()),"max_request_bytes":r.max_request_bytes.to_string(),"max_response_bytes":r.max_response_bytes.to_string(),"timeout_ms":r.timeout_ms.to_string(),"attempt_limit":"1","fixture_origin":self.config.fixture_origin.clone().unwrap_or_else(||"disabled".into())}
        });
        if r.upstream_input_schema.is_some() {
            entry["policy_target"]["upstream_schema_digest"] = serde_json::json!(digest(r.upstream_schema()));
        }
        if let Some(projection) = &r.output_projection {
            entry["policy_target"]["output_projection_digest"] = serde_json::json!(digest(projection));
            entry["policy_target"]["output_projection"] = serde_json::json!(serde_json::to_string(projection).expect("projection serializes"));
        }
        entry
        }).collect();
        Ok(serde_json::json!({"tools":tools}))
    }
    pub fn prepare(&self, input: CallInput) -> Result<Action, String> {
        if !uuid::Uuid::parse_str(&input.invocation_id)
            .is_ok_and(|id| id.to_string() == input.invocation_id)
            || !(1..=300).contains(&input.expires_in_secs)
        {
            return Err(unavailable());
        }
        let (registry, signed) = self.registry()?;
        let call = registry
            .prepare_json(
                &serde_json::to_vec(
                    &serde_json::json!({"route":input.route,"arguments":input.arguments}),
                )
                .map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?;
        let expires = signed.payload.expires_at.ok_or_else(unavailable)?;
        let credential_ref = format!(
            "file:{}",
            self.config.credentials[&call.route().credential_binding]
                .to_str()
                .ok_or_else(unavailable)?
        );
        Ok(Action {
            invocation_id: input.invocation_id,
            call,
            registry_org: signed.payload.org,
            registry_version: signed.payload.version,
            registry_digest: signed.digest,
            registry_expires_at: expires,
            tenant: self.tenant.clone(),
            credential_ref,
            expires_at: expires.min(now() + input.expires_in_secs as i64),
            fixture_origin: self.config.fixture_origin.clone(),
            policy_digest: String::new(),
            request_context_digest: String::new(),
        })
    }
    pub fn revalidate(&self, action: &Action) -> Result<(), String> {
        let (registry, signed) = self.registry()?;
        if now() >= action.expires_at
            || signed.digest != action.registry_digest
            || signed.payload.org != action.registry_org
            || signed.payload.version != action.registry_version
            || signed.payload.expires_at != Some(action.registry_expires_at)
            || action.expires_at > action.registry_expires_at
            || self.tenant != action.tenant
            || self.config.fixture_origin != action.fixture_origin
        {
            return Err(unavailable());
        }
        let current=registry.prepare_json(&serde_json::to_vec(&serde_json::json!({"route":action.call.route().alias,"arguments":action.call.arguments()})).map_err(|_|unavailable())?).map_err(|_|unavailable())?;
        let credential_ref = format!(
            "file:{}",
            self.config
                .credentials
                .get(&current.route().credential_binding)
                .and_then(|p| p.to_str())
                .ok_or_else(unavailable)?
        );
        if current != action.call || credential_ref != action.credential_ref {
            return Err(unavailable());
        }
        Ok(())
    }
    pub async fn execute<F, Fut, G>(
        &self,
        owner: &str,
        action: &Action,
        before_call: F,
        mut final_authority: G,
    ) -> Result<InvocationResult, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
        G: FnMut(&mut dyn FnMut() -> Result<(), String>) -> Result<(), String>,
    {
        self.revalidate(action)?;
        self.ledger.reserve(owner, action)?;
        let _guard = self.ledger.guard(owner, &action.invocation_id);
        let result = async {
            final_authority(&mut || {
                self.revalidate(action)?;
                self.ledger.authorize_dispatch(owner, action)
            })?;
            let path = action
                .credential_ref
                .strip_prefix("file:")
                .ok_or_else(unavailable)?;
            let bytes = private_read(Path::new(path), 8192, true)?;
            let credential = std::str::from_utf8(&bytes).map_err(|_| unavailable())?;
            if credential.is_empty() || !credential.bytes().all(|b| (b'!'..=b'~').contains(&b)) {
                return Err(unavailable());
            }
            Ok(transport::execute(
                &action.call,
                credential,
                || async {
                    before_call().await?;
                    final_authority(&mut || {
                        self.revalidate(action)?;
                        self.ledger.authorize_dispatch(owner, action)
                    })
                },
                action.fixture_origin.as_deref(),
            )
            .await)
        }
        .await;
        let outcome = result.unwrap_or_else(|_| {
            transport::Outcome::rejected("admission_or_credential_unavailable")
        });
        let receipt = self.ledger.finish(owner, action, &outcome)?;
        let mut result = InvocationResult {
            receipt,
            output: outcome.output,
            disclosure: outcome.disclosure,
        };
        if result.has_disclosable_values()
            && final_authority(&mut || {
                self.revalidate(action)?;
                if result.output.is_some() {
                    self.ledger.authorize_disclosure(owner, action)
                } else {
                    self.ledger.authorize_result(owner, action)
                }
            })
            .is_err()
        {
            result.withhold_authority_changed();
        }
        Ok(result)
    }
}

/// Never follow links/special files or read unbounded credential material.
fn private_read(path: &Path, limit: usize, secret: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| unavailable())?;
    let m = file.metadata().map_err(|_| unavailable())?;
    if !m.is_file()
        || m.nlink() != 1
        || m.len() > limit as u64
        || (secret && (m.mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() }))
    {
        return Err(unavailable());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > limit {
        return Err(unavailable());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
