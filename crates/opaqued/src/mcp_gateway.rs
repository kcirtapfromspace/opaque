//! Daemon-only composition for third-party MCP. Clients supply an alias and
//! arguments; signed registry, custody, policy and peer identity supply authority.
use super::*;
use opaque_bounded_work::mcp::{CallInput, Gateway};
use opaque_core::operation::WorkspaceContext;

pub fn initialize(
    config: &DaemonConfig,
    state_dir: &Path,
    tenant: Option<opaque_core::tenant::TenantBinding>,
) -> std::io::Result<Option<Arc<Gateway>>> {
    let Some(mcp) = config.mcp.clone() else {
        return Ok(None);
    };
    let fixture = config.approval_backend.as_deref() == Some("insecure_auto_approve")
        && std::env::var("OPAQUE_INSECURE_AUTO_APPROVE").as_deref() == Ok("1");
    if fixture && mcp.fixture_origin.is_none() {
        return Err(std::io::Error::other(
            "MCP insecure approval is limited to explicit loopback fixtures",
        ));
    }
    if !fixture
        && (!config.trust_domain.enforce
            || !config.require_seal
            || tenant.is_none()
            || !config.enforce_agent_sessions
            || !config
                .identity
                .as_ref()
                .is_some_and(|i| i.required && !i.allowed_subjects.is_empty()))
    {
        return Err(std::io::Error::other(
            "MCP production requires sealed isolated tenant custody and required delegated identity",
        ));
    }
    if mcp.credentials.values().any(|p| {
        !p.starts_with(state_dir)
            || p.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
    }) {
        return Err(std::io::Error::other(
            "MCP credential files must remain inside broker state custody",
        ));
    }
    for path in mcp.credentials.values() {
        validate_path_chain(path)?;
    }
    Gateway::new(mcp, &state_dir.join("mcp-invocations.db"), tenant, fixture)
        .map(Arc::new)
        .map(Some)
        .map_err(std::io::Error::other)
}

pub async fn handle(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
    workspace: Result<Option<WorkspaceContext>, String>,
) -> Response {
    let result = inner(
        state,
        &req,
        identity,
        client_type,
        session_id,
        principal,
        workspace,
    )
    .await;
    match result {
        Ok(value) => Response::ok(req.id, value),
        Err(_) => Response::err(
            Some(req.id),
            "mcp_unavailable",
            "MCP invocation unavailable; inspect the invocation receipt before creating new work",
        ),
    }
}
fn base(
    identity: &ClientIdentity,
    client_type: ClientType,
    principal: Option<PrincipalContext>,
) -> OperationRequest {
    OperationRequest {
        request_id: uuid::Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        principal,
        operation: "mcp.call".into(),
        target: HashMap::new(),
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: serde_json::Value::Null,
        workspace: None,
    }
}
async fn inner(
    state: &DaemonState,
    req: &Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
    workspace: Result<Option<WorkspaceContext>, String>,
) -> Result<serde_json::Value, String> {
    let Some(gateway) = &state.mcp else {
        if req.method == "mcp_catalog" {
            return Ok(serde_json::json!({"tools":[]}));
        }
        return Err("disabled".into());
    };
    let owner = state
        .tenant
        .as_ref()
        .map(|tenant| tenant.owner_key(identity.uid, principal.as_ref().map(|p| &p.sub)))
        .unwrap_or_else(|| match &principal {
            Some(p) => format!("uid:{}:sub:{}", identity.uid, p.sub.as_str()),
            None => format!("uid:{}", identity.uid),
        });
    if req.method == "mcp_catalog" {
        if !req.params.as_object().is_some_and(|m| m.is_empty()) {
            return Err("invalid catalog".into());
        }
        let mut catalog = gateway.catalog()?;
        if let Some(tools) = catalog
            .get_mut("tools")
            .and_then(serde_json::Value::as_array_mut)
        {
            tools.retain(|tool| {
                let mut request = base(identity, client_type, principal.clone());
                request.target =
                    serde_json::from_value(tool["policy_target"].clone()).unwrap_or_default();
                request.secret_ref_names = tool["secret_ref"]
                    .as_str()
                    .map(|s| vec![s.to_owned()])
                    .unwrap_or_default();
                state.enclave.mcp_route_allowed(&request)
            });
        }
        return Ok(catalog);
    }
    if matches!(req.method.as_str(), "mcp_get" | "mcp_revoke") {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reference {
            invocation_id: String,
        }
        let reference: Reference =
            serde_json::from_value(req.params.clone()).map_err(|_| "invalid reference")?;
        let receipt = if req.method == "mcp_revoke" {
            gateway.ledger.revoke(&owner, &reference.invocation_id)?
        } else {
            gateway.ledger.get(&owner, &reference.invocation_id)?
        };
        return Ok(serde_json::json!({"receipt":receipt}));
    }
    let mut params = req.params.clone();
    if let Some(map) = params.as_object_mut() {
        map.remove("workspace");
    }
    let input: CallInput = serde_json::from_value(params).map_err(|_| "invalid call")?;
    let action = gateway.prepare(input)?;
    let mut request = base(identity, client_type, principal);
    request.workspace = workspace?;
    let claimed_workspace = request.workspace.clone();
    let receipt = state
        .enclave
        .execute_mcp(gateway, &owner, request, action, || async {
            if let Some(claimed) = &claimed_workspace {
                verify_workspace(claimed, identity.pid).await?;
            }
            resolve_principal_context(state, session_id).await
        })
        .await?;
    Ok(serde_json::json!({"receipt":receipt}))
}

/// Configured dedicated runner availability; the raw generic execute route
/// deliberately has no MCP handler and cannot bypass invocation accounting.
pub fn operation_catalog(state: &DaemonState) -> Vec<serde_json::Value> {
    let mut catalog = state.enclave.operation_catalog();
    if let Some(entry) = catalog.iter_mut().find(|e| e["name"] == "mcp.call") {
        entry["mcp_exposed"] = serde_json::json!(state.mcp.is_some());
        if let Some(gateway) = &state.mcp {
            entry["availability"] = serde_json::json!(if gateway.fixture_only() {
                "fixture_only"
            } else {
                "enabled"
            });
            entry["execution_paths"] = serde_json::json!(["mcp_invocation"]);
        }
    }
    catalog
}
