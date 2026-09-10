//! RPC handlers for the "convenience wrapper" method family: `execute`,
//! `gitlab`, `onepassword`, `bitwarden`, and `exec`. Each parses a friendlier,
//! flat set of params into an `OperationRequest` for the appropriate
//! `provider.action` operation (or, for the bare `execute` method, the
//! caller-named operation directly) and hands it to
//! `state.enclave.execute()` — the same enclave entry point every other
//! operation-executing RPC method goes through.
//!
//! Extracted verbatim out of `main.rs`'s `handle_request` dispatch (pure
//! structural move, no behavior change): these five arms alone were ~600
//! lines of param-parsing/validation. They stay in `opaqued` rather than
//! `opaque-providers` (the sibling `github` method already delegates fully
//! into that crate's `handle_github_rpc`) because building an
//! `OperationRequest` and calling `state.enclave.execute()` is composition-
//! root wiring, not provider-specific logic — `gitlab`/`onepassword`/
//! `bitwarden` only shape params, the actual provider calls happen later,
//! inside the enclave's operation dispatch.
use std::collections::HashMap;
use std::time::SystemTime;

use opaque_core::identity::PrincipalContext;
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest};
use opaque_core::proto::{Request, Response};
use opaque_core::validate::InputValidator;
use tracing::warn;
use uuid::Uuid;

use crate::{DaemonState, truncate_for_error, verify_workspace};

/// `execute`: the general-purpose entry point — the caller names the
/// operation directly and supplies `target`/`secret_ref_names`/`params`/an
/// optional `workspace` claim, which this verifies itself (unlike the other
/// four wrappers below, which reuse `handle_request`'s pre-verified
/// `wrapper_workspace`, since `execute` is not in that pre-check's method
/// list — see the comment at its call site in `handle_request`).
pub async fn handle_execute(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
) -> Response {
    let operation = req
        .params
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    if operation.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'operation' field");
    }

    let target: HashMap<String, String> = match req.params.get("target") {
        None => HashMap::new(),
        Some(value) => match serde_json::from_value(value.clone()) {
            Ok(target) => target,
            Err(_) => {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "target must be an object of string assertions",
                );
            }
        },
    };

    // Caller reference hints are non-authoritative. Preparation supplies every
    // effective reference, including implicit credential selectors. Targets stay
    // byte-for-byte assertions; trimming them here would hide contradictions.
    let secret_ref_names = Vec::new();

    // Client type is derived from verified identity — NEVER from params.
    // Any `client_type` field in params is silently ignored.

    let op_params = req
        .params
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let mut workspace: Option<opaque_core::operation::WorkspaceContext> = req
        .params
        .get("workspace")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    // Sanitize workspace remote_url to strip embedded credentials.
    if let Some(ref mut ws) = workspace
        && let Some(ref url) = ws.remote_url
    {
        ws.remote_url = Some(InputValidator::sanitize_url(url));
    }

    // Verify claimed workspace against actual process state.
    // verify_workspace is async (offloads blocking git commands to spawn_blocking).
    if let Some(ref ws) = workspace
        && let Err(e) = verify_workspace(ws, identity.pid).await
    {
        warn!("workspace verification failed: {e}");
        return Response::err(
            Some(req.id),
            "workspace_verification_failed",
            "workspace verification failed",
        );
    }

    // Mark workspace as verified — the daemon confirmed the claimed
    // workspace state matches the actual process and git state.
    // Policy rules with workspace constraints will check this flag.
    if let Some(ref mut ws) = workspace {
        ws.workspace_verified = true;
    }

    let op_req = OperationRequest {
        principal: principal_ctx.clone(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation,
        target,
        secret_ref_names,
        created_at: SystemTime::now(),
        expires_at: None,
        params: op_params,
        workspace,
    };

    state
        .enclave
        .execute(op_req)
        .await
        .into_proto_response(req.id)
}

/// `gitlab`: convenience wrapper for `gitlab.set_ci_variable`.
pub async fn handle_gitlab(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
    wrapper_workspace: Option<opaque_core::operation::WorkspaceContext>,
) -> Response {
    // Convenience wrapper for gitlab.set_ci_variable.
    let action = req
        .params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("set_ci_variable")
        .to_owned();

    if action != "set_ci_variable" {
        return Response::err(
            Some(req.id),
            "bad_request",
            format!(
                "unknown action '{}' (expected: set_ci_variable)",
                truncate_for_error(&action, 64)
            ),
        );
    }

    let project = req
        .params
        .get("project")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if project.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'project' field");
    }

    let key = req
        .params
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if key.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'key' field");
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Response::err(
            Some(req.id),
            "bad_request",
            "key must be alphanumeric (with underscores)",
        );
    }

    let value_ref = req
        .params
        .get("value_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if value_ref.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'value_ref' field");
    }
    if !opaque_core::profile::ALLOWED_REF_SCHEMES
        .iter()
        .any(|s| value_ref.starts_with(s))
    {
        return Response::err(
            Some(req.id),
            "bad_request",
            format!(
                "value_ref must start with a known scheme ({:?})",
                opaque_core::profile::ALLOWED_REF_SCHEMES
            ),
        );
    }

    let mut refs_to_validate = vec![value_ref.clone()];
    if let Some(tok) = req.params.get("gitlab_token_ref").and_then(|v| v.as_str()) {
        refs_to_validate.push(tok.to_owned());
    }
    if let Err(e) = InputValidator::validate_secret_ref_names(&refs_to_validate) {
        return Response::err(
            Some(req.id),
            "bad_request",
            format!("invalid secret ref: {e}"),
        );
    }

    let target = HashMap::from([
        ("project".into(), project.clone()),
        ("key".into(), key.clone()),
    ]);
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    // Preserve provider input types and unknown fields for the strict preparer.
    // Removing an invalid optional value here would silently change the action.
    let mut op_params = req.params.clone();
    let Some(params) = op_params.as_object_mut() else {
        return Response::err(Some(req.id), "bad_request", "invalid GitLab parameters");
    };
    params.remove("action");
    params.remove("workspace");
    params.remove("client_type");

    let op_req = OperationRequest {
        principal: principal_ctx.clone(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: "gitlab.set_ci_variable".into(),
        target,
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: op_params,
        workspace: wrapper_workspace.clone(),
    };

    state
        .enclave
        .execute(op_req)
        .await
        .into_proto_response(req.id)
}

/// `onepassword`: convenience wrapper for `onepassword.list_vaults` /
/// `onepassword.list_items` / `onepassword.read_field`.
pub async fn handle_onepassword(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
    wrapper_workspace: Option<opaque_core::operation::WorkspaceContext>,
) -> Response {
    let operation = match req.params.get("action").and_then(|v| v.as_str()) {
        Some("list_vaults") => "onepassword.list_vaults",
        Some("list_items") => "onepassword.list_items",
        Some("read_field") => "onepassword.read_field",
        _ => return Response::err(Some(req.id), "bad_request", "unknown onepassword action"),
    };
    execute_wrapper(
        state,
        req,
        operation,
        identity,
        client_type,
        principal_ctx,
        wrapper_workspace,
    )
    .await
}

/// `bitwarden`: convenience wrapper for the typed Bitwarden actions.
pub async fn handle_bitwarden(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
    wrapper_workspace: Option<opaque_core::operation::WorkspaceContext>,
) -> Response {
    let operation = match req.params.get("action").and_then(|v| v.as_str()) {
        Some("list_projects") => "bitwarden.list_projects",
        Some("list_secrets") => "bitwarden.list_secrets",
        Some("read_secret") => "bitwarden.read_secret",
        _ => return Response::err(Some(req.id), "bad_request", "unknown bitwarden action"),
    };
    execute_wrapper(
        state,
        req,
        operation,
        identity,
        client_type,
        principal_ctx,
        wrapper_workspace,
    )
    .await
}

/// Preserve every supplied provider field for strict action validation. Only
/// documented RPC envelope fields are removed; wrong types and unknown options
/// must never silently become a broader default operation.
fn wrapper_params(mut params: serde_json::Value) -> serde_json::Value {
    if let Some(fields) = params.as_object_mut() {
        fields.remove("action");
        fields.remove("workspace");
        fields.remove("client_type");
    }
    params
}

#[allow(clippy::too_many_arguments)] // RPC envelope and verified peer context stay separate.
async fn execute_wrapper(
    state: &DaemonState,
    req: Request,
    operation: &str,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
    workspace: Option<opaque_core::operation::WorkspaceContext>,
) -> Response {
    let op_req = OperationRequest {
        principal: principal_ctx,
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: operation.into(),
        target: HashMap::new(),
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: wrapper_params(req.params),
        workspace,
    };
    state
        .enclave
        .execute(op_req)
        .await
        .into_proto_response(req.id)
}

/// `exec`: convenience wrapper that builds a `sandbox.exec` request from
/// exec-specific params (a named sandbox profile plus a command argv).
pub async fn handle_exec(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
    wrapper_workspace: Option<opaque_core::operation::WorkspaceContext>,
) -> Response {
    execute_wrapper(
        state,
        req,
        "sandbox.exec",
        identity,
        client_type,
        principal_ctx,
        wrapper_workspace,
    )
    .await
}
