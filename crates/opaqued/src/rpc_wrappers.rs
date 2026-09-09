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

    let target: HashMap<String, String> = req
        .params
        .get("target")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let secret_ref_names: Vec<String> = req
        .params
        .get("secret_ref_names")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // --- Input validation (P0): sanitize client-controlled strings ---
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    let secret_ref_names = match InputValidator::validate_secret_ref_names(&secret_ref_names) {
        Ok(n) => n,
        Err(e) => {
            return Response::err(
                Some(req.id),
                "bad_request",
                format!("invalid secret_ref_names: {e}"),
            );
        }
    };

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

    let mut op_params = serde_json::json!({
        "project": project,
        "key": key,
        "value_ref": value_ref,
    });
    if let Some(tok) = req.params.get("gitlab_token_ref").and_then(|v| v.as_str()) {
        op_params["gitlab_token_ref"] = serde_json::Value::String(tok.to_owned());
    }
    if let Some(scope) = req.params.get("environment_scope").and_then(|v| v.as_str()) {
        op_params["environment_scope"] = serde_json::Value::String(scope.to_owned());
    }
    if req.params.get("protected").is_some() {
        op_params["protected"] = req.params["protected"].clone();
    }
    if req.params.get("masked").is_some() {
        op_params["masked"] = req.params["masked"].clone();
    }
    if req.params.get("raw").is_some() {
        op_params["raw"] = req.params["raw"].clone();
    }
    if let Some(variable_type) = req.params.get("variable_type").and_then(|v| v.as_str()) {
        op_params["variable_type"] = serde_json::Value::String(variable_type.to_owned());
    }

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
    // The onepassword method is a convenience wrapper that builds an
    // "execute" request for the appropriate onepassword.* operation.
    let action = req
        .params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    if action.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'action' field");
    }

    let (operation, target, op_params) = match action.as_str() {
        "list_vaults" => (
            "onepassword.list_vaults",
            HashMap::new(),
            serde_json::json!({}),
        ),
        "list_items" => {
            let vault = req
                .params
                .get("vault")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if vault.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'vault' field");
            }

            let target = HashMap::from([("vault".into(), vault.clone())]);
            (
                "onepassword.list_items",
                target,
                serde_json::json!({ "vault": vault }),
            )
        }
        "read_field" => {
            let vault = req
                .params
                .get("vault")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let item = req
                .params
                .get("item")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let field = req
                .params
                .get("field")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if vault.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'vault' field");
            }
            if item.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'item' field");
            }
            if field.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'field' field");
            }

            let target = HashMap::from([
                ("vault".into(), vault.clone()),
                ("item".into(), item.clone()),
            ]);
            (
                "onepassword.read_field",
                target,
                serde_json::json!({ "vault": vault, "item": item, "field": field }),
            )
        }
        unknown => {
            return Response::err(
                Some(req.id),
                "bad_request",
                format!(
                    "unknown action '{}' (expected: list_vaults, list_items, read_field)",
                    truncate_for_error(unknown, 64)
                ),
            );
        }
    };

    // Validate target before building OperationRequest.
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    // Build secret_ref_names from the vault/item/field path for read_field.
    let secret_ref_names = if action == "read_field" {
        let v = op_params
            .get("vault")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let i = op_params.get("item").and_then(|v| v.as_str()).unwrap_or("");
        let f = op_params
            .get("field")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let refs = vec![format!("onepassword:{v}/{i}/{f}")];
        if let Err(e) = InputValidator::validate_secret_ref_names(&refs) {
            return Response::err(
                Some(req.id),
                "bad_request",
                format!("invalid secret ref: {e}"),
            );
        }
        refs
    } else {
        vec![]
    };

    let op_req = OperationRequest {
        principal: principal_ctx.clone(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: operation.into(),
        target,
        secret_ref_names,
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

/// `bitwarden`: convenience wrapper for `bitwarden.list_projects` /
/// `bitwarden.list_secrets` / `bitwarden.read_secret`.
pub async fn handle_bitwarden(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
    wrapper_workspace: Option<opaque_core::operation::WorkspaceContext>,
) -> Response {
    // The bitwarden method is a convenience wrapper that builds an
    // "execute" request for the appropriate bitwarden.* operation.
    let action = req
        .params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    if action.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'action' field");
    }

    let (operation, target, op_params) = match action.as_str() {
        "list_projects" => (
            "bitwarden.list_projects",
            HashMap::new(),
            serde_json::json!({}),
        ),
        "list_secrets" => {
            let project = req
                .params
                .get("project")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned());

            let target = if let Some(ref p) = project {
                HashMap::from([("project".into(), p.clone())])
            } else {
                HashMap::new()
            };
            let params = if let Some(ref p) = project {
                serde_json::json!({ "project": p })
            } else {
                serde_json::json!({})
            };
            ("bitwarden.list_secrets", target, params)
        }
        "read_secret" => {
            let secret_id = req
                .params
                .get("secret_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if secret_id.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'secret_id' field");
            }

            let target = HashMap::from([("secret_id".into(), secret_id.clone())]);
            (
                "bitwarden.read_secret",
                target,
                serde_json::json!({ "secret_id": secret_id }),
            )
        }
        unknown => {
            return Response::err(
                Some(req.id),
                "bad_request",
                format!(
                    "unknown action '{}' (expected: list_projects, list_secrets, read_secret)",
                    truncate_for_error(unknown, 64)
                ),
            );
        }
    };

    // Validate target before building OperationRequest.
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    // Build secret_ref_names for read_secret.
    let secret_ref_names = if action == "read_secret" {
        let sid = op_params
            .get("secret_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let refs = vec![format!("bitwarden:{sid}")];
        if let Err(e) = InputValidator::validate_secret_ref_names(&refs) {
            return Response::err(
                Some(req.id),
                "bad_request",
                format!("invalid secret ref: {e}"),
            );
        }
        refs
    } else {
        vec![]
    };

    let op_req = OperationRequest {
        principal: principal_ctx.clone(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: operation.into(),
        target,
        secret_ref_names,
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
    // The exec method is a convenience wrapper that builds an "execute"
    // request for "sandbox.exec" from exec-specific params.
    let profile = req
        .params
        .get("profile")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    if profile.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'profile' field");
    }

    let command: Vec<String> = req
        .params
        .get("command")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    if command.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'command' field");
    }

    // Validate profile name (alphanumeric + hyphens + underscores).
    if !profile
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Response::err(
            Some(req.id),
            "bad_request",
            "profile name must be alphanumeric (with hyphens/underscores)",
        );
    }

    // Derive secret_ref_names from the profile's secret declarations.
    let secret_ref_names = opaque_core::profile::load_named_profile(&profile)
        .map(|p| p.secrets.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    let op_req = OperationRequest {
        principal: principal_ctx.clone(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: "sandbox.exec".into(),
        // SECURITY (C3): include the command in `target` so it is rendered
        // in the approval prompt, covered by allowed_target_keys, and bound
        // into the content hash and lease key — the approver authorizes the
        // exact argv, not just the profile name.
        target: {
            let cmd_display = command
                .iter()
                .map(|a| {
                    if a.is_empty() || a.chars().any(|c| c.is_whitespace() || c == '"') {
                        format!("{a:?}")
                    } else {
                        a.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            HashMap::from([
                ("profile".into(), profile.clone()),
                ("command".into(), cmd_display),
            ])
        },
        secret_ref_names,
        created_at: SystemTime::now(),
        expires_at: None,
        params: serde_json::json!({
            "profile": profile,
            "command": command,
        }),
        workspace: wrapper_workspace.clone(),
    };

    state
        .enclave
        .execute(op_req)
        .await
        .into_proto_response(req.id)
}
