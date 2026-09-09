//! The `github` RPC convenience wrapper.
//!
//! Moved out of `opaqued::main.rs` verbatim (previously ~300 inline lines in
//! the top-level RPC dispatch `match`, plus two helper functions that already
//! took `&dyn EnclaveFacade`): scope routing for
//! repo_actions/env_actions/codespaces_user/codespaces_repo/dependabot/org_actions,
//! target building, secret-ref validation, and the `list_secrets`/
//! `delete_secret` sub-dispatch, before handing off to the enclave via
//! [`EnclaveFacade::execute`].
//!
//! One behavioral simplification versus the pre-move code: the two
//! list/delete helpers used to independently re-verify the workspace via
//! `opaqued::task_api::verified_workspace(&req.params, identity)` — a second,
//! redundant call, since `opaqued::main.rs`'s `handle_request` already
//! verifies it once up front for every `"github"`-method request and used to
//! pass that result only to the inline (set-secret) path. Workspace verification
//! stays in the daemon's composition root, so the already-verified workspace
//! is now a parameter threaded through all three paths — same verified value,
//! one verification instead of two.
//!
//! Error presentation retains a local helper while delegating byte-boundary
//! handling to the shared core validator.

use std::collections::HashMap;
use std::time::SystemTime;

use opaque_core::enclave_facade::EnclaveFacade;
use opaque_core::identity::PrincipalContext;
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest, WorkspaceContext};
use opaque_core::proto::{Request, Response};
use opaque_core::validate::InputValidator;
use uuid::Uuid;

/// Truncate a string for safe inclusion in an error message.
fn truncate_for_error(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_owned()
    } else {
        format!("{}...", opaque_core::validate::truncate_utf8(s, max_len))
    }
}

/// Handle the `github` RPC method: a convenience wrapper that builds an
/// "execute" request for the appropriate `github.*` operation based on the
/// `scope`/`action` params, then runs it through the enclave.
///
/// - `action: "list_secrets"` -> `github.list_secrets`
/// - `action: "delete_secret"` -> `github.delete_secret`
/// - (default) -> `github.set_*` (set secret), routed by `scope`
///
/// `workspace` is the already-verified workspace context computed once by
/// the caller (`opaqued::main.rs`'s `handle_request`, via
/// `verified_workspace`) for every `"github"`-method request.
pub async fn handle_github_rpc(
    req: &Request,
    state: &dyn EnclaveFacade,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<&PrincipalContext>,
    workspace: Option<WorkspaceContext>,
) -> Response {
    let action = req
        .params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("set_secret");

    // Route list_secrets and delete_secret to their own dispatch paths.
    if action == "list_secrets" {
        return handle_github_list_secrets(
            req,
            state,
            identity,
            client_type,
            principal_ctx,
            workspace,
        )
        .await;
    }
    if action == "delete_secret" {
        return handle_github_delete_secret(
            req,
            state,
            identity,
            client_type,
            principal_ctx,
            workspace,
        )
        .await;
    }

    let scope = req
        .params
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("repo_actions");

    let secret_name = req
        .params
        .get("secret_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    if secret_name.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'secret_name' field");
    }

    // Validate secret_name (alphanumeric + underscores).
    if !secret_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Response::err(
            Some(req.id),
            "bad_request",
            "secret_name must be alphanumeric (with underscores)",
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

    // Validate value_ref starts with a known scheme.
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

    // Validate value_ref and github_token_ref for control chars / secret patterns.
    // This prevents prompt injection in the approval UI via crafted ref strings.
    let mut refs_to_validate = vec![value_ref.clone()];
    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
        refs_to_validate.push(tok.to_owned());
    }
    if let Err(e) = InputValidator::validate_secret_ref_names(&refs_to_validate) {
        return Response::err(
            Some(req.id),
            "bad_request",
            format!("invalid secret ref: {e}"),
        );
    }

    // Determine operation name and target based on scope.
    let (operation, target, op_params) = match scope {
        "repo_actions" | "env_actions" => {
            let repo = req
                .params
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if repo.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'repo' field");
            }
            if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "repo must be in 'owner/repo' format",
                );
            }

            let mut params = serde_json::json!({
                "repo": repo,
                "secret_name": secret_name,
                "value_ref": value_ref,
            });
            if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                params["github_token_ref"] = serde_json::Value::String(tok.into());
            }
            if let Some(env) = req.params.get("environment").and_then(|v| v.as_str()) {
                params["environment"] = serde_json::Value::String(env.into());
            }
            let mut target = HashMap::from([
                ("repo".into(), repo),
                ("secret_name".into(), secret_name.clone()),
            ]);
            if let Some(env) = params.get("environment").and_then(|v| v.as_str()) {
                target.insert("environment".into(), env.to_owned());
            }
            ("github.set_actions_secret", target, params)
        }
        "codespaces_user" => {
            let mut params = serde_json::json!({
                "secret_name": secret_name,
                "value_ref": value_ref,
            });
            if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                params["github_token_ref"] = serde_json::Value::String(tok.into());
            }
            if let Some(ids) = req.params.get("selected_repository_ids") {
                params["selected_repository_ids"] = ids.clone();
            }
            let target = HashMap::from([("secret_name".into(), secret_name.clone())]);
            ("github.set_codespaces_secret", target, params)
        }
        "codespaces_repo" => {
            let repo = req
                .params
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if repo.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'repo' field");
            }
            if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "repo must be in 'owner/repo' format",
                );
            }

            let mut params = serde_json::json!({
                "repo": repo,
                "secret_name": secret_name,
                "value_ref": value_ref,
            });
            if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                params["github_token_ref"] = serde_json::Value::String(tok.into());
            }
            let target = HashMap::from([
                ("repo".into(), repo),
                ("secret_name".into(), secret_name.clone()),
            ]);
            ("github.set_codespaces_secret", target, params)
        }
        "dependabot" => {
            let repo = req
                .params
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if repo.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'repo' field");
            }
            if !repo.contains('/') || repo.starts_with('/') || repo.ends_with('/') {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "repo must be in 'owner/repo' format",
                );
            }

            let mut params = serde_json::json!({
                "repo": repo,
                "secret_name": secret_name,
                "value_ref": value_ref,
            });
            if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                params["github_token_ref"] = serde_json::Value::String(tok.into());
            }
            let target = HashMap::from([
                ("repo".into(), repo),
                ("secret_name".into(), secret_name.clone()),
            ]);
            ("github.set_dependabot_secret", target, params)
        }
        "org_actions" => {
            let org = req
                .params
                .get("org")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if org.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'org' field");
            }

            let mut params = serde_json::json!({
                "org": org,
                "secret_name": secret_name,
                "value_ref": value_ref,
            });
            if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
                params["github_token_ref"] = serde_json::Value::String(tok.into());
            }
            if let Some(vis) = req.params.get("visibility").and_then(|v| v.as_str()) {
                params["visibility"] = serde_json::Value::String(vis.into());
            }
            if let Some(ids) = req.params.get("selected_repository_ids") {
                params["selected_repository_ids"] = ids.clone();
            }
            let target = HashMap::from([
                ("org".into(), org),
                ("secret_name".into(), secret_name.clone()),
            ]);
            ("github.set_org_secret", target, params)
        }
        unknown => {
            return Response::err(
                Some(req.id),
                "bad_request",
                format!(
                    "unknown scope '{}' (expected: repo_actions, env_actions, codespaces_user, codespaces_repo, dependabot, org_actions)",
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

    let mut secret_refs = vec![value_ref.clone()];
    if let Some(tok) = op_params.get("github_token_ref").and_then(|v| v.as_str()) {
        secret_refs.push(tok.to_owned());
    }

    let op_req = OperationRequest {
        principal: principal_ctx.cloned(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: operation.into(),
        target,
        secret_ref_names: secret_refs,
        created_at: SystemTime::now(),
        expires_at: None,
        params: op_params,
        workspace,
    };

    state.execute(op_req).await.into_proto_response(req.id)
}

/// Handle `github` method with `action: "list_secrets"`.
///
/// Routes to `github.list_secrets` operation in the enclave.
async fn handle_github_list_secrets(
    req: &Request,
    state: &dyn EnclaveFacade,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<&PrincipalContext>,
    workspace: Option<WorkspaceContext>,
) -> Response {
    let scope = req
        .params
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("actions");

    let mut op_params = serde_json::json!({ "scope": scope });
    let mut target = HashMap::new();

    if let Some(repo) = req.params.get("repo").and_then(|v| v.as_str()) {
        op_params["repo"] = serde_json::Value::String(repo.into());
        target.insert("repo".into(), repo.to_owned());
    }
    if let Some(org) = req.params.get("org").and_then(|v| v.as_str()) {
        op_params["org"] = serde_json::Value::String(org.into());
        target.insert("org".into(), org.to_owned());
    }
    if let Some(env) = req.params.get("environment").and_then(|v| v.as_str()) {
        op_params["environment"] = serde_json::Value::String(env.into());
    }
    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
        op_params["github_token_ref"] = serde_json::Value::String(tok.into());
    }

    // Validate target before building OperationRequest.
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    let op_req = OperationRequest {
        principal: principal_ctx.cloned(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: "github.list_secrets".into(),
        target,
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: op_params,
        workspace,
    };

    state.execute(op_req).await.into_proto_response(req.id)
}

/// Handle `github` method with `action: "delete_secret"`.
///
/// Routes to `github.delete_secret` operation in the enclave.
async fn handle_github_delete_secret(
    req: &Request,
    state: &dyn EnclaveFacade,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<&PrincipalContext>,
    workspace: Option<WorkspaceContext>,
) -> Response {
    let scope = req
        .params
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("actions");

    let secret_name = req
        .params
        .get("secret_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    if secret_name.is_empty() {
        return Response::err(Some(req.id), "bad_request", "missing 'secret_name' field");
    }

    let mut op_params = serde_json::json!({
        "scope": scope,
        "secret_name": secret_name,
    });
    let mut target = HashMap::from([("secret_name".into(), secret_name.clone())]);

    if let Some(repo) = req.params.get("repo").and_then(|v| v.as_str()) {
        op_params["repo"] = serde_json::Value::String(repo.into());
        target.insert("repo".into(), repo.to_owned());
    }
    if let Some(org) = req.params.get("org").and_then(|v| v.as_str()) {
        op_params["org"] = serde_json::Value::String(org.into());
        target.insert("org".into(), org.to_owned());
    }
    if let Some(env) = req.params.get("environment").and_then(|v| v.as_str()) {
        op_params["environment"] = serde_json::Value::String(env.into());
    }
    if let Some(tok) = req.params.get("github_token_ref").and_then(|v| v.as_str()) {
        op_params["github_token_ref"] = serde_json::Value::String(tok.into());
    }

    // Validate target before building OperationRequest.
    let target = match InputValidator::validate_target(&target) {
        Ok(t) => t,
        Err(e) => {
            return Response::err(Some(req.id), "bad_request", format!("invalid target: {e}"));
        }
    };

    let op_req = OperationRequest {
        principal: principal_ctx.cloned(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: "github.delete_secret".into(),
        target,
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: op_params,
        workspace,
    };

    state.execute(op_req).await.into_proto_response(req.id)
}

#[cfg(test)]
mod error_tests {
    use super::truncate_for_error;

    #[test]
    fn multibyte_scope_errors_truncate_at_utf8_boundaries() {
        let scope = format!("{}界", "a".repeat(63));
        assert_eq!(
            truncate_for_error(&scope, 64),
            format!("{}...", "a".repeat(63))
        );
        assert_eq!(truncate_for_error("界", 0), "...");
        assert_eq!(truncate_for_error("界", 3), "界");
    }
}
