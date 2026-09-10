//! GitHub RPC routing into the daemon's canonical generic-operation path.
//!
//! Only envelope fields are removed. Provider inputs, including wrong types and
//! competing scope fields, reach the typed preparer unchanged and fail closed.

use std::collections::HashMap;
use std::time::SystemTime;

use opaque_core::enclave_facade::EnclaveFacade;
use opaque_core::identity::PrincipalContext;
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest, WorkspaceContext};
use opaque_core::proto::{Request, Response};
use uuid::Uuid;

fn normalize_params(
    params: &serde_json::Value,
) -> Result<(&'static str, serde_json::Value), String> {
    let mut params = params
        .as_object()
        .cloned()
        .ok_or("GitHub parameters must be an object")?;
    // The daemon verifies this claim and passes it separately; it is not a
    // provider parameter and cannot enter the action's execution projection.
    params.remove("workspace");
    // Peer classification is verified by the daemon, never by this legacy hint.
    params.remove("client_type");
    let action = params.remove("action");
    let action = match action.as_ref() {
        None | Some(serde_json::Value::Null) => "set_secret",
        Some(serde_json::Value::String(action)) => action.as_str(),
        _ => return Err("invalid GitHub action".into()),
    };
    if matches!(action, "list_secrets" | "delete_secret") {
        let operation = if action == "list_secrets" {
            "github.list_secrets"
        } else {
            "github.delete_secret"
        };
        return Ok((operation, params.into()));
    }
    if action != "set_secret" {
        return Err("unknown GitHub action".into());
    }
    let scope = params.remove("scope");
    let scope = match scope.as_ref() {
        None | Some(serde_json::Value::Null) => "repo_actions",
        Some(serde_json::Value::String(scope)) => scope.as_str(),
        _ => return Err("invalid GitHub scope".into()),
    };
    let present = |key: &str| params.get(key).is_some_and(|value| !value.is_null());
    let operation = match scope {
        // Historical wrapper/MCP alias: repo_actions also carries environment.
        // Preparation derives the actual environment scope from that field.
        "repo_actions" => "github.set_actions_secret",
        "env_actions" => {
            if !present("environment") {
                return Err("env_actions requires an environment".into());
            }
            "github.set_actions_secret"
        }
        "codespaces_user" => {
            if present("repo") {
                return Err("codespaces_user cannot select a repository".into());
            }
            "github.set_codespaces_secret"
        }
        "codespaces_repo" => {
            if !present("repo") {
                return Err("codespaces_repo requires a repository".into());
            }
            "github.set_codespaces_secret"
        }
        "dependabot" => "github.set_dependabot_secret",
        "org_actions" => "github.set_org_secret",
        _ => return Err("unknown GitHub scope".into()),
    };
    Ok((operation, params.into()))
}

/// Route one convenience request without pre-authorizing copied target fields.
/// The enclave derives policy, approval and audit projections from its handler.
pub async fn handle_github_rpc(
    req: &Request,
    state: &dyn EnclaveFacade,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<&PrincipalContext>,
    workspace: Option<WorkspaceContext>,
) -> Response {
    let (operation, params) = match normalize_params(&req.params) {
        Ok(normalized) => normalized,
        Err(error) => return Response::err(Some(req.id), "bad_request", error),
    };
    let request = OperationRequest {
        principal: principal_ctx.cloned(),
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: operation.into(),
        target: HashMap::new(),
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params,
        workspace,
    };
    state.execute(request).await.into_proto_response(req.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wrapper_keeps_provider_fields_for_typed_validation() {
        for (field, value) in [
            ("github_token_ref", json!(false)),
            ("environment", json!(17)),
            ("org", json!("competing-org")),
            ("unknown_field", json!(true)),
        ] {
            let mut params = json!({"scope":"env_actions", "repo":"acme/app", "environment":"production", "secret_name":"TOKEN", "value_ref":"env:VALUE"});
            params[field] = value.clone();
            let (operation, normalized) = normalize_params(&params).unwrap();
            assert_eq!(operation, "github.set_actions_secret");
            assert_eq!(normalized[field], value);
            assert!(normalized.get("scope").is_none());
        }
    }

    #[test]
    fn wrapper_rejects_ambiguous_routing_instead_of_silently_changing_scope() {
        for params in [
            json!({"scope":"env_actions"}),
            json!({"scope":"codespaces_repo"}),
            json!({"scope":"codespaces_user", "repo":"acme/app"}),
            json!({"scope":false}),
            json!({"action":17}),
            json!({"action":"unknown"}),
        ] {
            assert!(normalize_params(&params).is_err());
        }
        let error = normalize_params(&json!({"scope":"界".repeat(200)})).unwrap_err();
        assert_eq!(error, "unknown GitHub scope");
    }

    #[test]
    fn list_and_delete_preserve_scope_options_and_discard_only_verified_envelope() {
        for action in ["list_secrets", "delete_secret"] {
            let params = json!({"action":action, "scope":"codespaces", "repo":null, "environment":false, "workspace":null});
            let (operation, normalized) = normalize_params(&params).unwrap();
            assert_eq!(operation, format!("github.{action}"));
            assert_eq!(
                normalized,
                json!({"scope":"codespaces", "repo":null, "environment":false})
            );
        }
    }
}
