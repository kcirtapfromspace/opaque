//! Owner-scoped transport for the fixed-manifest task workflow.
use crate::{DaemonState, resolve_principal_context, verify_workspace};
use opaque_core::audit::{AuditEvent, AuditEventKind, ClientSummary};
use opaque_core::identity::{PrincipalContext, now_unix};
use opaque_core::operation::WorkspaceContext;
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest};
use opaque_core::proto::{Request, Response};
use opaque_core::sanitize::{SanitizedResponse, Sanitizer, Unsanitized};
use opaque_core::task::TaskManifest;
use opaque_core::validate::InputValidator;
use std::collections::HashMap;
use std::time::SystemTime;
use uuid::Uuid;

pub async fn verified_workspace(
    params: &serde_json::Value,
    identity: &ClientIdentity,
) -> Result<Option<WorkspaceContext>, String> {
    let Some(value) = params.get("workspace").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let mut workspace: WorkspaceContext =
        serde_json::from_value(value.clone()).map_err(|_| "invalid workspace context")?;
    if identity.pid.is_none() {
        return Err("workspace peer pid is unavailable".into());
    }
    if let Some(url) = &workspace.remote_url {
        workspace.remote_url = Some(InputValidator::sanitize_url(url));
    }
    workspace.workspace_verified = false;
    verify_workspace(&workspace, identity.pid)
        .await
        .map_err(|_| "workspace verification failed")?;
    workspace.workspace_verified = true;
    Ok(Some(workspace))
}

fn owner_key(identity: &ClientIdentity, principal: Option<&PrincipalContext>) -> String {
    match principal {
        Some(context) => format!("uid:{}:sub:{}", identity.uid, context.sub.as_str()),
        None => format!("uid:{}", identity.uid),
    }
}

pub async fn handle(
    state: &DaemonState,
    req: &Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
) -> Response {
    let result = handle_inner(state, req, identity, client_type, session_id, principal).await;
    let sanitizer = Sanitizer::new();
    match result {
        Ok(payload) => match sanitizer.sanitize_task_response(payload) {
            Ok(response) => response.into_proto_response(req.id),
            Err(_) => Response::err(
                Some(req.id),
                "task_unavailable",
                "invalid task receipt integrity",
            ),
        },
        Err(message) => sanitizer
            .sanitize_response(SanitizedResponse::<Unsanitized>::from_error(
                "task_unavailable",
                message,
                serde_json::Value::Null,
            ))
            .into_proto_response(req.id),
    }
}

async fn handle_inner(
    state: &DaemonState,
    req: &Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
) -> Result<serde_json::Value, String> {
    let store = state.tasks.as_ref().ok_or("fixed-manifest tasks are disabled; set enable_task_grants = true in the trusted daemon config")?;
    if identity.uid == u32::MAX {
        return Err("task peer identity is unavailable".into());
    }
    let owner = match &state.tenant {
        Some(tenant) => {
            tenant.owner_key(identity.uid, principal.as_ref().map(|context| &context.sub))
        }
        None => owner_key(identity, principal.as_ref()),
    };
    if req.method == "task_list" {
        let cursor = match req.params.get("cursor") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(cursor)) => Some(cursor.as_str()),
            _ => return Err("task list cursor must be a task ID".into()),
        };
        let (tasks, has_more, next_cursor) = store
            .list_page(&owner, now_unix(), cursor)
            .map_err(|e| e.to_string())?;
        return Ok(
            serde_json::json!({"tasks": tasks, "has_more": has_more, "next_cursor": next_cursor}),
        );
    }
    let id = req
        .params
        .get("task_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if req.method == "task_get" {
        return Ok(
            serde_json::json!({"task": store.get(id, &owner, now_unix()).map_err(|e| e.to_string())?}),
        );
    }
    if req.method == "task_revoke" {
        let task = store
            .revoke(id, &owner, now_unix())
            .map_err(|e| e.to_string())?;
        if let Some(action) = task
            .manifest
            .actions
            .first()
            .and_then(|action| action.as_ssh())
        {
            let closed = match state.enclave.ssh_profile() {
                Ok(profile) => crate::ssh::revoke_ssh_grant(profile, action, task.expires_at)
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            state.audit.emit(
                AuditEvent::new(AuditEventKind::OperationSucceeded)
                    .with_operation("ssh.revoke")
                    .with_outcome(if closed {
                        "host_acknowledged"
                    } else {
                        "host_acknowledgement_unavailable"
                    })
                    .with_detail(format!(
                        "task={id}; local authority revoked; host deadline remains enforced"
                    )),
            );
        }
        state.audit.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded)
                .with_client(ClientSummary::from((identity, client_type)))
                .with_operation("task.revoke")
                .with_outcome("revoked")
                .with_detail(format!("task={id}")),
        );
        return Ok(serde_json::json!({"task": task}));
    }
    let workspace = verified_workspace(&req.params, identity).await?;
    let mut request = OperationRequest {
        principal,
        request_id: Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        operation: "github.publish_manifest".into(),
        target: HashMap::new(),
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: serde_json::Value::Null,
        workspace,
    };
    if matches!(
        req.method.as_str(),
        "task_plan" | "task_plan_inference" | "task_plan_ssh"
    ) {
        let mut manifest: TaskManifest =
            if matches!(req.method.as_str(), "task_plan_inference" | "task_plan_ssh") {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct PlanInference {
                    title: String,
                    expires_in_secs: u64,
                }
                let mut input = req.params.clone();
                // Transport-owned workspace has already been independently verified.
                if let Some(object) = input.as_object_mut() {
                    object.remove("workspace");
                }
                let params: PlanInference =
                    serde_json::from_value(input).map_err(|_| "invalid fixed inference request")?;
                if req.method == "task_plan_ssh" {
                    require_tenant_identity(state, request.principal.as_ref())?;
                    crate::ssh::health_manifest(
                        state.enclave.ssh_profile()?,
                        params.title,
                        params.expires_in_secs,
                        request
                            .principal
                            .as_ref()
                            .ok_or("SSH identity unavailable")?,
                        identity,
                    )?
                } else {
                    crate::inference::public_demo_manifest(
                        state.enclave.inference_profile()?,
                        params.title,
                        params.expires_in_secs,
                    )?
                }
            } else {
                serde_json::from_value(
                    req.params
                        .get("manifest")
                        .cloned()
                        .ok_or("manifest is required")?,
                )
                .map_err(|_| "invalid task manifest shape")?
            };
        if manifest.is_ssh() {
            require_tenant_identity(state, request.principal.as_ref())?;
            crate::ssh::prepare_ssh_manifest(&mut manifest, state.enclave.ssh_profile()?)?;
        } else if manifest.is_inference() {
            require_tenant_identity(state, request.principal.as_ref())?;
            let boundary = state.tenant.as_ref().ok_or("tenant boundary unavailable")?;
            for action in &manifest.actions {
                let action = action.as_inference().ok_or("invalid inference action")?;
                boundary
                    .require_binding(&action.tenant)
                    .map_err(|_| "inference tenant binding differs from this broker")?;
            }
            crate::inference::prepare_inference_manifest(
                &mut manifest,
                state.enclave.inference_profile()?,
            )?;
        } else if manifest.is_release() {
            crate::github::prepare_staging_release(&mut manifest)?;
        } else {
            crate::github::prepare_task_manifest(&mut manifest)?;
        }
        state.enclave.preflight_task(&mut request, &manifest)?;
        let manifest = if manifest.is_ssh() {
            manifest
        } else if manifest.is_inference() {
            crate::inference::plan_inference_manifest(manifest, state.enclave.inference_profile()?)
                .await?
        } else if manifest.is_release() {
            crate::github::plan_staging_release(manifest).await?
        } else {
            crate::github::plan_task_manifest(manifest).await?
        };
        // Policy may have changed during metadata reads.
        if resolve_principal_context(state, session_id).await? != request.principal {
            return Err("task authority changed during planning".into());
        }
        state.enclave.preflight_task(&mut request, &manifest)?;
        let task = store
            .create(&owner, manifest, now_unix())
            .map_err(|e| e.to_string())?;
        return Ok(serde_json::json!({"task": task}));
    }
    if req.method == "task_reconcile" {
        let task = store
            .get(id, &owner, now_unix())
            .map_err(|e| e.to_string())?;
        if !task.manifest.is_release()
            || task.slots.len() != 1
            || !matches!(
                task.slots[0].state,
                opaque_core::task::SlotState::ApiAccepted | opaque_core::task::SlotState::Unknown
            )
            || task.slots[0].reserved_at.is_none()
        {
            return Err("only an attempted staging dispatch can be reconciled".into());
        }
        state
            .enclave
            .preflight_task_observation(&request, &task.manifest)?;
        let observation = crate::github::reconcile_staging_release(
            &task.manifest,
            id,
            task.slots[0]
                .outcome
                .as_ref()
                .and_then(|outcome| outcome.provider_run_id),
        )
        .await?;
        if resolve_principal_context(state, session_id).await? != request.principal {
            return Err("task authority changed during observation".into());
        }
        if let Some(workspace) = &request.workspace {
            verify_workspace(workspace, identity.pid)
                .await
                .map_err(|_| "workspace changed during observation")?;
        }
        state
            .enclave
            .preflight_task_observation(&request, &task.manifest)?;
        let task = store
            .record_release_observation(id, &owner, observation, now_unix())
            .map_err(|e| e.to_string())?;
        state.audit.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded)
                .with_client(ClientSummary::from((identity, client_type)))
                .with_operation("github.observe_staging_workflow")
                .with_outcome("observed")
                .with_detail(format!("task={id}")),
        );
        return Ok(serde_json::json!({"task": task}));
    }
    let stored = store
        .get(id, &owner, now_unix())
        .map_err(|e| e.to_string())?;
    if stored.manifest.is_inference() || stored.manifest.is_ssh() {
        require_tenant_identity(state, request.principal.as_ref())?;
    }
    let expected_workspace = request.workspace.clone();
    let approval_mode = if state.config.approval_backend.as_deref() == Some("insecure_auto_approve")
        || state.config.workstation_test_mode
    {
        opaque_core::task::TaskApprovalMode::InsecureTest
    } else {
        opaque_core::task::TaskApprovalMode::Native
    };
    let task = state
        .enclave
        .execute_task(store, &owner, id, request, approval_mode, || async {
            let context = resolve_principal_context(state, session_id).await?;
            if let Some(workspace) = &expected_workspace {
                verify_workspace(workspace, identity.pid)
                    .await
                    .map_err(|_| "workspace changed during task")?;
            }
            Ok(context)
        })
        .await?;
    Ok(serde_json::json!({"task": task}))
}

fn require_tenant_identity(
    state: &DaemonState,
    principal: Option<&PrincipalContext>,
) -> Result<(), String> {
    if state.tenant.is_none() || state.identity.is_none() || principal.is_none() {
        return Err(
            "tenant tasks require an authenticated tenant principal and live delegation".into(),
        );
    }
    Ok(())
}
