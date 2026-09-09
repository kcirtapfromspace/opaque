//! Owner-scoped transport for the fixed-manifest task workflow.
//!
//! Moved out of the `opaqued` binary crate, where this used to take
//! `&DaemonState` directly (the only option available to code living inside
//! `main.rs`'s own module tree). From a different crate, `DaemonState` and
//! `Enclave` are not nameable at all (`opaqued` has no `lib.rs`), so `handle`
//! now takes a [`TaskApiKernel`] bundling the two kernel-facing trait
//! objects (`opaque_core::enclave_facade::EnclaveFacade` and this crate's
//! own [`crate::task_facade::BoundedWorkFacade`]) plus the handful of plain
//! values (`tasks`, `tenant`, `has_identity`, `audit`, `insecure_auto_approve`)
//! that `opaqued::DaemonState` owns directly and this crate either can now
//! name outright (`TaskStore` lives here; `opaque_tenant::tenant::TenantBoundary`
//! is already a public cross-crate type) or only needs as an opaque flag
//! (`has_identity`, `insecure_auto_approve`).
//!
//! One behavioral change versus the pre-move code, made for the same reason
//! `opaque-providers::github::rpc` already made it: the transport-level,
//! once-per-request workspace verification (previously this module's own
//! `verified_workspace`, calling `opaqued::main.rs`'s kernel-side
//! `verify_workspace`/`workspace_process.rs` machinery directly) is now
//! computed once by `opaqued::main.rs`'s `handle_request` — the same place
//! that already computes it for `github`/`gitlab`/`onepassword`/`bitwarden`/
//! `exec` — and passed into `handle` as the `workspace` parameter. Moved
//! code reaching back into the daemon for kernel-side subprocess logic would
//! be exactly the wrong-direction dependency this extraction exists to cut.
//! The two *re*-verifications this module still performs at later points in
//! its own control flow (task-reconcile observation, task-execution TOCTOU
//! recheck) cannot be precomputed the same way — they must run live, after
//! further async work this module itself does — so those go through
//! `EnclaveFacade::verify_workspace` instead, the same "live callback into
//! the kernel" shape already established by `resolve_principal_context`.

use std::collections::HashMap;
use std::time::SystemTime;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, ClientSummary};
use opaque_core::enclave_facade::EnclaveFacade;
use opaque_core::identity::{PrincipalContext, now_unix};
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest, WorkspaceContext};
use opaque_core::proto::{Request, Response};
use opaque_core::sanitize::{SanitizedResponse, Sanitizer, Unsanitized};
use opaque_core::task::{TaskApprovalMode, TaskManifest};
use uuid::Uuid;

use crate::task_facade::BoundedWorkFacade;
use crate::task_store::TaskStore;

/// The daemon-owned dependencies `handle` needs beyond the RPC request
/// itself, gathered once per call by the composition root
/// (`opaqued::main.rs`). Bundled into one struct rather than passed as
/// several positional parameters: `facade` and `enclave` are the two
/// kernel-facing trait objects (see `crate::task_facade` for why there are
/// two and not one combined bound), and the rest are values
/// `opaqued::DaemonState` holds directly.
pub struct TaskApiKernel<'a> {
    /// `opaque_core::enclave_facade::EnclaveFacade`, implemented by
    /// `opaqued::DaemonState`: preflight, principal-context resolution, and
    /// workspace re-verification.
    pub facade: &'a dyn EnclaveFacade,
    /// [`BoundedWorkFacade`], implemented by `opaqued::enclave::Enclave`
    /// directly: `ssh_profile`/`inference_profile`/`execute_task`.
    pub enclave: &'a dyn BoundedWorkFacade,
    /// `None` when fixed-manifest tasks are disabled
    /// (`enable_task_grants = false`).
    pub tasks: Option<&'a TaskStore>,
    pub tenant: Option<&'a opaque_tenant::tenant::TenantBoundary>,
    /// Whether `opaqued::DaemonState.identity` is configured (`[identity]`
    /// present). `identity::IdentityRuntime` itself stays in `opaqued`, so
    /// this crate only ever needs its *presence*, never the runtime itself.
    pub has_identity: bool,
    pub audit: &'a dyn AuditSink,
    /// Precomputed by the caller from `DaemonConfig`
    /// (`approval_backend == "insecure_auto_approve" || workstation_test_mode`):
    /// trivial config-flag logic that belongs at the composition root, not
    /// duplicated here.
    pub insecure_auto_approve: bool,
}

fn owner_key(identity: &ClientIdentity, principal: Option<&PrincipalContext>) -> String {
    match principal {
        Some(context) => format!("uid:{}:sub:{}", identity.uid, context.sub.as_str()),
        None => format!("uid:{}", identity.uid),
    }
}

pub async fn handle(
    kernel: &TaskApiKernel<'_>,
    req: &Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
    workspace: Result<Option<WorkspaceContext>, String>,
) -> Response {
    let result = handle_inner(
        kernel,
        req,
        identity,
        client_type,
        session_id,
        principal,
        workspace,
    )
    .await;
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
    kernel: &TaskApiKernel<'_>,
    req: &Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
    workspace: Result<Option<WorkspaceContext>, String>,
) -> Result<serde_json::Value, String> {
    let store = kernel.tasks.ok_or(
        "fixed-manifest tasks are disabled; set enable_task_grants = true in the trusted daemon config",
    )?;
    if identity.uid == u32::MAX {
        return Err("task peer identity is unavailable".into());
    }
    let owner = match kernel.tenant {
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
            let closed = match kernel.enclave.ssh_profile() {
                Ok(profile) => crate::ssh::revoke_ssh_grant(profile, action, task.expires_at)
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            kernel.audit.emit(
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
        kernel.audit.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded)
                .with_client(ClientSummary::from((identity, client_type)))
                .with_operation("task.revoke")
                .with_outcome("revoked")
                .with_detail(format!("task={id}")),
        );
        return Ok(serde_json::json!({"task": task}));
    }
    // Already verified once, up front, by `opaqued::main.rs`'s
    // `handle_request` (see this module's doc comment).
    let workspace = workspace?;
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
                    require_tenant_identity(kernel, request.principal.as_ref())?;
                    crate::ssh::health_manifest(
                        kernel.enclave.ssh_profile()?,
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
                        kernel.enclave.inference_profile()?,
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
            require_tenant_identity(kernel, request.principal.as_ref())?;
            crate::ssh::prepare_ssh_manifest(&mut manifest, kernel.enclave.ssh_profile()?)?;
        } else if manifest.is_inference() {
            require_tenant_identity(kernel, request.principal.as_ref())?;
            let boundary = kernel.tenant.ok_or("tenant boundary unavailable")?;
            for action in &manifest.actions {
                let action = action.as_inference().ok_or("invalid inference action")?;
                boundary
                    .require_binding(&action.tenant)
                    .map_err(|_| "inference tenant binding differs from this broker")?;
            }
            crate::inference::prepare_inference_manifest(
                &mut manifest,
                kernel.enclave.inference_profile()?,
            )?;
        } else if manifest.is_release() {
            opaque_providers::github::prepare_staging_release(&mut manifest)?;
        } else {
            opaque_providers::github::prepare_task_manifest(&mut manifest)?;
        }
        kernel.facade.preflight_task(&mut request, &manifest)?;
        let manifest = if manifest.is_ssh() {
            manifest
        } else if manifest.is_inference() {
            crate::inference::plan_inference_manifest(manifest, kernel.enclave.inference_profile()?)
                .await?
        } else if manifest.is_release() {
            opaque_providers::github::plan_staging_release(manifest).await?
        } else {
            opaque_providers::github::plan_task_manifest(manifest).await?
        };
        // Policy may have changed during metadata reads.
        if kernel.facade.resolve_principal_context(session_id).await? != request.principal {
            return Err("task authority changed during planning".into());
        }
        kernel.facade.preflight_task(&mut request, &manifest)?;
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
        kernel
            .facade
            .preflight_task_observation(&request, &task.manifest)?;
        let observation = opaque_providers::github::reconcile_staging_release(
            &task.manifest,
            id,
            task.slots[0]
                .outcome
                .as_ref()
                .and_then(|outcome| outcome.provider_run_id),
        )
        .await?;
        if kernel.facade.resolve_principal_context(session_id).await? != request.principal {
            return Err("task authority changed during observation".into());
        }
        if let Some(workspace) = &request.workspace {
            kernel
                .facade
                .verify_workspace(workspace, identity.pid)
                .await
                .map_err(|_| "workspace changed during observation")?;
        }
        kernel
            .facade
            .preflight_task_observation(&request, &task.manifest)?;
        let task = store
            .record_release_observation(id, &owner, observation, now_unix())
            .map_err(|e| e.to_string())?;
        kernel.audit.emit(
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
        require_tenant_identity(kernel, request.principal.as_ref())?;
    }
    let expected_workspace = request.workspace.clone();
    let approval_mode = if kernel.insecure_auto_approve {
        TaskApprovalMode::InsecureTest
    } else {
        TaskApprovalMode::Native
    };
    let task = kernel
        .enclave
        .execute_task(
            store,
            &owner,
            id,
            request,
            approval_mode,
            Box::new(move || {
                // `execute_task`'s `check_context` is `Fn`, callable more
                // than once, so each invocation gets its own clone rather
                // than moving the outer `expected_workspace` capture.
                let expected_workspace = expected_workspace.clone();
                Box::pin(async move {
                    let context = kernel.facade.resolve_principal_context(session_id).await?;
                    if let Some(workspace) = &expected_workspace {
                        kernel
                            .facade
                            .verify_workspace(workspace, identity.pid)
                            .await
                            .map_err(|_| "workspace changed during task")?;
                    }
                    Ok(context)
                })
            }),
        )
        .await?;
    Ok(serde_json::json!({"task": task}))
}

fn require_tenant_identity(
    kernel: &TaskApiKernel<'_>,
    principal: Option<&PrincipalContext>,
) -> Result<(), String> {
    if kernel.tenant.is_none() || !kernel.has_identity || principal.is_none() {
        return Err(
            "tenant tasks require an authenticated tenant principal and live delegation".into(),
        );
    }
    Ok(())
}
