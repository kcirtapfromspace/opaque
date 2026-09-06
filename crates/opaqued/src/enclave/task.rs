//! A separate, opt-in approval path for immutable, one-shot task manifests.
//! Every child still passes registry, safety and live policy checks. There is
//! deliberately no generic handler for `github.publish_manifest`.

use super::*;
use opaque_bounded_work::task_store::{TaskStore, TaskStoreError};
use opaque_core::identity::{PrincipalContext, now_unix};
use opaque_core::task::{
    SlotOutcome, SlotState, TaskAction, TaskApprovalMode, TaskManifest, TaskRecord,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;

pub fn task_operation() -> OperationDef {
    OperationDef {
        name: "github.publish_manifest".into(),
        safety: OperationSafety::Safe,
        default_approval: ApprovalRequirement::Always,
        default_factors: vec![ApprovalFactor::LocalBio],
        description: "Approve one fixed GitHub secret publishing task".into(),
        params_schema: None,
        allowed_target_keys: vec!["task_id".into(), "manifest_digest".into()],
        secret_ref_param_keys: vec![],
    }
}

pub fn release_task_operations() -> Vec<OperationDef> {
    let mut parent = task_operation();
    parent.name = "github.release_manifest".into();
    parent.description = "Approve one fixed staging workflow dispatch".into();
    let child = OperationDef {
        name: "github.dispatch_staging_workflow".into(),
        safety: OperationSafety::Safe,
        default_approval: ApprovalRequirement::Always,
        default_factors: vec![ApprovalFactor::LocalBio],
        description: "Dispatch the approved staging artifact once".into(),
        params_schema: None,
        allowed_target_keys: [
            "repo",
            "workflow_path",
            "workflow_ref",
            "approved_commit_sha",
            "image_repository",
            "image_digest",
            "environment",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        secret_ref_param_keys: vec!["github_token_ref".into()],
    };
    let mut read = child.clone();
    read.name = "github.observe_staging_workflow".into();
    read.description = "Read correlated staging workflow evidence".into();
    read.default_approval = ApprovalRequirement::Never;
    read.default_factors.clear();
    vec![parent, child, read]
}

pub fn inference_task_operations() -> Vec<OperationDef> {
    let mut parent = task_operation();
    parent.name = "inference.fixed_manifest".into();
    parent.description = "Approve three tenant-scoped public-data completions".into();
    let child = OperationDef {
        name: "inference.fixed_completion".into(),
        safety: OperationSafety::Safe,
        default_approval: ApprovalRequirement::Always,
        default_factors: vec![ApprovalFactor::LocalBio],
        description: "Use one approved source snapshot with one approved model".into(),
        params_schema: None,
        allowed_target_keys: [
            "tenant_id",
            "broker_id",
            "profile_id",
            "profile_sha256",
            "model_id",
            "model_artifact_sha256",
            "source_id",
            "source_snapshot_sha256",
            "prompt_sha256",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        secret_ref_param_keys: vec!["credential_ref".into()],
    };
    vec![parent, child]
}

pub fn ssh_task_operations() -> Vec<OperationDef> {
    let mut parent = task_operation();
    parent.name = opaque_core::ssh::SSH_TASK_OPERATION.into();
    parent.description = "Approve one tenant-scoped SSH service health check".into();
    let child = OperationDef {
        name: opaque_core::ssh::SSH_OPERATION.into(),
        safety: OperationSafety::Safe,
        default_approval: ApprovalRequirement::Always,
        default_factors: vec![ApprovalFactor::LocalBio],
        description: "Run the fixed health command once on the pinned host".into(),
        params_schema: None,
        allowed_target_keys: [
            "tenant_id",
            "broker_id",
            "subject",
            "delegation_id",
            "workload_uid",
            "workload_exe_sha256",
            "profile_id",
            "profile_sha256",
            "destination_host",
            "destination_port",
            "host_key_sha256",
            "vault_role",
            "vault_ca_sha256",
            "principal",
            "login_user",
            "source_address",
            "command",
            "max_session_secs",
            "grant_id",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        secret_ref_param_keys: vec!["vault_token_ref".into()],
    };
    vec![parent, child]
}

fn action_request(base: &OperationRequest, action: &TaskAction) -> OperationRequest {
    let mut request = base.clone();
    request.params = serde_json::to_value(action).expect("typed action");
    request.secret_ref_names = action.secret_refs();
    match action {
        TaskAction::SshHealth(action) => {
            request.operation = opaque_core::ssh::SSH_OPERATION.into();
            request.target = HashMap::from([
                ("tenant_id".into(), action.tenant.tenant_id.to_string()),
                ("broker_id".into(), action.tenant.broker_id.to_string()),
                ("subject".into(), action.subject.to_string()),
                ("delegation_id".into(), action.delegation_id.clone()),
                ("workload_uid".into(), action.workload_uid.to_string()),
                ("profile_id".into(), action.profile_id.clone()),
                ("profile_sha256".into(), action.profile_sha256.clone()),
                ("destination_host".into(), action.destination_host.clone()),
                (
                    "destination_port".into(),
                    action.destination_port.to_string(),
                ),
                ("host_key_sha256".into(), action.host_key_sha256.clone()),
                ("vault_role".into(), action.vault_role.clone()),
                ("vault_ca_sha256".into(), action.vault_ca_sha256.clone()),
                ("principal".into(), action.principal.clone()),
                ("login_user".into(), action.login_user.clone()),
                ("source_address".into(), action.source_address.clone()),
                ("command".into(), action.command.clone()),
                (
                    "max_session_secs".into(),
                    action.max_session_secs.to_string(),
                ),
                ("grant_id".into(), action.grant_id.clone()),
            ]);
            if let Some(hash) = &action.workload_exe_sha256 {
                request
                    .target
                    .insert("workload_exe_sha256".into(), hash.clone());
            }
        }
        TaskAction::Inference(action) => {
            request.operation = "inference.fixed_completion".into();
            request.target = HashMap::from([
                ("tenant_id".into(), action.tenant.tenant_id.to_string()),
                ("broker_id".into(), action.tenant.broker_id.to_string()),
                ("profile_id".into(), action.profile_id.clone()),
                ("profile_sha256".into(), action.profile_sha256.clone()),
                ("model_id".into(), action.model_id.clone()),
                (
                    "model_artifact_sha256".into(),
                    action.model_artifact_sha256.clone(),
                ),
                ("source_id".into(), action.source_id.clone()),
                (
                    "source_snapshot_sha256".into(),
                    action.source_snapshot_sha256.clone(),
                ),
                ("prompt_sha256".into(), action.prompt_sha256.clone()),
            ]);
        }
        TaskAction::PublishSecret(action) => {
            request.operation = "github.set_actions_secret".into();
            request.target = HashMap::from([
                ("repo".into(), action.repo.clone()),
                ("secret_name".into(), action.secret_name.clone()),
            ]);
        }
        TaskAction::StagingRelease(action) => {
            request.operation = "github.dispatch_staging_workflow".into();
            request.target = HashMap::from([
                ("repo".into(), action.repo.clone()),
                ("workflow_path".into(), action.workflow_path.clone()),
                ("workflow_ref".into(), action.workflow_ref.clone()),
                (
                    "approved_commit_sha".into(),
                    action.approved_commit_sha.clone(),
                ),
                ("image_repository".into(), action.image_repository.clone()),
                ("image_digest".into(), action.image_digest.clone()),
                ("environment".into(), action.environment.clone()),
            ]);
        }
    }
    request
}

pub(super) fn approval_description(
    request: &OperationRequest,
    inference_profile: Option<&opaque_bounded_work::inference::TrustedInferenceProfile>,
    ssh_profile: Option<&opaque_bounded_work::ssh::TrustedSshProfile>,
) -> Result<String, EnclaveError> {
    let manifest: TaskManifest = serde_json::from_value(request.params["manifest"].clone())
        .map_err(|_| EnclaveError::InvalidInput("invalid task manifest".into()))?;
    manifest
        .validate()
        .map_err(|_| EnclaveError::InvalidInput("invalid task manifest".into()))?;
    if manifest.is_ssh() {
        let profile = ssh_profile.ok_or_else(|| {
            EnclaveError::InvalidInput("trusted SSH destination is unavailable".into())
        })?;
        opaque_bounded_work::ssh::prepare_ssh_manifest(&mut manifest.clone(), profile)
            .map_err(|_| EnclaveError::InvalidInput("SSH destination or signer changed".into()))?;
        let action = manifest.actions[0].as_ssh().expect("validated SSH action");
        return Ok(format!(
            "\nTask: {}\n{}Subject: {}\nDelegation session: {}\nObserved workload UID: {}\nExecutable SHA-256: {}\nProfile: {}\nProfile SHA-256: {}\nSSH destination: {}:{}\nHost key SHA-256: {}\nPrincipal: {}\nLogin user: {}\nAllowed source IP: {}\nExact command: {}\nGrant ID: {}\nVault role: {}\nVault CA SHA-256: {}\nVault credential reference: {}\nVault signing API: {}\nVault SSH mount: {}\nHost control API: {}\nHost receipt signer (Ed25519 public key hex): {}\nBroker grant signer file: {}\nAllowance: 1 connection attempt, permanently consumed before dispatch\nSession limit: {} seconds\nExpires: {}\n\nThe broker requests an ephemeral certificate from the configured Vault signer after approval and retains the private key. Shells, caller arguments, PTY, forwarding and subsystems are disabled. A verified host receipt reports only this fixed health observation. Unknown attempts consume allowance and cannot be retried under this task. Cancellation cannot undo a source read already accepted by the host. Host enforcement and the signing key are operator-managed; no hardware enclave attestation is claimed.\n",
            manifest.title,
            action.tenant.approval_context(),
            action.subject,
            action.delegation_id,
            action.workload_uid,
            action
                .workload_exe_sha256
                .as_deref()
                .unwrap_or("unavailable"),
            action.profile_id,
            action.profile_sha256,
            action.destination_host,
            action.destination_port,
            action.host_key_sha256,
            action.principal,
            action.login_user,
            action.source_address,
            action.command,
            action.grant_id,
            action.vault_role,
            action.vault_ca_sha256,
            action.vault_token_ref,
            sanitize_for_display(&profile.vault_url, 2048),
            sanitize_for_display(&profile.vault_mount, 64),
            sanitize_for_display(&profile.control_url, 2048),
            profile.receipt_public_key_hex,
            sanitize_for_display(&profile.grant_signing_key_path.display().to_string(), 4096),
            action.max_session_secs,
            request.params["expires_at"],
        ));
    }
    if manifest.is_inference() {
        let profile = inference_profile.ok_or_else(|| {
            EnclaveError::InvalidInput("trusted inference destination is unavailable".into())
        })?;
        // Derive recipient details directly from trusted broker state. A
        // profile hash is binding evidence, but cannot replace readable
        // destination information in a human review.
        opaque_bounded_work::inference::prepare_inference_manifest(&mut manifest.clone(), profile)
            .map_err(|_| EnclaveError::InvalidInput("inference destination changed".into()))?;
        let action = manifest.actions[0]
            .as_inference()
            .expect("validated inference");
        let mut text = format!(
            "\nTask: {}\n{}Profile: {}\nProfile SHA-256: {}\nModel: {}\nModel artifact SHA-256 (operator attestation): {}\nSource: {}\nSource snapshot SHA-256: {}\nBudget: 3 attempts, 96 requested output tokens each (288 reserved units)\nPer request: 512 input tokens, 30-second client deadline\nExpires: {}\n",
            manifest.title,
            action.tenant.approval_context(),
            action.profile_id,
            action.profile_sha256,
            action.model_id,
            action.model_artifact_sha256,
            action.source_id,
            action.source_snapshot_sha256,
            request.params["expires_at"],
        );
        text.push_str(&format!(
            "Inference API: {}\nService identity (operator attestation): {}\nServer build: {}\nChat template SHA-256: {}\nModel path (operator configuration): {}\n",
            profile.api_url, profile.service_uid, profile.server_build,
            profile.chat_template_sha256, profile.model_path,
        ));
        for action in &manifest.actions {
            let action = action.as_inference().expect("validated inference");
            text.push_str(&format!("\n{}. Fixed public source request\n   Prompt SHA-256: {}\n   Credential reference: {}\n", action.ordinal, action.prompt_sha256, action.credential_ref.as_deref().unwrap_or("none")));
            if let Some(prompt) = opaque_bounded_work::inference::demo_prompt(action.ordinal) {
                text.push_str(&format!("   Complete source and prompt: {prompt}\n"));
            }
        }
        text.push_str("\nThis grant permits disclosure of these synthetic public source records to the configured model provider. It permits no other sources, prompts, models, or generation options. Output limits are requested and checked; they do not attest GPU time or server cancellation. Unknown attempts consume allowance and stop later requests. No hardware enclave attestation is claimed.\n");
        return Ok(text);
    }
    let mut text = format!(
        "\nTask: {}\nGitHub: {}\nVault: {}\nBudget: {} writes, one attempt per slot\nExpires: {}\n",
        manifest.title,
        manifest.github_api_url,
        manifest.vault_api_url,
        manifest.actions.len(),
        request.params["expires_at"],
    );
    if let Some(value) = request
        .params
        .get("tenant")
        .filter(|value| !value.is_null())
    {
        let tenant: opaque_core::tenant::TenantBinding = serde_json::from_value(value.clone())
            .map_err(|_| EnclaveError::InvalidInput("invalid tenant binding".into()))?;
        tenant
            .validate()
            .map_err(|_| EnclaveError::InvalidInput("invalid tenant binding".into()))?;
        text.insert_str(0, &tenant.approval_context());
    }
    for (index, action) in manifest.actions.iter().enumerate() {
        match action {
            TaskAction::Inference(_) | TaskAction::SshHealth(_) => {
                unreachable!("typed review handled above")
            }
            TaskAction::PublishSecret(action) => {
                text.push_str(&format!(
                    "\n{}. {} (id {}) / {}\n   Source: {}\n   Credential: {}\n",
                    index + 1,
                    action.repo,
                    action.repository_id,
                    action.secret_name,
                    action.value_ref,
                    action.github_token_ref.as_deref().unwrap_or("missing"),
                ));
            }
            TaskAction::StagingRelease(action) => {
                text.push_str(&format!(
                "\n{}. {} (id {})\n   Workflow: {} (id {})\n   Protected branch: {}\n   Approved commit: {}\n   Trusted workflow SHA-256: {}\n   Artifact: {}@{}\n   Destination: {}\n   Credential: {}\n",
                index + 1, action.repo, action.repository_id, action.workflow_path, action.workflow_id,
                action.workflow_ref, action.approved_commit_sha, action.workflow_sha256,
                action.image_repository, action.image_digest, action.environment,
                action.github_token_ref.as_deref().unwrap_or("missing"),
            ));
                text.push_str("\nOne dispatch only. The protected workflow must enforce the approved commit and artifact. API acceptance and workflow success are separate evidence; neither alone proves service health. Rollback and reruns require new authority.\n");
            }
        }
    }
    text.push_str("\nGitHub acceptance does not prove deployment. Unknown writes cannot be retried under this task.\n");
    Ok(text)
}

/// Cancellation seals the task too: a timed-out PUT might have reached GitHub.
struct RunGuard<'a> {
    store: &'a TaskStore,
    owner: &'a str,
    id: &'a str,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        let _ = self.store.finish_run(self.id, self.owner, now_unix());
    }
}

impl Enclave {
    /// Read-only reconciliation has its own exact-scope policy rule. It may
    /// inspect an expired/revoked task, but never authorizes a new effect.
    pub fn preflight_task_observation(
        &self,
        base: &OperationRequest,
        manifest: &TaskManifest,
    ) -> Result<(), String> {
        manifest.validate().map_err(|e| e.to_string())?;
        if !manifest.is_release() {
            return Err("only staging releases have workflow observations".into());
        }
        let mut request = action_request(base, &manifest.actions[0]);
        request.operation = "github.observe_staging_workflow".into();
        let definition = self
            .registry
            .get(&request.operation)
            .map_err(|_| "release observation is unavailable")?;
        self.check_safety_constraints(&request, definition)
            .map_err(|e| e.to_string())?;
        let decision = self
            .policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .evaluate(&request, definition.safety);
        if !decision.allowed || decision.approval_requirement != ApprovalRequirement::Never {
            return Err("release observation requires an explicit read-only policy rule".into());
        }
        Ok(())
    }

    fn task_request_decision(
        &self,
        request: &OperationRequest,
    ) -> Result<(OperationDef, PolicyDecision), String> {
        if request.client_identity.uid == u32::MAX {
            return Err("task peer identity is unavailable".into());
        }
        let definition = self
            .registry
            .get(&request.operation)
            .map_err(|_| "task operation is not registered")?
            .clone();
        if request
            .target
            .keys()
            .any(|key| !definition.allowed_target_keys.contains(key))
        {
            return Err("task has an unexpected target".into());
        }
        if let Some(schema) = &definition.params_schema {
            validate_params(schema, &request.params).map_err(|_| "task parameters are invalid")?;
        }
        self.check_safety_constraints(request, &definition)
            .map_err(|_| "task violates an operation safety constraint")?;
        let mut decision = self
            .policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .evaluate(request, definition.safety);
        if !decision.allowed {
            return Err("task or one of its actions is denied by policy".into());
        }
        // The explicit task grant always requires a fresh approval, even when
        // a general-purpose policy has a weaker default.
        decision.approval_requirement = ApprovalRequirement::Always;
        if decision.required_factors.is_empty() {
            decision.required_factors = definition.default_factors.clone();
        }
        if decision.required_factors.is_empty() {
            return Err("task approval factor is not configured".into());
        }
        Ok((definition, decision))
    }

    /// Used before plan-time credential resolution and again at execution.
    pub fn preflight_task(
        &self,
        request: &mut OperationRequest,
        manifest: &TaskManifest,
    ) -> Result<(), String> {
        self.task_decision(request, manifest).map(|_| ())
    }

    fn task_decision(
        &self,
        request: &mut OperationRequest,
        manifest: &TaskManifest,
    ) -> Result<(OperationDef, PolicyDecision), String> {
        manifest.validate().map_err(|e| e.to_string())?;
        request.operation = manifest.operation_name().into();
        if manifest.is_ssh() {
            let profile = self.ssh_profile()?;
            opaque_bounded_work::ssh::prepare_ssh_manifest(&mut manifest.clone(), profile)?;
            let action = manifest.actions[0].as_ssh().ok_or("invalid SSH action")?;
            let principal = request
                .principal
                .as_ref()
                .ok_or("SSH requires authenticated delegation")?;
            if action.subject != principal.sub
                || action.delegation_id != principal.jti
                || action.workload_uid != request.client_identity.uid
                || action.workload_exe_sha256 != request.client_identity.exe_sha256
            {
                return Err("SSH subject, delegation or observed workload changed".into());
            }
        }
        if manifest.is_inference() {
            let profile = self.inference_profile()?;
            opaque_bounded_work::inference::prepare_inference_manifest(&mut manifest.clone(), profile)?;
        }
        request.secret_ref_names = manifest
            .actions
            .iter()
            .flat_map(TaskAction::secret_refs)
            .collect();
        request.secret_ref_names.sort();
        request.secret_ref_names.dedup();
        let (definition, mut decision) = self.task_request_decision(request)?;
        // Local review and the paired workstation protocol both bind a complete
        // review. Other operation types retain their existing factor choices.
        if decision.required_factors != [ApprovalFactor::LocalBio]
            && decision.required_factors != [ApprovalFactor::PairedWorkstation]
        {
            return Err(
                "bounded tasks require one complete review factor: local_bio or paired_workstation"
                    .into(),
            );
        }
        for action in &manifest.actions {
            let child = action_request(request, action);
            let (_, child_decision) = self.task_request_decision(&child)?;
            // Factor lists describe available alternatives. Unioning two
            // lists would weaken a stricter child rule, so tasks require equal
            // sets and rejects heterogeneous approvals explicitly.
            if decision.required_factors.len() != child_decision.required_factors.len()
                || !decision
                    .required_factors
                    .iter()
                    .all(|f| child_decision.required_factors.contains(f))
            {
                return Err("all task actions must require the same approval factors".into());
            }
            decision.require_distinct_approver |= child_decision.require_distinct_approver;
        }
        Ok((definition, decision))
    }

    /// Claim, approve and execute a stored manifest. Caller supplies fresh
    /// delegation/workspace verification before each provider dispatch.
    pub async fn execute_task<F, Fut>(
        &self,
        store: &TaskStore,
        owner: &str,
        id: &str,
        mut request: OperationRequest,
        approval_mode: TaskApprovalMode,
        check_context: F,
    ) -> Result<TaskRecord, String>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Option<PrincipalContext>, String>>,
    {
        let claimed = store
            .claim(id, owner, now_unix())
            .map_err(|e| e.to_string())?;
        let _guard = RunGuard { store, owner, id };
        request.target = HashMap::from([
            ("task_id".into(), claimed.id.clone()),
            ("manifest_digest".into(), claimed.manifest_digest.clone()),
        ]);
        request.params = serde_json::json!({"manifest": claimed.manifest, "expires_at": claimed.expires_at, "tenant": claimed.tenant});
        request.expires_at =
            Some(std::time::UNIX_EPOCH + Duration::from_secs(claimed.expires_at as u64));
        let generation = self.policy_generation.load(Ordering::SeqCst);
        let (definition, decision) = self.task_decision(&mut request, &claimed.manifest)?;
        let mut client = ClientSummary::from((&request.client_identity, request.client_type));
        if let Some(context) = &request.principal {
            client = client.with_principal(context);
        }
        let target = TargetSummary::sanitized(&request.target);
        self.audit.emit(
            AuditEvent::new(AuditEventKind::RequestReceived)
                .with_request_id(request.request_id)
                .with_client(client.clone())
                .with_operation(&request.operation)
                .with_target(target.clone())
                .with_secret_names(request.secret_ref_names.clone()),
        );
        self.handle_approval(&request, &definition, &decision, &client, &target)
            .await
            .map_err(|e| e.to_string())?;
        if self.policy_generation.load(Ordering::SeqCst) != generation {
            return Err("policy changed during task approval; create a fresh task".into());
        }
        let approval_mode = if approval_mode == TaskApprovalMode::Native
            && decision.required_factors == [ApprovalFactor::PairedWorkstation]
        {
            TaskApprovalMode::PairedWorkstation
        } else {
            approval_mode
        };
        store
            .approve(
                id,
                owner,
                &claimed.manifest_digest,
                approval_mode,
                now_unix(),
            )
            .map_err(|e| e.to_string())?;
        for slot in &claimed.slots {
            let context = check_context().await?;
            if context != request.principal
                || self.policy_generation.load(Ordering::SeqCst) != generation
            {
                return Err("task authority changed; create a fresh task".into());
            }
            self.task_decision(&mut request, &claimed.manifest)?;
            let request_id = Uuid::new_v4();
            store
                .reserve_slot(id, owner, &slot.id, &request_id.to_string(), now_unix())
                .map_err(|e| e.to_string())?;
            let child = action_request(&request, &slot.action);
            let child_target = TargetSummary::sanitized(&child.target);
            self.audit.emit(
                AuditEvent::new(AuditEventKind::OperationStarted)
                    .with_request_id(request_id)
                    .with_client(client.clone())
                    .with_operation(&child.operation)
                    .with_target(child_target.clone())
                    .with_request_hash(&claimed.manifest_digest)
                    .with_detail(format!("task={id} slot={}", slot.id)),
            );
            let before_dispatch = || async {
                let rejected = |code: &str| SlotOutcome {
                    ssh_receipt: None,
                    inference_receipt: None,
                    provider_run_id: None,
                    state: SlotState::Rejected,
                    code: code.into(),
                };
                let context = check_context()
                    .await
                    .map_err(|_| rejected("policy_denied"))?;
                if context != request.principal
                    || self.policy_generation.load(Ordering::SeqCst) != generation
                {
                    return Err(rejected("policy_denied"));
                }
                self.task_decision(&mut request.clone(), &claimed.manifest)
                    .map_err(|_| rejected("policy_denied"))?;
                // This final ledger check is the dispatch authorization boundary.
                // Revocation after it cannot recall an already authorized HTTP request.
                store
                    .authorize_dispatch(id, owner, &slot.id, &request_id.to_string(), now_unix())
                    .map_err(|error| {
                        rejected(match error {
                            TaskStoreError::Expired => "expired",
                            TaskStoreError::Revoked => "revoked",
                            _ => "policy_denied",
                        })
                    })?;
                Ok(())
            };
            let outcome = match &slot.action {
                TaskAction::SshHealth(action) => {
                    opaque_bounded_work::ssh::execute_ssh_action(
                        action,
                        self.ssh_profile()?,
                        claimed.expires_at,
                        before_dispatch,
                    )
                    .await
                }
                TaskAction::Inference(action) => {
                    let profile = self.inference_profile()?;
                    let execution = opaque_bounded_work::inference::execute_inference_action(
                        &claimed.manifest,
                        action,
                        profile,
                        before_dispatch,
                    )
                    .await;
                    let mut outcome = execution.outcome;
                    outcome.inference_receipt = execution.receipt;
                    outcome
                }
                TaskAction::PublishSecret(action) => {
                    opaque_providers::github::execute_task_action(
                        &claimed.manifest,
                        action,
                        before_dispatch,
                    )
                    .await
                }
                TaskAction::StagingRelease(action) => {
                    opaque_providers::github::dispatch_staging_release(
                        &claimed.manifest,
                        action,
                        id,
                        before_dispatch,
                    )
                    .await
                }
            };
            let accepted = outcome.state == SlotState::ApiAccepted;
            self.audit.emit(
                AuditEvent::new(if accepted {
                    AuditEventKind::OperationSucceeded
                } else {
                    AuditEventKind::OperationFailed
                })
                .with_request_id(request_id)
                .with_client(client.clone())
                .with_operation(&child.operation)
                .with_target(child_target)
                .with_request_hash(&claimed.manifest_digest)
                .with_outcome(&outcome.code)
                .with_detail(format!("task={id} slot={}", slot.id)),
            );
            store
                .finalize_slot(
                    id,
                    owner,
                    &slot.id,
                    &request_id.to_string(),
                    outcome,
                    now_unix(),
                )
                .map_err(|e| e.to_string())?;
            if !accepted {
                break;
            }
        }
        store
            .finish_run(id, owner, now_unix())
            .map_err(|e| e.to_string())
    }
}

/// `opaque_bounded_work::task_api` cannot name `Enclave` (`opaqued` has no
/// `lib.rs`), so it depends on this trait instead — the same "narrow trait
/// defined by the crate that needs it, `opaqued` implements it" direction as
/// `opaque_bounded_work::resource_authority::IdentityAuthority` for
/// `identity::IdentityRuntime`. Every method here just delegates to the
/// matching inherent method above/in `enclave.rs`: Rust always resolves
/// `self.method()` to an inherent method over a trait method of the same
/// name, even from within that trait's own `impl` block, so there is no
/// infinite recursion here.
impl opaque_bounded_work::task_facade::BoundedWorkFacade for Enclave {
    fn ssh_profile(&self) -> Result<&opaque_bounded_work::ssh::TrustedSshProfile, String> {
        self.ssh_profile()
    }

    fn inference_profile(
        &self,
    ) -> Result<&opaque_bounded_work::inference::TrustedInferenceProfile, String> {
        self.inference_profile()
    }

    fn execute_task<'a>(
        &'a self,
        store: &'a TaskStore,
        owner: &'a str,
        id: &'a str,
        request: OperationRequest,
        approval_mode: TaskApprovalMode,
        check_context: opaque_bounded_work::task_facade::CheckContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<TaskRecord, String>> + Send + 'a>> {
        // `check_context: Box<dyn Fn() -> Pin<Box<dyn Future<...> + Send>> + Send + Sync>`
        // itself implements `Fn() -> Pin<Box<dyn Future<...> + Send>>`, and
        // that return type implements `Future<Output = ...>` — so it
        // satisfies the inherent method's generic `F: Fn() -> Fut` bound
        // directly, with no adapter needed.
        Box::pin(self.execute_task(store, owner, id, request, approval_mode, check_context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::policy::PolicyRule;
    use opaque_core::task::PublishAction;
    use opaque_core::task::TaskState;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Notify;

    #[derive(Debug)]
    struct Gate {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        calls: Arc<AtomicUsize>,
        descriptions: Arc<Mutex<Vec<String>>>,
        approved: bool,
    }
    impl ApprovalGate for Gate {
        fn request_approval(
            &self,
            _: Uuid,
            _: &OperationRequest,
            _: &[ApprovalFactor],
            description: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.descriptions
                .lock()
                .unwrap()
                .push(description.to_owned());
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(if self.approved {
                    ApprovalOutcome::approved_anonymous()
                } else {
                    ApprovalOutcome::denied()
                })
            })
        }
    }
    fn rule(operation: &str) -> PolicyRule {
        serde_json::from_value(serde_json::json!({
            "name": operation, "operation_pattern": operation, "allow": true,
            "client_types": ["agent", "human"],
            "approval": {"require": "never", "factors": ["local_bio"]}
        }))
        .unwrap()
    }
    fn manifest() -> TaskManifest {
        TaskManifest {
            schema_version: 1,
            title: "Dogfood test".into(),
            expires_in_secs: 600,
            github_api_url: "https://api.github.com".into(),
            vault_api_url: "https://vault.example.com".into(),
            actions: vec![
                PublishAction {
                    repo: "example/app".into(),
                    repository_id: 42,
                    secret_name: "DOGFOOD_MARKER".into(),
                    value_ref: "vault:kv/data/dogfood?version=7#VALUE".into(),
                    github_token_ref: Some("env:DOGFOOD_PAT".into()),
                }
                .into(),
            ],
        }
    }
    fn request() -> OperationRequest {
        OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_type: ClientType::Agent,
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(4242),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            operation: "github.publish_manifest".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::Value::Null,
            workspace: None,
        }
    }
    struct Fixture {
        _directory: tempfile::TempDir,
        enclave: Arc<Enclave>,
        store: Arc<TaskStore>,
        id: String,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        calls: Arc<AtomicUsize>,
        descriptions: Arc<Mutex<Vec<String>>>,
    }
    impl Fixture {
        fn new(approved: bool, child_allowed: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let store = Arc::new(TaskStore::open(&directory.path().join("tasks.db")).unwrap());
            let id = store.create("owner", manifest(), now_unix()).unwrap().id;
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let calls = Arc::new(AtomicUsize::new(0));
            let descriptions = Arc::new(Mutex::new(vec![]));
            let mut registry = OperationRegistry::new();
            registry.register(task_operation()).unwrap();
            registry
                .register(OperationDef {
                    name: "github.set_actions_secret".into(),
                    safety: OperationSafety::Safe,
                    default_approval: ApprovalRequirement::Always,
                    default_factors: vec![ApprovalFactor::LocalBio],
                    description: "Publish secret".into(),
                    params_schema: None,
                    allowed_target_keys: vec!["repo".into(), "secret_name".into()],
                    secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
                })
                .unwrap();
            let mut rules = vec![rule("github.publish_manifest")];
            if child_allowed {
                rules.push(rule("github.set_actions_secret"));
            }
            let enclave = Arc::new(
                Enclave::builder()
                    .registry(registry)
                    .policy(PolicyEngine::with_rules(rules))
                    .approval_gate(Box::new(Gate {
                        entered: entered.clone(),
                        release: release.clone(),
                        calls: calls.clone(),
                        descriptions: descriptions.clone(),
                        approved,
                    }))
                    .audit(Arc::new(InMemoryAuditEmitter::new()))
                    .build()
                    .unwrap(),
            );
            Self {
                _directory: directory,
                enclave,
                store,
                id,
                entered,
                release,
                calls,
                descriptions,
            }
        }
        fn run(&self) -> tokio::task::JoinHandle<Result<TaskRecord, String>> {
            let enclave = self.enclave.clone();
            let store = self.store.clone();
            let id = self.id.clone();
            tokio::spawn(async move {
                enclave
                    .execute_task(
                        &store,
                        "owner",
                        &id,
                        request(),
                        TaskApprovalMode::InsecureTest,
                        || async { Err("test context revoked".into()) },
                    )
                    .await
            })
        }
    }

    struct InferenceFixture {
        _directory: tempfile::TempDir,
        provider_canary: std::net::TcpListener,
        profile: opaque_bounded_work::inference::TrustedInferenceProfile,
        enclave: Arc<Enclave>,
        audit: Arc<InMemoryAuditEmitter>,
        store: Arc<TaskStore>,
        task: TaskRecord,
        owner: String,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        calls: Arc<AtomicUsize>,
        context_checks: Arc<AtomicUsize>,
        descriptions: Arc<Mutex<Vec<String>>>,
    }

    fn inference_rules(profile: &opaque_bounded_work::inference::TrustedInferenceProfile) -> Vec<PolicyRule> {
        let parent = rule("inference.fixed_manifest");
        let mut child = rule("inference.fixed_completion");
        child.target.fields = HashMap::from([
            ("source_id".into(), profile.source_id.clone()),
            ("tenant_id".into(), profile.tenant.tenant_id.to_string()),
            ("broker_id".into(), profile.tenant.broker_id.to_string()),
            ("model_id".into(), profile.model_id.clone()),
            ("profile_sha256".into(), profile.digest().unwrap()),
        ]);
        child.secret_names = serde_json::from_value(serde_json::json!({
            "patterns": ["keychain:opaque/inference-fixture"]
        }))
        .unwrap();
        vec![parent, child]
    }

    impl InferenceFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let provider_canary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            provider_canary.set_nonblocking(true).unwrap();
            let tenant = opaque_core::tenant::TenantBinding::new(
                opaque_core::tenant::TenantId::parse("inference-tenant").unwrap(),
                Uuid::new_v4(),
            )
            .unwrap();
            let profile = opaque_bounded_work::inference::InferenceProfileConfig {
                profile_id: "review-fixture".into(),
                api_url: format!("http://{}", provider_canary.local_addr().unwrap()),
                model_id: "public-fixture.gguf".into(),
                model_path: "/models/public-fixture.gguf".into(),
                model_artifact_sha256: "a".repeat(64),
                chat_template_sha256: "b".repeat(64),
                server_build: "review-fixture-v1".into(),
                service_uid: Uuid::new_v4(),
                source_id: opaque_bounded_work::inference::DEMO_SOURCE_ID.into(),
                source_snapshot_sha256: opaque_bounded_work::inference::demo_source_snapshot_sha256(),
                credential_ref: Some("keychain:opaque/inference-fixture".into()),
                allow_loopback_http: true,
            }
            .bind(&tenant)
            .unwrap();
            let manifest = opaque_bounded_work::inference::public_demo_manifest(
                &profile,
                "Review all three public requests".into(),
                600,
            )
            .unwrap();
            let owner = tenant.owner_key(501, None);
            let store = Arc::new(
                TaskStore::open_for_tenant(&directory.path().join("tasks.db"), Some(tenant))
                    .unwrap(),
            );
            let task = store.create(&owner, manifest, now_unix()).unwrap();
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let calls = Arc::new(AtomicUsize::new(0));
            let context_checks = Arc::new(AtomicUsize::new(0));
            let descriptions = Arc::new(Mutex::new(vec![]));
            let audit = Arc::new(InMemoryAuditEmitter::new());
            let mut registry = OperationRegistry::new();
            for operation in inference_task_operations() {
                registry.register(operation).unwrap();
            }
            let enclave = Arc::new(
                Enclave::builder()
                    .registry(registry)
                    .policy(PolicyEngine::with_rules(inference_rules(&profile)))
                    .inference_profile(Some(profile.clone()))
                    .approval_gate(Box::new(Gate {
                        entered: entered.clone(),
                        release: release.clone(),
                        calls: calls.clone(),
                        descriptions: descriptions.clone(),
                        approved: true,
                    }))
                    .audit(audit.clone())
                    .build()
                    .unwrap(),
            );
            Self {
                _directory: directory,
                provider_canary,
                profile,
                enclave,
                audit,
                store,
                task,
                owner,
                entered,
                release,
                calls,
                context_checks,
                descriptions,
            }
        }

        fn run(&self) -> tokio::task::JoinHandle<Result<TaskRecord, String>> {
            let enclave = self.enclave.clone();
            let store = self.store.clone();
            let id = self.task.id.clone();
            let owner = self.owner.clone();
            let context_checks = self.context_checks.clone();
            tokio::spawn(async move {
                enclave
                    .execute_task(
                        &store,
                        &owner,
                        &id,
                        request(),
                        TaskApprovalMode::InsecureTest,
                        || {
                            context_checks.fetch_add(1, Ordering::SeqCst);
                            async {
                                Err("fixture context withdrawn before provider dispatch".into())
                            }
                        },
                    )
                    .await
            })
        }

        fn assert_no_provider_attempt(&self) -> TaskRecord {
            let task = self
                .store
                .get(&self.task.id, &self.owner, now_unix())
                .unwrap();
            assert!(task.slots.iter().all(|slot| slot.reserved_at.is_none()));
            assert!(
                self.audit
                    .events_of_kind(AuditEventKind::OperationStarted)
                    .is_empty()
            );
            match self.provider_canary.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("provider was contacted: {other:?}"),
            }
            task
        }
    }

    #[tokio::test]
    async fn inference_approval_reviews_all_prompts_tenant_destination_and_budget() {
        let fixture = InferenceFixture::new();
        let run = fixture.run();
        fixture.entered.notified().await;
        {
            let descriptions = fixture.descriptions.lock().unwrap();
            let description = &descriptions[0];
            for expected in [
                fixture.profile.tenant.approval_context(),
                fixture.profile.api_url.clone(),
                fixture.profile.service_uid.to_string(),
                fixture.profile.server_build.clone(),
                fixture.profile.chat_template_sha256.clone(),
                fixture.profile.model_path.clone(),
                fixture.profile.model_id.clone(),
                fixture.profile.model_artifact_sha256.clone(),
                fixture.profile.source_id.clone(),
                fixture.profile.source_snapshot_sha256.clone(),
                fixture.profile.digest().unwrap(),
                fixture.task.manifest_digest.clone(),
                fixture.task.expires_at.to_string(),
                fixture.profile.credential_ref.clone().unwrap(),
                "3 attempts, 96 requested output tokens each (288 reserved units)".into(),
                "512 input tokens, 30-second client deadline".into(),
            ] {
                assert!(description.contains(&expected), "review omitted {expected}");
            }
            for action in &fixture.task.manifest.actions {
                let action = action.as_inference().unwrap();
                let prompt = opaque_bounded_work::inference::demo_prompt(action.ordinal).unwrap();
                assert_eq!(description.matches(prompt).count(), 1);
                assert!(description.contains(&action.prompt_sha256));
            }
            assert!(description.contains("operator attestation"));
            assert!(description.contains("do not attest GPU time or server cancellation"));
        }
        fixture.assert_no_provider_attempt();
        fixture.release.notify_one();
        assert!(
            run.await
                .unwrap()
                .unwrap_err()
                .contains("context withdrawn")
        );
        assert_eq!(fixture.context_checks.load(Ordering::SeqCst), 1);
        let task = fixture.assert_no_provider_attempt();
        assert!(task.approved_at.is_some());
        assert_eq!(task.approval_mode, Some(TaskApprovalMode::InsecureTest));
        assert_eq!(task.state, TaskState::Partial);
    }

    #[tokio::test]
    async fn inference_wrong_source_policy_denies_before_prompt_or_provider() {
        let fixture = InferenceFixture::new();
        let mut rules = inference_rules(&fixture.profile);
        rules[1]
            .target
            .fields
            .insert("source_id".into(), "another-source".into());
        fixture.enclave.swap_policy(PolicyEngine::with_rules(rules));
        assert!(
            fixture
                .run()
                .await
                .unwrap()
                .unwrap_err()
                .contains("denied by policy")
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.context_checks.load(Ordering::SeqCst), 0);
        let task = fixture.assert_no_provider_attempt();
        assert_eq!(task.state, TaskState::Partial);
        assert_eq!(task.approved_at, None);
    }

    #[tokio::test]
    async fn inference_policy_broadening_while_review_waits_requires_fresh_grant() {
        let fixture = InferenceFixture::new();
        let run = fixture.run();
        fixture.entered.notified().await;
        fixture
            .enclave
            .swap_policy(PolicyEngine::with_rules(vec![rule("inference.*")]));
        fixture.release.notify_one();
        assert!(run.await.unwrap().unwrap_err().contains("policy changed"));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.context_checks.load(Ordering::SeqCst), 0);
        let task = fixture.assert_no_provider_attempt();
        assert_eq!(task.approved_at, None);
        assert_eq!(task.state, TaskState::Partial);
        assert!(fixture.run().await.unwrap().is_err());
    }

    #[test]
    fn inference_preflight_rejects_changed_profile_source_model_credential_or_prompt() {
        let fixture = InferenceFixture::new();
        fixture
            .enclave
            .preflight_task(&mut request(), &fixture.task.manifest)
            .unwrap();
        for field in 0..7 {
            let mut changed = fixture.task.manifest.clone();
            for action in &mut changed.actions {
                let action = action.as_inference_mut().unwrap();
                match field {
                    0 => action.profile_sha256 = "c".repeat(64),
                    1 => action.source_id = "other-source".into(),
                    2 => action.source_snapshot_sha256 = "c".repeat(64),
                    3 => action.model_id = "other-model.gguf".into(),
                    4 => action.model_artifact_sha256 = "c".repeat(64),
                    5 => action.credential_ref = Some("keychain:opaque/other-credential".into()),
                    _ => action.prompt_sha256 = "c".repeat(64),
                }
            }
            // These are structurally valid requests, but none match the
            // server-selected profile and compiled source snapshot.
            changed.validate().unwrap();
            assert!(
                fixture
                    .enclave
                    .preflight_task(&mut request(), &changed)
                    .is_err()
            );
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        fixture.assert_no_provider_attempt();
    }

    #[test]
    fn inference_review_uses_trusted_recipient_and_refuses_stale_profile() {
        let fixture = InferenceFixture::new();
        let mut request = request();
        request.params = serde_json::json!({
            "manifest": fixture.task.manifest, "expires_at": fixture.task.expires_at,
            "inference_destination": {"api_url": "https://untrusted.invalid", "service_uid": Uuid::new_v4()}
        });
        let reviewed = approval_description(&request, Some(&fixture.profile), None).unwrap();
        assert!(reviewed.contains(&fixture.profile.api_url));
        assert!(!reviewed.contains("untrusted.invalid"));
        assert!(approval_description(&request, None, None).is_err());
        for field in 0..5 {
            let mut config = fixture.profile.config.clone();
            match field {
                0 => config.api_url = "https://other-provider.invalid".into(),
                1 => config.service_uid = Uuid::new_v4(),
                2 => config.server_build = "other-build".into(),
                3 => config.chat_template_sha256 = "c".repeat(64),
                _ => config.model_path = "/models/other-location.gguf".into(),
            }
            let changed = config.bind(&fixture.profile.tenant).unwrap();
            assert!(approval_description(&request, Some(&changed), None).is_err());
            let fresh =
                opaque_bounded_work::inference::public_demo_manifest(&changed, "New recipient grant".into(), 600)
                    .unwrap();
            assert_ne!(fresh.digest().unwrap(), fixture.task.manifest_digest);
            let mut fresh_request = request.clone();
            fresh_request.params["manifest"] = serde_json::to_value(fresh).unwrap();
            let review = approval_description(&fresh_request, Some(&changed), None).unwrap();
            assert!(review.contains(&changed.api_url));
            assert!(review.contains(&changed.service_uid.to_string()));
            assert!(review.contains(&changed.server_build));
            assert!(review.contains(&changed.chat_template_sha256));
            assert!(review.contains(&changed.model_path));
        }
        fixture.assert_no_provider_attempt();
    }

    #[tokio::test]
    async fn denied_child_never_prompts_and_seals_task() {
        let fixture = Fixture::new(true, false);
        assert!(fixture.run().await.unwrap().is_err());
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .store
                .get(&fixture.id, "owner", now_unix())
                .unwrap()
                .state,
            TaskState::Partial
        );
    }

    #[tokio::test]
    async fn concurrent_runs_have_one_prompt_and_denied_task_cannot_resume() {
        let fixture = Fixture::new(false, true);
        let first = fixture.run();
        fixture.entered.notified().await;
        assert!(fixture.run().await.unwrap().is_err());
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        fixture.release.notify_one();
        assert!(first.await.unwrap().is_err());
        assert!(fixture.run().await.unwrap().is_err());
        let task = fixture.store.get(&fixture.id, "owner", now_unix()).unwrap();
        assert_eq!(task.state, TaskState::Partial);
        assert_eq!(task.approved_at, None);
        assert!(task.slots.iter().all(|s| s.reserved_at.is_none()));
    }

    #[tokio::test]
    async fn cancelling_approval_seals_claim_without_reusing_budget() {
        let fixture = Fixture::new(true, true);
        let run = fixture.run();
        fixture.entered.notified().await;
        run.abort();
        assert!(run.await.is_err());
        assert_eq!(
            fixture
                .store
                .get(&fixture.id, "owner", now_unix())
                .unwrap()
                .state,
            TaskState::Partial
        );
        assert!(fixture.run().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn policy_change_during_approval_invalidates_the_run() {
        let fixture = Fixture::new(true, true);
        let run = fixture.run();
        fixture.entered.notified().await;
        fixture
            .enclave
            .swap_policy(PolicyEngine::with_rules(vec![rule("github.*")]));
        fixture.release.notify_one();
        assert!(run.await.unwrap().unwrap_err().contains("policy changed"));
        assert_eq!(
            fixture
                .store
                .get(&fixture.id, "owner", now_unix())
                .unwrap()
                .approved_at,
            None
        );
    }

    #[tokio::test]
    async fn lost_context_after_approval_never_reserves_a_slot() {
        let fixture = Fixture::new(true, true);
        let run = fixture.run();
        fixture.entered.notified().await;
        fixture.release.notify_one();
        assert!(run.await.unwrap().is_err());
        let task = fixture.store.get(&fixture.id, "owner", now_unix()).unwrap();
        assert!(task.approved_at.is_some());
        assert_eq!(task.state, TaskState::Partial);
        assert!(task.slots.iter().all(|s| s.reserved_at.is_none()));
        let descriptions = fixture.descriptions.lock().unwrap();
        let description = &descriptions[0];
        assert!(description.contains("example/app (id 42) / DOGFOOD_MARKER"));
        assert!(description.contains("vault:kv/data/dogfood?version=7#VALUE"));
        assert!(description.contains(&task.manifest_digest));
        assert!(description.contains("Budget: 1 writes"));
    }

    #[test]
    fn secret_constraints_check_both_pinned_source_and_broker_credential() {
        let fixture = Fixture::new(true, true);
        let mut restricted = rule("github.*");
        restricted.secret_names =
            serde_json::from_value(serde_json::json!({"patterns": ["vault:*"]})).unwrap();
        fixture
            .enclave
            .swap_policy(PolicyEngine::with_rules(vec![restricted]));
        assert!(
            fixture
                .enclave
                .preflight_task(&mut request(), &manifest())
                .is_err()
        );
    }

    #[test]
    fn task_approval_cannot_race_an_unreviewed_alternate_factor() {
        let fixture = Fixture::new(true, true);
        let mut alternative = rule("github.*");
        alternative.approval.factors = vec![ApprovalFactor::LocalBio, ApprovalFactor::Fido2];
        fixture
            .enclave
            .swap_policy(PolicyEngine::with_rules(vec![alternative]));
        assert!(
            fixture
                .enclave
                .preflight_task(&mut request(), &manifest())
                .unwrap_err()
                .contains("one complete review factor")
        );
    }

    #[test]
    fn paired_review_must_be_required_by_parent_and_every_child() {
        let fixture = Fixture::new(true, true);
        let mut parent = rule("github.publish_manifest");
        parent.approval.factors = vec![ApprovalFactor::PairedWorkstation];
        let mut child = rule("github.set_actions_secret");
        fixture.enclave.swap_policy(PolicyEngine::with_rules(vec![
            parent.clone(),
            child.clone(),
        ]));
        assert!(
            fixture
                .enclave
                .preflight_task(&mut request(), &manifest())
                .is_err()
        );
        child.approval.factors = vec![ApprovalFactor::PairedWorkstation];
        fixture
            .enclave
            .swap_policy(PolicyEngine::with_rules(vec![parent, child]));
        assert!(
            fixture
                .enclave
                .preflight_task(&mut request(), &manifest())
                .is_ok()
        );
    }

    #[test]
    fn observation_requires_read_policy_for_exact_target_and_credential() {
        let mut registry = OperationRegistry::new();
        for operation in release_task_operations() {
            registry.register(operation).unwrap();
        }
        let enclave = Enclave::builder()
            .registry(registry)
            .policy(PolicyEngine::with_rules(vec![]))
            .approval_gate(Box::new(Gate {
                entered: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
                calls: Arc::new(AtomicUsize::new(0)),
                descriptions: Arc::new(Mutex::new(vec![])),
                approved: false,
            }))
            .audit(Arc::new(InMemoryAuditEmitter::new()))
            .build()
            .unwrap();
        let release = TaskManifest {
            schema_version: 2,
            title: "Reviewed staging artifact".into(),
            expires_in_secs: 600,
            github_api_url: "https://api.github.com".into(),
            vault_api_url: String::new(),
            actions: vec![
                opaque_core::release::StagingReleaseAction {
                    operation: "github.dispatch_staging_workflow".into(),
                    repo: "example/app".into(),
                    repository_id: 42,
                    workflow_path: ".github/workflows/staging.yml".into(),
                    workflow_id: 17,
                    workflow_ref: "main".into(),
                    approved_commit_sha: "a".repeat(40),
                    workflow_sha256: "b".repeat(64),
                    image_repository: "ghcr.io/example/app".into(),
                    image_digest: format!("sha256:{}", "c".repeat(64)),
                    environment: "staging".into(),
                    github_token_ref: Some("env:READ_PAT".into()),
                }
                .into(),
            ],
        };
        assert!(
            enclave
                .preflight_task_observation(&request(), &release)
                .is_err()
        );
        let mut read = rule("github.observe_staging_workflow");
        read.target.fields = HashMap::from([
            ("repo".into(), "example/app".into()),
            ("environment".into(), "staging".into()),
            ("image_digest".into(), format!("sha256:{}", "c".repeat(64))),
        ]);
        read.secret_names = serde_json::from_value(serde_json::json!({
            "patterns": ["env:READ_PAT"]
        }))
        .unwrap();
        enclave.swap_policy(PolicyEngine::with_rules(vec![read.clone()]));
        assert!(
            enclave
                .preflight_task_observation(&request(), &release)
                .is_ok()
        );
        let mut different_target = release.clone();
        different_target.actions[0]
            .as_release_mut()
            .unwrap()
            .image_digest = format!("sha256:{}", "d".repeat(64));
        assert!(
            enclave
                .preflight_task_observation(&request(), &different_target)
                .is_err()
        );
        let mut different_credential = release.clone();
        different_credential.actions[0]
            .as_release_mut()
            .unwrap()
            .github_token_ref = Some("env:OTHER_PAT".into());
        assert!(
            enclave
                .preflight_task_observation(&request(), &different_credential)
                .is_err()
        );
        read.approval.require = ApprovalRequirement::Always;
        enclave.swap_policy(PolicyEngine::with_rules(vec![read]));
        assert!(
            enclave
                .preflight_task_observation(&request(), &release)
                .is_err()
        );
    }

    fn ssh_action_fixture() -> TaskAction {
        serde_json::from_value(serde_json::json!({
            "operation":"ssh.service_health",
            "tenant":{"schema_version":1,"tenant_id":"tenant-a","broker_id":"00000000-0000-4000-8000-000000000001"},
            "subject":"hum_00000000000000000000000000000001", "delegation_id":"session-1",
            "workload_uid":501, "profile_id":"fixture-health", "profile_sha256":"a".repeat(64),
            "destination_host":"192.0.2.1", "destination_port":22, "host_key_sha256":"b".repeat(64),
            "vault_role":"fixture-health", "vault_ca_sha256":"c".repeat(64), "vault_token_ref":"env:VAULT_SIGNER_TOKEN",
            "principal":"fixture-health", "login_user":"opaque", "source_address":"192.0.2.2",
            "command":"opaque-service-health", "max_session_secs":30,
            "grant_id":"00000000-0000-4000-8000-000000000002"
        })).unwrap()
    }

    #[test]
    fn ssh_policy_checks_every_bound_destination_and_signer_credential() {
        let action = ssh_action_fixture();
        let mut base = request();
        base.secret_ref_names = vec!["env:UNTRUSTED_CALLER_CLAIM".into()];
        let child = action_request(&base, &action);
        let mut registry = OperationRegistry::new();
        for operation in ssh_task_operations() {
            registry.register(operation).unwrap();
        }
        let definition = registry.get(&child.operation).unwrap();
        assert!(
            child
                .target
                .keys()
                .all(|key| definition.allowed_target_keys.contains(key))
        );
        assert_eq!(child.secret_ref_names, ["env:VAULT_SIGNER_TOKEN"]);
        let mut allowed = rule("ssh.service_health");
        allowed.target.fields = child.target.clone();
        allowed.secret_names =
            serde_json::from_value(serde_json::json!({"patterns":["env:VAULT_SIGNER_TOKEN"]}))
                .unwrap();
        let enclave = Enclave::builder()
            .registry(registry)
            .policy(PolicyEngine::with_rules(vec![allowed]))
            .approval_gate(Box::new(Gate {
                entered: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
                calls: Arc::new(AtomicUsize::new(0)),
                descriptions: Arc::new(Mutex::new(vec![])),
                approved: false,
            }))
            .audit(Arc::new(InMemoryAuditEmitter::new()))
            .build()
            .unwrap();
        enclave.task_request_decision(&child).unwrap();
        for key in child.target.keys() {
            let mut changed = child.clone();
            changed.target.insert(key.clone(), "other-authority".into());
            assert!(
                enclave.task_request_decision(&changed).is_err(),
                "unbound policy target {key}"
            );
        }
        let mut changed = action.clone();
        changed.as_ssh_mut().unwrap().vault_token_ref = "env:OTHER_TOKEN".into();
        assert!(
            enclave
                .task_request_decision(&action_request(&base, &changed))
                .is_err()
        );
        let manifest = TaskManifest {
            schema_version: 4,
            title: "SSH health".into(),
            expires_in_secs: 300,
            github_api_url: String::new(),
            vault_api_url: String::new(),
            actions: vec![action],
        };
        assert!(
            enclave
                .preflight_task(&mut base, &manifest)
                .unwrap_err()
                .contains("not configured")
        );
        assert!(!enclave.handlers.contains_key("ssh.service_health"));
    }

    fn ssh_request_fixture() -> OperationRequest {
        let mut request = request();
        request.principal = Some(
            serde_json::from_value(serde_json::json!({
                "sub":"hum_00000000000000000000000000000001", "sub_label":"Fixture operator",
                "sub_roles":[], "sub_teams":[], "act":"agt_00000000000000000000000000000002",
                "act_label":"Fixture agent", "mode":"delegated", "jti":"session-1"
            }))
            .unwrap(),
        );
        request
    }

    struct SshFixture {
        _directory: tempfile::TempDir,
        provider_canary: std::net::TcpListener,
        profile: opaque_bounded_work::ssh::TrustedSshProfile,
        enclave: Arc<Enclave>,
        store: Arc<TaskStore>,
        task: TaskRecord,
        owner: String,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        calls: Arc<AtomicUsize>,
        descriptions: Arc<Mutex<Vec<String>>>,
    }
    impl SshFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let provider_canary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            provider_canary.set_nonblocking(true).unwrap();
            let mut profile = opaque_bounded_work::ssh::test_profile();
            profile.config.vault_url = format!("http://{}", provider_canary.local_addr().unwrap());
            profile.config.control_url = profile.vault_url.clone();
            profile.config.allow_loopback_http = true;
            let request = ssh_request_fixture();
            let manifest = opaque_bounded_work::ssh::health_manifest(
                &profile,
                "One fixed service health read".into(),
                300,
                request.principal.as_ref().unwrap(),
                &request.client_identity,
            )
            .unwrap();
            let owner = profile.tenant.owner_key(
                request.client_identity.uid,
                request.principal.as_ref().map(|p| &p.sub),
            );
            let store = Arc::new(
                TaskStore::open_for_tenant(
                    &directory.path().join("ssh-tasks.db"),
                    Some(profile.tenant.clone()),
                )
                .unwrap(),
            );
            let task = store.create(&owner, manifest, now_unix()).unwrap();
            let mut registry = OperationRegistry::new();
            for operation in ssh_task_operations() {
                registry.register(operation).unwrap();
            }
            let mut child = rule("ssh.service_health");
            child.target.fields = action_request(&request, &task.manifest.actions[0]).target;
            child.secret_names =
                serde_json::from_value(serde_json::json!({"patterns":[profile.vault_token_ref]}))
                    .unwrap();
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let calls = Arc::new(AtomicUsize::new(0));
            let descriptions = Arc::new(Mutex::new(vec![]));
            let enclave = Arc::new(
                Enclave::builder()
                    .registry(registry)
                    .policy(PolicyEngine::with_rules(vec![
                        rule("ssh.health_manifest"),
                        child,
                    ]))
                    .ssh_profile(Some(profile.clone()))
                    .approval_gate(Box::new(Gate {
                        entered: entered.clone(),
                        release: release.clone(),
                        calls: calls.clone(),
                        descriptions: descriptions.clone(),
                        approved: true,
                    }))
                    .audit(Arc::new(InMemoryAuditEmitter::new()))
                    .build()
                    .unwrap(),
            );
            Self {
                _directory: directory,
                provider_canary,
                profile,
                enclave,
                store,
                task,
                owner,
                entered,
                release,
                calls,
                descriptions,
            }
        }
        fn run(&self) -> tokio::task::JoinHandle<Result<TaskRecord, String>> {
            let enclave = self.enclave.clone();
            let store = self.store.clone();
            let id = self.task.id.clone();
            let owner = self.owner.clone();
            tokio::spawn(async move {
                enclave
                    .execute_task(
                        &store,
                        &owner,
                        &id,
                        ssh_request_fixture(),
                        TaskApprovalMode::InsecureTest,
                        || async { Err("SSH delegation withdrawn before signer dispatch".into()) },
                    )
                    .await
            })
        }
        fn assert_no_signer_or_host_attempt(&self) -> TaskRecord {
            let task = self
                .store
                .get(&self.task.id, &self.owner, now_unix())
                .unwrap();
            assert!(task.slots.iter().all(|slot| slot.reserved_at.is_none()));
            match self.provider_canary.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("signer or control API contacted: {other:?}"),
            }
            task
        }
    }

    #[tokio::test]
    async fn ssh_approval_reviews_identity_host_vault_session_controls_and_stops_on_lost_delegation()
     {
        let fixture = SshFixture::new();
        let run = fixture.run();
        tokio::time::timeout(Duration::from_secs(5), fixture.entered.notified())
            .await
            .unwrap();
        {
            let descriptions = fixture.descriptions.lock().unwrap();
            let text = &descriptions[0];
            let action = fixture.task.manifest.actions[0].as_ssh().unwrap();
            for expected in [
                fixture.profile.tenant.approval_context(),
                fixture.profile.vault_url.clone(),
                fixture.profile.control_url.clone(),
                fixture.profile.vault_mount.clone(),
                action.vault_role.clone(),
                action.vault_ca_sha256.clone(),
                action.vault_token_ref.clone(),
                action.profile_sha256.clone(),
                action.destination_host.clone(),
                action.destination_port.to_string(),
                action.host_key_sha256.clone(),
                action.principal.clone(),
                action.login_user.clone(),
                action.source_address.clone(),
                action.command.clone(),
                action.grant_id.clone(),
                action.subject.to_string(),
                action.delegation_id.clone(),
                action.workload_uid.to_string(),
                fixture.profile.receipt_public_key_hex.clone(),
                fixture.task.manifest_digest.clone(),
                fixture.task.expires_at.to_string(),
                "Allowance: 1 connection attempt".into(),
                "Session limit: 30 seconds".into(),
                "PTY, forwarding and subsystems are disabled".into(),
                "Unknown attempts consume allowance".into(),
                "no hardware enclave attestation is claimed".into(),
            ] {
                assert!(text.contains(&expected), "SSH review omitted {expected}");
            }
        }
        fixture.assert_no_signer_or_host_attempt();
        fixture.release.notify_one();
        assert!(
            run.await
                .unwrap()
                .unwrap_err()
                .contains("delegation withdrawn")
        );
        let task = fixture.assert_no_signer_or_host_attempt();
        assert!(task.approved_at.is_some());
        assert_eq!(task.state, TaskState::Partial);
        assert!(fixture.run().await.unwrap().is_err());
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ssh_preflight_rejects_subject_session_workload_profile_and_recipient_drift() {
        let fixture = SshFixture::new();
        fixture
            .enclave
            .preflight_task(&mut ssh_request_fixture(), &fixture.task.manifest)
            .unwrap();
        for field in 0..4 {
            let mut request = ssh_request_fixture();
            match field {
                0 => {
                    request.principal.as_mut().unwrap().sub =
                        opaque_core::identity::PrincipalId::parse(
                            "hum_00000000000000000000000000000003",
                        )
                        .unwrap()
                }
                1 => request.principal.as_mut().unwrap().jti = "other-session".into(),
                2 => request.client_identity.uid = 502,
                _ => request.client_identity.exe_sha256 = Some("b".repeat(64)),
            }
            assert!(
                fixture
                    .enclave
                    .preflight_task(&mut request, &fixture.task.manifest)
                    .is_err()
            );
        }
        let mut request = ssh_request_fixture();
        request.params = serde_json::json!({"manifest":fixture.task.manifest,"expires_at":fixture.task.expires_at,
            "ssh_destination":{"vault_url":"https://untrusted.invalid","control_url":"https://untrusted.invalid"}});
        let reviewed = approval_description(&request, None, Some(&fixture.profile)).unwrap();
        assert!(!reviewed.contains("untrusted.invalid"));
        assert!(approval_description(&request, None, None).is_err());
        for field in 0..6 {
            let mut profile = fixture.profile.clone();
            match field {
                0 => profile.config.vault_url = "https://other-vault.example.test".into(),
                1 => profile.config.control_url = "https://other-host.example.test".into(),
                2 => profile.config.vault_role = "other-role".into(),
                3 => profile.config.vault_token_ref = "env:OTHER_SIGNER_TOKEN".into(),
                4 => profile.config.destination_host = "192.0.2.3".into(),
                _ => profile.config.max_session_secs = 15,
            }
            profile.validate().unwrap();
            assert!(approval_description(&request, None, Some(&profile)).is_err());
            assert_ne!(fixture.profile.digest().unwrap(), profile.digest().unwrap());
        }
        fixture.assert_no_signer_or_host_attempt();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ssh_policy_change_while_review_waits_seals_without_signing() {
        let fixture = SshFixture::new();
        let run = fixture.run();
        tokio::time::timeout(Duration::from_secs(5), fixture.entered.notified())
            .await
            .unwrap();
        fixture
            .enclave
            .swap_policy(PolicyEngine::with_rules(vec![rule("ssh.*")]));
        fixture.release.notify_one();
        assert!(run.await.unwrap().unwrap_err().contains("policy changed"));
        let task = fixture.assert_no_signer_or_host_attempt();
        assert_eq!(task.approved_at, None);
        assert_eq!(task.state, TaskState::Partial);
    }
}
