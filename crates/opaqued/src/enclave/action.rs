//! One prepared action shared by generic policy, review, audit and execution.
use super::*;
use opaque_core::operation_handler::PreparedOperation;

pub(crate) const TASK_ONLY_OPERATIONS: &[&str] = &[
    "github.publish_manifest",
    "github.release_manifest",
    "github.dispatch_staging_workflow",
    "github.observe_staging_workflow",
    "inference.fixed_manifest",
    "inference.fixed_completion",
    "ssh.health_manifest",
    "ssh.service_health",
];

impl Enclave {
    pub(super) fn prepare_generic<'a>(
        &'a self,
        request: &OperationRequest,
        definition: &OperationDef,
    ) -> Result<PreparedOperation<'a>, EnclaveError> {
        if TASK_ONLY_OPERATIONS.contains(&request.operation.as_str()) {
            return Err(EnclaveError::InvalidInput(
                "operation requires the typed task transport".into(),
            ));
        }
        let handler = self.handlers.get(&request.operation).ok_or_else(|| {
            EnclaveError::InvalidInput("operation has no generic execution handler".into())
        })?;
        if !definition.allowed_target_keys.is_empty()
            && request
                .target
                .keys()
                .any(|key| !definition.allowed_target_keys.contains(key))
        {
            return Err(EnclaveError::InvalidInput(
                "unexpected target assertion key".into(),
            ));
        }
        // Validate wire params before converting to the typed action's internal
        // hash payload. Parser/schema diagnostics can quote secret input.
        self.registry
            .validate_params(&request.operation, &request.params)
            .map_err(|_| EnclaveError::InvalidParams("invalid operation parameters".into()))?;
        let prepared = handler
            .prepare(request)
            .map_err(|_| EnclaveError::InvalidParams("action preparation rejected".into()))?;
        opaque_core::validate::InputValidator::validate_prepared_refs(prepared.secret_ref_names())
            .map_err(|_| {
                EnclaveError::InvalidParams("invalid prepared reference metadata".into())
            })?;
        if request
            .target
            .iter()
            .any(|(key, value)| prepared.target().get(key) != Some(value))
        {
            return Err(EnclaveError::InvalidInput(
                "target assertion does not match prepared action".into(),
            ));
        }
        // Reject before policy and auditing if the exact action cannot fit a
        // complete review. This applies even when policy skips approval.
        if canonical_review_fields(prepared.target(), prepared.secret_ref_names()).len() > 32 * 1024
        {
            return Err(EnclaveError::InvalidParams(
                "prepared action review exceeds limit".into(),
            ));
        }
        Ok(prepared)
    }

    /// A rejected, unprepared request has no trusted target, refs or operation
    /// metadata to publish. Its event contains only correlation and peer identity.
    pub(super) fn reject_unprepared(
        &self,
        request_id: Uuid,
        client: ClientSummary,
        error: EnclaveError,
    ) -> SanitizedResponse<Sanitized> {
        self.audit.emit(
            AuditEvent::new(AuditEventKind::OperationFailed)
                .with_request_id(request_id)
                .with_client(client)
                .with_outcome("error")
                .with_detail("action_preparation_rejected"),
        );
        self.error_to_sanitized(&error)
    }
}

/// Every canonical target and reference appears in stable order and without
/// truncation. Quoting makes controls and line boundaries explicit. The native
/// review window has a separate overall bound, so reserve room for context.
pub(super) fn canonical_review_fields(target: &HashMap<String, String>, refs: &[String]) -> String {
    use opaque_core::operation_handler::render_review_text;
    let mut fields: Vec<_> = target.iter().collect();
    fields.sort_by_key(|(key, _)| *key);
    let mut review = String::new();
    for (key, value) in fields {
        review.push_str(&format!(
            "\n  {}: {}",
            render_review_text(key),
            render_review_text(value)
        ));
    }
    review.push_str("\nSecrets: ");
    review.push_str(&opaque_core::operation_handler::render_argv(refs));
    review
}
