//! Canonical MCP approval and final authorization. No raw caller destination
//! reaches the transport; only the signed-registry-derived Action does.
use super::*;
use opaque_bounded_work::mcp::{Action, Gateway, store::Receipt};
use opaque_core::identity::PrincipalContext;
use std::sync::atomic::Ordering;

pub fn operation() -> OperationDef {
    OperationDef {
        name: "mcp.call".into(),
        description:
            "Invoke exactly one signed, pinned third-party MCP tool; upstream output withheld"
                .into(),
        safety: OperationSafety::Safe,
        default_approval: ApprovalRequirement::Always,
        default_factors: vec![ApprovalFactor::LocalBio],
        params_schema: Some(serde_json::json!({"type":"object"})),
        allowed_target_keys: vec![
            "invocation_id",
            "route",
            "server_id",
            "endpoint",
            "tool",
            "protocol_version",
            "registry_digest",
            "policy_digest",
            "request_context_digest",
            "registry_version",
            "schema_digest",
            "arguments",
            "output_policy",
            "credential_ref",
            "max_request_bytes",
            "max_response_bytes",
            "timeout_ms",
            "expires_at",
            "attempt_limit",
            "fixture_origin",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        secret_ref_param_keys: vec!["credential_ref".into()],
    }
}
impl Enclave {
    pub fn mcp_route_allowed(&self, request: &OperationRequest) -> bool {
        self.policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .evaluate(request, OperationSafety::Safe)
            .allowed
    }
    pub async fn execute_mcp<F, Fut>(
        &self,
        gateway: &Gateway,
        owner: &str,
        mut request: OperationRequest,
        mut action: Action,
        check_context: F,
    ) -> Result<Receipt, String>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Option<PrincipalContext>, String>>,
    {
        if request.client_identity.uid == u32::MAX
            || (!gateway.fixture_only() && request.principal.is_none())
        {
            return Err("MCP peer identity unavailable".into());
        }
        let generation = self.policy_generation.load(Ordering::SeqCst);
        action.policy_digest = self
            .policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .digest()
            .map_err(|_| "MCP policy unavailable")?;
        action.request_context_digest = opaque_bounded_work::mcp::digest(&serde_json::json!({
            "peer": request.client_identity, "principal": request.principal,
            "client_type": request.client_type, "workspace": request.workspace
        }));
        request.operation = "mcp.call".into();
        request.target = action.target();
        request.secret_ref_names = vec![action.credential_ref.clone()];
        request.params = serde_json::to_value(&action).map_err(|_| "MCP action encoding failed")?;
        request.expires_at =
            Some(std::time::UNIX_EPOCH + Duration::from_secs(action.expires_at as u64));
        let definition = operation();
        self.check_safety_constraints(&request, &definition)
            .map_err(|_| "MCP safety policy denied")?;
        let mut decision = self
            .policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .evaluate(&request, definition.safety);
        let client = ClientSummary::from((&request.client_identity, request.client_type));
        let client = request
            .principal
            .as_ref()
            .map_or(client.clone(), |p| client.with_principal(p));
        let target = TargetSummary::sanitized(&request.target);
        let hash = request.content_hash();
        self.audit.emit(
            AuditEvent::new(AuditEventKind::RequestReceived)
                .with_request_id(request.request_id)
                .with_client(client.clone())
                .with_operation("mcp.call")
                .with_target(target.clone())
                .with_secret_names(request.secret_ref_names.clone())
                .with_request_hash(&hash),
        );
        if !decision.allowed {
            self.audit.emit(
                AuditEvent::new(AuditEventKind::PolicyDenied)
                    .with_request_id(request.request_id)
                    .with_operation("mcp.call")
                    .with_request_hash(&hash)
                    .with_outcome("denied"),
            );
            return Err("MCP policy denied".into());
        }
        decision.approval_requirement = ApprovalRequirement::Always;
        if decision.required_factors.is_empty() {
            decision.required_factors = definition.default_factors.clone();
        }
        // Remote approval will be admitted only once its receipt binds this
        // invocation and registry. No partial-review factor can silently pass.
        if decision.required_factors != [ApprovalFactor::LocalBio] {
            return Err("MCP requires local full review in this release".into());
        }
        gateway.ledger.claim(owner, &action)?;
        let _guard = gateway.ledger.guard(owner, &action.invocation_id);
        self.handle_approval(
            &request,
            &definition,
            &decision,
            &client,
            &target,
            generation,
        )
        .await
        .map_err(|_| "MCP approval not granted")?;
        self.confirm_audit(false)
            .await
            .map_err(|_| "MCP audit unavailable")?;
        if check_context().await? != request.principal
            || self.policy_generation.load(Ordering::SeqCst) != generation
        {
            return Err("MCP authority changed".into());
        }
        let result = gateway
            .execute(
                owner,
                &action,
                || async {
                    if check_context().await? != request.principal
                        || self.policy_generation.load(Ordering::SeqCst) != generation
                    {
                        return Err("MCP authority changed".into());
                    }
                    let current = self
                        .policy
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .evaluate(&request, definition.safety);
                    if !current.allowed {
                        return Err("MCP policy denied".into());
                    }
                    self.audit.emit(
                        AuditEvent::new(AuditEventKind::OperationStarted)
                            .with_request_id(request.request_id)
                            .with_operation("mcp.call")
                            .with_request_hash(&hash)
                            .with_target(target.clone())
                            .with_detail(format!(
                                "invocation={}; registry={}",
                                action.invocation_id, action.registry_digest
                            )),
                    );
                    self.confirm_audit(false)
                        .await
                        .map_err(|_| "MCP audit unavailable")?;
                    if check_context().await? != request.principal
                        || self.policy_generation.load(Ordering::SeqCst) != generation
                    {
                        return Err("MCP authority changed".into());
                    }
                    Ok(())
                },
                |dispatch| {
                    let policy = self.policy.read().unwrap_or_else(|p| p.into_inner());
                    if self.policy_generation.load(Ordering::SeqCst) != generation
                        || !policy.evaluate(&request, definition.safety).allowed
                    {
                        return Err("MCP policy changed".into());
                    }
                    if let Some(guard) = &self.task_authority_guard {
                        guard(request.principal.as_ref(), dispatch)
                    } else if request.principal.is_none() {
                        dispatch()
                    } else {
                        Err("MCP identity guard unavailable".into())
                    }
                },
            )
            .await?;
        self.audit.emit(
            AuditEvent::new(if result.state == "accepted" {
                AuditEventKind::OperationSucceeded
            } else {
                AuditEventKind::OperationFailed
            })
            .with_request_id(request.request_id)
            .with_operation("mcp.call")
            .with_request_hash(&hash)
            .with_outcome(&result.code)
            .with_detail(format!(
                "invocation={}; charged={}; receipt_digest={}",
                result.invocation_id,
                result.attempt_charged,
                opaque_bounded_work::mcp::digest(&result)
            )),
        );
        self.confirm_audit(true)
            .await
            .map_err(|_| "MCP audit unavailable")?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_bounded_work::mcp::{CallInput, Config};
    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::bundle::{BundlePayload, sign_bundle};
    use opaque_core::mcp::{PROTOCOL_VERSION, RegistryDocument};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::{Arc, atomic::AtomicUsize};

    #[derive(Debug)]
    struct DenyReviewedAction(Arc<AtomicUsize>);
    impl ApprovalGate for DenyReviewedAction {
        fn request_approval(
            &self,
            _id: Uuid,
            request: &OperationRequest,
            factors: &[ApprovalFactor],
            description: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
        > {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(factors, [ApprovalFactor::LocalBio]);
            for field in [
                "invocation_id",
                "registry_digest",
                "policy_digest",
                "request_context_digest",
                "schema_digest",
                "credential_ref",
                "endpoint",
                "arguments",
                "output_policy",
                "attempt_limit",
            ] {
                assert!(request.target.contains_key(field));
                assert!(description.contains(field), "missing review field {field}");
            }
            assert_eq!(request.target["arguments"], r#"{"message":"review me"}"#);
            assert_eq!(request.target["output_policy"], "withhold");
            assert_eq!(request.target["attempt_limit"], "1");
            assert_eq!(
                request.secret_ref_names,
                [request.target["credential_ref"].clone()]
            );
            Box::pin(async { Ok(ApprovalOutcome::denied()) })
        }
    }
    #[tokio::test]
    async fn mcp_approval_reviews_canonical_authority_and_denial_never_reserves_or_reads_credentials()
     {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("registry.bundle");
        let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let now = opaque_bounded_work::mcp::now();
        let registry:RegistryDocument=serde_json::from_value(json!({"version":1,"routes":[{"protocol_version":PROTOCOL_VERSION,"alias":"post_note","server_id":"fixture","endpoint":{"host":"mcp.example.com","path":"/mcp"},"tool":"post_note","credential_binding":"notes","input_schema":{"type":"object","additionalProperties":false,"required":["message"],"properties":{"message":{"type":"string","maxLength":64}}},"output_policy":"withhold","max_request_bytes":4096,"max_response_bytes":4096,"timeout_ms":1000}]})).unwrap();
        let payload = BundlePayload {
            org: "fixture".into(),
            version: 1,
            issued_at: now - 1,
            expires_at: Some(now + 600),
            key_id: String::new(),
            teams: vec![],
            rules: vec![],
            mcp_registry: Some(registry),
        };
        std::fs::write(&bundle_path, sign_bundle(&payload, &key).unwrap()).unwrap();
        // Missing on purpose: denial must happen before credential I/O.
        let credentials = BTreeMap::from([("notes".into(), dir.path().join("must-not-read"))]);
        let gateway = Gateway::new(
            Config {
                bundle_path,
                org: "fixture".into(),
                trust_anchors: vec![
                    key.verifying_key()
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                ],
                credentials,
                fixture_origin: Some("http://127.0.0.1:9".into()),
            },
            &dir.path().join("ledger.db"),
            None,
            true,
        )
        .unwrap();
        let action = gateway
            .prepare(CallInput {
                invocation_id: Uuid::new_v4().to_string(),
                route: "post_note".into(),
                arguments: serde_json::from_value(json!({"message":"review me"})).unwrap(),
                expires_in_secs: 120,
            })
            .unwrap();
        let id = action.invocation_id.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mut registry = OperationRegistry::new();
        registry.register(operation()).unwrap();
        let rule:opaque_core::policy::PolicyRule=serde_json::from_value(json!({"name":"fixture","operation_pattern":"mcp.call","allow":true,"approval":{"require":"never"}})).unwrap();
        let mut policy = PolicyEngine::new();
        policy.add_rule(rule);
        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .approval_gate(Box::new(DenyReviewedAction(calls.clone())))
            .audit(audit.clone())
            .build()
            .unwrap();
        let request = OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: opaque_core::operation::ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(123),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: opaque_core::operation::ClientType::Agent,
            principal: None,
            operation: String::new(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::Value::Null,
            workspace: None,
        };
        assert!(
            enclave
                .execute_mcp(&gateway, "alice", request, action, || async { Ok(None) })
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let receipt = gateway.ledger.get("alice", &id).unwrap();
        assert_eq!(receipt.state, "cancelled");
        assert!(!receipt.attempt_charged);
        assert!(
            audit
                .events()
                .iter()
                .any(|e| e.kind == AuditEventKind::ApprovalDenied)
        );
        assert!(
            !audit
                .events()
                .iter()
                .any(|e| e.kind == AuditEventKind::OperationStarted)
        );
    }
}
