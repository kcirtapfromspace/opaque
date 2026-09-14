//! Canonical MCP approval and final authorization. No raw caller destination
//! reaches the transport; only the signed-registry-derived Action does.
use super::*;
use opaque_bounded_work::mcp::{Action, Gateway, InvocationResult, store::Receipt};
use opaque_core::identity::PrincipalContext;
use std::sync::atomic::Ordering;

pub fn operation() -> OperationDef {
    OperationDef {
        name: "mcp.call".into(),
        description: "Invoke exactly one signed, pinned third-party MCP tool; raw output withheld, signed projections may disclose typed fields".into(),
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
            "upstream_schema_digest",
            "output_projection",
            "output_projection_digest",
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
    /// Legacy v1 receipt hashes/sizes are observable result data. Apply current
    /// authority when reading them too; control-state metadata remains readable
    /// to the authenticated owner without replaying an output disclosure.
    pub fn filter_mcp_receipt_metadata(
        &self,
        gateway: &Gateway,
        owner: &str,
        request: &OperationRequest,
        action: &Action,
        receipt: &mut Receipt,
    ) {
        if receipt.response_sha256.is_none() && receipt.response_bytes.is_none() {
            return;
        }
        let policy = self.policy.read().unwrap_or_else(|p| p.into_inner());
        let mut authorize = || {
            if !policy.evaluate(request, OperationSafety::Safe).allowed
                || !policy.digest().is_ok_and(|d| d == action.policy_digest)
            {
                return Err("MCP result authority changed".into());
            }
            gateway.revalidate(action)?;
            gateway.ledger.authorize_result(owner, action)
        };
        let allowed = if let Some(guard) = &self.task_authority_guard {
            guard(request.principal.as_ref(), &mut authorize)
        } else if request.principal.is_none() {
            authorize()
        } else {
            Err("MCP identity guard unavailable".into())
        };
        if allowed.is_err() {
            receipt.response_sha256 = None;
            receipt.response_bytes = None;
        }
    }
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
    ) -> Result<InvocationResult, String>
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
        let mut result = gateway
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
                opaque_bounded_work::mcp::digest(&result.receipt)
            )),
        );
        self.confirm_audit(true)
            .await
            .map_err(|_| "MCP audit unavailable")?;
        if result.has_disclosable_values() {
            // Revalidate after the final async audit/identity work. No await
            // follows this policy + identity + ledger disclosure fence.
            let context_current = check_context().await.is_ok_and(|p| p == request.principal);
            let policy = self.policy.read().unwrap_or_else(|p| p.into_inner());
            let mut disclose = || {
                if !context_current
                    || self.policy_generation.load(Ordering::SeqCst) != generation
                    || !policy.evaluate(&request, definition.safety).allowed
                {
                    return Err("MCP disclosure authority changed".into());
                }
                gateway.revalidate(&action)?;
                if result.output.is_some() {
                    gateway.ledger.authorize_disclosure(owner, &action)
                } else {
                    gateway.ledger.authorize_result(owner, &action)
                }
            };
            let allowed = if let Some(guard) = &self.task_authority_guard {
                guard(request.principal.as_ref(), &mut disclose)
            } else if request.principal.is_none() {
                disclose()
            } else {
                Err("MCP identity guard unavailable".into())
            };
            if allowed.is_err() {
                result.withhold_authority_changed();
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
            if request.target["output_policy"] == "typed_fields" {
                assert!(description.contains("output_projection"));
                assert!(description.contains("upstream_schema_digest"));
                assert!(description.contains("resource_id"));
                assert_eq!(
                    request.target["output_projection"],
                    r#"{"fields":[{"source":"id","name":"resource_id","value_type":{"kind":"integer_id","maximum":1000}}]}"#
                );
            } else {
                assert_eq!(request.target["output_policy"], "withhold");
            }
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
        assert_review_denial(false).await;
    }
    #[tokio::test]
    async fn mcp_approval_reviews_signed_projection_and_separate_upstream_pin() {
        assert_review_denial(true).await;
    }
    async fn assert_review_denial(project: bool) {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("registry.bundle");
        let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let now = opaque_bounded_work::mcp::now();
        let mut registry:RegistryDocument=serde_json::from_value(json!({"version":1,"routes":[{"protocol_version":PROTOCOL_VERSION,"alias":"post_note","server_id":"fixture","endpoint":{"host":"mcp.example.com","path":"/mcp"},"tool":"post_note","credential_binding":"notes","input_schema":{"type":"object","additionalProperties":false,"required":["message"],"properties":{"message":{"type":"string","maxLength":64}}},"output_policy":"withhold","max_request_bytes":4096,"max_response_bytes":4096,"timeout_ms":1000}]})).unwrap();
        if project {
            registry.version = 2;
            let route = &mut registry.routes[0];
            route.upstream_input_schema = Some(route.input_schema.clone());
            route.output_policy = opaque_core::mcp::OutputPolicy::TypedFields;
            route.output_projection = Some(serde_json::from_value(json!({"fields":[{"source":"id","name":"resource_id","value_type":{"kind":"integer_id","maximum":1000}}]})).unwrap());
        }
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
                workload: None,
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
    struct ApprovedFixture {
        _directory: tempfile::TempDir,
        gateway: Gateway,
        enclave: Enclave,
        action: Action,
        request: OperationRequest,
    }
    async fn approved_fixture(
        server: &wiremock::MockServer,
        audit: Arc<dyn AuditSink>,
        project: bool,
    ) -> ApprovedFixture {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("registry.bundle");
        let credential = directory.path().join("credential");
        std::fs::write(&credential, b"local-protocol-fixture").unwrap();
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
        let schema = json!({"type":"object","additionalProperties":false,"required":["message"],"properties":{"message":{"type":"string","maxLength":64}}});
        let mut registry:RegistryDocument=serde_json::from_value(json!({"version":2,"routes":[{"protocol_version":PROTOCOL_VERSION,"alias":"post_note","server_id":"fixture","endpoint":{"host":"mcp.example.com","path":"/mcp"},"tool":"post_note","credential_binding":"notes","input_schema":schema,"upstream_input_schema":schema,"output_policy":"typed_fields","output_projection":{"fields":[{"source":"id","name":"resource_id","value_type":{"kind":"integer_id","maximum":1000}}]},"max_request_bytes":4096,"max_response_bytes":4096,"timeout_ms":1000}]})).unwrap();
        if !project {
            registry.version = 1;
            let route = &mut registry.routes[0];
            route.upstream_input_schema = None;
            route.output_projection = None;
            route.output_policy = opaque_core::mcp::OutputPolicy::Withhold;
        }
        let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let now = opaque_bounded_work::mcp::now();
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
        std::fs::write(&bundle, sign_bundle(&payload, &key).unwrap()).unwrap();
        let gateway = Gateway::new(
            Config {
                bundle_path: bundle,
                org: "fixture".into(),
                trust_anchors: vec![opaque_core::workstation::hex(
                    key.verifying_key().as_bytes(),
                )],
                credentials: BTreeMap::from([("notes".into(), credential)]),
                fixture_origin: Some(server.uri()),
            },
            &directory.path().join("ledger.db"),
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
        let mut operations = OperationRegistry::new();
        operations.register(operation()).unwrap();
        let mut policy = PolicyEngine::new();
        policy.add_rule(serde_json::from_value(json!({"name":"fixture","operation_pattern":"mcp.call","allow":true,"approval":{"require":"never"}})).unwrap());
        let enclave = Enclave::builder()
            .registry(operations)
            .policy(policy)
            .approval_gate(Box::new(crate::enclave::test_support::AlwaysApproveGate))
            .audit(audit)
            .build()
            .unwrap();
        let request = OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(123),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
                workload: None,
            },
            client_type: ClientType::Agent,
            principal: None,
            operation: String::new(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::Value::Null,
            workspace: None,
        };
        wiremock::Mock::given(wiremock::matchers::method("POST")).and(wiremock::matchers::path("/mcp")).respond_with(move |request:&wiremock::Request| {
            let message:serde_json::Value=serde_json::from_slice(&request.body).unwrap();
            assert_eq!(request.headers.get("authorization").unwrap(),"Bearer local-protocol-fixture");
            let result=match message["method"].as_str().unwrap(){"initialize"=>json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}),"notifications/initialized"=>return wiremock::ResponseTemplate::new(202),"tools/list"=>json!({"tools":[{"name":"post_note","inputSchema":schema}]}),"tools/call"=>{assert_eq!(message["params"],json!({"name":"post_note","arguments":{"message":"review me"}}));json!({"content":[],"structuredContent":{"id":7,"private":"withheld-fixture-text"}})},_=>panic!("unexpected upstream method")};
            wiremock::ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":message["id"],"result":result}))
        }).mount(server).await;
        ApprovedFixture {
            _directory: directory,
            gateway,
            enclave,
            action,
            request,
        }
    }
    async fn tool_calls(server: &wiremock::MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    == "tools/call"
            })
            .count()
    }

    #[tokio::test]
    async fn mcp_context_failure_at_each_async_boundary_preserves_charge_and_withholds_output() {
        // Actual broker gateway, signed registry, SQLite ledger and loopback MCP.
        // Context lookup failures are injected at the existing private boundary;
        // this is not a claim of physical review or an external provider effect.
        for fail_at in 1..=4 {
            let server = wiremock::MockServer::start().await;
            let f = approved_fixture(&server, Arc::new(InMemoryAuditEmitter::new()), true).await;
            let calls = AtomicUsize::new(0);
            let id = f.action.invocation_id.clone();
            let outcome = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || {
                        let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                        async move {
                            if call == fail_at {
                                Err("live identity unavailable".into())
                            } else {
                                Ok(None)
                            }
                        }
                    },
                )
                .await;
            let retained = f.gateway.ledger.get("owner", &id).unwrap();
            assert_eq!(tool_calls(&server).await, usize::from(fail_at == 4));
            assert_eq!(retained.attempt_charged, fail_at > 1);
            if fail_at == 1 {
                assert_eq!(outcome.unwrap_err(), "live identity unavailable");
                assert_eq!(retained.state, "cancelled");
            } else {
                let result = outcome.unwrap();
                assert!(result.output.is_none());
                assert_eq!(
                    result.state,
                    if fail_at == 4 { "accepted" } else { "rejected" }
                );
                if fail_at == 4 {
                    assert_eq!(result.disclosure, Some("withheld_authority_changed"));
                    assert!(result.response_sha256.is_none());
                    assert!(result.response_bytes.is_none());
                }
            }
            assert_eq!(calls.load(Ordering::SeqCst), fail_at);
            assert!(
                f.enclave
                    .execute_mcp(
                        &f.gateway,
                        "owner",
                        f.request.clone(),
                        f.action.clone(),
                        || async { Ok(None) }
                    )
                    .await
                    .is_err()
            );
            assert_retained(&f.gateway, &id, &retained);
            assert_eq!(tool_calls(&server).await, usize::from(fail_at == 4));
        }
    }

    #[tokio::test]
    async fn mcp_policy_publication_after_review_and_before_disclosure_fails_closed() {
        for change_at in [1, 2, 3, 4] {
            let server = wiremock::MockServer::start().await;
            let f = approved_fixture(&server, Arc::new(InMemoryAuditEmitter::new()), true).await;
            let calls = AtomicUsize::new(0);
            let outcome = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || {
                        if calls.fetch_add(1, Ordering::SeqCst) + 1 == change_at {
                            f.enclave.swap_policy(PolicyEngine::new());
                        }
                        async { Ok(None) }
                    },
                )
                .await;
            let retained = f
                .gateway
                .ledger
                .get("owner", &f.action.invocation_id)
                .unwrap();
            assert_eq!(retained.attempt_charged, change_at > 1);
            assert_eq!(tool_calls(&server).await, usize::from(change_at == 4));
            if change_at == 1 {
                assert_eq!(outcome.unwrap_err(), "MCP authority changed");
            } else {
                let result = outcome.unwrap();
                assert!(result.output.is_none());
                if change_at == 4 {
                    assert_eq!(result.disclosure, Some("withheld_authority_changed"));
                    assert!(result.response_sha256.is_none());
                    assert!(result.response_bytes.is_none());
                }
            }
            assert!(
                f.enclave
                    .execute_mcp(
                        &f.gateway,
                        "owner",
                        f.request.clone(),
                        f.action.clone(),
                        || async { Ok(None) }
                    )
                    .await
                    .is_err()
            );
            assert_eq!(tool_calls(&server).await, usize::from(change_at == 4));
            assert_retained(&f.gateway, &f.action.invocation_id, &retained);
        }
    }

    #[derive(Debug)]
    struct FailingMcpAudit {
        calls: AtomicUsize,
        fail_at: usize,
    }
    impl AuditSink for FailingMcpAudit {
        fn emit(&self, _: AuditEvent) {}
        fn flush(&self, _: Duration) -> Result<(), opaque_core::audit::AuditFlushError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at {
                Err(opaque_core::audit::AuditFlushError::Storage(
                    "fixture MCP commit failure".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
    #[tokio::test]
    async fn mcp_audit_failure_before_or_after_dispatch_never_returns_successful_output() {
        for fail_at in 1..=3 {
            let server = wiremock::MockServer::start().await;
            let audit = Arc::new(FailingMcpAudit {
                calls: AtomicUsize::new(0),
                fail_at,
            });
            let f = approved_fixture(&server, audit.clone(), true).await;
            let outcome = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || async { Ok(None) },
                )
                .await;
            let retained = f
                .gateway
                .ledger
                .get("owner", &f.action.invocation_id)
                .unwrap();
            assert_eq!(tool_calls(&server).await, usize::from(fail_at == 3));
            assert_eq!(retained.attempt_charged, fail_at > 1);
            if fail_at == 2 {
                let result = outcome.unwrap();
                assert_eq!(result.state, "rejected");
                assert!(result.output.is_none());
            } else {
                assert_eq!(outcome.unwrap_err(), "MCP audit unavailable");
            }
            assert_eq!(
                audit.calls.load(Ordering::SeqCst),
                if fail_at == 2 { 3 } else { fail_at }
            );
            assert!(
                f.enclave
                    .execute_mcp(
                        &f.gateway,
                        "owner",
                        f.request.clone(),
                        f.action.clone(),
                        || async { Ok(None) }
                    )
                    .await
                    .is_err()
            );
            assert_eq!(tool_calls(&server).await, usize::from(fail_at == 3));
            assert_retained(&f.gateway, &f.action.invocation_id, &retained);
        }
    }
    fn assert_retained(gateway: &Gateway, id: &str, expected: &Receipt) {
        assert_eq!(
            serde_json::to_value(gateway.ledger.get("owner", id).unwrap()).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
    #[tokio::test]
    async fn legacy_receipt_metadata_rechecks_current_policy_and_revocation_without_replay() {
        for case in 0..4 {
            let server = wiremock::MockServer::start().await;
            let f = approved_fixture(&server, Arc::new(InMemoryAuditEmitter::new()), false).await;
            let result = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || async { Ok(None) },
                )
                .await
                .unwrap();
            assert!(result.attempt_charged);
            assert!(result.response_sha256.is_some());
            assert!(result.response_bytes.is_some());
            let action = f
                .gateway
                .ledger
                .get_action("owner", &f.action.invocation_id)
                .unwrap();
            let mut request = f.request.clone();
            request.operation = "mcp.call".into();
            request.target = action.target();
            let mut receipt = result.receipt.clone();
            match case {
                0 => {}
                1 => {
                    f.enclave.swap_policy(PolicyEngine::new());
                }
                2 => {
                    let mut policy = PolicyEngine::new();
                    policy.add_rule(serde_json::from_value(json!({"name":"new allowed policy","operation_pattern":"mcp.call","allow":true,"approval":{"require":"never"}})).unwrap());
                    f.enclave.swap_policy(policy);
                }
                _ => {
                    f.gateway
                        .ledger
                        .revoke("owner", &action.invocation_id)
                        .unwrap();
                }
            }
            let retained = f
                .gateway
                .ledger
                .get("owner", &action.invocation_id)
                .unwrap();
            f.enclave.filter_mcp_receipt_metadata(
                &f.gateway,
                "owner",
                &request,
                &action,
                &mut receipt,
            );
            assert_eq!(receipt.response_sha256.is_some(), case == 0);
            assert_eq!(receipt.response_bytes.is_some(), case == 0);
            assert!(receipt.attempt_charged);
            assert_eq!(receipt.state, "accepted");
            assert_retained(&f.gateway, &action.invocation_id, &retained);
            assert_eq!(tool_calls(&server).await, 1);
            // Filtering must never repopulate already-empty metadata.
            receipt.response_sha256 = None;
            receipt.response_bytes = None;
            f.enclave.filter_mcp_receipt_metadata(
                &f.gateway,
                "owner",
                &request,
                &action,
                &mut receipt,
            );
            assert!(receipt.response_sha256.is_none());
            assert!(receipt.response_bytes.is_none());
            assert_eq!(tool_calls(&server).await, 1);
        }
    }

    // The following cases use an actual identity SQLite store and the same
    // dispatch-authority guard installed by daemon startup. The scripted local
    // review and software-signed registry do not prove physical presence.
    fn attach_mcp_identity(f: &mut ApprovedFixture) -> Arc<crate::identity::IdentityRuntime> {
        use crate::identity::{IdentityConfig, IdentityRuntime, store::DelegationRecord};
        use opaque_core::identity::{AccessMode, Role, now_unix};
        use std::collections::BTreeSet;
        let runtime = Arc::new(
            IdentityRuntime::initialize(
                IdentityConfig {
                    issuer: "https://mcp-idp.example.invalid".into(),
                    client_id: "fixture".into(),
                    audience: None,
                    redirect_port: None,
                    session_ttl_secs: None,
                    allowed_email_domains: vec![],
                    allowed_subjects: vec![],
                    required: false,
                    persona: None,
                    service_principals: vec![],
                },
                f._directory.path(),
            )
            .unwrap(),
        );
        let human = runtime
            .store
            .upsert_human(
                &runtime.config.issuer,
                "requester",
                None,
                None,
                &BTreeSet::from([Role::Operator]),
            )
            .unwrap();
        let agent = runtime.store.upsert_agent("mcp-fixture-agent").unwrap();
        let session = runtime
            .store
            .create_human_session(&human.id, 600, &runtime.config.issuer)
            .unwrap();
        let context = PrincipalContext {
            sub: human.id.clone(),
            sub_label: human.display_label(),
            sub_roles: human.roles.clone(),
            sub_teams: vec![],
            act: agent.id.clone(),
            act_label: agent.display_label(),
            mode: AccessMode::Delegated,
            jti: Uuid::new_v4().to_string(),
            human_session_id: Some(session.id),
        };
        runtime
            .store
            .record_delegation(&DelegationRecord {
                jti: context.jti.clone(),
                sub_principal: context.sub.clone(),
                act_principal: context.act.clone(),
                mode: context.mode,
                human_session_id: context.human_session_id.clone(),
                approved_by: Some(human.id),
                created_at: now_unix(),
                expires_at: now_unix() + 600,
                revoked_at: None,
            })
            .unwrap();
        f.request.principal = Some(context);
        let guard_runtime = runtime.clone();
        f.enclave.task_authority_guard = Some(Arc::new(move |requester, authorize| {
            guard_runtime.with_dispatch_authority(requester, None, authorize)
        }));
        runtime
    }

    async fn mcp_protocol_history(server: &wiremock::MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| {
                assert_eq!(request.method.as_str(), "POST");
                assert_eq!(request.url.path(), "/mcp");
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    async fn assert_mcp_no_replay(
        f: &ApprovedFixture,
        server: &wiremock::MockServer,
        retained: &Receipt,
    ) {
        let history = mcp_protocol_history(server).await;
        let context = f.request.principal.clone();
        assert!(
            f.enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || async { Ok(context.clone()) }
                )
                .await
                .is_err()
        );
        assert_eq!(mcp_protocol_history(server).await, history);
        assert_retained(&f.gateway, &f.action.invocation_id, retained);
    }

    #[tokio::test]
    async fn mcp_missing_peer_identity_or_full_review_factor_never_claims_an_invocation() {
        for rejection in ["uid", "principal", "factor"] {
            let server = wiremock::MockServer::start().await;
            let audit = Arc::new(InMemoryAuditEmitter::new());
            let mut f = approved_fixture(&server, audit.clone(), true).await;
            let reviews = Arc::new(AtomicUsize::new(0));
            // If the early guard regresses, denial here also prevents any
            // accidental non-fixture transport when checking normal mode.
            f.enclave.approval_gate = Box::new(DenyReviewedAction(reviews.clone()));
            if rejection == "uid" {
                f.request.client_identity.uid = u32::MAX;
            } else if rejection == "principal" {
                let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
                f.gateway = Gateway::new(
                    Config {
                        bundle_path: f._directory.path().join("registry.bundle"),
                        org: "fixture".into(),
                        trust_anchors: vec![opaque_core::workstation::hex(
                            key.verifying_key().as_bytes(),
                        )],
                        credentials: BTreeMap::from([(
                            "notes".into(),
                            f._directory.path().join("credential"),
                        )]),
                        fixture_origin: None,
                    },
                    &f._directory.path().join("normal-mode-ledger.db"),
                    None,
                    false,
                )
                .unwrap();
                f.action = f
                    .gateway
                    .prepare(CallInput {
                        invocation_id: f.action.invocation_id.clone(),
                        route: "post_note".into(),
                        arguments: serde_json::from_value(json!({"message":"review me"})).unwrap(),
                        expires_in_secs: 120,
                    })
                    .unwrap();
                assert!(!f.gateway.fixture_only());
            } else {
                let mut policy = PolicyEngine::new();
                policy.add_rule(
                    serde_json::from_value(
                        json!({"name":"full-review-only","operation_pattern":"mcp.call",
                    "allow":true,"approval":{"require":"always","factors":["paired_workstation"]}}),
                    )
                    .unwrap(),
                );
                f.enclave.swap_policy(policy);
            }
            let error = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || async { Ok(None) },
                )
                .await
                .unwrap_err();
            assert_eq!(
                error,
                if rejection == "factor" {
                    "MCP requires local full review in this release"
                } else {
                    "MCP peer identity unavailable"
                }
            );
            assert_eq!(reviews.load(Ordering::SeqCst), 0);
            assert!(
                f.gateway
                    .ledger
                    .get("owner", &f.action.invocation_id)
                    .is_err()
            );
            assert!(mcp_protocol_history(&server).await.is_empty());
            assert!(!audit.events().iter().any(|e| matches!(
                e.kind,
                AuditEventKind::OperationStarted | AuditEventKind::OperationSucceeded
            )));
        }
    }

    #[tokio::test]
    async fn mcp_changed_verified_context_at_each_boundary_withholds_effect_or_disclosure() {
        for changed_at in 1..=4 {
            let server = wiremock::MockServer::start().await;
            let mut f =
                approved_fixture(&server, Arc::new(InMemoryAuditEmitter::new()), true).await;
            let runtime = attach_mcp_identity(&mut f);
            let original = f.request.principal.clone().unwrap();
            let context_calls = AtomicUsize::new(0);
            let result = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || {
                        let call = context_calls.fetch_add(1, Ordering::SeqCst) + 1;
                        if call == changed_at {
                            runtime
                                .store
                                .set_roles(
                                    &original.sub,
                                    &std::collections::BTreeSet::from([
                                        opaque_core::identity::Role::Auditor,
                                    ]),
                                )
                                .unwrap();
                        }
                        let mut current = original.clone();
                        current.sub_roles = runtime
                            .store
                            .get_principal(&current.sub)
                            .unwrap()
                            .unwrap()
                            .roles;
                        async move { Ok(Some(current)) }
                    },
                )
                .await;
            assert_eq!(context_calls.load(Ordering::SeqCst), changed_at);
            let retained = f
                .gateway
                .ledger
                .get("owner", &f.action.invocation_id)
                .unwrap();
            assert_eq!(retained.attempt_charged, changed_at > 1);
            assert_eq!(tool_calls(&server).await, usize::from(changed_at == 4));
            let expected_messages = [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call",
            ];
            assert_eq!(
                mcp_protocol_history(&server).await,
                expected_messages[..match changed_at {
                    1 => 0,
                    4 => 4,
                    _ => 3,
                }]
            );
            if changed_at == 1 {
                assert_eq!(result.unwrap_err(), "MCP authority changed");
                assert_eq!(retained.state, "cancelled");
            } else {
                let result = result.unwrap();
                assert!(!result.has_disclosable_values());
                assert_eq!(
                    result.state,
                    if changed_at == 4 {
                        "accepted"
                    } else {
                        "rejected"
                    }
                );
                if changed_at == 4 {
                    assert_eq!(result.disclosure, Some("withheld_authority_changed"));
                }
            }
            assert_eq!(
                runtime
                    .store
                    .get_principal(&original.sub)
                    .unwrap()
                    .unwrap()
                    .roles,
                std::collections::BTreeSet::from([opaque_core::identity::Role::Auditor])
            );
            assert_mcp_no_replay(&f, &server, &retained).await;
        }
    }

    #[tokio::test]
    async fn mcp_present_identity_without_dispatch_guard_is_charged_but_never_reaches_transport() {
        let server = wiremock::MockServer::start().await;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mut f = approved_fixture(&server, audit.clone(), true).await;
        let runtime = attach_mcp_identity(&mut f);
        f.enclave.task_authority_guard = None;
        let context = f.request.principal.clone();
        let result = f
            .enclave
            .execute_mcp(
                &f.gateway,
                "owner",
                f.request.clone(),
                f.action.clone(),
                || async { Ok(context.clone()) },
            )
            .await
            .unwrap();
        assert_eq!(result.state, "rejected");
        assert_eq!(result.code, "admission_or_credential_unavailable");
        assert!(result.attempt_charged);
        assert!(!result.has_disclosable_values());
        assert!(mcp_protocol_history(&server).await.is_empty());
        assert!(
            runtime
                .store
                .get_delegation(&context.unwrap().jti)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
        assert!(
            !audit
                .events()
                .iter()
                .any(|e| e.kind == AuditEventKind::OperationStarted)
        );
        let retained = f
            .gateway
            .ledger
            .get("owner", &f.action.invocation_id)
            .unwrap();
        assert_mcp_no_replay(&f, &server, &retained).await;
    }

    #[tokio::test]
    async fn mcp_durable_revocation_at_each_synchronous_guard_fences_calls_and_output_without_refund()
     {
        for revoke_at in 0..=4 {
            let server = wiremock::MockServer::start().await;
            let mut f =
                approved_fixture(&server, Arc::new(InMemoryAuditEmitter::new()), true).await;
            let runtime = attach_mcp_identity(&mut f);
            let context = f.request.principal.clone().unwrap();
            let guard_calls = Arc::new(AtomicUsize::new(0));
            let seen = guard_calls.clone();
            let guard_runtime = runtime.clone();
            let expected = context.clone();
            f.enclave.task_authority_guard = Some(Arc::new(move |requester, authorize| {
                assert_eq!(requester, Some(&expected));
                if seen.fetch_add(1, Ordering::SeqCst) + 1 == revoke_at {
                    assert!(
                        guard_runtime
                            .store
                            .revoke_delegation(&expected.jti)
                            .unwrap()
                    );
                }
                guard_runtime.with_dispatch_authority(requester, None, authorize)
            }));
            // Async lookups intentionally retain the earlier valid snapshot;
            // the real synchronous SQLite guard must independently fence it.
            let result = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || async { Ok(Some(context.clone())) },
                )
                .await
                .unwrap();
            assert!(result.attempt_charged);
            assert_eq!(
                guard_calls.load(Ordering::SeqCst),
                if revoke_at == 0 { 4 } else { revoke_at }
            );
            assert_eq!(
                tool_calls(&server).await,
                usize::from(revoke_at == 0 || revoke_at >= 3)
            );
            let expected_messages = [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call",
            ];
            assert_eq!(
                mcp_protocol_history(&server).await,
                expected_messages[..match revoke_at {
                    1 => 0,
                    2 => 3,
                    _ => 4,
                }]
            );
            assert_eq!(
                result.state,
                if revoke_at == 1 || revoke_at == 2 {
                    "rejected"
                } else {
                    "accepted"
                }
            );
            if revoke_at == 0 {
                assert_eq!(
                    result.output,
                    Some(BTreeMap::from([("resource_id".into(), json!(7))]))
                );
                assert_eq!(result.disclosure, Some("projected"));
            } else {
                assert!(!result.has_disclosable_values());
                if revoke_at >= 3 {
                    assert_eq!(result.disclosure, Some("withheld_authority_changed"));
                }
            }
            let persisted = runtime.store.get_delegation(&context.jti).unwrap().unwrap();
            assert_eq!(persisted.revoked_at.is_some(), revoke_at != 0);
            let retained = f
                .gateway
                .ledger
                .get("owner", &f.action.invocation_id)
                .unwrap();
            assert_mcp_no_replay(&f, &server, &retained).await;
            assert_eq!(
                guard_calls.load(Ordering::SeqCst),
                if revoke_at == 0 { 4 } else { revoke_at }
            );
        }
    }

    #[tokio::test]
    async fn mcp_legacy_metadata_requires_live_guard_and_preserves_retained_receipt_without_replay()
    {
        for fault in ["none", "missing-guard", "revoked", "one-field"] {
            let server = wiremock::MockServer::start().await;
            let mut f =
                approved_fixture(&server, Arc::new(InMemoryAuditEmitter::new()), false).await;
            let runtime = attach_mcp_identity(&mut f);
            let context = f.request.principal.clone();
            let result = f
                .enclave
                .execute_mcp(
                    &f.gateway,
                    "owner",
                    f.request.clone(),
                    f.action.clone(),
                    || async { Ok(context.clone()) },
                )
                .await
                .unwrap();
            assert!(result.response_sha256.is_some() && result.response_bytes.is_some());
            let action = f
                .gateway
                .ledger
                .get_action("owner", &f.action.invocation_id)
                .unwrap();
            let mut request = f.request.clone();
            request.operation = "mcp.call".into();
            request.target = action.target();
            let retained = f
                .gateway
                .ledger
                .get("owner", &f.action.invocation_id)
                .unwrap();
            let mut filtered = retained.clone();
            match fault {
                "missing-guard" => f.enclave.task_authority_guard = None,
                "revoked" => {
                    assert!(
                        runtime
                            .store
                            .revoke_delegation(&context.as_ref().unwrap().jti)
                            .unwrap()
                    );
                }
                // Optional legacy metadata fields are independent: one absent
                // value cannot suppress checking the other disclosed value.
                "one-field" => filtered.response_sha256 = None,
                _ => {}
            }
            f.enclave.filter_mcp_receipt_metadata(
                &f.gateway,
                "owner",
                &request,
                &action,
                &mut filtered,
            );
            let allowed = matches!(fault, "none" | "one-field");
            assert_eq!(filtered.response_sha256.is_some(), fault == "none");
            assert_eq!(filtered.response_bytes.is_some(), allowed);
            assert_eq!(filtered.state, "accepted");
            assert!(filtered.attempt_charged);
            assert_retained(&f.gateway, &f.action.invocation_id, &retained);
            assert_eq!(
                mcp_protocol_history(&server).await,
                [
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "tools/call"
                ]
            );
            assert_mcp_no_replay(&f, &server, &retained).await;
        }
    }
}
