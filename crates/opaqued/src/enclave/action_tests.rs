//! Cross-stage authority invariants; provider transport regressions live in the
//! real-binary provider_e2e suite.
use super::*;
use opaque_core::audit::InMemoryAuditEmitter;
use opaque_core::operation_handler::PreparedOperation;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, serde::Serialize)]
struct Action {
    repo: String,
    options: Vec<String>,
}

#[derive(Debug)]
struct FrozenHandler {
    executions: Arc<AtomicUsize>,
    long_target: bool,
    refs: Option<Vec<String>>,
}

impl OperationHandler for FrozenHandler {
    fn prepare<'a>(&'a self, _: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let action = Action {
            repo: "trusted/repo".into(),
            options: vec!["captured-default".into()],
        };
        let value = if self.long_target {
            "x".repeat(33 * 1024)
        } else {
            action.repo.clone()
        };
        let calls = self.executions.clone();
        PreparedOperation::new(
            action,
            HashMap::from([("repo".into(), value)]),
            self.refs
                .clone()
                .unwrap_or_else(|| vec!["env:TRUSTED_CREDENTIAL".into()]),
            move |action| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(serde_json::to_value(action).unwrap())
            },
        )
    }
}

type Reviews = Arc<Mutex<Vec<(OperationRequest, String)>>>;
#[derive(Debug)]
struct ReviewGate(Reviews);
impl ApprovalGate for ReviewGate {
    fn request_approval(
        &self,
        _: Uuid,
        request: &OperationRequest,
        _: &[ApprovalFactor],
        description: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
    > {
        self.0
            .lock()
            .unwrap()
            .push((request.clone(), description.to_owned()));
        Box::pin(async { Ok(ApprovalOutcome::approved_anonymous()) })
    }
}

fn fixture(handler: Box<dyn OperationHandler>) -> (Enclave, Reviews, Arc<InMemoryAuditEmitter>) {
    let mut registry = OperationRegistry::new();
    registry
        .register(OperationDef {
            name: "fixture.prepared".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Fixture action".into(),
            params_schema: None,
            allowed_target_keys: vec!["repo".into()],
            secret_ref_param_keys: vec![],
        })
        .unwrap();
    let rule = serde_json::from_value(json!({
        "name": "only-actual-target", "operation_pattern": "fixture.prepared", "allow": true,
        "target": {"fields": {"repo": "trusted/repo"}},
        "secret_names": {"patterns": ["env:TRUSTED_CREDENTIAL"]}
    }))
    .unwrap();
    let reviews = Arc::new(Mutex::new(vec![]));
    let audit = Arc::new(InMemoryAuditEmitter::new());
    let enclave = Enclave::builder()
        .registry(registry)
        .policy(PolicyEngine::with_rules(vec![rule]))
        .handler("fixture.prepared", handler)
        .approval_gate(Box::new(ReviewGate(reviews.clone())))
        .audit(audit.clone())
        .build()
        .unwrap();
    (enclave, reviews, audit)
}

fn request() -> OperationRequest {
    OperationRequest {
        principal: None,
        request_id: Uuid::new_v4(),
        client_identity: ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        },
        client_type: ClientType::Agent,
        operation: "fixture.prepared".into(),
        target: HashMap::new(),
        secret_ref_names: vec!["untrusted-hint".into()],
        created_at: std::time::SystemTime::now(),
        expires_at: None,
        params: json!({"untrusted": "wire"}),
        workspace: None,
    }
}

#[tokio::test]
async fn policy_review_audit_and_dispatch_share_the_prepared_action() {
    let executions = Arc::new(AtomicUsize::new(0));
    let (enclave, reviews, audit) = fixture(Box::new(FrozenHandler {
        executions: executions.clone(),
        long_target: false,
        refs: None,
    }));
    let wire = request();
    let wire_hash = wire.content_hash();
    let result = enclave.execute(wire).await;
    assert_eq!(result.error_code(), None);
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    let reviews = reviews.lock().unwrap();
    assert_eq!(reviews.len(), 1);
    let (reviewed, description) = &reviews[0];
    assert_eq!(reviewed.target["repo"], "trusted/repo");
    assert_eq!(reviewed.secret_ref_names, ["env:TRUSTED_CREDENTIAL"]);
    assert_eq!(reviewed.params, *result.payload());
    let hash = reviewed.content_hash();
    assert_ne!(hash, wire_hash);
    assert!(description.contains(&hash));
    assert!(description.contains("trusted/repo"));
    assert!(!description.contains("untrusted-hint"));
    for kind in [
        AuditEventKind::RequestReceived,
        AuditEventKind::ApprovalRequired,
        AuditEventKind::ApprovalPresented,
        AuditEventKind::ApprovalGranted,
        AuditEventKind::OperationStarted,
        AuditEventKind::OperationSucceeded,
    ] {
        let events = audit.events_of_kind(kind);
        assert_eq!(events.len(), 1, "{kind:?}");
        assert_eq!(
            events[0].request_hash.as_deref(),
            Some(hash.as_str()),
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn lifecycle_rejection_after_review_prevents_prepared_executor_polling() {
    let executions = Arc::new(AtomicUsize::new(0));
    let (mut enclave, reviews, audit) = fixture(Box::new(FrozenHandler {
        executions: executions.clone(),
        long_target: false,
        refs: None,
    }));
    let reviewed = reviews.clone();
    enclave.task_authority_guard = Some(Arc::new(move |_, _| {
        assert_eq!(
            reviewed.lock().unwrap().len(),
            1,
            "lifecycle checked after approval"
        );
        Err("fixture user deactivated during review".into())
    }));
    assert!(enclave.execute(request()).await.error_code().is_some());
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert!(
        audit
            .events_of_kind(AuditEventKind::OperationSucceeded)
            .is_empty()
    );
}

#[tokio::test]
async fn contradictory_or_unreviewable_action_never_reaches_approval_or_dispatch() {
    for long_target in [false, true] {
        let executions = Arc::new(AtomicUsize::new(0));
        let (enclave, reviews, audit) = fixture(Box::new(FrozenHandler {
            executions: executions.clone(),
            long_target,
            refs: None,
        }));
        let mut wire = request();
        if !long_target {
            wire.target.insert("repo".into(), " trusted/repo ".into());
        }
        assert!(enclave.execute(wire).await.error_code().is_some());
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert!(reviews.lock().unwrap().is_empty());
        let events = audit.events();
        assert_eq!(events.len(), 1);
        assert!(events[0].operation.is_none());
        assert!(events[0].target.is_none());
        assert!(events[0].secret_names.is_empty());
    }
}

#[derive(Debug)]
struct LegacyHandler;
impl OperationHandler for LegacyHandler {
    fn execute(
        &self,
        _: &OperationRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, String>> + Send + '_>>
    {
        panic!("unprepared legacy executor must be unreachable")
    }
}

#[tokio::test]
async fn legacy_handler_without_preparer_is_fail_closed() {
    let (enclave, reviews, audit) = fixture(Box::new(LegacyHandler));
    assert_eq!(
        enclave.execute(request()).await.error_code(),
        Some("invalid_params")
    );
    assert!(reviews.lock().unwrap().is_empty());
    assert!(
        audit
            .events_of_kind(AuditEventKind::OperationStarted)
            .is_empty()
    );
}

#[test]
fn review_preserves_long_destinations_all_references_and_display_controls() {
    let repo = format!("owner/{}-tail", "x".repeat(512));
    let refs: Vec<_> = (0..32).map(|i| format!("env:REF_{i}")).collect();
    let target = HashMap::from([
        ("repo".into(), repo.clone()),
        ("environment".into(), "prod\nforged\u{202e}".into()),
    ]);
    let review = action::canonical_review_fields(&target, &refs);
    assert!(review.contains(&repo));
    for reference in refs {
        assert!(review.contains(&reference));
    }
    assert!(review.contains("prod\\nforged\\u202e"));
    assert!(!review.contains('\u{202e}'));
    assert!(!review.contains("truncated"));
    assert!(review.find("environment").unwrap() < review.find("repo").unwrap());
}

#[tokio::test]
async fn secret_shaped_or_control_bearing_reference_never_enters_audit_or_review() {
    for reference in [
        format!("env:ghp_{}", "a".repeat(36)),
        "env:line\nforged".into(),
        "env:hidden\u{202e}".into(),
    ] {
        let executions = Arc::new(AtomicUsize::new(0));
        let (enclave, reviews, audit) = fixture(Box::new(FrozenHandler {
            executions: executions.clone(),
            long_target: false,
            refs: Some(vec![reference.clone()]),
        }));
        assert_eq!(
            enclave.execute(request()).await.error_code(),
            Some("invalid_params")
        );
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert!(reviews.lock().unwrap().is_empty());
        assert!(
            !serde_json::to_string(&audit.events())
                .unwrap()
                .contains(&reference)
        );
        assert!(
            audit
                .events()
                .iter()
                .all(|event| event.secret_names.is_empty())
        );
    }
}
