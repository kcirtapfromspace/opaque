//! Actual daemon dispatch, native disposable Git peer, and captured preparation.
//! GitLab uses its real typed preparer, then drops its deferred network executor
//! and substitutes an explicitly synthetic recorder. No vendor effects/approval
//! ceremony are claimed, and no credentials can be resolved by these fixtures.
use super::*;
use crate::{Enclave, handle_request, safe_command};
use opaque_core::approval_gate::{ApprovalGate, ApprovalOutcome};
use opaque_core::audit::{AuditEventKind, InMemoryAuditEmitter};
use opaque_core::operation::{
    ApprovalFactor, ApprovalRequirement, OperationDef, OperationRegistry, OperationSafety,
    WorkspaceContext,
};
use opaque_core::operation_handler::{OperationHandler, PreparedOperation};
use opaque_core::policy::PolicyEngine;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct Observed {
    prepared: Mutex<Vec<OperationRequest>>,
    reviewed: Mutex<Vec<OperationRequest>>,
    executed: Mutex<Vec<Value>>,
}

#[derive(Debug)]
struct CaptureHandler {
    observed: Arc<Observed>,
    gitlab: Option<opaque_providers::gitlab::GitLabHandler>,
}
impl OperationHandler for CaptureHandler {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        self.observed.prepared.lock().unwrap().push(request.clone());
        let (params, target, refs) = if let Some(handler) = &self.gitlab {
            let prepared = handler.prepare(request)?;
            // Only the real typed projection is kept, never its executor.
            (
                prepared.params().clone(),
                prepared.target().clone(),
                prepared.secret_ref_names().to_vec(),
            )
        } else {
            (request.params.clone(), request.target.clone(), vec![])
        };
        let observed = self.observed.clone();
        PreparedOperation::new(params, target, refs, move |action| async move {
            observed.executed.lock().unwrap().push(action);
            Ok(json!({"status":"recorded"}))
        })
    }
}
#[derive(Debug)]
struct Review(Arc<Observed>);
impl ApprovalGate for Review {
    fn request_approval(
        &self,
        _: Uuid,
        request: &OperationRequest,
        factors: &[ApprovalFactor],
        _: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalOutcome, String>> + Send + '_>,
    > {
        assert_eq!(factors, &[ApprovalFactor::LocalBio]);
        self.0.reviewed.lock().unwrap().push(request.clone());
        Box::pin(async { Ok(ApprovalOutcome::approved_anonymous()) })
    }
}
struct Fixture {
    state: DaemonState,
    observed: Arc<Observed>,
    audit: Arc<InMemoryAuditEmitter>,
}
impl Fixture {
    fn new() -> Self {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let mut state = crate::tests::build_test_state(audit.clone(), false);
        let observed = Arc::new(Observed::default());
        let mut registry = OperationRegistry::new();
        for operation in ["fixture.record", "gitlab.set_ci_variable"] {
            registry
                .register(OperationDef {
                    name: operation.into(),
                    safety: OperationSafety::Safe,
                    default_approval: ApprovalRequirement::Always,
                    default_factors: vec![ApprovalFactor::LocalBio],
                    description: "Record a private wrapper fixture".into(),
                    params_schema: None,
                    allowed_target_keys: vec![
                        "project".into(),
                        "key".into(),
                        "environment_scope".into(),
                        "gitlab_api_url".into(),
                        "variable_type".into(),
                        "protected".into(),
                        "masked".into(),
                        "raw".into(),
                    ],
                    secret_ref_param_keys: vec![],
                })
                .unwrap();
        }
        let rule =
            serde_json::from_value(json!({"name":"fixture","operation_pattern":"*","allow":true}))
                .unwrap();
        state.enclave = Arc::new(
            Enclave::builder()
                .registry(registry)
                .policy(PolicyEngine::with_rules(vec![rule]))
                .handler(
                    "fixture.record",
                    Box::new(CaptureHandler {
                        observed: observed.clone(),
                        gitlab: None,
                    }),
                )
                .handler(
                    "gitlab.set_ci_variable",
                    Box::new(CaptureHandler {
                        observed: observed.clone(),
                        gitlab: Some(
                            opaque_providers::gitlab::GitLabHandler::new(audit.clone()).unwrap(),
                        ),
                    }),
                )
                .approval_gate(Box::new(Review(observed.clone())))
                .audit(audit.clone())
                .build()
                .unwrap(),
        );
        Self {
            state,
            observed,
            audit,
        }
    }
    async fn call(&self, method: &str, params: Value, identity: &ClientIdentity) -> Response {
        handle_request(
            &self.state,
            Request {
                id: 7,
                method: method.into(),
                params,
            },
            identity,
            ClientType::Agent,
            None,
        )
        .await
    }
    fn untouched(&self) {
        assert!(self.observed.prepared.lock().unwrap().is_empty());
        assert!(self.observed.reviewed.lock().unwrap().is_empty());
        assert!(self.observed.executed.lock().unwrap().is_empty());
        assert!(
            self.audit
                .events_of_kind(AuditEventKind::OperationSucceeded)
                .is_empty()
        );
    }
}
struct Workspace {
    directory: tempfile::TempDir,
    root: std::path::PathBuf,
    child: std::process::Child,
}
impl Workspace {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let git = |args: &[&str]| {
            let result = safe_command("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        };
        git(&["init", "-q", "-b", "main"]);
        git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "initial",
        ]);
        git(&[
            "remote",
            "add",
            "origin",
            "https://fixture-secret@example.invalid/repository.git",
        ]);
        let child = safe_command("/bin/sleep")
            .arg("60")
            .current_dir(&root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Self {
            directory,
            root,
            child,
        }
    }
    fn identity(&self) -> ClientIdentity {
        ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(self.child.id() as i32),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        }
    }
    fn claim(&self) -> WorkspaceContext {
        WorkspaceContext {
            repo_root: self.root.canonicalize().unwrap(),
            remote_url: Some("https://fixture-secret@example.invalid/repository.git".into()),
            branch: Some("main".into()),
            head_sha: None,
            dirty: false,
            workspace_verified: true,
        }
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn rejected(response: Response, code: &str, message: &str) {
    assert!(
        response.result.is_none(),
        "unexpected success: {:?}",
        response.result
    );
    let error = response.error.unwrap();
    assert_eq!(error.code, code);
    assert_eq!(error.message, message);
}
fn gitlab_params() -> Value {
    json!({"project":"group/project","key":"VALID_0","value_ref":"env:FIXTURE_VALUE","gitlab_token_ref":"env:FIXTURE_PAT"})
}

#[tokio::test]
async fn execute_rejects_malformed_workspace_before_any_preparation_or_review() {
    let workspace = Workspace::new();
    for claim in [
        json!(false),
        json!("invalid"),
        json!({"repo_root":42}),
        json!({"repo_root":workspace.root}),
    ] {
        let fixture = Fixture::new();
        let response = fixture
            .call(
                "execute",
                json!({"operation":"fixture.record","params":{"marker":"never"},"workspace":claim}),
                &workspace.identity(),
            )
            .await;
        rejected(
            response,
            "workspace_verification_failed",
            "workspace verification failed",
        );
        fixture.untouched();
    }
}

#[tokio::test]
async fn execute_rejects_workspace_when_the_peer_pid_is_missing() {
    let workspace = Workspace::new();
    let fixture = Fixture::new();
    let mut identity = workspace.identity();
    identity.pid = None;
    let response = fixture.call("execute",json!({"operation":"fixture.record","params":{"marker":"never"},"workspace":workspace.claim()}),&identity).await;
    rejected(
        response,
        "workspace_verification_failed",
        "workspace verification failed",
    );
    fixture.untouched();
}

#[tokio::test]
async fn execute_native_workspace_control_preserves_verified_authority_and_rejects_foreign_root() {
    let workspace = Workspace::new();
    let fixture = Fixture::new();
    let original = std::fs::read(workspace.root.join(".git/config")).unwrap();
    let response = fixture.call("execute",json!({"operation":"fixture.record","params":{"marker":"exact"},
        "workspace":workspace.claim(),"client_type":"human","secret_ref_names":["env:UNTRUSTED_HINT"]}),&workspace.identity()).await;
    assert!(response.error.is_none(), "{:?}", response.error);
    {
        let prepared = fixture.observed.prepared.lock().unwrap();
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].params, json!({"marker":"exact"}));
        assert_eq!(prepared[0].client_type, ClientType::Agent);
        assert_eq!(prepared[0].client_identity.pid, workspace.identity().pid);
        assert!(prepared[0].secret_ref_names.is_empty());
        let verified = prepared[0].workspace.as_ref().unwrap();
        assert!(verified.workspace_verified);
        assert_eq!(verified.repo_root, workspace.root.canonicalize().unwrap());
        assert_eq!(
            verified.remote_url.as_deref(),
            Some("https://example.invalid/repository.git")
        );
        assert_eq!(verified.branch.as_deref(), Some("main"));
        assert!(!verified.dirty);
    }
    assert_eq!(fixture.observed.reviewed.lock().unwrap().len(), 1);
    assert_eq!(
        *fixture.observed.executed.lock().unwrap(),
        [json!({"marker":"exact"})]
    );
    assert_eq!(
        std::fs::read(workspace.root.join(".git/config")).unwrap(),
        original
    );
    let refused = Fixture::new();
    let mut claim = workspace.claim();
    claim.repo_root = workspace.directory.path().join("unrelated");
    std::fs::create_dir(&claim.repo_root).unwrap();
    rejected(
        refused
            .call(
                "execute",
                json!({"operation":"fixture.record","workspace":claim}),
                &workspace.identity(),
            )
            .await,
        "workspace_verification_failed",
        "workspace verification failed",
    );
    refused.untouched();
}

#[tokio::test]
async fn execute_missing_operation_and_invalid_target_assertions_never_prepare() {
    let workspace = Workspace::new();
    for params in [
        json!({}),
        json!({"operation":""}),
        json!({"operation":42}),
        json!({"operation":"fixture.record","target":[]}),
        json!({"operation":"fixture.record","target":{"project":42}}),
    ] {
        let fixture = Fixture::new();
        let expected = if params["operation"] == "fixture.record" {
            "target must be an object of string assertions"
        } else {
            "missing 'operation' field"
        };
        rejected(
            fixture.call("execute", params, &workspace.identity()).await,
            "bad_request",
            expected,
        );
        fixture.untouched();
    }
    for workspace_value in [None, Some(Value::Null)] {
        let fixture = Fixture::new();
        let mut params = json!({"operation":"fixture.record","params":{"without_workspace":true}});
        if let Some(value) = workspace_value {
            params["workspace"] = value;
        }
        let response = fixture.call("execute", params, &workspace.identity()).await;
        assert!(response.error.is_none());
        assert!(
            fixture.observed.prepared.lock().unwrap()[0]
                .workspace
                .is_none()
        );
        assert_eq!(fixture.observed.executed.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn gitlab_missing_fields_bad_action_and_invalid_key_stop_before_preparation() {
    let workspace = Workspace::new();
    for (field, value, expected) in [
        (
            "action",
            json!("different"),
            "unknown action 'different' (expected: set_ci_variable)",
        ),
        ("project", json!(""), "missing 'project' field"),
        ("key", json!(""), "missing 'key' field"),
        (
            "key",
            json!("bad-key"),
            "key must be alphanumeric (with underscores)",
        ),
        (
            "key",
            json!("unicodé"),
            "key must be alphanumeric (with underscores)",
        ),
        ("value_ref", json!(""), "missing 'value_ref' field"),
    ] {
        let fixture = Fixture::new();
        let mut params = gitlab_params();
        params[field] = value;
        rejected(
            fixture.call("gitlab", params, &workspace.identity()).await,
            "bad_request",
            expected,
        );
        fixture.untouched();
    }
}

#[tokio::test]
async fn gitlab_reference_and_target_rejections_preserve_local_state_without_review() {
    let workspace = Workspace::new();
    let before = std::fs::read(workspace.root.join(".git/config")).unwrap();
    for (field, value, prefix) in [
        (
            "value_ref",
            "unknown:VALUE".to_owned(),
            "value_ref must start with a known scheme",
        ),
        (
            "value_ref",
            "env:VALUE\nINJECT".to_owned(),
            "invalid secret ref:",
        ),
        (
            "gitlab_token_ref",
            "env:TOKEN\nINJECT".to_owned(),
            "invalid secret ref:",
        ),
        ("project", "group/\nINJECT".to_owned(), "invalid target:"),
        ("project", "x".repeat(257), "invalid target:"),
    ] {
        let fixture = Fixture::new();
        let mut params = gitlab_params();
        params[field] = value.into();
        let response = fixture.call("gitlab", params, &workspace.identity()).await;
        assert!(response.result.is_none());
        let error = response.error.unwrap();
        assert_eq!(error.code, "bad_request");
        assert!(error.message.starts_with(prefix), "{}", error.message);
        assert!(!error.message.contains("INJECT"));
        fixture.untouched();
        assert_eq!(
            std::fs::read(workspace.root.join(".git/config")).unwrap(),
            before
        );
    }
}

#[tokio::test]
async fn gitlab_wrapper_retains_optional_types_for_real_preparer_and_only_removes_envelope() {
    let workspace = Workspace::new();
    for (field, value) in [
        ("protected", json!("false")),
        ("masked", json!(42)),
        ("raw", json!([])),
        ("environment_scope", json!(true)),
        ("variable_type", json!(42)),
        ("unexpected", json!(true)),
    ] {
        let fixture = Fixture::new();
        let mut params = gitlab_params();
        params[field] = value.clone();
        params["action"] = "set_ci_variable".into();
        params["client_type"] = "human".into();
        let response = fixture.call("gitlab", params, &workspace.identity()).await;
        rejected(
            response,
            "invalid_params",
            "invalid params: action preparation rejected",
        );
        let prepared = fixture.observed.prepared.lock().unwrap();
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].params[field], value);
        assert!(prepared[0].params.get("action").is_none());
        assert!(prepared[0].params.get("client_type").is_none());
        assert_eq!(prepared[0].client_type, ClientType::Agent);
        assert!(fixture.observed.reviewed.lock().unwrap().is_empty());
        assert!(fixture.observed.executed.lock().unwrap().is_empty());
        assert!(
            fixture
                .audit
                .events_of_kind(AuditEventKind::OperationSucceeded)
                .is_empty()
        );
    }
    let fixture = Fixture::new();
    let mut params = gitlab_params();
    params["action"] = "set_ci_variable".into();
    params["client_type"] = "human".into();
    params["workspace"] = serde_json::to_value(workspace.claim()).unwrap();
    params["protected"] = false.into();
    params["masked"] = true.into();
    params["raw"] = false.into();
    params["environment_scope"] = "staging".into();
    params["variable_type"] = "file".into();
    let mut expected = params.clone();
    for key in ["action", "workspace", "client_type"] {
        expected.as_object_mut().unwrap().remove(key);
    }
    let response = fixture.call("gitlab", params, &workspace.identity()).await;
    assert!(response.error.is_none(), "{:?}", response.error);
    let prepared = fixture.observed.prepared.lock().unwrap();
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].params, expected);
    assert_eq!(
        prepared[0].target,
        HashMap::from([
            ("project".into(), "group/project".into()),
            ("key".into(), "VALID_0".into())
        ])
    );
    assert!(prepared[0].workspace.as_ref().unwrap().workspace_verified);
    assert_eq!(fixture.observed.reviewed.lock().unwrap().len(), 1);
    assert_eq!(fixture.observed.executed.lock().unwrap().len(), 1);
}
