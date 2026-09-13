use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn github_capture_is_bound_to_each_prompt_and_seed_cannot_execute() {
    use opaque_core::inference::github::{GithubCiRun, GithubCiSnapshot, RunConclusion, RunStatus};
    let (server, mut profile, _) = fixture().await;
    profile.config.source_id = GITHUB_SOURCE_ID.into();
    profile.config.source_snapshot_sha256.clear();
    profile.config.github_ci = Some(GithubCiSource {
        repository: "owner/repository".into(),
        workflow_id: 7,
        branch: "main".into(),
    });
    let mut manifest = public_demo_manifest(&profile, "CI review".into(), 600).unwrap();
    let seed = manifest.clone();
    let result = execute_inference_action(
        &seed,
        seed.actions[0].as_inference().unwrap(),
        &profile,
        || async { Ok(()) },
    )
    .await;
    assert_eq!(result.outcome.state, SlotState::Rejected);
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "an uncaptured seed must not resolve credentials or contact the model"
    );
    let snapshot = GithubCiSnapshot {
        source: profile.github_ci.clone().unwrap(),
        repository_id: 9,
        observed_at: 100,
        runs: vec![GithubCiRun {
            id: 10,
            attempt: 1,
            head_sha: "a".repeat(40),
            status: RunStatus::Completed,
            conclusion: Some(RunConclusion::Failure),
        }],
    };
    attach_github_snapshot(&mut manifest, &profile, snapshot.clone()).unwrap();
    assert_ne!(manifest.digest().unwrap(), seed.digest().unwrap());
    for action in &manifest.actions {
        let action = action.as_inference().unwrap();
        assert_eq!(action.source_snapshot_sha256, snapshot.digest());
        assert_eq!(
            action.prompt_sha256,
            sha256(action_prompt(&profile, action).unwrap().as_bytes())
        );
    }
    let mut changed = manifest.clone();
    changed.actions[0]
        .as_inference_mut()
        .unwrap()
        .github_ci_snapshot
        .as_mut()
        .unwrap()
        .runs[0]
        .conclusion = Some(RunConclusion::Success);
    assert!(prepare_inference_manifest(&mut changed, &profile).is_err());
    let mut other_profile = profile.clone();
    other_profile.config.github_ci.as_mut().unwrap().workflow_id = 8;
    assert!(prepare_inference_manifest(&mut manifest.clone(), &other_profile).is_err());
    Mock::given(method("POST"))
        .and(path("/completion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(&profile)))
        .expect(1)
        .mount(&server)
        .await;
    let action = manifest.actions[0].as_inference().unwrap();
    let result = execute_inference_action(&manifest, action, &profile, || async { Ok(()) }).await;
    assert_eq!(result.outcome.state, SlotState::ApiAccepted);
    result.receipt.unwrap().validate(action).unwrap();
    let requests = server.received_requests().await.unwrap();
    let template = requests
        .iter()
        .find(|request| request.url.path() == "/apply-template")
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&template.body).unwrap();
    assert_eq!(body["messages"][0]["content"], snapshot.prompt(1).unwrap());
}

async fn fixture() -> (MockServer, TrustedInferenceProfile, TaskManifest) {
    let server = MockServer::start().await;
    let tenant = TenantBinding::new(
        opaque_core::tenant::TenantId::parse("tenant-a").unwrap(),
        uuid::Uuid::new_v4(),
    )
    .unwrap();
    let config = InferenceProfileConfig {
        profile_id: "public-fixture".into(),
        api_url: server.uri(),
        model_id: "fixture-model.gguf".into(),
        model_path: "/models/fixture-model.gguf".into(),
        model_artifact_sha256: "a".repeat(64),
        chat_template_sha256: sha256(b"fixed-template-v1"),
        server_build: "b1-fixture".into(),
        service_uid: uuid::Uuid::new_v4(),
        source_id: DEMO_SOURCE_ID.into(),
        github_ci: None,
        source_snapshot_sha256: demo_source_snapshot_sha256(),
        credential_ref: None,
        allow_loopback_http: true,
    };
    let profile = config.bind(&tenant).unwrap();
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status":"ok"})))
        .mount(&server)
        .await;
    Mock::given(method("GET")).and(path("/props"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model_path":profile.model_path,"build_info":profile.server_build,"chat_template":"fixed-template-v1",
            "total_slots":1,"default_generation_settings":{"n_ctx":2048}
        }))).mount(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":[{"id":profile.model_id}]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/apply-template"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"prompt":"formatted public fixture"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tokenize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tokens":[10,11,12]})))
        .mount(&server)
        .await;
    let manifest = public_demo_manifest(&profile, "Synthetic receipt review".into(), 600).unwrap();
    (server, profile, manifest)
}

fn completion(profile: &TrustedInferenceProfile) -> serde_json::Value {
    json!({"content":"Artifact smoke passed. Service health was not observed.","model":profile.model_id,
        "stop":true,"truncated":false,"stop_type":"eos","tokens_evaluated":3,"tokens_predicted":8,
        "tokens":[1,2,3,4,5,6,7,8],"generation_settings":{"n_predict":96}})
}

async fn completion_requests(server: &MockServer) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == "/completion")
        .collect()
}

#[tokio::test]
async fn planned_public_source_executes_exact_native_payload_once() {
    let (server, profile, manifest) = fixture().await;
    Mock::given(method("POST"))
        .and(path("/completion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(&profile)))
        .expect(1)
        .mount(&server)
        .await;
    let manifest = plan_inference_manifest(manifest, &profile).await.unwrap();
    assert!(completion_requests(&server).await.is_empty());
    let action = manifest.actions[0].as_inference().unwrap();
    let calls = AtomicUsize::new(0);
    let result = execute_inference_action(&manifest, action, &profile, || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.outcome.state, SlotState::ApiAccepted);
    let receipt = result.receipt.unwrap();
    receipt.validate(action).unwrap();
    assert_eq!(receipt.reserved_output_tokens, 96);
    assert_eq!(receipt.observed_output_tokens, Some(8));
    assert_eq!(
        receipt.output_text.as_deref(),
        Some("Artifact smoke passed. Service health was not observed.")
    );
    assert_eq!(result.outcome.inference_receipt.as_ref(), Some(&receipt));
    let requests = completion_requests(&server).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
        json!({
            "model":profile.model_id,"prompt":[10,11,12],"n_predict":96,"n_cmpl":1,"temperature":0.0,
            "seed":0,"samplers":["temperature"],"cache_prompt":false,"stream":false,"return_tokens":true,
            "ignore_eos":false,"n_probs":0,"n_cache_reuse":0,"stop":[],"lora":[]
        })
    );
    let all = server.received_requests().await.unwrap();
    for request in all
        .iter()
        .filter(|request| request.url.path() == "/tokenize")
    {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            json!({
                "content":"formatted public fixture","add_special":false,"parse_special":true,"with_pieces":false
            })
        );
    }
}

#[tokio::test]
async fn changed_authority_and_source_are_rejected_before_provider_io() {
    let (server, profile, manifest) = fixture().await;
    for kind in 0..7 {
        let mut changed = manifest.clone();
        for slot in &mut changed.actions {
            let action = slot.as_inference_mut().unwrap();
            match kind {
                0 => action.tenant.broker_id = uuid::Uuid::new_v4(),
                1 => action.profile_sha256 = "f".repeat(64),
                2 => action.model_id = "other-model".into(),
                3 => action.source_snapshot_sha256 = "f".repeat(64),
                4 => action.prompt_sha256 = "f".repeat(64),
                5 => action.options.max_output_tokens = 97,
                _ => action.credential_ref = Some("keychain:other/credential".into()),
            }
        }
        assert!(prepare_inference_manifest(&mut changed, &profile).is_err());
        let result = execute_inference_action(
            &changed,
            changed.actions[0].as_inference().unwrap(),
            &profile,
            || async { panic!("changed authority must never reach dispatch fence") },
        )
        .await;
        assert_eq!(result.outcome.state, SlotState::Rejected);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn final_gate_denial_after_delayed_preparation_prevents_generation() {
    let (server, profile, manifest) = fixture().await;
    Mock::given(method("POST"))
        .and(path("/apply-template"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"prompt":"formatted public fixture"}))
                .set_delay(std::time::Duration::from_millis(20)),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let result = execute_inference_action(
        &manifest,
        manifest.actions[0].as_inference().unwrap(),
        &profile,
        || async { Err(outcome(SlotState::Rejected, "revoked")) },
    )
    .await;
    assert_eq!(result.outcome.code, "revoked");
    assert!(result.receipt.is_none());
    assert!(completion_requests(&server).await.is_empty());
}

#[tokio::test]
async fn tokenizer_cap_is_enforced_before_dispatch() {
    let (server, profile, manifest) = fixture().await;
    Mock::given(method("POST"))
        .and(path("/tokenize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tokens":vec![1;513]})))
        .with_priority(1)
        .mount(&server)
        .await;
    assert!(
        plan_inference_manifest(manifest.clone(), &profile)
            .await
            .is_err()
    );
    let result = execute_inference_action(
        &manifest,
        manifest.actions[0].as_inference().unwrap(),
        &profile,
        || async { panic!("oversize tokenizer result must not reach dispatch fence") },
    )
    .await;
    assert_eq!(result.outcome.state, SlotState::Rejected);
    assert!(completion_requests(&server).await.is_empty());
}

#[tokio::test]
async fn changed_model_evidence_fails_before_tokenization() {
    let (server, profile, manifest) = fixture().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data":[{"id":"other-model"}]})),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let result = execute_inference_action(
        &manifest,
        manifest.actions[0].as_inference().unwrap(),
        &profile,
        || async { panic!("model evidence mismatch must not reach dispatch fence") },
    )
    .await;
    assert_eq!(result.outcome.state, SlotState::Rejected);
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
}

#[tokio::test]
async fn uncertain_and_rejected_attempts_keep_full_allowance_without_retry() {
    for status in [400, 408, 429, 500, 302] {
        let (server, profile, manifest) = fixture().await;
        Mock::given(method("POST"))
            .and(path("/completion"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", format!("{}/redirected", server.uri()))
                    .set_body_string("private provider error must not leave provider boundary"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = execute_inference_action(
            &manifest,
            manifest.actions[0].as_inference().unwrap(),
            &profile,
            || async { Ok(()) },
        )
        .await;
        let expected = if status == 400 || status == 429 {
            SlotState::Rejected
        } else {
            SlotState::Unknown
        };
        assert_eq!(result.outcome.state, expected);
        let receipt = result.receipt.unwrap();
        assert_eq!(receipt.reserved_output_tokens, 96);
        assert!(receipt.output_text.is_none());
        assert_eq!(completion_requests(&server).await.len(), 1);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.url.path() != "/redirected")
        );
        assert!(
            !serde_json::to_string(&result.outcome)
                .unwrap()
                .contains("private provider error")
        );
    }
}

#[tokio::test]
async fn malformed_overrun_and_secret_output_remain_unknown() {
    for kind in 0..5 {
        let (server, profile, manifest) = fixture().await;
        let mut response = completion(&profile);
        match kind {
            0 => response["tokens_predicted"] = json!(97),
            1 => response["tokens_evaluated"] = json!(4),
            2 => response["content"] = json!("AKIAIOSFODNN7EXAMPLE"),
            3 => response["content"] = json!("unsafe\u{1b}[2Jtext"),
            _ => response = json!({"content":"missing evidence"}),
        }
        Mock::given(method("POST"))
            .and(path("/completion"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let result = execute_inference_action(
            &manifest,
            manifest.actions[0].as_inference().unwrap(),
            &profile,
            || async { Ok(()) },
        )
        .await;
        assert_eq!(result.outcome.state, SlotState::Unknown);
        assert_eq!(result.outcome.code, "provider_contract_violation");
        let receipt = result.receipt.unwrap();
        receipt
            .validate(manifest.actions[0].as_inference().unwrap())
            .unwrap();
        assert!(receipt.output_text.is_none());
        assert!(receipt.output_sha256.is_none());
        assert_eq!(receipt.reserved_output_tokens, 96);
    }
}

#[tokio::test]
async fn timeout_is_unknown_and_never_retried() {
    let (server, profile, manifest) = fixture().await;
    Mock::given(method("POST"))
        .and(path("/completion"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(completion(&profile))
                .set_delay(std::time::Duration::from_millis(150)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = execute_with_deadline(
        &manifest,
        manifest.actions[0].as_inference().unwrap(),
        &profile,
        std::time::Duration::from_millis(30),
        || async { Ok(()) },
    )
    .await;
    assert_eq!(result.outcome.code, "transport_unknown");
    assert_eq!(result.receipt.unwrap().reserved_output_tokens, 96);
    assert_eq!(completion_requests(&server).await.len(), 1);
}

#[test]
fn trusted_profile_rejects_endpoint_source_and_credential_expansion() {
    let tenant = TenantBinding::new(
        opaque_core::tenant::TenantId::parse("tenant-a").unwrap(),
        uuid::Uuid::new_v4(),
    )
    .unwrap();
    let config = InferenceProfileConfig {
        profile_id: "public-fixture".into(),
        api_url: "https://model.example.invalid".into(),
        model_id: "fixture-model".into(),
        model_path: "/models/fixture.gguf".into(),
        model_artifact_sha256: "a".repeat(64),
        chat_template_sha256: "b".repeat(64),
        server_build: "b1-fixture".into(),
        service_uid: uuid::Uuid::new_v4(),
        source_id: DEMO_SOURCE_ID.into(),
        github_ci: None,
        source_snapshot_sha256: demo_source_snapshot_sha256(),
        credential_ref: None,
        allow_loopback_http: false,
    };
    assert!(config.bind(&tenant).is_ok());
    for value in [
        "http://192.168.1.5:8080",
        "https://user:secret@example.invalid",
        "https://example.invalid/path",
        "https://example.invalid?token=value",
    ] {
        let mut changed = config.clone();
        changed.api_url = value.into();
        assert!(changed.bind(&tenant).is_err());
    }
    let mut changed = config.clone();
    changed.source_id = "private-warehouse".into();
    assert!(changed.bind(&tenant).is_err());
    for reference in [
        "env:TOKEN",
        "pass:opaque/inference-fixture",
        "keychain:",
        "keychain:opaque/",
        "keychain:/credential",
        "keychain:opaque/credential?version=1",
        "vault:kv/data/provider#TOKEN",
    ] {
        let mut changed = config.clone();
        changed.credential_ref = Some(reference.into());
        assert!(changed.bind(&tenant).is_err(), "{reference}");
    }
    for reference in [
        "keychain:opaque/inference-fixture",
        "vault:kv/data/provider?version=1#TOKEN",
    ] {
        let mut changed = config.clone();
        changed.credential_ref = Some(reference.into());
        let profile = changed.bind(&tenant).unwrap();
        assert!(public_demo_manifest(&profile, "Credential validation".into(), 600).is_ok());
    }
}

#[tokio::test]
async fn each_model_identity_field_and_metadata_status_fails_before_preprocessing() {
    for kind in 0..11 {
        let (server, profile, manifest) = fixture().await;
        let mut properties = json!({
            "model_path":profile.model_path,"build_info":profile.server_build,"chat_template":"fixed-template-v1",
            "total_slots":1,"default_generation_settings":{"n_ctx":2048}
        });
        let (endpoint, status, body, expected_gets) = match kind {
            0 => ("/health", 200, json!({"status":"loading model"}), 1),
            1 => {
                properties["model_path"] = json!("/models/replaced.gguf");
                ("/props", 200, properties, 2)
            }
            2 => {
                properties["build_info"] = json!("unreviewed-build");
                ("/props", 200, properties, 2)
            }
            3 => {
                properties["chat_template"] = json!("changed template");
                ("/props", 200, properties, 2)
            }
            4 => {
                properties["total_slots"] = json!(2);
                ("/props", 200, properties, 2)
            }
            5 => {
                properties["default_generation_settings"]["n_ctx"] = json!(607);
                ("/props", 200, properties, 2)
            }
            6 => ("/v1/models", 200, json!({"data":[]}), 3),
            7 => (
                "/v1/models",
                200,
                json!({"data":[{"id":profile.model_id},{"id":"second-model"}]}),
                3,
            ),
            8 => (
                "/health",
                503,
                json!({"private":"provider detail must not escape"}),
                1,
            ),
            9 => (
                "/props",
                401,
                json!({"private":"provider detail must not escape"}),
                2,
            ),
            _ => (
                "/v1/models",
                500,
                json!({"private":"provider detail must not escape"}),
                3,
            ),
        };
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        let result = execute_inference_action(
            &manifest,
            manifest.actions[0].as_inference().unwrap(),
            &profile,
            || async { panic!("identity mutation reached final dispatch fence") },
        )
        .await;
        assert_eq!(
            result.outcome.state,
            SlotState::Rejected,
            "identity mutation {kind}"
        );
        assert_eq!(result.outcome.code, "source_unavailable");
        assert!(result.receipt.is_none());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), expected_gets, "identity mutation {kind}");
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() == "GET")
        );
        assert!(
            !serde_json::to_string(&result.outcome)
                .unwrap()
                .contains("provider detail")
        );
    }
}

#[tokio::test]
async fn model_drift_after_tokenization_stops_before_the_final_authority_fence() {
    use std::sync::Arc;
    let (server, profile, manifest) = fixture().await;
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = reads.clone();
    let model_path = profile.model_path.clone();
    let build = profile.server_build.clone();
    Mock::given(method("GET")).and(path("/props"))
        .respond_with(move |_request: &wiremock::Request| {
            let count = observed.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "model_path":model_path,"build_info":if count == 0 { build.as_str() } else { "replaced-after-tokenization" },
                "chat_template":"fixed-template-v1","total_slots":1,"default_generation_settings":{"n_ctx":2048}
            }))
        }).with_priority(1).expect(2).mount(&server).await;
    let result = execute_inference_action(
        &manifest,
        manifest.actions[0].as_inference().unwrap(),
        &profile,
        || async { panic!("changed model crossed final authority fence") },
    )
    .await;
    assert_eq!(result.outcome.state, SlotState::Rejected);
    assert!(result.receipt.is_none());
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        [
            "/health",
            "/props",
            "/v1/models",
            "/apply-template",
            "/tokenize",
            "/health",
            "/props"
        ]
    );
}

#[tokio::test]
async fn empty_or_invalid_preprocessing_never_spends_a_completion_attempt() {
    for kind in 0..4 {
        let (server, profile, manifest) = fixture().await;
        let (endpoint, body) = match kind {
            0 => ("/apply-template", json!({"prompt":""})),
            1 => ("/apply-template", json!({"prompt":"x".repeat(8193)})),
            2 => ("/tokenize", json!({"tokens":[]})),
            _ => ("/tokenize", json!({"tokens":[10,-1,12]})),
        };
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        let result = execute_inference_action(
            &manifest,
            manifest.actions[0].as_inference().unwrap(),
            &profile,
            || async { panic!("invalid preprocessing reached dispatch") },
        )
        .await;
        assert_eq!(result.outcome.state, SlotState::Rejected);
        assert!(result.receipt.is_none());
        assert!(completion_requests(&server).await.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/tokenize")
                .count(),
            usize::from(kind >= 2)
        );
    }
    let (server, profile, _) = fixture().await;
    let client = InferenceClient::new(&profile).unwrap();
    for prompt in [String::new(), "x".repeat(8193)] {
        assert!(client.tokenize_prompt(&prompt, None).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// Exercise the real provider result and ledger together. Approval is explicitly
/// synthetic here; signed ceremony and live identity are covered by daemon tests.
async fn retain_unknown_across_restart(
    profile: &TrustedInferenceProfile,
    manifest: TaskManifest,
    expected_code: &str,
) {
    use crate::task_store::TaskStore;
    use opaque_core::task::{TaskApprovalMode, TaskState};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inference.sqlite");
    let owner = profile.tenant.owner_key(501, None);
    let store = TaskStore::open_for_tenant(&path, Some(profile.tenant.clone())).unwrap();
    let now = opaque_core::identity::now_unix();
    let task = store.create(&owner, manifest, now).unwrap();
    store.claim(&task.id, &owner, now).unwrap();
    store
        .approve(
            &task.id,
            &owner,
            &task.manifest_digest,
            TaskApprovalMode::InsecureTest,
            now,
        )
        .unwrap();
    let slot = &task.slots[0];
    store
        .reserve_slot(&task.id, &owner, &slot.id, "attempt-one", now)
        .unwrap();
    let fences = AtomicUsize::new(0);
    let result = execute_inference_action(
        &task.manifest,
        slot.action.as_inference().unwrap(),
        profile,
        || async {
            fences.fetch_add(1, Ordering::SeqCst);
            store
                .authorize_dispatch(
                    &task.id,
                    &owner,
                    &slot.id,
                    "attempt-one",
                    opaque_core::identity::now_unix(),
                )
                .map_err(|_| outcome(SlotState::Rejected, "revoked"))
        },
    )
    .await;
    assert_eq!(fences.load(Ordering::SeqCst), 1);
    assert_eq!(result.outcome.state, SlotState::Unknown);
    assert_eq!(result.outcome.code, expected_code);
    let receipt = result.receipt.unwrap();
    receipt
        .validate(slot.action.as_inference().unwrap())
        .unwrap();
    assert_eq!(receipt.reserved_output_tokens, 96);
    assert!(receipt.output_text.is_none());
    assert!(receipt.output_sha256.is_none());
    let finished = opaque_core::identity::now_unix();
    store
        .finalize_slot(
            &task.id,
            &owner,
            &slot.id,
            "attempt-one",
            result.outcome,
            finished,
        )
        .unwrap();
    let closed = store.finish_run(&task.id, &owner, finished).unwrap();
    assert_eq!(closed.state, TaskState::Partial);
    drop(store);
    let reopened = TaskStore::open_for_tenant(&path, Some(profile.tenant.clone())).unwrap();
    assert_eq!(reopened.get(&task.id, &owner, finished).unwrap(), closed);
    assert_eq!(closed.slots[0].state, SlotState::Unknown);
    assert!(closed.slots[0].reserved_at.is_some());
    assert_eq!(closed.slots[0].request_id.as_deref(), Some("attempt-one"));
    assert_eq!(
        closed.slots[0]
            .action
            .as_inference()
            .unwrap()
            .options
            .max_output_tokens,
        96
    );
    assert!(
        reopened
            .reserve_slot(&task.id, &owner, &slot.id, "replay", finished)
            .is_err()
    );
    assert!(
        reopened
            .reserve_slot(&task.id, &owner, &task.slots[1].id, "later-slot", finished)
            .is_err()
    );
    assert!(reopened.claim(&task.id, &owner, finished).is_err());
    assert_eq!(reopened.get(&task.id, &owner, finished).unwrap(), closed);
}

#[tokio::test]
async fn individual_completion_contract_mutations_remain_durably_charged_unknown() {
    for kind in 0..8 {
        let (server, profile, manifest) = fixture().await;
        let mut response = completion(&profile);
        match kind {
            0 => response["model"] = json!("different-completion-model"),
            1 => response["stop"] = json!(false),
            2 => response["truncated"] = json!(true),
            3 => response["tokens"] = json!([1, 2, 3, 4, 5, 6, 7]),
            4 => response["tokens"] = json!([1, 2, 3, 4, 5, 6, 7, -1]),
            5 => response["stop_type"] = json!("unexpected"),
            6 => response["content"] = json!("x".repeat(8193)),
            _ => response["generation_settings"]["n_predict"] = json!(95),
        }
        Mock::given(method("POST"))
            .and(path("/completion"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        retain_unknown_across_restart(&profile, manifest, "provider_contract_violation").await;
        assert_eq!(
            completion_requests(&server).await.len(),
            1,
            "completion mutation {kind}"
        );
    }
}

#[tokio::test]
async fn bearer_is_exactly_one_authorization_header_and_never_url_or_payload_data() {
    let (server, profile, _) = fixture().await;
    Mock::given(method("POST"))
        .and(path("/completion"))
        .respond_with(ResponseTemplate::new(200).set_body_json(completion(&profile)))
        .expect(1)
        .mount(&server)
        .await;
    let token = "synthetic-inference-bearer-only";
    let client = InferenceClient::new(&profile).unwrap();
    client.verify_identity(&profile, Some(token)).await.unwrap();
    let tokens = client
        .tokenize_prompt("Reviewed public fixture", Some(token))
        .await
        .unwrap();
    assert!(matches!(
        client.complete(&profile, &tokens, Some(token)).await,
        CompletionResult::Observed { tokens: 8, .. }
    ));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 6);
    for request in requests {
        assert_eq!(request.headers.get_all("authorization").iter().count(), 1);
        assert_eq!(request.headers["authorization"], format!("Bearer {token}"));
        assert!(!request.url.as_str().contains(token));
        assert!(request.url.query().is_none());
        assert!(!String::from_utf8_lossy(&request.body).contains(token));
        for (name, value) in &request.headers {
            if name != "authorization" {
                assert!(!value.to_str().unwrap().contains(token));
            }
        }
    }
}

#[derive(Clone, Copy)]
enum StreamMutation {
    OversizedHealth,
    OversizedCompletion,
    TruncatedCompletion,
}

struct StreamingFixture {
    url: String,
    completions: std::sync::Arc<AtomicUsize>,
    worker: tokio::task::JoinHandle<()>,
}
impl Drop for StreamingFixture {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

/// A real HTTP/1 transport, forwarding valid metadata to the existing fixture.
/// The mutated body is framed here so tests cannot accidentally replace streamed
/// overflow/EOF with a Content-Length rejection or a synthetic client result.
async fn streaming_fixture(
    upstream: &str,
    response: serde_json::Value,
    mutation: StreamMutation,
) -> StreamingFixture {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = upstream.to_owned();
    let completions = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = completions.clone();
    let worker = tokio::spawn(async move {
        let forward = reqwest::Client::builder().no_proxy().build().unwrap();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut incoming = Vec::new();
            let mut bytes = [0; 4096];
            let header_end = loop {
                let size = stream.read(&mut bytes).await.unwrap();
                assert!(size > 0);
                incoming.extend_from_slice(&bytes[..size]);
                assert!(incoming.len() <= 32768);
                if let Some(position) = incoming.windows(4).position(|w| w == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let header = std::str::from_utf8(&incoming[..header_end])
                .unwrap()
                .to_owned();
            let first = header
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>();
            let method = first[0];
            let path = first[1];
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while incoming.len() - header_end < length {
                let size = stream.read(&mut bytes).await.unwrap();
                assert!(size > 0);
                incoming.extend_from_slice(&bytes[..size]);
                assert!(incoming.len() <= 32768);
            }
            let mutated = (path == "/health"
                && matches!(mutation, StreamMutation::OversizedHealth))
                || path == "/completion";
            if path == "/completion" {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            if mutated {
                let mut value = if path == "/health" {
                    json!({"status":"ok"})
                } else {
                    response.clone()
                };
                if !matches!(mutation, StreamMutation::TruncatedCompletion) {
                    value["otherwise_ignored_padding"] =
                        json!("x".repeat(if path == "/health" { 6000 } else { 40000 }));
                }
                let body = serde_json::to_vec(&value).unwrap();
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                if matches!(mutation, StreamMutation::TruncatedCompletion) {
                    // The counted operation happened, but this complete JSON is
                    // shorter than the promised chunk. EOF must remain Unknown.
                    stream
                        .write_all(format!("{:x}\r\n", body.len() + 17).as_bytes())
                        .await
                        .unwrap();
                    stream.write_all(&body).await.unwrap();
                } else {
                    // Each chunk is under the limit; their aggregate exceeds it.
                    // Without aggregate accounting, the valid otherwise-ignored
                    // padding would be accepted and the test would fail.
                    let chunk_size = if path == "/health" { 3072 } else { 16384 };
                    for chunk in body.chunks(chunk_size) {
                        let mut frame = format!("{:x}\r\n", chunk.len()).into_bytes();
                        frame.extend(chunk);
                        frame.extend(b"\r\n");
                        if stream.write_all(&frame).await.is_err() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                }
            } else {
                let request = forward
                    .request(
                        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                        format!("{upstream}{path}"),
                    )
                    .body(incoming[header_end..header_end + length].to_vec())
                    .header("content-type", "application/json");
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), reqwest::StatusCode::OK);
                let body = response.bytes().await.unwrap();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
        }
    });
    StreamingFixture {
        url,
        completions,
        worker,
    }
}

#[tokio::test]
async fn streamed_body_limits_and_transport_loss_keep_effects_bounded_and_durable() {
    for mutation in [
        StreamMutation::OversizedHealth,
        StreamMutation::OversizedCompletion,
        StreamMutation::TruncatedCompletion,
    ] {
        let (server, mut profile, _) = fixture().await;
        let stream = streaming_fixture(&server.uri(), completion(&profile), mutation).await;
        profile.config.api_url = stream.url.clone();
        let manifest =
            public_demo_manifest(&profile, "Streamed protocol evidence".into(), 600).unwrap();
        if matches!(mutation, StreamMutation::OversizedHealth) {
            let result = execute_inference_action(
                &manifest,
                manifest.actions[0].as_inference().unwrap(),
                &profile,
                || async { panic!("oversized health must not dispatch a completion") },
            )
            .await;
            assert_eq!(result.outcome.state, SlotState::Rejected);
            assert!(result.receipt.is_none());
            assert_eq!(stream.completions.load(Ordering::SeqCst), 0);
            assert!(server.received_requests().await.unwrap().is_empty());
        } else {
            retain_unknown_across_restart(
                &profile,
                manifest,
                if matches!(mutation, StreamMutation::TruncatedCompletion) {
                    "transport_unknown"
                } else {
                    "provider_contract_violation"
                },
            )
            .await;
            assert_eq!(stream.completions.load(Ordering::SeqCst), 1);
        }
    }
}
