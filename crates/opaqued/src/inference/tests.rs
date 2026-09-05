use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
