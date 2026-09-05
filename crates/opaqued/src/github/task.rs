//! Provider boundary for approved, bounded repository secret publishing.
//! The caller owns policy, trusted approval, and durable slot reservation.

use std::collections::HashMap;

use opaque_core::task::{PublishAction, SlotOutcome, SlotState, TaskManifest};

use crate::sandbox::resolve::{CompositeResolver, SecretResolver};
use crate::vault::client::{DEFAULT_BASE_URL, VAULT_URL_ENV, VaultClient};
use crate::vault::resolve::{VaultResolver, validate_pinned_ref};

use super::client::{
    DEFAULT_GITHUB_API_URL, GITHUB_API_URL_ENV, GitHubApiError, GitHubClient, SecretScope,
};
use super::crypto::encrypt_secret;
use super::{DEFAULT_GITHUB_TOKEN_REF, GITHUB_TOKEN_REF_ENV};

const LOOPBACK_ENV: &str = "OPAQUE_DOGFOOD_LOOPBACK";

fn endpoint_from_env(name: &str, default: &str) -> Result<String, String> {
    let endpoint = std::env::var(name).unwrap_or_else(|_| default.to_owned());
    validate_endpoint(&endpoint, std::env::var(LOOPBACK_ENV).as_deref() == Ok("1"))?;
    Ok(endpoint.trim_end_matches('/').to_owned())
}

fn validate_endpoint(endpoint: &str, allow_loopback: bool) -> Result<(), String> {
    let invalid =
        || "provider endpoint requires HTTPS or explicit loopback dogfood configuration".to_owned();
    let parsed = reqwest::Url::parse(endpoint).map_err(|_| invalid())?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid());
    }
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback && allow_loopback) {
        return Err(invalid());
    }
    Ok(())
}

/// Populate provider authority and explicit token refs before policy preflight.
/// This function performs no provider requests and resolves no secrets.
pub fn prepare_task_manifest(manifest: &mut TaskManifest) -> Result<(), String> {
    manifest.github_api_url = endpoint_from_env(GITHUB_API_URL_ENV, DEFAULT_GITHUB_API_URL)?;
    manifest.vault_api_url = endpoint_from_env(VAULT_URL_ENV, DEFAULT_BASE_URL)?;
    let default_token =
        std::env::var(GITHUB_TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_GITHUB_TOKEN_REF.to_owned());
    let mut provisional_ids = HashMap::new();
    for action in &mut manifest.actions {
        let action = action
            .as_publish_mut()
            .ok_or("expected a secret publishing action")?;
        let next_id = provisional_ids.len() as u64 + 1;
        action.repository_id = *provisional_ids
            .entry(action.repo.to_ascii_lowercase())
            .or_insert(next_id);
        if action.github_token_ref.is_none() {
            action.github_token_ref = Some(default_token.clone());
        }
        validate_pinned_ref(&action.value_ref)
            .map_err(|_| "invalid pinned Vault source reference".to_owned())?;
    }
    manifest.validate().map_err(|e| e.to_string())
}

/// Bind exact provider repository identities after the caller's policy preflight.
/// Source secret values are never fetched during planning.
pub async fn plan_task_manifest(mut manifest: TaskManifest) -> Result<TaskManifest, String> {
    prepare_task_manifest(&mut manifest)?;
    let client = GitHubClient::from_base_url(&manifest.github_api_url)
        .map_err(|_| "GitHub provider configuration unavailable".to_owned())?;
    let resolver = CompositeResolver::new();
    for action in &mut manifest.actions {
        let action = action
            .as_publish_mut()
            .ok_or("expected a secret publishing action")?;
        let token_ref = action
            .github_token_ref
            .as_deref()
            .ok_or_else(|| "GitHub credential reference unavailable".to_owned())?;
        let token = resolver
            .resolve(token_ref)
            .map_err(|_| "GitHub credential unavailable".to_owned())?;
        token.mlock();
        let token = token
            .as_str()
            .ok_or_else(|| "GitHub credential unavailable".to_owned())?;
        let (owner, repo) = action
            .repo
            .split_once('/')
            .expect("manifest validated repository");
        action.repository_id = client
            .repository_id(token, owner, repo)
            .await
            .map_err(|_| "GitHub repository identity could not be verified".to_owned())?;
    }
    manifest.validate().map_err(|e| e.to_string())?;
    Ok(manifest)
}

fn outcome(state: SlotState, code: &str) -> SlotOutcome {
    SlotOutcome {
        inference_receipt: None,
        provider_run_id: None,
        state,
        code: code.to_owned(),
    }
}

fn unavailable() -> SlotOutcome {
    outcome(SlotState::Rejected, "source_unavailable")
}

fn publish_outcome(
    result: Result<super::client::SetSecretResponse, GitHubApiError>,
) -> SlotOutcome {
    match result {
        Ok(_) => outcome(SlotState::ApiAccepted, "api_accepted"),
        Err(
            GitHubApiError::Unauthorized
            | GitHubApiError::NotFound(_)
            | GitHubApiError::RateLimited,
        ) => outcome(SlotState::Rejected, "provider_rejected"),
        Err(GitHubApiError::UnexpectedStatus(code))
            if (400..500).contains(&code) && code != 408 =>
        {
            outcome(SlotState::Rejected, "provider_rejected")
        }
        Err(_) => outcome(SlotState::Unknown, "transport_unknown"),
    }
}

/// Execute one previously reserved action. All receipts use fixed public codes.
/// The broker's final callback runs after preparation and immediately before
/// PUT. That authorization is the in-flight boundary: revocation can prevent
/// later dispatches but cannot cancel a write already authorized for dispatch.
/// No approval, slot reservation, or retries occur at this layer.
pub async fn execute_task_action<F, Fut>(
    manifest: &TaskManifest,
    action: &PublishAction,
    before_publish: F,
) -> SlotOutcome
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), SlotOutcome>>,
{
    if manifest.validate().is_err()
        || !manifest
            .actions
            .iter()
            .any(|candidate| candidate.as_publish() == Some(action))
        || validate_pinned_ref(&action.value_ref).is_err()
    {
        return unavailable();
    }
    let Ok(github_url) = endpoint_from_env(GITHUB_API_URL_ENV, DEFAULT_GITHUB_API_URL) else {
        return unavailable();
    };
    let Ok(vault_url) = endpoint_from_env(VAULT_URL_ENV, DEFAULT_BASE_URL) else {
        return unavailable();
    };
    if github_url != manifest.github_api_url || vault_url != manifest.vault_api_url {
        return unavailable();
    }
    let Ok(client) = GitHubClient::from_base_url(&github_url) else {
        return unavailable();
    };
    let Ok(vault_client) = VaultClient::new() else {
        return unavailable();
    };
    if vault_client.base_url() != vault_url {
        return unavailable();
    }
    let Ok(source) = VaultResolver::new(vault_client).resolve(&action.value_ref) else {
        return unavailable();
    };
    source.mlock();
    let Some(token_ref) = action.github_token_ref.as_deref() else {
        return unavailable();
    };
    let Ok(token) = CompositeResolver::new().resolve(token_ref) else {
        return unavailable();
    };
    token.mlock();
    let Some(token_str) = token.as_str() else {
        return unavailable();
    };
    let Some((owner, repo)) = action.repo.split_once('/') else {
        return unavailable();
    };
    let scope = SecretScope::RepoActions { owner, repo };
    let Ok(key) = client.get_public_key_scoped(token_str, &scope).await else {
        return unavailable();
    };
    let Ok(encrypted) = encrypt_secret(source.as_bytes(), &key.key) else {
        return unavailable();
    };
    // Free the plaintext as soon as the sealed value is ready.
    drop(source);
    let Ok(current_id) = client.repository_id(token_str, owner, repo).await else {
        return unavailable();
    };
    if current_id != action.repository_id {
        return unavailable();
    }
    if let Err(outcome) = before_publish().await {
        return if outcome.validate().is_ok() {
            outcome
        } else {
            unavailable()
        };
    }
    publish_outcome(
        client
            .set_secret_scoped(
                token_str,
                &scope,
                &action.secret_name,
                &encrypted,
                &key.key_id,
                None,
            )
            .await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct EnvRestore(Vec<(String, Option<std::ffi::OsString>)>);

    impl EnvRestore {
        fn set(values: &[(&str, &str)]) -> Self {
            let mut previous = Vec::new();
            for (name, value) in values {
                previous.push(((*name).into(), std::env::var_os(name)));
                unsafe { std::env::set_var(name, value) };
            }
            Self(previous)
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (name, previous) in &self.0 {
                unsafe {
                    match previous {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    fn manifest() -> TaskManifest {
        TaskManifest {
            schema_version: 1,
            title: "Publish dogfood configuration".into(),
            expires_in_secs: 600,
            github_api_url: String::new(),
            vault_api_url: String::new(),
            actions: vec![
                PublishAction {
                    repo: "thinkstudio/opaque".into(),
                    repository_id: 0,
                    secret_name: "DOGFOOD_MARKER".into(),
                    value_ref: "vault:kv/data/demo?version=7#FIELD".into(),
                    github_token_ref: None,
                }
                .into(),
            ],
        }
    }

    async fn mount_repository(server: &MockServer, id: u64) {
        Mock::given(method("GET"))
            .and(path("/repos/thinkstudio/opaque"))
            .and(header("authorization", "Bearer disposable-pat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": id, "full_name": "thinkstudio/opaque"
            })))
            .mount(server)
            .await;
    }

    async fn mount_source(server: &MockServer, version: u64) {
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/demo"))
            .and(query_param("version", "7"))
            .and(header("x-vault-token", "disposable-vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": { "FIELD": "approved-disposable-marker" },
                    "metadata": { "version": version, "destroyed": false, "deletion_time": "" }
                }
            })))
            .mount(server)
            .await;
    }

    async fn mount_public_key(server: &MockServer) -> crypto_box::SecretKey {
        let key = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        Mock::given(method("GET"))
            .and(path("/repos/thinkstudio/opaque/actions/secrets/public-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "key_id": "dogfood-key", "key": BASE64.encode(key.public_key().as_bytes())
            })))
            .mount(server)
            .await;
        key
    }

    fn configure(github: &MockServer, vault: &MockServer) -> EnvRestore {
        EnvRestore::set(&[
            (GITHUB_API_URL_ENV, &github.uri()),
            (VAULT_URL_ENV, &vault.uri()),
            (LOOPBACK_ENV, "1"),
            (GITHUB_TOKEN_REF_ENV, "env:OPAQUE_TEST_TASK_PAT"),
            ("OPAQUE_TEST_TASK_PAT", "disposable-pat"),
            ("OPAQUE_VAULT_TOKEN_REF", "env:OPAQUE_TEST_TASK_VAULT_TOKEN"),
            ("OPAQUE_TEST_TASK_VAULT_TOKEN", "disposable-vault-token"),
        ])
    }

    #[test]
    fn endpoint_requires_explicit_loopback_opt_in() {
        assert!(validate_endpoint("http://127.0.0.1:8200", false).is_err());
        validate_endpoint("http://127.0.0.1:8200", true).unwrap();
        validate_endpoint("https://api.github.com", false).unwrap();
        for invalid in [
            "http://remote.example",
            "http://localhost@remote.example",
            "https://user:password@api.github.com",
            "https://api.github.com?redirect=elsewhere",
        ] {
            assert!(validate_endpoint(invalid, true).is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn planning_binds_authority_without_reading_source_and_validates_first() {
        let _guard = super::super::TEST_ENV_LOCK.lock().await;
        let github = MockServer::start().await;
        let vault = MockServer::start().await;
        let _env = configure(&github, &vault);
        mount_repository(&github, 101).await;
        let planned = plan_task_manifest(manifest()).await.unwrap();
        assert_eq!(planned.actions[0].as_publish().unwrap().repository_id, 101);
        assert_eq!(
            planned.actions[0]
                .as_publish()
                .unwrap()
                .github_token_ref
                .as_deref(),
            Some("env:OPAQUE_TEST_TASK_PAT")
        );
        assert_eq!(planned.github_api_url, github.uri());
        assert_eq!(planned.vault_api_url, vault.uri());
        assert!(vault.received_requests().await.unwrap().is_empty());

        github.reset().await;
        let mut invalid = manifest();
        invalid.actions.push(invalid.actions[0].clone());
        invalid.actions[1].as_publish_mut().unwrap().secret_name = "invalid-name".into();
        assert!(plan_task_manifest(invalid).await.is_err());
        assert!(github.received_requests().await.unwrap().is_empty());

        let mut multiple_repos = manifest();
        let mut second = multiple_repos.actions[0].as_publish().unwrap().clone();
        second.repo = "thinkstudio/adanima".into();
        multiple_repos.actions.push(second.into());
        prepare_task_manifest(&mut multiple_repos).unwrap();
        assert_ne!(
            multiple_repos.actions[0]
                .as_publish()
                .unwrap()
                .repository_id,
            multiple_repos.actions[1]
                .as_publish()
                .unwrap()
                .repository_id
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execution_encrypts_exact_source_and_classifies_write_outcomes_without_retry() {
        let _guard = super::super::TEST_ENV_LOCK.lock().await;
        let github = MockServer::start().await;
        let vault = MockServer::start().await;
        let _env = configure(&github, &vault);
        mount_repository(&github, 101).await;
        let planned = plan_task_manifest(manifest()).await.unwrap();
        mount_source(&vault, 7).await;
        for (status, expected_state, expected_code) in [
            (201, SlotState::ApiAccepted, "api_accepted"),
            (204, SlotState::ApiAccepted, "api_accepted"),
            (403, SlotState::Rejected, "provider_rejected"),
            (422, SlotState::Rejected, "provider_rejected"),
            (429, SlotState::Rejected, "provider_rejected"),
            (408, SlotState::Unknown, "transport_unknown"),
            (500, SlotState::Unknown, "transport_unknown"),
            (307, SlotState::Unknown, "transport_unknown"),
        ] {
            github.reset().await;
            mount_repository(&github, 101).await;
            let key = mount_public_key(&github).await;
            Mock::given(method("PUT"))
                .and(path(
                    "/repos/thinkstudio/opaque/actions/secrets/DOGFOOD_MARKER",
                ))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&github)
                .await;
            let result = execute_task_action(
                &planned,
                planned.actions[0].as_publish().unwrap(),
                || async { Ok(()) },
            )
            .await;
            assert_eq!(result.state, expected_state);
            assert_eq!(result.code, expected_code);
            result.validate().unwrap();
            let requests = github.received_requests().await.unwrap();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[1].url.path(), "/repos/thinkstudio/opaque");
            assert_eq!(requests[2].method, "PUT");
            let payload: serde_json::Value = serde_json::from_slice(&requests[2].body).unwrap();
            let ciphertext = BASE64
                .decode(payload["encrypted_value"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                key.unseal(&ciphertext).unwrap(),
                b"approved-disposable-marker"
            );
            assert!(
                !String::from_utf8_lossy(&requests[2].body).contains("approved-disposable-marker")
            );
            github.verify().await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execution_blocks_changed_source_repository_and_endpoint() {
        let _guard = super::super::TEST_ENV_LOCK.lock().await;
        let github = MockServer::start().await;
        let vault = MockServer::start().await;
        let _env = configure(&github, &vault);
        mount_repository(&github, 101).await;
        let planned = plan_task_manifest(manifest()).await.unwrap();
        github.reset().await;
        mount_source(&vault, 8).await;
        assert_eq!(
            execute_task_action(
                &planned,
                planned.actions[0].as_publish().unwrap(),
                || async { Ok(()) }
            )
            .await,
            unavailable()
        );
        assert!(github.received_requests().await.unwrap().is_empty());

        vault.reset().await;
        mount_source(&vault, 7).await;
        mount_repository(&github, 999).await;
        mount_public_key(&github).await;
        assert_eq!(
            execute_task_action(
                &planned,
                planned.actions[0].as_publish().unwrap(),
                || async { Ok(()) }
            )
            .await,
            unavailable()
        );
        assert!(
            github
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method != "PUT")
        );

        github.reset().await;
        vault.reset().await;
        let changed = MockServer::start().await;
        let _changed = EnvRestore::set(&[(GITHUB_API_URL_ENV, &changed.uri())]);
        assert_eq!(
            execute_task_action(
                &planned,
                planned.actions[0].as_publish().unwrap(),
                || async { Ok(()) }
            )
            .await,
            unavailable()
        );
        assert!(github.received_requests().await.unwrap().is_empty());
        assert!(vault.received_requests().await.unwrap().is_empty());
        assert!(changed.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn final_authority_gate_runs_after_delayed_preparation_and_prevents_put() {
        let _guard = super::super::TEST_ENV_LOCK.lock().await;
        let github = MockServer::start().await;
        let vault = MockServer::start().await;
        let _env = configure(&github, &vault);
        mount_repository(&github, 101).await;
        let planned = plan_task_manifest(manifest()).await.unwrap();
        github.reset().await;
        mount_source(&vault, 7).await;
        mount_public_key(&github).await;
        Mock::given(method("GET"))
            .and(path("/repos/thinkstudio/opaque"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(50))
                    .set_body_json(
                        serde_json::json!({"id": 101, "full_name": "thinkstudio/opaque"}),
                    ),
            )
            .mount(&github)
            .await;
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result = execute_task_action(
            &planned,
            planned.actions[0].as_publish().unwrap(),
            || async {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // The callback observes all preparation requests complete and
                // rejects authority that was revoked while the provider was slow.
                assert_eq!(github.received_requests().await.unwrap().len(), 2);
                Err(outcome(SlotState::Rejected, "revoked"))
            },
        )
        .await;
        assert_eq!(result, outcome(SlotState::Rejected, "revoked"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            github
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method != "PUT")
        );
    }
}
