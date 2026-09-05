//! HTTP and durable-ledger regressions for the synthetic bounded-work surface.
use super::*;
use opaque_metrics::bounded_demo::{Error, Store, TaskReference, TaskState};

async fn value(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 32768).await.unwrap()).unwrap()
}
async fn task(fixture: &Fixture, cookie: &str) -> Value {
    let response = fixture
        .browser("GET", "/api/work-task", cookie, Value::Null)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    value(response).await
}
fn reference(task: &Value) -> Value {
    json!({"task_id":task["task_id"],"manifest_sha256":task["manifest_sha256"]})
}
async fn approve(fixture: &Fixture, cookie: &str) -> Value {
    let task = task(fixture, cookie).await;
    let response = fixture
        .browser("POST", "/api/work-task/approve", cookie, reference(&task))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = value(response).await;
    assert_eq!(result["state"], "approved");
    result
}
async fn source(fixture: &Fixture, delay: Duration, status: u16) {
    Mock::given(method("POST"))
        .and(path("/v1/metrics/query"))
        .respond_with(move |request: &wiremock::Request| {
            assert_eq!(
                request.body_json::<Value>().unwrap(),
                json!({"metrics":["manual_review_rate_percent"],"window_secs":60})
            );
            ResponseTemplate::new(status)
                .set_delay(delay)
                .set_body_json(json!({
                    "tenant_id":"customer-a", "window_secs":60,"as_of":now(),"watermark":now(),
                    "metrics":[{"name":"manual_review_rate_percent","value":17.25,"count":400}]
                }))
        })
        .mount(&fixture.source)
        .await;
}
async fn wait_for_source(fixture: &Fixture) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.source.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
fn request(fixture: &Fixture, cookie: &str, path: &str, body: Value) -> Request<Body> {
    let mut request = fixture.request("POST", path, body);
    request
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    request
}

#[tokio::test]
async fn bounded_task_exact_manifest_single_use_and_reload() {
    let fixture = Fixture::organization(false).await;
    let (_, cookie) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let planned = task(&fixture, &cookie).await;
    assert_eq!(planned["state"], "planned");
    assert_eq!(planned["simulation"], true);
    assert_eq!(planned["manifest"]["max_uses"], 1);
    assert_eq!(planned["manifest"]["window_secs"], 60);
    assert_eq!(planned, task(&fixture, &cookie).await);
    let mut override_request = reference(&planned);
    override_request["tenant_id"] = json!("customer-b");
    assert_eq!(
        fixture
            .browser("POST", "/api/work-task/approve", &cookie, override_request)
            .await
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut wrong_digest = reference(&planned);
    wrong_digest["manifest_sha256"] = json!("0".repeat(64));
    assert_eq!(
        fixture
            .browser("POST", "/api/work-task/approve", &cookie, wrong_digest)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/work-task/execute",
                &cookie,
                reference(&planned)
            )
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let mut cross_origin = request(
        &fixture,
        &cookie,
        "/api/work-task/approve",
        reference(&planned),
    );
    cross_origin
        .headers_mut()
        .insert(header::ORIGIN, "https://foreign.example".parse().unwrap());
    assert_eq!(
        fixture
            .router()
            .oneshot(cross_origin)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
    source(&fixture, Duration::ZERO, 200).await;
    let approved = approve(&fixture, &cookie).await;
    assert_eq!(approved["approval"]["kind"], "synthetic_demo_confirmation");
    let response = fixture
        .browser(
            "POST",
            "/api/work-task/execute",
            &cookie,
            reference(&planned),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let completed = value(response).await;
    assert_eq!(completed["state"], "completed");
    assert_eq!(completed["consumed"], true);
    assert_eq!(
        completed["receipt"]["evidence"],
        "synthetic_source_observed"
    );
    assert_eq!(completed["receipt"]["result"]["metrics"][0]["value"], 17.25);
    assert_eq!(completed, task(&fixture, &cookie).await);
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/work-task/execute",
                &cookie,
                reference(&planned)
            )
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn bounded_task_concurrent_execution_reserves_before_source_once() {
    let fixture = Fixture::organization(false).await;
    let (_, cookie) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let approved = approve(&fixture, &cookie).await;
    source(&fixture, Duration::from_millis(200), 200).await;
    let (first, second) = tokio::join!(
        fixture.browser(
            "POST",
            "/api/work-task/execute",
            &cookie,
            reference(&approved)
        ),
        fixture.browser(
            "POST",
            "/api/work-task/execute",
            &cookie,
            reference(&approved)
        )
    );
    assert!(matches!(
        (first.status(), second.status()),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert_eq!(task(&fixture, &cookie).await["consumed"], true);
}

#[tokio::test]
async fn bounded_task_revoke_race_withholds_result_and_never_refunds() {
    let fixture = Fixture::organization(false).await;
    let (_, cookie) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let approved = approve(&fixture, &cookie).await;
    source(&fixture, Duration::from_millis(250), 200).await;
    let execute = tokio::spawn(fixture.router().oneshot(request(
        &fixture,
        &cookie,
        "/api/work-task/execute",
        reference(&approved),
    )));
    wait_for_source(&fixture).await;
    let response = fixture
        .browser(
            "POST",
            "/api/work-task/revoke",
            &cookie,
            reference(&approved),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let revoked = value(response).await;
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(revoked["consumed"], true);
    let response = value(execute.await.unwrap().unwrap()).await;
    assert_eq!(response["state"], "revoked");
    assert!(response["receipt"].is_null());
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/work-task/execute",
                &cookie,
                reference(&approved)
            )
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn bounded_task_identity_change_during_read_and_receipt_delivery_fails_closed() {
    let fixture = Fixture::organization(false).await;
    let (_, cookie) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let approved = approve(&fixture, &cookie).await;
    source(&fixture, Duration::from_millis(250), 200).await;
    let execute = tokio::spawn(fixture.router().oneshot(request(
        &fixture,
        &cookie,
        "/api/work-task/execute",
        reference(&approved),
    )));
    wait_for_source(&fixture).await;
    let (_, engineer_cookie) = org_identity(&fixture, Persona::Engineer).await;
    activate(&fixture, &engineer_cookie, Persona::Engineer, None).await;
    assert_eq!(
        fixture
            .browser("GET", "/api/work-task", &engineer_cookie, Value::Null)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    for action in ["approve", "execute", "revoke"] {
        assert_eq!(
            fixture
                .browser(
                    "POST",
                    &format!("/api/work-task/{action}"),
                    &engineer_cookie,
                    reference(&approved)
                )
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let response = execute.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(value(response).await["receipt"].is_null());
    let response = fixture
        .browser(
            "POST",
            "/api/demo/persona",
            &cookie,
            json!({"persona_id":"customer_analyst"}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let current = task(&fixture, &cookie).await;
    assert_eq!(current["task_id"], approved["task_id"]);
    assert_eq!(current["state"], "revoked");
    assert_eq!(current["consumed"], true);
    assert!(current["receipt"].is_null());
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn bounded_task_source_failure_is_unknown_and_cannot_be_retried() {
    let fixture = Fixture::organization(false).await;
    let (_, cookie) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let approved = approve(&fixture, &cookie).await;
    source(&fixture, Duration::ZERO, 503).await;
    let response = fixture
        .browser(
            "POST",
            "/api/work-task/execute",
            &cookie,
            reference(&approved),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let unknown = value(response).await;
    assert_eq!(unknown["state"], "unknown");
    assert_eq!(unknown["consumed"], true);
    assert!(unknown["receipt"].is_null());
    assert_eq!(
        fixture
            .browser(
                "POST",
                "/api/work-task/execute",
                &cookie,
                reference(&approved)
            )
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn bounded_task_receipt_is_projected_at_delivery_after_revocation() {
    let fixture = Fixture::organization(false).await;
    let (_, cookie) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let approved = approve(&fixture, &cookie).await;
    source(&fixture, Duration::ZERO, 200).await;
    let pending = fixture
        .browser(
            "POST",
            "/api/work-task/execute",
            &cookie,
            reference(&approved),
        )
        .await;
    assert_eq!(pending.status(), StatusCode::OK);
    let revoked = fixture
        .browser(
            "POST",
            "/api/work-task/revoke",
            &cookie,
            reference(&approved),
        )
        .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let delivered = value(pending).await;
    assert_eq!(delivered["state"], "revoked");
    assert!(delivered["receipt"].is_null());
}

#[tokio::test]
async fn bounded_task_unavailable_without_explicit_organization_fixture() {
    let fixture = Fixture::new(false).await;
    let response = fixture
        .browser("GET", "/api/work-task", "", Value::Null)
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    for action in ["approve", "execute", "revoke"] {
        let response = fixture
            .browser(
                "POST",
                &format!("/api/work-task/{action}"),
                "",
                json!({"task_id":Uuid::new_v4(),"manifest_sha256":"0".repeat(64)}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn bounded_task_support_case_does_not_grant_analyst_task_authority() {
    let fixture = Fixture::organization(false).await;
    let (_, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let planned = task(&fixture, &analyst).await;
    let (_, support) = org_identity(&fixture, Persona::Support).await;
    activate(
        &fixture,
        &support,
        Persona::Support,
        Some("Investigate the synthetic service issue"),
    )
    .await;
    assert_eq!(
        fixture
            .browser("GET", "/api/work-task", &support, Value::Null)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    for action in ["approve", "execute", "revoke"] {
        assert_eq!(
            fixture
                .browser(
                    "POST",
                    &format!("/api/work-task/{action}"),
                    &support,
                    reference(&planned)
                )
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert!(fixture.source.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn bounded_ledger_restart_expiry_key_binding_and_profile_binding() {
    let fixture = Fixture::organization(false).await;
    let token = fixture.persona_token(Persona::CustomerAnalyst);
    let verifier = opaque_metrics::auth::AuthVerifier::new(fixture.config.auth.clone()).unwrap();
    let access = verifier
        .verify_bearer(Some(&format!("Bearer {token}")))
        .unwrap();
    let directory = fixture.config.state_dir.join("isolated-ledger");
    std::fs::create_dir(&directory).unwrap();
    let mut store = Store::open(&directory, &fixture.config.source).unwrap();
    let planned = store
        .current(&access, 2, now(), &fixture.config.source)
        .unwrap();
    assert!(planned.manifest.expires_at <= access.expires_at());
    assert_eq!(
        planned.manifest.expires_at - planned.manifest.created_at,
        300
    );
    let reference = TaskReference {
        task_id: planned.task_id.clone(),
        manifest_sha256: planned.manifest_sha256.clone(),
    };
    store
        .transition(&access, 2, now(), &reference, TaskState::Approved)
        .unwrap();
    store
        .transition(&access, 2, now(), &reference, TaskState::Reserved)
        .unwrap();
    drop(store);
    let mut store = Store::open(&directory, &fixture.config.source).unwrap();
    let unknown = store
        .current(&access, 2, now(), &fixture.config.source)
        .unwrap();
    assert_eq!(unknown.state, TaskState::Unknown);
    assert!(unknown.consumed);
    assert_eq!(
        store
            .transition(&access, 2, now(), &reference, TaskState::Reserved)
            .unwrap_err(),
        Error::Conflict
    );
    let other_token = fixture.persona_token(Persona::CustomerAnalyst);
    let other_access = verifier
        .verify_bearer(Some(&format!("Bearer {other_token}")))
        .unwrap();
    assert_eq!(
        store
            .current(&other_access, 2, now(), &fixture.config.source)
            .unwrap_err(),
        Error::Forbidden
    );
    drop(store);
    let mut changed_source = fixture.config.source.clone();
    changed_source.base_url.push_str("/different");
    assert!(Store::open(&directory, &changed_source).is_err());
    let directory = fixture.config.state_dir.join("expired-ledger");
    std::fs::create_dir(&directory).unwrap();
    let mut store = Store::open(&directory, &fixture.config.source).unwrap();
    let planned = store
        .current(&access, 2, now(), &fixture.config.source)
        .unwrap();
    let reference = TaskReference {
        task_id: planned.task_id,
        manifest_sha256: planned.manifest_sha256,
    };
    assert_eq!(
        store
            .transition(
                &access,
                2,
                planned.manifest.expires_at,
                &reference,
                TaskState::Approved
            )
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        store
            .current(&access, 2, now(), &fixture.config.source)
            .unwrap()
            .state,
        TaskState::Expired
    );

    let directory = fixture.config.state_dir.join("completed-expiry-ledger");
    std::fs::create_dir(&directory).unwrap();
    let mut store = Store::open(&directory, &fixture.config.source).unwrap();
    let planned = store
        .current(&access, 2, now(), &fixture.config.source)
        .unwrap();
    let reference = TaskReference {
        task_id: planned.task_id,
        manifest_sha256: planned.manifest_sha256,
    };
    store
        .transition(&access, 2, now(), &reference, TaskState::Approved)
        .unwrap();
    store
        .transition(&access, 2, now(), &reference, TaskState::Reserved)
        .unwrap();
    let evidence = opaque_metrics::metrics::MetricsEvidence {
        tenant_id: fixture.config.tenant_id.clone(),
        source_id: fixture.config.source.source_id.clone(),
        window_secs: 60,
        as_of: now(),
        watermark: now(),
        observed_at: now(),
        metrics: vec![opaque_metrics::metrics::MetricRow {
            name: "manual_review_rate_percent".into(),
            value: 17.25,
            count: 100,
        }],
    };
    let completed = store
        .finish(&reference, planned.manifest.expires_at - 1, Some(evidence))
        .unwrap();
    assert_eq!(completed.state, TaskState::Completed);
    assert!(completed.receipt.is_some());
    let expired = store
        .current(
            &access,
            2,
            planned.manifest.expires_at,
            &fixture.config.source,
        )
        .unwrap();
    assert_eq!(expired.state, TaskState::Expired);
    assert!(expired.consumed);
    assert!(expired.receipt.is_none());
    drop(store);
    let mut store = Store::open(&directory, &fixture.config.source).unwrap();
    assert!(
        store
            .current(&access, 2, now(), &fixture.config.source)
            .unwrap()
            .receipt
            .is_none()
    );
}
