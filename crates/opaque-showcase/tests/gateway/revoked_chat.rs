//! Hold the actual model HTTP response until revocation commits. Keep the SSE
//! receiver alive until the producer records failure, so delivery cancellation
//! cannot mask the producer's final authorization check.
use super::*;
use axum::{extract::State, response::IntoResponse};
use std::sync::Mutex;
use tokio::sync::{Semaphore, oneshot};

struct ModelState {
    entered: Semaphore,
    release: Semaphore,
    requests: Mutex<Vec<(String, String, Value)>>,
}

struct PlanningBarrier {
    url: String,
    state: Arc<ModelState>,
    shutdown: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl PlanningBarrier {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(ModelState {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            requests: Mutex::new(Vec::new()),
        });
        let serving = Router::new()
            .fallback(model_response)
            .with_state(state.clone());
        let (shutdown, stopped) = oneshot::channel();
        let worker = tokio::spawn(async move {
            axum::serve(listener, serving)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            url,
            state,
            shutdown: Some(shutdown),
            worker: Some(worker),
        }
    }

    async fn finish(mut self) -> Vec<(String, String, Value)> {
        self.state.release.close();
        self.shutdown.take().unwrap().send(()).unwrap();
        // Keep the handle owned by Drop until joining succeeds. A failing
        // assertion/deadline closes the gate and aborts this owned server.
        tokio::time::timeout(Duration::from_secs(5), self.worker.as_mut().unwrap())
            .await
            .expect("owned model server did not stop")
            .unwrap();
        self.worker.take();
        self.state.requests.lock().unwrap().clone()
    }
}

impl Drop for PlanningBarrier {
    fn drop(&mut self) {
        self.state.release.close();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

async fn model_response(State(state): State<Arc<ModelState>>, request: Request<Body>) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let bytes = to_bytes(request.into_body(), 32768).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap();
    let ordinal = {
        let mut requests = state.requests.lock().unwrap();
        assert!(requests.len() < 8, "unexpected unbounded model requests");
        requests.push((method, path, value));
        requests.len()
    };
    if ordinal == 1 {
        state.entered.add_permits(1);
        let Ok(permit) = state.release.acquire().await else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        permit.forget();
        axum::Json(json!({"choices":[{"finish_reason":"tool_calls","message":{
            "role":"assistant","content":null,"tool_calls":[{
                "id":"held-plan","type":"function","function":{
                    "name":"opaque_metrics_query",
                    "arguments":"{\"metrics\":[\"manual_review_rate_percent\"],\"window_secs\":60,\"watch_secs\":0}"
                }
            }]
        }}]})).into_response()
    } else if ordinal == 2 {
        axum::Json(json!({"choices":[{"finish_reason":"stop","message":{
            "role":"assistant","content":"The observed manual review rate is 17.25 percent."
        }}]}))
        .into_response()
    } else {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

#[tokio::test]
async fn revoked_chat_records_producer_failure_before_sse_delivery_without_source_or_replay() {
    for revoked in [false, true] {
        let model = PlanningBarrier::new().await;
        let fixture = Fixture::setup_with_model(
            true,
            Experience::CreditPortfolio,
            true,
            false,
            Some(model.url.clone()),
        )
        .await;
        fixture.successful_source().await;
        let (token, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
        let (_, engineer) = org_identity(&fixture, Persona::Engineer).await;
        let question = "What is my manual review rate?";
        let response = fixture
            .browser("POST", "/api/chat", &analyst, json!({"message":question}))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::timeout(Duration::from_secs(5), model.state.entered.acquire())
            .await
            .expect("model planning was not reached")
            .unwrap()
            .forget();
        assert_eq!(model.state.requests.lock().unwrap().len(), 1);
        assert!(fixture.source.received_requests().await.unwrap().is_empty());

        if revoked {
            let logout = fixture
                .browser("POST", "/auth/logout", &analyst, Value::Null)
                .await;
            assert_eq!(logout.status(), StatusCode::OK);
            assert_eq!(
                body(logout).await,
                json!({"signed_out":true,"revoked":true})
            );
            assert_eq!(
                fixture
                    .mcp(Some(&token), args(&["manual_review_rate_percent"]))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            // Select the admitted metadata observer after revocation. This also
            // changes the demo persona epoch; the already-revoked bearer
            // independently makes the producer's auth_failed check true. This
            // observer can witness activity but cannot read customer metrics.
            activate(&fixture, &engineer, Persona::Engineer, None).await;
            let before = body(
                fixture
                    .browser("GET", "/api/organization/activity", &engineer, Value::Null)
                    .await,
            )
            .await;
            let records = before["records"].as_array().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["outcome"], "started");
            assert_eq!(records[0]["source_accessed"], false);
        }
        model.state.release.add_permits(1);

        if revoked {
            // Do not poll/drop the chat body until run_chat has recorded its
            // error. The bounded queue holds status, error and done; no receiver
            // cancellation can win run_chat's select while this witness waits.
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let activity = fixture
                        .browser("GET", "/api/organization/activity", &engineer, Value::Null)
                        .await;
                    assert_eq!(activity.status(), StatusCode::OK);
                    let activity = body(activity).await;
                    let records = activity["records"].as_array().unwrap();
                    assert_eq!(records.len(), 1);
                    let record = &records[0];
                    assert_eq!(record["tool_calls"], 0);
                    assert_eq!(record["source_accessed"], false);
                    assert_ne!(record["outcome"], "completed");
                    if record["outcome"] == "failed" {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("producer did not record failure while receiver remained open");
        }
        let events = String::from_utf8(
            tokio::time::timeout(
                Duration::from_secs(5),
                to_bytes(response.into_body(), 65536),
            )
            .await
            .unwrap()
            .unwrap()
            .to_vec(),
        )
        .unwrap();
        if revoked {
            assert!(events.contains("auth_expired"), "{events}");
            assert!(
                !events.contains("event: result") && !events.contains("event: answer"),
                "{events}"
            );
            assert_eq!(
                fixture
                    .mcp(Some(&token), args(&["manual_review_rate_percent"]))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        } else {
            // The same held response must parse and execute successfully under
            // unchanged authority, ruling out malformed planning as the oracle.
            assert!(
                events.contains("event: result") && events.contains("event: answer"),
                "{events}"
            );
            assert!(events.contains("event: done"), "{events}");
            assert!(!events.contains("event: error"), "{events}");
        }
        let reads = fixture.source.received_requests().await.unwrap();
        assert_eq!(reads.len(), if revoked { 0 } else { 1 });
        if !revoked {
            assert_eq!(reads[0].url.path(), "/v1/metrics/query");
            assert_eq!(
                reads[0].body_json::<Value>().unwrap(),
                json!({"metrics":["manual_review_rate_percent"],"window_secs":60})
            );
        }
        let requests = model.finish().await;
        assert_eq!(requests.len(), if revoked { 1 } else { 2 });
        for (method, path, request) in &requests {
            assert_eq!(method, "POST");
            assert_eq!(path, "/v1/chat/completions");
            assert_eq!(request["model"], "fixture-model");
        }
        assert_eq!(requests[0].2["messages"][1]["content"], question);
        assert!(fixture.model.received_requests().await.unwrap().is_empty());
    }
}
