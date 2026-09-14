//! Hold a real source response until the persona transition has committed.
//! This checks the producer's post-source fence before evidence is audited or
//! disclosed, independently of queued SSE cancellation and timing delays.
use super::*;
use axum::{extract::State, response::IntoResponse};
use std::sync::Mutex;
use tokio::sync::{Semaphore, oneshot};

struct SourceState {
    entered: Semaphore,
    release: Semaphore,
    requests: Mutex<Vec<Value>>,
}
struct SourceBarrier {
    url: String,
    state: Arc<SourceState>,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}
impl SourceBarrier {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(SourceState {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            requests: Mutex::new(vec![]),
        });
        let router = Router::new()
            .fallback(source_response)
            .with_state(state.clone());
        let (stop, stopped) = oneshot::channel();
        let worker = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            url,
            state,
            stop: Some(stop),
            worker: Some(worker),
        }
    }
    async fn finish(mut self) -> Vec<Value> {
        self.state.release.close();
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.worker.as_mut().unwrap())
            .await
            .expect("source did not stop")
            .unwrap();
        self.worker.take();
        self.state.requests.lock().unwrap().clone()
    }
}
impl Drop for SourceBarrier {
    fn drop(&mut self) {
        self.state.release.close();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}
async fn source_response(
    State(state): State<Arc<SourceState>>,
    request: Request<Body>,
) -> Response {
    assert_eq!(request.method(), "POST");
    assert_eq!(request.uri().path(), "/v1/portfolio/query");
    assert_eq!(
        request.headers().get(header::AUTHORIZATION).unwrap(),
        "Bearer opaque-showcase"
    );
    let bytes = to_bytes(request.into_body(), 32768).await.unwrap();
    let query: Value = serde_json::from_slice(&bytes).unwrap();
    {
        let mut requests = state.requests.lock().unwrap();
        assert!(requests.is_empty(), "source request must not be replayed");
        requests.push(query.clone());
    }
    state.entered.add_permits(1);
    let Ok(permit) = state.release.acquire().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    permit.forget();
    axum::Json(portfolio_response(query)).into_response()
}

#[tokio::test]
async fn persona_withdrawal_after_source_admission_withholds_result_without_retry_or_observed_audit()
 {
    for withdraw in [false, true] {
        let source = SourceBarrier::new().await;
        let fixture = Fixture::setup_with_transports(
            false,
            Experience::CreditPortfolio,
            true,
            true,
            None,
            Some(source.url.clone()),
        )
        .await;
        let (token, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
        let (_, engineer) = org_identity(&fixture, Persona::Engineer).await;
        let args = portfolio_args();
        let expected = args["arguments"].clone();
        let operation = fixture.mcp(Some(&token), args);
        tokio::pin!(operation);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                _=&mut operation=>panic!("operation completed before source response release"),
                permit=source.state.entered.acquire()=>{permit.unwrap().forget();}
            }
        })
        .await
        .unwrap();
        assert_eq!(
            source.state.requests.lock().unwrap().as_slice(),
            std::slice::from_ref(&expected)
        );
        if withdraw {
            activate(&fixture, &engineer, Persona::Engineer, None).await;
        }
        source.state.release.add_permits(1);
        let response = tokio::time::timeout(Duration::from_secs(5), &mut operation)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if withdraw {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::OK
            }
        );
        let result = body(response).await;
        if withdraw {
            assert_eq!(result["error"]["code"], "organization_access_denied");
            assert!(result.get("result").is_none());
        } else {
            assert_eq!(result["result"]["isError"], false);
            assert_eq!(result["result"]["structuredContent"]["query"], expected);
        }
        let observer = if withdraw { &engineer } else { &analyst };
        let activity = body(
            fixture
                .browser("GET", "/api/organization/activity", observer, Value::Null)
                .await,
        )
        .await;
        let records = activity["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["kind"], "tool_call");
        assert_eq!(records[0]["outcome"], "observed");
        assert_eq!(records[0]["source_accessed"], true);
        assert_eq!(records[0]["tool_calls"], 1);
        let audit = std::fs::read_to_string(fixture.config.state_dir.join("audit.jsonl")).unwrap();
        let entries = audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            entries
                .iter()
                .filter(
                    |row| row["operation"] == "portfolio.query" && row["outcome"] == "authorized"
                )
                .count(),
            1
        );
        assert_eq!(
            entries
                .iter()
                .filter(|row| row["details"]["operation"] == "portfolio.query"
                    && row["details"]["outcome"] == "observed")
                .count(),
            usize::from(!withdraw)
        );
        assert!(fixture.source.received_requests().await.unwrap().is_empty());
        assert!(fixture.model.received_requests().await.unwrap().is_empty());
        assert_eq!(source.finish().await, [expected]);
    }
}
