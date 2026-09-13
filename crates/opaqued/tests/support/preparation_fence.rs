//! Real HTTP forwarding with an explicit metadata-response barrier. This lets
//! a test change live authority after signed approval and reservation without
//! adding a timing delay or a production authorization bypass.
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    response::Response,
};
use std::sync::Arc;
use tokio::sync::Semaphore;

struct StateData {
    upstream: String,
    client: reqwest::Client,
    observed: Semaphore,
    release: Semaphore,
}

pub struct PreparationFence {
    uri: String,
    state: Arc<StateData>,
    task: tokio::task::JoinHandle<()>,
}

impl PreparationFence {
    pub async fn new(upstream: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uri = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(StateData {
            upstream: upstream.into(),
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            observed: Semaphore::new(0),
            release: Semaphore::new(0),
        });
        let app = axum::Router::new()
            .fallback(forward)
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { uri, state, task }
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub async fn wait_for_preparation(&self) {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.state.observed.acquire(),
        )
        .await
        .expect("approved task did not reach metadata preparation")
        .unwrap()
        .forget();
    }

    pub fn release(&self) {
        self.state.release.add_permits(1);
    }
}

impl Drop for PreparationFence {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward(State(state): State<Arc<StateData>>, request: Request) -> Response {
    if request.method() == reqwest::Method::GET
        && request.uri().path() == "/repos/acme/synthetic/actions/secrets/public-key"
    {
        state.observed.add_permits(1);
        state.release.acquire().await.unwrap().forget();
    }
    let (mut parts, body) = request.into_parts();
    parts.headers.remove("host");
    let body = to_bytes(body, 128 * 1024).await.unwrap();
    let response = state
        .client
        .request(parts.method, format!("{}{}", state.upstream, parts.uri))
        .headers(parts.headers)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap();
    let mut result = Response::new(Body::from(body));
    *result.status_mut() = status;
    *result.headers_mut() = headers;
    result
}
