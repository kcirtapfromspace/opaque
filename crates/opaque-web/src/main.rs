use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;

mod config;
mod daemon_client;
mod demo;
mod routes;
pub mod security;
mod sse;

#[derive(Parser)]
#[command(name = "opaque-web", about = "Opaque live dashboard & demo explorer")]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value = "7380")]
    port: u16,

    /// Open the dashboard in the default browser on startup.
    #[arg(long)]
    open: bool,

    /// Show synthetic example data explicitly; never connect to the daemon.
    #[arg(long)]
    demo: bool,

    /// Isolated data directory (config.toml, audit.db, web.token, run/opaqued.sock).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Read policy from this config file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Connect to this daemon Unix socket.
    #[arg(long)]
    socket: Option<PathBuf>,
}

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub daemon: daemon_client::DaemonClient,
    pub config_path: PathBuf,
    pub audit_db_path: PathBuf,
    pub cancel: CancellationToken,
    pub auth_token: String,
    pub demo: bool,
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();
    let cancel = CancellationToken::new();

    let paths = config::resolve_paths(args.data_dir, args.config, args.socket);
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    // Bind before writing the token or opening a browser. A failed second launch
    // must not replace the running dashboard's token file.
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    let bound_port = listener.local_addr().expect("bound address").port();
    let auth_token = security::generate_token();
    match security::write_token_file(&paths.data_dir, &auth_token) {
        Ok(path) => tracing::info!("auth token written to {}", path.display()),
        Err(e) => {
            tracing::error!("failed to write auth token: {e}");
            std::process::exit(1);
        }
    }

    let state = AppState {
        daemon: daemon_client::DaemonClient::new(Some(paths.socket)),
        config_path: paths.config,
        audit_db_path: paths.audit_db,
        cancel: cancel.clone(),
        auth_token,
        demo: args.demo,
    };
    let app = application(state, bound_port);
    let url = format!("http://127.0.0.1:{bound_port}");
    tracing::info!("opaque-web listening on {url}");
    if args.demo {
        tracing::info!("explicit demo mode: all example activity is synthetic");
    }
    if args.open
        && let Err(e) = open_browser(&url)
    {
        tracing::warn!("failed to open browser: {e}");
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(cancel))
    .await
    .expect("server error");
}

/// Build the real router, also exercised directly by integration tests.
fn application(state: AppState, port: u16) -> axum::Router {
    let auth = security::AuthToken(Arc::new(state.auth_token.clone()));
    routes::router()
        .layer(axum::middleware::from_fn_with_state(
            auth,
            |axum::extract::State(auth): axum::extract::State<security::AuthToken>,
             request,
             next| async move { security::require_api_token(auth, request, next).await },
        ))
        .layer(axum::middleware::from_fn_with_state(
            security::LocalOrigin::new(port),
            security::validate_origin,
        ))
        .with_state(state)
}

async fn shutdown_signal(cancel: CancellationToken) {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }
    cancel.cancel();
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};
    use tower::ServiceExt;

    struct Fixture {
        dir: PathBuf,
        state: AppState,
    }
    impl Fixture {
        fn new(demo: bool) -> Self {
            let dir = PathBuf::from("/tmp").join(format!("ow-{}", uuid::Uuid::new_v4()));
            let socket = dir.join("run/opaqued.sock");
            opaque_core::socket::ensure_socket_parent_dir(&socket).unwrap();
            Self {
                state: AppState {
                    daemon: daemon_client::DaemonClient::new(Some(socket)),
                    config_path: dir.join("config.toml"),
                    audit_db_path: dir.join("audit.db"),
                    cancel: CancellationToken::new(),
                    auth_token: "router-test-token".into(),
                    demo,
                },
                dir,
            }
        }
        fn app(&self) -> axum::Router {
            application(self.state.clone(), 9389)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.state.cancel.cancel();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    fn request(uri: &str) -> axum::http::request::Builder {
        Request::builder().uri(uri).header("host", "127.0.0.1:9389")
    }
    fn authenticated(uri: &str) -> Request<Body> {
        request(uri)
            .header("authorization", "Bearer router-test-token")
            .body(Body::empty())
            .unwrap()
    }
    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn real_router_requires_bearer_for_every_read_api_including_stream() {
        let fixture = Fixture::new(false);
        for uri in [
            "/api/status",
            "/api/tasks",
            "/api/tasks/test",
            "/api/audit",
            "/api/audit/stream",
            "/api/policy",
            "/api/sessions",
            "/api/operations",
        ] {
            let response = fixture
                .app()
                .oneshot(request(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let response = fixture
            .app()
            .oneshot(
                request("/api/status?token=router-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn configured_port_origin_works_and_cross_origin_and_rebinding_fail() {
        let fixture = Fixture::new(false);
        for origin in ["http://localhost:9389", "http://127.0.0.1:9389"] {
            let req = request("/api/status")
                .header("origin", origin)
                .header("authorization", "Bearer router-test-token")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::OK
            );
        }
        for origin in ["http://localhost:7380", "https://evil.example", "null"] {
            let req = request("/")
                .header("origin", origin)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
        for host in ["evil.example:9389", "127.0.0.1:7380"] {
            let req = Request::builder()
                .uri("/")
                .header("host", host)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
    }

    #[tokio::test]
    async fn spa_bootstraps_auth_without_cache_and_is_not_frameable() {
        let fixture = Fixture::new(false);
        let response = fixture
            .app()
            .oneshot(request("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        let body = String::from_utf8(
            to_bytes(response.into_body(), 1_000_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("content=\"router-test-token\""));
    }

    #[tokio::test]
    async fn missing_live_resources_never_fall_back_to_synthetic_data() {
        let fixture = Fixture::new(false);
        let status = json_body(
            fixture
                .app()
                .oneshot(authenticated("/api/status"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status["mode"], "disconnected");
        for uri in [
            "/api/audit",
            "/api/audit/stream",
            "/api/policy",
            "/api/sessions",
            "/api/tasks",
        ] {
            let response = fixture.app().oneshot(authenticated(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            let body = json_body(response).await;
            assert_eq!(body["mode"], "unavailable");
            assert!(body.get("events").is_none());
        }
    }

    #[tokio::test]
    async fn explicit_demo_never_reads_existing_live_policy_or_audit() {
        let fixture = Fixture::new(true);
        std::fs::write(&fixture.state.config_path, "malformed = [").unwrap();
        std::fs::write(&fixture.state.audit_db_path, "not sqlite").unwrap();
        for uri in [
            "/api/status",
            "/api/audit",
            "/api/policy",
            "/api/sessions",
            "/api/tasks",
        ] {
            let response = fixture.app().oneshot(authenticated(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(json_body(response).await["mode"], "demo");
        }
    }

    #[tokio::test]
    async fn live_audit_and_resume_stream_report_real_persisted_events() {
        use futures_util::StreamExt;
        let fixture = Fixture::new(false);
        let sink = SqliteAuditSink::new(fixture.state.audit_db_path.clone(), 90).unwrap();
        sink.emit(AuditEvent::new(AuditEventKind::OperationSucceeded).with_operation("test.first"));
        sink.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded).with_operation("test.second"),
        );
        sink.flush(std::time::Duration::from_secs(2)).unwrap();
        let response = fixture
            .app()
            .oneshot(authenticated("/api/audit"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["mode"], "live");
        assert_eq!(body["events"].as_array().unwrap().len(), 2);
        let cursor = body["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["sequence_number"].as_i64().unwrap())
            .min()
            .unwrap();
        let req = request("/api/audit/stream")
            .header("authorization", "Bearer router-test-token")
            .header("last-event-id", cursor.to_string())
            .body(Body::empty())
            .unwrap();
        let response = fixture.app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut stream = response.into_body().into_data_stream();
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("event: audit"));
        assert!(text.contains("test.second"));
        assert!(!text.contains("test.first"));
        drop(sink);
    }

    async fn daemon_response(
        fixture: &Fixture,
        expected_method: &'static str,
        result: serde_json::Value,
    ) -> tokio::task::JoinHandle<()> {
        use std::os::unix::fs::PermissionsExt;
        let socket = fixture.state.daemon.socket_path();
        std::fs::write(
            socket.parent().unwrap().join("daemon.token"),
            "daemon-test-token",
        )
        .unwrap();
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            let (socket, _) = listener.accept().await.unwrap();
            let mut framed = tokio_util::codec::Framed::new(
                socket,
                tokio_util::codec::LengthDelimitedCodec::new(),
            );
            let handshake: serde_json::Value =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(handshake["daemon_token"], "daemon-test-token");
            let request: serde_json::Value =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(request["method"], expected_method);
            if matches!(expected_method, "task_get" | "task_reconcile") {
                assert_eq!(request["params"]["task_id"], "task-123");
            }
            if result.get("next_cursor").and_then(|value| value.as_str()) == Some("page-2") {
                assert_eq!(request["params"]["cursor"], "page-1");
            }
            let response = opaque_core::proto::Response::ok(1, result);
            framed
                .send(bytes::Bytes::from(serde_json::to_vec(&response).unwrap()))
                .await
                .unwrap();
        })
    }

    #[tokio::test]
    async fn operation_inventory_never_substitutes_examples_for_a_disconnected_daemon() {
        let fixture = Fixture::new(false);
        let response = fixture
            .app()
            .oneshot(authenticated("/api/operations"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(response).await;
        assert!(body.get("operations").is_none());
        assert!(body["error"].as_str().unwrap().contains("disconnected"));
    }

    #[tokio::test]
    async fn demo_operation_inventory_is_explicitly_synthetic() {
        let fixture = Fixture::new(true);
        let response = fixture
            .app()
            .oneshot(authenticated("/api/operations"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["mode"], "demo");
        let operations = body["operations"].as_array().unwrap();
        assert!(!operations.is_empty());
        assert!(
            operations
                .iter()
                .all(|operation| operation["availability"] == "synthetic"
                    && operation["policy_status"] == "synthetic")
        );
    }

    #[tokio::test]
    async fn live_operation_inventory_preserves_the_selected_daemons_capability_status() {
        let fixture = Fixture::new(false);
        let payload = serde_json::json!({"mode":"live", "operations":[
            {"name":"fixture.custom", "safety":"SensitiveOutput", "availability":"enabled",
             "mcp_exposed":false, "policy_status":"evaluated_per_request"},
            {"name":"aws.create_secret", "safety":"Safe", "availability":"disabled",
             "mcp_exposed":true, "policy_status":"evaluated_per_request"},
            {"name":"fixture.mock", "safety":"Safe", "availability":"fixture_only",
             "mcp_exposed":false, "policy_status":"evaluated_per_request"}
        ]});
        let server = daemon_response(&fixture, "operations", payload.clone()).await;
        let response = fixture
            .app()
            .oneshot(authenticated("/api/operations"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await, payload);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_daemon_inventory_fails_instead_of_returning_a_partial_catalog() {
        let fixture = Fixture::new(false);
        let server = daemon_response(
            &fixture,
            "operations",
            serde_json::json!({"operations":null}),
        )
        .await;
        let response = fixture
            .app()
            .oneshot(authenticated("/api/operations"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(json_body(response).await.get("operations").is_none());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sessions_unwrap_daemon_envelope_and_task_routes_preserve_scoped_receipts() {
        for (uri, method, result, key) in [
            (
                "/api/sessions",
                "agent_session_list",
                serde_json::json!({"count":1,"sessions":[{"session_id":"session-1"}]}),
                "sessions",
            ),
            (
                "/api/tasks",
                "task_list",
                serde_json::json!({"tasks":[{"id":"task-123"}]}),
                "tasks",
            ),
            (
                "/api/tasks/task-123",
                "task_get",
                serde_json::json!({"task":{"id":"task-123"}}),
                "task",
            ),
        ] {
            let fixture = Fixture::new(false);
            let server = daemon_response(&fixture, method, result.clone()).await;
            let response = fixture.app().oneshot(authenticated(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body[key], result[key]);
            assert_eq!(body["mode"], "live");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn status_reports_the_actual_approval_backend_from_version_rpc() {
        let fixture = Fixture::new(false);
        let server = daemon_response(
            &fixture,
            "version",
            serde_json::json!({
                "version": "test-version", "approval_backend": "insecure_auto_approve",
                "task_grants_enabled": true, "trust_domain_enforced": false,
                "workstation_test_mode": true,
            }),
        )
        .await;
        let body = json_body(
            fixture
                .app()
                .oneshot(authenticated("/api/status"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["mode"], "live");
        assert_eq!(body["daemon_version"], "test-version");
        assert_eq!(body["approval_backend"], "insecure_auto_approve");
        assert_eq!(body["task_grants_enabled"], true);
        assert_eq!(body["workstation_test_mode"], true);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn workflow_check_requires_auth_and_only_calls_read_only_reconciliation() {
        let fixture = Fixture::new(false);
        let uri = "/api/tasks/task-123/reconcile";
        let unauthenticated = request(uri).method("POST").body(Body::empty()).unwrap();
        assert_eq!(
            fixture
                .app()
                .oneshot(unauthenticated)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let cross_origin = request(uri)
            .method("POST")
            .header("authorization", "Bearer router-test-token")
            .header("origin", "https://untrusted.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            fixture.app().oneshot(cross_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let result = serde_json::json!({"task": {
            "id": "task-123", "state": "completed", "approval_mode": "paired_workstation",
            "release_observation": {"state": "failed", "code": "workflow_failed", "run_id": 42}
        }});
        let server = daemon_response(&fixture, "task_reconcile", result.clone()).await;
        let req = request(uri)
            .method("POST")
            .header("authorization", "Bearer router-test-token")
            .body(Body::empty())
            .unwrap();
        let response = fixture.app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["task"], result["task"]);
        server.await.unwrap();
        for uri in ["/api/tasks/task-123/run", "/api/tasks/task-123/approve"] {
            let req = request(uri)
                .method("POST")
                .header("authorization", "Bearer router-test-token")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn task_pagination_preserves_the_daemon_cursor() {
        let fixture = Fixture::new(false);
        let result = serde_json::json!({"tasks": [], "has_more": true, "next_cursor": "page-2"});
        let server = daemon_response(&fixture, "task_list", result).await;
        let response = fixture
            .app()
            .oneshot(authenticated("/api/tasks?cursor=page-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["has_more"], true);
        assert_eq!(body["next_cursor"], "page-2");
        server.await.unwrap();
    }

    #[test]
    fn isolated_paths_and_explicit_overrides_do_not_touch_default_home() {
        let dir = PathBuf::from("/tmp/opaque-dogfood");
        let paths = config::resolve_paths(Some(dir.clone()), None, None);
        assert_eq!(paths.config, dir.join("config.toml"));
        assert_eq!(paths.audit_db, dir.join("audit.db"));
        assert_eq!(paths.socket, dir.join("run/opaqued.sock"));
        let paths = config::resolve_paths(
            Some(dir),
            Some("/tmp/other.toml".into()),
            Some("/tmp/other.sock".into()),
        );
        assert_eq!(paths.config, PathBuf::from("/tmp/other.toml"));
        assert_eq!(paths.socket, PathBuf::from("/tmp/other.sock"));
    }
}
