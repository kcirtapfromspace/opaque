//! Security middleware for the Opaque web dashboard.
//!
//! Provides:
//! - **Origin validation**: rejects cross-origin requests to prevent local API exfiltration.
//! - **Bearer token authentication**: protects `/api/*` routes with a local auth token.
//! - **Token generation**: creates a cryptographically random token and writes it to disk.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Only the two loopback hostnames at the actual listening port may serve
/// dashboard HTML or protected API responses. Host validation also blocks DNS rebinding.
#[derive(Clone)]
pub struct LocalOrigin {
    hosts: [String; 2],
    origins: [String; 2],
}

impl LocalOrigin {
    pub fn new(port: u16) -> Self {
        Self {
            hosts: [format!("127.0.0.1:{port}"), format!("localhost:{port}")],
            origins: [
                format!("http://127.0.0.1:{port}"),
                format!("http://localhost:{port}"),
            ],
        }
    }
}

pub async fn validate_origin(
    axum::extract::State(local): axum::extract::State<LocalOrigin>,
    request: Request,
    next: Next,
) -> Response {
    let host = request.headers().get("host").and_then(|v| v.to_str().ok());
    let allowed_host = host.is_some_and(|host| local.hosts.iter().any(|allowed| allowed == host));
    let allowed_origin = match request.headers().get("origin") {
        None => true,
        Some(origin) => origin
            .to_str()
            .is_ok_and(|origin| local.origins.iter().any(|allowed| allowed == origin)),
    };
    let mut response = if allowed_host && allowed_origin {
        next.run(request).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    };
    let headers = response.headers_mut();
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("content-security-policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().unwrap());
    response
}

/// Shared state holding the auth token for Bearer authentication.
#[derive(Clone)]
pub struct AuthToken(pub Arc<String>);

/// Middleware that requires a valid `Authorization: Bearer <token>` header
/// on all requests whose path starts with `/api/`.
///
/// Non-API paths (e.g. `/`, static assets) are passed through without auth.
pub async fn require_api_token(auth_token: AuthToken, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();

    // Only enforce token auth on API routes.
    if !path.starts_with("/api/") && path != "/api" {
        return next.run(request).await;
    }

    let authorized = is_bearer_authorized(request.headers(), &auth_token.0);
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    next.run(request).await
}

/// Check whether the request carries a valid Bearer token.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
fn is_bearer_authorized(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()))
}

/// Generate a 32-byte random hex token using `getrandom`.
pub fn generate_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("getrandom failed");
    hex_encode(&buf)
}

/// Write the token to `<dir>/web.token` with 0600 permissions.
pub fn write_token_file(dir: &Path, token: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("web.token");
    // Create atomically with private permissions; never follow an existing symlink.
    use std::io::Write;
    let temp_path = dir.join(format!(".web.token.{}", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp_path)?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp_path, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result?;

    Ok(path)
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt; // for `oneshot`

    /// Build a test app with both middleware layers applied.
    fn test_app(token: &str) -> Router {
        let auth = AuthToken(Arc::new(token.to_string()));

        Router::new()
            .route("/", get(|| async { "home" }))
            .route("/api/status", get(|| async { "ok" }))
            .route("/api/sessions", get(|| async { "sessions" }))
            .layer(axum::middleware::from_fn_with_state(
                auth.clone(),
                |state: axum::extract::State<AuthToken>,
                 request: Request<Body>,
                 next: Next| async move {
                    require_api_token(state.0, request, next).await
                },
            ))
            .layer(axum::middleware::from_fn_with_state(LocalOrigin::new(7380), validate_origin))
            .with_state(auth)
    }

    // ---------------------------------------------------------------
    // Origin validation tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rejects_cross_origin_request() {
        let app = test_app("test-token");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/api/status")
            .header("origin", "https://evil.com")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn allows_localhost_origin() {
        let app = test_app("test-token");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/api/status")
            .header("origin", "http://127.0.0.1:7380")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn allows_localhost_name_origin() {
        let app = test_app("test-token");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/api/status")
            .header("origin", "http://localhost:7380")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn allows_no_origin_header() {
        let app = test_app("test-token");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/api/status")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ---------------------------------------------------------------
    // Bearer token auth tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rejects_api_request_without_token() {
        let app = test_app("secret-token-123");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/api/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_api_request_with_wrong_token() {
        let app = test_app("correct-token");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/api/status")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn allows_api_request_with_valid_token() {
        let app = test_app("my-secret");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/api/status")
            .header("authorization", "Bearer my-secret")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn allows_non_api_route_without_token() {
        let app = test_app("some-token");
        let req = Request::builder()
            .header("host", "127.0.0.1:7380")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ---------------------------------------------------------------
    // Token generation tests
    // ---------------------------------------------------------------

    #[test]
    fn generated_token_is_64_hex_chars() {
        let token = generate_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generated_tokens_are_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_file_is_written_and_readable() {
        let dir = std::env::temp_dir().join(format!("opaque-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let token = "deadbeef42";
        let path = write_token_file(&dir, token).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "token file should have 0600 permissions"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
