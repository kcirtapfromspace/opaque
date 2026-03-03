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

/// Allowed origin values for local dashboard requests.
const ALLOWED_ORIGINS: &[&str] = &["http://127.0.0.1:7380", "http://localhost:7380"];

/// Middleware that validates the `Origin` header on incoming requests.
///
/// Requests are allowed if:
/// - No `Origin` header is present (same-origin browser requests, curl, etc.)
/// - The `Origin` header matches one of the allowed local origins.
///
/// All other origins are rejected with 403 Forbidden.
pub async fn validate_origin(request: Request, next: Next) -> Response {
    if let Some(origin) = request.headers().get("origin") {
        let origin_str = match origin.to_str() {
            Ok(s) => s,
            Err(_) => return StatusCode::FORBIDDEN.into_response(),
        };
        if !ALLOWED_ORIGINS.contains(&origin_str) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(request).await
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
    std::fs::write(&path, token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(path)
}

/// Inject a `<meta name="opaque-auth-token" content="...">` tag into the HTML `<head>`.
///
/// The dashboard JavaScript reads this to authenticate API requests.
/// The token value is HTML-escaped to prevent attribute injection.
pub fn inject_token_meta(html: &str, token: &str) -> String {
    let escaped = html_escape_attr(token);
    let meta_tag = format!(r#"<meta name="opaque-auth-token" content="{escaped}">"#);
    // Insert right after the opening <head> tag.
    if let Some(pos) = html.find("<head>") {
        let insert_at = pos + "<head>".len();
        let mut result = String::with_capacity(html.len() + meta_tag.len() + 1);
        result.push_str(&html[..insert_at]);
        result.push('\n');
        result.push_str(&meta_tag);
        result.push_str(&html[insert_at..]);
        result
    } else {
        // Fallback: prepend (should not happen with well-formed HTML).
        format!("{meta_tag}\n{html}")
    }
}

/// Escape a string for safe inclusion in an HTML double-quoted attribute value.
fn html_escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
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
            .layer(axum::middleware::from_fn(validate_origin))
            .with_state(auth)
    }

    // ---------------------------------------------------------------
    // Origin validation tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn rejects_cross_origin_request() {
        let app = test_app("test-token");
        let req = Request::builder()
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
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

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

    // ---------------------------------------------------------------
    // HTML meta tag injection test
    // ---------------------------------------------------------------

    #[test]
    fn html_meta_tag_escapes_special_chars() {
        let html = "<html><head></head><body></body></html>";
        let malicious = r#""><script>alert(1)</script><meta x=""#;
        let injected = inject_token_meta(html, malicious);
        assert!(
            !injected.contains("<script>"),
            "special characters must be escaped to prevent XSS"
        );
        assert!(injected.contains("&lt;script&gt;"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn html_meta_tag_injection() {
        let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Opaque Dashboard</title>
</head>
<body></body>
</html>"#;

        let token = "abc123";
        let injected = inject_token_meta(html, token);
        assert!(
            injected.contains(r#"<meta name="opaque-auth-token" content="abc123">"#),
            "injected HTML should contain auth token meta tag"
        );
        // Meta tag should appear inside <head>
        let head_start = injected.find("<head>").unwrap();
        let head_end = injected.find("</head>").unwrap();
        let meta_pos = injected.find(r#"<meta name="opaque-auth-token""#).unwrap();
        assert!(meta_pos > head_start && meta_pos < head_end);
    }
}
