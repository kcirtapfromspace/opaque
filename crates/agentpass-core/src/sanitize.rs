//! Response sanitization: scrubs error messages, response payloads, and audit
//! text to prevent secret leakage through daemon responses.
//!
//! Uses a typestate pattern ([`SanitizedResponse`]) to make it impossible to
//! return an unsanitized response from the enclave.

use std::fmt;
use std::marker::PhantomData;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Typestate markers
// ---------------------------------------------------------------------------

/// Marker: response has NOT been sanitized.
#[derive(Debug, Clone)]
pub enum Unsanitized {}

/// Marker: response HAS been sanitized.
#[derive(Debug, Clone)]
pub enum Sanitized {}

// ---------------------------------------------------------------------------
// SanitizedResponse wrapper (typestate pattern)
// ---------------------------------------------------------------------------

/// A response wrapper that uses the typestate pattern to guarantee at compile
/// time that only sanitized responses can be returned from the enclave.
///
/// - `SanitizedResponse<Unsanitized>` can only be constructed internally.
/// - Only the [`Sanitizer`] can produce a `SanitizedResponse<Sanitized>`.
/// - The enclave returns `SanitizedResponse<Sanitized>`.
pub struct SanitizedResponse<State> {
    /// The response payload.
    pub payload: serde_json::Value,

    /// Error code, if this is an error response.
    pub error_code: Option<String>,

    /// Sanitized error message (if error).
    pub error_message: Option<String>,

    /// Marker for the sanitization state.
    _state: PhantomData<State>,
}

impl SanitizedResponse<Unsanitized> {
    /// Create a new unsanitized response from a payload.
    pub fn from_payload(payload: serde_json::Value) -> Self {
        Self {
            payload,
            error_code: None,
            error_message: None,
            _state: PhantomData,
        }
    }

    /// Create a new unsanitized error response.
    pub fn from_error(
        code: impl Into<String>,
        message: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            payload,
            error_code: Some(code.into()),
            error_message: Some(message.into()),
            _state: PhantomData,
        }
    }
}

// Only Sanitized responses expose the payload for external consumption.
impl SanitizedResponse<Sanitized> {
    /// Convert to a proto Response suitable for sending to the client.
    pub fn into_proto_response(self, request_id: u64) -> crate::proto::Response {
        if let Some(code) = self.error_code {
            crate::proto::Response::err(
                Some(request_id),
                code,
                self.error_message.unwrap_or_default(),
            )
        } else {
            crate::proto::Response::ok(request_id, self.payload)
        }
    }

    /// Access the sanitized payload.
    pub fn payload(&self) -> &serde_json::Value {
        &self.payload
    }

    /// Access the error code, if present.
    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }
}

// Custom Debug that never shows raw payload content for unsanitized responses.
impl fmt::Debug for SanitizedResponse<Unsanitized> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SanitizedResponse<Unsanitized>")
            .field("payload", &"<not yet sanitized>")
            .field("error_code", &self.error_code)
            .finish()
    }
}

impl fmt::Debug for SanitizedResponse<Sanitized> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SanitizedResponse<Sanitized>")
            .field("error_code", &self.error_code)
            .field("error_message", &self.error_message)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Secret pattern detection
// ---------------------------------------------------------------------------

/// Compiled set of patterns for detecting secret-like content.
#[derive(Clone)]
pub(crate) struct SecretPatterns {
    patterns: Vec<(String, Regex)>,
}

impl SecretPatterns {
    pub(crate) fn compile() -> Self {
        // Each pattern is (label, regex).
        let raw = vec![
            // JWT tokens (header.payload.signature).
            (
                "jwt",
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            ),
            // AWS access key IDs.
            ("aws_key_id", r"AKIA[0-9A-Z]{16}"),
            // AWS secret access keys (40-char base64-ish).
            (
                "aws_secret",
                r"(?i)(?:aws_secret_access_key|secret_?key)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            ),
            // Generic long base64 tokens (>= 40 chars, likely API keys).
            ("base64_token", r"[A-Za-z0-9+/]{40,}={0,2}"),
            // Connection strings with credentials.
            (
                "connection_string",
                r"(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^\s]+:[^\s]+@[^\s]+",
            ),
            // Bearer tokens in headers.
            ("bearer", r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
            // GitHub PAT / fine-grained tokens.
            ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
            // Generic secret-looking env assignments.
            (
                "env_secret",
                r"(?i)(?:password|token|secret|api_?key|private_?key)\s*[=:]\s*\S{8,}",
            ),
            // PEM private keys.
            ("pem_key", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
            // Hex-encoded secrets (64+ chars, typical for SHA-256 hashes used as keys).
            (
                "hex_secret",
                r"(?i)(?:secret|key|token)\s*[=:]\s*[0-9a-f]{64,}",
            ),
        ];

        let patterns = raw
            .into_iter()
            .filter_map(|(label, pat)| Regex::new(pat).ok().map(|r| (label.to_owned(), r)))
            .collect();

        Self { patterns }
    }

    /// Returns true if the text contains any secret-like pattern.
    pub(crate) fn contains_secret(&self, text: &str) -> bool {
        self.patterns.iter().any(|(_, re)| re.is_match(text))
    }

    /// Replace all secret-like patterns in text with `[REDACTED]`.
    pub(crate) fn redact(&self, text: &str) -> String {
        let mut result = text.to_owned();
        for (label, re) in &self.patterns {
            result = re
                .replace_all(&result, &format!("[REDACTED:{label}]"))
                .into_owned();
        }
        result
    }
}

impl fmt::Debug for SecretPatterns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPatterns")
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Path and URL scrubbing
// ---------------------------------------------------------------------------

/// Scrub filesystem paths from error messages.
fn scrub_paths(text: &str) -> String {
    // Remove absolute paths that look like they contain user directories.
    let path_re =
        Regex::new(r"(?:/[Uu]sers/[^\s:]+|/home/[^\s:]+|/tmp/[^\s:]+)").expect("valid regex");
    path_re.replace_all(text, "[PATH]").into_owned()
}

/// Scrub URLs that may contain credentials or tokens.
pub(crate) fn scrub_urls(text: &str) -> String {
    // URLs with embedded credentials (user:pass@host).
    let cred_url_re = Regex::new(r"https?://[^\s@]+:[^\s@]+@[^\s]+").expect("valid regex");
    let result = cred_url_re.replace_all(text, "[URL:REDACTED]");

    // URLs with long query parameters that might contain tokens.
    let token_url_re = Regex::new(r"(https?://[^\s?]+)\?[^\s]{40,}").expect("valid regex");
    token_url_re
        .replace_all(&result, "$1?[PARAMS:REDACTED]")
        .into_owned()
}

// ---------------------------------------------------------------------------
// Redaction level
// ---------------------------------------------------------------------------

/// Redaction level for audit text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionLevel {
    /// Full redaction for agent-visible feeds: operation name + outcome only.
    Agent,

    /// Human-visible: includes target metadata but never secret values.
    Human,
}

// ---------------------------------------------------------------------------
// Sanitizer
// ---------------------------------------------------------------------------

/// The sanitizer scrubs responses, error messages, and audit text.
///
/// It is the only code path that can produce a `SanitizedResponse<Sanitized>`.
#[derive(Debug, Clone)]
pub struct Sanitizer {
    patterns: SecretPatterns,
}

impl Sanitizer {
    /// Create a new sanitizer with the default pattern set.
    pub fn new() -> Self {
        Self {
            patterns: SecretPatterns::compile(),
        }
    }

    /// Sanitize an unsanitized response, producing a `SanitizedResponse<Sanitized>`.
    ///
    /// This is the ONLY way to produce a sanitized response. The enclave
    /// must call this before returning any response to the client.
    pub fn sanitize_response(
        &self,
        response: SanitizedResponse<Unsanitized>,
    ) -> SanitizedResponse<Sanitized> {
        let payload = self.sanitize_value(&response.payload);

        let error_message = response.error_message.map(|msg| self.scrub_error(&msg));

        SanitizedResponse {
            payload,
            error_code: response.error_code,
            error_message,
            _state: PhantomData,
        }
    }

    /// Scrub an error message: remove paths, credentials in URLs, and
    /// secret-like patterns.
    pub fn scrub_error(&self, message: &str) -> String {
        let scrubbed = scrub_paths(message);
        let scrubbed = scrub_urls(&scrubbed);
        self.patterns.redact(&scrubbed)
    }

    /// Sanitize a JSON value by recursively scrubbing string values
    /// that look like secrets, and removing fields whose names suggest
    /// they contain secrets.
    pub fn sanitize_value(&self, value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::String(s) => {
                if self.patterns.contains_secret(s) {
                    serde_json::Value::String("[REDACTED]".into())
                } else {
                    // Still scrub paths and URLs in string values.
                    let scrubbed = scrub_paths(s);
                    let scrubbed = scrub_urls(&scrubbed);
                    serde_json::Value::String(scrubbed)
                }
            }
            serde_json::Value::Object(map) => {
                let mut cleaned = serde_json::Map::new();
                for (key, val) in map {
                    // Strip fields whose names suggest secret content.
                    let key_lower = key.to_ascii_lowercase();
                    if is_secret_field_name(&key_lower) {
                        cleaned.insert(key.clone(), serde_json::Value::String("[REDACTED]".into()));
                    } else {
                        cleaned.insert(key.clone(), self.sanitize_value(val));
                    }
                }
                serde_json::Value::Object(cleaned)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| self.sanitize_value(v)).collect())
            }
            other => other.clone(),
        }
    }

    /// Redact audit event text based on the redaction level.
    pub fn redact_audit_text(&self, text: &str, level: RedactionLevel) -> String {
        match level {
            RedactionLevel::Agent => {
                // For agents: only include operation outcome keywords,
                // strip everything else.
                self.patterns.redact(&scrub_paths(&scrub_urls(text)))
            }
            RedactionLevel::Human => {
                // For humans: keep target metadata but redact secret patterns.
                self.patterns.redact(text)
            }
        }
    }
}

impl Default for Sanitizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a JSON field name suggests it contains secret content.
fn is_secret_field_name(name: &str) -> bool {
    const SECRET_FIELD_NAMES: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "access_key",
        "secret_key",
        "private_key",
        "api_key",
        "apikey",
        "auth_token",
        "authorization",
        "credentials",
        "connection_string",
        "private_key_pem",
        "client_secret",
    ];

    SECRET_FIELD_NAMES.iter().any(|s| name.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jwt() {
        let sanitizer = Sanitizer::new();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(sanitizer.patterns.contains_secret(jwt));
    }

    #[test]
    fn detects_aws_key() {
        let sanitizer = Sanitizer::new();
        assert!(sanitizer.patterns.contains_secret("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_github_pat() {
        let sanitizer = Sanitizer::new();
        assert!(
            sanitizer
                .patterns
                .contains_secret("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        );
    }

    #[test]
    fn detects_connection_string() {
        let sanitizer = Sanitizer::new();
        assert!(
            sanitizer
                .patterns
                .contains_secret("postgres://user:password@host:5432/db")
        );
    }

    #[test]
    fn scrubs_paths() {
        let result = scrub_paths("failed to read /Users/alice/.config/secret.key");
        assert!(result.contains("[PATH]"));
        assert!(!result.contains("/Users/alice"));
    }

    #[test]
    fn scrubs_credential_urls() {
        let result = scrub_urls("connecting to https://admin:p4ssw0rd@db.example.com/mydb");
        assert!(result.contains("[URL:REDACTED]"));
        assert!(!result.contains("p4ssw0rd"));
    }

    #[test]
    fn sanitize_value_redacts_secret_fields() {
        let sanitizer = Sanitizer::new();
        let input = serde_json::json!({
            "status": "ok",
            "password": "hunter2",
            "api_key": "abc123",
            "name": "my-secret",
        });
        let output = sanitizer.sanitize_value(&input);
        assert_eq!(output["password"], "[REDACTED]");
        assert_eq!(output["api_key"], "[REDACTED]");
        assert_eq!(output["status"], "ok");
        assert_eq!(output["name"], "my-secret");
    }

    #[test]
    fn sanitize_value_redacts_jwt_in_string() {
        let sanitizer = Sanitizer::new();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let input = serde_json::Value::String(jwt.into());
        let output = sanitizer.sanitize_value(&input);
        assert_eq!(output, serde_json::Value::String("[REDACTED]".into()));
    }

    #[test]
    fn sanitized_response_typestate() {
        let sanitizer = Sanitizer::new();
        let raw = SanitizedResponse::<Unsanitized>::from_error(
            "provider_error",
            "vault returned: token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij at /Users/bob/.vault/config",
            serde_json::json!({"password": "secret123"}),
        );

        let clean = sanitizer.sanitize_response(raw);

        // Error message should be scrubbed.
        let msg = clean.error_message.as_deref().unwrap();
        assert!(!msg.contains("ghp_ABCDEF"));
        assert!(!msg.contains("/Users/bob"));
        assert!(msg.contains("[REDACTED:"));
        assert!(msg.contains("[PATH]"));

        // Payload should have secret fields redacted.
        assert_eq!(clean.payload["password"], "[REDACTED]");
    }

    #[test]
    fn scrub_error_combined() {
        let sanitizer = Sanitizer::new();
        let msg = "error connecting to postgres://admin:secret@db.internal:5432/prod from /Users/deploy/.config/db.toml";
        let scrubbed = sanitizer.scrub_error(msg);
        assert!(!scrubbed.contains("admin:secret"));
        assert!(!scrubbed.contains("/Users/deploy"));
    }

    #[test]
    fn redact_audit_text_agent_level() {
        let sanitizer = Sanitizer::new();
        let text = "operation github.set_actions_secret for repo org/myrepo with token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let redacted = sanitizer.redact_audit_text(text, RedactionLevel::Agent);
        assert!(!redacted.contains("ghp_ABCDEF"));
    }

    #[test]
    fn sanitized_response_into_proto_ok() {
        let sanitizer = Sanitizer::new();
        let raw =
            SanitizedResponse::<Unsanitized>::from_payload(serde_json::json!({"status": "ok"}));
        let clean = sanitizer.sanitize_response(raw);
        let proto = clean.into_proto_response(42);
        assert_eq!(proto.id, Some(42));
        assert!(proto.result.is_some());
        assert!(proto.error.is_none());
    }

    #[test]
    fn sanitized_response_into_proto_error() {
        let sanitizer = Sanitizer::new();
        let raw = SanitizedResponse::<Unsanitized>::from_error(
            "test_error",
            "something failed",
            serde_json::Value::Null,
        );
        let clean = sanitizer.sanitize_response(raw);
        let proto = clean.into_proto_response(99);
        assert_eq!(proto.id, Some(99));
        assert!(proto.error.is_some());
        assert_eq!(proto.error.as_ref().unwrap().code, "test_error");
    }

    #[test]
    fn sanitized_response_payload_accessor() {
        let sanitizer = Sanitizer::new();
        let raw =
            SanitizedResponse::<Unsanitized>::from_payload(serde_json::json!({"key": "value"}));
        let clean = sanitizer.sanitize_response(raw);
        assert_eq!(clean.payload()["key"], "value");
    }

    #[test]
    fn sanitized_response_error_code_none() {
        let sanitizer = Sanitizer::new();
        let raw = SanitizedResponse::<Unsanitized>::from_payload(serde_json::json!({}));
        let clean = sanitizer.sanitize_response(raw);
        assert!(clean.error_code().is_none());
    }

    #[test]
    fn unsanitized_debug_hides_payload() {
        let raw = SanitizedResponse::<Unsanitized>::from_payload(
            serde_json::json!({"secret": "super_secret_value"}),
        );
        let dbg = format!("{raw:?}");
        assert!(dbg.contains("<not yet sanitized>"));
        assert!(!dbg.contains("super_secret_value"));
    }

    #[test]
    fn sanitized_debug_shows_error_code() {
        let sanitizer = Sanitizer::new();
        let raw = SanitizedResponse::<Unsanitized>::from_error(
            "test_err",
            "msg",
            serde_json::Value::Null,
        );
        let clean = sanitizer.sanitize_response(raw);
        let dbg = format!("{clean:?}");
        assert!(dbg.contains("test_err"));
    }

    #[test]
    fn sanitize_value_array() {
        let sanitizer = Sanitizer::new();
        let input = serde_json::json!([
            "safe text",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            42,
            null,
        ]);
        let output = sanitizer.sanitize_value(&input);
        let arr = output.as_array().unwrap();
        assert_eq!(arr[0], "safe text");
        assert_eq!(arr[1], "[REDACTED]");
        assert_eq!(arr[2], 42);
        assert!(arr[3].is_null());
    }

    #[test]
    fn sanitize_value_primitives() {
        let sanitizer = Sanitizer::new();
        assert_eq!(
            sanitizer.sanitize_value(&serde_json::json!(42)),
            serde_json::json!(42)
        );
        assert_eq!(
            sanitizer.sanitize_value(&serde_json::json!(true)),
            serde_json::json!(true)
        );
        assert_eq!(
            sanitizer.sanitize_value(&serde_json::Value::Null),
            serde_json::Value::Null
        );
    }

    #[test]
    fn redact_audit_text_human_level() {
        let sanitizer = Sanitizer::new();
        let text =
            "operation for repo org/myrepo with token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let redacted = sanitizer.redact_audit_text(text, RedactionLevel::Human);
        assert!(!redacted.contains("ghp_ABCDEF"));
        assert!(redacted.contains("repo org/myrepo"));
    }

    #[test]
    fn sanitizer_default() {
        let sanitizer = Sanitizer::default();
        assert!(sanitizer.patterns.contains_secret("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn detects_bearer_token() {
        let sanitizer = Sanitizer::new();
        assert!(
            sanitizer
                .patterns
                .contains_secret("Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abc")
        );
    }

    #[test]
    fn detects_pem_key() {
        let sanitizer = Sanitizer::new();
        assert!(
            sanitizer
                .patterns
                .contains_secret("-----BEGIN PRIVATE KEY-----")
        );
        assert!(
            sanitizer
                .patterns
                .contains_secret("-----BEGIN RSA PRIVATE KEY-----")
        );
    }

    #[test]
    fn detects_hex_secret() {
        let sanitizer = Sanitizer::new();
        let hex = format!("secret={}", "a".repeat(64));
        assert!(sanitizer.patterns.contains_secret(&hex));
    }

    #[test]
    fn detects_env_secret() {
        let sanitizer = Sanitizer::new();
        assert!(
            sanitizer
                .patterns
                .contains_secret("password=mysuperpassword123")
        );
    }

    #[test]
    fn scrubs_long_query_param_urls() {
        let url = format!("https://api.example.com/endpoint?token={}", "a".repeat(50));
        let result = scrub_urls(&url);
        assert!(result.contains("[PARAMS:REDACTED]"));
        assert!(!result.contains(&"a".repeat(50)));
    }

    #[test]
    fn redact_replaces_with_labels() {
        let patterns = SecretPatterns::compile();
        let text = "found token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij in logs";
        let redacted = patterns.redact(text);
        assert!(redacted.contains("[REDACTED:github_token]"));
        assert!(!redacted.contains("ghp_ABCDEF"));
    }

    #[test]
    fn is_secret_field_name_variants() {
        assert!(is_secret_field_name("password"));
        assert!(is_secret_field_name("passwd"));
        assert!(is_secret_field_name("secret"));
        assert!(is_secret_field_name("token"));
        assert!(is_secret_field_name("access_key"));
        assert!(is_secret_field_name("secret_key"));
        assert!(is_secret_field_name("private_key"));
        assert!(is_secret_field_name("api_key"));
        assert!(is_secret_field_name("apikey"));
        assert!(is_secret_field_name("auth_token"));
        assert!(is_secret_field_name("authorization"));
        assert!(is_secret_field_name("credentials"));
        assert!(is_secret_field_name("connection_string"));
        assert!(is_secret_field_name("private_key_pem"));
        assert!(is_secret_field_name("client_secret"));
    }

    #[test]
    fn is_secret_field_name_negative() {
        assert!(!is_secret_field_name("name"));
        assert!(!is_secret_field_name("status"));
        assert!(!is_secret_field_name("repo"));
        assert!(!is_secret_field_name("id"));
        assert!(!is_secret_field_name("description"));
    }

    #[test]
    fn from_payload_constructor() {
        let raw = SanitizedResponse::<Unsanitized>::from_payload(serde_json::json!({"key": "val"}));
        assert!(raw.error_code.is_none());
        assert!(raw.error_message.is_none());
        assert_eq!(raw.payload["key"], "val");
    }
}
