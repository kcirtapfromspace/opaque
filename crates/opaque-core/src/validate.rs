//! Input validation and sanitization of client-controlled strings.
//!
//! Client-supplied fields (target, secret_ref_names, workspace) flow into
//! audit events and approval UI. Without validation, a malicious client
//! could embed secret values, Unicode control characters, or newlines to
//! inject content into approval prompts or audit logs.

use std::collections::HashMap;
use std::fmt;

use crate::sanitize::SecretPatterns;

// ---------------------------------------------------------------------------
// Validation error
// ---------------------------------------------------------------------------

/// Errors returned by input validation.
#[derive(Debug, Clone)]
pub enum ValidationError {
    TooLong {
        field: String,
        max: usize,
        actual: usize,
    },
    TooManyEntries {
        kind: String,
        max: usize,
        actual: usize,
    },
    InvalidCharset {
        field: String,
        value: String,
    },
    SecretDetected {
        field: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { field, max, actual } => {
                write!(f, "{field} too long: {actual} chars (max {max})")
            }
            Self::TooManyEntries { kind, max, actual } => {
                write!(f, "too many {kind}: {actual} (max {max})")
            }
            Self::InvalidCharset { field, .. } => {
                write!(f, "{field} contains invalid characters")
            }
            Self::SecretDetected { field } => {
                write!(f, "{field} appears to contain a secret value")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ---------------------------------------------------------------------------
// InputValidator
// ---------------------------------------------------------------------------

/// Validates and sanitizes client-controlled strings before they enter
/// the audit log or approval UI.
pub struct InputValidator;

impl InputValidator {
    /// Validate a string field: max length, no control chars (0x00-0x1F),
    /// no RTL overrides (U+202A-U+202E, U+2066-U+2069), strip
    /// leading/trailing whitespace.
    pub fn validate_field(
        field_name: &str,
        value: &str,
        max_len: usize,
    ) -> Result<String, ValidationError> {
        let trimmed = value.trim();

        if trimmed.len() > max_len {
            return Err(ValidationError::TooLong {
                field: field_name.into(),
                max: max_len,
                actual: trimmed.len(),
            });
        }

        // Reject all control characters (0x00-0x1F).
        // Reject RTL overrides and bidi isolates.
        for ch in trimmed.chars() {
            let cp = ch as u32;
            if cp <= 0x1F {
                return Err(ValidationError::InvalidCharset {
                    field: field_name.into(),
                    value: trimmed.into(),
                });
            }
            // RTL override characters (U+202A-U+202E).
            if (0x202A..=0x202E).contains(&cp) {
                return Err(ValidationError::InvalidCharset {
                    field: field_name.into(),
                    value: trimmed.into(),
                });
            }
            // Bidi isolate characters (U+2066-U+2069).
            if (0x2066..=0x2069).contains(&cp) {
                return Err(ValidationError::InvalidCharset {
                    field: field_name.into(),
                    value: trimmed.into(),
                });
            }
        }

        Ok(trimmed.to_owned())
    }

    /// Validate a target HashMap: max 16 entries, keys `[a-z0-9_]` max 64
    /// chars, values via `validate_field(256)`. Reject if any value matches
    /// secret patterns.
    pub fn validate_target(
        target: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, ValidationError> {
        if target.len() > 16 {
            return Err(ValidationError::TooManyEntries {
                kind: "target entries".into(),
                max: 16,
                actual: target.len(),
            });
        }

        let patterns = SecretPatterns::compile();
        let mut validated = HashMap::new();

        for (key, value) in target {
            // Keys must be [a-z0-9_], max 64 chars.
            if key.len() > 64 {
                return Err(ValidationError::TooLong {
                    field: format!("target key '{key}'"),
                    max: 64,
                    actual: key.len(),
                });
            }
            if !key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                return Err(ValidationError::InvalidCharset {
                    field: "target key".into(),
                    value: key.clone(),
                });
            }

            // Values: validate field + secret detection.
            let clean_value = Self::validate_field(&format!("target[{key}]"), value, 256)?;
            if patterns.contains_secret(&clean_value) {
                return Err(ValidationError::SecretDetected {
                    field: format!("target[{key}]"),
                });
            }

            validated.insert(key.clone(), clean_value);
        }

        Ok(validated)
    }

    /// Validate secret ref names: max 32 entries, each `[A-Za-z0-9_./-]` max
    /// 128 chars. Reject if any name matches secret patterns (a value, not a
    /// name).
    pub fn validate_secret_ref_names(names: &[String]) -> Result<Vec<String>, ValidationError> {
        if names.len() > 32 {
            return Err(ValidationError::TooManyEntries {
                kind: "secret ref names".into(),
                max: 32,
                actual: names.len(),
            });
        }

        let patterns = SecretPatterns::compile();
        let mut validated = Vec::with_capacity(names.len());

        for name in names {
            if name.len() > 128 {
                return Err(ValidationError::TooLong {
                    field: "secret_ref_name".into(),
                    max: 128,
                    actual: name.len(),
                });
            }

            // Allowed charset: A-Z, a-z, 0-9, _, ., /, -
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '/' || c == '-')
            {
                return Err(ValidationError::InvalidCharset {
                    field: "secret_ref_name".into(),
                    value: name.clone(),
                });
            }

            // Reject if the "name" looks like a secret value.
            if patterns.contains_secret(name) {
                return Err(ValidationError::SecretDetected {
                    field: "secret_ref_name".into(),
                });
            }

            validated.push(name.clone());
        }

        Ok(validated)
    }

    /// Strip userinfo from a URL.
    ///
    /// - `https://user:pass@host/path` -> `https://host/path`
    /// - `https://token@host/path` -> `https://host/path`
    /// - SSH URLs (`git@...`) are passed through unchanged.
    /// - Malformed URLs are passed through unchanged.
    pub fn sanitize_url(url: &str) -> String {
        // SSH URLs: git@host:path — pass through.
        if url.starts_with("git@") || url.starts_with("ssh://") {
            return url.to_owned();
        }

        // HTTP(S) URLs: strip userinfo.
        if let Some(rest) = url.strip_prefix("https://") {
            if let Some(at_pos) = rest.find('@') {
                // Only strip if the @ comes before the first / (i.e., it's in the authority).
                let slash_pos = rest.find('/').unwrap_or(rest.len());
                if at_pos < slash_pos {
                    return format!("https://{}", &rest[at_pos + 1..]);
                }
            }
            return url.to_owned();
        }

        if let Some(rest) = url.strip_prefix("http://") {
            if let Some(at_pos) = rest.find('@') {
                let slash_pos = rest.find('/').unwrap_or(rest.len());
                if at_pos < slash_pos {
                    return format!("http://{}", &rest[at_pos + 1..]);
                }
            }
            return url.to_owned();
        }

        // Unknown scheme — pass through.
        url.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_field_accepts_normal() {
        let result = InputValidator::validate_field("test", "hello world", 256);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello world");
    }

    #[test]
    fn validate_field_rejects_control_chars() {
        let result = InputValidator::validate_field("test", "hello\x00world", 256);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InvalidCharset { field, .. } => assert_eq!(field, "test"),
            other => panic!("expected InvalidCharset, got {other}"),
        }

        // Tab (0x09) should also be rejected.
        let result = InputValidator::validate_field("test", "hello\tworld", 256);
        assert!(result.is_err());
    }

    #[test]
    fn validate_field_rejects_rtl_override() {
        // U+202E = RIGHT-TO-LEFT OVERRIDE
        let result = InputValidator::validate_field("test", "hello\u{202E}world", 256);
        assert!(result.is_err());

        // U+2066 = LEFT-TO-RIGHT ISOLATE
        let result = InputValidator::validate_field("test", "hello\u{2066}world", 256);
        assert!(result.is_err());
    }

    #[test]
    fn validate_field_rejects_overlength() {
        let long_str = "a".repeat(300);
        let result = InputValidator::validate_field("test", &long_str, 256);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::TooLong { max, actual, .. } => {
                assert_eq!(max, 256);
                assert_eq!(actual, 300);
            }
            other => panic!("expected TooLong, got {other}"),
        }
    }

    #[test]
    fn validate_field_strips_whitespace() {
        let result = InputValidator::validate_field("test", "  hello  ", 256);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn validate_target_rejects_too_many() {
        let mut target = HashMap::new();
        for i in 0..20 {
            target.insert(format!("key{i}"), "value".into());
        }
        let result = InputValidator::validate_target(&target);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::TooManyEntries { max, actual, .. } => {
                assert_eq!(max, 16);
                assert_eq!(actual, 20);
            }
            other => panic!("expected TooManyEntries, got {other}"),
        }
    }

    #[test]
    fn validate_target_rejects_bad_key() {
        let mut target = HashMap::new();
        target.insert("UPPER_CASE".into(), "value".into());
        let result = InputValidator::validate_target(&target);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InvalidCharset { field, .. } => assert_eq!(field, "target key"),
            other => panic!("expected InvalidCharset, got {other}"),
        }
    }

    #[test]
    fn validate_target_accepts_normal() {
        let mut target = HashMap::new();
        target.insert("repo".into(), "org/myrepo".into());
        target.insert("environment".into(), "production".into());
        let result = InputValidator::validate_target(&target);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_secret_ref_rejects_jwt_value() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = InputValidator::validate_secret_ref_names(&[jwt.into()]);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::SecretDetected { field } => {
                assert_eq!(field, "secret_ref_name");
            }
            other => panic!("expected SecretDetected, got {other}"),
        }
    }

    #[test]
    fn validate_secret_ref_rejects_aws_key() {
        let result = InputValidator::validate_secret_ref_names(&["AKIAIOSFODNN7EXAMPLE".into()]);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::SecretDetected { field } => {
                assert_eq!(field, "secret_ref_name");
            }
            other => panic!("expected SecretDetected, got {other}"),
        }
    }

    #[test]
    fn validate_secret_ref_accepts_normal() {
        let result = InputValidator::validate_secret_ref_names(&[
            "JWT".into(),
            "AWS_ACCESS_KEY".into(),
            "my-org/db/password".into(),
        ]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn sanitize_url_strips_https_userinfo() {
        let result = InputValidator::sanitize_url("https://user:pass@host.example.com/path");
        assert_eq!(result, "https://host.example.com/path");
        assert!(!result.contains("user"));
        assert!(!result.contains("pass"));
    }

    #[test]
    fn sanitize_url_strips_token_userinfo() {
        let result = InputValidator::sanitize_url("https://ghp_abc123@github.com/org/repo.git");
        assert_eq!(result, "https://github.com/org/repo.git");
        assert!(!result.contains("ghp_abc123"));
    }

    #[test]
    fn sanitize_url_preserves_ssh() {
        let ssh_url = "git@github.com:org/repo.git";
        let result = InputValidator::sanitize_url(ssh_url);
        assert_eq!(result, ssh_url);
    }

    #[test]
    fn sanitize_url_preserves_clean_https() {
        let url = "https://github.com/org/repo.git";
        let result = InputValidator::sanitize_url(url);
        assert_eq!(result, url);
    }

    #[test]
    fn sanitize_url_strips_http_userinfo() {
        let result = InputValidator::sanitize_url("http://admin:secret@db.internal:5432/mydb");
        assert_eq!(result, "http://db.internal:5432/mydb");
    }

    #[test]
    fn validate_field_rejects_newline() {
        // Newlines are rejected to prevent approval prompt injection.
        let result = InputValidator::validate_field("test", "line1\nline2", 256);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InvalidCharset { field, .. } => assert_eq!(field, "test"),
            other => panic!("expected InvalidCharset, got {other}"),
        }
    }

    #[test]
    fn validate_secret_ref_rejects_too_many() {
        let names: Vec<String> = (0..40).map(|i| format!("SECRET_{i}")).collect();
        let result = InputValidator::validate_secret_ref_names(&names);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::TooManyEntries { max, .. } => assert_eq!(max, 32),
            other => panic!("expected TooManyEntries, got {other}"),
        }
    }

    #[test]
    fn validate_secret_ref_rejects_invalid_charset() {
        let result = InputValidator::validate_secret_ref_names(&["secret with spaces".into()]);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InvalidCharset { field, .. } => {
                assert_eq!(field, "secret_ref_name");
            }
            other => panic!("expected InvalidCharset, got {other}"),
        }
    }

    #[test]
    fn validation_error_display() {
        let err = ValidationError::TooLong {
            field: "test".into(),
            max: 10,
            actual: 20,
        };
        assert!(format!("{err}").contains("too long"));

        let err = ValidationError::TooManyEntries {
            kind: "entries".into(),
            max: 5,
            actual: 10,
        };
        assert!(format!("{err}").contains("too many"));

        let err = ValidationError::InvalidCharset {
            field: "test".into(),
            value: "bad".into(),
        };
        assert!(format!("{err}").contains("invalid characters"));

        let err = ValidationError::SecretDetected {
            field: "test".into(),
        };
        assert!(format!("{err}").contains("secret value"));
    }

    #[test]
    fn validate_target_rejects_secret_in_value() {
        let mut target = HashMap::new();
        target.insert(
            "repo".into(),
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".into(),
        );
        let result = InputValidator::validate_target(&target);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::SecretDetected { field } => {
                assert!(field.contains("target"));
            }
            other => panic!("expected SecretDetected, got {other}"),
        }
    }
}
