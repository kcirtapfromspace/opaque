//! `.env.opaque` template injection.
//!
//! `opaque inject -- <command>` reads a `.env.opaque` template file containing
//! secret refs, resolves them through the daemon, and injects the resolved
//! values as environment variables into the child process. Secret values NEVER
//! touch the filesystem.
//!
//! Template format:
//! ```text
//! # Comments start with '#'
//! DATABASE_URL=vault:secret/data/db#connection_string
//! API_KEY=aws-sm:prod/api-key
//! STATIC_VALUE=literal:my-non-secret-value
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::ui;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A parsed entry from the `.env.opaque` template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    pub key: String,
    pub ref_or_literal: RefOrLiteral,
}

/// Either a literal value (passed through without daemon resolution) or a
/// secret reference that must be resolved via the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefOrLiteral {
    /// `literal:value` — passed through as-is (value after the `literal:` prefix).
    Literal(String),
    /// A secret ref string (e.g. `vault:secret/data/db#conn`, `aws-sm:prod/key`).
    Ref(String),
}

/// A resolved secret value. Kept as an opaque string; the inner value is
/// only exposed when building the child process environment.
#[derive(Debug, Clone)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Errors from inject operations.
#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("template file not found: {0}")]
    TemplateNotFound(PathBuf),

    #[error("failed to read template file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("parse error at line {line}: {message}")]
    ParseError { line: usize, message: String },

    #[error("failed to resolve secret ref '{reference}': {message}")]
    ResolveError { reference: String, message: String },

    #[error("failed to spawn child process: {0}")]
    SpawnError(String),

    #[error("child process error: {0}")]
    ChildError(String),

    #[error("daemon connection failed: {0}")]
    DaemonError(String),
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a `.env.opaque` template file into a list of [`EnvEntry`] entries.
///
/// - Lines starting with `#` (optionally preceded by whitespace) are comments.
/// - Empty or whitespace-only lines are skipped.
/// - Each non-comment line must contain `KEY=value` where value is a secret ref
///   or `literal:` prefixed value.
/// - Quoted values (`KEY="value"` or `KEY='value'`) have their quotes stripped.
pub fn parse_env_template(path: &Path) -> Result<Vec<EnvEntry>, InjectError> {
    if !path.exists() {
        return Err(InjectError::TemplateNotFound(path.to_path_buf()));
    }

    let content = std::fs::read_to_string(path)?;
    parse_env_template_str(&content)
}

/// Parse template content from a string (useful for testing).
pub fn parse_env_template_str(content: &str) -> Result<Vec<EnvEntry>, InjectError> {
    let mut entries = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let line_num = idx + 1;

        // Find the first '=' separator.
        let eq_pos = trimmed.find('=').ok_or_else(|| InjectError::ParseError {
            line: line_num,
            message: format!("missing '=' separator in: {trimmed}"),
        })?;

        let key = trimmed[..eq_pos].trim().to_string();
        if key.is_empty() {
            return Err(InjectError::ParseError {
                line: line_num,
                message: "empty key before '='".to_string(),
            });
        }

        // Validate key: must be a valid env var name (alphanumeric + underscore, not starting with digit).
        if !is_valid_env_key(&key) {
            return Err(InjectError::ParseError {
                line: line_num,
                message: format!("invalid environment variable name: {key}"),
            });
        }

        let raw_value = trimmed[eq_pos + 1..].trim().to_string();

        // Strip surrounding quotes if present.
        let value = strip_quotes(&raw_value);

        if value.is_empty() {
            return Err(InjectError::ParseError {
                line: line_num,
                message: format!("empty value for key '{key}'"),
            });
        }

        let ref_or_literal = if let Some(literal_val) = value.strip_prefix("literal:") {
            RefOrLiteral::Literal(literal_val.to_string())
        } else {
            // Validate that the ref contains a ':' scheme separator.
            if !value.contains(':') {
                return Err(InjectError::ParseError {
                    line: line_num,
                    message: format!(
                        "invalid ref format for key '{key}': expected 'scheme:path' but got '{value}'"
                    ),
                });
            }
            RefOrLiteral::Ref(value.to_string())
        };

        entries.push(EnvEntry {
            key,
            ref_or_literal,
        });
    }

    Ok(entries)
}

/// Check that a string is a valid environment variable name.
fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let first = key.as_bytes()[0];
    if first.is_ascii_digit() {
        return false;
    }
    key.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Strip matching surrounding quotes (single or double) from a value.
fn strip_quotes(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Trait for resolving secret refs through the daemon (or a mock).
pub trait RefResolver {
    fn resolve(&self, reference: &str) -> Result<String, InjectError>;
}

/// Resolve all entries: literals pass through, refs go through the resolver.
pub fn resolve_entries(
    entries: &[EnvEntry],
    resolver: &dyn RefResolver,
) -> Result<Vec<(String, SecretValue)>, InjectError> {
    let mut resolved = Vec::with_capacity(entries.len());

    for entry in entries {
        let value = match &entry.ref_or_literal {
            RefOrLiteral::Literal(val) => SecretValue::new(val.clone()),
            RefOrLiteral::Ref(reference) => {
                let val = resolver.resolve(reference)?;
                SecretValue::new(val)
            }
        };
        resolved.push((entry.key.clone(), value));
    }

    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Child process execution
// ---------------------------------------------------------------------------

/// Execute a child process with the given environment variables injected.
///
/// The resolved secrets are passed via `Command::env()` — they exist ONLY in
/// the child process environment, never written to disk.
pub async fn execute_with_env(
    command: &[String],
    env: Vec<(String, SecretValue)>,
) -> Result<ExitStatus, InjectError> {
    if command.is_empty() {
        return Err(InjectError::SpawnError(
            "command must not be empty".to_string(),
        ));
    }

    let mut cmd = tokio::process::Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    // Inject resolved env vars into the child process.
    for (key, value) in &env {
        cmd.env(key, value.as_str());
    }

    // Inherit stdio so the user sees the child's output.
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let status = cmd
        .spawn()
        .map_err(|e| InjectError::SpawnError(format!("{}: {e}", command[0])))?
        .wait()
        .await
        .map_err(|e| InjectError::ChildError(e.to_string()))?;

    Ok(status)
}

// ---------------------------------------------------------------------------
// Daemon-backed resolver
// ---------------------------------------------------------------------------

/// Resolves secret refs by calling the opaque daemon's `execute` method.
///
/// Each ref is sent as a `resolve_secret` operation to the daemon, which
/// performs policy evaluation and approval before returning the value.
pub struct DaemonResolver<'a> {
    sock: &'a Path,
}

impl<'a> DaemonResolver<'a> {
    pub fn new(sock: &'a Path) -> Self {
        Self { sock }
    }
}

impl RefResolver for DaemonResolver<'_> {
    fn resolve(&self, reference: &str) -> Result<String, InjectError> {
        // Use a blocking runtime handle to call the async daemon.
        let sock = self.sock.to_path_buf();
        let reference = reference.to_string();

        // We use tokio::task::block_in_place + Handle::current to run async
        // code from within an already-running tokio runtime.
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let resp = crate::daemon_call(&sock, "resolve_ref", serde_json::json!({ "ref": reference }))
                .await
                .map_err(|e| InjectError::DaemonError(e.to_string()))?;

            if let Some(err) = resp.error {
                return Err(InjectError::ResolveError {
                    reference: reference.clone(),
                    message: format!("{}: {}", err.code, err.message),
                });
            }

            let result = resp
                .result
                .ok_or_else(|| InjectError::ResolveError {
                    reference: reference.clone(),
                    message: "daemon returned no result".to_string(),
                })?;

            result
                .get("value")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| InjectError::ResolveError {
                    reference,
                    message: "daemon response missing 'value' field".to_string(),
                })
        })
    }
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/// Run the inject subcommand.
pub async fn run(
    sock: &Path,
    env_file: &Path,
    command: &[String],
    json_output: bool,
) -> Result<i32, String> {
    if command.is_empty() {
        return Err("inject command must not be empty".into());
    }

    // Parse the template file.
    let entries = parse_env_template(env_file).map_err(|e| e.to_string())?;

    if entries.is_empty() {
        if !json_output {
            ui::warn("no entries found in template file; running command with no injected env vars");
        }
    } else if !json_output {
        ui::info(&format!(
            "Resolving {} secret(s) from {}...",
            entries.iter().filter(|e| matches!(e.ref_or_literal, RefOrLiteral::Ref(_))).count(),
            env_file.display()
        ));
    }

    // Resolve all entries.
    let resolver = DaemonResolver::new(sock);
    let resolved = resolve_entries(&entries, &resolver).map_err(|e| e.to_string())?;

    if !json_output {
        ui::success(&format!(
            "Resolved {} env var(s), launching: {}",
            resolved.len(),
            command.join(" ")
        ));
    }

    // Execute the child process.
    let status = execute_with_env(command, resolved)
        .await
        .map_err(|e| e.to_string())?;

    Ok(status.code().unwrap_or(1))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -- Mock resolver for testing --

    struct MockResolver {
        values: HashMap<String, String>,
    }

    impl MockResolver {
        fn new(values: Vec<(&str, &str)>) -> Self {
            Self {
                values: values.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            }
        }
    }

    impl RefResolver for MockResolver {
        fn resolve(&self, reference: &str) -> Result<String, InjectError> {
            self.values
                .get(reference)
                .cloned()
                .ok_or_else(|| InjectError::ResolveError {
                    reference: reference.to_string(),
                    message: "not found in mock".to_string(),
                })
        }
    }

    // -- Parsing tests --

    #[test]
    fn test_parse_env_template_valid() {
        let content = "\
DATABASE_URL=vault:secret/data/db#connection_string
API_KEY=aws-sm:prod/api-key
GITHUB_TOKEN=onepassword:vault/item#token
";
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].key, "DATABASE_URL");
        assert_eq!(
            entries[0].ref_or_literal,
            RefOrLiteral::Ref("vault:secret/data/db#connection_string".to_string())
        );

        assert_eq!(entries[1].key, "API_KEY");
        assert_eq!(
            entries[1].ref_or_literal,
            RefOrLiteral::Ref("aws-sm:prod/api-key".to_string())
        );

        assert_eq!(entries[2].key, "GITHUB_TOKEN");
        assert_eq!(
            entries[2].ref_or_literal,
            RefOrLiteral::Ref("onepassword:vault/item#token".to_string())
        );
    }

    #[test]
    fn test_parse_env_template_comments() {
        let content = "\
# This is a comment
DATABASE_URL=vault:secret/data/db#conn

  # Indented comment
API_KEY=aws-sm:prod/api-key
";
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "DATABASE_URL");
        assert_eq!(entries[1].key, "API_KEY");
    }

    #[test]
    fn test_parse_env_template_literal() {
        let content = "STATIC_VALUE=literal:my-non-secret-value\n";
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "STATIC_VALUE");
        assert_eq!(
            entries[0].ref_or_literal,
            RefOrLiteral::Literal("my-non-secret-value".to_string())
        );
    }

    #[test]
    fn test_parse_env_template_invalid_missing_eq() {
        let content = "DATABASE_URL\n";
        let result = parse_env_template_str(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InjectError::ParseError { line: 1, .. }),
            "expected ParseError at line 1, got: {err:?}"
        );
    }

    #[test]
    fn test_parse_env_template_invalid_empty_key() {
        let content = "=vault:secret/data/db#conn\n";
        let result = parse_env_template_str(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, InjectError::ParseError { .. }));
    }

    #[test]
    fn test_parse_env_template_invalid_ref_format() {
        // No ':' scheme separator in the value.
        let content = "MY_KEY=no-scheme-here\n";
        let result = parse_env_template_str(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, InjectError::ParseError { line: 1, .. }));
        assert!(err.to_string().contains("invalid ref format"));
    }

    #[test]
    fn test_parse_env_template_quoted_values_double() {
        let content = r#"MY_KEY="vault:secret/data/db#conn"
"#;
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].ref_or_literal,
            RefOrLiteral::Ref("vault:secret/data/db#conn".to_string())
        );
    }

    #[test]
    fn test_parse_env_template_quoted_values_single() {
        let content = "MY_KEY='vault:secret/data/db#conn'\n";
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].ref_or_literal,
            RefOrLiteral::Ref("vault:secret/data/db#conn".to_string())
        );
    }

    #[test]
    fn test_parse_env_template_literal_quoted() {
        let content = r#"MY_KEY="literal:hello world"
"#;
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].ref_or_literal,
            RefOrLiteral::Literal("hello world".to_string())
        );
    }

    // -- Resolution tests --

    #[test]
    fn test_resolve_refs() {
        let entries = vec![
            EnvEntry {
                key: "DB_URL".to_string(),
                ref_or_literal: RefOrLiteral::Ref("vault:secret/data/db#url".to_string()),
            },
            EnvEntry {
                key: "STATIC".to_string(),
                ref_or_literal: RefOrLiteral::Literal("hello".to_string()),
            },
        ];

        let resolver = MockResolver::new(vec![
            ("vault:secret/data/db#url", "postgres://localhost/mydb"),
        ]);

        let resolved = resolve_entries(&entries, &resolver).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].0, "DB_URL");
        assert_eq!(resolved[0].1.as_str(), "postgres://localhost/mydb");
        assert_eq!(resolved[1].0, "STATIC");
        assert_eq!(resolved[1].1.as_str(), "hello");
    }

    #[test]
    fn test_resolve_refs_failure() {
        let entries = vec![EnvEntry {
            key: "DB_URL".to_string(),
            ref_or_literal: RefOrLiteral::Ref("vault:secret/data/missing#url".to_string()),
        }];

        let resolver = MockResolver::new(vec![]);
        let result = resolve_entries(&entries, &resolver);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InjectError::ResolveError { .. }
        ));
    }

    // -- Child process injection test --

    #[tokio::test]
    async fn test_inject_into_env() {
        let env = vec![
            ("INJECTED_VAR_A".to_string(), SecretValue::new("value_a".to_string())),
            ("INJECTED_VAR_B".to_string(), SecretValue::new("value_b".to_string())),
        ];

        // Use a command that prints env vars. On Unix we use `env` or `printenv`.
        // Here we use `sh -c` with a targeted echo for reliability.
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo $INJECTED_VAR_A:$INJECTED_VAR_B".to_string(),
        ];

        let status = execute_with_env(&command, env).await.unwrap();
        assert!(status.success());
    }

    #[tokio::test]
    async fn test_inject_empty_command() {
        let result = execute_with_env(&[], vec![]).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InjectError::SpawnError(_)));
    }

    // -- Template file existence tests --

    #[test]
    fn test_missing_template_file() {
        let result = parse_env_template(Path::new("/nonexistent/.env.opaque"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InjectError::TemplateNotFound(_)
        ));
    }

    #[test]
    fn test_custom_template_path() {
        // Create a temp file with valid content.
        let dir = tempfile::tempdir().unwrap();
        let custom_path = dir.path().join("my-custom.env");
        std::fs::write(
            &custom_path,
            "CUSTOM_KEY=vault:secret/data/custom#value\n",
        )
        .unwrap();

        let entries = parse_env_template(&custom_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "CUSTOM_KEY");
    }

    // -- Edge case tests --

    #[test]
    fn test_parse_env_template_whitespace_around_eq() {
        let content = "MY_KEY = vault:secret/data/db#conn\n";
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "MY_KEY");
        assert_eq!(
            entries[0].ref_or_literal,
            RefOrLiteral::Ref("vault:secret/data/db#conn".to_string())
        );
    }

    #[test]
    fn test_parse_env_template_empty_file() {
        let entries = parse_env_template_str("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_env_template_only_comments() {
        let content = "# comment 1\n# comment 2\n";
        let entries = parse_env_template_str(content).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_is_valid_env_key() {
        assert!(is_valid_env_key("MY_VAR"));
        assert!(is_valid_env_key("_PRIVATE"));
        assert!(is_valid_env_key("A"));
        assert!(is_valid_env_key("VAR123"));
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("123VAR"));
        assert!(!is_valid_env_key("MY-VAR"));
        assert!(!is_valid_env_key("MY.VAR"));
    }

    #[test]
    fn test_strip_quotes() {
        assert_eq!(strip_quotes(r#""hello""#), "hello");
        assert_eq!(strip_quotes("'hello'"), "hello");
        assert_eq!(strip_quotes("hello"), "hello");
        assert_eq!(strip_quotes(r#""hello'"#), r#""hello'"#); // mismatched
        assert_eq!(strip_quotes(r#"""#), r#"""#); // single char
    }

    #[test]
    fn test_error_display() {
        let err = InjectError::TemplateNotFound(PathBuf::from("/a/b"));
        assert!(err.to_string().contains("template file not found"));

        let err = InjectError::ParseError {
            line: 5,
            message: "bad line".to_string(),
        };
        assert!(err.to_string().contains("line 5"));

        let err = InjectError::ResolveError {
            reference: "vault:x".to_string(),
            message: "oops".to_string(),
        };
        assert!(err.to_string().contains("vault:x"));

        let err = InjectError::SpawnError("not found".to_string());
        assert!(err.to_string().contains("spawn"));
    }

    #[test]
    fn test_parse_env_template_invalid_key_name() {
        let content = "123BAD=vault:secret/data/db#conn\n";
        let result = parse_env_template_str(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid environment variable name"));
    }

    #[test]
    fn test_parse_mixed_entries() {
        let content = "\
# Database config
DATABASE_URL=vault:secret/data/db#connection_string

# API settings
API_KEY=aws-sm:prod/api-key
GITHUB_TOKEN=onepassword:vault/item#token
STATIC_VALUE=literal:my-non-secret-value
DEBUG=literal:true
";
        let entries = parse_env_template_str(content).unwrap();
        assert_eq!(entries.len(), 5);

        // Verify ref types
        assert!(matches!(entries[0].ref_or_literal, RefOrLiteral::Ref(_)));
        assert!(matches!(entries[1].ref_or_literal, RefOrLiteral::Ref(_)));
        assert!(matches!(entries[2].ref_or_literal, RefOrLiteral::Ref(_)));
        assert!(matches!(entries[3].ref_or_literal, RefOrLiteral::Literal(_)));
        assert!(matches!(entries[4].ref_or_literal, RefOrLiteral::Literal(_)));
    }
}
