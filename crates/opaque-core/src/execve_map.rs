//! Execve-to-operation mapping rules.
//!
//! Translates executable paths and arguments into Opaque operation names.
//! Used by the `sandbox.execve_check` handler to map external sandbox
//! execve requests to operations that can be evaluated by the policy engine.
//!
//! Pattern matching uses simple glob syntax on the joined command string
//! (`executable arg1 arg2 ...`). Rules are ordered; first match wins.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ExecveRule
// ---------------------------------------------------------------------------

/// A single mapping rule from an execve command pattern to an Opaque operation.
///
/// The pattern is matched against the joined command string:
/// `"{basename} {arg1} {arg2} ..."` using glob syntax.
///
/// Note: `*` does NOT match `/` (it is a path-segment glob). Use `**`
/// if arguments may contain slashes (e.g. URLs). For simple argument
/// matching (no slashes), `*` is sufficient.
///
/// Example TOML:
/// ```toml
/// [[execve_rules]]
/// pattern = "git push *"
/// operation = "git.push"
/// secret_refs = ["GITHUB_TOKEN"]
/// description = "Push to a git remote"
///
/// [[execve_rules]]
/// pattern = "curl **"
/// operation = "network.curl"
/// description = "Curl with URL arguments (may contain slashes)"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecveRule {
    /// Glob pattern matched against `"{executable} {args...}"`.
    /// Supports `*` (any sequence of chars), `?` (any single char), and
    /// `**` (any path segments) via the `glob-match` crate.
    pub pattern: String,

    /// Opaque operation name this command maps to (e.g. `"git.push"`).
    pub operation: String,

    /// Secret reference names needed for this command (names only, never values).
    #[serde(default)]
    pub secret_refs: Vec<String>,

    /// Optional human-readable description shown in audit logs and approval prompts.
    #[serde(default)]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// ExecveDefault
// ---------------------------------------------------------------------------

/// Default decision for commands that do not match any execve rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecveDefaultDecision {
    /// Allow unmatched commands without prompting.
    #[default]
    Allow,
    /// Prompt for human approval before allowing unmatched commands.
    Prompt,
    /// Deny unmatched commands.
    Deny,
}

/// Configuration for the default execve behavior when no rule matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecveDefault {
    /// The decision to apply when no rule matches.
    #[serde(default)]
    pub decision: ExecveDefaultDecision,
}

impl Default for ExecveDefault {
    fn default() -> Self {
        Self {
            decision: ExecveDefaultDecision::Allow,
        }
    }
}

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

/// The result of matching an execve against the rules.
#[derive(Debug, Clone)]
pub struct ExecveMatch {
    /// The matched operation name, or `None` if no rule matched (default applies).
    pub operation: Option<String>,

    /// Secret reference names from the matched rule.
    pub secret_refs: Vec<String>,

    /// Name of the matched rule pattern (for audit).
    pub matched_pattern: Option<String>,

    /// Whether this was the default (no rule matched).
    pub is_default: bool,
}

// ---------------------------------------------------------------------------
// ExecveMapper
// ---------------------------------------------------------------------------

/// Maps execve (executable, args) pairs to Opaque operations.
///
/// Rules are evaluated in order; the first match wins.
/// If no rule matches, the default applies.
#[derive(Debug, Clone)]
pub struct ExecveMapper {
    rules: Vec<ExecveRule>,
    default: ExecveDefault,
}

impl ExecveMapper {
    /// Create a new mapper from a list of rules and a default config.
    pub fn new(rules: Vec<ExecveRule>, default: ExecveDefault) -> Self {
        Self { rules, default }
    }

    /// Create a mapper with no rules (everything uses the default decision).
    pub fn empty() -> Self {
        Self {
            rules: vec![],
            default: ExecveDefault::default(),
        }
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Return the default decision setting.
    pub fn default_decision(&self) -> ExecveDefaultDecision {
        self.default.decision
    }

    /// Match an execve call against the rules.
    ///
    /// Constructs the command string from `executable` and `args`, then
    /// tests each rule's glob pattern in order. Returns the first match,
    /// or a default result if nothing matched.
    pub fn match_execve(&self, executable: &str, args: &[String]) -> ExecveMatch {
        let command_str = build_command_string(executable, args);

        for rule in &self.rules {
            if glob_match::glob_match(&rule.pattern, &command_str) {
                return ExecveMatch {
                    operation: Some(rule.operation.clone()),
                    secret_refs: rule.secret_refs.clone(),
                    matched_pattern: Some(rule.pattern.clone()),
                    is_default: false,
                };
            }
        }

        // No rule matched; return default.
        ExecveMatch {
            operation: None,
            secret_refs: vec![],
            matched_pattern: None,
            is_default: true,
        }
    }
}

/// Build the command string for pattern matching.
///
/// Format: `"{executable_basename} {arg1} {arg2} ..."`.
/// We use only the basename of the executable for matching so that rules
/// like `"git push *"` match both `/usr/bin/git` and `/usr/local/bin/git`.
fn build_command_string(executable: &str, args: &[String]) -> String {
    let basename = std::path::Path::new(executable)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(executable);

    if args.is_empty() {
        basename.to_owned()
    } else {
        format!("{} {}", basename, args.join(" "))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rules() -> Vec<ExecveRule> {
        vec![
            ExecveRule {
                pattern: "git push *".into(),
                operation: "git.push".into(),
                secret_refs: vec!["GITHUB_TOKEN".into()],
                description: Some("Push to a git remote".into()),
            },
            ExecveRule {
                pattern: "npm publish *".into(),
                operation: "npm.publish".into(),
                secret_refs: vec!["NPM_TOKEN".into()],
                description: None,
            },
            ExecveRule {
                pattern: "docker push *".into(),
                operation: "docker.push".into(),
                secret_refs: vec!["DOCKER_TOKEN".into()],
                description: None,
            },
            ExecveRule {
                pattern: "curl **".into(),
                operation: "network.curl".into(),
                secret_refs: vec![],
                description: None,
            },
        ]
    }

    #[test]
    fn execve_rule_glob_matching() {
        let mapper = ExecveMapper::new(test_rules(), ExecveDefault::default());

        // Should match "git push *"
        let result = mapper.match_execve(
            "/usr/bin/git",
            &["push".into(), "origin".into(), "main".into()],
        );
        assert!(!result.is_default);
        assert_eq!(result.operation.as_deref(), Some("git.push"));
        assert_eq!(result.secret_refs, vec!["GITHUB_TOKEN"]);
        assert_eq!(result.matched_pattern.as_deref(), Some("git push *"));

        // Should match "curl **" (uses ** because URLs contain slashes)
        let result = mapper.match_execve("/usr/bin/curl", &["https://example.com".into()]);
        assert!(!result.is_default);
        assert_eq!(result.operation.as_deref(), Some("network.curl"));
        assert!(result.secret_refs.is_empty());
    }

    #[test]
    fn execve_rule_first_match_wins() {
        // Create two rules that could both match, first one should win.
        let rules = vec![
            ExecveRule {
                pattern: "git push origin main".into(),
                operation: "git.push.main".into(),
                secret_refs: vec!["DEPLOY_TOKEN".into()],
                description: None,
            },
            ExecveRule {
                pattern: "git push *".into(),
                operation: "git.push".into(),
                secret_refs: vec!["GITHUB_TOKEN".into()],
                description: None,
            },
        ];
        let mapper = ExecveMapper::new(rules, ExecveDefault::default());

        let result = mapper.match_execve(
            "/usr/bin/git",
            &["push".into(), "origin".into(), "main".into()],
        );
        assert_eq!(result.operation.as_deref(), Some("git.push.main"));
        assert_eq!(result.secret_refs, vec!["DEPLOY_TOKEN"]);
    }

    #[test]
    fn execve_default_applies_when_no_match() {
        let mapper = ExecveMapper::new(
            test_rules(),
            ExecveDefault {
                decision: ExecveDefaultDecision::Deny,
            },
        );

        // "ls" doesn't match any rule
        let result = mapper.match_execve("/bin/ls", &["-la".into()]);
        assert!(result.is_default);
        assert!(result.operation.is_none());
        assert!(result.secret_refs.is_empty());
        assert!(result.matched_pattern.is_none());
    }

    #[test]
    fn execve_rules_parse_from_toml() {
        let toml_str = r#"
[[execve_rules]]
pattern = "git push *"
operation = "git.push"
secret_refs = ["GITHUB_TOKEN"]
description = "Push to a git remote"

[[execve_rules]]
pattern = "npm publish *"
operation = "npm.publish"

[execve_default]
decision = "deny"
"#;

        #[derive(Deserialize)]
        struct TestConfig {
            #[serde(default)]
            execve_rules: Vec<ExecveRule>,
            #[serde(default)]
            execve_default: ExecveDefault,
        }

        let config: TestConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(config.execve_rules.len(), 2);
        assert_eq!(config.execve_rules[0].pattern, "git push *");
        assert_eq!(config.execve_rules[0].operation, "git.push");
        assert_eq!(config.execve_rules[0].secret_refs, vec!["GITHUB_TOKEN"]);
        assert_eq!(
            config.execve_rules[0].description.as_deref(),
            Some("Push to a git remote")
        );
        assert_eq!(config.execve_rules[1].pattern, "npm publish *");
        assert!(config.execve_rules[1].secret_refs.is_empty());
        assert_eq!(config.execve_default.decision, ExecveDefaultDecision::Deny);
    }

    #[test]
    fn execve_rules_empty_means_allow_all() {
        // No rules + default allow = everything is allowed by default.
        let mapper = ExecveMapper::empty();
        assert_eq!(mapper.rule_count(), 0);
        assert_eq!(mapper.default_decision(), ExecveDefaultDecision::Allow);

        let result = mapper.match_execve("/usr/bin/anything", &["--flag".into()]);
        assert!(result.is_default);
        assert!(result.operation.is_none());
    }

    #[test]
    fn build_command_string_basename_only() {
        let s = build_command_string("/usr/bin/git", &["push".into(), "origin".into()]);
        assert_eq!(s, "git push origin");
    }

    #[test]
    fn build_command_string_no_args() {
        let s = build_command_string("/bin/ls", &[]);
        assert_eq!(s, "ls");
    }

    #[test]
    fn execve_mapper_debug() {
        let mapper = ExecveMapper::empty();
        let dbg = format!("{mapper:?}");
        assert!(dbg.contains("ExecveMapper"));
    }

    #[test]
    fn execve_default_decision_default() {
        let d = ExecveDefaultDecision::default();
        assert_eq!(d, ExecveDefaultDecision::Allow);
    }

    #[test]
    fn execve_rule_serde_roundtrip() {
        let rule = ExecveRule {
            pattern: "git push *".into(),
            operation: "git.push".into(),
            secret_refs: vec!["TOKEN".into()],
            description: Some("test".into()),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let rt: ExecveRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.pattern, "git push *");
        assert_eq!(rt.operation, "git.push");
        assert_eq!(rt.secret_refs, vec!["TOKEN"]);
    }

    #[test]
    fn execve_default_serde_roundtrip() {
        let d = ExecveDefault {
            decision: ExecveDefaultDecision::Prompt,
        };
        let json = serde_json::to_string(&d).unwrap();
        let rt: ExecveDefault = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.decision, ExecveDefaultDecision::Prompt);
    }

    #[test]
    fn match_executable_basename_regardless_of_path() {
        let rules = vec![ExecveRule {
            pattern: "git push *".into(),
            operation: "git.push".into(),
            secret_refs: vec![],
            description: None,
        }];
        let mapper = ExecveMapper::new(rules, ExecveDefault::default());

        // Different paths, same basename
        let r1 = mapper.match_execve("/usr/bin/git", &["push".into(), "origin".into()]);
        let r2 = mapper.match_execve("/usr/local/bin/git", &["push".into(), "origin".into()]);
        let r3 = mapper.match_execve("git", &["push".into(), "origin".into()]);

        assert!(!r1.is_default);
        assert!(!r2.is_default);
        assert!(!r3.is_default);
        assert_eq!(r1.operation, r2.operation);
        assert_eq!(r2.operation, r3.operation);
    }
}
