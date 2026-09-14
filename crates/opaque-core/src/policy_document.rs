//! The policy view of a complete broker TOML configuration. Unknown top-level
//! settings remain available to their owning subsystem and are ignored here.
use crate::policy::PolicyRule;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyDocument {
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub require_seal: bool,
}

impl PolicyDocument {
    pub fn from_toml(input: &str) -> Result<Self, toml_edit::de::Error> {
        toml_edit::de::from_str(input)
    }

    /// Existing CLI policy checks, shared with offline parser robustness tests.
    pub fn validation_errors(&self) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();
        for (i, rule) in self.rules.iter().enumerate() {
            let prefix = format!("rules[{i}] ({:?})", rule.name);
            if rule.name.is_empty() {
                errors.push(format!("{prefix}: name must be non-empty"));
            }
            if rule.operation_pattern.is_empty() {
                errors.push(format!("{prefix}: operation_pattern must be non-empty"));
            }
            if rule.client_types.is_empty() {
                errors.push(format!("{prefix}: client_types must not be empty"));
            }
            if let Some(ttl) = rule.approval.lease_ttl
                && ttl.as_secs() == 0
            {
                errors.push(format!("{prefix}: approval.lease_ttl must be > 0"));
            }
            if rule.approval.budget.is_some()
                && (rule.approval.require != crate::operation::ApprovalRequirement::FirstUse
                    || rule.approval.budget == Some(0))
            {
                errors.push(format!(
                    "{prefix}: approval.budget requires first_use and must be > 0"
                ));
            }
        }
        errors
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn production_policy_document_preserves_defaults_and_other_subsystem_settings() {
        let document =
            PolicyDocument::from_toml("require_seal = true\n[server]\nport = 42\n").unwrap();
        assert!(document.require_seal);
        assert!(document.rules.is_empty());
        assert!(document.validation_errors().is_empty());
        assert!(!PolicyDocument::from_toml("").unwrap().require_seal);
    }

    #[test]
    fn malformed_and_unknown_matcher_fields_are_rejected() {
        assert!(PolicyDocument::from_toml("[[rules]").is_err());
        assert!(
            PolicyDocument::from_toml(
                r#"
[[rules]]
name = "fixture"
operation_pattern = "*"
[rules.client]
uuid_typo = 12
"#
            )
            .is_err()
        );
    }

    #[test]
    fn semantic_checks_keep_all_existing_cli_failures() {
        let document = PolicyDocument::from_toml(
            r#"
[[rules]]
name = ""
operation_pattern = ""
[rules.approval]
require = "never"
lease_ttl = 0
budget = 0
"#,
        )
        .unwrap();
        let errors = document.validation_errors();
        assert_eq!(errors.len(), 5);
        for field in [
            "name",
            "operation_pattern",
            "client_types",
            "approval.lease_ttl",
            "approval.budget",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(field)),
                "missing {field}"
            );
        }
    }

    #[test]
    fn reviewed_fuzz_seeds_reach_semantic_validation() {
        let policy = PolicyDocument::from_toml(include_str!(
            "../../../fuzz/corpus/policy_document/allow.toml"
        ))
        .unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.validation_errors().is_empty());
        let manifest: crate::task::TaskManifest = serde_json::from_str(include_str!(
            "../../../fuzz/corpus/task_manifest/valid-publish.json"
        ))
        .unwrap();
        assert!(manifest.validate().is_ok());
        assert_eq!(manifest.digest().unwrap().len(), 64);
    }
}
