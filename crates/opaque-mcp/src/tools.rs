use serde_json::json;

/// A single MCP tool definition.
pub struct ToolDef {
    /// MCP tool name (e.g. `opaque_github_set_actions_secret`).
    pub name: &'static str,
    /// Human-readable description shown to LLMs.
    pub description: &'static str,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: serde_json::Value,
    /// How to build the daemon IPC params from the MCP tool arguments.
    pub build_params: fn(&serde_json::Value) -> serde_json::Value,
}

/// Build the hard-coded list of Safe MCP tools.
///
/// SECURITY: Only Safe operations are exposed. Never add Reveal or
/// SensitiveOutput operations here (defense-in-depth).
pub fn safe_tools() -> Vec<ToolDef> {
    vec![
        // --- GitHub operations ---
        ToolDef {
            name: "opaque_github_set_actions_secret",
            description: "Set a GitHub Actions repository secret via Opaque's approval-gated enclave. \
                           The secret value is resolved from a secure ref (e.g. keychain:opaque/my-key) \
                           and never exposed to the caller.",
            input_schema: json!({
                "type": "object",
                "required": ["repo", "secret_name", "value_ref"],
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository in owner/repo format"
                    },
                    "secret_name": {
                        "type": "string",
                        "description": "Secret name (e.g. AWS_ACCESS_KEY_ID)"
                    },
                    "value_ref": {
                        "type": "string",
                        "description": "Secret ref (e.g. keychain:opaque/aws-key)"
                    },
                    "github_token_ref": {
                        "type": "string",
                        "description": "GitHub token ref (default: keychain:opaque/github-pat)"
                    },
                    "environment": {
                        "type": "string",
                        "description": "GitHub environment name (for environment secrets)"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                // Daemon routes set ops by scope; "repo_actions" covers both
                // repo-level and env-scoped actions secrets (environment is
                // passed as a param, not a scope variant).
                params["scope"] = json!("repo_actions");
                params
            },
        },
        ToolDef {
            name: "opaque_github_set_codespaces_secret",
            description: "Set a GitHub Codespaces secret (user-level or repo-level) via Opaque's \
                           approval-gated enclave.",
            input_schema: json!({
                "type": "object",
                "required": ["secret_name", "value_ref"],
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository in owner/repo format (omit for user-level)"
                    },
                    "secret_name": {
                        "type": "string",
                        "description": "Secret name"
                    },
                    "value_ref": {
                        "type": "string",
                        "description": "Secret ref"
                    },
                    "github_token_ref": {
                        "type": "string",
                        "description": "GitHub token ref"
                    },
                    "selected_repository_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Selected repository IDs (for user-level secrets)"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                // Daemon distinguishes codespaces_user vs codespaces_repo by
                // whether a `repo` field is present.
                if args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .is_empty()
                {
                    params["scope"] = json!("codespaces_user");
                } else {
                    params["scope"] = json!("codespaces_repo");
                }
                params
            },
        },
        ToolDef {
            name: "opaque_github_set_dependabot_secret",
            description: "Set a GitHub Dependabot repository secret via Opaque's approval-gated enclave.",
            input_schema: json!({
                "type": "object",
                "required": ["repo", "secret_name", "value_ref"],
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository in owner/repo format"
                    },
                    "secret_name": {
                        "type": "string",
                        "description": "Secret name"
                    },
                    "value_ref": {
                        "type": "string",
                        "description": "Secret ref"
                    },
                    "github_token_ref": {
                        "type": "string",
                        "description": "GitHub token ref"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                params["scope"] = json!("dependabot");
                params
            },
        },
        ToolDef {
            name: "opaque_github_set_org_secret",
            description: "Set a GitHub Actions organization secret via Opaque's approval-gated enclave.",
            input_schema: json!({
                "type": "object",
                "required": ["org", "secret_name", "value_ref"],
                "properties": {
                    "org": {
                        "type": "string",
                        "description": "Organization name"
                    },
                    "secret_name": {
                        "type": "string",
                        "description": "Secret name"
                    },
                    "value_ref": {
                        "type": "string",
                        "description": "Secret ref"
                    },
                    "github_token_ref": {
                        "type": "string",
                        "description": "GitHub token ref"
                    },
                    "visibility": {
                        "type": "string",
                        "enum": ["all", "private", "selected"],
                        "description": "Secret visibility (default: private)"
                    },
                    "selected_repository_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Selected repository IDs (when visibility is selected)"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                params["scope"] = json!("org_actions");
                params
            },
        },
        ToolDef {
            name: "opaque_github_list_secrets",
            description: "List GitHub secret names for a repository, environment, or organization. \
                           Returns metadata only (names, dates) — never secret values.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository in owner/repo format"
                    },
                    "org": {
                        "type": "string",
                        "description": "Organization name (for org scope)"
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["actions", "codespaces", "dependabot", "org"],
                        "description": "Secret scope (default: actions)"
                    },
                    "environment": {
                        "type": "string",
                        "description": "GitHub environment name"
                    },
                    "github_token_ref": {
                        "type": "string",
                        "description": "GitHub token ref"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                params["action"] = json!("list_secrets");
                params
            },
        },
        ToolDef {
            name: "opaque_github_delete_secret",
            description: "Delete a GitHub secret from a repository, environment, or organization.",
            input_schema: json!({
                "type": "object",
                "required": ["secret_name"],
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository in owner/repo format"
                    },
                    "org": {
                        "type": "string",
                        "description": "Organization name (for org scope)"
                    },
                    "secret_name": {
                        "type": "string",
                        "description": "Secret name to delete"
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["actions", "codespaces", "dependabot", "org"],
                        "description": "Secret scope (default: actions)"
                    },
                    "environment": {
                        "type": "string",
                        "description": "GitHub environment name"
                    },
                    "github_token_ref": {
                        "type": "string",
                        "description": "GitHub token ref"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                params["action"] = json!("delete_secret");
                params
            },
        },
        // --- 1Password operations (Safe only — read_field is Reveal, excluded) ---
        ToolDef {
            name: "opaque_onepassword_list_vaults",
            description: "List accessible 1Password vaults. Returns vault names and IDs only.",
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),

            build_params: |_args| json!({"action": "list_vaults"}),
        },
        ToolDef {
            name: "opaque_onepassword_list_items",
            description: "List items in a 1Password vault. Returns item titles and metadata only — never secret values.",
            input_schema: json!({
                "type": "object",
                "required": ["vault"],
                "properties": {
                    "vault": {
                        "type": "string",
                        "description": "Vault name"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                params["action"] = json!("list_items");
                params
            },
        },
        // --- Bitwarden operations (Safe only — read_secret is Reveal, excluded) ---
        ToolDef {
            name: "opaque_bitwarden_list_projects",
            description: "List Bitwarden Secrets Manager projects. Returns project names and IDs only.",
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),

            build_params: |_args| json!({"action": "list_projects"}),
        },
        ToolDef {
            name: "opaque_bitwarden_list_secrets",
            description: "List secrets in a Bitwarden Secrets Manager project. Returns secret names and metadata only — never secret values.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project": {
                        "type": "string",
                        "description": "Project name or ID to filter by (optional)"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                params["action"] = json!("list_secrets");
                params
            },
        },
    ]
}

/// Map an MCP tool name to the daemon IPC method that should be called.
///
/// IMPORTANT: This returns the daemon RPC *method* (e.g. `"github"`,
/// `"onepassword"`, `"bitwarden"`), NOT the enclave operation name
/// (e.g. `"github.set_actions_secret"`). The daemon wrapper methods
/// route to the correct enclave operation based on `action`/`scope`
/// fields in the params built by each tool's `build_params`.
pub fn tool_to_daemon_method(tool_name: &str) -> Option<&'static str> {
    static MAPPING: &[(&str, &str)] = &[
        ("opaque_github_set_actions_secret", "github"),
        ("opaque_github_set_codespaces_secret", "github"),
        ("opaque_github_set_dependabot_secret", "github"),
        ("opaque_github_set_org_secret", "github"),
        ("opaque_github_list_secrets", "github"),
        ("opaque_github_delete_secret", "github"),
        ("opaque_onepassword_list_vaults", "onepassword"),
        ("opaque_onepassword_list_items", "onepassword"),
        ("opaque_bitwarden_list_projects", "bitwarden"),
        ("opaque_bitwarden_list_secrets", "bitwarden"),
    ];
    MAPPING
        .iter()
        .find(|(k, _)| *k == tool_name)
        .map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tools_are_safe() {
        // Verify no Reveal or SensitiveOutput tool names leak into the tool list.
        let tools = safe_tools();
        let allowed_methods = ["github", "onepassword", "bitwarden"];
        for tool in &tools {
            let method = tool_to_daemon_method(tool.name)
                .unwrap_or_else(|| panic!("no daemon method mapping for {}", tool.name));
            assert!(
                allowed_methods.contains(&method),
                "tool {} maps to unexpected daemon method '{}'",
                tool.name,
                method
            );

            // Tool names must never reference Reveal or SensitiveOutput operations.
            assert!(
                !tool.name.contains("read_field"),
                "Reveal tool leaked: {}",
                tool.name
            );
            assert!(
                !tool.name.contains("read_secret"),
                "Reveal tool leaked: {}",
                tool.name
            );
            assert!(
                !tool.name.contains("sandbox"),
                "SensitiveOutput tool leaked: {}",
                tool.name
            );
            assert!(
                !tool.name.contains("noop"),
                "test tool leaked: {}",
                tool.name
            );
        }
    }

    #[test]
    fn all_tools_have_operation_mappings() {
        let tools = safe_tools();
        for tool in &tools {
            assert!(
                tool_to_daemon_method(tool.name).is_some(),
                "tool {} has no operation mapping",
                tool.name,
            );
        }
    }

    #[test]
    fn tool_count() {
        let tools = safe_tools();
        assert_eq!(tools.len(), 10);
    }

    #[test]
    fn input_schemas_are_objects() {
        let tools = safe_tools();
        for tool in &tools {
            assert_eq!(
                tool.input_schema["type"], "object",
                "tool {} input_schema is not an object",
                tool.name,
            );
        }
    }

    #[test]
    fn build_params_produces_valid_json() {
        let tools = safe_tools();
        for tool in &tools {
            let args = serde_json::json!({"test_key": "test_value"});
            let params = (tool.build_params)(&args);
            assert!(
                params.is_object(),
                "build_params for {} didn't return an object",
                tool.name
            );
        }
    }

    #[test]
    fn no_reveal_tools_in_safe_list() {
        let tools = safe_tools();
        for tool in &tools {
            assert!(
                !tool.name.contains("read_field"),
                "Reveal tool leaked: {}",
                tool.name
            );
            assert!(
                !tool.name.contains("read_secret"),
                "Reveal tool leaked: {}",
                tool.name
            );
        }
    }

    #[test]
    fn no_sensitive_output_tools_in_safe_list() {
        let tools = safe_tools();
        for tool in &tools {
            assert!(
                !tool.name.contains("sandbox"),
                "SensitiveOutput tool leaked: {}",
                tool.name
            );
        }
    }

    #[test]
    fn github_set_tools_include_scope() {
        let tools = safe_tools();
        let set_tools: Vec<_> = tools
            .iter()
            .filter(|t| t.name.starts_with("opaque_github_set_"))
            .collect();
        assert!(!set_tools.is_empty());
        for tool in set_tools {
            let args = serde_json::json!({"repo": "org/repo", "secret_name": "S", "value_ref": "keychain:x"});
            let params = (tool.build_params)(&args);
            assert!(
                params.get("scope").is_some(),
                "GitHub set tool {} must include 'scope' in daemon params",
                tool.name,
            );
        }
    }
}
