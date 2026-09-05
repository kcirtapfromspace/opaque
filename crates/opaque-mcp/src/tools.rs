use std::path::Path;

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

/// Summary of a profile for listing purposes (no secret values).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub description: Option<String>,
}

/// Status of a single secret reference in a profile (no values exposed).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecretRefStatus {
    pub env_name: String,
    pub scheme: String,
    pub reference: String,
}

/// List available profiles by reading `~/.opaque/profiles/` (or a custom dir).
///
/// This is implemented client-side in the MCP server since it only reads TOML
/// files and never resolves secret values.
pub fn list_profiles(profiles_dir: &Path) -> Vec<ProfileSummary> {
    let entries = match std::fs::read_dir(profiles_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut summaries = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Extract the expected name from the filename (without .toml).
        let expected_name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };

        match opaque_core::profile::load_profile(&contents, Some(expected_name)) {
            Ok(profile) => {
                summaries.push(ProfileSummary {
                    name: profile.name,
                    description: profile.description,
                });
            }
            Err(_) => {
                // Skip invalid TOML files gracefully.
                continue;
            }
        }
    }

    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    summaries
}

/// Extract secret reference statuses from a profile TOML without resolving values.
///
/// Returns the env name, scheme, and full reference string for each secret
/// defined in the profile. Never resolves or returns actual secret values.
pub fn secrets_status(
    profiles_dir: &Path,
    profile_name: &str,
) -> Result<Vec<SecretRefStatus>, String> {
    let path = profiles_dir.join(format!("{profile_name}.toml"));
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read profile '{}': {e}", path.display()))?;

    let profile = opaque_core::profile::load_profile(&contents, Some(profile_name))
        .map_err(|e| format!("invalid profile '{profile_name}': {e}"))?;

    let mut statuses: Vec<SecretRefStatus> = profile
        .secrets
        .iter()
        .map(|(env_name, ref_str)| {
            let scheme = ref_str
                .split_once(':')
                .map(|(s, _)| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            SecretRefStatus {
                env_name: env_name.clone(),
                scheme,
                reference: ref_str.clone(),
            }
        })
        .collect();

    statuses.sort_by(|a, b| a.env_name.cmp(&b.env_name));
    Ok(statuses)
}

/// Build the hard-coded list of Safe MCP tools.
///
/// SECURITY: Only Safe operations are exposed. Never add Reveal or
/// SensitiveOutput operations here (defense-in-depth).
///
/// The sandbox exec tool is safe because:
/// - It goes through the daemon's policy engine (approval required)
/// - Secrets are resolved server-side (never sent to MCP client)
/// - The sandbox enforces OS-level isolation
/// - Audit trail captures everything
pub fn safe_tools() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "opaque_task_plan_inference",
            description: "Plan three fixed synthetic public-source model completions in the authenticated tenant. The broker selects the source snapshot, model and exact prompts. No custom SQL, data source, endpoint, tenant or prompt is accepted. Planning is read-only and grants no authority. Human approval is required before execution; each attempt reserves 96 output units and uncertainty stops later requests.",
            input_schema: json!({"type":"object","additionalProperties":false,"required":["title","expires_in_secs"],"properties":{"title":{"type":"string","minLength":1,"maxLength":160},"expires_in_secs":{"type":"integer","minimum":1,"maximum":600}}}),
            build_params: |args| json!({"title": args.get("title").cloned().unwrap_or(json!(null)), "expires_in_secs": args.get("expires_in_secs").cloned().unwrap_or(json!(null))}),
        },
        ToolDef {
            name: "opaque_task_plan",
            description: "Plan an immutable bounded task: schema1 publishes pinned Vault values to exact GitHub secrets; schema2 dispatches one trusted staging workflow with an immutable image digest. The broker resolves provider identities and validates the trusted workflow profile. Planning grants no approval and performs no writes. Present the complete returned scope for trusted human review.",
            input_schema: task_plan_schema(),
            build_params: |args| json!({"manifest": args.get("manifest").cloned().unwrap_or(json!(null))}),
        },
        ToolDef {
            name: "opaque_task_run",
            description: "Request trusted human approval for an immutable planned task and execute its fixed actions once, including secret publishing, staging workflow dispatch or bounded inference. Approval cannot be supplied as a tool argument. Each reserved action permanently consumes its slot; inference attempts reserve 96 output tokens. Failures and unknown outcomes receive no automatic retry or fresh allowance. After a timeout or concurrent run, use opaque_task_get to inspect the receipt. Repeating this call cannot resume a closed task.",
            input_schema: task_id_schema(),
            build_params: task_id_params,
        },
        ToolDef {
            name: "opaque_task_get",
            description: "Inspect a bounded task's exact targets, source and tenant bindings, digest, approval state, expiry and durable receipt. Interpret evidence by action type: GitHub write or dispatch acceptance, or an observed inference completion with returned text and reported token usage. API acceptance alone does not establish deployment or service health. Secret values cannot be read back. Reserved or unknown slots remain charged. Use this after interrupted runs instead of repeating provider actions.",
            input_schema: task_id_schema(),
            build_params: task_id_params,
        },
        ToolDef {
            name: "opaque_task_list",
            description: "List a bounded page of tasks belonging to the current authenticated owner, including planned work and durable receipts. When has_more is true, pass next_cursor as cursor to retrieve older tasks. Agent session changes do not reset their allowance.",
            input_schema: json!({"type": "object", "additionalProperties": false, "properties": {
                "cursor": {"type": "string", "description": "Optional next_cursor task ID returned by the previous page"}
            }}),
            build_params: |args| json!({"cursor": args.get("cursor").cloned().unwrap_or(json!(null))}),
        },
        ToolDef {
            name: "opaque_task_revoke",
            description: "Revoke a task to block future provider actions, including secret writes, workflow dispatch and model generation attempts. Work already authorized for dispatch may still complete; inspect the resulting receipt. Revocation never refunds reserved slots or generation allowances, and never enables a retry.",
            input_schema: task_id_schema(),
            build_params: task_id_params,
        },
        ToolDef {
            name: "opaque_task_reconcile",
            description: "Read and persist correlated staging workflow evidence for an attempted task. This performs read-only provider requests and never dispatches, retries, refunds authority, or rolls back. API acceptance, workflow success and application health are distinct. Failed or ambiguous evidence is returned as a tool error with the receipt preserved.",
            input_schema: task_id_schema(),
            build_params: task_id_params,
        },
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
        // --- GitLab operations ---
        ToolDef {
            name: "opaque_gitlab_set_ci_variable",
            description: "Set a GitLab CI/CD project variable via Opaque's approval-gated enclave. \
                           The value is resolved from a secure ref and never returned to the caller.",
            input_schema: json!({
                "type": "object",
                "required": ["project", "key", "value_ref"],
                "properties": {
                    "project": {
                        "type": "string",
                        "description": "Project path or ID (e.g. group/project)"
                    },
                    "key": {
                        "type": "string",
                        "description": "Variable key"
                    },
                    "value_ref": {
                        "type": "string",
                        "description": "Secret ref (e.g. keychain:opaque/db-url)"
                    },
                    "gitlab_token_ref": {
                        "type": "string",
                        "description": "GitLab token ref (default: keychain:opaque/gitlab-pat)"
                    },
                    "environment_scope": {
                        "type": "string",
                        "description": "Environment scope (default: *)"
                    },
                    "protected": {
                        "type": "boolean",
                        "description": "Mark variable as protected"
                    },
                    "masked": {
                        "type": "boolean",
                        "description": "Mark variable as masked"
                    },
                    "raw": {
                        "type": "boolean",
                        "description": "Keep variable raw (no expansion)"
                    },
                    "variable_type": {
                        "type": "string",
                        "enum": ["env_var", "file"],
                        "description": "Variable type (default: env_var)"
                    }
                }
            }),

            build_params: |args| {
                let mut params = args.clone();
                params["action"] = json!("set_ci_variable");
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
        // --- Sandbox operations ---
        ToolDef {
            name: "opaque_sandbox_exec",
            description: "Execute a command in Opaque's sandboxed environment with vault-backed secrets. \
                           The command runs in an isolated sandbox with only the secrets specified by the \
                           profile injected as environment variables. Network access, filesystem writes, \
                           and process isolation are enforced by the sandbox.",
            input_schema: json!({
                "type": "object",
                "required": ["profile", "command"],
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "Opaque profile name (e.g. 'dev', 'ci-deploy'). Profiles define which secrets, env vars, network rules, and filesystem access the sandbox gets. See ~/.opaque/profiles/"
                    },
                    "command": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command and arguments to execute (e.g. ['npm', 'test'] or ['python', 'deploy.py'])"
                    }
                }
            }),

            build_params: |args| {
                json!({
                    "profile": args.get("profile").cloned().unwrap_or(json!(null)),
                    "command": args.get("command").cloned().unwrap_or(json!(null))
                })
            },
        },
        ToolDef {
            name: "opaque_sandbox_list_profiles",
            description: "List available Opaque sandbox profiles. Each profile defines a sandboxed \
                           execution environment with specific secrets, network rules, and filesystem \
                           access. Use this to discover which profiles are available before calling \
                           opaque_sandbox_exec.",
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),

            build_params: |_args| json!({}),
        },
        ToolDef {
            name: "opaque_secrets_status",
            description: "List secret reference names, schemes and configured paths from a local Opaque \
                           profile without resolving values. This parses configuration only: it does not \
                           check provider connectivity, credential availability or whether a secret exists.",
            input_schema: json!({
                "type": "object",
                "required": ["profile"],
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "Profile name to check secrets for"
                    }
                }
            }),

            build_params: |args| {
                json!({
                    "profile": args.get("profile").cloned().unwrap_or(json!(null))
                })
            },
        },
    ]
}

fn task_plan_schema() -> serde_json::Value {
    let secret = json!({
        "type": "object", "additionalProperties": false,
        "required": ["repo", "secret_name", "value_ref"],
        "properties": {
            "repo": {"type":"string"}, "repository_id":{"type":"integer","minimum":0},
            "secret_name":{"type":"string","pattern":"^[A-Z_][A-Z0-9_]*$","maxLength":100},
            "value_ref":{"type":"string","description":"Pinned Vault KV v2 reference; never a value"},
            "github_token_ref":{"type":"string","maxLength":128}
        }
    });
    let release = json!({
        "type":"object", "additionalProperties":false,
        "required":["operation","repo","workflow_path","workflow_ref","image_repository","image_digest","environment"],
        "properties": {
            "operation":{"const":"github.dispatch_staging_workflow"},
            "repo":{"type":"string"}, "repository_id":{"type":"integer","minimum":0},
            "workflow_path":{"type":"string"},"workflow_id":{"type":"integer","minimum":0},
            "workflow_ref":{"type":"string","description":"Exact trusted branch"},
            "approved_commit_sha":{"type":"string"},"workflow_sha256":{"type":"string"},
            "image_repository":{"type":"string"},"image_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "environment":{"const":"staging"},"github_token_ref":{"type":"string","maxLength":128}
        }
    });
    json!({"type":"object","additionalProperties":false,"required":["manifest"],"properties":{
        "manifest":{"type":"object","additionalProperties":false,
            "required":["schema_version","title","expires_in_secs","actions"],
            "properties":{
                "schema_version":{"type":"integer","enum":[1,2]},
                "title":{"type":"string","minLength":1,"maxLength":160},
                "expires_in_secs":{"type":"integer","minimum":1,"maximum":3600},
                "github_api_url":{"type":"string"},"vault_api_url":{"type":"string"},
                "actions":{"type":"array","minItems":1,"maxItems":32}
            },
            "allOf":[{
                "if":{"properties":{"schema_version":{"const":1}}},
                "then":{"properties":{"actions":{"items":secret}}},
                "else":{"properties":{"actions":{"maxItems":1,"items":release}}}
            }]
        }
    }})
}

fn task_id_schema() -> serde_json::Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["task_id"],
        "properties": {"task_id": {"type": "string", "description": "Broker-issued task ID returned by opaque_task_plan or opaque_task_plan_inference"}}
    })
}

fn task_id_params(args: &serde_json::Value) -> serde_json::Value {
    json!({"task_id": args.get("task_id").cloned().unwrap_or(json!(null))})
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
        ("opaque_task_plan_inference", "task_plan_inference"),
        ("opaque_task_plan", "task_plan"),
        ("opaque_task_run", "task_run"),
        ("opaque_task_get", "task_get"),
        ("opaque_task_list", "task_list"),
        ("opaque_task_revoke", "task_revoke"),
        ("opaque_task_reconcile", "task_reconcile"),
        ("opaque_github_set_actions_secret", "github"),
        ("opaque_github_set_codespaces_secret", "github"),
        ("opaque_github_set_dependabot_secret", "github"),
        ("opaque_github_set_org_secret", "github"),
        ("opaque_github_list_secrets", "github"),
        ("opaque_github_delete_secret", "github"),
        ("opaque_gitlab_set_ci_variable", "gitlab"),
        ("opaque_onepassword_list_vaults", "onepassword"),
        ("opaque_onepassword_list_items", "onepassword"),
        ("opaque_bitwarden_list_projects", "bitwarden"),
        ("opaque_bitwarden_list_secrets", "bitwarden"),
        ("opaque_sandbox_exec", "sandbox.exec"),
        // opaque_sandbox_list_profiles is handled client-side (no daemon call)
        ("opaque_sandbox_list_profiles", "sandbox.list_profiles"),
        // opaque_secrets_status is handled client-side (no daemon call)
        ("opaque_secrets_status", "sandbox.secrets_status"),
    ];
    MAPPING
        .iter()
        .find(|(k, _)| *k == tool_name)
        .map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_tools_are_safe() {
        // Verify no Reveal tool names leak into the tool list.
        let tools = safe_tools();
        let allowed_methods = [
            "github",
            "gitlab",
            "onepassword",
            "bitwarden",
            "sandbox.exec",
            "sandbox.list_profiles",
            "sandbox.secrets_status",
            "task_plan",
            "task_plan_inference",
            "task_run",
            "task_get",
            "task_list",
            "task_revoke",
            "task_reconcile",
        ];
        for tool in &tools {
            let method = tool_to_daemon_method(tool.name)
                .expect("all tools in safe_tools() must have daemon method mapping");
            assert!(
                allowed_methods.contains(&method),
                "tool {} maps to unexpected daemon method '{}'",
                tool.name,
                method
            );

            // Tool names must never reference Reveal operations.
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
        assert_eq!(tools.len(), 21);
    }

    #[test]
    fn task_tools_keep_approval_and_workspace_out_of_model_arguments() {
        for tool in safe_tools()
            .iter()
            .filter(|tool| tool.name.starts_with("opaque_task_"))
        {
            assert_eq!(tool.input_schema["additionalProperties"], false);
            assert!(tool.input_schema["properties"].get("approved").is_none());
            assert!(tool.input_schema["properties"].get("workspace").is_none());
            let params = (tool.build_params)(
                &json!({"task_id":"id", "approved":true, "workspace":{"repo_root":"/forged"}}),
            );
            assert!(params.get("approved").is_none());
            assert!(params.get("workspace").is_none());
        }
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

    // --- Sandbox exec tool tests ---

    #[test]
    fn sandbox_exec_tool_has_correct_schema() {
        let tools = safe_tools();
        let tool = tools
            .iter()
            .find(|t| t.name == "opaque_sandbox_exec")
            .expect("opaque_sandbox_exec tool not found");

        assert_eq!(tool.input_schema["type"], "object");

        let required = tool.input_schema["required"]
            .as_array()
            .expect("required should be an array");
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"profile"));
        assert!(required_strs.contains(&"command"));

        let properties = tool.input_schema["properties"]
            .as_object()
            .expect("properties should be an object");
        assert!(properties.contains_key("profile"));
        assert!(properties.contains_key("command"));
        assert_eq!(properties["profile"]["type"], "string");
        assert_eq!(properties["command"]["type"], "array");
        assert_eq!(properties["command"]["items"]["type"], "string");
    }

    #[test]
    fn sandbox_exec_builds_correct_params() {
        let tools = safe_tools();
        let tool = tools
            .iter()
            .find(|t| t.name == "opaque_sandbox_exec")
            .expect("opaque_sandbox_exec tool not found");

        let args = json!({
            "profile": "dev",
            "command": ["npm", "test"]
        });
        let params = (tool.build_params)(&args);

        assert_eq!(params["profile"], "dev");
        let cmd = params["command"]
            .as_array()
            .expect("command should be array");
        assert_eq!(cmd.len(), 2);
        assert_eq!(cmd[0], "npm");
        assert_eq!(cmd[1], "test");
    }

    // --- List profiles tool tests ---

    #[test]
    fn list_profiles_tool_has_correct_schema() {
        let tools = safe_tools();
        let tool = tools
            .iter()
            .find(|t| t.name == "opaque_sandbox_list_profiles")
            .expect("opaque_sandbox_list_profiles tool not found");

        assert_eq!(tool.input_schema["type"], "object");
        let properties = tool.input_schema["properties"]
            .as_object()
            .expect("properties should be an object");
        assert!(properties.is_empty());
    }

    // --- Secrets status tool tests ---

    #[test]
    fn secrets_status_tool_has_correct_schema() {
        let tools = safe_tools();
        let tool = tools
            .iter()
            .find(|t| t.name == "opaque_secrets_status")
            .expect("opaque_secrets_status tool not found");

        assert_eq!(tool.input_schema["type"], "object");

        let required = tool.input_schema["required"]
            .as_array()
            .expect("required should be an array");
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"profile"));

        let properties = tool.input_schema["properties"]
            .as_object()
            .expect("properties should be an object");
        assert!(properties.contains_key("profile"));
        assert_eq!(properties["profile"]["type"], "string");
    }

    // --- Cross-cutting tool tests ---

    #[test]
    fn all_tool_names_are_unique() {
        let tools = safe_tools();
        let mut seen = HashSet::new();
        for tool in &tools {
            assert!(seen.insert(tool.name), "duplicate tool name: {}", tool.name);
        }
    }

    #[test]
    fn all_tool_schemas_are_valid_json_schema() {
        let tools = safe_tools();
        for tool in &tools {
            assert_eq!(
                tool.input_schema["type"], "object",
                "tool {} schema must have type: object",
                tool.name
            );
            // Properties must be an object if present.
            if let Some(props) = tool.input_schema.get("properties") {
                assert!(
                    props.is_object(),
                    "tool {} properties must be an object",
                    tool.name
                );
            }
        }
    }

    // --- Profile listing function tests ---

    #[test]
    fn list_profiles_reads_directory() {
        let dir = tempfile::tempdir().unwrap();

        // Create two valid profile TOML files.
        std::fs::write(
            dir.path().join("dev.toml"),
            r#"
[profile]
name = "dev"
description = "Development sandbox"
project_dir = "/tmp/project"

[secrets]
TOKEN = "env:MY_TOKEN"
"#,
        )
        .unwrap();

        std::fs::write(
            dir.path().join("ci.toml"),
            r#"
[profile]
name = "ci"
description = "CI pipeline"
project_dir = "/tmp/ci-project"
"#,
        )
        .unwrap();

        let profiles = list_profiles(dir.path());
        assert_eq!(profiles.len(), 2);

        // Sorted by name.
        assert_eq!(profiles[0].name, "ci");
        assert_eq!(profiles[0].description.as_deref(), Some("CI pipeline"));
        assert_eq!(profiles[1].name, "dev");
        assert_eq!(
            profiles[1].description.as_deref(),
            Some("Development sandbox")
        );
    }

    #[test]
    fn list_profiles_handles_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = list_profiles(dir.path());
        assert!(profiles.is_empty());
    }

    #[test]
    fn list_profiles_skips_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();

        // Valid profile.
        std::fs::write(
            dir.path().join("good.toml"),
            r#"
[profile]
name = "good"
project_dir = "/tmp/project"
"#,
        )
        .unwrap();

        // Invalid TOML (malformed).
        std::fs::write(dir.path().join("bad.toml"), "this is not valid toml {{{}}}").unwrap();

        // Non-TOML file (should be skipped).
        std::fs::write(dir.path().join("readme.txt"), "not a profile").unwrap();

        let profiles = list_profiles(dir.path());
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "good");
    }

    #[test]
    fn list_profiles_nonexistent_dir() {
        let profiles = list_profiles(Path::new("/nonexistent/dir/that/should/not/exist"));
        assert!(profiles.is_empty());
    }

    // --- Secrets status function tests ---

    #[test]
    fn secrets_status_returns_refs_without_values() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(
            dir.path().join("myprofile.toml"),
            r#"
[profile]
name = "myprofile"
project_dir = "/tmp/project"

[secrets]
GITHUB_TOKEN = "keychain:opaque/github-token"
DB_PASSWORD = "env:DB_PASSWORD"
VAULT_SECRET = "vault:secret/data/myapp#key"
"#,
        )
        .unwrap();

        let statuses = secrets_status(dir.path(), "myprofile").unwrap();
        assert_eq!(statuses.len(), 3);

        // Sorted by env_name.
        assert_eq!(statuses[0].env_name, "DB_PASSWORD");
        assert_eq!(statuses[0].scheme, "env");
        assert_eq!(statuses[0].reference, "env:DB_PASSWORD");

        assert_eq!(statuses[1].env_name, "GITHUB_TOKEN");
        assert_eq!(statuses[1].scheme, "keychain");
        assert_eq!(statuses[1].reference, "keychain:opaque/github-token");

        assert_eq!(statuses[2].env_name, "VAULT_SECRET");
        assert_eq!(statuses[2].scheme, "vault");
        assert_eq!(statuses[2].reference, "vault:secret/data/myapp#key");
    }

    #[test]
    fn secrets_status_missing_profile() {
        let dir = tempfile::tempdir().unwrap();
        let result = secrets_status(dir.path(), "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn secrets_status_empty_secrets() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(
            dir.path().join("empty.toml"),
            r#"
[profile]
name = "empty"
project_dir = "/tmp/project"
"#,
        )
        .unwrap();

        let statuses = secrets_status(dir.path(), "empty").unwrap();
        assert!(statuses.is_empty());
    }
}
