//! Shared routing metadata for the shipped MCP adapter and daemon inventory.
//! Exposure describes a direct tool route, never authorization for a request.

/// (tool name, adapter method, direct enclave operation). Task workflows and
/// client-local introspection have no single direct enclave operation.
pub const MCP_ROUTES: &[(&str, &str, Option<&str>)] = &[
    ("opaque_task_plan_ssh", "task_plan_ssh", None),
    ("opaque_task_plan_inference", "task_plan_inference", None),
    ("opaque_task_plan", "task_plan", None),
    ("opaque_task_run", "task_run", None),
    ("opaque_task_get", "task_get", None),
    ("opaque_task_list", "task_list", None),
    ("opaque_task_revoke", "task_revoke", None),
    ("opaque_task_reconcile", "task_reconcile", None),
    (
        "opaque_github_set_actions_secret",
        "github",
        Some("github.set_actions_secret"),
    ),
    (
        "opaque_github_set_codespaces_secret",
        "github",
        Some("github.set_codespaces_secret"),
    ),
    (
        "opaque_github_set_dependabot_secret",
        "github",
        Some("github.set_dependabot_secret"),
    ),
    (
        "opaque_github_set_org_secret",
        "github",
        Some("github.set_org_secret"),
    ),
    (
        "opaque_github_list_secrets",
        "github",
        Some("github.list_secrets"),
    ),
    (
        "opaque_github_delete_secret",
        "github",
        Some("github.delete_secret"),
    ),
    (
        "opaque_gitlab_set_ci_variable",
        "gitlab",
        Some("gitlab.set_ci_variable"),
    ),
    (
        "opaque_onepassword_list_vaults",
        "onepassword",
        Some("onepassword.list_vaults"),
    ),
    (
        "opaque_onepassword_list_items",
        "onepassword",
        Some("onepassword.list_items"),
    ),
    (
        "opaque_bitwarden_list_projects",
        "bitwarden",
        Some("bitwarden.list_projects"),
    ),
    (
        "opaque_bitwarden_list_secrets",
        "bitwarden",
        Some("bitwarden.list_secrets"),
    ),
    ("opaque_sandbox_exec", "sandbox.exec", Some("sandbox.exec")),
    (
        "opaque_sandbox_list_profiles",
        "sandbox.list_profiles",
        None,
    ),
    ("opaque_secrets_status", "sandbox.secrets_status", None),
];

pub fn tool_to_daemon_method(tool: &str) -> Option<&'static str> {
    MCP_ROUTES
        .iter()
        .find(|route| route.0 == tool)
        .map(|route| route.1)
}

pub fn mcp_exposes(operation: &str) -> bool {
    MCP_ROUTES.iter().any(|route| route.2 == Some(operation))
}
