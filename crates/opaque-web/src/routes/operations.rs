use axum::Json;
use serde_json::json;

/// Hardcoded operation registry. Same data in both live and demo modes.
pub async fn get_operations() -> Json<serde_json::Value> {
    Json(json!({
        "operations": [
            {
                "name": "github.set_actions_secret",
                "provider": "github",
                "safety": "Safe",
                "default_approval": "always",
                "description": "Set a GitHub Actions repository secret",
                "mcp_exposed": true
            },
            {
                "name": "github.set_codespaces_secret",
                "provider": "github",
                "safety": "Safe",
                "default_approval": "always",
                "description": "Set a GitHub Codespaces secret (user or repo level)",
                "mcp_exposed": true
            },
            {
                "name": "github.set_dependabot_secret",
                "provider": "github",
                "safety": "Safe",
                "default_approval": "always",
                "description": "Set a GitHub Dependabot repository secret",
                "mcp_exposed": true
            },
            {
                "name": "github.set_org_secret",
                "provider": "github",
                "safety": "Safe",
                "default_approval": "always",
                "description": "Set a GitHub Actions organization secret",
                "mcp_exposed": true
            },
            {
                "name": "github.list_secrets",
                "provider": "github",
                "safety": "Safe",
                "default_approval": "first_use",
                "description": "List GitHub secret names for a repository, environment, or org",
                "mcp_exposed": true
            },
            {
                "name": "github.delete_secret",
                "provider": "github",
                "safety": "Safe",
                "default_approval": "always",
                "description": "Delete a GitHub secret",
                "mcp_exposed": true
            },
            {
                "name": "gitlab.set_ci_variable",
                "provider": "gitlab",
                "safety": "Safe",
                "default_approval": "always",
                "description": "Set a GitLab CI/CD variable for a project",
                "mcp_exposed": true
            },
            {
                "name": "onepassword.list_vaults",
                "provider": "1password",
                "safety": "Safe",
                "default_approval": "first_use",
                "description": "List available 1Password vaults",
                "mcp_exposed": true
            },
            {
                "name": "onepassword.list_items",
                "provider": "1password",
                "safety": "Safe",
                "default_approval": "first_use",
                "description": "List items in a 1Password vault",
                "mcp_exposed": true
            },
            {
                "name": "onepassword.read_field",
                "provider": "1password",
                "safety": "Reveal",
                "default_approval": "always",
                "description": "Read a single field value from a 1Password item",
                "mcp_exposed": false
            },
            {
                "name": "bitwarden.list_projects",
                "provider": "bitwarden",
                "safety": "Safe",
                "default_approval": "first_use",
                "description": "List available Bitwarden Secrets Manager projects",
                "mcp_exposed": true
            },
            {
                "name": "bitwarden.list_secrets",
                "provider": "bitwarden",
                "safety": "Safe",
                "default_approval": "first_use",
                "description": "List secrets in a Bitwarden Secrets Manager project",
                "mcp_exposed": true
            },
            {
                "name": "bitwarden.read_secret",
                "provider": "bitwarden",
                "safety": "Reveal",
                "default_approval": "always",
                "description": "Read a secret value from Bitwarden Secrets Manager",
                "mcp_exposed": false
            },
            {
                "name": "sandbox.exec",
                "provider": "sandbox",
                "safety": "SensitiveOutput",
                "default_approval": "always",
                "description": "Execute a command in a sandboxed environment",
                "mcp_exposed": false
            },
            {
                "name": "test.noop",
                "provider": "test",
                "safety": "Safe",
                "default_approval": "first_use",
                "description": "No-op test operation for pipeline validation",
                "mcp_exposed": false
            }
        ]
    }))
}
