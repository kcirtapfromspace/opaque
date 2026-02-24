//! Infisical secret resolver.
//!
//! Resolves `infisical:<project-id>/<environment>/<secret-name>` references
//! using the Infisical REST API.
//!
//! The service token is itself resolved via the base resolver (env + keychain
//! only) to prevent resolution cycles.

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::InfisicalClient;

/// Default keychain ref for the Infisical service token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/infisical-token";

/// Environment variable to override the default Infisical token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_INFISICAL_TOKEN_REF";

/// Resolves `infisical:<project-id>/<environment>/<secret-name>` secret references.
pub struct InfisicalResolver {
    client: InfisicalClient,
    token_ref: String,
}

impl std::fmt::Debug for InfisicalResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InfisicalResolver")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

/// Parsed Infisical ref.
#[derive(Debug, PartialEq)]
struct InfisicalRef<'a> {
    project_id: &'a str,
    environment: &'a str,
    secret_name: &'a str,
}

impl InfisicalResolver {
    /// Create a new resolver with the given Infisical client.
    pub fn new(client: InfisicalClient) -> Self {
        let token_ref =
            std::env::var(TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Self { client, token_ref }
    }

    /// Parse an `infisical:` ref into (project_id, environment, secret_name).
    ///
    /// Format: `infisical:<project-id>/<environment>/<secret-name>`
    fn parse_ref(ref_str: &str) -> Result<InfisicalRef<'_>, ResolveError> {
        let rest = ref_str
            .strip_prefix("infisical:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::InfisicalError(
                ref_str.to_owned(),
                "empty ref after 'infisical:' prefix".into(),
            ));
        }

        // Split into exactly 3 parts: project-id/environment/secret-name
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() != 3 {
            return Err(ResolveError::InfisicalError(
                ref_str.to_owned(),
                "expected format infisical:<project-id>/<environment>/<secret-name>".into(),
            ));
        }

        let project_id = parts[0];
        let environment = parts[1];
        let secret_name = parts[2];

        if project_id.is_empty() || environment.is_empty() || secret_name.is_empty() {
            return Err(ResolveError::InfisicalError(
                ref_str.to_owned(),
                "project ID, environment, and secret name must be non-empty".into(),
            ));
        }

        Ok(InfisicalRef {
            project_id,
            environment,
            secret_name,
        })
    }
}

impl SecretResolver for InfisicalResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        // Resolve the service token via base resolvers only (env + keychain)
        // to prevent cycles.
        let base = BaseResolver::new();
        let token_value = base.resolve(&self.token_ref).map_err(|e| {
            ResolveError::InfisicalError(
                ref_str.to_owned(),
                format!("failed to resolve service token: {e}"),
            )
        })?;
        let token = token_value.as_str().ok_or_else(|| {
            ResolveError::InfisicalError(
                ref_str.to_owned(),
                "service token is not valid UTF-8".into(),
            )
        })?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                let secret = self
                    .client
                    .get_secret(
                        token,
                        parsed.project_id,
                        parsed.environment,
                        parsed.secret_name,
                    )
                    .await
                    .map_err(|e| format!("secret fetch failed: {e}"))?;

                Ok::<String, String>(secret.value)
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::InfisicalError(ref_str.to_owned(), msg)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ref_valid() {
        let result =
            InfisicalResolver::parse_ref("infisical:proj-123/production/DB_PASSWORD").unwrap();
        assert_eq!(
            result,
            InfisicalRef {
                project_id: "proj-123",
                environment: "production",
                secret_name: "DB_PASSWORD",
            }
        );
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = InfisicalResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_prefix() {
        let result = InfisicalResolver::parse_ref("infisical:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_missing_parts() {
        // Only project_id, no environment or secret
        let result = InfisicalResolver::parse_ref("infisical:project");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("expected format"));
    }

    #[test]
    fn parse_ref_two_parts_only() {
        // project/env but no secret name
        let result = InfisicalResolver::parse_ref("infisical:project/env");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("expected format"));
    }

    #[test]
    fn parse_ref_empty_project() {
        let result = InfisicalResolver::parse_ref("infisical:/env/secret");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_environment() {
        let result = InfisicalResolver::parse_ref("infisical:project//secret");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_secret() {
        let result = InfisicalResolver::parse_ref("infisical:project/env/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_with_uuid_project_id() {
        let result = InfisicalResolver::parse_ref(
            "infisical:550e8400-e29b-41d4-a716-446655440000/staging/API_KEY",
        )
        .unwrap();
        assert_eq!(
            result,
            InfisicalRef {
                project_id: "550e8400-e29b-41d4-a716-446655440000",
                environment: "staging",
                secret_name: "API_KEY",
            }
        );
    }

    #[test]
    fn resolver_debug() {
        let client = InfisicalClient::new("http://localhost:8080").unwrap();
        let resolver = InfisicalResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("InfisicalResolver"));
    }
}
