//! Doppler secret resolver.
//!
//! Resolves `doppler:<project>/<config>/<secret-name>` references using
//! the Doppler REST API.
//!
//! The service token is itself resolved via the base resolver (env + keychain
//! only) to prevent resolution cycles.

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::DopplerClient;

/// Default keychain ref for the Doppler service token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/doppler-token";

/// Environment variable to override the default Doppler token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_DOPPLER_TOKEN_REF";

/// Resolves `doppler:<project>/<config>/<secret-name>` secret references.
pub struct DopplerResolver {
    client: DopplerClient,
    token_ref: String,
}

impl std::fmt::Debug for DopplerResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DopplerResolver")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

/// Parsed Doppler ref.
#[derive(Debug, PartialEq)]
struct DopplerRef<'a> {
    project: &'a str,
    config: &'a str,
    secret_name: &'a str,
}

impl DopplerResolver {
    /// Create a new resolver with the given Doppler client.
    pub fn new(client: DopplerClient) -> Self {
        let token_ref =
            std::env::var(TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Self { client, token_ref }
    }

    /// Parse a `doppler:` ref into (project, config, secret_name).
    ///
    /// Format: `doppler:<project>/<config>/<secret-name>`
    fn parse_ref(ref_str: &str) -> Result<DopplerRef<'_>, ResolveError> {
        let rest = ref_str
            .strip_prefix("doppler:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::DopplerError(
                ref_str.to_owned(),
                "empty ref after 'doppler:' prefix".into(),
            ));
        }

        // Split into exactly 3 parts: project/config/secret-name
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() != 3 {
            return Err(ResolveError::DopplerError(
                ref_str.to_owned(),
                "expected format doppler:<project>/<config>/<secret-name>".into(),
            ));
        }

        let project = parts[0];
        let config = parts[1];
        let secret_name = parts[2];

        if project.is_empty() || config.is_empty() || secret_name.is_empty() {
            return Err(ResolveError::DopplerError(
                ref_str.to_owned(),
                "project, config, and secret name must be non-empty".into(),
            ));
        }

        Ok(DopplerRef {
            project,
            config,
            secret_name,
        })
    }
}

impl SecretResolver for DopplerResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        // Resolve the service token via base resolvers only (env + keychain)
        // to prevent cycles.
        let base = BaseResolver::new();
        let token_value = base.resolve(&self.token_ref).map_err(|e| {
            ResolveError::DopplerError(
                ref_str.to_owned(),
                format!("failed to resolve service token: {e}"),
            )
        })?;
        let token = token_value.as_str().ok_or_else(|| {
            ResolveError::DopplerError(
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
                    .get_secret(token, parsed.project, parsed.config, parsed.secret_name)
                    .await
                    .map_err(|e| format!("secret fetch failed: {e}"))?;

                secret.value.computed.or(secret.value.raw).ok_or_else(|| {
                    format!(
                        "secret '{}' in project '{}' config '{}' has no value",
                        parsed.secret_name, parsed.project, parsed.config
                    )
                })
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::DopplerError(ref_str.to_owned(), msg)),
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
            DopplerResolver::parse_ref("doppler:my-project/production/DB_PASSWORD").unwrap();
        assert_eq!(
            result,
            DopplerRef {
                project: "my-project",
                config: "production",
                secret_name: "DB_PASSWORD",
            }
        );
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = DopplerResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_prefix() {
        let result = DopplerResolver::parse_ref("doppler:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_missing_parts() {
        // Only project, no config or secret
        let result = DopplerResolver::parse_ref("doppler:project");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("expected format"));
    }

    #[test]
    fn parse_ref_two_parts_only() {
        // project/config but no secret name
        let result = DopplerResolver::parse_ref("doppler:project/config");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("expected format"));
    }

    #[test]
    fn parse_ref_empty_project() {
        let result = DopplerResolver::parse_ref("doppler:/config/secret");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_config() {
        let result = DopplerResolver::parse_ref("doppler:project//secret");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_secret() {
        let result = DopplerResolver::parse_ref("doppler:project/config/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_with_hyphens_and_underscores() {
        let result =
            DopplerResolver::parse_ref("doppler:my-project/my_config/MY_SECRET_KEY").unwrap();
        assert_eq!(
            result,
            DopplerRef {
                project: "my-project",
                config: "my_config",
                secret_name: "MY_SECRET_KEY",
            }
        );
    }

    #[test]
    fn resolver_debug() {
        let client = DopplerClient::new("http://localhost:8080").unwrap();
        let resolver = DopplerResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("DopplerResolver"));
    }
}
