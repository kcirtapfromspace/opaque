//! Bitwarden Secrets Manager secret resolver.
//!
//! Resolves `bitwarden:<secret-id>` or `bitwarden:<project>/<secret-key>`
//! references using the Bitwarden Secrets Manager REST API.
//!
//! For `<secret-id>` format, the secret is fetched directly by UUID.
//! For `<project>/<secret-key>` format, the project is resolved by name,
//! then the secret is found by key within that project.
//!
//! The access token is itself resolved via the base resolver (env + keychain
//! only) to prevent resolution cycles.

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::BitwardenClient;

/// Default keychain ref for the Bitwarden access token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/bitwarden-token";

/// Environment variable to override the default Bitwarden token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_BITWARDEN_TOKEN_REF";

/// Resolves `bitwarden:<secret-id>` or `bitwarden:<project>/<secret-key>` secret references.
pub struct BitwardenResolver {
    client: BitwardenClient,
    token_ref: String,
}

impl std::fmt::Debug for BitwardenResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitwardenResolver")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

/// Parsed Bitwarden ref: either a direct secret ID or a project/key pair.
#[derive(Debug, PartialEq)]
enum BitwardenRef<'a> {
    /// Direct secret ID (UUID).
    SecretId(&'a str),
    /// Project name + secret key.
    ProjectKey { project: &'a str, key: &'a str },
}

impl BitwardenResolver {
    /// Create a new resolver with the given Bitwarden client.
    pub fn new(client: BitwardenClient) -> Self {
        let token_ref = std::env::var(TOKEN_REF_ENV)
            .unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Self { client, token_ref }
    }

    /// Parse a `bitwarden:` ref into either a secret ID or (project, key).
    ///
    /// Formats:
    /// - `bitwarden:<secret-id>` — direct UUID lookup
    /// - `bitwarden:<project>/<secret-key>` — project + key lookup
    fn parse_ref(ref_str: &str) -> Result<BitwardenRef<'_>, ResolveError> {
        let rest = ref_str
            .strip_prefix("bitwarden:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::BitwardenError(
                ref_str.to_owned(),
                "empty ref after 'bitwarden:' prefix".into(),
            ));
        }

        if let Some((project, key)) = rest.split_once('/') {
            // project/key format
            if project.is_empty() || key.is_empty() {
                return Err(ResolveError::BitwardenError(
                    ref_str.to_owned(),
                    "project and key names must be non-empty".into(),
                ));
            }
            Ok(BitwardenRef::ProjectKey { project, key })
        } else {
            // Direct secret ID
            Ok(BitwardenRef::SecretId(rest))
        }
    }
}

impl SecretResolver for BitwardenResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        // Resolve the access token via base resolvers only (env + keychain)
        // to prevent cycles.
        let base = BaseResolver::new();
        let token_value = base.resolve(&self.token_ref).map_err(|e| {
            ResolveError::BitwardenError(
                ref_str.to_owned(),
                format!("failed to resolve access token: {e}"),
            )
        })?;
        let token = token_value.as_str().ok_or_else(|| {
            ResolveError::BitwardenError(
                ref_str.to_owned(),
                "access token is not valid UTF-8".into(),
            )
        })?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                match parsed {
                    BitwardenRef::SecretId(secret_id) => {
                        let secret = self
                            .client
                            .get_secret(token, secret_id)
                            .await
                            .map_err(|e| format!("secret fetch failed: {e}"))?;

                        secret.value.ok_or_else(|| {
                            format!("secret '{secret_id}' has no value")
                        })
                    }
                    BitwardenRef::ProjectKey { project, key } => {
                        let project_id = self
                            .client
                            .find_project_by_name(token, project)
                            .await
                            .map_err(|e| format!("project lookup failed: {e}"))?;

                        let secret_id = self
                            .client
                            .find_secret_by_key(token, &project_id, key)
                            .await
                            .map_err(|e| format!("secret lookup failed: {e}"))?;

                        let secret = self
                            .client
                            .get_secret(token, &secret_id)
                            .await
                            .map_err(|e| format!("secret fetch failed: {e}"))?;

                        secret.value.ok_or_else(|| {
                            format!(
                                "secret '{key}' in project '{project}' has no value"
                            )
                        })
                    }
                }
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::BitwardenError(ref_str.to_owned(), msg)),
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
    fn parse_ref_secret_id() {
        let result =
            BitwardenResolver::parse_ref("bitwarden:550e8400-e29b-41d4-a716-446655440000")
                .unwrap();
        assert_eq!(
            result,
            BitwardenRef::SecretId("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn parse_ref_project_key() {
        let result =
            BitwardenResolver::parse_ref("bitwarden:Production/DB_PASSWORD").unwrap();
        assert_eq!(
            result,
            BitwardenRef::ProjectKey {
                project: "Production",
                key: "DB_PASSWORD"
            }
        );
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = BitwardenResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_prefix() {
        let result = BitwardenResolver::parse_ref("bitwarden:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_project() {
        let result = BitwardenResolver::parse_ref("bitwarden:/key");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_key() {
        let result = BitwardenResolver::parse_ref("bitwarden:project/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_project_with_spaces() {
        let result =
            BitwardenResolver::parse_ref("bitwarden:My Project/My Secret").unwrap();
        assert_eq!(
            result,
            BitwardenRef::ProjectKey {
                project: "My Project",
                key: "My Secret"
            }
        );
    }

    #[test]
    fn resolver_debug() {
        let client = BitwardenClient::new("http://localhost:8080");
        let resolver = BitwardenResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("BitwardenResolver"));
    }
}
