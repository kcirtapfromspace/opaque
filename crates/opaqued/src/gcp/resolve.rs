//! GCP Secret Manager secret resolver.
//!
//! Resolves `gcp:<project>/<secret>` or `gcp:<project>/<secret>/<version>`
//! references using the GCP Secret Manager REST API.
//!
//! Default version is `latest` when not specified.
//!
//! The access token is obtained via the client's `get_access_token()` method,
//! which supports both direct token and service account JWT authentication.

use base64::Engine;

use crate::sandbox::resolve::{ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::GcpSecretManagerClient;

/// Resolves `gcp:<project>/<secret>` or `gcp:<project>/<secret>/<version>` secret references.
pub struct GcpResolver {
    client: GcpSecretManagerClient,
}

impl std::fmt::Debug for GcpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpResolver").finish()
    }
}

/// Parsed GCP secret ref.
#[derive(Debug, PartialEq)]
struct GcpRef<'a> {
    project: &'a str,
    secret: &'a str,
    version: &'a str,
}

impl GcpResolver {
    /// Create a new resolver with the given GCP Secret Manager client.
    pub fn new(client: GcpSecretManagerClient) -> Self {
        Self { client }
    }

    /// Parse a `gcp:` ref into project, secret, and optional version.
    ///
    /// Formats:
    /// - `gcp:<project>/<secret>` -- uses `latest` version
    /// - `gcp:<project>/<secret>/<version>` -- explicit version
    fn parse_ref(ref_str: &str) -> Result<GcpRef<'_>, ResolveError> {
        let rest = ref_str
            .strip_prefix("gcp:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::GcpError(
                ref_str.to_owned(),
                "empty ref after 'gcp:' prefix".into(),
            ));
        }

        let parts: Vec<&str> = rest.splitn(3, '/').collect();

        match parts.len() {
            1 => {
                // Just project, no secret
                Err(ResolveError::GcpError(
                    ref_str.to_owned(),
                    "expected format gcp:<project>/<secret> or gcp:<project>/<secret>/<version>"
                        .into(),
                ))
            }
            2 => {
                let project = parts[0];
                let secret = parts[1];
                if project.is_empty() || secret.is_empty() {
                    return Err(ResolveError::GcpError(
                        ref_str.to_owned(),
                        "project and secret names must be non-empty".into(),
                    ));
                }
                Ok(GcpRef {
                    project,
                    secret,
                    version: "latest",
                })
            }
            3 => {
                let project = parts[0];
                let secret = parts[1];
                let version = parts[2];
                if project.is_empty() || secret.is_empty() || version.is_empty() {
                    return Err(ResolveError::GcpError(
                        ref_str.to_owned(),
                        "project, secret, and version names must be non-empty".into(),
                    ));
                }
                Ok(GcpRef {
                    project,
                    secret,
                    version,
                })
            }
            _ => unreachable!("splitn(3) produces at most 3 parts"),
        }
    }
}

impl SecretResolver for GcpResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                let token = self
                    .client
                    .get_access_token()
                    .await
                    .map_err(|e| format!("GCP auth failed: {e}"))?;

                let resp = self
                    .client
                    .access_secret_version(&token, parsed.project, parsed.secret, parsed.version)
                    .await
                    .map_err(|e| format!("secret access failed: {e}"))?;

                // Decode base64 payload.
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&resp.payload.data)
                    .map_err(|e| format!("failed to decode secret payload: {e}"))?;

                Ok(decoded)
            })
        });

        match result {
            Ok(data) => Ok(SecretValue::new(data)),
            Err(msg) => Err(ResolveError::GcpError(ref_str.to_owned(), msg)),
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
    fn parse_ref_project_secret() {
        let result = GcpResolver::parse_ref("gcp:my-project/my-secret").unwrap();
        assert_eq!(
            result,
            GcpRef {
                project: "my-project",
                secret: "my-secret",
                version: "latest",
            }
        );
    }

    #[test]
    fn parse_ref_project_secret_version() {
        let result = GcpResolver::parse_ref("gcp:my-project/my-secret/3").unwrap();
        assert_eq!(
            result,
            GcpRef {
                project: "my-project",
                secret: "my-secret",
                version: "3",
            }
        );
    }

    #[test]
    fn parse_ref_latest_is_default() {
        let result = GcpResolver::parse_ref("gcp:proj/sec").unwrap();
        assert_eq!(result.version, "latest");
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = GcpResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_prefix() {
        let result = GcpResolver::parse_ref("gcp:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_only_project() {
        let result = GcpResolver::parse_ref("gcp:my-project");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::GcpError(..)));
    }

    #[test]
    fn parse_ref_empty_project() {
        let result = GcpResolver::parse_ref("gcp:/secret");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_secret() {
        let result = GcpResolver::parse_ref("gcp:project/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_version() {
        let result = GcpResolver::parse_ref("gcp:project/secret/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_with_numeric_version() {
        let result = GcpResolver::parse_ref("gcp:my-project/db-pass/42").unwrap();
        assert_eq!(result.version, "42");
    }

    #[test]
    fn parse_ref_version_latest_explicit() {
        let result = GcpResolver::parse_ref("gcp:my-project/db-pass/latest").unwrap();
        assert_eq!(result.version, "latest");
    }

    #[test]
    fn resolver_debug() {
        let client = GcpSecretManagerClient::new("http://localhost:8080").unwrap();
        let resolver = GcpResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("GcpResolver"));
    }
}
