//! AWS secret resolver.
//!
//! Resolves `aws:<secret-name>` references using the AWS Secrets Manager
//! REST API, or `aws:ssm:<parameter-name>` via SSM Parameter Store.
//!
//! Credentials (access key / secret key) are resolved via the base resolver
//! (env + keychain only) to prevent resolution cycles.

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::AwsClient;

/// Default keychain ref for the AWS access key ID.
const DEFAULT_ACCESS_KEY_REF: &str = "keychain:opaque/aws-access-key-id";

/// Default keychain ref for the AWS secret access key.
const DEFAULT_SECRET_KEY_REF: &str = "keychain:opaque/aws-secret-access-key";

/// Environment variable to override the AWS access key ref.
const ACCESS_KEY_REF_ENV: &str = "OPAQUE_AWS_ACCESS_KEY_REF";

/// Environment variable to override the AWS secret key ref.
const SECRET_KEY_REF_ENV: &str = "OPAQUE_AWS_SECRET_KEY_REF";

/// Parsed AWS ref: either a Secrets Manager secret or an SSM parameter.
#[derive(Debug, PartialEq)]
enum AwsRef<'a> {
    /// Secrets Manager: `aws:<secret-name>`
    SecretsManager(&'a str),
    /// SSM Parameter Store: `aws:ssm:<parameter-name>`
    SsmParameter(&'a str),
}

/// Resolves `aws:<secret-name>` and `aws:ssm:<parameter-name>` secret references.
pub struct AwsResolver {
    client: AwsClient,
    access_key_ref: String,
    secret_key_ref: String,
}

impl std::fmt::Debug for AwsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsResolver")
            .field("access_key_ref", &self.access_key_ref)
            .field("secret_key_ref", &self.secret_key_ref)
            .finish()
    }
}

impl AwsResolver {
    /// Create a new resolver with the given AWS client.
    pub fn new(client: AwsClient) -> Self {
        let access_key_ref =
            std::env::var(ACCESS_KEY_REF_ENV).unwrap_or_else(|_| DEFAULT_ACCESS_KEY_REF.to_owned());
        let secret_key_ref =
            std::env::var(SECRET_KEY_REF_ENV).unwrap_or_else(|_| DEFAULT_SECRET_KEY_REF.to_owned());
        Self {
            client,
            access_key_ref,
            secret_key_ref,
        }
    }

    /// Parse an `aws:` ref.
    ///
    /// Formats:
    /// - `aws:<secret-name>` — Secrets Manager lookup
    /// - `aws:ssm:<parameter-name>` — SSM Parameter Store lookup
    fn parse_ref(ref_str: &str) -> Result<AwsRef<'_>, ResolveError> {
        let rest = ref_str
            .strip_prefix("aws:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::AwsError(
                ref_str.to_owned(),
                "empty ref after 'aws:' prefix".into(),
            ));
        }

        if let Some(param_name) = rest.strip_prefix("ssm:") {
            if param_name.is_empty() {
                return Err(ResolveError::AwsError(
                    ref_str.to_owned(),
                    "empty parameter name after 'aws:ssm:' prefix".into(),
                ));
            }
            Ok(AwsRef::SsmParameter(param_name))
        } else {
            Ok(AwsRef::SecretsManager(rest))
        }
    }
}

impl SecretResolver for AwsResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        // Resolve AWS credentials via base resolvers only (env + keychain).
        let base = BaseResolver::new();
        let access_key_value = base.resolve(&self.access_key_ref).map_err(|e| {
            ResolveError::AwsError(
                ref_str.to_owned(),
                format!("failed to resolve AWS access key: {e}"),
            )
        })?;
        let access_key = access_key_value.as_str().ok_or_else(|| {
            ResolveError::AwsError(
                ref_str.to_owned(),
                "AWS access key is not valid UTF-8".into(),
            )
        })?;

        let secret_key_value = base.resolve(&self.secret_key_ref).map_err(|e| {
            ResolveError::AwsError(
                ref_str.to_owned(),
                format!("failed to resolve AWS secret key: {e}"),
            )
        })?;
        let secret_key = secret_key_value.as_str().ok_or_else(|| {
            ResolveError::AwsError(
                ref_str.to_owned(),
                "AWS secret key is not valid UTF-8".into(),
            )
        })?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                match parsed {
                    AwsRef::SecretsManager(secret_name) => {
                        let sv = self
                            .client
                            .get_secret_value(access_key, secret_key, secret_name)
                            .await
                            .map_err(|e| format!("secret fetch failed: {e}"))?;

                        sv.secret_string
                            .ok_or_else(|| format!("secret '{secret_name}' has no string value"))
                    }
                    AwsRef::SsmParameter(param_name) => {
                        let param = self
                            .client
                            .get_parameter(access_key, secret_key, param_name, true)
                            .await
                            .map_err(|e| format!("parameter fetch failed: {e}"))?;

                        param
                            .value
                            .ok_or_else(|| format!("parameter '{param_name}' has no value"))
                    }
                }
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::AwsError(ref_str.to_owned(), msg)),
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
    fn parse_ref_secrets_manager() {
        let result = AwsResolver::parse_ref("aws:prod/db-password").unwrap();
        assert_eq!(result, AwsRef::SecretsManager("prod/db-password"));
    }

    #[test]
    fn parse_ref_ssm_parameter() {
        let result = AwsResolver::parse_ref("aws:ssm:/myapp/config/key").unwrap();
        assert_eq!(result, AwsRef::SsmParameter("/myapp/config/key"));
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = AwsResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_prefix() {
        let result = AwsResolver::parse_ref("aws:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_ssm_name() {
        let result = AwsResolver::parse_ref("aws:ssm:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_secret_with_slashes() {
        let result = AwsResolver::parse_ref("aws:prod/team/db").unwrap();
        assert_eq!(result, AwsRef::SecretsManager("prod/team/db"));
    }

    #[test]
    fn parse_ref_ssm_with_deep_path() {
        let result = AwsResolver::parse_ref("aws:ssm:/a/b/c/d").unwrap();
        assert_eq!(result, AwsRef::SsmParameter("/a/b/c/d"));
    }

    #[test]
    fn resolver_debug() {
        let client = AwsClient::new_single("http://localhost:8080");
        let resolver = AwsResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("AwsResolver"));
    }
}
