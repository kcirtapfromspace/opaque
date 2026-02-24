//! AWS secret resolver.
//!
//! Resolves `aws-sm:<secret-name-or-arn>` references via AWS Secrets Manager
//! and `aws-ssm:<parameter-name>` references via SSM Parameter Store.
//!
//! Credentials are resolved via the standard AWS credential chain
//! (environment variables or CLI).
//!
//! The resolved secret value is held in a `SecretValue` that is
//! automatically zeroed on drop and optionally `mlock`'d.

use crate::sandbox::resolve::{ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::{AwsCredentials, AwsSecretsManagerClient};

/// Resolves `aws-sm:<secret-name-or-arn>` and `aws-ssm:<parameter-name>` references.
pub struct AwsResolver {
    client: AwsSecretsManagerClient,
}

impl std::fmt::Debug for AwsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsResolver")
            .field("region", &self.client.region())
            .finish()
    }
}

/// Parsed AWS ref: either a Secrets Manager secret or an SSM parameter.
#[derive(Debug, PartialEq)]
enum AwsRef<'a> {
    /// AWS Secrets Manager secret by name or ARN.
    SecretsManager(&'a str),
    /// SSM Parameter Store parameter by name.
    SsmParameter(&'a str),
}

impl AwsResolver {
    /// Create a new resolver with the given AWS client.
    pub fn new(client: AwsSecretsManagerClient) -> Self {
        Self { client }
    }

    /// Parse an `aws-sm:` or `aws-ssm:` ref.
    ///
    /// Formats:
    /// - `aws-sm:<secret-name-or-arn>` -- AWS Secrets Manager
    /// - `aws-ssm:<parameter-name>` -- SSM Parameter Store
    fn parse_ref(ref_str: &str) -> Result<AwsRef<'_>, ResolveError> {
        if let Some(rest) = ref_str.strip_prefix("aws-sm:") {
            if rest.is_empty() {
                return Err(ResolveError::AwsError(
                    ref_str.to_owned(),
                    "empty ref after 'aws-sm:' prefix".into(),
                ));
            }
            Ok(AwsRef::SecretsManager(rest))
        } else if let Some(rest) = ref_str.strip_prefix("aws-ssm:") {
            if rest.is_empty() {
                return Err(ResolveError::AwsError(
                    ref_str.to_owned(),
                    "empty ref after 'aws-ssm:' prefix".into(),
                ));
            }
            Ok(AwsRef::SsmParameter(rest))
        } else {
            Err(ResolveError::UnknownScheme(ref_str.to_owned()))
        }
    }
}

impl SecretResolver for AwsResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        // Resolve AWS credentials from environment.
        let credentials = AwsCredentials::from_env().map_err(|e| {
            ResolveError::AwsError(
                ref_str.to_owned(),
                format!("failed to resolve AWS credentials: {e}"),
            )
        })?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                match parsed {
                    AwsRef::SecretsManager(secret_id) => {
                        let sv = self
                            .client
                            .get_secret_value(&credentials, secret_id)
                            .await
                            .map_err(|e| format!("secret fetch failed: {e}"))?;

                        sv.secret_string
                            .ok_or_else(|| format!("secret '{secret_id}' has no SecretString"))
                    }
                    AwsRef::SsmParameter(name) => {
                        let param = self
                            .client
                            .get_parameter(&credentials, name)
                            .await
                            .map_err(|e| format!("parameter fetch failed: {e}"))?;

                        param
                            .value
                            .ok_or_else(|| format!("parameter '{name}' has no value"))
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
        let result = AwsResolver::parse_ref("aws-sm:prod/db-password").unwrap();
        assert_eq!(result, AwsRef::SecretsManager("prod/db-password"));
    }

    #[test]
    fn parse_ref_secrets_manager_arn() {
        let result = AwsResolver::parse_ref(
            "aws-sm:arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db-password",
        )
        .unwrap();
        assert_eq!(
            result,
            AwsRef::SecretsManager(
                "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db-password"
            )
        );
    }

    #[test]
    fn parse_ref_ssm_parameter() {
        let result = AwsResolver::parse_ref("aws-ssm:/app/config/db-url").unwrap();
        assert_eq!(result, AwsRef::SsmParameter("/app/config/db-url"));
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
    fn parse_ref_bitwarden_scheme_rejected() {
        let result = AwsResolver::parse_ref("bitwarden:some-id");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_sm_prefix() {
        let result = AwsResolver::parse_ref("aws-sm:");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResolveError::AwsError(..)));
    }

    #[test]
    fn parse_ref_empty_after_ssm_prefix() {
        let result = AwsResolver::parse_ref("aws-ssm:");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResolveError::AwsError(..)));
    }

    #[test]
    fn parse_ref_sm_with_slashes() {
        let result = AwsResolver::parse_ref("aws-sm:prod/team/db-password").unwrap();
        assert_eq!(result, AwsRef::SecretsManager("prod/team/db-password"));
    }

    #[test]
    fn parse_ref_ssm_with_nested_path() {
        let result = AwsResolver::parse_ref("aws-ssm:/prod/team/config/db-url").unwrap();
        assert_eq!(result, AwsRef::SsmParameter("/prod/team/config/db-url"));
    }

    #[test]
    fn resolver_debug() {
        let client = AwsSecretsManagerClient::with_urls(
            "http://localhost:4566",
            "http://localhost:4566",
            "us-east-1",
        )
        .unwrap();
        let resolver = AwsResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("AwsResolver"));
        assert!(debug.contains("us-east-1"));
    }
}
