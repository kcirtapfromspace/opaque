//! Azure Key Vault secret resolver.
//!
//! Resolves `azure:<vault-name>/<secret-name>` or
//! `azure:<vault-name>/<secret-name>/<version>` references using the
//! Azure Key Vault REST API.
//!
//! The Azure AD credentials (tenant ID, client ID, client secret) are
//! resolved via environment variables. The vault URL is constructed from
//! the vault name or overridden via `OPAQUE_AZURE_VAULT_URL`.

use crate::sandbox::resolve::{ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::{
    AZURE_CLIENT_ID_ENV, AZURE_CLIENT_SECRET_ENV, AZURE_TENANT_ID_ENV, AZURE_VAULT_URL_ENV,
    AzureKeyVaultClient,
};

/// Resolves `azure:<vault>/<secret>` or `azure:<vault>/<secret>/<version>` secret references.
pub struct AzureResolver;

impl std::fmt::Debug for AzureResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureResolver").finish()
    }
}

/// Parsed Azure Key Vault ref.
#[derive(Debug, PartialEq)]
enum AzureRef<'a> {
    /// `azure:<vault>/<secret>` — latest version.
    Latest {
        vault_name: &'a str,
        secret_name: &'a str,
    },
    /// `azure:<vault>/<secret>/<version>` — specific version.
    Versioned {
        vault_name: &'a str,
        secret_name: &'a str,
        version: &'a str,
    },
}

impl AzureResolver {
    /// Parse an `azure:` ref into its components.
    ///
    /// Formats:
    /// - `azure:<vault-name>/<secret-name>` — latest version
    /// - `azure:<vault-name>/<secret-name>/<version>` — specific version
    fn parse_ref(ref_str: &str) -> Result<AzureRef<'_>, ResolveError> {
        let rest = ref_str
            .strip_prefix("azure:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::AzureError(
                ref_str.to_owned(),
                "empty ref after 'azure:' prefix".into(),
            ));
        }

        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        match parts.len() {
            1 => {
                // No slash at all — missing secret name.
                Err(ResolveError::AzureError(
                    ref_str.to_owned(),
                    "expected format azure:<vault>/<secret> or azure:<vault>/<secret>/<version>"
                        .into(),
                ))
            }
            2 => {
                let vault_name = parts[0];
                let secret_name = parts[1];

                if vault_name.is_empty() || secret_name.is_empty() {
                    return Err(ResolveError::AzureError(
                        ref_str.to_owned(),
                        "vault name and secret name must be non-empty".into(),
                    ));
                }

                Ok(AzureRef::Latest {
                    vault_name,
                    secret_name,
                })
            }
            3 => {
                let vault_name = parts[0];
                let secret_name = parts[1];
                let version = parts[2];

                if vault_name.is_empty() || secret_name.is_empty() || version.is_empty() {
                    return Err(ResolveError::AzureError(
                        ref_str.to_owned(),
                        "vault name, secret name, and version must be non-empty".into(),
                    ));
                }

                Ok(AzureRef::Versioned {
                    vault_name,
                    secret_name,
                    version,
                })
            }
            _ => unreachable!("splitn(3) can return at most 3 parts"),
        }
    }

    /// Construct the vault base URL from a vault name.
    fn vault_url(vault_name: &str) -> String {
        // Check for explicit override first.
        if let Ok(url) = std::env::var(AZURE_VAULT_URL_ENV) {
            return url;
        }
        format!("https://{vault_name}.vault.azure.net")
    }
}

impl SecretResolver for AzureResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        let (vault_name, secret_name, version) = match &parsed {
            AzureRef::Latest {
                vault_name,
                secret_name,
            } => (*vault_name, *secret_name, None),
            AzureRef::Versioned {
                vault_name,
                secret_name,
                version,
            } => (*vault_name, *secret_name, Some(*version)),
        };

        // Read Azure AD credentials from environment.
        let tenant_id = std::env::var(AZURE_TENANT_ID_ENV).map_err(|_| {
            ResolveError::AzureError(ref_str.to_owned(), format!("{AZURE_TENANT_ID_ENV} not set"))
        })?;
        let client_id = std::env::var(AZURE_CLIENT_ID_ENV).map_err(|_| {
            ResolveError::AzureError(ref_str.to_owned(), format!("{AZURE_CLIENT_ID_ENV} not set"))
        })?;
        let client_secret = std::env::var(AZURE_CLIENT_SECRET_ENV).map_err(|_| {
            ResolveError::AzureError(
                ref_str.to_owned(),
                format!("{AZURE_CLIENT_SECRET_ENV} not set"),
            )
        })?;

        let base_url = Self::vault_url(vault_name);
        let client = AzureKeyVaultClient::new(&base_url, tenant_id, client_id, client_secret)
            .map_err(|e| {
                ResolveError::AzureError(ref_str.to_owned(), format!("client init failed: {e}"))
            })?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                let secret = client
                    .get_secret(secret_name, version)
                    .await
                    .map_err(|e| format!("secret fetch failed: {e}"))?;

                secret
                    .value
                    .ok_or_else(|| format!("secret '{secret_name}' has no value"))
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::AzureError(ref_str.to_owned(), msg)),
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
    fn parse_ref_vault_and_secret() {
        let result = AzureResolver::parse_ref("azure:my-vault/my-secret").unwrap();
        assert_eq!(
            result,
            AzureRef::Latest {
                vault_name: "my-vault",
                secret_name: "my-secret"
            }
        );
    }

    #[test]
    fn parse_ref_with_version() {
        let result = AzureResolver::parse_ref("azure:my-vault/my-secret/abc123def").unwrap();
        assert_eq!(
            result,
            AzureRef::Versioned {
                vault_name: "my-vault",
                secret_name: "my-secret",
                version: "abc123def"
            }
        );
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = AzureResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_prefix() {
        let result = AzureResolver::parse_ref("azure:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_missing_secret_name() {
        let result = AzureResolver::parse_ref("azure:my-vault");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::AzureError(..)));
        assert!(format!("{err}").contains("expected format"));
    }

    #[test]
    fn parse_ref_empty_vault() {
        let result = AzureResolver::parse_ref("azure:/secret");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_secret() {
        let result = AzureResolver::parse_ref("azure:vault/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_version() {
        let result = AzureResolver::parse_ref("azure:vault/secret/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_with_hyphens_and_numbers() {
        let result = AzureResolver::parse_ref("azure:my-vault-01/db-password-2").unwrap();
        assert_eq!(
            result,
            AzureRef::Latest {
                vault_name: "my-vault-01",
                secret_name: "db-password-2"
            }
        );
    }

    #[test]
    fn vault_url_default() {
        // Remove override if set.
        unsafe { std::env::remove_var(AZURE_VAULT_URL_ENV) };
        let url = AzureResolver::vault_url("my-vault");
        assert_eq!(url, "https://my-vault.vault.azure.net");
    }

    #[test]
    fn vault_url_override() {
        unsafe { std::env::set_var(AZURE_VAULT_URL_ENV, "http://localhost:8080") };
        let url = AzureResolver::vault_url("ignored");
        assert_eq!(url, "http://localhost:8080");
        unsafe { std::env::remove_var(AZURE_VAULT_URL_ENV) };
    }

    #[test]
    fn resolver_debug() {
        let resolver = AzureResolver;
        let debug = format!("{resolver:?}");
        assert!(debug.contains("AzureResolver"));
    }
}
