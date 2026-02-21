//! Vault secret resolver.
//!
//! Resolves `vault:<path>#<field>` secret refs using Vault HTTP API.

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::VaultClient;

/// Default keychain ref for the Vault token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/vault-token";

/// Environment variable to override the default Vault token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_VAULT_TOKEN_REF";

/// Parsed vault secret ref.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VaultRef<'a> {
    path: &'a str,
    field: &'a str,
}

/// Resolves `vault:<path>#<field>` refs.
pub struct VaultResolver {
    client: VaultClient,
    token_ref: String,
}

impl std::fmt::Debug for VaultResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultResolver")
            .field("token_ref", &self.token_ref)
            .finish()
    }
}

impl VaultResolver {
    /// Create a new resolver using env/default token ref.
    pub fn new(client: VaultClient) -> Self {
        let token_ref =
            std::env::var(TOKEN_REF_ENV).unwrap_or_else(|_| DEFAULT_TOKEN_REF.to_owned());
        Self { client, token_ref }
    }

    /// Parse `vault:<path>#<field>`.
    fn parse_ref(ref_str: &str) -> Result<VaultRef<'_>, ResolveError> {
        let rest = ref_str
            .strip_prefix("vault:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "empty ref after 'vault:' prefix".into(),
            ));
        }

        let (path, field) = rest.split_once('#').ok_or_else(|| {
            ResolveError::VaultError(
                ref_str.to_owned(),
                "expected format vault:<path>#<field>".into(),
            )
        })?;

        if path.is_empty() || field.is_empty() {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "path and field must be non-empty".into(),
            ));
        }

        if path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "..")
        {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "path must not contain '..' or empty segments".into(),
            ));
        }

        if path.chars().any(|c| c.is_ascii_control()) || field.chars().any(|c| c.is_ascii_control())
        {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "path/field must not contain control characters".into(),
            ));
        }

        Ok(VaultRef { path, field })
    }
}

impl SecretResolver for VaultResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let parsed = Self::parse_ref(ref_str)?;

        // Resolve the Vault token via base resolvers only (env + keychain)
        // to prevent cycles.
        let base = BaseResolver::new();
        let token_value = base.resolve(&self.token_ref).map_err(|e| {
            ResolveError::VaultError(
                ref_str.to_owned(),
                format!("failed to resolve access token: {e}"),
            )
        })?;
        let token = token_value.as_str().ok_or_else(|| {
            ResolveError::VaultError(ref_str.to_owned(), "access token is not valid UTF-8".into())
        })?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                self.client
                    .read_secret_field(token, parsed.path, parsed.field)
                    .await
                    .map_err(|e| format!("secret read failed: {e}"))
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::VaultError(ref_str.to_owned(), msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_ref_valid() {
        let parsed = VaultResolver::parse_ref("vault:secret/data/myapp#DATABASE_URL").unwrap();
        assert_eq!(
            parsed,
            VaultRef {
                path: "secret/data/myapp",
                field: "DATABASE_URL",
            }
        );
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = VaultResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_missing_field_delimiter() {
        let result = VaultResolver::parse_ref("vault:secret/data/myapp");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::VaultError(..)));
        assert!(format!("{err}").contains("expected format"));
    }

    #[test]
    fn parse_ref_empty_path_or_field() {
        assert!(VaultResolver::parse_ref("vault:#FIELD").is_err());
        assert!(VaultResolver::parse_ref("vault:secret/path#").is_err());
    }

    #[test]
    fn parse_ref_rejects_parent_dir() {
        let result = VaultResolver::parse_ref("vault:secret/data/../prod#TOKEN");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ResolveError::VaultError(..)));
        assert!(format!("{err}").contains("must not contain '..'"));
    }

    #[test]
    fn resolver_debug() {
        let client = VaultClient::new();
        let resolver = VaultResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("VaultResolver"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_reads_field_with_env_token_ref() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myapp"))
            .and(header("x-vault-token", "vault-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": {
                        "DATABASE_URL": "postgres://example"
                    }
                }
            })))
            .mount(&server)
            .await;

        unsafe { std::env::set_var("OPAQUE_VAULT_TOKEN_REF", "env:OPAQUE_TEST_VAULT_TOKEN") };
        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_TOKEN", "vault-token-123") };

        let resolver = VaultResolver::new(client);
        let value = resolver
            .resolve("vault:secret/data/myapp#DATABASE_URL")
            .unwrap();
        assert_eq!(value.as_str().unwrap(), "postgres://example");

        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN") };
        unsafe { std::env::remove_var("OPAQUE_VAULT_TOKEN_REF") };
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_propagates_client_failure() {
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myapp"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        unsafe { std::env::set_var("OPAQUE_VAULT_TOKEN_REF", "env:OPAQUE_TEST_VAULT_TOKEN") };
        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_TOKEN", "vault-token-123") };

        let resolver = VaultResolver::new(client);
        let err = resolver
            .resolve("vault:secret/data/myapp#DATABASE_URL")
            .unwrap_err();
        assert!(matches!(err, ResolveError::VaultError(..)));
        assert!(format!("{err}").contains("authentication failed"));

        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN") };
        unsafe { std::env::remove_var("OPAQUE_VAULT_TOKEN_REF") };
    }
}
