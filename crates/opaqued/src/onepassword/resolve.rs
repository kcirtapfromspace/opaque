//! 1Password secret resolver.
//!
//! Resolves `onepassword:<vault>/<item>[/<field>]` references using either:
//! - **Connect Server API** — via `OnePasswordClient` (self-hosted, bearer token)
//! - **`op` CLI** — via `OpCliClient` (desktop app, biometric auth)
//!
//! The field defaults to `"password"` if not specified.
//!
//! For the Connect Server backend, the bearer token is itself resolved via the
//! base resolver (env + keychain only) to prevent resolution cycles.

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::OnePasswordClient;
use super::op_cli::OpCliClient;

/// Default keychain ref for the 1Password Connect token.
const DEFAULT_CONNECT_TOKEN_REF: &str = "keychain:opaque/1password-connect-token";

/// Environment variable to override the default Connect token ref.
const CONNECT_TOKEN_REF_ENV: &str = "OPAQUE_1PASSWORD_TOKEN_REF";

/// Default field name when not specified in the ref.
const DEFAULT_FIELD: &str = "password";

/// Which backend the resolver uses.
pub enum ResolverBackend {
    /// Connect Server: needs a client and a token ref.
    ConnectServer {
        client: OnePasswordClient,
        connect_token_ref: String,
    },
    /// `op` CLI: no token needed, auth via desktop app.
    Cli(OpCliClient),
}

impl std::fmt::Debug for ResolverBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectServer {
                connect_token_ref, ..
            } => f
                .debug_struct("ConnectServer")
                .field("connect_token_ref", connect_token_ref)
                .finish(),
            Self::Cli(_) => write!(f, "OpCli"),
        }
    }
}

/// Resolves `onepassword:<vault>/<item>[/<field>]` secret references.
pub struct OnePasswordResolver {
    backend: ResolverBackend,
}

impl std::fmt::Debug for OnePasswordResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnePasswordResolver")
            .field("backend", &self.backend)
            .finish()
    }
}

impl OnePasswordResolver {
    /// Create a resolver backed by the Connect Server.
    pub fn new(client: OnePasswordClient) -> Self {
        let connect_token_ref = std::env::var(CONNECT_TOKEN_REF_ENV)
            .unwrap_or_else(|_| DEFAULT_CONNECT_TOKEN_REF.to_owned());
        Self {
            backend: ResolverBackend::ConnectServer {
                client,
                connect_token_ref,
            },
        }
    }

    /// Create a resolver backed by the `op` CLI.
    pub fn from_cli(cli: OpCliClient) -> Self {
        Self {
            backend: ResolverBackend::Cli(cli),
        }
    }

    /// Parse a `onepassword:` ref into (vault, item, field).
    ///
    /// Format: `onepassword:<vault>/<item>[/<field>]`
    /// Field defaults to `"password"` if not specified.
    fn parse_ref(ref_str: &str) -> Result<(&str, &str, &str), ResolveError> {
        let rest = ref_str
            .strip_prefix("onepassword:")
            .ok_or_else(|| ResolveError::UnknownScheme(ref_str.to_owned()))?;

        if rest.is_empty() {
            return Err(ResolveError::OnePasswordError(
                ref_str.to_owned(),
                "empty ref after 'onepassword:' prefix".into(),
            ));
        }

        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        match parts.len() {
            2 => {
                let vault = parts[0];
                let item = parts[1];
                if vault.is_empty() || item.is_empty() {
                    return Err(ResolveError::OnePasswordError(
                        ref_str.to_owned(),
                        "vault and item names must be non-empty".into(),
                    ));
                }
                Ok((vault, item, DEFAULT_FIELD))
            }
            3 => {
                let vault = parts[0];
                let item = parts[1];
                let field = parts[2];
                if vault.is_empty() || item.is_empty() || field.is_empty() {
                    return Err(ResolveError::OnePasswordError(
                        ref_str.to_owned(),
                        "vault, item, and field names must be non-empty".into(),
                    ));
                }
                Ok((vault, item, field))
            }
            _ => Err(ResolveError::OnePasswordError(
                ref_str.to_owned(),
                "expected format onepassword:<vault>/<item>[/<field>]".into(),
            )),
        }
    }

    /// Resolve via the Connect Server API (async, bridged to sync).
    fn resolve_connect_server(
        &self,
        ref_str: &str,
        client: &OnePasswordClient,
        connect_token_ref: &str,
        vault_name: &str,
        item_title: &str,
        field_label: &str,
    ) -> Result<SecretValue, ResolveError> {
        // Resolve the Connect token via base resolvers only (env + keychain)
        // to prevent cycles.
        let base = BaseResolver::new();
        let token_value = base.resolve(connect_token_ref).map_err(|e| {
            ResolveError::OnePasswordError(
                ref_str.to_owned(),
                format!("failed to resolve connect token: {e}"),
            )
        })?;
        let token = token_value.as_str().ok_or_else(|| {
            ResolveError::OnePasswordError(
                ref_str.to_owned(),
                "connect token is not valid UTF-8".into(),
            )
        })?;

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                let vault_id = client
                    .find_vault_by_name(token, vault_name)
                    .await
                    .map_err(|e| format!("vault lookup failed: {e}"))?;

                let item_id = client
                    .find_item_by_title(token, &vault_id, item_title)
                    .await
                    .map_err(|e| format!("item lookup failed: {e}"))?;

                let item = client
                    .get_item(token, &vault_id, &item_id)
                    .await
                    .map_err(|e| format!("item fetch failed: {e}"))?;

                let field_value = item
                    .fields
                    .iter()
                    .find(|f| f.label.as_deref() == Some(field_label))
                    .and_then(|f| f.value.as_deref())
                    .ok_or_else(|| {
                        format!(
                            "field '{}' not found on item '{}' in vault '{}'",
                            field_label, item_title, vault_name
                        )
                    })?;

                Ok::<String, String>(field_value.to_owned())
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::OnePasswordError(ref_str.to_owned(), msg)),
        }
    }

    /// Resolve via the `op` CLI using `op read`.
    fn resolve_cli(
        &self,
        ref_str: &str,
        cli: &OpCliClient,
        vault_name: &str,
        item_title: &str,
        field_label: &str,
    ) -> Result<SecretValue, ResolveError> {
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                cli.read_field(vault_name, item_title, field_label)
                    .await
                    .map_err(|e| format!("{e}"))
            })
        });

        match result {
            Ok(value) => Ok(SecretValue::from_string(value)),
            Err(msg) => Err(ResolveError::OnePasswordError(ref_str.to_owned(), msg)),
        }
    }
}

impl SecretResolver for OnePasswordResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let (vault_name, item_title, field_label) = Self::parse_ref(ref_str)?;

        match &self.backend {
            ResolverBackend::ConnectServer {
                client,
                connect_token_ref,
            } => self.resolve_connect_server(
                ref_str,
                client,
                connect_token_ref,
                vault_name,
                item_title,
                field_label,
            ),
            ResolverBackend::Cli(cli) => {
                self.resolve_cli(ref_str, cli, vault_name, item_title, field_label)
            }
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
    fn parse_ref_vault_item() {
        let (vault, item, field) =
            OnePasswordResolver::parse_ref("onepassword:Personal/GitHub Token").unwrap();
        assert_eq!(vault, "Personal");
        assert_eq!(item, "GitHub Token");
        assert_eq!(field, "password"); // default
    }

    #[test]
    fn parse_ref_vault_item_field() {
        let (vault, item, field) =
            OnePasswordResolver::parse_ref("onepassword:Work/API Key/api_key").unwrap();
        assert_eq!(vault, "Work");
        assert_eq!(item, "API Key");
        assert_eq!(field, "api_key");
    }

    #[test]
    fn parse_ref_wrong_scheme() {
        let result = OnePasswordResolver::parse_ref("env:FOO");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ResolveError::UnknownScheme(_)
        ));
    }

    #[test]
    fn parse_ref_empty_after_prefix() {
        let result = OnePasswordResolver::parse_ref("onepassword:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_no_slash() {
        let result = OnePasswordResolver::parse_ref("onepassword:justname");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_vault() {
        let result = OnePasswordResolver::parse_ref("onepassword:/item");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_item() {
        let result = OnePasswordResolver::parse_ref("onepassword:vault/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_empty_field() {
        let result = OnePasswordResolver::parse_ref("onepassword:vault/item/");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ref_vault_with_spaces() {
        let (vault, item, field) =
            OnePasswordResolver::parse_ref("onepassword:My Vault/My Item").unwrap();
        assert_eq!(vault, "My Vault");
        assert_eq!(item, "My Item");
        assert_eq!(field, "password");
    }

    #[test]
    fn resolver_debug_connect_server() {
        let client = OnePasswordClient::new("http://localhost:8080");
        let resolver = OnePasswordResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("OnePasswordResolver"));
        assert!(debug.contains("ConnectServer"));
    }

    #[test]
    fn resolver_debug_cli() {
        if let Ok(cli) = OpCliClient::new() {
            let resolver = OnePasswordResolver::from_cli(cli);
            let debug = format!("{resolver:?}");
            assert!(debug.contains("OnePasswordResolver"));
            assert!(debug.contains("OpCli"));
        }
    }
}
