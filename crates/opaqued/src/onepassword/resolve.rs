//! 1Password secret resolver.
//!
//! Resolves `onepassword:<vault>/<item>[/<field>]` references by calling
//! the 1Password Connect Server API. The field defaults to `"password"`
//! if not specified.
//!
//! The Connect bearer token is itself resolved via the base resolver
//! (env + keychain only) to prevent resolution cycles.

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;

use super::client::OnePasswordClient;

/// Default keychain ref for the 1Password Connect token.
const DEFAULT_CONNECT_TOKEN_REF: &str = "keychain:opaque/1password-connect-token";

/// Environment variable to override the default Connect token ref.
const CONNECT_TOKEN_REF_ENV: &str = "OPAQUE_1PASSWORD_TOKEN_REF";

/// Default field name when not specified in the ref.
const DEFAULT_FIELD: &str = "password";

/// Resolves `onepassword:<vault>/<item>[/<field>]` secret references.
pub struct OnePasswordResolver {
    client: OnePasswordClient,
    connect_token_ref: String,
}

impl std::fmt::Debug for OnePasswordResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnePasswordResolver")
            .field("connect_token_ref", &self.connect_token_ref)
            .finish()
    }
}

impl OnePasswordResolver {
    /// Create a new resolver with the given client.
    ///
    /// The Connect token ref is read from `OPAQUE_1PASSWORD_TOKEN_REF` env var,
    /// defaulting to `keychain:opaque/1password-connect-token`.
    pub fn new(client: OnePasswordClient) -> Self {
        let connect_token_ref = std::env::var(CONNECT_TOKEN_REF_ENV)
            .unwrap_or_else(|_| DEFAULT_CONNECT_TOKEN_REF.to_owned());
        Self {
            client,
            connect_token_ref,
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
}

impl SecretResolver for OnePasswordResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        let (vault_name, item_title, field_label) = Self::parse_ref(ref_str)?;

        // Resolve the Connect token via base resolvers only (env + keychain)
        // to prevent cycles.
        let base = BaseResolver::new();
        let token_value = base.resolve(&self.connect_token_ref).map_err(|e| {
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
                // Step 1: Find vault by name.
                let vault_id = self
                    .client
                    .find_vault_by_name(token, vault_name)
                    .await
                    .map_err(|e| format!("vault lookup failed: {e}"))?;

                // Step 2: Find item by title within vault.
                let item_id = self
                    .client
                    .find_item_by_title(token, &vault_id, item_title)
                    .await
                    .map_err(|e| format!("item lookup failed: {e}"))?;

                // Step 3: Get item with field values.
                let item = self
                    .client
                    .get_item(token, &vault_id, &item_id)
                    .await
                    .map_err(|e| format!("item fetch failed: {e}"))?;

                // Step 4: Extract the named field.
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
    fn resolver_debug_does_not_leak_token() {
        let client = OnePasswordClient::new("http://localhost:8080");
        let resolver = OnePasswordResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("OnePasswordResolver"));
        assert!(!debug.contains("secret"));
    }
}
