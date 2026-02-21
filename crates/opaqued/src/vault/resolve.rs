//! Vault secret resolver.
//!
//! Resolves `vault:<path>#<field>` secret refs using Vault HTTP API.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::sandbox::resolve::{BaseResolver, ResolveError, SecretResolver};
use crate::secret::SecretValue;
use sha2::{Digest, Sha256};

use super::client::VaultClient;

/// Default keychain ref for the Vault token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/vault-token";

/// Environment variable to override the default Vault token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_VAULT_TOKEN_REF";

#[derive(Debug, Clone)]
struct LeaseCacheEntry {
    value: String,
    expires_at: Instant,
}

static LEASE_CACHE: LazyLock<Mutex<HashMap<String, LeaseCacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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

    #[cfg(test)]
    fn with_token_ref(client: VaultClient, token_ref: String) -> Self {
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

    fn token_fingerprint(token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        digest
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }

    fn lease_cache_key(&self, token: &str, path: &str, field: &str) -> String {
        format!(
            "{}|{}|{}#{}",
            self.client.base_url(),
            Self::token_fingerprint(token),
            path,
            field
        )
    }

    fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<String, LeaseCacheEntry>> {
        LEASE_CACHE.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn get_cached_value(key: &str) -> Option<String> {
        let now = Instant::now();
        let mut cache = Self::lock_cache();
        cache.retain(|_, entry| entry.expires_at > now);
        cache.get(key).map(|entry| entry.value.clone())
    }

    fn store_cached_value(key: String, value: String, lease_duration_secs: u64) {
        if lease_duration_secs == 0 {
            return;
        }
        let ttl = lease_duration_secs.max(1);
        let expires_at = Instant::now() + Duration::from_secs(ttl);
        let mut cache = Self::lock_cache();
        cache.insert(key, LeaseCacheEntry { value, expires_at });
    }

    #[cfg(test)]
    fn clear_cache_for_tests() {
        let mut cache = Self::lock_cache();
        cache.clear();
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
        let cache_key = self.lease_cache_key(token, parsed.path, parsed.field);
        if let Some(value) = Self::get_cached_value(&cache_key) {
            return Ok(SecretValue::from_string(value));
        }

        // Use block_in_place + block_on to call async HTTP from sync trait.
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async {
                self.client
                    .read_secret_field_with_lease(token, parsed.path, parsed.field)
                    .await
                    .map_err(|e| format!("secret read failed: {e}"))
            })
        });

        match result {
            Ok(read) => {
                if let Some(lease) = read.lease {
                    Self::store_cached_value(
                        cache_key,
                        read.value.clone(),
                        lease.lease_duration_secs,
                    );
                }
                Ok(SecretValue::from_string(read.value))
            }
            Err(msg) => Err(ResolveError::VaultError(ref_str.to_owned(), msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
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
        VaultResolver::clear_cache_for_tests();
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

        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_READ", "vault-token-123") };
        let resolver =
            VaultResolver::with_token_ref(client, "env:OPAQUE_TEST_VAULT_TOKEN_READ".into());
        let value = resolver
            .resolve("vault:secret/data/myapp#DATABASE_URL")
            .unwrap();
        assert_eq!(value.as_str().unwrap(), "postgres://example");

        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_READ") };
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_propagates_client_failure() {
        VaultResolver::clear_cache_for_tests();
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myapp"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_FAIL", "vault-token-123") };
        let resolver =
            VaultResolver::with_token_ref(client, "env:OPAQUE_TEST_VAULT_TOKEN_FAIL".into());
        let err = resolver
            .resolve("vault:secret/data/myapp#DATABASE_URL")
            .unwrap_err();
        assert!(matches!(err, ResolveError::VaultError(..)));
        assert!(format!("{err}").contains("authentication failed"));

        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_FAIL") };
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_uses_cached_leased_value_before_expiry() {
        VaultResolver::clear_cache_for_tests();
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/readonly"))
            .and(header("x-vault-token", "vault-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1",
                "lease_duration": 30,
                "renewable": true,
                "data": {
                    "username": "v-user",
                    "password": "first-password"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_CACHE", "vault-token-123") };
        let resolver =
            VaultResolver::with_token_ref(client, "env:OPAQUE_TEST_VAULT_TOKEN_CACHE".into());
        let first = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        let second = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(first.as_str(), Some("first-password"));
        assert_eq!(second.as_str(), Some("first-password"));

        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_CACHE") };
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_refreshes_after_lease_expiry() {
        VaultResolver::clear_cache_for_tests();
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/readonly"))
            .and(header("x-vault-token", "vault-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1",
                "lease_duration": 1,
                "renewable": true,
                "data": {
                    "password": "first-password"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_REFRESH", "vault-token-123") };
        let resolver = VaultResolver::with_token_ref(
            client.clone(),
            "env:OPAQUE_TEST_VAULT_TOKEN_REFRESH".into(),
        );
        let first = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(first.as_str(), Some("first-password"));

        sleep(Duration::from_secs(2)).await;

        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/v1/database/creds/readonly"))
            .and(header("x-vault-token", "vault-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/b2",
                "lease_duration": 30,
                "renewable": true,
                "data": {
                    "password": "second-password"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let second = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(second.as_str(), Some("second-password"));

        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_REFRESH") };
    }
}
