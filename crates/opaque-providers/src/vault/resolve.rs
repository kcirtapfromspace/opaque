//! Vault secret resolver.
//!
//! Resolves `vault:<path>[?version=<positive-integer>]#<field>` secret refs.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use opaque_core::resolver::{BaseResolver, ResolveError, SecretResolver};
use opaque_core::secret::SecretValue;
use sha2::{Digest, Sha256};

use super::client::{VaultApiError, VaultClient, VaultLease, VaultSecret};

/// Default keychain ref for the Vault token.
const DEFAULT_TOKEN_REF: &str = "keychain:opaque/vault-token";

/// Environment variable to override the default Vault token ref.
const TOKEN_REF_ENV: &str = "OPAQUE_VAULT_TOKEN_REF";

/// Environment variable to control proactive lease renewal timing.
const LEASE_RENEW_WINDOW_SECS_ENV: &str = "OPAQUE_VAULT_LEASE_RENEW_WINDOW_SECS";

/// Default proactive lease renewal window.
const DEFAULT_LEASE_RENEW_WINDOW_SECS: u64 = 30;

#[derive(Debug)]
struct LeaseCacheEntry {
    snapshot: Arc<VaultSecret>,
    expires_at: Instant,
    lease: VaultLease,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LeaseCacheKey {
    base_url: String,
    token_fingerprint: [u8; 32],
    path: String,
    version: Option<NonZeroU64>,
}

#[derive(Clone)]
struct ResolutionSnapshot {
    secret: Arc<VaultSecret>,
    expires_at: Option<Instant>,
}

type CacheSlot = Arc<tokio::sync::Mutex<Option<LeaseCacheEntry>>>;
// The global map only protects slot lookup. Network I/O holds the individual
// slot's async mutex, making issuance/renewal/refresh singleflight per identity.
static LEASE_CACHE: LazyLock<Mutex<HashMap<LeaseCacheKey, CacheSlot>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const MAX_CACHED_PATHS: usize = 4096;

/// Parsed vault secret ref.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VaultRef<'a> {
    path: &'a str,
    field: &'a str,
    version: Option<NonZeroU64>,
}

/// Validate a reference that binds execution to one Vault KV v2 version.
/// This performs no network requests and does not resolve credentials.
pub fn validate_pinned_ref(ref_str: &str) -> Result<(), ResolveError> {
    let parsed = VaultResolver::parse_ref(ref_str)?;
    if parsed.version.is_none() {
        return Err(ResolveError::VaultError(
            ref_str.to_owned(),
            "a pinned KV v2 ref requires ?version=<positive-integer> before #<field>".into(),
        ));
    }
    Ok(())
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
    #[cfg_attr(coverage_nightly, coverage(off))]
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

        let (path_query, field) = rest.split_once('#').ok_or_else(|| {
            ResolveError::VaultError(
                ref_str.to_owned(),
                "expected format vault:<path>#<field>".into(),
            )
        })?;

        let (path, version) = match path_query.split_once('?') {
            Some((path, query)) => {
                let version = query.strip_prefix("version=").and_then(|raw| {
                    if raw.starts_with('0') || !raw.bytes().all(|b| b.is_ascii_digit()) {
                        return None;
                    }
                    raw.parse::<NonZeroU64>().ok().filter(|version| version.get() <= i64::MAX as u64)
                }).ok_or_else(|| ResolveError::VaultError(
                    ref_str.to_owned(),
                    "only ?version=<positive-integer> is supported (no leading zeros or additional parameters)".into(),
                ))?;
                if !path.contains("/data/") {
                    return Err(ResolveError::VaultError(
                        ref_str.to_owned(),
                        "pinned refs require a KV v2 path: <mount>/data/<secret>".into(),
                    ));
                }
                (path, Some(version))
            }
            None => (path_query, None),
        };

        if path.is_empty() || field.is_empty() {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "path and field must be non-empty".into(),
            ));
        }

        if path
            .split('/')
            .any(|segment| segment.is_empty() || segment == ".." || segment == ".")
        {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "path must not contain '..', '.', or empty segments".into(),
            ));
        }

        if path.chars().any(|c| c.is_ascii_control()) || field.chars().any(|c| c.is_ascii_control())
        {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "path/field must not contain control characters".into(),
            ));
        }

        if path.contains(['%', '\\']) || field.contains(['#', '?']) {
            return Err(ResolveError::VaultError(
                ref_str.to_owned(),
                "path must be unescaped and field must not contain ref delimiters".into(),
            ));
        }

        Ok(VaultRef {
            path,
            field,
            version,
        })
    }

    fn lease_cache_key(&self, token: &str, parsed: &VaultRef<'_>) -> LeaseCacheKey {
        LeaseCacheKey {
            base_url: self.client.base_url().to_owned(),
            token_fingerprint: Sha256::digest(token.as_bytes()).into(),
            path: parsed.path.to_owned(),
            version: parsed.version,
        }
    }

    fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<LeaseCacheKey, CacheSlot>> {
        LEASE_CACHE.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn cache_slot(key: &LeaseCacheKey) -> Result<CacheSlot, String> {
        let mut cache = Self::lock_cache();
        if let Some(slot) = cache.get(key) {
            return Ok(slot.clone());
        }
        // Retire unused expired snapshots without dropping an in-flight slot.
        cache.retain(|_, slot| {
            if Arc::strong_count(slot) != 1 {
                return true;
            }
            match slot.try_lock() {
                Ok(entry) => entry
                    .as_ref()
                    .is_some_and(|entry| entry.expires_at > Instant::now()),
                Err(_) => true,
            }
        });
        if cache.len() >= MAX_CACHED_PATHS {
            return Err("Vault dynamic credential cache capacity reached".into());
        }
        let slot = Arc::new(tokio::sync::Mutex::new(None));
        cache.insert(key.clone(), slot.clone());
        Ok(slot)
    }

    fn lease_renew_window_secs() -> u64 {
        match std::env::var(LEASE_RENEW_WINDOW_SECS_ENV) {
            Ok(raw) => match raw.parse::<u64>() {
                Ok(secs) => secs,
                Err(err) => {
                    tracing::warn!(
                        "invalid {}='{}' ({}); using default {}",
                        LEASE_RENEW_WINDOW_SECS_ENV,
                        raw,
                        err,
                        DEFAULT_LEASE_RENEW_WINDOW_SECS
                    );
                    DEFAULT_LEASE_RENEW_WINDOW_SECS
                }
            },
            Err(_) => DEFAULT_LEASE_RENEW_WINDOW_SECS,
        }
    }

    async fn read_snapshot(
        &self,
        token: &str,
        parsed: &VaultRef<'_>,
    ) -> Result<ResolutionSnapshot, String> {
        // Pinned KV reads revalidate deletion/destruction on every batch. They
        // never reuse plaintext from the cross-execution dynamic cache.
        if parsed.version.is_some() {
            return self
                .client
                .read_secret_at_version(token, parsed.path, parsed.version)
                .await
                .map(|secret| ResolutionSnapshot {
                    secret: Arc::new(secret),
                    expires_at: None,
                })
                .map_err(|e| e.to_string());
        }
        let key = self.lease_cache_key(token, parsed);
        let slot = Self::cache_slot(&key)?;
        let mut entry = slot.lock().await;
        if let Some(cached) = entry.as_mut() {
            let renew_window = Duration::from_secs(Self::lease_renew_window_secs());
            if cached.expires_at > Instant::now()
                && cached.lease.renewable
                && !renew_window.is_zero()
                && cached.expires_at.saturating_duration_since(Instant::now()) <= renew_window
            {
                let started = Instant::now();
                match self.client.renew_lease(token, &cached.lease.lease_id).await {
                    Ok(lease) => {
                        cached.expires_at = started
                            .checked_add(Duration::from_secs(lease.lease_duration_secs))
                            .ok_or("Vault lease duration exceeds supported expiry")?;
                        cached.lease = lease;
                    }
                    Err(
                        err @ (VaultApiError::Unauthorized
                        | VaultApiError::NotFound(_)
                        | VaultApiError::BadRequest
                        | VaultApiError::InvalidLease),
                    ) => {
                        // Revoked/invalid authority is not an availability failure.
                        // Never return a cached credential after this rejection.
                        *entry = None;
                        return Err(err.to_string());
                    }
                    Err(err) => tracing::warn!("best-effort Vault lease renewal failed: {err}"),
                }
            }
            // Recheck after network latency, including a failed renewal.
            if cached.expires_at > Instant::now() {
                return Ok(ResolutionSnapshot {
                    secret: cached.snapshot.clone(),
                    expires_at: Some(cached.expires_at),
                });
            }
        }
        if let Some(expired) = entry.take()
            && let Err(err) = self
                .client
                .revoke_lease(token, &expired.lease.lease_id)
                .await
        {
            tracing::warn!("best-effort Vault lease revoke failed: {err}");
        }
        let started = Instant::now();
        let snapshot = Arc::new(
            self.client
                .read_secret_at_version(token, parsed.path, None)
                .await
                .map_err(|e| e.to_string())?,
        );
        if let Some(lease) = &snapshot.lease {
            let expires_at = started
                .checked_add(Duration::from_secs(lease.lease_duration_secs))
                .ok_or("Vault lease duration exceeds supported expiry")?;
            if expires_at <= Instant::now() {
                return Err("Vault credential lease expired during issuance".into());
            }
            *entry = Some(LeaseCacheEntry {
                snapshot: snapshot.clone(),
                expires_at,
                lease: lease.clone(),
            });
        }
        let expires_at = entry.as_ref().map(|entry| entry.expires_at);
        Ok(ResolutionSnapshot {
            secret: snapshot,
            expires_at,
        })
    }

    fn resolve_references(&self, refs: &[&str]) -> Result<Vec<SecretValue>, ResolveError> {
        if refs.is_empty() {
            return Ok(Vec::new());
        }
        // Validate the entire batch before resolving any credential or issuing
        // any dynamic secret. Capture one token identity for the full batch.
        let parsed = refs
            .iter()
            .map(|reference| Self::parse_ref(reference))
            .collect::<Result<Vec<_>, _>>()?;
        let token_value = BaseResolver::new().resolve(&self.token_ref).map_err(|e| {
            ResolveError::VaultError(
                refs[0].into(),
                format!("failed to resolve access token: {e}"),
            )
        })?;
        let token = token_value.as_str().ok_or_else(|| {
            ResolveError::VaultError(refs[0].into(), "access token is not valid UTF-8".into())
        })?;
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ResolveError::VaultError(
                refs[0].into(),
                "Vault resolution requires a multi-thread Tokio runtime".into(),
            )
        })?;
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err(ResolveError::VaultError(
                refs[0].into(),
                "Vault resolution requires a multi-thread Tokio runtime".into(),
            ));
        }
        tokio::task::block_in_place(|| {
            handle.block_on(async {
            // Execution-local snapshots keep related fields coherent even if
            // the global lease expires or another execution refreshes it.
            let mut snapshots: HashMap<LeaseCacheKey, ResolutionSnapshot> = HashMap::new();
            let mut values = Vec::with_capacity(refs.len());
            for (reference, parsed) in refs.iter().zip(&parsed) {
                let key = self.lease_cache_key(token, parsed);
                let snapshot = if let Some(snapshot) = snapshots.get(&key) {
                    snapshot.clone()
                } else {
                    let snapshot = self.read_snapshot(token, parsed).await.map_err(|e| ResolveError::VaultError((*reference).into(), format!("secret read failed: {e}")))?;
                    snapshots.insert(key, snapshot.clone());
                    snapshot
                };
                let value = snapshot.secret.fields.get(parsed.field).ok_or_else(|| ResolveError::VaultError((*reference).into(), "requested field not found in secret snapshot".into()))?;
                values.push(SecretValue::new(value.as_bytes().to_vec()));
            }
            if snapshots.values().any(|snapshot| snapshot.expires_at.is_some_and(|expiry| expiry <= Instant::now())) {
                return Err(ResolveError::VaultError(refs[0].into(), "credential lease expired while resolving execution snapshot; retry the complete execution".into()));
            }
            Ok(values)
        })
        })
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn clear_cache_for_tests() {
        Self::lock_cache().clear();
    }
}

impl SecretResolver for VaultResolver {
    fn resolve(&self, ref_str: &str) -> Result<SecretValue, ResolveError> {
        self.resolve_references(&[ref_str])
            .map(|mut values| values.remove(0))
    }

    fn resolve_batch(&self, refs: &[&str]) -> Result<Vec<SecretValue>, ResolveError> {
        self.resolve_references(refs)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::{Arc, OnceLock};
    use tokio::time::sleep;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(super) async fn test_lock() -> tokio::sync::OwnedMutexGuard<()> {
        static LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
        LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await
    }

    #[test]
    fn parse_ref_valid() {
        let parsed = VaultResolver::parse_ref("vault:secret/data/myapp#DATABASE_URL").unwrap();
        assert_eq!(
            parsed,
            VaultRef {
                path: "secret/data/myapp",
                field: "DATABASE_URL",
                version: None,
            }
        );
    }

    #[test]
    fn pinned_ref_is_typed_and_strict() {
        let parsed = VaultResolver::parse_ref("vault:kv/data/demo?version=7#FIELD").unwrap();
        assert_eq!(parsed.path, "kv/data/demo");
        assert_eq!(parsed.field, "FIELD");
        assert_eq!(parsed.version, NonZeroU64::new(7));
        validate_pinned_ref("vault:team/kv/data/demo?version=7#FIELD").unwrap();
        for invalid in [
            "vault:kv/data/demo#FIELD",
            "vault:kv/data/demo?version=0#FIELD",
            "vault:kv/data/demo?version=07#FIELD",
            "vault:kv/data/demo?version=+7#FIELD",
            "vault:kv/data/demo?version=-7#FIELD",
            "vault:kv/data/demo?version=latest#FIELD",
            "vault:kv/data/demo?version=18446744073709551616#FIELD",
            "vault:kv/data/demo?version=9223372036854775808#FIELD",
            "vault:kv/data/demo?version=7&version=8#FIELD",
            "vault:kv/data/demo?version=7&other=value#FIELD",
            "vault:kv/data/demo?other=7#FIELD",
            "vault:kv/data/demo?version=#FIELD",
            "vault:kv/demo?version=7#FIELD",
            "vault:kv/data/?version=7#FIELD",
            "vault:kv/data/./demo?version=7#FIELD",
            "vault:kv/data/%2e%2e/demo?version=7#FIELD",
            "vault:kv/data/demo?version=7#FIELD#extra",
            "vault:kv/data/demo#FIELD?version=7",
        ] {
            assert!(validate_pinned_ref(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn cache_identity_binds_server_token_path_and_version_but_groups_fields() {
        let resolver = VaultResolver::with_token_ref(
            VaultClient::with_base_url("http://127.0.0.1:8200".into()),
            "env:UNUSED".into(),
        );
        let reference = VaultResolver::parse_ref("vault:kv/data/demo?version=7#FIELD").unwrap();
        let key = resolver.lease_cache_key("first-token", &reference);
        for different in [
            "vault:kv/data/other?version=7#FIELD",
            "vault:kv/data/demo?version=8#FIELD",
            "vault:kv/data/demo#FIELD",
        ] {
            let parsed = VaultResolver::parse_ref(different).unwrap();
            assert_ne!(key, resolver.lease_cache_key("first-token", &parsed));
        }
        let other_field = VaultResolver::parse_ref("vault:kv/data/demo?version=7#OTHER").unwrap();
        assert_eq!(key, resolver.lease_cache_key("first-token", &other_field));
        assert_ne!(key, resolver.lease_cache_key("second-token", &reference));
        let other_server = VaultResolver::with_token_ref(
            VaultClient::with_base_url("http://127.0.0.1:8201".into()),
            "env:UNUSED".into(),
        );
        assert_ne!(key, other_server.lease_cache_key("first-token", &reference));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pinned_resolution_does_not_follow_latest_or_cache_deleted_version() {
        let _guard = test_lock().await;
        VaultResolver::clear_cache_for_tests();
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());
        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_PINNED", "disposable-token") };
        let resolver = VaultResolver::with_token_ref(client, "env:OPAQUE_TEST_VAULT_PINNED".into());

        // Even unexpected lease metadata must never turn a pinned read into a
        // plaintext cache snapshot that would conceal a later deletion.
        for latest in [8, 9] {
            VaultResolver::clear_cache_for_tests();
            server.reset().await;
            Mock::given(method("GET"))
                .and(path("/v1/kv/data/demo"))
                .respond_with(move |request: &wiremock::Request| {
                    let pinned = request.url.query_pairs().any(|(k, v)| k == "version" && v == "7");
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "lease_id": "unexpected/lease",
                        "lease_duration": 600,
                        "renewable": true,
                        "data": {
                            "data": { "FIELD": if pinned { "approved".to_owned() } else { format!("latest-{latest}") } },
                            "metadata": {
                                "version": if pinned { 7 } else { latest },
                                "destroyed": false,
                                "deletion_time": ""
                            }
                        }
                    }))
                })
                .expect(2)
                .mount(&server).await;
            assert_eq!(
                resolver
                    .resolve("vault:kv/data/demo#FIELD")
                    .unwrap()
                    .as_str(),
                Some(format!("latest-{latest}").as_str())
            );
            assert_eq!(
                resolver
                    .resolve("vault:kv/data/demo?version=7#FIELD")
                    .unwrap()
                    .as_str(),
                Some("approved")
            );
            server.verify().await;
        }

        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/demo"))
            .and(wiremock::matchers::query_param("version", "7"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let error = resolver
            .resolve("vault:kv/data/demo?version=7#FIELD")
            .unwrap_err();
        assert!(error.to_string().contains("unavailable"));
        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_PINNED") };
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
        let client = VaultClient::new().unwrap();
        let resolver = VaultResolver::new(client);
        let debug = format!("{resolver:?}");
        assert!(debug.contains("VaultResolver"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lease_renew_window_invalid_value_uses_default() {
        let _guard = test_lock().await;
        unsafe { std::env::set_var(LEASE_RENEW_WINDOW_SECS_ENV, "abc") };
        assert_eq!(
            VaultResolver::lease_renew_window_secs(),
            DEFAULT_LEASE_RENEW_WINDOW_SECS
        );
        unsafe { std::env::remove_var(LEASE_RENEW_WINDOW_SECS_ENV) };
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_reads_field_with_env_token_ref() {
        let _guard = test_lock().await;
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
        let _guard = test_lock().await;
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
        let _guard = test_lock().await;
        VaultResolver::clear_cache_for_tests();
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/readonly"))
            .and(header("x-vault-token", "vault-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1",
                "lease_duration": 120,
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
    async fn resolve_renews_lease_proactively_near_expiry() {
        let _guard = test_lock().await;
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
                    "password": "first-password"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("x-vault-token", "vault-token-123"))
            .and(body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1",
                "lease_duration": 120,
                "renewable": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_RENEW", "vault-token-123");
            std::env::set_var(LEASE_RENEW_WINDOW_SECS_ENV, "30");
        }
        let resolver =
            VaultResolver::with_token_ref(client, "env:OPAQUE_TEST_VAULT_TOKEN_RENEW".into());

        let first = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        let second = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        let third = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(first.as_str(), Some("first-password"));
        assert_eq!(second.as_str(), Some("first-password"));
        assert_eq!(third.as_str(), Some("first-password"));

        unsafe {
            std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_RENEW");
            std::env::remove_var(LEASE_RENEW_WINDOW_SECS_ENV);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_renew_failure_falls_back_to_cached_until_expiry() {
        let _guard = test_lock().await;
        VaultResolver::clear_cache_for_tests();
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/readonly"))
            .and(header("x-vault-token", "vault-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1",
                "lease_duration": 2,
                "renewable": true,
                "data": {
                    "password": "first-password"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .and(header("x-vault-token", "vault-token-123"))
            .and(body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1"
            })))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_RENEW_FAIL", "vault-token-123");
            std::env::set_var(LEASE_RENEW_WINDOW_SECS_ENV, "30");
        }
        let resolver = VaultResolver::with_token_ref(
            client.clone(),
            "env:OPAQUE_TEST_VAULT_TOKEN_RENEW_FAIL".into(),
        );

        let first = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        let second = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(first.as_str(), Some("first-password"));
        assert_eq!(second.as_str(), Some("first-password"));

        sleep(Duration::from_secs(3)).await;

        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/revoke"))
            .and(header("x-vault-token", "vault-token-123"))
            .and(body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1"
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
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

        let third = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(third.as_str(), Some("second-password"));

        unsafe {
            std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_RENEW_FAIL");
            std::env::remove_var(LEASE_RENEW_WINDOW_SECS_ENV);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_non_renewable_lease_does_not_attempt_renewal() {
        let _guard = test_lock().await;
        VaultResolver::clear_cache_for_tests();
        let server = MockServer::start().await;
        let client = VaultClient::with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/v1/database/creds/readonly"))
            .and(header("x-vault-token", "vault-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1",
                "lease_duration": 30,
                "renewable": false,
                "data": {
                    "password": "first-password"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_NON_RENEW", "vault-token-123");
            std::env::set_var(LEASE_RENEW_WINDOW_SECS_ENV, "30");
        }
        let resolver =
            VaultResolver::with_token_ref(client, "env:OPAQUE_TEST_VAULT_TOKEN_NON_RENEW".into());

        let first = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        let second = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(first.as_str(), Some("first-password"));
        assert_eq!(second.as_str(), Some("first-password"));

        unsafe {
            std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_NON_RENEW");
            std::env::remove_var(LEASE_RENEW_WINDOW_SECS_ENV);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_zero_renew_window_disables_proactive_renewal() {
        let _guard = test_lock().await;
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
                    "password": "first-password"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/renew"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var(
                "OPAQUE_TEST_VAULT_TOKEN_RENEW_WINDOW_ZERO",
                "vault-token-123",
            );
            std::env::set_var(LEASE_RENEW_WINDOW_SECS_ENV, "0");
        }
        let resolver = VaultResolver::with_token_ref(
            client,
            "env:OPAQUE_TEST_VAULT_TOKEN_RENEW_WINDOW_ZERO".into(),
        );

        let first = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        let second = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(first.as_str(), Some("first-password"));
        assert_eq!(second.as_str(), Some("first-password"));

        unsafe {
            std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_RENEW_WINDOW_ZERO");
            std::env::remove_var(LEASE_RENEW_WINDOW_SECS_ENV);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_refreshes_after_lease_expiry() {
        let _guard = test_lock().await;
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

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_revokes_expired_lease_before_refresh() {
        let _guard = test_lock().await;
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

        unsafe { std::env::set_var("OPAQUE_TEST_VAULT_TOKEN_REVOKE", "vault-token-123") };
        let resolver = VaultResolver::with_token_ref(
            client.clone(),
            "env:OPAQUE_TEST_VAULT_TOKEN_REVOKE".into(),
        );
        let first = resolver
            .resolve("vault:database/creds/readonly#password")
            .unwrap();
        assert_eq!(first.as_str(), Some("first-password"));

        sleep(Duration::from_secs(2)).await;

        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/v1/sys/leases/revoke"))
            .and(header("x-vault-token", "vault-token-123"))
            .and(body_json(serde_json::json!({
                "lease_id": "database/creds/readonly/a1"
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
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

        unsafe { std::env::remove_var("OPAQUE_TEST_VAULT_TOKEN_REVOKE") };
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "snapshot_tests.rs"]
mod snapshot_tests;
