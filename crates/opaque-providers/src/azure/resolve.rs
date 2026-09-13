//! Resolve only the configured Azure vault into a zeroizing consumer value.
use super::client::{AzureKeyVaultClient, validate_name, validate_vault, validate_version};
use opaque_core::{
    resolver::{ResolveError, SecretResolver},
    secret::SecretValue,
};
pub struct AzureResolver {
    client: AzureKeyVaultClient,
}
impl std::fmt::Debug for AzureResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureResolver").finish_non_exhaustive()
    }
}
impl AzureResolver {
    pub fn new(client: AzureKeyVaultClient) -> Self {
        Self { client }
    }
    fn parse_ref(value: &str) -> Result<(&str, &str, Option<&str>), ResolveError> {
        let rest = value
            .strip_prefix("azure:")
            .ok_or_else(|| ResolveError::UnknownScheme(value.into()))?;
        let parts: Vec<_> = rest.split('/').collect();
        if !(2..=3).contains(&parts.len())
            || validate_vault(parts[0]).is_err()
            || validate_name(parts[1]).is_err()
            || parts.get(2).is_some_and(|v| validate_version(v).is_err())
        {
            return Err(ResolveError::AzureError(
                "azure:".into(),
                "expected azure:vault/secret[/version] with valid resource IDs".into(),
            ));
        }
        Ok((parts[0], parts[1], parts.get(2).copied()))
    }
}
impl SecretResolver for AzureResolver {
    fn resolve(&self, value: &str) -> Result<SecretValue, ResolveError> {
        let (vault, secret, version) = Self::parse_ref(value)?;
        if self.client.vault_name() != Some(vault) {
            return Err(ResolveError::AzureError(
                "azure:".into(),
                "reference does not match the configured vault".into(),
            ));
        }
        let run = async {
            let mut result = self
                .client
                .get_secret(secret, version)
                .await
                .map_err(|e| e.to_string())?;
            if self
                .client
                .resource_name(&result.id, "secrets")
                .map_err(|e| e.to_string())?
                != secret
            {
                return Err("Azure returned a different secret".into());
            }
            let bytes = result.value.take().ok_or("Azure secret has no value")?;
            Ok(SecretValue::from_string(bytes))
        };
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(run))
            }
            Ok(_) => Err("Azure resolver requires a broker worker or multi-thread runtime".into()),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "Azure runtime unavailable".to_owned())
                .and_then(|runtime| runtime.block_on(run)),
        };
        result.map_err(|message| ResolveError::AzureError("azure:".into(), message))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refs_are_exact_and_safe() {
        assert_eq!(
            AzureResolver::parse_ref("azure:myvault/my-secret").unwrap(),
            ("myvault", "my-secret", None)
        );
        assert_eq!(
            AzureResolver::parse_ref("azure:myvault/my-secret/abc123")
                .unwrap()
                .2,
            Some("abc123")
        );
        for value in [
            "azure:",
            "azure:vault",
            "azure:vault/",
            "azure:vault/../x",
            "azure:vault/secret/%2f",
            "azure:vault/secret/1/x",
            "azure:vault/secret/1?x",
            "azure:vault#evil/secret",
            "azure:../secret",
        ] {
            assert!(AzureResolver::parse_ref(value).is_err(), "{value}");
        }
        assert!(matches!(
            AzureResolver::parse_ref("env:X"),
            Err(ResolveError::UnknownScheme(_))
        ));
    }
    #[test]
    fn mismatched_vault_rejected_without_runtime_or_credentials() {
        let client = AzureKeyVaultClient::new(
            "https://configured.vault.azure.net",
            "tenant".into(),
            "client".into(),
            "env:MISSING_CLOUD_TEST_SECRET".into(),
        )
        .unwrap();
        let error = AzureResolver::new(client)
            .resolve("azure:foreign/test")
            .unwrap_err()
            .to_string();
        assert!(error.contains("configured vault"));
    }
}
