//! Resolve a GCP secret directly into zeroizing consumer custody, never operation output.
use super::client::{GcpSecretManagerClient, validate_project, validate_secret, validate_version};
use base64::Engine;
use opaque_core::{
    resolver::{ResolveError, SecretResolver},
    secret::SecretValue,
};
pub struct GcpResolver {
    client: GcpSecretManagerClient,
}
impl std::fmt::Debug for GcpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpResolver").finish_non_exhaustive()
    }
}
impl GcpResolver {
    pub fn new(client: GcpSecretManagerClient) -> Self {
        Self { client }
    }
    fn parse_ref(value: &str) -> Result<(&str, &str, &str), ResolveError> {
        let rest = value
            .strip_prefix("gcp:")
            .ok_or_else(|| ResolveError::UnknownScheme(value.into()))?;
        let parts: Vec<_> = rest.split('/').collect();
        if !(2..=3).contains(&parts.len())
            || validate_project(parts[0]).is_err()
            || validate_secret(parts[1]).is_err()
            || parts.get(2).is_some_and(|v| validate_version(v).is_err())
        {
            return Err(ResolveError::GcpError(
                "gcp:".into(),
                "expected gcp:project/secret[/version] with valid resource IDs".into(),
            ));
        }
        Ok((
            parts[0],
            parts[1],
            parts.get(2).copied().unwrap_or("latest"),
        ))
    }
}
impl SecretResolver for GcpResolver {
    fn resolve(&self, value: &str) -> Result<SecretValue, ResolveError> {
        let (project, secret, version) = Self::parse_ref(value)?;
        let run = async {
            let token = self
                .client
                .get_access_token()
                .await
                .map_err(|e| e.to_string())?;
            let response = self
                .client
                .access_secret_version(&token, project, secret, version)
                .await
                .map_err(|e| e.to_string())?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&response.payload.data)
                .map_err(|_| "invalid GCP secret encoding".to_owned())?;
            Ok(SecretValue::new(bytes))
        };
        // Sync consumers can run inside the broker's multi-thread runtime or on
        // a plain worker thread. Never panic on a missing/current-thread runtime.
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(run))
            }
            Ok(_) => Err("GCP resolver requires a broker worker or multi-thread runtime".into()),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "GCP runtime unavailable".to_owned())
                .and_then(|runtime| runtime.block_on(run)),
        };
        result.map_err(|message| ResolveError::GcpError("gcp:".into(), message))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refs_validate_every_segment() {
        assert_eq!(
            GcpResolver::parse_ref("gcp:123456789012/my-secret").unwrap(),
            ("123456789012", "my-secret", "latest")
        );
        assert_eq!(
            GcpResolver::parse_ref("gcp:123456789012/my-secret/12")
                .unwrap()
                .2,
            "12"
        );
        for value in [
            "gcp:",
            "gcp:p",
            "gcp:named-project/secret",
            "gcp:123456789012/s/",
            "gcp:123456789012/s/1/extra",
            "gcp:123456789012/../1",
            "gcp:123456789012/s?x/1",
            "gcp:123456789012/s/%2f",
            "gcp:123456789012/s/1#x",
            "gcp:p\\evil/s",
            "gcp:/s",
        ] {
            assert!(GcpResolver::parse_ref(value).is_err(), "{value}");
        }
        assert!(matches!(
            GcpResolver::parse_ref("env:X"),
            Err(ResolveError::UnknownScheme(_))
        ));
    }
}
