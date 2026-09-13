//! Bitwarden Secrets Manager through the official `bws` CLI.
//!
//! `bws` owns machine-token login, organization-key decryption and secret
//! decryption. Opaque invokes only fixed read commands, with a pinned executable,
//! isolated configuration, no persistent login state and bounded output.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use zeroize::{Zeroize, Zeroizing};

pub const BITWARDEN_URL_ENV: &str = "OPAQUE_BITWARDEN_URL";
pub const BITWARDEN_IDENTITY_URL_ENV: &str = "OPAQUE_BITWARDEN_IDENTITY_URL";
pub const BITWARDEN_CLI_PATH_ENV: &str = "OPAQUE_BITWARDEN_CLI_PATH";
pub const DEFAULT_BASE_URL: &str = "https://api.bitwarden.com";
const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors never include child output, tokens, secret values or rejected URLs.
#[derive(Debug, thiserror::Error)]
pub enum BitwardenApiError {
    #[error("Bitwarden requires the official bws CLI; install it or set OPAQUE_BITWARDEN_CLI_PATH")]
    CliUnavailable,
    #[error("Bitwarden bws executable changed; restart the broker and review the new executable")]
    ExecutableChanged,
    #[error(
        "invalid Bitwarden endpoint configuration (HTTPS required; no credentials, query or fragment)"
    )]
    InvalidEndpoint,
    #[error(
        "custom Bitwarden API URL requires OPAQUE_BITWARDEN_IDENTITY_URL (or a self-hosted URL ending in /api)"
    )]
    MissingIdentityEndpoint,
    #[error("failed to create isolated Bitwarden CLI configuration")]
    Configuration,
    #[error(
        "Bitwarden bws command failed (check machine access token, permissions and server configuration)"
    )]
    CommandFailed,
    #[error("Bitwarden bws command timed out")]
    Timeout,
    #[error("Bitwarden bws response exceeds the output limit")]
    OutputLimit,
    #[error("Bitwarden bws returned an invalid response")]
    InvalidResponse,
    #[error("invalid Bitwarden UUID selector")]
    InvalidSelector,
    #[error("Bitwarden resource not found")]
    NotFound,
    #[error("Bitwarden name is ambiguous; use a unique project/key or secret UUID")]
    AmbiguousName,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitwardenProject {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitwardenSecretSummary {
    pub id: String,
    pub key: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct BitwardenSecret {
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default, rename = "projectId")]
    pub project_id: Option<String>,
}

impl std::fmt::Debug for BitwardenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitwardenSecret")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for BitwardenSecret {
    fn drop(&mut self) {
        self.value.zeroize();
        self.note.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct BitwardenClient {
    base_url: String,
    identity_url: String,
    executable: PathBuf,
    executable_sha256: String,
    timeout: Duration,
}

fn validate_endpoint(url: &str) -> Result<String, BitwardenApiError> {
    crate::endpoint::validate_http_endpoint(url).map_err(|_| BitwardenApiError::InvalidEndpoint)?;
    // Official bws enforces HTTPS, including for loopback destinations.
    if !url.starts_with("https://") {
        return Err(BitwardenApiError::InvalidEndpoint);
    }
    Ok(url.trim_end_matches('/').to_owned())
}

fn identity_url(api_url: &str, explicit: Option<&str>) -> Result<String, BitwardenApiError> {
    if let Some(explicit) = explicit {
        return validate_endpoint(explicit);
    }
    match api_url {
        "https://api.bitwarden.com" => Ok("https://identity.bitwarden.com".into()),
        "https://api.bitwarden.eu" => Ok("https://identity.bitwarden.eu".into()),
        _ => api_url
            .strip_suffix("/api")
            .map(|base| format!("{base}/identity"))
            .ok_or(BitwardenApiError::MissingIdentityEndpoint),
    }
}

fn executable_digest(path: &Path) -> Result<String, BitwardenApiError> {
    let mut file = std::fs::File::open(path).map_err(|_| BitwardenApiError::CliUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| BitwardenApiError::CliUnavailable)?;
    if !metadata.is_file() {
        return Err(BitwardenApiError::CliUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(BitwardenApiError::CliUnavailable);
        }
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| BitwardenApiError::CliUnavailable)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(super) fn validate_id(id: &str) -> Result<(), BitwardenApiError> {
    uuid::Uuid::parse_str(id)
        .ok()
        .filter(|id| !id.is_nil())
        .map(|_| ())
        .ok_or(BitwardenApiError::InvalidSelector)
}

impl BitwardenClient {
    pub(super) fn base_url(&self) -> &str {
        &self.base_url
    }
    pub(super) fn identity_url(&self) -> &str {
        &self.identity_url
    }
    pub(super) fn executable_path(&self) -> &Path {
        &self.executable
    }
    pub(super) fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    /// Construct without reading a token or starting the CLI. API and identity
    /// endpoints plus executable identity are frozen before approval.
    pub fn new(base_url: &str) -> Result<Self, BitwardenApiError> {
        let api = validate_endpoint(base_url)?;
        let identity = identity_url(
            &api,
            std::env::var(BITWARDEN_IDENTITY_URL_ENV).ok().as_deref(),
        )?;
        let executable = if let Some(path) = std::env::var_os(BITWARDEN_CLI_PATH_ENV) {
            PathBuf::from(path)
        } else {
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|dir| dir.join(if cfg!(windows) { "bws.exe" } else { "bws" }))
                .find(|path| executable_digest(path).is_ok())
                .ok_or(BitwardenApiError::CliUnavailable)?
        };
        Self::with_executable(&api, &identity, &executable)
    }

    pub(super) fn with_executable(
        api: &str,
        identity: &str,
        executable: &Path,
    ) -> Result<Self, BitwardenApiError> {
        let executable = executable
            .canonicalize()
            .map_err(|_| BitwardenApiError::CliUnavailable)?;
        let executable_sha256 = executable_digest(&executable)?;
        Ok(Self {
            base_url: validate_endpoint(api)?,
            identity_url: validate_endpoint(identity)?,
            executable,
            executable_sha256,
            timeout: COMMAND_TIMEOUT,
        })
    }

    async fn run<T: DeserializeOwned>(
        &self,
        token: &str,
        args: &[&str],
    ) -> Result<T, BitwardenApiError> {
        if token.is_empty() || token.contains('\0') {
            return Err(BitwardenApiError::CommandFailed);
        }
        if executable_digest(&self.executable).map_err(|_| BitwardenApiError::ExecutableChanged)?
            != self.executable_sha256
        {
            return Err(BitwardenApiError::ExecutableChanged);
        }
        // The official CLI reads this TOML schema. Explicit API/identity values
        // prevent ambient bws profiles or BWS_SERVER_URL changing destinations.
        // Quoted booleans support released bws 2.1.0 and newer parsers.
        let mut config =
            tempfile::NamedTempFile::new().map_err(|_| BitwardenApiError::Configuration)?;
        let config_text = format!(
            "[profiles.opaque]\nserver_api = {}\nserver_identity = {}\nstate_opt_out = \"true\"\n",
            serde_json::to_string(&self.base_url).map_err(|_| BitwardenApiError::Configuration)?,
            serde_json::to_string(&self.identity_url)
                .map_err(|_| BitwardenApiError::Configuration)?
        );
        config
            .write_all(config_text.as_bytes())
            .map_err(|_| BitwardenApiError::Configuration)?;
        config
            .flush()
            .map_err(|_| BitwardenApiError::Configuration)?;
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .env_clear()
            .env("BWS_ACCESS_TOKEN", token)
            .arg("--config-file")
            .arg(config.path())
            .args(["--profile", "opaque", "--output", "json", "--color", "no"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        let mut child = command
            .spawn()
            .map_err(|_| BitwardenApiError::CliUnavailable)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(BitwardenApiError::CommandFailed)?;
        let mut output = Zeroizing::new(Vec::new());
        let result = tokio::time::timeout(self.timeout, async {
            stdout
                .take(MAX_OUTPUT_BYTES + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|_| BitwardenApiError::CommandFailed)?;
            if output.len() as u64 > MAX_OUTPUT_BYTES {
                return Err(BitwardenApiError::OutputLimit);
            }
            let status = child
                .wait()
                .await
                .map_err(|_| BitwardenApiError::CommandFailed)?;
            if !status.success() {
                return Err(BitwardenApiError::CommandFailed);
            }
            serde_json::from_slice(&output).map_err(|_| BitwardenApiError::InvalidResponse)
        })
        .await;
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                let _ = child.kill().await;
                Err(error)
            }
            Err(_) => {
                let _ = child.kill().await;
                Err(BitwardenApiError::Timeout)
            }
        }
    }

    pub async fn list_projects(
        &self,
        token: &str,
    ) -> Result<Vec<BitwardenProject>, BitwardenApiError> {
        self.run(token, &["project", "list"]).await
    }

    pub async fn list_secrets(
        &self,
        token: &str,
        project_id: Option<&str>,
    ) -> Result<Vec<BitwardenSecretSummary>, BitwardenApiError> {
        let mut args = vec!["secret", "list"];
        if let Some(id) = project_id {
            validate_id(id)?;
            args.push(id);
        }
        // Deserialize metadata only; returned plaintext values/notes are skipped
        // by serde and the complete raw stdout buffer is zeroized on drop.
        self.run(token, &args).await
    }

    pub async fn get_secret(
        &self,
        token: &str,
        secret_id: &str,
    ) -> Result<BitwardenSecret, BitwardenApiError> {
        validate_id(secret_id)?;
        let secret: BitwardenSecret = self.run(token, &["secret", "get", secret_id]).await?;
        if uuid::Uuid::parse_str(&secret.id).ok() != uuid::Uuid::parse_str(secret_id).ok() {
            return Err(BitwardenApiError::InvalidResponse);
        }
        Ok(secret)
    }

    pub async fn find_project_by_name(
        &self,
        token: &str,
        name: &str,
    ) -> Result<String, BitwardenApiError> {
        let projects = self.list_projects(token).await?;
        unique_id(
            projects
                .into_iter()
                .filter(|p| p.name == name)
                .map(|p| p.id),
        )
    }

    pub async fn find_secret_by_key(
        &self,
        token: &str,
        project_id: &str,
        key: &str,
    ) -> Result<String, BitwardenApiError> {
        let secrets = self.list_secrets(token, Some(project_id)).await?;
        unique_id(secrets.into_iter().filter(|s| s.key == key).map(|s| s.id))
    }
}

fn unique_id(mut ids: impl Iterator<Item = String>) -> Result<String, BitwardenApiError> {
    let id = ids.next().ok_or(BitwardenApiError::NotFound)?;
    if ids.next().is_some() {
        return Err(BitwardenApiError::AmbiguousName);
    }
    validate_id(&id)?;
    Ok(id)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "client_tests.rs"]
mod tests;
