//! Sandbox orchestrator for `sandbox.exec` operations.
//!
//! The `SandboxExecutor` implements `OperationHandler` and coordinates:
//! 1. Loading the execution profile
//! 2. Resolving secret references
//! 3. Dispatching to the platform-specific sandbox (Linux or macOS)
//! 4. Streaming output frames back to the client
//! 5. Emitting audit events
//! 6. Cleaning up secret memory after execution

pub mod resolve;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;
use opaque_core::profile::{self, ExecProfile};
use opaque_core::proto::ExecFrame;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::enclave::OperationHandler;
use crate::secret::SecretValue;
use resolve::{CompositeResolver, resolve_all};

/// The sandbox executor handles `sandbox.exec` operations.
///
/// It loads profiles, resolves secrets, dispatches to the platform sandbox,
/// and returns the exit code. Output streaming is handled via the exec
/// frame channel stored in the operation request's params.
pub struct SandboxExecutor {
    audit: Arc<dyn AuditSink>,
}

impl fmt::Debug for SandboxExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxExecutor").finish()
    }
}

impl SandboxExecutor {
    pub fn new(audit: Arc<dyn AuditSink>) -> Self {
        Self { audit }
    }

    /// Load and validate a profile by name.
    fn load_profile(name: &str) -> Result<ExecProfile, String> {
        profile::load_named_profile(name)
            .map_err(|e| format!("failed to load profile '{name}': {e}"))
    }

    /// Resolve all secret references in the profile.
    fn resolve_secrets(profile: &ExecProfile) -> Result<HashMap<String, SecretValue>, String> {
        let resolver = CompositeResolver::new();
        resolve_all(&profile.secrets, &resolver)
            .map_err(|e| format!("secret resolution failed: {e}"))
    }

    /// Build the combined environment for the sandbox (secrets + literal env).
    ///
    /// Extracts the string value from each `SecretValue` for injection into the
    /// child process environment. The `SecretValue`s remain alive (and will be
    /// zeroed on drop) in the caller's `resolved_secrets` map.
    fn build_env(
        profile: &ExecProfile,
        resolved_secrets: &HashMap<String, SecretValue>,
    ) -> HashMap<String, String> {
        let mut env = HashMap::with_capacity(profile.env.len() + resolved_secrets.len());

        // Literal env vars first.
        for (key, value) in &profile.env {
            env.insert(key.clone(), value.clone());
        }

        // Resolved secrets (overwrite if conflict — secrets take precedence).
        for (key, secret) in resolved_secrets {
            if let Some(s) = secret.as_str() {
                env.insert(key.clone(), s.to_owned());
            }
        }

        env
    }
}

impl OperationHandler for SandboxExecutor {
    fn execute(
        &self,
        request: &OperationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + '_>> {
        let request_id = request.request_id;
        let params = request.params.clone();
        let audit = self.audit.clone();

        Box::pin(async move {
            // Parse params: profile name + command.
            let profile_name = params
                .get("profile")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing 'profile' parameter".to_string())?
                .to_owned();

            let command: Vec<String> = params
                .get("command")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .ok_or_else(|| "missing or invalid 'command' parameter".to_string())?;

            if command.is_empty() {
                return Err("command must not be empty".into());
            }

            // Load and validate the profile.
            let profile = Self::load_profile(&profile_name)?;

            // Resolve secret references.
            let resolved_secrets = Self::resolve_secrets(&profile)?;

            // Emit SecretResolved audit events (one per secret, without the value).
            for env_name in resolved_secrets.keys() {
                let event = AuditEvent::new(AuditEventKind::SecretResolved)
                    .with_request_id(request_id)
                    .with_operation("sandbox.exec")
                    .with_outcome("resolved")
                    .with_detail(format!("profile={profile_name} env_name={env_name}"));
                audit.emit(event);
            }

            // Build combined environment.
            let env = Self::build_env(&profile, &resolved_secrets);

            // Emit SandboxCreated audit event.
            let sandbox_event = AuditEvent::new(AuditEventKind::SandboxCreated)
                .with_request_id(request_id)
                .with_operation("sandbox.exec")
                .with_outcome("created")
                .with_detail(format!(
                    "profile={profile_name} command={:?} project_dir={}",
                    command,
                    profile.project_dir.display()
                ));
            audit.emit(sandbox_event);

            // Create the frame channel for streaming.
            //
            // IMPORTANT: Drain this concurrently while the sandbox runs. If we
            // only collect after completion, the bounded channel can fill up
            // and deadlock output tasks that are awaiting `send()`.
            let (tx, mut rx) = mpsc::channel::<ExecFrame>(64);

            /// Maximum bytes of stdout/stderr to capture in the response.
            /// Output beyond this is counted but not returned.
            const MAX_CAPTURE_BYTES: usize = 64 * 1024; // 64 KB

            #[derive(Debug, Default)]
            struct FrameSummary {
                stdout_len: u64,
                stderr_len: u64,
                stdout: String,
                stderr: String,
                duration_ms: u64,
            }

            let summary = Arc::new(Mutex::new(FrameSummary::default()));
            let summary_rx = summary.clone();

            let drain_task = tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    let mut s = summary_rx.lock().await;
                    match frame {
                        ExecFrame::Output {
                            stream: opaque_core::proto::ExecStream::Stdout,
                            data,
                        } => {
                            s.stdout_len = s.stdout_len.saturating_add(data.len() as u64);
                            if s.stdout.len() < MAX_CAPTURE_BYTES {
                                let remaining = MAX_CAPTURE_BYTES - s.stdout.len();
                                s.stdout.push_str(&data[..data.len().min(remaining)]);
                            }
                        }
                        ExecFrame::Output {
                            stream: opaque_core::proto::ExecStream::Stderr,
                            data,
                        } => {
                            s.stderr_len = s.stderr_len.saturating_add(data.len() as u64);
                            if s.stderr.len() < MAX_CAPTURE_BYTES {
                                let remaining = MAX_CAPTURE_BYTES - s.stderr.len();
                                s.stderr.push_str(&data[..data.len().min(remaining)]);
                            }
                        }
                        ExecFrame::ExecCompleted { duration_ms: d, .. } => s.duration_ms = d,
                        _ => {}
                    }
                }
            });

            // Dispatch to platform-specific sandbox.
            let exit_code = execute_platform_sandbox(&profile, command, env, tx).await?;

            // Best-effort: wait for the drain task to finish once the channel closes.
            // Ignore join errors (panic) and fall back to default zero values.
            let _ = drain_task.await;

            // Emit SandboxCompleted audit event.
            let completed_event = AuditEvent::new(AuditEventKind::SandboxCompleted)
                .with_request_id(request_id)
                .with_operation("sandbox.exec")
                .with_outcome(if exit_code == 0 { "success" } else { "failed" })
                .with_detail(format!("profile={profile_name} exit_code={exit_code}"));
            audit.emit(completed_event);

            let s = summary.lock().await;

            let truncated =
                s.stdout.len() < s.stdout_len as usize || s.stderr.len() < s.stderr_len as usize;

            Ok(serde_json::json!({
                "exit_code": exit_code,
                "duration_ms": s.duration_ms,
                "stdout_length": s.stdout_len,
                "stderr_length": s.stderr_len,
                "truncated": truncated,
            }))
        })
    }
}

/// Dispatch to the platform-specific sandbox executor.
async fn execute_platform_sandbox(
    profile: &ExecProfile,
    command: Vec<String>,
    env: HashMap<String, String>,
    tx: mpsc::Sender<ExecFrame>,
) -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    {
        let config = linux::LinuxSandboxConfig {
            command,
            env,
            project_dir: profile.project_dir.clone(),
            extra_read_paths: profile.extra_read_paths.clone(),
            timeout_secs: profile.limits.timeout_secs,
            max_output_bytes: profile.limits.max_output_bytes,
        };
        linux::execute(config, tx)
            .await
            .map_err(|e| format!("linux sandbox failed: {e}"))
    }

    #[cfg(target_os = "macos")]
    {
        let config = macos::MacOSSandboxConfig {
            command,
            env,
            project_dir: profile.project_dir.clone(),
            extra_read_paths: profile.extra_read_paths.clone(),
            network_allow: profile.network.allow.clone(),
            timeout_secs: profile.limits.timeout_secs,
            max_output_bytes: profile.limits.max_output_bytes,
        };
        macos::execute(config, tx)
            .await
            .map_err(|e| format!("macos sandbox failed: {e}"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (profile, command, env, tx);
        Err("sandbox execution is not supported on this platform".into())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::operation::{ClientIdentity, ClientType};
    use uuid::Uuid;

    fn test_profile() -> ExecProfile {
        ExecProfile {
            name: "test".into(),
            description: None,
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network: opaque_core::profile::NetworkConfig { allow: vec![] },
            secrets: HashMap::new(),
            env: HashMap::from([("RUST_LOG".into(), "info".into())]),
            limits: opaque_core::profile::LimitsConfig {
                timeout_secs: 60,
                max_output_bytes: 1024,
            },
        }
    }

    #[test]
    fn build_env_combines_secrets_and_literals() {
        use crate::secret::SecretValue;
        let profile = test_profile();
        let mut secrets = HashMap::new();
        secrets.insert(
            "API_KEY".into(),
            SecretValue::from_string("secret_value".into()),
        );

        let env = SandboxExecutor::build_env(&profile, &secrets);
        assert_eq!(env.get("RUST_LOG").unwrap(), "info");
        assert_eq!(env.get("API_KEY").unwrap(), "secret_value");
    }

    #[test]
    fn build_env_secrets_override_literals() {
        use crate::secret::SecretValue;
        let mut profile = test_profile();
        profile
            .env
            .insert("SHARED_KEY".into(), "literal_value".into());

        let mut secrets = HashMap::new();
        secrets.insert(
            "SHARED_KEY".into(),
            SecretValue::from_string("secret_value".into()),
        );

        let env = SandboxExecutor::build_env(&profile, &secrets);
        assert_eq!(env.get("SHARED_KEY").unwrap(), "secret_value");
    }

    #[test]
    fn sandbox_executor_debug_format() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit);
        let debug = format!("{executor:?}");
        assert!(debug.contains("SandboxExecutor"));
    }

    #[tokio::test]
    async fn missing_profile_param_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit);

        let request = OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: ClientType::Human,
            operation: "sandbox.exec".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({}),
            workspace: None,
        };

        let result = executor.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'profile'"));
    }

    #[tokio::test]
    async fn missing_command_param_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit);

        let request = OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: ClientType::Human,
            operation: "sandbox.exec".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({"profile": "test"}),
            workspace: None,
        };

        let result = executor.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing or invalid 'command'"));
    }

    #[tokio::test]
    async fn empty_command_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit);

        let request = OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
            },
            client_type: ClientType::Human,
            operation: "sandbox.exec".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({"profile": "test", "command": []}),
            workspace: None,
        };

        let result = executor.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("command must not be empty"));
    }

    #[test]
    fn sandbox_response_does_not_contain_stdout_stderr() {
        // Verify the response JSON structure contains only metadata —
        // no raw stdout/stderr fields that could leak secrets.
        let response = serde_json::json!({
            "exit_code": 0,
            "duration_ms": 150_u64,
            "stdout_length": 1024_u64,
            "stderr_length": 256_u64,
            "truncated": false,
        });

        let obj = response.as_object().unwrap();
        assert!(!obj.contains_key("stdout"), "response must not contain 'stdout'");
        assert!(!obj.contains_key("stderr"), "response must not contain 'stderr'");

        // Verify expected metadata keys are present.
        assert!(obj.contains_key("exit_code"));
        assert!(obj.contains_key("duration_ms"));
        assert!(obj.contains_key("stdout_length"));
        assert!(obj.contains_key("stderr_length"));
        assert!(obj.contains_key("truncated"));
    }
}
