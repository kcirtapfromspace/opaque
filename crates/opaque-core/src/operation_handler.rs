//! Operation handler trait.
//!
//! Promoted from `opaqued::enclave` so that provider crates (which each
//! implement this trait once per provider) do not need to depend on the
//! `opaqued` binary crate — which, having no `lib.rs`, cannot be depended on
//! by anything.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use serde::Serialize;

use crate::operation::OperationRequest;

type Execution<'a> = Pin<Box<dyn Future<Output = Result<serde_json::Value, String>> + Send + 'a>>;

/// Exact argv for human review and unmatched execve keys. A JSON array retains
/// empty arguments, whitespace, quotes and shell metacharacters without implying
/// shell parsing. Escape direction controls so review cannot hide their effect.
pub fn render_argv(argv: &[String]) -> String {
    escape_direction_controls(&serde_json::to_string(argv).expect("string argv serializes"))
}

/// Quote one review field without losing bytes or allowing a new display line.
pub fn render_review_text(value: &str) -> String {
    escape_direction_controls(&serde_json::to_string(value).expect("string serializes"))
}

fn escape_direction_controls(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| {
            if matches!(ch as u32, 0x061c | 0x200e..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069) {
                format!("\\u{:04x}", ch as u32).chars().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}

/// A daemon-owned action, prepared without resolving credentials or performing
/// effects. Its canonical projection and deferred executor come from the same
/// typed value. The executor consumes that value once, after authorization.
///
/// No raw `OperationRequest` reaches the prepared executor. Handlers must include
/// every execution-relevant default/reference/configuration snapshot in the
/// serialized action, or bind confidential fields with a digest while retaining
/// their original typed value for execution. Preparation is not authorization.
pub struct PreparedOperation<'a> {
    target: HashMap<String, String>,
    secret_ref_names: Vec<String>,
    params: serde_json::Value,
    execute: Execution<'a>,
}

impl fmt::Debug for PreparedOperation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedOperation").finish_non_exhaustive()
    }
}

impl<'a> PreparedOperation<'a> {
    pub fn new<T, F, Fut>(
        action: T,
        target: HashMap<String, String>,
        mut secret_ref_names: Vec<String>,
        run: F,
    ) -> Result<Self, String>
    where
        T: Serialize + Send + 'a,
        F: FnOnce(T) -> Fut + Send + 'a,
        Fut: Future<Output = Result<serde_json::Value, String>> + Send + 'a,
    {
        let params = serde_json::to_value(&action)
            .map_err(|_| "cannot encode prepared action".to_string())?;
        secret_ref_names.sort();
        secret_ref_names.dedup();
        Ok(Self {
            target,
            secret_ref_names,
            params,
            // Do not invoke even the closure until the future is polled. This
            // prevents credential resolution in a closure's synchronous prefix
            // from occurring during preparation.
            execute: Box::pin(async move { run(action).await }),
        })
    }

    pub fn target(&self) -> &HashMap<String, String> {
        &self.target
    }

    pub fn secret_ref_names(&self) -> &[String] {
        &self.secret_ref_names
    }

    pub fn params(&self) -> &serde_json::Value {
        &self.params
    }

    pub fn execute(self) -> Execution<'a> {
        self.execute
    }
}

// ---------------------------------------------------------------------------
// Operation handler trait
// ---------------------------------------------------------------------------

/// Trait for operation handlers. Each registered operation has a corresponding
/// handler that performs the actual work.
///
/// Handlers receive the validated request and return a raw JSON payload.
/// The enclave sanitizes the payload before returning it to the client.
pub trait OperationHandler: Send + Sync + fmt::Debug {
    /// Parse, validate and freeze an exact action before policy or approval.
    /// Legacy/unconverted handlers cannot be called through the daemon's generic
    /// route: the default deliberately provides no raw-request fallback.
    fn prepare<'a>(&'a self, _request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        Err("operation has no prepared action implementation".into())
    }

    /// Whether this implementation only supports explicit test endpoints.
    /// Capability status comes from the installed handler, not its name.
    fn fixture_only(&self) -> bool {
        false
    }

    /// Execute the operation. Returns a raw (unsanitized) JSON payload.
    ///
    /// The handler must NOT return secret values in the payload. The sanitizer
    /// provides defense-in-depth, but handlers should be written to avoid
    /// including secrets in the first place.
    fn execute(
        &self,
        request: &OperationRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + '_>,
    > {
        let prepared = self.prepare(request);
        Box::pin(async move { prepared?.execute().await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn command_display_preserves_argument_boundaries_and_exposes_controls() {
        let args = [
            "/bin/sh",
            "-c",
            "echo '$TOKEN'\n",
            "",
            "two words",
            "a\u{202e}b",
        ]
        .map(str::to_owned);
        let display = render_argv(&args);
        assert_eq!(serde_json::from_str::<Vec<String>>(&display).unwrap(), args);
        assert!(!display.contains('\u{202e}'));
        assert!(display.contains("\\u202e"));
        assert_ne!(
            render_argv(&["echo".into(), "a b".into()]),
            render_argv(&["echo".into(), "a".into(), "b".into()])
        );
    }

    #[tokio::test]
    async fn preparation_freezes_typed_action_and_defers_all_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let prepared = PreparedOperation::new(
            vec!["exact-argv".to_string()],
            HashMap::from([("target".into(), "private-target".into())]),
            vec!["ref:b".into(), "ref:a".into(), "ref:b".into()],
            move |action| {
                observed.fetch_add(1, Ordering::SeqCst);
                async move { Ok(serde_json::json!(action)) }
            },
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(prepared.secret_ref_names(), ["ref:a", "ref:b"]);
        assert_eq!(prepared.params(), &serde_json::json!(["exact-argv"]));
        assert!(!format!("{prepared:?}").contains("private-target"));
        assert_eq!(
            prepared.execute().await.unwrap(),
            serde_json::json!(["exact-argv"])
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_prepared_work_does_not_invoke_the_executor() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let prepared = PreparedOperation::new((), HashMap::new(), vec![], move |()| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok(serde_json::Value::Null) }
        })
        .unwrap();
        drop(prepared);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
