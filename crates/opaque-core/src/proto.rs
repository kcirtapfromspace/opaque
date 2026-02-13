use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorObj {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObj>,
}

impl Response {
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            id: Some(id),
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Option<u64>, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(ErrorObj {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming exec frames
// ---------------------------------------------------------------------------

/// A streaming frame for `sandbox.exec` operations.
///
/// The daemon sends multiple `Response` frames with the same `id` during exec:
/// 1. `Started` — sandbox created, child process launched
/// 2. `Output` — stdout/stderr data chunks (may be many)
/// 3. `Completed` — child exited, with exit code and duration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecFrame {
    /// The sandbox was created and the child process started.
    ExecStarted {
        /// PID of the child process (inside the sandbox).
        pid: u32,
    },
    /// A chunk of output from the child process.
    Output {
        /// Which output stream this data came from.
        stream: ExecStream,
        /// The output data (UTF-8 text).
        data: String,
    },
    /// The child process has exited.
    ExecCompleted {
        /// Exit code of the child process.
        exit_code: i32,
        /// Wall-clock duration of the execution in milliseconds.
        duration_ms: u64,
    },
}

/// Output stream identifier for exec frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecStream {
    Stdout,
    Stderr,
}

impl std::fmt::Display for ExecStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdout => write!(f, "stdout"),
            Self::Stderr => write!(f, "stderr"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_frame_started_roundtrip() {
        let frame = ExecFrame::ExecStarted { pid: 12345 };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "exec_started");
        assert_eq!(json["pid"], 12345);

        let parsed: ExecFrame = serde_json::from_value(json).unwrap();
        assert!(matches!(parsed, ExecFrame::ExecStarted { pid: 12345 }));
    }

    #[test]
    fn exec_frame_output_roundtrip() {
        let frame = ExecFrame::Output {
            stream: ExecStream::Stdout,
            data: "hello world\n".into(),
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "output");
        assert_eq!(json["stream"], "stdout");
        assert_eq!(json["data"], "hello world\n");

        let parsed: ExecFrame = serde_json::from_value(json).unwrap();
        assert!(matches!(
            parsed,
            ExecFrame::Output {
                stream: ExecStream::Stdout,
                ..
            }
        ));
    }

    #[test]
    fn exec_frame_stderr_output() {
        let frame = ExecFrame::Output {
            stream: ExecStream::Stderr,
            data: "error: something failed\n".into(),
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["stream"], "stderr");
    }

    #[test]
    fn exec_frame_completed_roundtrip() {
        let frame = ExecFrame::ExecCompleted {
            exit_code: 0,
            duration_ms: 4523,
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "exec_completed");
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["duration_ms"], 4523);

        let parsed: ExecFrame = serde_json::from_value(json).unwrap();
        assert!(matches!(
            parsed,
            ExecFrame::ExecCompleted {
                exit_code: 0,
                duration_ms: 4523,
            }
        ));
    }

    #[test]
    fn exec_frame_nonzero_exit_code() {
        let frame = ExecFrame::ExecCompleted {
            exit_code: 1,
            duration_ms: 100,
        };
        let json = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["exit_code"], 1);
    }

    #[test]
    fn exec_stream_display() {
        assert_eq!(format!("{}", ExecStream::Stdout), "stdout");
        assert_eq!(format!("{}", ExecStream::Stderr), "stderr");
    }

    #[test]
    fn response_ok_roundtrip() {
        let resp = Response::ok(1, serde_json::json!({"status": "ok"}));
        assert_eq!(resp.id, Some(1));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn response_err_roundtrip() {
        let resp = Response::err(Some(2), "test_code", "test message");
        assert_eq!(resp.id, Some(2));
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, "test_code");
        assert_eq!(err.message, "test message");
    }

    #[test]
    fn exec_frame_as_response_result() {
        let frame = ExecFrame::ExecStarted { pid: 42 };
        let value = serde_json::to_value(&frame).unwrap();
        let resp = Response::ok(1, value);
        let result = resp.result.unwrap();
        assert_eq!(result["type"], "exec_started");
        assert_eq!(result["pid"], 42);
    }
}
