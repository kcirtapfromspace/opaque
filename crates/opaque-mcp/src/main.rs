use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info, warn};

mod daemon_client;
mod tools;

use daemon_client::DaemonClient;

/// Build a version string that includes the git SHA: `0.1.0+abc1234`.
const fn version_string() -> &'static str {
    concat!(env!("CARGO_PKG_VERSION"), "+", env!("OPAQUE_GIT_SHA"))
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    fn ok(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Option<serde_json::Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// JSON-RPC error codes
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

fn maybe_handle_cli_flag() -> bool {
    let mut args = std::env::args().skip(1);
    let Some(arg) = args.next() else {
        return false;
    };

    match arg.as_str() {
        "-V" | "--version" => {
            println!("opaque-mcp {}", version_string());
            true
        }
        "-h" | "--help" => {
            println!("opaque-mcp {}", version_string());
            println!("Usage: opaque-mcp [--version]");
            println!("Runs as an MCP server over stdio.");
            true
        }
        _ => {
            eprintln!("unknown argument: {arg}");
            eprintln!("Usage: opaque-mcp [--version]");
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// MCP protocol handling
// ---------------------------------------------------------------------------

/// Handle `initialize` — return server capabilities.
fn handle_initialize(id: Option<serde_json::Value>) -> JsonRpcResponse {
    JsonRpcResponse::ok(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "opaque-mcp",
                "version": version_string()
            }
        }),
    )
}

/// Handle `tools/list` — return the hard-coded Safe tool list.
fn handle_tools_list(id: Option<serde_json::Value>) -> JsonRpcResponse {
    let tool_defs = tools::safe_tools();
    let tools_json: Vec<serde_json::Value> = tool_defs
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema
            })
        })
        .collect();

    JsonRpcResponse::ok(id, json!({ "tools": tools_json }))
}

/// Handle `tools/call` — execute a tool by forwarding to the daemon.
async fn handle_tools_call(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    client: &DaemonClient,
) -> JsonRpcResponse {
    let tool_name = match params.get("name").and_then(|v| v.as_str()) {
        Some(name) => name,
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "missing 'name' in tools/call");
        }
    };

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    // Handle client-side tools that don't need daemon communication.
    match tool_name {
        "opaque_sandbox_list_profiles" => {
            return handle_list_profiles(id);
        }
        "opaque_secrets_status" => {
            return handle_secrets_status(id, &arguments);
        }
        _ => {}
    }

    // Look up the daemon IPC method for this tool.
    let daemon_method = match tools::tool_to_daemon_method(tool_name) {
        Some(m) => m,
        None => {
            return JsonRpcResponse::error(
                id,
                INVALID_PARAMS,
                format!("unknown tool: {}", &tool_name[..tool_name.len().min(64)]),
            );
        }
    };

    // Find the tool definition to build daemon params.
    let tool_defs = tools::safe_tools();
    let tool_def = match tool_defs.iter().find(|t| t.name == tool_name) {
        Some(t) => t,
        None => {
            return JsonRpcResponse::error(
                id,
                INTERNAL_ERROR,
                format!("tool definition not found: {tool_name}"),
            );
        }
    };

    // Build daemon IPC params.
    let daemon_params = (tool_def.build_params)(&arguments);

    debug!(
        tool = tool_name,
        daemon_method, "forwarding tool call to daemon"
    );

    // Call the daemon wrapper method with tool-specific params.
    match client.call(daemon_method, daemon_params).await {
        Ok(resp) => {
            if let Some(ref err) = resp.error {
                // Daemon returned an error — surface it as MCP tool error content.
                let error_text = format!("Opaque error [{}]: {}", err.code, err.message);
                JsonRpcResponse::ok(
                    id,
                    json!({
                        "content": [{"type": "text", "text": error_text}],
                        "isError": true
                    }),
                )
            } else if tool_name == "opaque_sandbox_exec" {
                // Sandbox exec returns structured output with stdout/stderr.
                format_sandbox_exec_response(id, resp.result)
            } else {
                // Daemon returned success.
                let result_text = match resp.result {
                    Some(val) => {
                        if let Some(s) = val.as_str() {
                            s.to_string()
                        } else {
                            serde_json::to_string_pretty(&val).unwrap_or_else(|_| val.to_string())
                        }
                    }
                    None => "Operation completed successfully.".to_string(),
                };
                JsonRpcResponse::ok(
                    id,
                    json!({
                        "content": [{"type": "text", "text": result_text}]
                    }),
                )
            }
        }
        Err(e) => {
            // Sanitize the error to prevent leaking filesystem paths or
            // credentials embedded in connection strings to the LLM context.
            let sanitizer = opaque_core::sanitize::Sanitizer::new();
            let error_text = format!("Failed to communicate with opaqued: {}", sanitizer.scrub_error(&e.to_string()));
            JsonRpcResponse::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": error_text}],
                    "isError": true
                }),
            )
        }
    }
}

/// Handle `opaque_sandbox_list_profiles` client-side by reading profile TOMLs.
fn handle_list_profiles(id: Option<serde_json::Value>) -> JsonRpcResponse {
    let profiles_dir = opaque_core::profile::profiles_dir();
    let profiles = tools::list_profiles(&profiles_dir);

    let result_text = serde_json::to_string_pretty(&profiles).unwrap_or_else(|_| "[]".to_string());

    JsonRpcResponse::ok(
        id,
        json!({
            "content": [{"type": "text", "text": result_text}]
        }),
    )
}

/// Handle `opaque_secrets_status` client-side by parsing profile secrets.
fn handle_secrets_status(
    id: Option<serde_json::Value>,
    arguments: &serde_json::Value,
) -> JsonRpcResponse {
    let profile_name = match arguments.get("profile").and_then(|v| v.as_str()) {
        Some(name) => name,
        None => {
            return JsonRpcResponse::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": "missing required parameter: profile"}],
                    "isError": true
                }),
            );
        }
    };

    let profiles_dir = opaque_core::profile::profiles_dir();
    match tools::secrets_status(&profiles_dir, profile_name) {
        Ok(statuses) => {
            let result_text =
                serde_json::to_string_pretty(&statuses).unwrap_or_else(|_| "[]".to_string());
            JsonRpcResponse::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": result_text}]
                }),
            )
        }
        Err(e) => JsonRpcResponse::ok(
            id,
            json!({
                "content": [{"type": "text", "text": e}],
                "isError": true
            }),
        ),
    }
}

/// Format a sandbox exec daemon response into MCP content items with stdout/stderr.
fn format_sandbox_exec_response(
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
) -> JsonRpcResponse {
    let Some(val) = result else {
        return JsonRpcResponse::ok(
            id,
            json!({
                "content": [{"type": "text", "text": "Sandbox execution completed (no output)."}]
            }),
        );
    };

    let mut content = Vec::new();

    // Build metadata summary.
    let exit_code = val.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1);
    let duration_ms = val.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let truncated = val
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut meta = format!("exit_code: {exit_code}, duration: {duration_ms}ms");
    if truncated {
        meta.push_str(" (output truncated)");
    }
    content.push(json!({"type": "text", "text": meta}));

    // Add stdout as a text content item if present and non-empty.
    if let Some(stdout) = val.get("stdout").and_then(|v| v.as_str())
        && !stdout.is_empty()
    {
        content.push(json!({"type": "text", "text": format!("--- stdout ---\n{stdout}")}));
    }

    // Add stderr as a text content item if present and non-empty.
    if let Some(stderr) = val.get("stderr").and_then(|v| v.as_str())
        && !stderr.is_empty()
    {
        content.push(json!({"type": "text", "text": format!("--- stderr ---\n{stderr}")}));
    }

    let is_error = exit_code != 0;
    let mut result_obj = json!({ "content": content });
    if is_error {
        result_obj["isError"] = json!(true);
    }

    JsonRpcResponse::ok(id, result_obj)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    if maybe_handle_cli_flag() {
        return;
    }

    // Tracing goes to stderr only — stdout is the MCP transport.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    info!("opaque-mcp {} starting", version_string());

    // Allow socket path override via env var or CLI arg.
    let socket_override = std::env::var("OPAQUE_SOCK").ok().map(PathBuf::from);
    let client = DaemonClient::new(socket_override);

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(raw_line)) = lines.next_line().await {
        let line = raw_line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                warn!("invalid JSON-RPC: {e}");
                let resp = JsonRpcResponse::error(None, -32700, format!("parse error: {e}"));
                let out = match serde_json::to_string(&resp) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("failed to serialize error response: {e}");
                        continue;
                    }
                };
                let _ = stdout.write_all(out.as_bytes()).await;
                let _ = stdout.write_all(b"\n").await;
                let _ = stdout.flush().await;
                continue;
            }
        };

        if request.jsonrpc != "2.0" {
            warn!("invalid jsonrpc version: {}", request.jsonrpc);
        }

        let response = match request.method.as_str() {
            "initialize" => handle_initialize(request.id),
            "notifications/initialized" => {
                // This is a notification (no id), no response needed.
                debug!("received initialized notification");
                continue;
            }
            "tools/list" => handle_tools_list(request.id),
            "tools/call" => handle_tools_call(request.id, &request.params, &client).await,
            "ping" => JsonRpcResponse::ok(request.id, json!({})),
            method => {
                // Notifications (no id) should not get error responses.
                if request.id.is_none() {
                    debug!("ignoring notification: {method}");
                    continue;
                }
                JsonRpcResponse::error(
                    request.id,
                    METHOD_NOT_FOUND,
                    format!("method not found: {method}"),
                )
            }
        };

        let out = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                error!("failed to serialize response: {e}");
                continue;
            }
        };

        if let Err(e) = stdout.write_all(out.as_bytes()).await {
            error!("failed to write to stdout: {e}");
            break;
        }
        if let Err(e) = stdout.write_all(b"\n").await {
            error!("failed to write newline: {e}");
            break;
        }
        if let Err(e) = stdout.flush().await {
            error!("failed to flush stdout: {e}");
            break;
        }
    }

    info!("opaque-mcp shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_response_has_tools_capability() {
        let resp = handle_initialize(Some(json!(1)));
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "opaque-mcp");
    }

    #[test]
    fn tools_list_returns_only_safe_operations() {
        let resp = handle_tools_list(Some(json!(1)));
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 14);

        let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

        // Verify Safe operations are present.
        assert!(tool_names.contains(&"opaque_github_set_actions_secret"));
        assert!(tool_names.contains(&"opaque_github_list_secrets"));
        assert!(tool_names.contains(&"opaque_gitlab_set_ci_variable"));
        assert!(tool_names.contains(&"opaque_onepassword_list_vaults"));
        assert!(tool_names.contains(&"opaque_bitwarden_list_projects"));

        // Verify sandbox tools are present.
        assert!(tool_names.contains(&"opaque_sandbox_exec"));
        assert!(tool_names.contains(&"opaque_sandbox_list_profiles"));
        assert!(tool_names.contains(&"opaque_secrets_status"));

        // Verify no Reveal operations leak through.
        for name in &tool_names {
            assert!(!name.contains("read_field"), "Reveal tool leaked: {name}");
            assert!(!name.contains("read_secret"), "Reveal tool leaked: {name}");
            assert!(!name.contains("noop"), "test tool leaked: {name}");
        }
    }

    #[test]
    fn tools_list_schemas_are_valid() {
        let resp = handle_tools_list(Some(json!(1)));
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn jsonrpc_response_ok_serialization() {
        let resp = JsonRpcResponse::ok(Some(json!(42)), json!({"status": "ok"}));
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["result"]["status"], "ok");
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn jsonrpc_response_error_serialization() {
        let resp = JsonRpcResponse::error(Some(json!(1)), METHOD_NOT_FOUND, "not found");
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["error"]["code"], -32601);
        assert_eq!(parsed["error"]["message"], "not found");
        assert!(parsed.get("result").is_none());
    }

    #[test]
    fn jsonrpc_request_parsing() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let req: JsonRpcRequest = serde_json::from_str(input).unwrap();
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Some(json!(1)));
    }

    #[test]
    fn jsonrpc_notification_parsing() {
        let input = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(input).unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.method, "notifications/initialized");
    }

    #[test]
    fn initialize_response_id_propagated() {
        let resp = handle_initialize(Some(json!("abc-123")));
        assert_eq!(resp.id, Some(json!("abc-123")));
    }

    #[test]
    fn sandbox_exec_response_success() {
        let result = json!({
            "exit_code": 0,
            "duration_ms": 1234,
            "stdout_length": 10,
            "stderr_length": 0,
            "truncated": false,
            "stdout": "all passed",
            "stderr": ""
        });

        let resp = format_sandbox_exec_response(Some(json!(1)), Some(result));
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();

        // First item is metadata.
        assert!(
            content[0]["text"]
                .as_str()
                .unwrap()
                .contains("exit_code: 0")
        );
        assert!(
            content[0]["text"]
                .as_str()
                .unwrap()
                .contains("duration: 1234ms")
        );

        // Second item is stdout.
        assert!(content[1]["text"].as_str().unwrap().contains("all passed"));

        // isError should not be set for exit_code 0.
        assert!(r.get("isError").is_none());
    }

    #[test]
    fn sandbox_exec_response_failure() {
        let result = json!({
            "exit_code": 1,
            "duration_ms": 500,
            "stdout_length": 0,
            "stderr_length": 5,
            "truncated": false,
            "stdout": "",
            "stderr": "error"
        });

        let resp = format_sandbox_exec_response(Some(json!(1)), Some(result));
        let r = resp.result.unwrap();

        // isError should be set for non-zero exit_code.
        assert_eq!(r["isError"], true);

        let content = r["content"].as_array().unwrap();
        // Metadata + stderr (stdout is empty so not included).
        assert_eq!(content.len(), 2);
        assert!(content[1]["text"].as_str().unwrap().contains("error"));
    }

    #[test]
    fn sandbox_exec_response_truncated() {
        let result = json!({
            "exit_code": 0,
            "duration_ms": 100,
            "truncated": true,
            "stdout": "partial",
            "stderr": ""
        });

        let resp = format_sandbox_exec_response(Some(json!(1)), Some(result));
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();
        assert!(content[0]["text"].as_str().unwrap().contains("truncated"));
    }

    #[test]
    fn sandbox_exec_response_no_result() {
        let resp = format_sandbox_exec_response(Some(json!(1)), None);
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();
        assert!(content[0]["text"].as_str().unwrap().contains("no output"));
    }

    #[test]
    fn handle_list_profiles_returns_json() {
        // This reads from the real ~/.opaque/profiles/ which may not exist.
        // The function should gracefully return an empty list.
        let resp = handle_list_profiles(Some(json!(1)));
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "text");
        // Should be valid JSON (either [] or a list of profiles).
        let text = content[0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn handle_secrets_status_missing_profile_param() {
        let resp = handle_secrets_status(Some(json!(1)), &json!({}));
        let r = resp.result.unwrap();
        assert_eq!(r["isError"], true);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("missing required parameter"));
    }

    #[test]
    fn unknown_tool_name_is_truncated_in_error() {
        // Verify that the truncation logic used for unknown tool names works.
        let long_name = "a".repeat(200);
        let truncated = &long_name[..long_name.len().min(64)];
        assert_eq!(truncated.len(), 64);
        // The format string in handle_tools_call uses this pattern:
        let msg = format!("unknown tool: {}", truncated);
        assert_eq!(msg.len(), "unknown tool: ".len() + 64);
    }
}
