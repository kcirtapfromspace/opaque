//! Bounded MCP 2025-06-18 Streamable HTTP subset. One connection destination,
//! one tool invocation, no redirects/retries/proxies or server-initiated work.
use super::unavailable;
use opaque_core::mcp::{OutputPolicy, PROTOCOL_VERSION, PreparedCall};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub struct Outcome {
    pub state: &'static str,
    pub code: &'static str,
    pub response_sha256: Option<String>,
    pub response_bytes: Option<usize>,
    pub output: Option<std::collections::BTreeMap<String, Value>>,
    pub disclosure: Option<&'static str>,
    pub dispatched: bool,
}
impl Outcome {
    pub fn rejected(code: &'static str) -> Self {
        Self {
            state: "rejected",
            code,
            response_sha256: None,
            response_bytes: None,
            output: None,
            disclosure: None,
            dispatched: false,
        }
    }
    fn unknown() -> Self {
        Self {
            state: "unknown",
            code: "outcome_unknown",
            response_sha256: None,
            response_bytes: None,
            output: None,
            disclosure: None,
            dispatched: true,
        }
    }
}
pub fn validate_fixture_origin(origin: &str) -> Result<(), String> {
    let u = reqwest::Url::parse(origin).map_err(|_| unavailable())?;
    if u.scheme() != "http"
        || u.host_str() != Some("127.0.0.1")
        || u.port().is_none()
        || u.path() != "/"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(unavailable());
    }
    Ok(())
}
/// Fail closed for non-global ranges, including mapped IPv4 and translation/
/// tunnel ranges. DNS answers are vetted once and pinned in the client resolver.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let a = v.octets();
            !(a[0] == 0
                || a[0] == 10
                || a[0] == 127
                || a[0] >= 224
                || (a[0] == 100 && (64..=127).contains(&a[1]))
                || (a[0] == 169 && a[1] == 254)
                || (a[0] == 172 && (16..=31).contains(&a[1]))
                || (a[0] == 192 && (a[1] == 0 || a[1] == 168))
                || (a[0] == 198 && (a[1] == 18 || a[1] == 19 || a[1] == 51))
                || (a[0] == 203 && a[1] == 0))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
        }
    }
}
async fn client(
    call: &PreparedCall,
    fixture: Option<&str>,
) -> Result<(reqwest::Client, String), String> {
    let route = call.route();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_millis(route.timeout_ms))
        .timeout(Duration::from_millis(route.timeout_ms));
    let url = if let Some(origin) = fixture {
        validate_fixture_origin(origin)?;
        format!("{}{}", origin.trim_end_matches('/'), route.endpoint.path)
    } else {
        let addresses: Vec<SocketAddr> =
            tokio::net::lookup_host((route.endpoint.host.as_str(), 443))
                .await
                .map_err(|_| unavailable())?
                .collect();
        if addresses.is_empty()
            || addresses.len() > 16
            || addresses.iter().any(|a| !public_ip(a.ip()))
        {
            return Err(unavailable());
        }
        builder = builder
            .https_only(true)
            .resolve_to_addrs(&route.endpoint.host, &addresses);
        format!("https://{}{}", route.endpoint.host, route.endpoint.path)
    };
    Ok((builder.build().map_err(|_| unavailable())?, url))
}
async fn send(
    client: &reqwest::Client,
    url: &str,
    credential: &str,
    session: Option<&str>,
    message: Value,
    limit: usize,
    request_limit: usize,
) -> Result<(Value, Option<String>, Vec<u8>), String> {
    let bytes = serde_json::to_vec(&message).map_err(|_| unavailable())?;
    if bytes.len() > request_limit {
        return Err(unavailable());
    }
    let mut req = client
        .post(url)
        .bearer_auth(credential)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", PROTOCOL_VERSION)
        .body(bytes);
    if let Some(session) = session {
        req = req.header("Mcp-Session-Id", session);
    }
    let mut response = req.send().await.map_err(|_| unavailable())?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|len| len > limit as u64)
    {
        return Err(unavailable());
    }
    let notification = message.get("id").is_none();
    if notification && response.status() != reqwest::StatusCode::ACCEPTED {
        return Err(unavailable());
    }
    let returned_session = response
        .headers()
        .get("Mcp-Session-Id")
        .map(|h| h.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| unavailable())?;
    if returned_session.as_ref().is_some_and(|s| {
        s.is_empty() || s.len() > 256 || !s.bytes().all(|b| (b'!'..=b'~').contains(&b))
    }) {
        return Err(unavailable());
    }
    if session.is_some()
        && returned_session
            .as_deref()
            .is_some_and(|s| Some(s) != session)
    {
        return Err(unavailable());
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len() + chunk.len() > limit {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    if notification {
        if !bytes.is_empty() {
            return Err(unavailable());
        }
        return Ok((Value::Null, returned_session, bytes));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| unavailable())?;
    let value: Value = match content_type.as_str() {
        "application/json" => serde_json::from_str(text).map_err(|_| unavailable())?,
        "text/event-stream" => {
            let normalized = text.replace("\r\n", "\n");
            let mut messages = Vec::new();
            for frame in normalized.split("\n\n").filter(|f| !f.trim().is_empty()) {
                let mut data = Vec::new();
                for line in frame.lines() {
                    if let Some(body) = line.strip_prefix("data:") {
                        data.push(body.trim_start());
                    } else if !(line.starts_with(':')
                        || line == "event: message"
                        || line.starts_with("id:"))
                    {
                        return Err(unavailable());
                    }
                }
                if !data.is_empty() {
                    messages.push(
                        serde_json::from_str::<Value>(&data.join("\n"))
                            .map_err(|_| unavailable())?,
                    );
                }
            }
            if messages.len() != 1 {
                return Err(unavailable());
            }
            messages.remove(0)
        }
        _ => return Err(unavailable()),
    };
    if !value.is_object()
        || value.get("jsonrpc") != Some(&json!("2.0"))
        || value.get("id") != message.get("id")
        || value.get("method").is_some()
        || value.get("result").is_some() == value.get("error").is_some()
    {
        return Err(unavailable());
    }
    Ok((value, returned_session, bytes))
}

pub async fn execute<F, Fut>(
    call: &PreparedCall,
    credential: &str,
    before_call: F,
    fixture: Option<&str>,
) -> Outcome
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut dispatched = false;
    let exchange = async {
        let route = call.route();
        let (client, url) = client(call, fixture).await?;
        let (initialize,session,_)=send(&client,&url,credential,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"opaque-broker","version":"1"}}}),route.max_response_bytes,route.max_request_bytes).await?;
        let init = initialize.get("result").ok_or_else(unavailable)?;
        if init.get("protocolVersion") != Some(&json!(PROTOCOL_VERSION))
            || !init
                .pointer("/capabilities/tools")
                .is_some_and(Value::is_object)
            || !init.get("serverInfo").is_some_and(Value::is_object)
        {
            return Err(unavailable());
        }
        send(
            &client,
            &url,
            credential,
            session.as_deref(),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            route.max_response_bytes,
            route.max_request_bytes,
        )
        .await?;
        let (list, _, _) = send(
            &client,
            &url,
            credential,
            session.as_deref(),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            route.max_response_bytes,
            route.max_request_bytes,
        )
        .await?;
        let result = list.get("result").ok_or_else(unavailable)?;
        if result.get("nextCursor").is_some() {
            return Err(unavailable());
        }
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(unavailable)?;
        if tools.len() > 128 {
            return Err(unavailable());
        }
        let matches: Vec<_> = tools
            .iter()
            .filter(|tool| tool.get("name") == Some(&json!(route.tool)))
            .collect();
        if matches.len() != 1 || matches[0].get("inputSchema") != Some(route.upstream_schema()) {
            return Err(unavailable());
        }
        let message = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":route.tool,"arguments":call.arguments()}});
        if serde_json::to_vec(&message)
            .map_err(|_| unavailable())?
            .len()
            > route.max_request_bytes
        {
            return Err(unavailable());
        }
        before_call().await?;
        // No await between the final broker fence and marking dispatch uncertain.
        dispatched = true;
        let (response, _, bytes) = send(
            &client,
            &url,
            credential,
            session.as_deref(),
            message,
            route.max_response_bytes,
            route.max_request_bytes,
        )
        .await?;
        let result = response.get("result").ok_or_else(unavailable)?;
        if !result.is_object()
            || !result.get("content").is_some_and(Value::is_array)
            || result.get("isError").is_some_and(|v| !v.is_boolean())
        {
            return Err(unavailable());
        }
        let is_error = result.get("isError") == Some(&json!(true));
        let (output, disclosure) = if route.output_policy == OutputPolicy::TypedFields {
            if is_error {
                (None, Some("withheld_tool_error"))
            } else {
                match route
                    .output_projection
                    .as_ref()
                    .and_then(|p| p.project(result.get("structuredContent")?).ok())
                {
                    Some(fields) => (Some(fields), Some("projected")),
                    None => (None, Some("withheld_invalid_projection")),
                }
            }
        } else {
            (None, None)
        };
        Ok(Outcome {
            state: if result.get("isError") == Some(&json!(true)) {
                "rejected"
            } else {
                "accepted"
            },
            code: if result.get("isError") == Some(&json!(true)) {
                "server_reported_error"
            } else {
                "tool_result_observed"
            },
            response_sha256: Some(format!("{:x}", Sha256::digest(&bytes))),
            response_bytes: Some(bytes.len()),
            output,
            disclosure,
            dispatched: true,
        })
    };
    match tokio::time::timeout(Duration::from_millis(call.route().timeout_ms), exchange).await {
        Ok(Ok(outcome)) => outcome,
        _ if dispatched => Outcome::unknown(),
        _ => Outcome::rejected("admission_or_transport_rejected"),
    }
}
