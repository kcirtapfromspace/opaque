//! The actual stdio line decoder and JSON-RPC envelope validation. This module
//! contains no transport, daemon client, credentials or service access.
use serde::{Deserialize, Serialize};
use tokio_util::codec::{Decoder, LinesCodec, LinesCodecError};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    Json,
    Envelope,
}
impl RequestError {
    pub fn code(self) -> i64 {
        match self {
            Self::Json => -32700,
            Self::Envelope => -32600,
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::Json => "invalid JSON-RPC request",
            Self::Envelope => "invalid JSON-RPC version or request ID",
        }
    }
}

/// Preserve the production distinction between malformed JSON and invalid
/// version/ID envelopes. The line decoder applies the shared IPC byte limit.
pub fn parse_request(bytes: &[u8]) -> Result<JsonRpcRequest, RequestError> {
    let request: JsonRpcRequest = serde_json::from_slice(bytes).map_err(|_| RequestError::Json)?;
    if request.jsonrpc != "2.0"
        || request
            .id
            .as_ref()
            .is_some_and(|id| !id.is_string() && !id.is_number())
    {
        return Err(RequestError::Envelope);
    }
    Ok(request)
}

/// Oversized or non-UTF-8 lines are recoverable protocol items. Returning a
/// decoder error would terminate FramedRead and discard the next valid request.
pub type McpLine = Result<String, &'static str>;
pub struct McpLines(LinesCodec);
impl Decoder for McpLines {
    type Item = McpLine;
    type Error = std::io::Error;

    fn decode(&mut self, source: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Self::classify(self.0.decode(source))
    }

    fn decode_eof(
        &mut self,
        source: &mut bytes::BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        Self::classify(self.0.decode_eof(source))
    }
}
impl McpLines {
    pub fn new() -> Self {
        Self(LinesCodec::new_with_max_length(
            opaque_core::MAX_FRAME_LENGTH,
        ))
    }
    fn classify(
        result: Result<Option<String>, LinesCodecError>,
    ) -> std::io::Result<Option<McpLine>> {
        match result {
            Ok(line) => Ok(line.map(Ok)),
            Err(LinesCodecError::MaxLineLengthExceeded) => {
                Ok(Some(Err("MCP frame exceeds the size limit")))
            }
            Err(LinesCodecError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                Ok(Some(Err("MCP frame is not UTF-8")))
            }
            Err(LinesCodecError::Io(error)) => Err(error),
        }
    }
}

impl Default for McpLines {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn envelope_errors_and_notification_ids_keep_stdio_semantics() {
        for input in [b"{".as_slice(), br#"{"jsonrpc":"2.0","method":1}"#] {
            let error = parse_request(input).unwrap_err();
            assert_eq!(error, RequestError::Json);
            assert_eq!(error.code(), -32700);
            assert_eq!(error.message(), "invalid JSON-RPC request");
        }
        for input in [
            br#"{"jsonrpc":"1.0","method":"ping"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","method":"ping","id":false}"#,
        ] {
            let error = parse_request(input).unwrap_err();
            assert_eq!(error, RequestError::Envelope);
            assert_eq!(error.code(), -32600);
            assert_eq!(error.message(), "invalid JSON-RPC version or request ID");
        }
        let notification =
            parse_request(br#"{"jsonrpc":"2.0","method":"ping","id":null}"#).unwrap();
        assert!(notification.id.is_none());
        assert_eq!(notification.params, serde_json::Value::Null);
        for id in [serde_json::json!(1), serde_json::json!("request")] {
            let request = parse_request(
                &serde_json::to_vec(&serde_json::json!({
                    "jsonrpc":"2.0", "method":"ping", "id":id,
                }))
                .unwrap(),
            )
            .unwrap();
            assert_eq!(request.id, Some(id));
        }
    }

    #[test]
    fn decoder_recovers_after_invalid_utf8_and_oversized_frames() {
        for invalid in [vec![0xff], vec![b'a'; opaque_core::MAX_FRAME_LENGTH + 1]] {
            let mut bytes = bytes::BytesMut::from(invalid.as_slice());
            bytes.extend_from_slice(b"\nnext\n");
            let mut codec = McpLines::new();
            assert!(codec.decode(&mut bytes).unwrap().unwrap().is_err());
            let next = (0..3)
                .find_map(|_| codec.decode(&mut bytes).unwrap())
                .expect("decoder must recover within the bounded number of frames");
            assert_eq!(next.unwrap(), "next");
            assert!(bytes.is_empty());
            assert!(codec.decode_eof(&mut bytes).unwrap().is_none());
        }
    }
}
