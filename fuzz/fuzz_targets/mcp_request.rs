#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_mcp::protocol::{McpLines, RequestError, parse_request};
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    if data.len() > opaque_core::MAX_FRAME_LENGTH + 2 {
        return;
    }
    if let Ok(request) = parse_request(data) {
        assert_eq!(request.jsonrpc, "2.0");
        assert!(
            request
                .id
                .as_ref()
                .is_none_or(|id| id.is_string() || id.is_number())
        );
        let bytes = serde_json::to_vec(&request).unwrap();
        assert_eq!(parse_request(&bytes).unwrap(), request);
        let mut changed = request;
        changed.jsonrpc = "1.0".into();
        assert_eq!(
            parse_request(&serde_json::to_vec(&changed).unwrap()),
            Err(RequestError::Envelope)
        );
    }
    // Exercise the same recoverable line decoder used by real stdio, including
    // invalid UTF-8 and oversize input, without a transport or daemon process.
    let mut input = bytes::BytesMut::from(data);
    input.extend_from_slice(b"\n");
    let mut codec = McpLines::new();
    for _ in 0..=data.len() + 1 {
        let before = input.len();
        match codec.decode(&mut input).unwrap() {
            Some(Ok(line)) => {
                assert!(line.len() <= opaque_core::MAX_FRAME_LENGTH);
                assert!(input.len() < before);
            }
            Some(Err(_)) => {
                assert!(input.len() <= before);
            }
            None => break,
        }
    }
    // A discarded oversized line may need one more decode before fresh input.
    while codec.decode(&mut input).unwrap().is_some() {}
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    let recovered = codec.decode(&mut input).unwrap().unwrap().unwrap();
    assert_eq!(parse_request(recovered.as_bytes()).unwrap().method, "ping");
});
