#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_core::proto::{Request, Response};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz JSON deserialization of IPC request/response messages
        let _ = serde_json::from_str::<Request>(s);
        let _ = serde_json::from_str::<Response>(s);
    }
});
