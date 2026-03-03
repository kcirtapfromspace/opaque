#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_core::proto::ExecFrame;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz JSON deserialization of streaming exec frames
        let _ = serde_json::from_str::<ExecFrame>(s);
    }
});
