#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the IPC request JSON deserialization path.
    // This is the daemon's entry point for all client messages over the UDS socket.
    let _ = serde_json::from_slice::<opaque_core::proto::Request>(data);

    // Also fuzz the response path (parsed by CLI and web dashboard).
    let _ = serde_json::from_slice::<opaque_core::proto::Response>(data);
});
