#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the streaming exec frame deserialization.
    // ExecFrame is a tagged enum that carries sandbox execution output.
    let _ = serde_json::from_slice::<opaque_core::proto::ExecFrame>(data);

    // Fuzz the operation request deserialization.
    let _ = serde_json::from_slice::<opaque_core::operation::OperationRequest>(data);

    // Fuzz the audit event deserialization (stored/retrieved from SQLite).
    let _ = serde_json::from_slice::<opaque_core::audit::AuditEvent>(data);
});
