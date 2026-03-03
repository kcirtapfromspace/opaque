#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_core::profile::ExecProfile;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz TOML deserialization of execution profiles
        let _ = toml_edit::de::from_str::<ExecProfile>(s);
    }
});
