#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz the execution profile TOML parsing + validation pipeline.
        // Profiles control sandbox boundaries (paths, network, limits).
        let _ = opaque_core::profile::load_profile(s, None);

        // Also test with an expected name to exercise the name validation path.
        let _ = opaque_core::profile::load_profile(s, Some("test-profile"));
    }
});
