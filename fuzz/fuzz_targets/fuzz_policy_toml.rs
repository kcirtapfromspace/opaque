#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz the policy rule TOML deserialization path.
        // This is the primary config surface: untrusted TOML → PolicyRule.
        let _ = toml_edit::de::from_str::<Vec<opaque_core::policy::PolicyRule>>(s);

        // Also fuzz single-rule parsing (common in tests/examples).
        let _ = toml_edit::de::from_str::<opaque_core::policy::PolicyRule>(s);
    }
});
