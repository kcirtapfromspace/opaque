#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_core::policy::PolicyRule;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to deserialize as a single PolicyRule from TOML
        let _ = toml_edit::de::from_str::<PolicyRule>(s);
        // Try as a Vec of rules (how the config file usually looks)
        let _ = toml_edit::de::from_str::<Vec<PolicyRule>>(s);
    }
});
