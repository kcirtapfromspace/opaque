#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_core::task::TaskManifest;

fuzz_target!(|data: &[u8]| {
    if data.len() > opaque_core::MAX_FRAME_LENGTH {
        return;
    }
    let Ok(manifest) = serde_json::from_slice::<TaskManifest>(data) else {
        return;
    };
    if manifest.validate().is_err() {
        return;
    }
    let canonical = manifest.canonicalized().unwrap();
    let digest = manifest.digest().unwrap();
    assert_eq!(canonical.digest().unwrap(), digest);
    assert_eq!(
        serde_json::to_vec(&canonical.canonicalized().unwrap()).unwrap(),
        serde_json::to_vec(&canonical).unwrap()
    );
    let restored: TaskManifest =
        serde_json::from_slice(&serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(restored.digest().unwrap(), digest);
    let mut invalid = manifest.clone();
    invalid.expires_in_secs = 0;
    assert!(invalid.validate().is_err());
    invalid = manifest;
    invalid.title.clear();
    assert!(invalid.validate().is_err());
});
