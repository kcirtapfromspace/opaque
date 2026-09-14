#![no_main]
use libfuzzer_sys::fuzz_target;
use opaque_core::proto::decode_response;

fuzz_target!(|data: &[u8]| {
    if data.len() > opaque_core::MAX_FRAME_LENGTH {
        return;
    }
    let expected = 7;
    if let Ok(response) = decode_response(data, expected) {
        assert_eq!(response.id, Some(expected));
        assert_ne!(response.result.is_some(), response.error.is_some());
        assert!(decode_response(data, expected + 1).is_err());
        let canonical = serde_json::to_vec(&response).unwrap();
        let restored = decode_response(&canonical, expected).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), canonical);
        let mut changed: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        changed.as_object_mut().unwrap().remove("id");
        assert!(decode_response(&serde_json::to_vec(&changed).unwrap(), expected).is_err());
    }
});
