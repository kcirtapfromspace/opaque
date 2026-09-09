use opaque_core::validate::truncate_utf8;

#[test]
fn every_unicode_scalar_respects_the_byte_budget() {
    let mut encoded = [0; 4];
    for scalar in 0..=0x10ffff {
        let Some(character) = char::from_u32(scalar) else {
            continue;
        };
        let value: &str = character.encode_utf8(&mut encoded);
        for budget in 0..=5 {
            let prefix = truncate_utf8(value, budget);
            assert!(prefix.len() <= budget);
            assert!(value.starts_with(prefix));
            assert_eq!(prefix, if budget < value.len() { "" } else { value });
        }
    }
}

#[test]
fn mixed_text_preserves_complete_prefixes_at_every_boundary() {
    let text = "plain é e\u{301} 中文 🙂";
    for budget in 0..=text.len() + 4 {
        let expected: String = text
            .chars()
            .scan(0, |used, ch| {
                *used += ch.len_utf8();
                (*used <= budget).then_some(ch)
            })
            .collect();
        assert_eq!(truncate_utf8(text, budget), expected);
    }
}
