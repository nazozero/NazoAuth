use super::*;

#[test]
fn signing_seed_accepts_both_encodings_and_rejects_wrong_lengths() {
    let seed = [0xabu8; 32];
    for value in [
        "ab".repeat(32),
        "AB".repeat(32),
        URL_SAFE_NO_PAD.encode(seed),
    ] {
        assert_eq!(parse_signing_key(&value).unwrap().to_bytes(), seed);
    }
    for value in [
        "ab".repeat(31),
        "ab".repeat(33),
        URL_SAFE_NO_PAD.encode([0u8; 31]),
    ] {
        assert!(parse_signing_key(&value).is_err());
    }
}
