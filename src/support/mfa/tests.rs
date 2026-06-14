use super::*;

#[test]
fn totp_matches_rfc6238_sha1_vectors() {
    let secret = b"12345678901234567890";
    let cases = [
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_111_111_111, "050471"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
        (20_000_000_000, "353130"),
    ];

    for (timestamp, expected) in cases {
        let step = timestamp / MFA_TOTP_PERIOD_SECONDS;
        assert_eq!(totp_for_step(secret, step).unwrap(), expected);
    }
}

#[test]
fn generated_totp_secret_is_base32_without_padding() {
    let secret = generate_totp_secret_base32();

    assert_eq!(secret.len(), 32);
    assert!(
        secret
            .chars()
            .all(|value| matches!(value, 'A'..='Z' | '2'..='7'))
    );
    assert_eq!(base32_decode(&secret).unwrap().len(), 20);
}

#[test]
fn backup_code_normalization_accepts_display_format_only() {
    assert_eq!(
        normalize_backup_code("12345-67890").as_deref(),
        Some("1234567890")
    );
    assert_eq!(
        normalize_backup_code("12345 67890").as_deref(),
        Some("1234567890")
    );
    assert!(normalize_backup_code("1234-67890").is_none());
    assert!(normalize_backup_code("abcdefghij").is_none());
}
