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

#[test]
fn totp_verifier_rejects_replay_and_accepts_only_one_step_skew() {
    let secret = base32_encode(b"12345678901234567890");
    let now = 1_234_567_890;
    let current_step = now / MFA_TOTP_PERIOD_SECONDS;
    let current_code = totp_for_step(b"12345678901234567890", current_step).unwrap();
    let previous_code = totp_for_step(b"12345678901234567890", current_step - 1).unwrap();
    let too_old_code = totp_for_step(b"12345678901234567890", current_step - 2).unwrap();
    let future_code = totp_for_step(b"12345678901234567890", current_step + 1).unwrap();
    let too_future_code = totp_for_step(b"12345678901234567890", current_step + 2).unwrap();

    assert_eq!(
        verified_totp_step(&secret, &current_code, now, None),
        Some(current_step)
    );
    assert_eq!(
        verified_totp_step(&secret, &previous_code, now, None),
        Some(current_step - 1)
    );
    assert_eq!(
        verified_totp_step(&secret, &future_code, now, None),
        Some(current_step + 1)
    );
    assert_eq!(
        verified_totp_step(&secret, &current_code, now, Some(current_step)),
        None,
        "a TOTP value from an already used step must not be replayable"
    );
    assert_eq!(
        verified_totp_step(&secret, &previous_code, now, Some(current_step - 1)),
        None,
        "the skew window must not reopen an already consumed older step"
    );
    assert_eq!(
        verified_totp_step(&secret, &too_old_code, now, None),
        None,
        "codes older than the configured skew window must fail closed"
    );
    assert_eq!(
        verified_totp_step(&secret, &too_future_code, now, None),
        None,
        "codes beyond the configured future skew window must fail closed"
    );
}

#[test]
fn totp_verifier_rejects_malformed_code_or_secret_without_fallback() {
    let secret = base32_encode(b"12345678901234567890");
    let now = 1_234_567_890;
    let step = now / MFA_TOTP_PERIOD_SECONDS;
    let code = totp_for_step(b"12345678901234567890", step).unwrap();

    for malformed in ["", "00592", "0059247", "00592a", "005 24"] {
        assert_eq!(
            verified_totp_step(&secret, malformed, now, None),
            None,
            "malformed TOTP code {malformed:?} must not be normalized into a valid credential"
        );
    }

    assert_eq!(
        verified_totp_step("!!!!", &code, now, None),
        None,
        "invalid base32 secrets must fail closed instead of verifying against empty key material"
    );
    assert_eq!(
        verified_totp_step("", &code, now, None),
        None,
        "empty TOTP secrets must not be accepted"
    );
}

#[test]
fn remembered_mfa_device_user_agent_hash_is_bound_to_non_empty_header() {
    let with_agent = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, "Example Browser"))
        .to_http_request();
    let empty_agent = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, "   "))
        .to_http_request();
    let missing_agent = actix_web::test::TestRequest::default().to_http_request();

    assert_eq!(
        request_user_agent_hash(&with_agent).as_deref(),
        Some(blake3_hex("Example Browser").as_str())
    );
    assert_eq!(
        request_user_agent_hash(&empty_agent),
        None,
        "blank User-Agent must not create a reusable remembered-device binding"
    );
    assert_eq!(
        request_user_agent_hash(&missing_agent),
        None,
        "missing User-Agent must remain unbound rather than matching an attacker supplied blank value"
    );
}
