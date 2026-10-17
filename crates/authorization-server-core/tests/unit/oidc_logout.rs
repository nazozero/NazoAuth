use super::*;

#[test]
fn resolve_client_rejects_conflicting_hint_audience() {
    let hint = IdTokenHintClaims {
        sub: "subject".to_owned(),
        aud: Value::String("client-a".to_owned()),
        sid: None,
    };
    assert_eq!(
        resolve_logout_client_id(Some("client-b"), false, Some(&hint)),
        Err(LogoutPolicyError::ClientAudienceMismatch)
    );
}

#[test]
fn redirect_state_is_appended_without_replacing_registered_query() {
    let registered = vec!["https://client.example/logout?source=op".to_owned()];
    assert_eq!(
        validate_post_logout_redirect(
            Some("https://client.example/logout?source=op"),
            Some("logout-state"),
            Some(&registered),
        )
        .expect("registered redirect"),
        Some("https://client.example/logout?source=op&state=logout-state".to_owned())
    );
}

#[test]
fn pairwise_subject_is_stable_within_sector_and_distinct_across_sectors() {
    let user_id = Uuid::nil();
    let secret = b"this-is-a-long-enough-secret-key-for-hmac-sha256!!";

    let first = pairwise_subject(secret, "https://issuer.example", "client.example", user_id);
    let second = pairwise_subject(secret, "https://issuer.example", "client.example", user_id);
    let third = pairwise_subject(secret, "https://issuer.example", "other.example", user_id);

    assert_eq!(first, second);
    assert_eq!(first, "ueLqFom86MNO_OCs6rKD1wCWP2OyXVvnQgkKrf3GZ30");
    assert_ne!(first, third);
    assert_ne!(first, user_id.to_string());
}

#[test]
fn logout_subjects_preserve_sector_identity_and_ambiguity() {
    let issuer = "https://issuer.example";
    let secret = "this-is-a-long-enough-secret-key-for-hmac-sha256!!";
    let user_id = Uuid::nil();
    let redirects = [
        "https://one.example/callback".to_owned(),
        "https://one.example/other".to_owned(),
        "https://two.example/callback".to_owned(),
    ];
    let mut client = LogoutClient {
        redirect_uris: &redirects,
        subject_type: "public",
        sector_identifier_host: None,
    };
    assert_eq!(
        logout_subjects_for_client(issuer, None, user_id, &client).unwrap(),
        vec![user_id.to_string()]
    );
    client.subject_type = "pairwise";
    let mut expected = vec![
        pairwise_subject(secret.as_bytes(), issuer, "one.example", user_id),
        pairwise_subject(secret.as_bytes(), issuer, "two.example", user_id),
    ];
    expected.sort();
    assert_eq!(
        logout_subjects_for_client(issuer, Some(secret), user_id, &client).unwrap(),
        expected
    );
    assert_eq!(
        unique_logout_subject_for_client(issuer, Some(secret), user_id, &client).unwrap(),
        None
    );
    client.redirect_uris = &redirects[..2];
    assert_eq!(
        unique_logout_subject_for_client(issuer, Some(secret), user_id, &client).unwrap(),
        Some(pairwise_subject(
            secret.as_bytes(),
            issuer,
            "one.example",
            user_id
        ))
    );
    client.redirect_uris = &redirects;
    client.sector_identifier_host = Some("sector.example");
    assert_eq!(
        unique_logout_subject_for_client(issuer, Some(secret), user_id, &client).unwrap(),
        Some(pairwise_subject(
            secret.as_bytes(),
            issuer,
            "sector.example",
            user_id
        ))
    );
    client.redirect_uris = &[];
    client.sector_identifier_host = None;
    assert_eq!(
        unique_logout_subject_for_client(issuer, Some(secret), user_id, &client).unwrap(),
        Some(pairwise_subject(secret.as_bytes(), issuer, "", user_id))
    );
}

#[test]
fn oidc_subject_for_public_client_is_the_user_identifier() {
    let user_id = Uuid::now_v7();
    let subject = oidc_subject_for_client(
        "https://issuer.example",
        Some("this-is-a-long-enough-secret-key-for-hmac-sha256!!"),
        user_id,
        "public",
        Some("client.example"),
        "https://client.example/callback",
    )
    .expect("public subject should resolve");

    assert_eq!(subject, user_id.to_string());
}

#[test]
fn oidc_pairwise_subject_uses_explicit_sector_and_redirect_host_fallback() {
    let user_id = Uuid::now_v7();
    let secret = "this-is-a-long-enough-secret-key-for-hmac-sha256!!";
    let explicit = oidc_subject_for_client(
        "https://issuer.example",
        Some(secret),
        user_id,
        "pairwise",
        Some("pairwise.example"),
        "https://client.example/callback",
    )
    .expect("pairwise subject should resolve");
    assert_eq!(
        explicit,
        pairwise_subject(
            secret.as_bytes(),
            "https://issuer.example",
            "pairwise.example",
            user_id,
        )
    );

    let fallback = oidc_subject_for_client(
        "https://issuer.example",
        Some(secret),
        user_id,
        "pairwise",
        None,
        "https://fallback.example/callback",
    )
    .expect("redirect host fallback should resolve");
    let same_host = oidc_subject_for_client(
        "https://issuer.example",
        Some(secret),
        user_id,
        "pairwise",
        None,
        "https://fallback.example/other",
    )
    .expect("same redirect host should resolve");
    assert_eq!(fallback, same_host);
}

#[test]
fn oidc_pairwise_subject_requires_secret_and_supported_subject_type() {
    assert_eq!(
        oidc_subject_for_client(
            "https://issuer.example",
            None,
            Uuid::now_v7(),
            "pairwise",
            Some("pairwise.example"),
            "https://client.example/callback",
        ),
        Err(LogoutPolicyError::PairwiseSecretMissing)
    );
    assert_eq!(
        oidc_subject_for_client(
            "https://issuer.example",
            Some("this-is-a-long-enough-secret-key-for-hmac-sha256!!"),
            Uuid::now_v7(),
            "transient",
            Some("client.example"),
            "https://client.example/callback",
        ),
        Err(LogoutPolicyError::UnsupportedSubjectType)
    );
}
