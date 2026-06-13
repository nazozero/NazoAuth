use super::*;

#[test]
fn post_logout_redirect_requires_exact_registered_uri_and_preserves_state() {
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!(["https://client.example/logout/callback"]),
        backchannel_logout_uri: None,
    };
    let form = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout/callback".to_owned()),
        state: Some("state-1".to_owned()),
        ..LogoutRequest::default()
    };

    assert_eq!(
        validate_post_logout_redirect(&form, Some(&client)).unwrap(),
        Some("https://client.example/logout/callback?state=state-1".to_owned())
    );

    let unregistered = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout/other".to_owned()),
        ..LogoutRequest::default()
    };
    assert!(validate_post_logout_redirect(&unregistered, Some(&client)).is_err());
}

#[test]
fn logout_client_id_must_match_id_token_hint_audience() {
    let hint = IdTokenHintClaims {
        sub: "user-1".to_owned(),
        aud: json!("client-1"),
        sid: Some("sid-1".to_owned()),
    };
    let matching = LogoutRequest {
        client_id: Some("client-1".to_owned()),
        ..LogoutRequest::default()
    };
    let conflicting = LogoutRequest {
        client_id: Some("client-2".to_owned()),
        ..LogoutRequest::default()
    };

    assert_eq!(
        identify_logout_client(&matching, Some(&hint)).unwrap(),
        Some("client-1".to_owned())
    );
    assert!(identify_logout_client(&conflicting, Some(&hint)).is_err());
}

#[test]
fn multi_audience_id_token_hint_requires_explicit_matching_client_id() {
    let hint = IdTokenHintClaims {
        sub: "user-1".to_owned(),
        aud: json!(["client-1", "client-2"]),
        sid: Some("sid-1".to_owned()),
    };
    let missing = LogoutRequest::default();
    let matching = LogoutRequest {
        client_id: Some("client-2".to_owned()),
        ..LogoutRequest::default()
    };

    assert!(identify_logout_client(&missing, Some(&hint)).is_err());
    assert_eq!(
        identify_logout_client(&matching, Some(&hint)).unwrap(),
        Some("client-2".to_owned())
    );
}

#[test]
fn id_token_hint_subject_matches_pairwise_subject_for_registered_client_sector() {
    use crate::config::ConfigSource;
    use crate::settings::SubjectType;

    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.subject_type = SubjectType::Pairwise;
    settings.pairwise_subject_secret = Some("secret".to_owned());
    let user_id = Uuid::now_v7();
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: Some("https://client.example/backchannel-logout".to_owned()),
    };
    let subject = oidc_subject(&settings, user_id, "https://client.example/callback");
    let hint = IdTokenHintClaims {
        sub: subject,
        aud: json!("client-1"),
        sid: Some("sid-1".to_owned()),
    };

    assert!(id_token_hint_matches_current_session(
        &settings,
        Some(&client),
        user_id,
        "sid-1",
        &hint
    ));
    assert!(!id_token_hint_matches_current_session(
        &settings,
        Some(&client),
        user_id,
        "sid-2",
        &hint
    ));
}

#[test]
fn backchannel_logout_subject_is_omitted_when_pairwise_sector_is_ambiguous() {
    use crate::config::ConfigSource;
    use crate::settings::SubjectType;

    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.subject_type = SubjectType::Pairwise;
    settings.pairwise_subject_secret = Some("secret".to_owned());
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!([
            "https://one.example/callback",
            "https://two.example/callback"
        ]),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: Some("https://client.example/backchannel-logout".to_owned()),
    };

    assert!(unique_logout_subject_for_client(&settings, Uuid::now_v7(), &client).is_none());
}
