use super::*;

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[test]
fn logout_query_parser_trims_known_parameters_and_ignores_unknown_values() {
    let form = parse_logout_pairs(
        "id_token_hint=%20token%20&client_id=%20client-1%20&post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Flogout&state=%20state-1%20&unknown=value",
    )
    .expect("valid logout query should parse");

    assert_eq!(form.id_token_hint.as_deref(), Some("token"));
    assert_eq!(form.client_id.as_deref(), Some("client-1"));
    assert_eq!(
        form.post_logout_redirect_uri.as_deref(),
        Some("https://client.example/logout")
    );
    assert_eq!(form.state.as_deref(), Some("state-1"));
}

#[test]
fn logout_query_parser_rejects_duplicate_registered_parameters() {
    let response = match parse_logout_pairs("client_id=client-1&client_id=client-2") {
        Ok(_) => panic!("duplicate client_id must fail before client lookup"),
        Err(response) => response,
    };

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

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
fn post_logout_redirect_rejects_missing_client_and_invalid_registered_uri() {
    let form = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout/callback".to_owned()),
        ..LogoutRequest::default()
    };
    let missing_client = validate_post_logout_redirect(&form, None)
        .expect_err("redirect URI requires a resolved registered client");
    assert_eq!(missing_client.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&missing_client).as_deref(),
        Some("invalid_request")
    );

    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!(["not a uri"]),
        backchannel_logout_uri: None,
    };
    let invalid = LogoutRequest {
        post_logout_redirect_uri: Some("not a uri".to_owned()),
        ..LogoutRequest::default()
    };
    let invalid_uri = validate_post_logout_redirect(&invalid, Some(&client))
        .expect_err("registered logout redirects must still be absolute URI values");
    assert_eq!(invalid_uri.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&invalid_uri).as_deref(),
        Some("invalid_request")
    );
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
fn logout_client_identification_requires_client_context_for_redirects() {
    let redirect_without_client = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout".to_owned()),
        ..LogoutRequest::default()
    };
    let response = identify_logout_client(&redirect_without_client, None)
        .expect_err("post logout redirect must be tied to a registered client");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );

    assert_eq!(
        identify_logout_client(&LogoutRequest::default(), None).unwrap(),
        None
    );
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
fn single_audience_accepts_string_or_single_string_array_only() {
    assert_eq!(
        single_audience(&json!("client-1")).as_deref(),
        Some("client-1")
    );
    assert_eq!(
        single_audience(&json!(["client-1"])).as_deref(),
        Some("client-1")
    );
    assert!(single_audience(&json!(["client-1", "client-2"])).is_none());
    assert!(single_audience(&json!([42])).is_none());
    assert!(single_audience(&json!({"aud": "client-1"})).is_none());
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
fn id_token_hint_without_registered_client_never_matches_session() {
    use crate::config::ConfigSource;

    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let hint = IdTokenHintClaims {
        sub: Uuid::now_v7().to_string(),
        aud: json!("client-1"),
        sid: None,
    };

    assert!(!id_token_hint_matches_current_session(
        &settings,
        None,
        Uuid::now_v7(),
        "sid-1",
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

#[test]
fn backchannel_logout_subject_uses_public_subject_when_configured() {
    use crate::config::ConfigSource;

    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let user_id = Uuid::now_v7();
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!([]),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: Some("https://client.example/backchannel-logout".to_owned()),
    };

    assert_eq!(
        unique_logout_subject_for_client(&settings, user_id, &client).as_deref(),
        Some(user_id.to_string().as_str())
    );
}
