use super::*;

#[path = "request/endpoint.rs"]
mod endpoint;
#[path = "request/prompt_none.rs"]
mod prompt_none;

fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn pkce_policy_client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    }
}

#[test]
fn first_acr_value_is_used_for_id_token_acr() {
    assert_eq!(
        requested_acr(&query(&[("acr_values", "urn:one urn:two")]), None),
        Some("urn:one".to_owned())
    );
    assert_eq!(
        requested_acr(
            &query(&[("acr_values", "urn:one urn:two")]),
            Some("urn:claims".to_owned()),
        ),
        Some("urn:one".to_owned())
    );
    assert_eq!(
        requested_acr(
            &query(&[("acr_values", "   ")]),
            Some("urn:claims".to_owned())
        ),
        Some("urn:claims".to_owned())
    );
}

#[test]
fn claims_parameter_extracts_supported_user_claim_names() {
    let requested = requested_claims(&query(&[(
        "claims",
        r#"{"userinfo":{"name":{"essential":true},"unknown":null},"id_token":{"email":{"essential":true},"acr":{"value":"urn:acr:1"},"auth_time":{"essential":true}}}"#,
    )]))
    .unwrap();

    assert_eq!(claim_request_names(&requested.userinfo), vec!["name"]);
    assert!(requested.userinfo[0].essential);
    assert_eq!(claim_request_names(&requested.id_token), vec!["email"]);
    assert!(requested.id_token[0].essential);
    assert_eq!(requested.acr, Some("urn:acr:1".to_owned()));
    assert!(requested.auth_time);
}

#[test]
fn claims_parameter_accepts_value_values_and_null_requests() {
    let requested = requested_claims(&query(&[(
        "claims",
        r#"{"userinfo":{"name":null,"email":{"value":"alice@example.com"},"phone_number":{"values":["+15555550000","+15555550001"]}},"id_token":{"email_verified":{"essential":false},"acr":{"values":["urn:acr:2"]}}}"#,
    )]))
    .unwrap();

    assert_eq!(
        claim_request_names(&requested.userinfo),
        vec!["email", "name", "phone_number"]
    );
    let email = requested
        .userinfo
        .iter()
        .find(|request| request.name == "email")
        .expect("email claim request");
    assert_eq!(email.value, Some(json!("alice@example.com")));
    let phone = requested
        .userinfo
        .iter()
        .find(|request| request.name == "phone_number")
        .expect("phone claim request");
    assert_eq!(
        phone.values,
        vec![json!("+15555550000"), json!("+15555550001")]
    );
    assert_eq!(
        claim_request_names(&requested.id_token),
        vec!["email_verified"]
    );
    assert!(!requested.id_token[0].essential);
    assert_eq!(requested.acr, Some("urn:acr:2".to_owned()));
    assert!(!requested.auth_time);
}

#[test]
fn malformed_claims_parameter_is_invalid() {
    assert!(requested_claims(&query(&[("claims", "not-json")])).is_err());
    assert!(requested_claims(&query(&[("claims", r#"{"userinfo":[]}"#)])).is_err());
    assert!(requested_claims(&query(&[("claims", r#"{"id_token":{"acr":[]}}"#)])).is_err());
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"essential":"yes"}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"value":"a@example.com","values":["a@example.com"]}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"values":"a@example.com"}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"userinfo":{"email":{"values":[]}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"id_token":{"acr":{"values":"one"}}}"#
        )]))
        .is_err()
    );
    assert!(
        requested_claims(&query(&[(
            "claims",
            r#"{"id_token":{"auth_time":{"essential":"yes"}}}"#
        )]))
        .is_err()
    );
}

#[test]
fn claims_parameter_uses_first_non_empty_acr_values_entry() {
    let requested = requested_claims(&query(&[(
        "claims",
        r#"{"id_token":{"acr":{"values":["","urn:acr:2","urn:acr:3"]}}}"#,
    )]))
    .unwrap();

    assert_eq!(requested.acr, Some("urn:acr:2".to_owned()));
}

#[test]
fn max_age_zero_and_prompt_directives_require_reauthentication() {
    let prompt = PromptDirectives::default();

    assert!(session_requires_reauthentication(
        prompt,
        Some(0),
        1_000,
        None,
        1_000
    ));
    assert!(!session_requires_reauthentication(
        prompt,
        Some(30),
        1_000,
        None,
        1_030
    ));
    assert!(session_requires_reauthentication(
        prompt,
        Some(30),
        1_000,
        None,
        1_031
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            login: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        None,
        1_001,
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            login: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        Some(1_001),
        1_001,
    ));
    assert!(!session_requires_reauthentication(
        PromptDirectives {
            login: true,
            ..PromptDirectives::default()
        },
        None,
        1_001,
        Some(1_001),
        1_006,
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            select_account: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        None,
        1_001,
    ));
    assert!(session_requires_reauthentication(
        PromptDirectives {
            select_account: true,
            ..PromptDirectives::default()
        },
        None,
        1_000,
        Some(1_001),
        1_001,
    ));
    assert!(!session_requires_reauthentication(
        PromptDirectives {
            select_account: true,
            ..PromptDirectives::default()
        },
        None,
        1_001,
        Some(1_001),
        1_006,
    ));
}

#[test]
fn authorization_login_url_marks_reauthentication_start_once() {
    let q = query(&[("client_id", "client-1"), ("prompt", "login")]);

    let url = authorization_login_url_for_frontend("https://auth.example", &q, true, None);

    let url = url::Url::parse(&url).unwrap();
    assert!(url.as_str().starts_with("https://auth.example/auth?"));
    let next = url
        .query_pairs()
        .find_map(|(key, value)| (key == "next").then_some(value.into_owned()))
        .unwrap();
    assert!(next.contains("_nazo_reauth_started_at="));
}

#[test]
fn request_uri_allows_outer_parameters_only_when_equal_to_pushed_values() {
    let pushed = query(&[
        ("client_id", "client-1"),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("scope", "openid profile"),
    ]);

    assert!(outer_request_uri_parameters_match_pushed(
        &query(&[
            ("client_id", "client-1"),
            ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            ("redirect_uri", "https://client.example/callback"),
            ("response_type", "code"),
            ("scope", "openid profile"),
        ]),
        &pushed,
    ));
    assert!(!outer_request_uri_parameters_match_pushed(
        &query(&[
            ("client_id", "client-1"),
            ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            ("redirect_uri", "https://attacker.example/callback"),
        ]),
        &pushed,
    ));
    assert!(!outer_request_uri_parameters_match_pushed(
        &query(&[
            ("client_id", "client-1"),
            ("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            ("state", "outer-state"),
        ]),
        &pushed,
    ));
}

#[test]
fn authorization_nonce_length_check_allows_long_state_but_rejects_long_nonce() {
    assert!(!authorization_nonce_too_long(&query(&[(
        "state",
        &"s".repeat(1000),
    )])));
    assert!(authorization_nonce_too_long(&query(&[(
        "nonce",
        &"n".repeat(AUTHORIZATION_NONCE_MAX_BYTES + 1),
    )])));
}

#[test]
fn authorization_response_query_preserves_explicit_empty_state() {
    let location = append_authorization_response_query(
        "https://client.example/callback",
        "https://issuer.example",
        Some("code-1"),
        None,
        Some(""),
    );

    let url = url::Url::parse(&location).unwrap();
    let pairs = url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            ("code".into(), "code-1".into()),
            ("state".into(), "".into()),
            ("iss".into(), "https://issuer.example".into()),
        ]
    );
}

#[test]
fn authorization_response_query_omits_absent_state_and_inapplicable_result() {
    let location = append_authorization_response_query(
        "https://client.example/callback",
        "https://issuer.example",
        None,
        Some("invalid_request"),
        None,
    );

    let url = url::Url::parse(&location).unwrap();
    let pairs = url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            ("error".into(), "invalid_request".into()),
            ("iss".into(), "https://issuer.example".into()),
        ]
    );
}

#[test]
fn authorization_response_jwt_redirect_uses_only_response_parameter() {
    let response = authorization_response_jwt_redirect(
        "https://client.example/callback?existing=1",
        "signed-jarm",
    );

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let url = url::Url::parse(location).unwrap();
    let pairs = url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            ("existing".into(), "1".into()),
            ("response".into(), "signed-jarm".into()),
        ]
    );
    assert!(
        !pairs
            .iter()
            .any(|(key, _)| matches!(key.as_ref(), "code" | "error" | "state" | "iss"))
    );
}

#[test]
fn authorization_response_jwt_signing_failure_does_not_fallback_to_query() {
    let response = authorization_response_jwt_result(
        "https://client.example/callback",
        Err(jsonwebtoken::errors::new_error(
            jsonwebtoken::errors::ErrorKind::Signing("test signing failure".to_owned()),
        )),
    );

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::LOCATION).is_none());
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}

#[test]
fn preserve_verified_dpop_binding_adds_missing_authorization_parameter() {
    let mut q = query(&[("client_id", "client-1")]);
    let dpop_jkt = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";

    preserve_verified_dpop_binding(&mut q, Some(dpop_jkt));

    assert_eq!(q.get("dpop_jkt").map(String::as_str), Some(dpop_jkt));
}

#[test]
fn preserve_verified_dpop_binding_keeps_explicit_authorization_parameter() {
    let mut q = query(&[
        ("client_id", "client-1"),
        ("dpop_jkt", "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"),
    ]);

    preserve_verified_dpop_binding(&mut q, Some("Vx6mH6nGWV2DnuqEbuGX4Xw_Dc0p0AQxnKpEG7o5YS8"));

    assert_eq!(
        q.get("dpop_jkt").map(String::as_str),
        Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ")
    );
}

#[test]
fn prompt_parsing_accepts_oidc_values_and_rejects_invalid_combinations() {
    let directives =
        requested_prompt(&query(&[("prompt", "login consent select_account")])).unwrap();
    assert!(directives.login);
    assert!(directives.consent);
    assert!(directives.select_account);
    assert!(!directives.none);

    assert_eq!(
        requested_prompt(&query(&[("prompt", "none")])).unwrap(),
        PromptDirectives {
            none: true,
            ..PromptDirectives::default()
        }
    );
    assert!(requested_prompt(&query(&[("prompt", "none consent")])).is_err());
    assert!(requested_prompt(&query(&[("prompt", "unsupported")])).is_err());
}

#[test]
fn authorization_pkce_allows_absent_value_for_parse_layer_but_rejects_invalid_pkce() {
    assert_eq!(authorization_pkce(&query(&[])).unwrap(), (None, None));
    let valid_challenge = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    assert!(
        authorization_pkce(&query(&[
            ("code_challenge", valid_challenge),
            ("code_challenge_method", "plain"),
        ]))
        .is_err()
    );
    assert!(authorization_pkce(&query(&[("code_challenge", valid_challenge)])).is_err());
    assert!(
        authorization_pkce(&query(&[
            ("code_challenge", valid_challenge),
            ("code_challenge_method", "S256"),
        ]))
        .is_ok()
    );
}

#[test]
fn authorization_request_pkce_policy_allows_only_explicit_confidential_compatibility() {
    let mut client = pkce_policy_client();
    assert!(authorization_request_requires_pkce(&client));

    client.allow_authorization_code_without_pkce = true;
    assert!(!authorization_request_requires_pkce(&client));

    client.client_type = "public".to_owned();
    assert!(authorization_request_requires_pkce(&client));

    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    assert!(authorization_request_requires_pkce(&client));

    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    assert!(authorization_request_requires_pkce(&client));
}
