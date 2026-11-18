use super::*;

fn signed_ciba_request_object_for_client_with_alg(
    client_id: &str,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let mut claims = json!({
        "iss": client_id,
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("ciba-request-{}", Uuid::now_v7()),
        "scope": "openid profile email",
        "login_hint": "subject@example.test",
        "binding_message": "1234"
    });
    let target = claims.as_object_mut().expect("claims should be object");
    for (key, value) in extra_claims
        .as_object()
        .expect("extra claims should be object")
    {
        if value.is_null() {
            target.remove(key);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    let mut header = jsonwebtoken::Header::new(alg);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

fn signed_ciba_request_object_for_client(
    client_id: &str,
    kid: &str,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    signed_ciba_request_object_for_client_with_alg(
        client_id,
        kid,
        jsonwebtoken::Algorithm::PS256,
        fixture,
        extra_claims,
    )
}

pub(super) fn signed_ciba_client_assertion(
    client_id: &str,
    kid: &str,
    fixture: &ClientSigningFixture,
) -> String {
    let now = jiff::Timestamp::now().as_second();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("ciba-client-assertion-{}", Uuid::now_v7()),
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

fn ciba_backchannel_body(
    client_id: &str,
    request_object: Option<&str>,
    client_assertion: Option<&str>,
    scope: Option<&str>,
    login_hint: Option<&str>,
) -> String {
    let mut fields = Vec::new();
    fields.push(format!("client_id={}", urlencoding::encode(client_id)));
    fields.push(format!(
        "client_assertion_type={}",
        urlencoding::encode(nazo_auth::CLIENT_ASSERTION_TYPE_JWT_BEARER)
    ));
    if let Some(request_object) = request_object {
        fields.push(format!("request={}", urlencoding::encode(request_object)));
    }
    if let Some(client_assertion) = client_assertion {
        fields.push(format!(
            "client_assertion={}",
            urlencoding::encode(client_assertion)
        ));
    }
    if let Some(scope) = scope {
        fields.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(login_hint) = login_hint {
        fields.push(format!("login_hint={}", urlencoding::encode(login_hint)));
    }
    fields.join("&")
}

#[actix_web::test]
async fn token_ciba_rejects_client_policy_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.security_policy = nazo_auth::ClientSecurityPolicy {
        allow_cross_device_flows: false,
        ..nazo_auth::ClientSecurityPolicy::default()
    };

    let response = call_ciba_token_for_test(&state, &client, "not-stored".to_owned()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("unauthorized_client")
    );
}

#[actix_web::test]
async fn token_ciba_rejects_a_disabled_module_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("disabled-module-kid", &key);
    let modules = nazo_runtime_modules::ActiveModuleSnapshot {
        revision: nazo_runtime_modules::ModuleRevision::new(0),
        accepting: std::collections::BTreeSet::new(),
        draining: std::collections::BTreeSet::new(),
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let response = call_ciba_token_with_modules_for_test(
        &state,
        &client,
        ciba_token_form("not-stored".to_owned()),
        request,
        None,
        "private_key_jwt",
        modules,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "unsupported_grant_type");
}

#[actix_web::test]
async fn token_ciba_rejects_an_invalid_fapi_client_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("invalid-fapi-client-kid", &key);

    let response = call_ciba_token_for_test(&state, &client, "not-stored".to_owned()).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_request");
}

#[actix_web::test]
async fn ciba_backchannel_fails_closed_before_client_state_access() {
    let state = ciba_test_state();
    let application = ciba_test_application(&state).await;
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(application)
            .configure(nazo_http_actix::configure),
    )
    .await;

    let missing_credentials = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("scope=openid&login_hint=subject%40example.test")
        .to_request();
    let response = actix_web::test::call_service(&app, missing_credentials).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_client"
    );

    let mixed_methods = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(
            "client_id=unknown&client_secret=secret&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=jwt",
        )
        .to_request();
    let response = actix_web::test::call_service(&app, mixed_methods).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );

    let lookup_failure = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("client_id=unknown&client_secret=secret")
        .to_request();
    let response = actix_web::test::call_service(&app, lookup_failure).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "server_error"
    );
}

#[actix_web::test]
async fn ciba_backchannel_authentication_errors_use_applicable_http_challenges() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let kid = "backchannel-auth-error-kid";
    let mut client = ciba_private_key_jwt_client(kid, &key);
    client.client_id = format!("ciba-auth-error-client-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("CIBA client should be stored");
    let mut mtls_client = client.clone();
    mtls_client.id = Uuid::now_v7();
    mtls_client.client_id = format!("ciba-mtls-error-client-{}", Uuid::now_v7());
    mtls_client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    mtls_client.tls_client_auth_subject_dn = Some("CN=registered-other-client".to_owned());
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&mtls_client, None, None)
        .await
        .expect("CIBA mTLS client should be stored");
    let application = ciba_test_application(&state).await;
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(
                crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
            ))
            .app_data(application)
            .configure(nazo_http_actix::configure),
    )
    .await;

    let assertion = signed_ciba_client_assertion(&client.client_id, kid, &key);
    let (signed, signature) = assertion.rsplit_once('.').unwrap();
    let invalid_signature = format!(
        "{signed}.{}{}",
        if signature.starts_with('A') { 'B' } else { 'A' },
        &signature[1..]
    );
    let unknown_client = format!("unknown-ciba-client-{}", Uuid::now_v7());
    let unknown_assertion = signed_ciba_client_assertion(&unknown_client, kid, &key);
    for (case, body, basic, certificate) in [
        (
            "invalid JWT signature",
            ciba_backchannel_body(
                &client.client_id,
                None,
                Some(&invalid_signature),
                None,
                None,
            ),
            false,
            false,
        ),
        (
            "unknown JWT client",
            ciba_backchannel_body(&unknown_client, None, Some(&unknown_assertion), None, None),
            false,
            false,
        ),
        (
            "missing mTLS certificate",
            format!("client_id={}", mtls_client.client_id),
            false,
            false,
        ),
        (
            "mismatched mTLS certificate",
            format!("client_id={}", mtls_client.client_id),
            false,
            true,
        ),
        ("invalid Basic credentials", String::new(), true, false),
    ] {
        let mut request = actix_web::test::TestRequest::post()
            .uri("/bc-authorize")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(body);
        if basic {
            request = request.insert_header((header::AUTHORIZATION, "Basic dW5rbm93bjpiYWQ="));
        }
        if certificate {
            request = request
                .peer_addr("127.0.0.1:12345".parse().unwrap())
                .insert_header(("client-cert", ciba_test_mtls_certificate().header.as_str()));
        }
        let response = actix_web::test::call_service(&app, request.to_request()).await;
        assert_eq!(
            response.status(),
            if basic {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            },
            "{case}"
        );
        let challenge = response.headers().get(header::WWW_AUTHENTICATE);
        if basic {
            assert!(
                challenge.unwrap().to_str().unwrap().starts_with("Basic "),
                "{case}"
            );
        } else {
            assert!(challenge.is_none(), "{case}");
        }
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store",
            "{case}"
        );
        assert_eq!(
            oauth_error_code(response.into_parts().1).await,
            "invalid_client",
            "{case}"
        );
    }
}

#[actix_web::test]
async fn ciba_backchannel_validates_request_object_and_creates_bound_state() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let kid = "backchannel-kid";
    let mut client = ciba_private_key_jwt_client(kid, &key);
    client.client_id = format!("ciba-backchannel-client-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("CIBA backchannel client should be stored");

    let user_id = Uuid::now_v7();
    let login_hint = format!("ciba-backchannel-user-{user_id}@example.test");
    insert_ciba_user_with_email(&state, user_id, &login_hint).await;
    let application = ciba_test_application(&state).await;
    let ciba_service = actix_web::web::Data::new(ServerCibaService::new(std::sync::Arc::new(
        CibaStore::new(&state.valkey_connection()),
    )));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(application)
            .configure(nazo_http_actix::configure),
    )
    .await;

    let request_object = signed_ciba_request_object_for_client(
        &client.client_id,
        kid,
        &key,
        json!({
            "scope": "openid profile",
            "login_hint": login_hint,
        }),
    );
    let client_assertion = signed_ciba_client_assertion(&client.client_id, kid, &key);
    let body = ciba_backchannel_body(
        &client.client_id,
        Some(&request_object),
        Some(&client_assertion),
        None,
        None,
    );
    let request = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::test::read_body(response).await;
    let response: Value = serde_json::from_slice(&body).expect("CIBA response should be JSON");
    let auth_req_id = response["auth_req_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .expect("CIBA response should contain auth_req_id");
    assert_eq!(
        response["interval"],
        state.settings.ciba.ciba_poll_interval_seconds
    );

    let stored = load_ciba_request_payload(&ciba_service, auth_req_id)
        .await
        .expect("CIBA state lookup should succeed")
        .expect("successful backchannel request should persist state");
    assert_eq!(stored.client_id, client.client_id);
    assert_eq!(stored.user_id, user_id);
    assert_eq!(stored.status, CibaStatus::Pending);
    assert_eq!(stored.scopes, vec!["openid", "profile"]);
}

#[actix_web::test]
async fn ciba_backchannel_rejects_invalid_request_object_claims_before_user_lookup() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let kid = "backchannel-invalid-kid";
    let login_hint = format!(
        "ciba-backchannel-invalid-user-{}@example.test",
        Uuid::now_v7()
    );
    let mut client = ciba_private_key_jwt_client(kid, &key);
    client.client_id = format!("ciba-backchannel-invalid-client-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("CIBA invalid-request client should be stored");

    let application = ciba_test_application(&state).await;
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(application)
            .configure(nazo_http_actix::configure),
    )
    .await;

    let client_assertion = signed_ciba_client_assertion(&client.client_id, kid, &key);
    let cases = [
        (
            json!({"scope": "openid", "login_hint": login_hint.clone(), "binding_message": null}),
            "invalid_request",
        ),
        (
            json!({"scope": "profile", "login_hint": login_hint.clone()}),
            "invalid_scope",
        ),
        (
            json!({"scope": "openid", "login_hint": login_hint.clone(), "id_token_hint": "unexpected"}),
            "invalid_request",
        ),
        (
            json!({"scope": "openid", "login_hint": login_hint.clone(), "acr_values": "9"}),
            "unknown_user_id",
        ),
    ];
    for (extra_claims, expected_error) in cases {
        let request_object =
            signed_ciba_request_object_for_client(&client.client_id, kid, &key, extra_claims);
        let body = ciba_backchannel_body(
            &client.client_id,
            Some(&request_object),
            Some(&client_assertion),
            None,
            None,
        );
        let request = actix_web::test::TestRequest::post()
            .uri("/bc-authorize")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(body)
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            oauth_error_code(response.into_parts().1).await,
            expected_error
        );
    }

    insert_ciba_user_with_email(&state, Uuid::now_v7(), &login_hint).await;
    let request_object = signed_ciba_request_object_for_client(
        &client.client_id,
        kid,
        &key,
        json!({
            "scope": "openid",
            "login_hint": login_hint,
            "acr_values": "9",
        }),
    );
    let body = ciba_backchannel_body(
        &client.client_id,
        Some(&request_object),
        Some(&client_assertion),
        None,
        None,
    );
    let request = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );
}

#[actix_web::test]
async fn ciba_request_parser_enforces_form_encoding_and_parameter_uniqueness() {
    let body = concat!(
        "scope=+openid%20profile+&login_hint=%E2%80%83user%40example.test%E2%80%83&",
        "id_token_hint=id-token&login_hint_token=hint-token&binding_message=1234&",
        "acr_values=1&requested_expiry=30&client_id=client-1&client_secret=secret&",
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&",
        "client_assertion=assertion&client_notification_token=notification&unknown=ignored"
    );
    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let form = parse_backchannel_authentication_form(&request, &mut payload)
        .await
        .expect("valid CIBA form should parse");
    assert!(form.request.is_none());
    assert_eq!(form.scope.as_deref(), Some("openid profile"));
    assert_eq!(form.login_hint.as_deref(), Some("user@example.test"));
    assert_eq!(form.id_token_hint.as_deref(), Some("id-token"));
    assert_eq!(form.login_hint_token.as_deref(), Some("hint-token"));
    assert_eq!(form.binding_message.as_deref(), Some("1234"));
    assert_eq!(form.acr_values.as_deref(), Some("1"));
    assert_eq!(form.requested_expiry_seconds, Some(30));
    assert_eq!(
        form.client_notification_token.as_deref(),
        Some("notification")
    );

    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("scope=openid&sc%6fpe=profile")
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let duplicate = match parse_backchannel_authentication_form(&request, &mut payload).await {
        Ok(_) => panic!("duplicate CIBA parameters must fail"),
        Err(response) => response,
    };
    assert_eq!(oauth_error_code(duplicate).await, "invalid_request");

    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(body)
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let wrong_content_type =
        match parse_backchannel_authentication_form(&request, &mut payload).await {
            Ok(_) => panic!("CIBA must reject non-form content types"),
            Err(response) => response,
        };
    assert_eq!(wrong_content_type.status(), StatusCode::BAD_REQUEST);

    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("x".repeat(16 * 1024 + 1))
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let oversized = match parse_backchannel_authentication_form(&request, &mut payload).await {
        Ok(_) => panic!("oversized CIBA forms must fail closed"),
        Err(response) => response,
    };
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn ciba_token_request_requires_mtls_binding_before_pending_state() {
    let Some(valkey) = live_test_valkey().await else {
        return;
    };
    let mut state = ciba_test_state();
    state.valkey = valkey;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("pending-mtls-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &auth_req_id, CibaStatus::Pending).await;

    let response = call_ciba_token_for_test(&state, &client, auth_req_id).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("invalid_grant")
    );
}

#[actix_web::test]
async fn ciba_token_request_validates_mtls_binding_before_issuing_approved_token() {
    let Some(valkey) = live_test_valkey().await else {
        return;
    };
    let mut state = ciba_test_state();
    state.valkey = valkey;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("approved-mtls-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &auth_req_id, CibaStatus::Approved).await;

    let response = call_ciba_token_for_test(&state, &client, auth_req_id).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("invalid_grant")
    );
}

#[actix_web::test]
async fn protocol_ciba_http_rejects_outer_field_presence_without_erasing_empty_values() {
    for field in [
        "scope",
        "login_hint",
        "id_token_hint",
        "login_hint_token",
        "binding_message",
        "acr_values",
        "client_notification_token",
        "requested_expiry",
    ] {
        for value in ["", "same-as-signed", "not-a-number", "0"] {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("request", "signed.request.object"),
                    ("client_id", "client-1"),
                    (field, value),
                ])
                .finish();
            let (request, mut payload) = actix_web::test::TestRequest::post()
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload(body)
                .to_http_parts();
            let mut payload = <actix_web::web::Payload as actix_web::FromRequest>::from_request(
                &request,
                &mut payload,
            )
            .await
            .unwrap();
            let response = match parse_backchannel_authentication_form(&request, &mut payload).await
            {
                Ok(_) => panic!(
                    "outer field {field} presence must reject before authentication or storage"
                ),
                Err(response) => response,
            };
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(oauth_error_code(response).await, "invalid_request");
        }
    }
    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("request=signed.request.object&client_id=client-1&client_assertion_type=jwt-bearer&client_assertion=outer-authentication")
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .unwrap();
    let form = parse_backchannel_authentication_form(&request, &mut payload).await
        .expect("signed-only authentication parameters may retain separate outer client-authentication fields");
    assert_eq!(form.client_id.as_deref(), Some("client-1"));
    assert_eq!(
        form.client_assertion.as_deref(),
        Some("outer-authentication")
    );
}
