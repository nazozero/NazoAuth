use super::*;

#[actix_web::test]
async fn authorization_code_holder_error_responses_preserve_oauth_error_classes() {
    let mtls = nazo_http_actix::oauth_endpoint_error_response(
        authorization_code_mtls_holder_error_response(),
    );
    assert_eq!(mtls.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(mtls).await, "invalid_request");

    let mismatch = nazo_http_actix::oauth_endpoint_error_response(
        authorization_code_client_mismatch_response(),
    );
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(mismatch).await, "invalid_grant");

    let dpop = nazo_http_actix::oauth_endpoint_error_response(
        authorization_code_dpop_error_response(DpopError::MissingProof),
    );
    assert_eq!(dpop.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(dpop).await, "invalid_grant");
}

#[test]
fn confidential_required_dpop_client_does_not_pin_refresh_token_to_access_token_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .is_none()
    );
}

#[test]
fn public_dpop_client_binds_refresh_token_to_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "public".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert_eq!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .as_deref(),
        Some("verified-dpop-jkt")
    );
}

#[test]
fn confidential_optional_dpop_code_pins_refresh_token_to_verified_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = Some("request-dpop-jkt".to_owned());

    assert_eq!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .as_deref(),
        Some("verified-dpop-jkt")
    );
}

#[test]
fn bearer_confidential_client_does_not_bind_refresh_token_to_access_token_dpop() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .is_none()
    );
}

#[actix_web::test]
async fn token_authorization_code_requires_sender_constrained_proof_before_consumption() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let mut dpop_client = live_client("client-dpop");
    dpop_client.require_dpop_bound_tokens = true;
    let dpop_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &dpop_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&dpop_client),
            },
        )
        .await;
    let dpop_response = token_authorization_code(
        &fixture.state,
        &req,
        &dpop_client,
        &form_for_code(&dpop_code),
        None,
    )
    .await;
    let (status, body) = token_json_body(dpop_response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(matches!(
        fixture.code_state(&dpop_code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let mtls_client = live_client("client-mtls");
    let mut mtls_payload = payload_for_client(&mtls_client);
    mtls_payload.mtls_x5t_s256 = Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ".to_owned());
    let mtls_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &mtls_code,
            &AuthorizationCodeState::Pending {
                payload: mtls_payload,
            },
        )
        .await;
    let mtls_response = token_authorization_code(
        &fixture.state,
        &req,
        &mtls_client,
        &form_for_code(&mtls_code),
        None,
    )
    .await;
    let (status, body) = token_json_body(mtls_response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(matches!(
        fixture.code_state(&mtls_code).await,
        AuthorizationCodeState::Pending { .. }
    ));
}

#[actix_web::test]
async fn token_authorization_code_enforces_client_mtls_policy_before_consumption() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let mut client = live_client(&format!("client-mtls-policy-{}", Uuid::now_v7()));
    client.require_mtls_bound_tokens = true;
    fixture.insert_client(&client).await;
    let user = fixture.insert_user().await;
    let mut unbound_payload = payload_for_client(&client);
    unbound_payload.user_id = user.id;
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Pending {
                payload: unbound_payload,
            },
        )
        .await;

    let response =
        token_authorization_code(&fixture.state, &req, &client, &form_for_code(&code), None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(matches!(
        fixture.code_state(&code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let bound_code = format!("code-{}", Uuid::now_v7());
    let mut bound_payload = payload_for_client(&client);
    bound_payload.user_id = user.id;
    fixture
        .store_code_state(
            &bound_code,
            &AuthorizationCodeState::Pending {
                payload: bound_payload,
            },
        )
        .await;
    let certificate =
        crate::test_support::rfc9440_certificate_fixture("authorization-code-mtls-policy");
    let verified_req = actix_web::test::TestRequest::post()
        .uri("/token")
        .app_data(actix_web::web::Data::new(
            crate::http::mtls::MtlsCertificateSource::new(
                crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
            ),
        ))
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header(("client-cert", certificate.header.as_str()))
        .to_http_request();

    let bound_response = token_authorization_code(
        &fixture.state,
        &verified_req,
        &client,
        &form_for_code(&bound_code),
        None,
    )
    .await;
    let (bound_status, bound_body) = token_json_body(bound_response).await;

    assert_eq!(
        bound_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "holder binding should succeed before the fixture reaches its intentionally invalid signing key: {bound_body}"
    );
    assert_eq!(bound_body["error"], "server_error");
}

#[actix_web::test]
async fn token_authorization_code_accepts_matching_mtls_bound_code_before_issuing_response() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("client-mtls-bound-{}", Uuid::now_v7()));
    fixture.insert_client(&client).await;
    let user = fixture.insert_user().await;
    let certificate = crate::test_support::rfc9440_certificate_fixture("authorization-code-actual");
    let mut payload = payload_for_client(&client);
    payload.user_id = user.id;
    payload.mtls_x5t_s256 = Some(certificate.thumbprint.clone());
    payload.scopes = vec!["accounts".to_owned()];
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .app_data(actix_web::web::Data::new(
            crate::http::mtls::MtlsCertificateSource::new(
                crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
            ),
        ))
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header(("client-cert", certificate.header.as_str()))
        .to_http_request();

    let response =
        token_authorization_code(&fixture.state, &req, &client, &form_for_code(&code), None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the fixture uses an intentionally invalid signing key after holder binding succeeds: {body}"
    );
    assert_eq!(body["error"], "server_error");
}
