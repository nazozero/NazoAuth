use super::*;

async fn store_ciba_session(state: &TestInfrastructure, sid: &str, user_id: Uuid) {
    let payload = nazo_oauth_server::sessions::SessionPayload {
        user_id,
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned(), "otp".to_owned(), "mfa".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
        serde_json::to_string(&payload).expect("CIBA session should serialize"),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("CIBA session should store");
}

#[actix_web::test]
async fn ciba_decision_storage_failure_maps_to_non_cacheable_server_error() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    let sid = format!("ciba-corrupt-session-{}", Uuid::now_v7());
    store_ciba_session(&state, &sid, user_id).await;
    let id = format!("ciba-corrupt-{}", Uuid::now_v7());
    valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::ciba_request_storage_key(&id),
        "{not-json".to_owned(),
        60,
    )
    .await
    .expect("corrupt fixture stores");
    let settings = state.settings.clone();
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("runtime fixture");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;
    let request = actix_web::test::TestRequest::post()
        .uri(&format!("/auth/ciba/{id}"))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            sid,
        ))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.csrf_cookie_name.clone(),
            "csrf",
        ))
        .set_json(json!({"decision":"approve","csrf_token":"csrf"}))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "server_error"
    );
}

#[actix_web::test]
async fn ciba_verification_page_preserves_redirect_and_non_cacheable_headers() {
    let state = ciba_test_state_with(|settings| {
        settings.endpoint.frontend_base_url = "https://frontend.example/".to_owned();
    });
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::get()
        .uri("/ciba/auth-request-id")
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://frontend.example/ciba/auth-request-id")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
}

#[actix_web::test]
async fn ciba_verification_loads_the_bound_user_and_rejects_a_session_mismatch() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("verification-kid", &key);
    client.client_id = format!("ciba-verification-client-{}", Uuid::now_v7());
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("verification CIBA client should be stored");

    let user_id = Uuid::now_v7();
    let other_user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    insert_ciba_user(&state, other_user_id).await;
    let auth_req_id = format!("verification-{}", Uuid::now_v7());
    store_ciba_state_with_user(&state, &client, &auth_req_id, user_id, CibaStatus::Pending).await;
    let session_id = format!("ciba-session-{}", Uuid::now_v7());
    let other_session_id = format!("ciba-session-other-{}", Uuid::now_v7());
    store_ciba_session(&state, &session_id, user_id).await;
    store_ciba_session(&state, &other_session_id, other_user_id).await;

    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::get()
        .uri(&format!("/auth/ciba/{auth_req_id}"))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            session_id,
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::test::read_body(response).await;
    let view: Value = serde_json::from_slice(&body).expect("verification view should be JSON");
    assert_eq!(view["auth_req_id"], auth_req_id);
    assert!(view["request"].is_object());

    let request = actix_web::test::TestRequest::get()
        .uri(&format!("/auth/ciba/{auth_req_id}"))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            other_session_id,
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "access_denied"
    );
}

#[actix_web::test]
async fn ciba_browser_decision_rejects_invalid_csrf_before_session_lookup() {
    let state = ciba_test_state();
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::post()
        .uri("/auth/ciba/not-stored")
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "session-csrf-check",
        ))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.csrf_cookie_name.clone(),
            "csrf-cookie",
        ))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(r#"{"decision":"approve","csrf_token":"csrf-body-mismatch"}"#)
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );
}

#[actix_web::test]
async fn ciba_browser_decision_commits_user_context_and_rejects_replay() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("browser-decision-kid", &key);
    client.client_id = format!("ciba-browser-decision-client-{}", Uuid::now_v7());
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("CIBA browser-decision client should be stored");
    let user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    let auth_req_id = format!("browser-decision-{}", Uuid::now_v7());
    store_ciba_state_with_user(&state, &client, &auth_req_id, user_id, CibaStatus::Pending).await;
    let session_id = format!("ciba-browser-session-{}", Uuid::now_v7());
    store_ciba_session(&state, &session_id, user_id).await;

    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let ciba_service = actix_web::web::Data::new(ServerCibaService::new(std::sync::Arc::new(
        CibaStore::new(&state.valkey_connection()),
    )));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let decision_request = || {
        actix_web::test::TestRequest::post()
            .uri(&format!("/auth/ciba/{auth_req_id}"))
            .cookie(actix_web::cookie::Cookie::new(
                state.settings.session.session_cookie_name.clone(),
                session_id.clone(),
            ))
            .cookie(actix_web::cookie::Cookie::new(
                state.settings.session.csrf_cookie_name.clone(),
                "csrf-session-token",
            ))
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(r#"{"decision":"approve","csrf_token":"csrf-session-token"}"#)
            .to_request()
    };
    let response = actix_web::test::call_service(&app, decision_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::test::read_body(response).await;
    let value: Value = serde_json::from_slice(&body).expect("decision response should be JSON");
    assert_eq!(value["success"], true);

    let state_after = load_ciba_request_payload(&ciba_service, &auth_req_id)
        .await
        .expect("CIBA state lookup should succeed")
        .expect("decision should retain CIBA state for polling");
    assert_eq!(state_after.status, CibaStatus::Approved);
    let context = state_after
        .authentication_context
        .expect("browser decision should persist authentication context");
    assert!(
        context
            .oidc_sid
            .as_deref()
            .is_some_and(|sid| sid.starts_with("oidc-"))
    );

    let response = actix_web::test::call_service(&app, decision_request()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );
}

/// CB-03: the OIDC subject snapshot read filters `is_active` in SQL, so an
/// inactive row is rejected as invalid_grant before conversion — even when the
/// stored role/admin_level combination is corrupt. An ACTIVE row whose
/// identity conversion fails still propagates as server_error.
#[actix_web::test]
async fn ciba_oidc_poll_classifies_inactive_and_corrupt_subject_states() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("subject-classification-kid", &key);
    client.client_id = format!("ciba-subject-class-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    persist_ciba_test_client(&state, &client).await;

    async fn corrupt(
        connection: &mut diesel_async::AsyncPgConnection,
        user_id: Uuid,
        active: bool,
    ) {
        sql_query(
            "UPDATE users SET is_active = $3, role = 'admin', admin_level = 0 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .bind::<Bool, _>(active)
        .execute(connection)
        .await
        .expect("subject fixture corruption should apply");
    }

    let inactive_corrupt = Uuid::now_v7();
    insert_ciba_user(&state, inactive_corrupt).await;
    {
        let mut connection = get_conn(&state.diesel_db)
            .await
            .expect("CIBA test database connection should be available");
        corrupt(&mut connection, inactive_corrupt, false).await;
    }
    let auth_req_id = format!("inactive-corrupt-{}", Uuid::now_v7());
    store_ciba_state_with_user(
        &state,
        &client,
        &auth_req_id,
        inactive_corrupt,
        CibaStatus::Approved,
    )
    .await;
    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(
        (response.status(), oauth_error_code(response).await.as_str()),
        (StatusCode::BAD_REQUEST, "invalid_grant"),
        "an inactive subject is filtered before conversion and must report \
         invalid_grant regardless of corrupt row data"
    );

    let active_corrupt = Uuid::now_v7();
    insert_ciba_user(&state, active_corrupt).await;
    {
        let mut connection = get_conn(&state.diesel_db)
            .await
            .expect("CIBA test database connection should be available");
        corrupt(&mut connection, active_corrupt, true).await;
    }
    let auth_req_id = format!("active-corrupt-{}", Uuid::now_v7());
    store_ciba_state_with_user(
        &state,
        &client,
        &auth_req_id,
        active_corrupt,
        CibaStatus::Approved,
    )
    .await;
    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(
        (response.status(), oauth_error_code(response).await.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "server_error"),
        "an active subject whose stored identity fails conversion must fail closed"
    );
}

/// CB-01/CB-02/CB-06: the approved OIDC CIBA poll+issue path reads the active
/// subject claims exactly once — the request-local snapshot prepared at the
/// poll boundary is consumed by shared issuance without a second claims read.
/// A non-OIDC approved CIBA grant keeps the original `users.by_id` active
/// check and never touches the OIDC subject-claims read.
#[actix_web::test]
async fn ciba_approved_poll_reads_subject_claims_once_for_oidc_and_never_for_plain() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    state.keyset =
        crate::test_support::test_key_manager_with_auxiliary(jsonwebtoken::Algorithm::PS256);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("claims-count-kid", &key);
    client.client_id = format!("ciba-claims-count-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    // `insert` persists the fixture's `client.id`, which the issuance commit
    // uses as the oauth_token_issuances FK — the `upsert` helper does not
    // write the id column and would leave commit-time FK mismatches.
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("claims-count CIBA client should be stored");

    let counting = crate::test_support::CountingTokenRepository::new(std::sync::Arc::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
    ));
    let token_service = ServerTokenService::new(
        counting.clone(),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );

    let poll = |auth_req_id: String| {
        let certificate = ciba_test_mtls_certificate();
        call_ciba_token_with_prepared_service(
            &state,
            &token_service,
            &client,
            ciba_token_form(auth_req_id),
            actix_web::test::TestRequest::post()
                .uri("/token")
                .app_data(actix_web::web::Data::new(
                    crate::http::mtls::MtlsCertificateSource::new(
                        crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
                    ),
                ))
                .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
                .insert_header(("client-cert", certificate.header.as_str()))
                .to_http_request(),
            None,
            "private_key_jwt",
            state.active_module_snapshot(),
        )
    };

    // Baseline: the identical request through the existing helper must issue
    // before the counting assertions are meaningful.
    let baseline_user = Uuid::now_v7();
    insert_ciba_user(&state, baseline_user).await;
    let baseline_req = format!("oidc-baseline-{}", Uuid::now_v7());
    store_ciba_state_with_user(
        &state,
        &client,
        &baseline_req,
        baseline_user,
        CibaStatus::Approved,
    )
    .await;
    let baseline = call_ciba_token_with_mtls_for_test(&state, &client, baseline_req).await;
    let status = baseline.status();
    let body = actix_web::body::to_bytes(baseline.into_body())
        .await
        .expect("baseline CIBA response should collect");
    assert_eq!(
        status,
        StatusCode::OK,
        "baseline OIDC CIBA should issue: {}",
        String::from_utf8_lossy(&body)
    );

    let user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    let auth_req_id = format!("oidc-claims-count-{}", Uuid::now_v7());
    store_ciba_state_with_user(&state, &client, &auth_req_id, user_id, CibaStatus::Approved).await;
    let response = poll(auth_req_id).await;
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("CIBA response should collect");
    let value: Value = serde_json::from_slice(&body).expect("CIBA response should be JSON");
    assert_eq!(
        status,
        StatusCode::OK,
        "OIDC CIBA should issue: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(value["access_token"].as_str().is_some());
    assert!(value["id_token"].as_str().is_some());
    assert_eq!(
        counting.active_subject_claims_count(),
        1,
        "the OIDC poll+issue path must read active subject claims exactly once"
    );

    // Non-OIDC CIBA: same approved flow minus the openid scope. The poll must
    // not read OIDC subject claims at all — the plain active-user check in the
    // CIBA account store path remains the only subject read.
    let plain_user = Uuid::now_v7();
    insert_ciba_user(&state, plain_user).await;
    let plain_req_id = format!("plain-claims-count-{}", Uuid::now_v7());
    let now = Utc::now().timestamp();
    CibaStore::new(&state.valkey_connection())
        .create(
            &plain_req_id,
            &CibaRequestState {
                client_id: client.client_id.clone(),
                user_id: plain_user,
                scopes: vec!["profile".to_owned()],
                audiences: vec!["resource://default".to_owned()],
                acr: None,
                authentication_context: Some(CibaAuthenticationContext {
                    auth_time: now,
                    amr: vec!["pwd".to_owned()],
                    oidc_sid: Some(format!("ciba-test-session-{plain_user}")),
                }),
                binding_message: None,
                issued_at: now,
                status: CibaStatus::Approved,
                interval_seconds: 5,
                expires_at: now + 600,
                retention_expires_at: now + 720,
                last_poll_at: None,
                ping_notification: None,
            },
        )
        .await
        .expect("plain CIBA state should be stored");
    let response = poll(plain_req_id).await;
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("CIBA response should collect");
    let value: Value = serde_json::from_slice(&body).expect("CIBA response should be JSON");
    assert_eq!(
        status,
        StatusCode::OK,
        "non-OIDC CIBA should issue: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(value["access_token"].as_str().is_some());
    assert!(value.get("id_token").is_none());
    assert_eq!(
        counting.active_subject_claims_count(),
        1,
        "the non-OIDC CIBA path must not read OIDC subject claims"
    );
}
