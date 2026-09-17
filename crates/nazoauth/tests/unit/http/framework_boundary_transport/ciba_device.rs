use super::live_transport_state;

mod ciba_device_contract {
    use crate::test_support::{
        ClientSigningFixture, TestInfrastructure, client_signing_fixture, valkey::valkey_set_ex,
    };
    use actix_web::{
        HttpRequest, HttpResponse,
        test::TestRequest,
        web::{Data, Form},
    };
    use chrono::Utc;
    use diesel::{
        sql_query,
        sql_types::{Bool, Text, Uuid as SqlUuid},
    };
    use diesel_async::RunQueryDsl;
    use nazo_auth::{CibaAuthenticationContext, CibaRequestState, CibaStatus};
    use nazo_identity::DEFAULT_ORGANIZATION_ID;
    use nazo_identity::DEFAULT_REALM_ID;
    use nazo_identity::DEFAULT_TENANT_ID;
    use nazo_oauth_server::contracts::token_forms::TokenForm;
    use nazo_oauth_server::domain::rows::ClientRow;
    use nazo_oauth_server::services::ServerCibaService;
    use nazo_oauth_server::services::ServerTokenService;
    use nazo_oauth_server::token::ciba::{
        CIBA_GRANT_TYPE, CibaTokenContext, CibaTokenHandles, token_ciba,
    };
    use nazo_oauth_server::token::issue::TokenIssuanceContext;
    use nazo_postgres::get_conn;
    use nazo_valkey::CibaStore;
    use serde_json::{Value, json};
    use std::sync::{Arc, OnceLock};
    use uuid::Uuid;
    fn ciba_token_form(auth_req_id: String) -> TokenForm {
        TokenForm {
            grant_type: CIBA_GRANT_TYPE.to_owned(),
            code: None,
            device_code: None,
            auth_req_id: Some(auth_req_id),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            device_secret: None,
            scope: None,
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            assertion: None,
            requested_token_type: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audiences: Vec::new(),
            has_audience_param: false,
        }
    }

    async fn store_ciba_state(
        state: &TestInfrastructure,
        client: &ClientRow,
        auth_req_id: &str,
        status: CibaStatus,
    ) {
        store_ciba_state_with_user(state, client, auth_req_id, Uuid::now_v7(), status).await;
    }

    async fn store_ciba_state_with_user(
        state: &TestInfrastructure,
        client: &ClientRow,
        auth_req_id: &str,
        user_id: Uuid,
        status: CibaStatus,
    ) {
        let now = Utc::now().timestamp();
        let authentication_context = match status {
            CibaStatus::Approved => Some(CibaAuthenticationContext {
                auth_time: now,
                amr: vec!["pwd".to_owned()],
                oidc_sid: Some(format!("ciba-test-session-{user_id}")),
            }),
            CibaStatus::Pending | CibaStatus::Denied => None,
        };
        CibaStore::new(&state.valkey_connection())
            .create(
                auth_req_id,
                &CibaRequestState {
                    client_id: client.client_id.clone(),
                    user_id,
                    scopes: vec!["openid".to_owned()],
                    audiences: vec!["resource://default".to_owned()],
                    acr: None,
                    authentication_context,
                    binding_message: None,
                    issued_at: now,
                    status,
                    interval_seconds: 5,
                    expires_at: now + 600,
                    retention_expires_at: now + 720,
                    last_poll_at: None,
                    ping_notification: None,
                },
            )
            .await
            .expect("CIBA state should be stored");
    }

    async fn persist_ciba_test_client(state: &TestInfrastructure, client: &ClientRow) {
        nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
            .insert(client, None, None)
            .await
            .expect("CIBA test client should be persisted");
    }

    async fn insert_ciba_user(state: &TestInfrastructure, user_id: Uuid) {
        insert_ciba_user_with_email(state, user_id, &format!("ciba-user-{user_id}@example.test"))
            .await;
    }

    async fn insert_ciba_user_with_email(state: &TestInfrastructure, user_id: Uuid, email: &str) {
        let mut connection = get_conn(&state.diesel_db)
            .await
            .expect("CIBA test database connection should be available");
        sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(user_id)
            .execute(&mut connection)
            .await
            .expect("CIBA test user cleanup should succeed");
        sql_query(
            "INSERT INTO users (\
            id, tenant_id, realm_id, organization_id, username, email, password_hash,\
            is_active, mfa_enabled, email_verified, role, admin_level\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, TRUE, 'user', 0)",
        )
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(format!("ciba-user-{user_id}"))
        .bind::<Text, _>(email.to_owned())
        .bind::<Text, _>("ciba-test-password-hash")
        .bind::<Bool, _>(true)
        .execute(&mut connection)
        .await
        .expect("CIBA test user should insert");
    }

    fn ciba_test_mtls_certificate() -> &'static crate::test_support::Rfc9440CertificateFixture {
        static CERTIFICATE: OnceLock<crate::test_support::Rfc9440CertificateFixture> =
            OnceLock::new();
        CERTIFICATE.get_or_init(|| crate::test_support::rfc9440_certificate_fixture("ciba-test"))
    }

    fn configure_ciba_test_mtls_proxy(state: &mut TestInfrastructure) {
        let mut settings = (*state.settings).clone();
        settings.endpoint.trusted_proxy_cidrs = vec![
            nazo_http_actix::IpCidr::parse("127.0.0.1/32")
                .expect("trusted proxy CIDR should parse"),
        ];
        state.settings = Arc::new(settings);
    }

    async fn call_ciba_token_with_mtls_for_test(
        state: &TestInfrastructure,
        client: &ClientRow,
        auth_req_id: String,
    ) -> HttpResponse {
        let certificate = ciba_test_mtls_certificate();
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
        call_ciba_token_with_request_for_test(state, client, auth_req_id, req).await
    }

    fn ciba_private_key_jwt_client_with_alg(
        kid: &str,
        fixture: &ClientSigningFixture,
    ) -> ClientRow {
        let public_jwk = fixture.public_jwk(kid);
        let mut client = client_row! {
            id: Uuid::now_v7(),
            tenant_id: DEFAULT_TENANT_ID,
            realm_id: DEFAULT_REALM_ID,
            organization_id: DEFAULT_ORGANIZATION_ID,
            client_id: "client-1".to_owned(),
            client_name: "CIBA Client".to_owned(),
            client_type: "confidential".to_owned(),
            client_secret_hash: None,
            redirect_uris: json!(["https://client.example/callback"]),
            scopes: json!(["openid", "profile", "email", "offline_access"]),
            allowed_audiences: json!(["resource://default"]),
            grant_types: json!([CIBA_GRANT_TYPE, "refresh_token"]),
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
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
            is_active: true,
            jwks: Some(json!({"keys": [public_jwk]})),
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            post_logout_redirect_uris: json!([]),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
        };
        client.security_policy.allow_cross_device_flows = true;
        client
    }

    async fn store_device_session(state: &TestInfrastructure, session_id: &str, user_id: Uuid) {
        let payload = nazo_oauth_server::sessions::SessionPayload {
            user_id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
            oidc_sid: Some(format!("device-oidc-{session_id}")),
        };
        valkey_set_ex(
            &state.valkey,
            nazo_valkey::test_support::state_storage_key(format!("oauth:session:{session_id}")),
            serde_json::to_string(&payload).expect("device session should serialize"),
            state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("device session should store");
    }

    async fn call_ciba_token_with_request_for_test(
        state: &TestInfrastructure,
        client: &ClientRow,
        id: String,
        req: HttpRequest,
    ) -> HttpResponse {
        let connection = state.valkey_connection();
        let token_service = ServerTokenService::new(
            crate::test_support::token_issuance_repository(state.diesel_db.clone()),
            Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
            state.keyset.clone(),
        );
        let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
        let modules = state.active_module_snapshot();
        let authorization =
            crate::http::token::issue::test_support::test_authorization_service(state);
        let issuance = TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
            security_audit: crate::http::authorization::test_support::test_security_audit(),
            remote_client_documents: crate::test_support::test_remote_client_documents(),
        };
        let handles = CibaTokenHandles::new(
            Arc::new(ServerCibaService::new(Arc::new(CibaStore::new(
                &connection,
            )))),
            Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            Arc::new(crate::http::token::ciba::ciba_config(
                state.settings.as_ref(),
            )),
        );
        let client_ip = nazo_http_actix::ClientIpConfig::new(
            &state.settings.endpoint.trusted_proxy_cidrs,
            state.settings.endpoint.client_ip_header_mode,
        );
        let facts = crate::http::token::dispatch::token_request_facts(&req, &client_ip);
        present_token_result(
            token_ciba(
                CibaTokenContext {
                    token_service: &token_service,
                    issuance: &issuance,
                    handles: &handles,
                    request: &facts,
                },
                client,
                &ciba_token_form(id),
                None,
                "private_key_jwt",
            )
            .await,
        )
    }

    fn present_token_result(
        result: Result<
            nazo_oauth_server::contracts::token_endpoint::TokenEndpointSuccess,
            nazo_oauth_server::contracts::oauth_error::OAuthEndpointError,
        >,
    ) -> HttpResponse {
        match result {
            Ok(success) => nazo_http_actix::token_endpoint_success_response(success),
            Err(error) => nazo_http_actix::oauth_endpoint_error_response(error),
        }
    }

    #[derive(Debug)]
    struct Wire {
        status: u16,
        headers: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
    }
    async fn wire(response: HttpResponse) -> Wire {
        let status = response.status().as_u16();
        let mut headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect();
        headers.sort();
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("body bytes")
            .to_vec();
        Wire {
            status,
            headers,
            body,
        }
    }
    fn json_headers(no_store: bool, pragma: bool) -> Vec<(String, Vec<u8>)> {
        let mut headers = vec![("content-type".to_owned(), b"application/json".to_vec())];
        if no_store {
            headers.push(("cache-control".to_owned(), b"no-store".to_vec()));
        }
        if pragma {
            headers.push(("pragma".to_owned(), b"no-cache".to_vec()));
        }
        headers.sort();
        headers
    }
    async fn token_error(response: HttpResponse, expected: &[u8]) {
        let actual = wire(response).await;
        assert_eq!(actual.status, 400, "{actual:?}");
        assert_eq!(actual.headers, json_headers(true, true));
        assert_eq!(actual.body, expected);
    }
    fn verify_jwt(state: &TestInfrastructure, token: &str, audience: &str, subject: &str) -> Value {
        let header = jsonwebtoken::decode_header(token).expect("issued compact JWT header");
        assert_ne!(header.alg, jsonwebtoken::Algorithm::HS256);
        let jwks: jsonwebtoken::jwk::JwkSet =
            serde_json::from_value(state.keyset.snapshot().jwks())
                .expect("server verification JWKS");
        let jwk = jwks
            .find(header.kid.as_deref().expect("issued JWT kid"))
            .expect("issued kid belongs to keyset");
        let key = jsonwebtoken::DecodingKey::from_jwk(jwk).expect("public decoding key");
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_audience(&[audience]);
        validation.set_issuer(&["https://issuer.example"]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.leeway = 0;
        let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
            .expect("issued JWT signature and claims")
            .claims;
        assert_eq!(claims["sub"], subject);
        let now = Utc::now().timestamp();
        let iat = claims["iat"].as_i64().expect("iat integer");
        let exp = claims["exp"].as_i64().expect("exp integer");
        assert!(iat <= now && now - iat <= 60);
        assert!(exp > now && exp > iat);
        claims
    }
    async fn ciba_fixture() -> (TestInfrastructure, ClientRow) {
        let mut state = super::live_transport_state().await;
        configure_ciba_test_mtls_proxy(&mut state);
        state.keyset =
            crate::test_support::test_key_manager_with_auxiliary(jsonwebtoken::Algorithm::PS256);
        let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
        let mut client = ciba_private_key_jwt_client_with_alg("golden-ciba", &key);
        client.client_id = format!("golden-ciba-{}", client.id);
        client.require_mtls_bound_tokens = true;
        persist_ciba_test_client(&state, &client).await;
        (state, client)
    }
    #[actix_web::test]
    async fn real_ciba_pending_slow_down_terminal_and_single_use_replay_wire() {
        let (state, client) = ciba_fixture().await;
        let pending = format!("golden-pending-{}", Uuid::now_v7());
        store_ciba_state(&state, &client, &pending, CibaStatus::Pending).await;
        token_error(call_ciba_token_with_mtls_for_test(&state, &client, pending.clone()).await, br#"{"error":"authorization_pending","error_description":"CIBA authorization is pending."}"#).await;
        token_error(
            call_ciba_token_with_mtls_for_test(&state, &client, pending).await,
            br#"{"error":"slow_down","error_description":"CIBA polling too fast."}"#,
        )
        .await;
        let denied = format!("golden-denied-{}", Uuid::now_v7());
        store_ciba_state(&state, &client, &denied, CibaStatus::Denied).await;
        token_error(
            call_ciba_token_with_mtls_for_test(&state, &client, denied).await,
            br#"{"error":"access_denied","error_description":"CIBA authorization was denied."}"#,
        )
        .await;
        let user = Uuid::now_v7();
        insert_ciba_user(&state, user).await;
        let approved = format!("golden-approved-{}", Uuid::now_v7());
        store_ciba_state_with_user(&state, &client, &approved, user, CibaStatus::Approved).await;
        let first =
            wire(call_ciba_token_with_mtls_for_test(&state, &client, approved.clone()).await).await;
        assert_eq!(first.status, 200, "{first:?}");
        assert_eq!(first.headers, json_headers(true, true));
        let body: Value = serde_json::from_slice(&first.body).expect("token JSON");
        let access = verify_jwt(
            &state,
            body["access_token"].as_str().expect("access token"),
            "resource://default",
            &user.to_string(),
        );
        assert_eq!(
            access["cnf"]["x5t#S256"],
            ciba_test_mtls_certificate().thumbprint
        );
        assert_eq!(access["client_id"], client.client_id);
        assert_eq!(
            access["exp"].as_i64().unwrap() - access["iat"].as_i64().unwrap(),
            body["expires_in"].as_i64().unwrap()
        );
        let id = verify_jwt(
            &state,
            body["id_token"].as_str().expect("id token"),
            &client.client_id,
            &user.to_string(),
        );
        assert_eq!(id["amr"], json!(["pwd"]));
        assert!(id["auth_time"].as_i64().is_some());
        assert!(body.get("refresh_token").is_none());
        assert!(
            CibaStore::load(&CibaStore::new(&state.valkey_connection()), &approved)
                .await
                .expect("post issuance state")
                .is_none()
        );
        token_error(
            call_ciba_token_with_mtls_for_test(&state, &client, approved).await,
            br#"{"error":"invalid_grant","error_description":"CIBA auth_req_id is expired."}"#,
        )
        .await;
    }

    #[actix_web::test]
    async fn real_device_decision_csrf_session_preserve_state_then_deny_wire() {
        use crate::http::token::device::{DeviceDecisionForm, device_decision};
        use crate::http::token::device_config::DeviceHttpConfig;
        use nazo_oauth_server::services::ServerDeviceGrantService;
        use nazo_oauth_server::token::device::DeviceDecisionHandles;
        let state = super::live_transport_state().await;
        let user = Uuid::now_v7();
        insert_ciba_user(&state, user).await;
        let sid = format!("golden-session-{}", Uuid::now_v7());
        store_device_session(&state, &sid, user).await;
        let now = Utc::now();
        let payload = nazo_auth::DeviceAuthorizationPayload {
            client_id: format!("golden-device-{}", Uuid::now_v7()),
            client_name: "Golden Device".into(),
            scopes: vec!["openid".into()],
            resource_indicators: vec!["resource://default".into()],
            authorization_details: json!([]),
            interval_seconds: 5,
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(10),
        };
        let service = ServerDeviceGrantService::new(Arc::new(nazo_valkey::DeviceStore::new(
            &state.valkey_connection(),
        )));
        let device_code = format!("golden-device-code-{}", Uuid::now_v7());
        let user_code = format!("GOLDEN{}", Uuid::now_v7().simple()).to_uppercase();
        let (_, code) = service
            .create_unique(&payload, 600, || device_code.clone(), || user_code.clone())
            .await
            .expect("device persisted");
        let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
            state.diesel_db.clone(),
            state.settings.as_ref(),
        )
        .expect("runtime");
        let sessions =
            Data::new(crate::http::sessions::test_support::profile_session_handles(&state));
        let config = Data::new(DeviceHttpConfig::from(state.settings.as_ref()));
        let rate_limit = &state.settings.identity.rate_limit;
        let handles = Data::new(DeviceDecisionHandles::new(
            Arc::new(crate::http::token::issue::test_support::test_authorization_service(&state)),
            Arc::new(service),
            Arc::new(nazo_postgres::AuthorizationFlowRepository::new(
                state.diesel_db.clone(),
                DEFAULT_TENANT_ID,
            )),
            Arc::new(
                crate::http::token::device_config::device_config_from_settings(
                    state.settings.as_ref(),
                ),
            ),
            runtime.snapshot_store(),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .expect("empty resolver should build"),
            ),
            Arc::new(
                nazo_oauth_server::rate_limit::TokenManagementRequestLimiter::new(
                    Arc::new(nazo_valkey::RateLimitStore::new(&state.valkey_connection())),
                    rate_limit.window_seconds,
                    rate_limit.token_management_max_requests,
                ),
            ),
            Arc::new(crate::adapters::audit::TenantSecurityAudit::new(
                state.settings.tenant.context.tenant_id,
            )),
        ));
        let check_state = ServerDeviceGrantService::new(Arc::new(nazo_valkey::DeviceStore::new(
            &state.valkey_connection(),
        )));
        let before = serde_json::to_value(
            check_state
                .pending_request_for_user_code(&code, Utc::now)
                .await
                .expect("read pending"),
        )
        .unwrap();
        for (session, csrf, expected_status) in [
            (true, None, 400),
            (true, Some("wrong"), 400),
            (false, Some("golden-csrf"), 401),
            (true, Some("golden-csrf"), 200),
        ] {
            let mut request = TestRequest::post().uri("/device/decision");
            if session {
                request = request.cookie(actix_web::cookie::Cookie::new(
                    state.settings.session.session_cookie_name.clone(),
                    sid.clone(),
                ));
            }
            request = request.cookie(actix_web::cookie::Cookie::new(
                state.settings.session.csrf_cookie_name.clone(),
                "golden-csrf",
            ));
            let form: DeviceDecisionForm = serde_json::from_value(
                json!({"user_code":code,"decision":"deny","csrf_token":csrf}),
            )
            .expect("device form");
            let response = wire(
                device_decision(
                    handles.clone(),
                    sessions.clone(),
                    config.clone(),
                    request.to_http_request(),
                    Form(form),
                )
                .await,
            )
            .await;
            assert_eq!(response.status, expected_status, "{response:?}");
            if expected_status == 400 {
                assert_eq!(response.headers, json_headers(false, false));
                assert_eq!(
                    response.body,
                    br#"{"error":"invalid_request","error_description":"Request failed."}"#
                );
            } else if expected_status == 401 {
                assert_eq!(
                    response.body,
                    br#"{"error":"login_required","error_description":"Request failed."}"#
                );
                assert_eq!(
                    response
                        .headers
                        .iter()
                        .filter(|(k, _)| k != "set-cookie")
                        .cloned()
                        .collect::<Vec<_>>(),
                    json_headers(false, false)
                );
                let cookies: Vec<_> = response
                    .headers
                    .iter()
                    .filter(|(k, _)| k == "set-cookie")
                    .collect();
                assert_eq!(cookies.len(), 2);
                for name in [
                    &state.settings.session.session_cookie_name,
                    &state.settings.session.csrf_cookie_name,
                ] {
                    let raw = cookies
                        .iter()
                        .find(|(_, v)| v.starts_with(format!("{name}=").as_bytes()))
                        .expect("clearing cookie");
                    let cookie =
                        actix_web::cookie::Cookie::parse(std::str::from_utf8(&raw.1).unwrap())
                            .unwrap();
                    assert_eq!(cookie.value(), "");
                    assert_eq!(cookie.path(), Some("/"));
                    assert_eq!(cookie.http_only(), Some(true));
                    assert_eq!(cookie.same_site(), Some(actix_web::cookie::SameSite::Lax));
                    assert_eq!(
                        cookie.secure().unwrap_or(false),
                        state.settings.session.cookie_secure
                    );
                    assert_eq!(cookie.max_age().unwrap().whole_seconds(), 0);
                    assert!(
                        cookie
                            .expires_datetime()
                            .expect("removal expiry")
                            .unix_timestamp()
                            < Utc::now().timestamp()
                    );
                }
            } else {
                assert!(response.headers.is_empty());
                assert!(response.body.is_empty());
            }
            let after = serde_json::to_value(
                check_state
                    .pending_request_for_user_code(&code, Utc::now)
                    .await
                    .expect("read after decision"),
            )
            .unwrap();
            if expected_status != 200 {
                assert_eq!(
                    after, before,
                    "rejected browser request must not consume device state"
                );
            } else {
                assert!(after.is_null());
            }
        }
    }
    #[actix_web::test]
    async fn real_single_use_issuance_rejects_a_consumed_grant_key() {
        use nazo_auth::TokenIssuanceMode;
        use nazo_oauth_server::token::issue::issue_token_response;
        let (state, client) = ciba_fixture().await;
        let user = Uuid::now_v7();
        insert_ciba_user(&state, user).await;
        let connection = state.valkey_connection();
        let service = ServerTokenService::new(
            crate::test_support::token_issuance_repository(state.diesel_db.clone()),
            Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
            state.keyset.clone(),
        );
        let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
        let modules = state.active_module_snapshot();
        let authorization =
            crate::http::token::issue::test_support::test_authorization_service(&state);
        let context = TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
            security_audit: crate::http::authorization::test_support::test_security_audit(),
            remote_client_documents: crate::test_support::test_remote_client_documents(),
        };
        let grant = format!("golden-idempotent-{}", Uuid::now_v7());
        let auth_time = Utc::now().timestamp();
        let issue = || nazo_oauth_server::domain::oauth::TokenIssue {
            user_id: Some(user),
            prepared_subject: None,
            subject: user.to_string(),
            scopes: vec!["openid".into()],
            authorization_details: json!([]),
            audiences: vec!["resource://default".into()],
            nonce: None,
            auth_time: Some(auth_time),
            amr: vec!["pwd".into()],
            oidc_sid: Some(format!("golden-idempotent-{user}")),
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            refresh_id_token_sid: None,
            include_refresh: false,
            refresh_token_policy:
                nazo_oauth_server::domain::oauth::RefreshTokenPolicy::PreserveExisting,
            dpop_jkt: None,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256: Some(ciba_test_mtls_certificate().thumbprint.clone()),
            refresh_token_mtls_x5t_s256: None,
            refresh_token_client_attestation_jkt: None,
            refresh_token_scopes: None,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        };
        let first = wire(present_token_result(
            issue_token_response(
                &context,
                &service,
                &client,
                TokenIssuanceMode::SingleUse {
                    grant_key: grant.clone(),
                    grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
                },
                issue(),
            )
            .await,
        ))
        .await;
        assert_eq!(first.status, 200, "{first:?}");
        assert_eq!(first.headers, json_headers(true, true));
        let replay = wire(present_token_result(
            issue_token_response(
                &context,
                &service,
                &client,
                TokenIssuanceMode::SingleUse {
                    grant_key: grant,
                    grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
                },
                issue(),
            )
            .await,
        ))
        .await;
        assert_eq!(replay.status, 400, "{replay:?}");
        let replay_body: Value =
            serde_json::from_slice(&replay.body).expect("replay rejection body should be JSON");
        assert_eq!(replay_body["error"], "invalid_grant");
        let body: Value = serde_json::from_slice(&first.body).expect("issuance response JSON");
        let access = verify_jwt(
            &state,
            body["access_token"].as_str().unwrap(),
            "resource://default",
            &user.to_string(),
        );
        assert_eq!(
            access["cnf"]["x5t#S256"],
            ciba_test_mtls_certificate().thumbprint
        );
        assert_eq!(
            access["exp"].as_i64().unwrap() - access["iat"].as_i64().unwrap(),
            body["expires_in"].as_i64().unwrap()
        );
        let id = verify_jwt(
            &state,
            body["id_token"].as_str().unwrap(),
            &client.client_id,
            &user.to_string(),
        );
        assert_eq!(id["auth_time"], auth_time);
        assert_eq!(id["amr"], json!(["pwd"]));
    }
}
