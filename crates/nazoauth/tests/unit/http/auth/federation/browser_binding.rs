use super::*;
use crate::settings::SocialProviderKind;
use crate::test_support::federation_binding::unavailable_federation_service;
use std::sync::atomic::Ordering;

fn binding_http_config(secure: bool) -> FederationHttpConfig {
    let settings = settings_with_oidc_provider(Some(&oidc_provider()));
    FederationHttpConfig::new(
        settings.identity.federation.providers.clone(),
        None,
        settings.session.session_cookie_name.as_str(),
        settings.session.csrf_cookie_name.as_str(),
        settings.session.session_ttl_seconds,
        secure,
    )
    .unwrap()
}

fn binding_request(config: &FederationHttpConfig, seed: Option<&[u8; 32]>) -> HttpRequest {
    let mut request = actix_web::test::TestRequest::get();
    if let Some(seed) = seed {
        request = request.cookie(actix_web::cookie::Cookie::new(
            federation_binding_cookie_name(config),
            URL_SAFE_NO_PAD.encode(seed),
        ));
    }
    request.to_http_request()
}

fn callback_query(state: &str) -> OidcCallbackQuery {
    OidcCallbackQuery {
        code: Some("code-1".to_owned()),
        state: Some(state.to_owned()),
        error: None,
    }
}

fn custom_social_provider() -> SocialProviderSettings {
    SocialProviderSettings {
        kind: SocialProviderKind::Custom,
        authorization_endpoint: "https://social.example/authorize".to_owned(),
        token_endpoint: "https://social.example/token".to_owned(),
        openid_endpoint: None,
        userinfo_endpoint: "https://social.example/userinfo".to_owned(),
        client_id: "social-client".to_owned(),
        client_secret: "social-secret".to_owned(),
        redirect_uri: "https://auth.example/auth/federation/social/callback".to_owned(),
        scopes: "profile email".to_owned(),
        subject_claim: "sub".to_owned(),
        email_claim: Some("email".to_owned()),
        email_verified_claim: Some("email_verified".to_owned()),
        name_claim: Some("name".to_owned()),
        union_id_claim: None,
    }
}

fn assert_no_binding_cookie(response: &HttpResponse) {
    for value in response.headers().get_all(header::SET_COOKIE) {
        let value = value.to_str().unwrap();
        assert!(!value.starts_with("nazo_federation_binding="));
        assert!(!value.starts_with("__Host-nazo_federation_binding="));
    }
}

async fn raw_state_snapshot(state: &TestInfrastructure, key: String) -> Value {
    use fred::interfaces::LuaInterface;
    let raw = state.valkey.eval::<String, _, _, _>(
        "return cjson.encode({raw=redis.call('GET',KEYS[1]),deadline=redis.call('PEXPIRETIME',KEYS[1])})",
        vec![key],
        Vec::<String>::new(),
    ).await.unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn binding_cookie_requires_exact_canonical_32_byte_encoding_and_configured_name() {
    for secure in [true, false] {
        let config = binding_http_config(secure);
        assert_eq!(
            read_federation_binding_seed(
                &binding_request(&config, Some(&TEST_BROWSER_BINDING_SEED)),
                &config,
            ),
            Some(TEST_BROWSER_BINDING_SEED),
        );
        assert!(read_federation_binding_seed(&binding_request(&config, None), &config).is_none());
        for value in [
            URL_SAFE_NO_PAD.encode([1_u8; 31]),
            URL_SAFE_NO_PAD.encode([1_u8; 33]),
            format!("{}=", URL_SAFE_NO_PAD.encode(TEST_BROWSER_BINDING_SEED)),
            format!("{}+", "A".repeat(42)),
            format!("{}B", "A".repeat(42)), // Nonzero discarded trailing bits.
            format!(" {}", URL_SAFE_NO_PAD.encode(TEST_BROWSER_BINDING_SEED)),
        ] {
            let req = actix_web::test::TestRequest::get()
                .cookie(actix_web::cookie::Cookie::new(federation_binding_cookie_name(&config), value))
                .to_http_request();
            assert!(read_federation_binding_seed(&req, &config).is_none());
        }
        let wrong_name = if secure { "nazo_federation_binding" } else { "__Host-nazo_federation_binding" };
        let req = actix_web::test::TestRequest::get()
            .cookie(actix_web::cookie::Cookie::new(wrong_name, URL_SAFE_NO_PAD.encode(TEST_BROWSER_BINDING_SEED)))
            .to_http_request();
        assert!(read_federation_binding_seed(&req, &config).is_none());
    }
}

#[test]
fn successful_start_cookie_has_secure_host_or_dev_attributes_and_renews_300_seconds() {
    for secure in [true, false] {
        let config = binding_http_config(secure);
        let response = federation_start_response(&config, "https://provider.example/authorize".to_owned(), &TEST_BROWSER_BINDING_SEED);
        assert_eq!(response.status(), StatusCode::FOUND);
        let header = response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        let cookie = actix_web::cookie::Cookie::parse(header.to_owned()).unwrap();
        assert_eq!(cookie.name(), if secure { "__Host-nazo_federation_binding" } else { "nazo_federation_binding" });
        assert_eq!(cookie.value(), URL_SAFE_NO_PAD.encode(TEST_BROWSER_BINDING_SEED));
        assert_eq!(cookie.value().len(), 43);
        assert_eq!(cookie.path(), Some("/"));
        assert!(cookie.domain().is_none());
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure().unwrap_or(false), secure);
        assert_eq!(cookie.same_site(), Some(actix_web::cookie::SameSite::Lax));
        assert_eq!(cookie.max_age().unwrap().whole_seconds(), 300);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 1);
    }
}

#[actix_web::test]
async fn missing_or_bad_cookie_calls_no_state_store_and_valid_cookie_preserves_outage_503() {
    let state = oidc_callback_state();
    let config = crate::test_support::federation_http_config(&state);
    let client_ip = crate::test_support::client_ip_config(&state);
    let (service, states) = unavailable_federation_service(&state);
    for social in [false, true] {
        for invalid in [None, Some("bad-cookie".to_owned())] {
            let mut req = actix_web::test::TestRequest::get();
            if let Some(value) = invalid {
                req = req.cookie(actix_web::cookie::Cookie::new(federation_binding_cookie_name(&config), value));
            }
            let response = if social {
                super::super::social_callback_after_rate_limit(
                    service.clone(), config.clone(), client_ip.clone(), req.to_http_request(),
                    callback_query(&"A".repeat(32)), "social".to_owned(), custom_social_provider(),
                ).await
            } else {
                super::super::oidc_callback_after_rate_limit_for_provider(
                    service.clone(), config.clone(), client_ip.clone(), req.to_http_request(),
                    callback_query(&"A".repeat(32)), oidc_provider(),
                ).await
            };
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_no_binding_cookie(&response);
            assert_eq!(oauth_error_code(response).await.as_deref(), Some("invalid_request"));
            assert_eq!(states.calls.load(Ordering::SeqCst), 0);
        }
    }
    for social in [false, true] {
        let req = binding_request(&config, Some(&TEST_BROWSER_BINDING_SEED));
        let before = states.calls.load(Ordering::SeqCst);
        let response = if social {
            super::super::social_callback_after_rate_limit(
                service.clone(), config.clone(), client_ip.clone(), req,
                callback_query(&"A".repeat(32)), "social".to_owned(), custom_social_provider(),
            ).await
        } else {
            super::super::oidc_callback_after_rate_limit_for_provider(
                service.clone(), config.clone(), client_ip.clone(), req,
                callback_query(&"A".repeat(32)), oidc_provider(),
            ).await
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(states.calls.load(Ordering::SeqCst), before + 1);
        assert_no_binding_cookie(&response);
    }
}

#[actix_web::test]
async fn failed_start_never_publishes_binding_cookie_or_redirect() {
    let Some(state) = live_federation_state(Some(oidc_provider()), None).await else {
        return;
    };
    let config = crate::test_support::federation_http_config(&state);
    let (service, states) = unavailable_federation_service(&state);
    let response = super::super::federation_provider_start(
        crate::test_support::auth_request_limiter(&state),
        crate::test_support::client_ip_config(&state),
        service, config.clone(), binding_request(&config, None),
        Path::from(TEST_OIDC_PROVIDER_ID.to_owned()),
    ).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(states.calls.load(Ordering::SeqCst), 1);
    assert!(response.headers().get(header::LOCATION).is_none());
    assert_no_binding_cookie(&response);
}

#[actix_web::test]
async fn oidc_attacker_code_and_state_in_another_browser_cannot_burn_owner_login() {
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("binding-oidc-{suffix}@example.com");
    let subject = format!("binding-subject-{suffix}");
    let (provider, token_request, jwks_request, nonce) = provider_backed_by_local_oidc(json!({
        "sub": subject, "email": email,
    })).await;
    let Some(fixture) = LiveFederationFixture::new(Some(provider.clone()), None).await else {
        token_request.abort();
        jwks_request.abort();
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&fixture.state, &state_token, &nonce, Utc::now().timestamp()).await;
    let config = crate::test_support::federation_http_config(&fixture.state);
    let key = oidc_state_key(&state_token);
    let before = raw_state_snapshot(&fixture.state, key.clone()).await;
    let owner_hash = serde_json::from_str::<OidcFederationState>(before["raw"].as_str().unwrap())
        .unwrap().browser_binding_hash.unwrap();
    for seed in [None, Some([0x91_u8; 32])] {
        let response = super::super::oidc_callback_after_rate_limit_for_provider(
            crate::test_support::federation_service(&fixture.state),
            config.clone(), crate::test_support::client_ip_config(&fixture.state),
            binding_request(&config, seed.as_ref()), callback_query(&state_token), provider.clone(),
        ).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert!(!token_request.is_finished());
        assert!(!jwks_request.is_finished());
        assert_eq!(raw_state_snapshot(&fixture.state, key.clone()).await, before);
        assert!(fixture.user_by_email(&email).await.is_none());
        assert!(fixture.external_identity_link("oidc", TEST_OIDC_PROVIDER_ID, &subject).await.is_none());
    }
    let response = super::super::oidc_callback_after_rate_limit_for_provider(
        crate::test_support::federation_service(&fixture.state),
        config.clone(), crate::test_support::client_ip_config(&fixture.state),
        binding_request(&config, Some(&TEST_BROWSER_BINDING_SEED)),
        callback_query(&state_token), provider,
    ).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_binding_cookie(&response);
    let session_cookie = cookie_value_from_response(&response, &fixture.state.settings.session.session_cookie_name).unwrap();
    let session = fixture.session_payload(&session_cookie).await;
    let owner = fixture.user_by_email(&email).await.unwrap();
    assert_eq!(session.user_id, owner.id());
    let request = token_request.await.unwrap();
    jwks_request.await.unwrap();
    assert!(request.contains("code=code-1"));
    assert!(request.contains("code_verifier=verifier-1"));
    assert!(!request.contains(&URL_SAFE_NO_PAD.encode(TEST_BROWSER_BINDING_SEED)));
    assert!(!request.contains(&owner_hash));
    assert!(valkey_get(&fixture.state.valkey, key).await.unwrap().is_none());
}

#[actix_web::test]
async fn social_attacker_code_and_state_in_another_browser_preserves_owner_completion() {
    let Some(fixture) = LiveFederationFixture::new(None, None).await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("binding-social-{suffix}@example.com");
    let subject = format!("binding-social-subject-{suffix}");
    let (token_endpoint, token_request) = one_shot_json_server(json!({"access_token":"upstream-token"})).await;
    let (userinfo_endpoint, userinfo_request) = one_shot_json_server(json!({
        "sub": subject, "email": email, "email_verified": true,
    })).await;
    let mut provider = custom_social_provider();
    provider.token_endpoint = token_endpoint;
    provider.userinfo_endpoint = userinfo_endpoint;
    let service = crate::test_support::federation_service(&fixture.state);
    let start = service.start_social("social".to_owned(), &TEST_BROWSER_BINDING_SEED, Utc::now()).await.unwrap();
    let config = crate::test_support::federation_http_config(&fixture.state);
    let key = nazo_valkey::test_support::social_federation_storage_key(&start.state);
    let before = raw_state_snapshot(&fixture.state, key.clone()).await;
    let owner_hash = serde_json::from_str::<nazo_identity::SocialFederationState>(before["raw"].as_str().unwrap())
        .unwrap().browser_binding_hash.unwrap();
    for seed in [None, Some([0x92_u8; 32])] {
        let response = super::super::social_callback_after_rate_limit(
            service.clone(), config.clone(), crate::test_support::client_ip_config(&fixture.state),
            binding_request(&config, seed.as_ref()), callback_query(&start.state),
            "social".to_owned(), provider.clone(),
        ).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert!(!token_request.is_finished());
        assert!(!userinfo_request.is_finished());
        assert_eq!(raw_state_snapshot(&fixture.state, key.clone()).await, before);
        assert!(fixture.user_by_email(&email).await.is_none());
        assert!(fixture.external_identity_link("oauth2_social", "social", &subject).await.is_none());
    }
    let response = super::super::social_callback_after_rate_limit(
        service, config.clone(), crate::test_support::client_ip_config(&fixture.state),
        binding_request(&config, Some(&TEST_BROWSER_BINDING_SEED)),
        callback_query(&start.state), "social".to_owned(), provider,
    ).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_binding_cookie(&response);
    let session_cookie = cookie_value_from_response(&response, &fixture.state.settings.session.session_cookie_name).unwrap();
    assert_eq!(fixture.session_payload(&session_cookie).await.user_id, fixture.user_by_email(&email).await.unwrap().id());
    for request in [token_request.await.unwrap(), userinfo_request.await.unwrap()] {
        assert!(!request.contains(&URL_SAFE_NO_PAD.encode(TEST_BROWSER_BINDING_SEED)));
        assert!(!request.contains(&owner_hash));
    }
    assert!(valkey_get(&fixture.state.valkey, key).await.unwrap().is_none());
}


fn redirect_state(response: &HttpResponse) -> String {
    let location = response.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    url::Url::parse(location).unwrap().query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap()
}

fn parallel_provider_config(state: &TestInfrastructure) -> Data<FederationHttpConfig> {
    let provider = oidc_provider();
    let config_source = ConfigSource::from_owned_pairs_for_test([(
        "FEDERATION_PROVIDER_CONFIGS".to_owned(),
        json!([
            {
                "provider_id": provider.provider_id,
                "display_name": "OIDC", "enabled": true, "adapter_type": "oidc",
                "issuer": provider.issuer,
                "authorization_endpoint": provider.authorization_endpoint,
                "token_endpoint": provider.token_endpoint, "jwks_url": provider.jwks_url,
                "client_id": provider.client_id, "client_secret": provider.client_secret,
                "redirect_uri": provider.redirect_uri, "scopes": provider.scopes
            },
            {
                "provider_id": "social", "display_name": "Social", "enabled": true,
                "adapter_type": "oauth2_social", "provider_kind": "qq",
                "client_id": "social-client", "client_secret": "social-secret",
                "redirect_uri": "https://auth.example/auth/federation/social/callback"
            }
        ]).to_string(),
    )]);
    let mut config = crate::test_support::federation_http_config(state).get_ref().clone();
    config.providers = Settings::from_config(&config_source).unwrap().identity.federation.providers;
    Data::new(config)
}

#[actix_web::test]
async fn existing_browser_cookie_supports_parallel_oidc_and_social_starts_without_rotation() {
    let Some(state) = live_federation_state(Some(oidc_provider()), None).await else {
        return;
    };
    let service = crate::test_support::federation_service(&state);
    let limiter = crate::test_support::auth_request_limiter(&state);
    let client_ip = crate::test_support::client_ip_config(&state);
    for secure in [true, false] {
        let mut config = parallel_provider_config(&state).get_ref().clone();
        config.cookie_secure = secure;
        let config = Data::new(config);
        let (oidc, social) = tokio::join!(
            super::super::federation_provider_start(
                limiter.clone(), client_ip.clone(), service.clone(), config.clone(),
                binding_request(&config, Some(&TEST_BROWSER_BINDING_SEED)),
                Path::from(TEST_OIDC_PROVIDER_ID.to_owned()),
            ),
            super::super::federation_provider_start(
                limiter.clone(), client_ip.clone(), service.clone(), config.clone(),
                binding_request(&config, Some(&TEST_BROWSER_BINDING_SEED)),
                Path::from("social".to_owned()),
            ),
        );
        for response in [&oidc, &social] {
            assert_eq!(response.status(), StatusCode::FOUND);
            let encoded = URL_SAFE_NO_PAD.encode(TEST_BROWSER_BINDING_SEED);
            assert_eq!(cookie_value_from_response(response, federation_binding_cookie_name(&config)), Some(encoded.clone()));
            let header = response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
            let cookie = actix_web::cookie::Cookie::parse(header.to_owned()).unwrap();
            assert_eq!(cookie.max_age().unwrap().whole_seconds(), 300);
            assert!(!response.headers().get(header::LOCATION).unwrap().to_str().unwrap().contains(&encoded));
        }
        let oidc_state = redirect_state(&oidc);
        let social_state = redirect_state(&social);
        assert_ne!(oidc_state, social_state);
        let (oidc_stored, social_stored) = tokio::join!(
            service.consume_oidc(&oidc_state, TEST_OIDC_PROVIDER_ID, &TEST_BROWSER_BINDING_SEED, Utc::now()),
            service.consume_social(&social_state, "social", &TEST_BROWSER_BINDING_SEED, Utc::now()),
        );
        let oidc_stored = oidc_stored.unwrap();
        let social_stored = social_stored.unwrap();
        assert!(oidc_stored.browser_binding_hash.is_some());
        assert_eq!(oidc_stored.browser_binding_hash, social_stored.browser_binding_hash);
        for response in [&oidc, &social] {
            assert!(!response.headers().get(header::LOCATION).unwrap().to_str().unwrap()
                .contains(oidc_stored.browser_binding_hash.as_ref().unwrap()));
        }
    }
}

#[actix_web::test]
async fn invalid_start_cookie_is_replaced_with_a_fresh_canonical_owner_seed() {
    let Some(state) = live_federation_state(Some(oidc_provider()), None).await else {
        return;
    };
    let config = crate::test_support::federation_http_config(&state);
    let service = crate::test_support::federation_service(&state);
    let req = actix_web::test::TestRequest::get()
        .cookie(actix_web::cookie::Cookie::new(federation_binding_cookie_name(&config), "invalid"))
        .to_http_request();
    let response = super::super::federation_provider_start(
        crate::test_support::auth_request_limiter(&state),
        crate::test_support::client_ip_config(&state),
        service.clone(), config.clone(), req, Path::from(TEST_OIDC_PROVIDER_ID.to_owned()),
    ).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let encoded = cookie_value_from_response(&response, federation_binding_cookie_name(&config)).unwrap();
    let req = actix_web::test::TestRequest::get()
        .cookie(actix_web::cookie::Cookie::new(federation_binding_cookie_name(&config), encoded))
        .to_http_request();
    let seed = read_federation_binding_seed(&req, &config).unwrap();
    service.consume_oidc(&redirect_state(&response), TEST_OIDC_PROVIDER_ID, &seed, Utc::now()).await.unwrap();
}

#[actix_web::test]
async fn simultaneous_cold_starts_fail_closed_when_last_set_cookie_displaces_the_first_seed() {
    let Some(state) = live_federation_state(Some(oidc_provider()), None).await else {
        return;
    };
    let config = crate::test_support::federation_http_config(&state);
    let service = crate::test_support::federation_service(&state);
    let limiter = crate::test_support::auth_request_limiter(&state);
    let client_ip = crate::test_support::client_ip_config(&state);
    let (first, second) = tokio::join!(
        super::super::federation_provider_start(
            limiter.clone(), client_ip.clone(), service.clone(), config.clone(),
            binding_request(&config, None), Path::from(TEST_OIDC_PROVIDER_ID.to_owned()),
        ),
        super::super::federation_provider_start(
            limiter, client_ip.clone(), service.clone(), config.clone(),
            binding_request(&config, None), Path::from(TEST_OIDC_PROVIDER_ID.to_owned()),
        ),
    );
    assert_eq!(first.status(), StatusCode::FOUND);
    assert_eq!(second.status(), StatusCode::FOUND);
    let seed_for = |response: &HttpResponse| {
        let value = cookie_value_from_response(response, federation_binding_cookie_name(&config)).unwrap();
        let req = actix_web::test::TestRequest::get()
            .cookie(actix_web::cookie::Cookie::new(federation_binding_cookie_name(&config), value))
            .to_http_request();
        read_federation_binding_seed(&req, &config).unwrap()
    };
    let first_seed = seed_for(&first);
    let second_seed = seed_for(&second);
    assert_ne!(first_seed, second_seed);
    let first_state = redirect_state(&first);
    let second_state = redirect_state(&second);
    let key = oidc_state_key(&first_state);
    let before = raw_state_snapshot(&state, key.clone()).await;
    let response = super::super::oidc_callback_after_rate_limit_for_provider(
        service.clone(), config.clone(), client_ip,
        binding_request(&config, Some(&second_seed)), callback_query(&first_state), oidc_provider(),
    ).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_binding_cookie(&response);
    assert_eq!(raw_state_snapshot(&state, key).await, before);
    service.consume_oidc(&first_state, TEST_OIDC_PROVIDER_ID, &first_seed, Utc::now()).await.unwrap();
    service.consume_oidc(&second_state, TEST_OIDC_PROVIDER_ID, &second_seed, Utc::now()).await.unwrap();
}
