use super::*;
use crate::test_support::{CountingTokenRepository, client_signing_fixture, dpop_token_request};
use fred::interfaces::KeysInterface as _;
use nazo_auth::TokenRepositoryPort as _;
use nazo_oauth_server::token::authorization_code::authorization_code_identity;

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

async fn assert_one_committed_result(fixture: &LiveAuthorizationCodeFixture, client: &ClientRow) {
    let mut connection = get_conn(&fixture.state.diesel_db).await.unwrap();
    for table in ["oauth_token_issuances", "oauth_refresh_families"] {
        let row = sql_query(format!(
            "SELECT COUNT(*)::bigint AS count FROM {table} WHERE tenant_id=$1 AND client_id=$2"
        ))
        .bind::<SqlUuid, _>(client.tenant_id)
        .bind::<SqlUuid, _>(client.id)
        .get_result::<Count>(&mut connection)
        .await
        .unwrap();
        assert_eq!(row.count, 1, "one code must produce only one {table} row");
    }
    let row = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events \
         WHERE event_type='token_issued' AND payload->>'client_id'=$1",
    )
    .bind::<Text, _>(&client.client_id)
    .get_result::<Count>(&mut connection)
    .await
    .unwrap();
    assert_eq!(row.count, 1);
}

#[actix_web::test]
async fn authorization_code_unknown_commit_keeps_one_identity_and_requires_fresh_original_holder() {
    let mut settings = LiveAuthorizationCodeFixture::settings();
    settings.protocol.dpop_nonce_policy = nazo_auth::DpopNoncePolicy::Optional;
    let Some(fixture) = LiveAuthorizationCodeFixture::new_with_settings_and_keyset(
        settings,
        crate::test_support::test_key_manager_with_algorithm(jsonwebtoken::Algorithm::RS256),
    )
    .await
    else {
        return;
    };
    let user = fixture.insert_user().await;
    let mut client = live_client(&format!("code-identity-{}", Uuid::now_v7()));
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();
    client.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    client.allowed_audiences = vec!["resource://a".to_owned(), "resource://b".to_owned()];
    fixture.insert_client(&client).await;
    let code = format!("code-{}", Uuid::now_v7());
    let mut payload = payload_for_client(&client);
    payload.user_id = user.id;
    payload.scopes = client.scopes.clone();
    payload.resource_indicators = client.allowed_audiences.clone();
    payload.redirect_uri_was_supplied = false;
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload: payload.clone() })
        .await;
    let repository = Arc::new(CountingTokenRepository::with_lost_commit_ack(
        crate::test_support::token_issuance_repository(fixture.state.diesel_db.clone()),
    ));
    let service = ServerTokenService::new(
        repository.clone(),
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&fixture.state.valkey_connection())),
        fixture.state.keyset.clone(),
    );
    let original_key = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let different_key = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let mut form = form_for_code(&code);
    form.audiences = vec!["resource://a".to_owned()];
    let req = dpop_token_request(&fixture.state.settings, &original_key);
    let response = token_authorization_code_using_service(
        &fixture.state, &req, &client, &form, None, &service,
    )
    .await;
    let (status, body) = token_json_body(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body.get("access_token").is_none() && body.get("refresh_token").is_none());
    assert!(matches!(fixture.code_state(&code).await, AuthorizationCodeState::Failed { .. }));
    let identity = authorization_code_identity(&blake3_hex(&code));
    let receipt = repository.single_use_redemption(client.tenant_id, client.id, &identity)
        .await.unwrap().unwrap();
    let holder = receipt.authorization_code_holder.as_ref().unwrap();
    assert!(!holder.authenticated_client);
    assert_eq!(holder.pkce_s256.as_deref(), Some(pkce_s256(VALID_CODE_VERIFIER).as_str()));
    assert!(holder.dpop_jkt.is_some());
    let family = receipt.refresh_token_family_id.expect("the real commit created a refresh family");
    assert_one_committed_result(&fixture, &client).await;

    // Every candidate is processed by the production signature, target and
    // replay validator. A different fresh key or PKCE is not revocation authority.
    for wrong_pkce in [true, false] {
        let mut candidate = form_for_code(&code);
        candidate.audiences = form.audiences.clone();
        let key = if wrong_pkce {
            candidate.code_verifier = Some("x".repeat(64));
            &original_key
        } else {
            &different_key
        };
        let req = dpop_token_request(&fixture.state.settings, key);
        let response = token_authorization_code_using_service(
            &fixture.state, &req, &client, &candidate, None, &service,
        ).await;
        assert_eq!(oauth_error_code(response).await, "invalid_grant");
        assert_eq!(fixture.access_token_revocation_count(&client, &receipt.access_token_jti).await, 0);
        assert!(fixture.refresh_token_revoked_at(&client, family).await.is_none());
    }
    fixture.state.valkey.del::<i64, _>(authorization_code_key(&code)).await.unwrap();
    let no_proof = actix_web::test::TestRequest::post().uri("/token").to_http_request();
    let response = token_authorization_code_using_service(
        &fixture.state, &no_proof, &client, &form, None, &service,
    ).await;
    assert_eq!(oauth_error_code(response).await, "invalid_grant");
    assert_eq!(fixture.access_token_revocation_count(&client, &receipt.access_token_jti).await, 0);
    let req = dpop_token_request(&fixture.state.settings, &original_key);
    let response = token_authorization_code_using_service(
        &fixture.state, &req, &client, &form, None, &service,
    ).await;
    assert_eq!(oauth_error_code(response).await, "invalid_grant");
    assert_eq!(fixture.access_token_revocation_count(&client, &receipt.access_token_jti).await, 1);
    assert!(fixture.refresh_token_revoked_at(&client, family).await.is_some());

    // Fixture-only restoration models an HA switch losing an acknowledged
    // cache transition. Valid resource/redirect/scope/proof variants still
    // hit the original durable code identity and never mint another token.
    for original_holder in [false, true] {
        fixture.store_code_state(&code, &AuthorizationCodeState::Pending { payload: payload.clone() }).await;
        let mut candidate = form_for_code(&code);
        candidate.audiences = form.audiences.clone();
        candidate.audiences = if original_holder {
            vec!["resource://b".to_owned(), "resource://a".to_owned()]
        } else {
            vec!["resource://b".to_owned()]
        };
        candidate.scope = Some("openid offline_access".to_owned());
        candidate.redirect_uri = None;
        let key = if original_holder { &original_key } else { &different_key };
        let req = dpop_token_request(&fixture.state.settings, key);
        let response = token_authorization_code_using_service(
            &fixture.state, &req, &client, &candidate, None, &service,
        ).await;
        assert_eq!(oauth_error_code(response).await, "invalid_grant");
        assert_one_committed_result(&fixture, &client).await;
    }
    assert_eq!(repository.code_commit_keys(), vec![identity.clone(), identity.clone(), identity]);
}

#[actix_web::test]
async fn authorization_code_legacy_payload_and_cache_only_marker_cannot_issue_or_revoke() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("code-legacy-{}", Uuid::now_v7()));
    fixture.insert_client(&client).await;
    let req = actix_web::test::TestRequest::post().uri("/token").to_http_request();
    let legacy = format!("code-legacy-{}", Uuid::now_v7());
    let mut raw = serde_json::to_value(AuthorizationCodeState::Pending {
        payload: payload_for_client(&client),
    }).unwrap();
    raw["payload"].as_object_mut().unwrap().remove("redemption_contract_version");
    fixture.store_raw_code_state(&legacy, &raw.to_string()).await;
    let response = token_authorization_code(&fixture.state, &req, &client, &form_for_code(&legacy), None).await;
    assert_eq!(oauth_error_code(response).await, "invalid_grant");
    assert!(matches!(fixture.code_state(&legacy).await, AuthorizationCodeState::Pending { .. }));
    let code = format!("code-marker-only-{}", Uuid::now_v7());
    let form = form_for_code(&code);
    let jti = format!("must-not-revoke-{}", Uuid::now_v7());
    fixture.store_code_state(&code, &AuthorizationCodeState::Consumed {
        marker: ConsumedAuthorizationCode {
            client_id: client.id,
            redemption_binding: Some(legacy_authorization_code_redemption_key(
                &blake3_hex(&code), &form, None, None, None,
            )),
            access_token_jti: jti.clone(),
            access_token_expires_at: (Utc::now() + Duration::minutes(5)).timestamp(),
            refresh_token_family_id: None,
        },
    }).await;
    let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;
    assert_eq!(oauth_error_code(response).await, "invalid_grant");
    assert_eq!(fixture.access_token_revocation_count(&client, &jti).await, 0);
    let mut connection = get_conn(&fixture.state.diesel_db).await.unwrap();
    let count = sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE client_id=$1")
        .bind::<SqlUuid, _>(client.id).get_result::<Count>(&mut connection).await.unwrap();
    assert_eq!(count.count, 0);
}
