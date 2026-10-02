use super::*;

#[actix_web::test]
async fn ciba_token_approved_state_issues_access_and_id_tokens_for_an_active_user() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    state.keyset =
        crate::test_support::test_key_manager_with_auxiliary(jsonwebtoken::Algorithm::PS256);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("approved-issue-kid", &key);
    client.client_id = format!("ciba-approved-client-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("approved CIBA client should be stored");

    let user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    let auth_req_id = format!("approved-issue-{}", Uuid::now_v7());
    store_ciba_state_with_user(&state, &client, &auth_req_id, user_id, CibaStatus::Approved).await;

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id.clone()).await;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("CIBA error response should collect");
        panic!(
            "approved CIBA token request returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("CIBA token response should collect");
    let value: Value = serde_json::from_slice(&body).expect("CIBA token response should be JSON");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(value.get("refresh_token").is_none());

    let replay = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(replay).await, "invalid_grant");
}

#[actix_web::test]
async fn ciba_replay_rejects_a_consumed_auth_req_id_after_a_committed_issuance() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-replay-kid", &key);
    client.client_id = format!("ciba-persisted-replay-{}", client.id);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("ciba-replay-{}", Uuid::now_v7());
    let grant_key = ciba_grant_key(&auth_req_id);

    crate::http::token::issue::tests::persist_consumed_single_use_grant_for_test(
        &state, &client, &grant_key,
    )
    .await;

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("invalid_grant")
    );
}

#[actix_web::test]
async fn ciba_precommit_dependency_failure_is_retryable_and_sender_keys_share_one_fence() {
    let Some(mut state)=live_ciba_replay_state().await else {return;};
    let mut settings=(*state.settings).clone();settings.protocol.dpop_nonce_policy=nazo_auth::DpopNoncePolicy::Optional;state.settings=Arc::new(settings);
    let client_key=client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client=ciba_private_key_jwt_client("retryable-approved-kid",&client_key);client.client_id=format!("ciba-sender-fence-{}",Uuid::now_v7());client.require_dpop_bound_tokens=true;
    persist_ciba_test_client(&state,&client).await;
    let user_id=Uuid::now_v7();insert_ciba_user(&state,user_id).await;
    let one=client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);let two=client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    for concurrent in [false,true] {
        let id=format!("ciba-sender-{}",Uuid::now_v7());store_ciba_state_with_user(&state,&client,&id,user_id,CibaStatus::Approved).await;
        let before=crate::http::token::issue::tests::token_issuance_row_count(&state,&client).await;
        state.keyset=crate::test_support::test_key_manager();
        let failed=call_ciba_token_with_request_for_test(&state,&client,id.clone(),crate::test_support::dpop_token_request(state.settings.as_ref(),&one)).await;
        assert_eq!(failed.status(),StatusCode::SERVICE_UNAVAILABLE);
        let service=ServerCibaService::new(Arc::new(CibaStore::new(&state.valkey_connection())));
        assert_eq!(service.load(&id).await.unwrap().unwrap().state().status,CibaStatus::Approved);
        assert_eq!(crate::http::token::issue::tests::token_issuance_row_count(&state,&client).await,before);
        state.keyset=crate::test_support::test_key_manager_with_auxiliary(jsonwebtoken::Algorithm::PS256);
        let request_a=crate::test_support::dpop_token_request(state.settings.as_ref(),&one);let request_b=crate::test_support::dpop_token_request(state.settings.as_ref(),&two);
        let (a,b)=if concurrent {
            tokio::join!(call_ciba_token_with_request_for_test(&state,&client,id.clone(),request_a),call_ciba_token_with_request_for_test(&state,&client,id.clone(),request_b))
        } else {
            let a=call_ciba_token_with_request_for_test(&state,&client,id.clone(),request_a).await;let b=call_ciba_token_with_request_for_test(&state,&client,id.clone(),request_b).await;(a,b)
        };
        assert_eq!([a.status(),b.status()].into_iter().filter(|status|*status==StatusCode::OK).count(),1);
        let rejected=if a.status()==StatusCode::OK {b} else {a};assert_eq!(oauth_error_code(rejected).await,"invalid_grant");
        let replay=call_ciba_token_with_request_for_test(&state,&client,id,crate::test_support::dpop_token_request(state.settings.as_ref(),&one)).await;
        assert_eq!(oauth_error_code(replay).await,"invalid_grant");
        assert_eq!(crate::http::token::issue::tests::token_issuance_row_count(&state,&client).await,before+1);
        #[derive(diesel::QueryableByName)] struct Count {#[diesel(sql_type=diesel::sql_types::BigInt)] count:i64}
        let mut conn=get_conn(&state.diesel_db).await.unwrap();
        let revoked=sql_query("SELECT COUNT(*)::bigint AS count FROM access_token_revocations WHERE tenant_id=$1 AND client_id=$2").bind::<SqlUuid,_>(client.tenant_id).bind::<SqlUuid,_>(client.id).get_result::<Count>(&mut conn).await.unwrap();
        assert_eq!(revoked.count,0,"CIBA replay must not revoke another holder's tokens");
    }
}
