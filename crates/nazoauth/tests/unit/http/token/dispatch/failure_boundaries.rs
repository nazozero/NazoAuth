use super::*;

#[actix_web::test]
async fn token_endpoint_rejects_client_auth_if_token_rate_limit_is_exceeded() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let mut settings = (*state.settings).clone();
    settings.identity.rate_limit.token_max_requests = 0;
    let state = Data::new(TestInfrastructure {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(settings),
        keyset: state.keyset.clone(),
    });
    let correct_secret = fixture_secret("rate-limited");
    insert_token_client(
        &state,
        "rate-limited-client",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_id=rate-limited-client&client_secret={}",
        urlencoding::encode(&correct_secret)
    ));

    let response = token(state, req, body).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(oauth_error_code(response).await, "temporarily_unavailable");
}

#[actix_web::test]
async fn token_endpoint_rejects_client_lookup_db_failure_with_server_error() {
    let Some(state) =
        live_valkey_invalid_db_token_state(AuthorizationServerProfile::Oauth2Baseline).await
    else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=db-fail-client&client_secret=secret",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        false,
    )
    .await;
}
