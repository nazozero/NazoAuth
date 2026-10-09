use crate::test_support::TestInfrastructure;

pub(crate) fn token_request_facts<'a>(
    request: &'a actix_web::HttpRequest,
    settings: &crate::settings::Settings,
) -> nazo_oauth_server::contracts::token_endpoint::TokenRequestFacts<'a> {
    crate::http::token::dispatch::token_request_facts(
        request,
        &nazo_http_actix::ClientIpConfig::new(
            &settings.endpoint.trusted_proxy_cidrs,
            settings.endpoint.client_ip_header_mode,
        ),
    )
}

pub(crate) fn present_token_result(
    result: Result<
        nazo_oauth_server::contracts::token_endpoint::TokenEndpointSuccess,
        nazo_oauth_server::contracts::oauth_error::OAuthEndpointError,
    >,
) -> actix_web::HttpResponse {
    match result {
        Ok(success) => nazo_http_actix::token_endpoint_success_response(success),
        Err(error) => nazo_http_actix::oauth_endpoint_error_response(error),
    }
}

pub(crate) fn test_authorization_service(
    state: &TestInfrastructure,
) -> nazo_oauth_server::services::ServerAuthorizationService {
    let connection = state.valkey_connection();
    nazo_oauth_server::services::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            state.settings.tenant.context.tenant_id.as_uuid(),
        ),
        std::sync::Arc::new(nazo_valkey::AuthorizationStateAdapter::new(&connection)),
        state.keyset.clone(),
    )
}

/// Execute real HTTP grant routing, authentication and issuance, replacing
/// only the final repository commit with the explicit expiration result.
pub(crate) async fn token_with_expired_grant_commit(
    state: &TestInfrastructure,
    request: actix_web::HttpRequest,
    body: actix_web::web::Bytes,
) -> (actix_web::HttpResponse, usize) {
    use std::sync::Arc;
    let repository = Arc::new(
        crate::test_support::CountingTokenRepository::with_expired_grant_commit(Arc::new(
            crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        )),
    );
    let state_data = actix_web::web::Data::new(TestInfrastructure {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: state.settings.clone(),
        keyset: state.keyset.clone(),
    });
    let response =
        crate::http::token::dispatch::tests::token_with_port_repositories_and_state_and_modules(
            state_data,
            repository.clone(),
            Arc::new(nazo_postgres::AuthorizationFlowRepository::new(
                state.diesel_db.clone(),
                state.settings.tenant.context.tenant_id.as_uuid(),
            )),
            Arc::new(nazo_valkey::AuthorizationStateAdapter::new(
                &state.valkey_connection(),
            )),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .expect("empty remote document policy is valid"),
            ),
            nazo_oauth_server::token::dispatch::Openid4vcTokenHandles::default(),
            request,
            body,
            crate::test_support::persisted_runtime_modules_fixture(),
        )
        .await;
    (response, repository.commit_count())
}

pub(crate) async fn assert_expired_grant_dispatch_response(
    state: &TestInfrastructure,
    client: &nazo_oauth_server::domain::rows::ClientRow,
    response: actix_web::HttpResponse,
    commits: usize,
    expected_error: &str,
) {
    assert_eq!(
        commits, 1,
        "real grant routing must reach the controlled commit exactly once"
    );
    assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
    let bytes = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], expected_error);
    for name in ["access_token", "refresh_token", "id_token"] {
        assert!(
            body.get(name).is_none(),
            "expired commit must not release tokens"
        );
    }
    assert_eq!(
        crate::http::token::issue::tests::token_issuance_row_count(state, client).await,
        0
    );
}
