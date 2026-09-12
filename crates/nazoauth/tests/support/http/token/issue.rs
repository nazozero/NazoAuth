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
