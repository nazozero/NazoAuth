use nazo_identity::SessionService;
use nazo_oauth_server::domain::passkey::PasskeyOperationsProvider;

fn test_operations(
    state: &crate::test_support::TestInfrastructure,
) -> std::sync::Arc<PasskeyOperationsProvider> {
    std::sync::Arc::new(PasskeyOperationsProvider::new(
        crate::test_support::passkey_service(state)
            .get_ref()
            .clone(),
        SessionService::new(
            std::sync::Arc::new(nazo_valkey::SessionStore::new(&state.valkey_connection())),
            std::sync::Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            state.settings.tenant.context.tenant_id,
        ),
    ))
}

pub(crate) fn test_login_endpoint(
    state: &crate::test_support::TestInfrastructure,
) -> actix_web::web::Data<nazoauth::test_support::http::PasskeyLoginEndpoint> {
    let identity = &state.settings.identity;
    let session = &state.settings.session;
    let endpoint = &state.settings.endpoint;
    actix_web::web::Data::new(nazoauth::test_support::http::PasskeyLoginEndpoint::new(
        test_operations(state),
        std::sync::Arc::new(
            nazo_oauth_server::domain::local_registration::ServerAuthenticationRateLimit::new(
                std::sync::Arc::new(nazo_valkey::RateLimitStore::new(&state.valkey_connection())),
                identity.rate_limit.window_seconds,
                identity.rate_limit.auth_max_requests,
            ),
        ),
        nazoauth::test_support::http::ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        ),
        nazoauth::test_support::http::PasskeyLoginConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            crate::http::auth::MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            session.cookie_secure,
        ),
    ))
}

pub(crate) fn test_profile_endpoint(
    state: &crate::test_support::TestInfrastructure,
) -> actix_web::web::Data<nazoauth::test_support::http::PasskeyProfileEndpoint> {
    let session = &state.settings.session;
    actix_web::web::Data::new(nazoauth::test_support::http::PasskeyProfileEndpoint::new(
        test_operations(state),
        nazoauth::test_support::http::PasskeyProfileConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    ))
}
