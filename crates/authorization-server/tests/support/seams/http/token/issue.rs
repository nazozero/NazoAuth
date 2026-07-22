use crate::domain::TestInfrastructure;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use nazo_auth::OidcClaimRequest;

use nazo_http_actix::OAuthJsonErrorFields;

pub(crate) fn test_authorization_service(
    state: &TestInfrastructure,
) -> crate::http::authorization::ServerAuthorizationService {
    let connection = state.valkey_connection();
    crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    )
}

pub(crate) async fn issue_token_response(
    state: &TestInfrastructure,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    let service = ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = test_authorization_service(state);
    issue_token_response_with_service(
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
        },
        &service,
        client,
        issue,
    )
    .await
}
