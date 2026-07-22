use crate::domain::TestInfrastructure;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::settings::Settings;

use actix_web::web::Data;

use nazo_http_actix::OAuthJsonErrorFields;

use uuid::Uuid;

pub(super) fn client_credentials_issue_request(
    settings: &Settings,
    client: &ClientRow,
    form: &TokenForm,
) -> Result<ClientCredentialsIssue, HttpResponse> {
    client_credentials_issue_request_with_default_audience(
        &settings.protocol.default_audience,
        client,
        form,
    )
}

pub(crate) async fn token_client_credentials(
    state: &TestInfrastructure,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let connection = state.valkey_connection();
    let service = ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let config = super::issue::TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization_service = crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    token_client_credentials_with_service(
        &service,
        &authorization_service,
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization_service,
        },
        req,
        client,
        form,
        client_assertion,
    )
    .await
}
