use nazo_http_actix::OAuthJsonErrorFields;

use crate::domain::TestInfrastructure;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::settings::Settings;

use crate::test_support::{ClientSigningFixture, client_signing_fixture};

use base64::Engine;

use uuid::Uuid;

fn validate_jwt_bearer_assertion(
    settings: &Settings,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedJwtBearerAssertion, JwtBearerAssertionError> {
    validate_jwt_bearer_assertion_with_issuer(&settings.endpoint.issuer, client, assertion)
}

async fn consume_jwt_bearer_assertion(
    state: &TestInfrastructure,
    client: &ClientRow,
    assertion: &ValidatedJwtBearerAssertion,
) -> Result<(), JwtBearerAssertionError> {
    let authorization = super::issue::test_authorization_service(state);
    consume_jwt_bearer_assertion_with_authorization_service(&authorization, client, assertion).await
}

pub(crate) async fn token_jwt_bearer(
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
    let authorization = super::issue::test_authorization_service(state);
    token_jwt_bearer_with_service(
        &service,
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
        },
        req,
        client,
        form,
        client_assertion,
    )
    .await
}
