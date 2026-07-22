use crate::adapters::security::tokens::decode_access_claims_with;

use crate::domain::TestInfrastructure;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::settings::Settings;

use actix_web::http::header;

use chrono::Duration;

use serde_json::Value;

use super::issue::TokenIssuanceConfig;

fn refresh_token_policy_for_profile(
    settings: &Settings,
    client: &ClientRow,
    token: &TokenRow,
) -> RefreshTokenPolicy {
    refresh_token_policy_for_authorization_server_profile(
        settings.protocol.authorization_server_profile,
        client,
        token,
    )
}

fn refresh_token_audiences(
    settings: &Settings,
    token: &TokenRow,
    form: &TokenForm,
) -> Result<Vec<String>, ()> {
    let original_audiences = json_array_to_strings(&token.audience);
    let original_audiences = if original_audiences.is_empty() {
        vec![settings.protocol.default_audience.clone()]
    } else {
        original_audiences
    };
    if form.audiences.is_empty() {
        return Ok(original_audiences);
    }
    is_subset(&form.audiences, &original_audiences)
        .then(|| form.audiences.clone())
        .ok_or(())
}

pub(crate) async fn token_refresh(
    state: &TestInfrastructure,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let service = ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = super::issue::test_authorization_service(state);
    token_refresh_with_service(
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
        None,
    )
    .await
}
