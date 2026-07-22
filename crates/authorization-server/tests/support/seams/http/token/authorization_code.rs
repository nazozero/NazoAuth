use crate::domain::TestInfrastructure;

use crate::domain::client_policy::authorization_code_key;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::settings::Settings;

use crate::test_support::valkey::valkey_get;

use crate::test_support::valkey::valkey_set_ex;

use actix_web::http::header;

use actix_web::http::header::HeaderValue;

use actix_web::web::Data;

use base64::Engine;

use chrono::{DateTime, Duration};

use nazo_auth::OidcClaimRequest;

use nazo_http_actix::OAuthJsonErrorFields;

use serde_json::{Value, json};

use uuid::Uuid;

fn authorization_code_audiences(
    settings: &Settings,
    payload: &CodePayload,
    form: &TokenForm,
) -> Result<Vec<String>, ()> {
    let config = TokenIssuanceConfig::from(settings);
    authorization_code_audiences_with_default(
        config.default_audience(),
        config.openid4vci_audience(&payload.scopes, &payload.authorization_details),
        payload,
        form,
    )
}

fn test_token_service(state: &TestInfrastructure) -> ServerTokenService {
    ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    )
}

async fn load_pending_authorization_code_payload(
    state: &TestInfrastructure,
    code_hash: &str,
) -> Result<Option<Box<CodePayload>>, HttpResponse> {
    load_pending_authorization_code_payload_with_service(&test_token_service(state), code_hash)
        .await
}

async fn begin_authorization_code_consumption(
    state: &TestInfrastructure,
    code_hash: &str,
) -> Result<AuthorizationCodeConsumption, HttpResponse> {
    begin_authorization_code_consumption_with_service(&test_token_service(state), code_hash).await
}

pub(crate) async fn token_authorization_code(
    state: &TestInfrastructure,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let service = test_token_service(state);
    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = super::issue::test_authorization_service(state);
    token_authorization_code_with_service(
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
