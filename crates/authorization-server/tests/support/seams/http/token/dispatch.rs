use crate::domain::client_policy::authorization_code_key;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::domain::{CodePayload, TestInfrastructure};

use crate::settings::Settings;

use base64::Engine;

use chrono::{Duration, Utc};

use nazo_http_actix::OAuthJsonErrorFields;

use serde_json::{Value, json};

use uuid::Uuid;

fn pending_authorization_code_payload(raw: &str) -> Result<Option<CodePayload>, serde_json::Error> {
    match serde_json::from_str::<AuthorizationCodeState>(raw)? {
        AuthorizationCodeState::Pending { payload } => Ok(Some(payload)),
        _ => Ok(None),
    }
}

pub(crate) async fn token(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let service = Data::new(ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    ));
    let connection = state.valkey_connection();
    let authorization_service = Data::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    ));
    let ciba_service = Data::new(super::ciba::ServerCibaService::new(
        nazo_valkey::CibaStore::new(&connection),
    ));
    let ciba_users = Data::new(nazo_postgres::UserRepository::new(state.diesel_db.clone()));
    let ciba_config = Data::new(super::ciba::CibaHttpConfig::from(state.settings.as_ref()));
    let issuance_config = Data::new(TokenIssuanceConfig::from(state.settings.as_ref()));
    let device_service = Data::new(super::device::ServerDeviceGrantService::new(
        nazo_valkey::DeviceStore::new(&connection),
    ));
    let runtime_modules = Data::from(
        crate::runtime_modules::runtime_module_registry_for_test(
            state.diesel_db.clone(),
            state.settings.as_ref(),
        )
        .expect("test runtime module registry should be valid"),
    );
    token_with_service(
        Data::new(TokenEndpointHandles::new(
            TokenCoreHandles {
                token_service: service,
                authorization_service,
                device_service,
            },
            CibaTokenHandles::new(ciba_service, ciba_users, ciba_config),
            issuance_config,
            runtime_modules,
            Arc::new(
                crate::domain::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .expect("empty remote document policy is valid"),
            ),
            Openid4vcTokenHandles::default(),
        )),
        req,
        body,
    )
    .await
}

pub(crate) fn validate_token_request_profile(
    settings: &Settings,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    validate_token_request_profile_with_profile(
        settings.protocol.authorization_server_profile,
        client,
        auth_method,
    )
}
