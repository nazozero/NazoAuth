use crate::domain::TestInfrastructure;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::settings::Settings;

use chrono::Utc;

use serde_json::json;

use uuid::Uuid;

pub(crate) async fn verify_confidential_client(
    state: &TestInfrastructure,
    request: &ClientAuthRequestFacts,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    let connection = state.valkey_connection();
    let service = crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            crate::domain::tenancy::DEFAULT_TENANT_ID,
        ),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let result = authenticate_client_with_dependencies(
        &service,
        ClientAuthConfig::new(
            &state.settings.endpoint.issuer,
            &state.settings.protocol.client_secret_pepper,
        ),
        request,
        client,
        credentials,
        ClientAuthenticationContext::ConfidentialOnly,
    )
    .await;
    result.map_err(|error| match error {
        TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementClientAuthError::InvalidClient
        }
        other => other,
    })
}

fn revocation_public_client_allows_credentials(credentials: &ClientCredentials) -> bool {
    credentials.method == "none"
        && credentials.client_secret.is_none()
        && credentials.client_assertion.is_none()
}

pub(crate) async fn consume_token_client_assertion(
    state: &TestInfrastructure,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    let connection = state.valkey_connection();
    let service = crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            crate::domain::tenancy::DEFAULT_TENANT_ID,
        ),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    consume_token_client_assertion_with_authorization_service(&service, client, Some(assertion))
        .await
}
