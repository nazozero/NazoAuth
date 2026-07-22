use crate::adapters::security::pkce_s256;

use crate::domain::TestInfrastructure;

use crate::domain::client_policy::authorization_code_key;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::domain::{AuthorizationCodeState, DatabaseUserFixture, PushedAuthorizationRequest};

use crate::http::sessions::SessionPayload;

use crate::settings::Settings;

use crate::test_support::valkey::valkey_get;

use crate::test_support::valkey::valkey_set_ex;

use actix_web::http::header;

use serde_json::json;

pub(crate) async fn consume_pushed_authorization_request(
    state: &TestInfrastructure,
    request_uri: &str,
) -> Result<(), PushedAuthorizationRequestConsumeError> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    consume_pushed_authorization_request_with_context(&dependencies.context(), request_uri).await
}

async fn authorization_response_redirect_with_protection(
    state: &TestInfrastructure,
    input: AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> HttpResponse {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    authorization_response_redirect_with_protection_context(
        &dependencies.context(),
        input,
        protection,
    )
    .await
}

async fn consume_reauth_nonce(
    state: &TestInfrastructure,
    q: &mut HashMap<String, String>,
) -> Option<i64> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    consume_reauth_nonce_with_context(&dependencies.context(), q).await
}

async fn authorization_login_url(
    state: &TestInfrastructure,
    q: &HashMap<String, String>,
    reauthentication_required: bool,
) -> Result<String, HttpResponse> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    authorization_login_url_with_context(&dependencies.context(), q, reauthentication_required)
        .await
}
