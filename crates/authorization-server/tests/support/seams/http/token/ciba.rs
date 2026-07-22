use nazo_http_actix::OAuthJsonErrorFields;

use crate::domain::TestInfrastructure;

use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID};

use super::validate_token_request_profile;

fn validate_and_apply_ciba_request_object_claims(
    state: &TestInfrastructure,
    client: &ClientRow,
    form: &mut BackchannelAuthenticationForm,
) -> Result<Option<CibaRequestObjectReplay>, HttpResponse> {
    validate_and_apply_ciba_request_object_claims_with_config(
        &CibaHttpConfig::from(state.settings.as_ref()),
        client,
        form,
    )
}

fn validate_ciba_security_profile_client(
    settings: &Settings,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    validate_ciba_security_profile_client_with_config(
        &CibaHttpConfig::from(settings),
        client,
        auth_method,
    )
}

fn validate_ciba_request_object_presence(
    settings: &Settings,
    client: &ClientRow,
    form: &BackchannelAuthenticationForm,
) -> Result<(), HttpResponse> {
    validate_ciba_request_object_presence_with_config(&CibaHttpConfig::from(settings), client, form)
}

fn ciba_request_key(auth_req_id: &str) -> String {
    format!("oauth:ciba:{}", blake3_hex(auth_req_id))
}
