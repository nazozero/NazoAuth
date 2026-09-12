use super::*;
use crate::http::mtls::request_mtls_client_certificate;
use nazo_http_actix::{
    TokenClientAuthForm, oauth_endpoint_error_response, token_client_auth_transport_facts,
};
use nazo_oauth_server::token::ciba::{CibaApplication, prepare_ciba_creation};

pub(crate) async fn backchannel_authentication(
    application: Data<CibaApplication>,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    mut payload: Payload,
) -> HttpResponse {
    if !application.check_admission(nazo_auth::CapabilityAdmission::NewRequest) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let form = match parse_backchannel_authentication_form(&req, &mut payload).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let prepared = match prepare_ciba_creation(form, has_basic_authorization_scheme(req.headers()))
    {
        Ok(prepared) => prepared,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    let form = prepared.form();
    let transport = token_client_auth_transport_facts(
        &req,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let presentation = transport.presentation();
    let mtls_present = !presentation.http_basic
        && !presentation.client_assertion_type
        && !presentation.client_assertion
        && !presentation.form_client_secret
        && form.client_id.is_some()
        && request_mtls_client_certificate(&req, client_ip.trusted_proxy_cidrs()).is_some();
    let prepared = match application
        .prepare_client(prepared, &transport, mtls_present)
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    let auth_request = client_auth_request_facts(&req, client_ip.trusted_proxy_cidrs());
    let source_ip = client_ip_with_config(&req, &client_ip);
    match application.create(prepared, auth_request, &source_ip).await {
        Ok(response) => json_response_no_store(json!(response)),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
