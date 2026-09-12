//! Token HTTP boundary: budget, parsing, extraction and presentation.
use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Bytes, Data},
};
use nazo_http_actix::{
    ClientIpConfig, TokenClientAuthForm, client_ip_with_config, oauth_endpoint_error_response,
    oauth_token_error, parse_token_form_with_pre_authorized, token_client_auth_transport_facts,
    token_endpoint_success_response,
};
use nazo_oauth_server::contracts::token_endpoint::{
    ClientAttestationFacts, TokenRequestFacts, prepare_token_request,
};
use nazo_oauth_server::contracts::token_forms::TokenFormError;
use nazo_oauth_server::token::dispatch::TokenEndpointHandles;

pub(crate) fn token_request_facts<'a>(
    req: &'a HttpRequest,
    client_ip: &ClientIpConfig,
) -> TokenRequestFacts<'a> {
    let headers = req.headers();
    TokenRequestFacts {
        dpop: crate::http::dpop::dpop_request_facts(req),
        first_dpop_header: headers.get("DPoP").and_then(|v| v.to_str().ok()),
        client_attestation: ClientAttestationFacts {
            any_header_present: headers.contains_key("OAuth-Client-Attestation")
                || headers.contains_key("OAuth-Client-Attestation-PoP"),
            strict_pair: crate::http::client_attestation::client_attestation_headers(headers),
            first_attestation: headers
                .get("OAuth-Client-Attestation")
                .and_then(|v| v.to_str().ok()),
            first_pop: headers
                .get("OAuth-Client-Attestation-PoP")
                .and_then(|v| v.to_str().ok()),
        },
        certificate: crate::http::mtls::request_mtls_client_certificate(
            req,
            client_ip.trusted_proxy_cidrs(),
        ),
        request_target: req
            .uri()
            .to_string()
            .parse()
            .expect("parsed HTTP request target is valid"),
        idempotency_key: super::issue::request_idempotency_key(req),
    }
}
pub(crate) async fn token_with_service(
    handles: Data<TokenEndpointHandles>,
    client_ip: Data<ClientIpConfig>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if let Err(error) = handles
        .enforce_rate_limit(&client_ip_with_config(&req, &client_ip))
        .await
    {
        return oauth_endpoint_error_response(error);
    }
    let parsed_form = match parse_token_form_with_pre_authorized(&req, &body) {
        Ok(form) => form,
        Err(TokenFormError::InvalidContentType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求必须使用 application/x-www-form-urlencoded.",
                false,
            );
        }
        Err(TokenFormError::InvalidEncoding) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求体必须使用 UTF-8 编码.",
                false,
            );
        }
        Err(TokenFormError::DuplicateParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
                false,
            );
        }
        Err(TokenFormError::InvalidResourceParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource must be an absolute URI without a fragment.",
                false,
            );
        }
        Err(TokenFormError::MissingGrantType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 grant_type.",
                false,
            );
        }
    };

    let form = &parsed_form.form;
    let auth = token_client_auth_transport_facts(
        &req,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let prepared = match prepare_token_request(parsed_form, auth) {
        Ok(value) => value,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    let facts = token_request_facts(&req, &client_ip);
    match handles.execute(prepared, facts).await {
        Ok(success) => token_endpoint_success_response(success),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
pub(crate) use token_with_service as token;

#[cfg(test)]
#[path = "../../../../tests/unit/http/token/dispatch.rs"]
mod tests;
