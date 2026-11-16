//! Token HTTP boundary: budget, parsing, extraction and presentation.

use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::{
    ClientIpConfig, basic_authorization_credentials, client_ip_with_config,
    oauth_endpoint_error_response, oauth_token_error, parse_token_form_with_pre_authorized,
    token_endpoint_success_response,
};
use bytes::Bytes;
use http::StatusCode;
use nazo_oauth_server::contracts::token_endpoint::{
    ClientAttestationFacts, TokenRequestFacts, prepare_token_request,
};
use nazo_oauth_server::contracts::token_forms::TokenFormError;
use nazo_oauth_server::token::dispatch::TokenEndpointHandles;

pub fn token_request_facts(req: &HttpRequest) -> TokenRequestFacts<'_> {
    let headers = req.headers();
    TokenRequestFacts {
        dpop: crate::endpoints::dpop::dpop_request_facts(req),
        client_attestation: ClientAttestationFacts {
            strict_pair: crate::endpoints::client_attestation::client_attestation_headers(headers),
        },
        certificate: crate::endpoints::mtls::with_request_mtls_client_certificate(
            req,
            |certificate| certificate,
        ),
    }
}
pub async fn token_with_service(
    handles: &TokenEndpointHandles,
    client_ip: &ClientIpConfig,
    req: &HttpRequest,
    body: &Bytes,
) -> HttpResponse {
    if let Err(error) = handles
        .enforce_rate_limit(&client_ip_with_config(req, client_ip))
        .await
    {
        return oauth_endpoint_error_response(error);
    }
    let parsed_form = match parse_token_form_with_pre_authorized(req, body) {
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
                "invalid_request",
                "resource must be an absolute URI without a fragment.",
                false,
            );
        }
        Err(TokenFormError::InvalidAudienceParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "audience 参数不能为空.",
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

    let prepared = match prepare_token_request(parsed_form, basic_authorization_credentials(req)) {
        Ok(value) => value,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    let facts = token_request_facts(req);
    match handles.execute(prepared, facts).await {
        Ok(success) => token_endpoint_success_response(success),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
