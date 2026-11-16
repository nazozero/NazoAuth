//! PAR HTTP parsing, transport facts and response presentation.
use super::AuthorizationEndpoint;
use crate::endpoints::client_attestation::client_attestation_headers;
use crate::endpoints::mtls::{request_mtls_thumbprint, with_request_mtls_client_certificate};
use crate::endpoints::security::has_basic_authorization_scheme;
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use bytes::Bytes;
use http::StatusCode;
use http::header;

use crate::http::{
    TokenClientAuthForm, json_response_status, oauth_endpoint_error_response,
    token_client_auth_transport_facts,
};
use nazo_auth::encode_resource_indicators;
use nazo_oauth_server::{
    authorization::par::{ParPreparation, ParRequestFacts},
    contracts::oauth_error::OAuthEndpointError,
};
use std::collections::HashMap;

pub const PAR_AUTHORIZATION_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "resource",
    "authorization_details",
    "issuer_state",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "acr_values",
    "prompt",
    "max_age",
    "dpop_jkt",
    "response_mode",
    "request",
];

pub fn parse_par_form(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<HashMap<String, String>, OAuthEndpointError> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(OAuthEndpointError::json(
            http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR 请求必须使用 application/x-www-form-urlencoded.",
        ));
    }
    let raw = match std::str::from_utf8(body) {
        Ok(raw) => raw,
        Err(_) => {
            return Err(OAuthEndpointError::json(
                http::StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 表单无效.",
            ));
        }
    };
    let mut params = HashMap::new();
    let mut resource_values = Vec::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if key == "request_uri" {
            return Err(OAuthEndpointError::json(
                http::StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求不能包含 request_uri.",
            ));
        }
        if !PAR_AUTHORIZATION_PARAMETERS.contains(&key.as_ref())
            && !matches!(
                key.as_ref(),
                "client_secret" | "client_assertion_type" | "client_assertion"
            )
        {
            // Authorization request parameters are extension points. OAuth 2.0
            // and OpenID4VCI require unrecognized authorization request
            // parameters to be ignored, not rejected. Do not retain them in the
            // pushed request: this preserves interoperability without allowing
            // attacker-controlled extension data into authenticated PAR state.
            continue;
        }
        if key == "resource" {
            resource_values.push(value.into_owned());
            continue;
        }
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(OAuthEndpointError::json(
                http::StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 参数不能重复.",
            ));
        }
    }
    if let Some(encoded) = encode_resource_indicators(&resource_values) {
        params.insert("resource".to_owned(), encoded);
    }
    Ok(params)
}
pub async fn par(
    endpoint: &AuthorizationEndpoint,
    req: &HttpRequest,
    body: &Bytes,
) -> HttpResponse {
    let source_ip = crate::http::client_ip_with_config(req, &endpoint.client_ip);
    let preparation = match endpoint.application.begin_par(&source_ip).await {
        Ok(preparation) => preparation,
        Err(error) => return oauth_endpoint_error_response(error),
    };
    let result = par_after_rate_limit(
        preparation,
        req,
        body,
        endpoint.client_attestation.as_deref(),
    )
    .await;
    log_par_result(&result);
    match result {
        Ok(body) => json_response_status(StatusCode::CREATED, body),
        Err(error) => oauth_endpoint_error_response(error),
    }
}

pub async fn par_after_rate_limit(
    preparation: ParPreparation<'_>,
    req: &HttpRequest,
    body: &Bytes,
    validator: Option<&nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator>,
) -> Result<serde_json::Value, OAuthEndpointError> {
    let params = parse_par_form(req, body)?;
    let has_basic = has_basic_authorization_scheme(req.headers());
    let attestation = client_attestation_headers(req.headers()).map_err(|()| {
        OAuthEndpointError::json(
            http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "Exactly one of each client attestation header is required.",
        )
    })?;
    let prepared = preparation.prepare_parameters(params, has_basic, attestation)?;
    let params = prepared.parameters();
    let transport = token_client_auth_transport_facts(
        req,
        TokenClientAuthForm {
            client_id: Some(prepared.client_id()),
            client_secret: params.get("client_secret").map(String::as_str),
            client_assertion_type: params.get("client_assertion_type").map(String::as_str),
            client_assertion: params.get("client_assertion").map(String::as_str),
        },
    );
    let presentation = transport.presentation();
    // Preserve the original early certificate read only for the mTLS candidate.
    let mtls_present = !presentation.http_basic
        && !presentation.client_assertion_type
        && !presentation.client_assertion
        && !presentation.form_client_secret
        && with_request_mtls_client_certificate(req, |certificate| certificate.is_some());
    let prepared = prepared
        .prepare_client(&transport, mtls_present, attestation.is_some())
        .await?;
    // Other authentication methods first extract certificates after client lookup.
    let client_auth = crate::endpoints::token::client_auth_request_facts(req);
    let facts = ParRequestFacts {
        client_auth,
        dpop: crate::endpoints::dpop::dpop_request_facts(req),
        mtls_thumbprint: request_mtls_thumbprint(req),
        attestation,
    };
    prepared.par(facts, validator).await
}

pub fn log_par_result(result: &Result<serde_json::Value, OAuthEndpointError>) {
    if let Some((status, error)) = par_error_log_fields(result) {
        tracing::warn!("PAR request rejected http_status={status} oauth_error={error}");
    }
}
pub fn par_error_log_fields(
    result: &Result<serde_json::Value, OAuthEndpointError>,
) -> Option<(u16, String)> {
    let error = result.as_ref().err()?;
    match error {
        OAuthEndpointError::Json(fields) => Some((fields.status.as_u16(), fields.error.clone())),
        OAuthEndpointError::Dpop { error, .. } => {
            let (status, code) = match error {
                nazo_auth::DpopError::StateStoreUnavailable => (503, "server_error"),
                nazo_auth::DpopError::UseNonce(_) => (400, "use_dpop_nonce"),
                _ => (400, "invalid_dpop_proof"),
            };
            Some((status, code.to_owned()))
        }
        _ => None,
    }
}
