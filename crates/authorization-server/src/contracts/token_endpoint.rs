use super::{request_facts::DpopRequestFacts, token_client_auth::ClientCertificateFacts};

pub struct ClientAttestationFacts<'a> {
    pub any_header_present: bool,
    pub strict_pair: Result<Option<(&'a str, &'a str)>, ()>,
    pub first_attestation: Option<&'a str>,
    pub first_pop: Option<&'a str>,
}

pub struct TokenRequestFacts<'a> {
    pub dpop: DpopRequestFacts<'a>,
    pub first_dpop_header: Option<&'a str>,
    pub client_attestation: ClientAttestationFacts<'a>,
    pub certificate: Option<ClientCertificateFacts>,
    pub request_target: http::Uri,
    pub idempotency_key: Option<String>,
}

/// Parsed input whose endpoint-level parameter and authentication-source checks passed.
pub struct PreparedTokenRequest {
    pub(crate) parsed: super::token_forms::ParsedTokenForm,
    pub(crate) auth: super::token_client_auth::TokenClientAuthTransportFacts,
}

pub fn prepare_token_request(
    parsed: super::token_forms::ParsedTokenForm,
    auth: super::token_client_auth::TokenClientAuthTransportFacts,
) -> Result<PreparedTokenRequest, super::oauth_error::OAuthEndpointError> {
    use super::oauth_error::OAuthEndpointError;
    if parsed.form.has_audience_param
        && parsed.form.grant_type != crate::token::TOKEN_EXCHANGE_GRANT_TYPE
    {
        return Err(OAuthEndpointError::token(
            http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "audience is only valid for OAuth token exchange; use RFC 8707 resource elsewhere.",
            false,
        ));
    }
    nazo_auth::token_client_authentication_context(auth.presentation()).map_err(|_| {
        OAuthEndpointError::token(
            http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一 token 请求不能同时使用多种客户端认证方式.",
            false,
        )
    })?;
    Ok(PreparedTokenRequest { parsed, auth })
}

#[derive(Clone, Debug, PartialEq)]
pub enum TokenEndpointSuccess {
    Issued {
        body: serde_json::Value,
        dpop_nonce: Option<String>,
    },
    Replayed {
        body: Vec<u8>,
    },
    PreAuthorized(nazo_openid4vci::application::PreAuthorizedTokenResponse),
}
