use super::{request_facts::DpopRequestFacts, token_client_auth::ClientCertificateFacts};

pub struct ClientAttestationFacts<'a> {
    /// `Err(())` when either header is malformed, empty, or repeated; the
    /// strict pair is the only attestation material the dispatcher may use.
    pub strict_pair: Result<Option<(&'a str, &'a str)>, ()>,
}

pub struct TokenRequestFacts<'a> {
    pub dpop: DpopRequestFacts<'a>,
    pub client_attestation: ClientAttestationFacts<'a>,
    pub certificate: Option<ClientCertificateFacts>,
}

/// Parsed input whose endpoint-level parameter and authentication-source checks passed.
pub struct PreparedTokenRequest {
    pub(crate) parsed: super::token_forms::ParsedTokenForm,
    pub(crate) auth: super::token_client_auth::TokenClientAuthTransportFacts,
    pub(crate) client_auth_context: nazo_auth::TokenClientAuthenticationContext,
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
    let client_auth_context = nazo_auth::token_client_authentication_context(auth.presentation())
        .map_err(|_| {
        OAuthEndpointError::token(
            http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一 token 请求不能同时使用多种客户端认证方式.",
            false,
        )
    })?;
    Ok(PreparedTokenRequest {
        parsed,
        auth,
        client_auth_context,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub enum TokenEndpointSuccess {
    Issued {
        body: serde_json::Value,
        dpop_nonce: Option<String>,
    },
    PreAuthorized(nazo_openid4vci::application::PreAuthorizedTokenResponse),
}
