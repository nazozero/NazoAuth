use http::StatusCode;

use super::request_facts::DpopErrorContext;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthErrorFields {
    pub status: StatusCode,
    pub error: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OAuthEndpointError {
    Json(OAuthErrorFields),
    Authorization(OAuthErrorFields),
    Token {
        fields: OAuthErrorFields,
        basic_challenge: bool,
    },
    Bearer(OAuthErrorFields),
    Dpop {
        error: nazo_auth::DpopError,
        context: DpopErrorContext,
    },
    PreAuthorized(nazo_openid4vci::application::CredentialHttpError),
    RateLimited {
        retry_after_seconds: u64,
    },
    Disabled,
}

impl OAuthEndpointError {
    pub fn json(
        status: StatusCode,
        error: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self::Json(OAuthErrorFields {
            status,
            error: error.into(),
            description: description.into(),
        })
    }

    pub fn authorization(
        status: StatusCode,
        error: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self::Authorization(OAuthErrorFields {
            status,
            error: error.into(),
            description: description.into(),
        })
    }

    pub fn token(
        status: StatusCode,
        error: impl Into<String>,
        description: impl Into<String>,
        basic_challenge: bool,
    ) -> Self {
        Self::Token {
            fields: OAuthErrorFields {
                status,
                error: error.into(),
                description: description.into(),
            },
            basic_challenge,
        }
    }

    pub fn bearer(
        status: StatusCode,
        error: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self::Bearer(OAuthErrorFields {
            status,
            error: error.into(),
            description: description.into(),
        })
    }
}
