use std::{future::Future, pin::Pin};

use nazo_auth::TokenInspection;

use super::{
    token_client_auth::{ClientCertificateFacts, TokenClientAuthTransportFacts},
    token_forms::TokenOnlyForm,
};

pub const TOKEN_INTROSPECTION_JWT_MEDIA_TYPE: &str = "application/token-introspection+jwt";

pub type TokenManagementFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TokenManagementError>> + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementError {
    InvalidClient { basic_challenge: bool },
    AuthenticationStoreUnavailable,
    ClientLookupUnavailable,
    InspectionUnavailable,
    RevocationUnavailable,
    ResponseProtectionFailed,
}

// The inspection payload is value-owned so callers can build an RFC 7662 response
// without allocating a separate box for the bounded payload.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum TokenIntrospectionRepresentation {
    Inspection(TokenInspection),
    Jwt(String),
}

/// Deployment-derived request facts shared by rate limiting and token-management operations.
///
/// Protocol/application implementations never receive the Actix request or its headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenManagementRequestFacts {
    pub source_ip: String,
    pub endpoint_path: String,
    pub client_certificate: Option<ClientCertificateFacts>,
}

pub trait TokenManagementRequestGuard: Send + Sync {
    fn enforce<'a>(
        &'a self,
        request: &'a TokenManagementRequestFacts,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>>;
}

pub trait TokenManagementOperations: Send + Sync {
    fn introspect<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
        signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation>;

    fn revoke<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()>;
}
