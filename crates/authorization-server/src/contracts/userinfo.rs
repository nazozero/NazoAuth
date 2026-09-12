use serde_json::Value;
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTokenAuthScheme {
    Bearer,
    DPoP,
}

pub type UserinfoFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UserinfoSuccess, UserinfoError>> + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub enum UserinfoRepresentation {
    Claims(Value),
    Jwt(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct UserinfoSuccess {
    pub representation: UserinfoRepresentation,
    pub dpop_nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserinfoDpopError {
    MissingProof,
    MalformedProof,
    InvalidProof,
    ReplayDetected,
    BindingMismatch,
    TokenNotBound,
    UseNonce(String),
    NonceStoreUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserinfoError {
    InvalidAccessToken,
    InvalidAudience,
    InvalidTenantBoundary,
    RevokedAccessToken,
    Dpop(UserinfoDpopError),
    MissingMtlsCertificate,
    MtlsCertificateMismatch,
    InsufficientScope,
    InvalidSubject,
    InactiveSubject,
    ClientUnavailable,
    QueryUnavailable,
    ResponseProtectionFailed,
}

/// A validated access token. Only the application crate can prepare this value.
pub struct PreparedUserinfo {
    pub(crate) scheme: AccessTokenAuthScheme,
    pub(crate) token: String,
    pub(crate) claims: nazo_auth::Claims,
    pub(crate) tenant_id: uuid::Uuid,
}

impl PreparedUserinfo {
    pub fn requires_mtls_certificate(&self) -> bool {
        self.scheme == AccessTokenAuthScheme::Bearer
            && self
                .claims
                .cnf
                .as_ref()
                .is_some_and(|cnf| cnf.x5t_s256.is_some())
    }
}

pub struct UserinfoRequestFacts<'a> {
    pub dpop: crate::contracts::request_facts::DpopRequestFacts<'a>,
    pub mtls_thumbprint: Option<String>,
}

pub type UserinfoPreparationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PreparedUserinfo, UserinfoError>> + 'a>>;

pub trait UserinfoOperations: Send + Sync {
    fn prepare<'a>(
        &'a self,
        scheme: AccessTokenAuthScheme,
        token: String,
    ) -> UserinfoPreparationFuture<'a>;

    fn userinfo<'a>(
        &'a self,
        prepared: PreparedUserinfo,
        facts: UserinfoRequestFacts<'a>,
    ) -> UserinfoFuture<'a>;
}
