use std::{future::Future, pin::Pin, sync::Arc};

use nazo_http_signatures::VerifiedInput;
use nazo_resource_server::{
    ProtectedResourceAuthorizationContext, ProtectedResourceAuthorizationError,
    ProtectedResourceAuthorizationRequest, ProtectedResourceAuthorizationResult,
};

pub type FapiFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub enum FapiAuthorizationError {
    Protocol(ProtectedResourceAuthorizationError),
    UseDpopNonce(String),
    DpopNonceUnavailable,
}

pub trait FapiResourceAuthorizer: Send + Sync {
    fn authorize<'a>(
        &'a self,
        request: ProtectedResourceAuthorizationRequest<'a>,
        context: ProtectedResourceAuthorizationContext<'a>,
    ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FapiSignatureVerificationError {
    Invalid,
    Replay,
    LookupUnavailable,
    ReplayUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FapiSignatureOperationError {
    Unavailable,
}

pub trait FapiResponseSignature: Send + Sync {
    fn kid(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn sign<'a>(
        &'a self,
        signature_base: &'a [u8],
    ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>>;
}

pub trait FapiHttpMessageSignatures: Send + Sync {
    fn enabled(&self) -> bool;

    fn verify_and_consume<'a>(
        &'a self,
        tenant_id: &'a str,
        client_id: &'a str,
        input: &'a VerifiedInput,
    ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>>;

    fn response_signature(
        &self,
    ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError>;
}
