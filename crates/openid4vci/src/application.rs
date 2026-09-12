//! Issuer application contracts shared by transport and host implementations.

use crate::{
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, NotificationRequest,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub type CredentialIssuerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessTokenScheme {
    Bearer,
    Dpop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRequestContext {
    pub bearer_token: String,
    pub access_token_scheme: AccessTokenScheme,
    pub dpop_proof: Option<String>,
    /// Verified client-certificate thumbprint supplied by the deployment's
    /// certificate adapter.  The transport layer never derives this from an
    /// ordinary request header.
    pub mtls_x5t_s256: Option<String>,
    pub request_url: String,
    pub method: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialResponseBody {
    Json(CredentialResponse),
    Jwt(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialEndpointResponse<T> {
    pub body: T,
    pub dpop_nonce: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialRequestBody<T> {
    Json(T),
    Jwt(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreAuthorizedTokenRequest {
    pub pre_authorized_code: String,
    pub tx_code: Option<String>,
    pub client_id: Option<String>,
    pub dpop_proof: Option<String>,
    pub client_attestation: Option<String>,
    pub client_attestation_pop: Option<String>,
    pub request_url: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PreAuthorizedTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_details: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCredentialOfferRequest {
    pub subject_id: Uuid,
    pub credential_configuration_ids: Vec<String>,
    pub grant_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
    #[serde(default = "default_offer_lifetime")]
    pub expires_in: u64,
}

const fn default_offer_lifetime() -> u64 {
    300
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CreateCredentialOfferResponse {
    pub offer_id: Uuid,
    pub credential_offer_uri: String,
    pub credential_offer: CredentialOffer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialHttpError {
    pub status: u16,
    pub error: &'static str,
    pub description: &'static str,
    pub dpop_nonce: Option<String>,
}

pub trait CredentialIssuerOperations: Send + Sync {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>>;
    fn offer<'a>(
        &'a self,
        offer_id: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>>;
    fn nonce(
        &self,
        dpop_proof: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>>;
    fn credential<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    >;
    fn deferred<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    >;
    fn notify<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>;
    fn pre_authorized_token<'a>(
        &'a self,
        request: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>>;
    fn create_offer<'a>(
        &'a self,
        request: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>;
}
