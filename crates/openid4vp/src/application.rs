//! Verifier application contracts shared by transport and host implementations.

use crate::{AuthorizationResponse, PresentationResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub type PresentationFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub enum PresentationResponseBody {
    RequestObject(String),
    Json(Value),
}

#[derive(Clone, Debug, PartialEq)]
pub enum PresentationResponseInput {
    DirectPost(AuthorizationResponse),
    DirectPostJwt(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationHttpError {
    pub status: u16,
    pub error: &'static str,
    pub description: &'static str,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePresentationRequest {
    pub create_request_jti: String,
    pub wallet_authorization_endpoint: String,
    pub dcql_query: nazo_digital_credentials::DcqlQuery,
    #[serde(default)]
    pub haip: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<Value>>,
    /// Optional ordinary OpenID4VC trust policy resource selected for this
    /// verifier transaction. The digest is an immutable version fence; either
    /// both fields are present or neither is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openid4vc_trust_policy_resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openid4vc_trust_policy_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CreatePresentationResponse {
    #[serde(flatten)]
    pub idempotency: nazo_operator_protocol::Openid4vpCreateIdempotencyBinding,
    pub transaction_id: Uuid,
    pub authorization_url: String,
    pub expires_in: u64,
}

pub trait PresentationOperations: Send + Sync {
    fn create<'a>(
        &'a self,
        request: CreatePresentationRequest,
    ) -> PresentationFuture<'a, Result<CreatePresentationResponse, PresentationHttpError>>;
    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        wallet_nonce: Option<&'a str>,
    ) -> PresentationFuture<'a, Result<PresentationResponseBody, PresentationHttpError>>;
    fn respond<'a>(
        &'a self,
        transaction_id: Uuid,
        response: PresentationResponseInput,
    ) -> PresentationFuture<'a, Result<Option<String>, PresentationHttpError>>;
    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
    ) -> PresentationFuture<'a, Result<PresentationResult, PresentationHttpError>>;
}
