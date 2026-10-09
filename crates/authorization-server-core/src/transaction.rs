use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{deserialize_authorization_details, empty_authorization_details};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConsentPayload {
    pub request_id: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub redirect_uri_was_supplied: bool,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_indicators: Vec<String>,
    #[serde(
        default = "empty_authorization_details",
        deserialize_with = "deserialize_authorization_details"
    )]
    pub authorization_details: Value,
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(flatten, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claim_requests: crate::UserinfoClaimRequests,
    #[serde(flatten, skip_serializing_if = "Vec::is_empty")]
    pub id_token_claim_requests: crate::IdTokenClaimRequests,
    #[serde(flatten)]
    pub pkce: crate::S256Pkce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_x5t_s256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_request_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_authorization_response_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_management_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_code_ttl_seconds: Option<u64>,

    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PushedAuthorizationRequest {
    pub client_id: String,
    pub params: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_x5t_s256: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Payloads before this contract cannot be mapped to a stable durable fence.
pub const AUTHORIZATION_CODE_REDEMPTION_VERSION: u8 = 2;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CodePayload {
    #[serde(default)]
    pub redemption_contract_version: u8,
    pub code_id: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub redirect_uri_was_supplied: bool,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_indicators: Vec<String>,
    #[serde(
        default = "empty_authorization_details",
        deserialize_with = "deserialize_authorization_details"
    )]
    pub authorization_details: Value,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(flatten, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claim_requests: crate::UserinfoClaimRequests,
    #[serde(flatten, skip_serializing_if = "Vec::is_empty")]
    pub id_token_claim_requests: crate::IdTokenClaimRequests,
    #[serde(flatten)]
    pub pkce: crate::S256Pkce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_x5t_s256: Option<String>,

    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthorizationCodeState {
    Pending {
        payload: CodePayload,
    },
    Consuming {
        payload: CodePayload,
        consuming_at: DateTime<Utc>,
    },
    Consumed,
    Failed {
        failed_at: DateTime<Utc>,
        error: String,
    },
}
