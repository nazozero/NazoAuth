//! OAuth/OIDC 流程中的序列化载荷。
// 这些结构体会进入 JWT、临时协议状态或 token 签发逻辑，字段名需保持协议稳定。
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub use nazo_auth::{
    AuthorizationCodeState, CodePayload, ConsentPayload, ConsumedAuthorizationCode,
    OidcClaimRequest, PushedAuthorizationRequest,
};

/// token 签发函数所需的归一化输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshTokenPolicy {
    IssueNew,
    Rotate {
        family_id: Uuid,
        rotated_from_id: Uuid,
    },
    RotateLostResponse {
        family_id: Uuid,
        original_id: Uuid,
        successor_id: Uuid,
        retry_started_at: DateTime<Utc>,
    },
    PreserveExisting,
}

pub struct TokenIssue {
    pub user_id: Option<Uuid>,
    pub subject: String,
    pub scopes: Vec<String>,
    pub authorization_details: Value,
    pub audiences: Vec<String>,
    pub nonce: Option<String>,
    pub auth_time: Option<i64>,
    pub amr: Vec<String>,
    pub oidc_sid: Option<String>,
    pub acr: Option<String>,
    pub userinfo_claims: Vec<String>,
    pub userinfo_claim_requests: Vec<OidcClaimRequest>,
    pub id_token_claims: Vec<String>,
    pub id_token_claim_requests: Vec<OidcClaimRequest>,
    /// `None` means this is not a refresh issuance. `Some(None)` records that
    /// the original ID Token omitted `sid`; `Some(Some(value))` preserves the
    /// exact SID emitted by the original ID Token (including Native SSO).
    pub refresh_id_token_sid: Option<Option<String>>,
    pub include_refresh: bool,
    pub refresh_token_policy: RefreshTokenPolicy,
    pub dpop_jkt: Option<String>,
    pub refresh_token_dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub refresh_token_mtls_x5t_s256: Option<String>,
    pub refresh_token_client_attestation_jkt: Option<String>,
    /// Original refresh-token authorization. A refresh request may narrow the
    /// access-token scope, but RFC 6749 requires a rotated refresh token to
    /// retain the scope of the token presented by the client.
    pub refresh_token_scopes: Option<Vec<String>>,
    pub authorization_code_hash: Option<String>,
    pub actor: Option<Value>,
    pub issued_token_type: Option<String>,
    pub native_sso: Option<NativeSsoTokenBinding>,
}

#[derive(Clone, Debug)]
pub struct NativeSsoTokenBinding {
    pub device_secret: String,
    pub ds_hash: String,
    pub sid: String,
}

#[cfg(test)]
#[path = "../../tests/unit/domain/oauth.rs"]
mod tests;
