//! OAuth/OIDC 流程中的序列化载荷。
// 这些结构体会进入 JWT、Valkey 临时键或 token 签发逻辑，字段名需保持协议稳定。
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// RFC 9449/RFC 7800 confirmation claim，当前用于 DPoP JWK thumbprint 绑定。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ConfirmationClaims {
    pub(crate) jkt: String,
}

/// Access token 中的 JWT claims。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Claims {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) subject_type: String,
    pub(crate) aud: String,
    pub(crate) client_id: String,
    pub(crate) scope: String,
    pub(crate) token_use: String,
    pub(crate) jti: String,
    pub(crate) iat: i64,
    pub(crate) nbf: i64,
    pub(crate) exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cnf: Option<ConfirmationClaims>,
}

/// 用户待确认的授权请求快照。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ConsentPayload {
    pub(crate) request_id: String,
    pub(crate) user_id: Uuid,
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) redirect_uri: String,
    pub(crate) redirect_uri_was_supplied: bool,
    pub(crate) scopes: Vec<String>,
    pub(crate) state: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) code_challenge: String,
    pub(crate) code_challenge_method: String,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// 授权码对应的服务端临时载荷。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct CodePayload {
    pub(crate) code_id: String,
    pub(crate) user_id: Uuid,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) redirect_uri_was_supplied: bool,
    pub(crate) scopes: Vec<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) code_challenge: String,
    pub(crate) code_challenge_method: String,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// 已成功兑换的授权码索引，用于发现授权码重放后撤销前次签发的令牌。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ConsumedAuthorizationCode {
    pub(crate) client_id: Uuid,
    pub(crate) access_token_jti: String,
    pub(crate) access_token_expires_at: i64,
    pub(crate) refresh_token_family_id: Option<Uuid>,
    pub(crate) consumed_at: DateTime<Utc>,
}

/// token 签发函数所需的归一化输入。
pub(crate) struct TokenIssue {
    pub(crate) user_id: Option<Uuid>,
    pub(crate) subject: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) audience: String,
    pub(crate) nonce: Option<String>,
    pub(crate) include_refresh: bool,
    pub(crate) rotation: Option<(Uuid, Option<Uuid>)>,
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) authorization_code_hash: Option<String>,
}
