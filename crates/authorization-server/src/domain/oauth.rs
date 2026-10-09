//! OAuth/OIDC 流程中的序列化载荷。
// 这些结构体会进入 JWT、临时协议状态或 token 签发逻辑，字段名需保持协议稳定。
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub use nazo_auth::{
    AuthorizationCodeState, CodePayload, ConsentPayload, PreparedTokenSubject,
    PushedAuthorizationRequest,
};

/// token 签发函数所需的归一化输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshTokenPolicy {
    /// This grant neither creates nor uses a refresh-token family.
    NoRefresh,
    IssueNew,
    Rotate {
        family_id: Uuid,
        rotated_from_id: Uuid,
    },
    RotateLostResponse {
        family_id: Uuid,
        original_id: Uuid,
        /// BLAKE3 digest of the originally presented (spent) token; the
        /// retry proves the direct-predecessor edge against the spent proof.
        original_blake3: [u8; 32],
        successor_id: Uuid,
        retry_started_at: DateTime<Utc>,
    },
    /// Reuse an existing refresh authority without replacing its member.
    /// Its source is still checked under the final issuance transaction's lock.
    PreserveExisting,
}

pub struct TokenIssue {
    pub user_id: Option<Uuid>,
    pub prepared_subject: Option<PreparedTokenSubject>,
    pub subject: String,
    pub scopes: Vec<String>,
    pub authorization_details: Value,
    pub audiences: Vec<String>,
    pub nonce: Option<String>,
    pub auth_time: Option<i64>,
    pub amr: Vec<String>,
    pub oidc_sid: Option<String>,
    pub acr: Option<String>,
    pub userinfo_claim_requests: nazo_auth::UserinfoClaimRequests,
    pub id_token_claim_requests: nazo_auth::IdTokenClaimRequests,
    /// `None` means this is not a refresh issuance. `Some(None)` records that
    /// the original ID Token omitted `sid`; `Some(Some(value))` preserves the
    /// exact SID emitted by the original ID Token (including Native SSO).
    pub refresh_id_token_sid: Option<Option<String>>,
    /// Whether this issuance permits a refresh-token response, subject to the
    /// client and scope policy. NoRefresh requires false; disabling a response
    /// never removes an existing refresh authority from the final commit.
    pub include_refresh: bool,
    pub refresh_token_policy: RefreshTokenPolicy,
    pub dpop_jkt: Option<String>,
    pub refresh_token_dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub refresh_token_mtls_x5t_s256: Option<String>,
    pub refresh_token_client_attestation_jkt: Option<String>,
    /// The original refresh authority, retained even when no replacement RT
    /// is issued. The durable commit revalidates this exact source.
    pub refresh_authority: Option<nazo_auth::RefreshTokenAuthority>,
    /// Source family fenced separately from the destination refresh family.
    pub native_sso_source: Option<nazo_auth::NativeSsoSourceFence>,
    /// Original resources of a newly redeemed authorization grant. This is
    /// only used to create a family; subsequent refreshes use their authority.
    pub refresh_grant_audiences: Option<Vec<String>>,
    pub authorization_code_hash: Option<String>,
    pub actor: Option<Value>,
    pub issued_token_type: Option<String>,
    pub native_sso: Option<NativeSsoTokenBinding>,
}

#[derive(Clone)]
pub struct NativeSsoTokenBinding {
    pub device_secret: String,
    pub ds_hash: String,
    pub sid: String,
}

impl std::fmt::Debug for NativeSsoTokenBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeSsoTokenBinding([REDACTED])")
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/oauth.rs"]
mod tests;
