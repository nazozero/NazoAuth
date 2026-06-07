//! OAuth/OIDC 流程中的序列化载荷。
// 这些结构体会进入 JWT、Valkey 临时键或 token 签发逻辑，字段名需保持协议稳定。
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// RFC 9449/RFC 7800 confirmation claim for proof-of-possession access tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ConfirmationClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) jkt: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub(crate) x5t_s256: Option<String>,
}

/// One requested OIDC Claim from the `claims` authorization request parameter.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct OidcClaimRequest {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) essential: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) values: Vec<Value>,
}

/// Access token 中的 JWT claims。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Claims {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user_id: Option<String>,
    pub(crate) subject_type: String,
    pub(crate) aud: Value,
    pub(crate) client_id: String,
    pub(crate) scope: String,
    #[serde(
        default,
        skip_serializing_if = "crate::domain::authorization_details_empty"
    )]
    pub(crate) authorization_details: Value,
    pub(crate) token_use: String,
    pub(crate) jti: String,
    pub(crate) iat: i64,
    pub(crate) nbf: i64,
    pub(crate) exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cnf: Option<ConfirmationClaims>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) userinfo_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) userinfo_claim_requests: Vec<OidcClaimRequest>,
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
    #[serde(
        default = "crate::domain::empty_authorization_details",
        deserialize_with = "crate::domain::deserialize_authorization_details"
    )]
    pub(crate) authorization_details: Value,
    pub(crate) state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response_mode: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) oidc_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) acr: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) userinfo_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) userinfo_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) id_token_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) id_token_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mtls_x5t_s256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pushed_request_uri: Option<String>,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct PushedAuthorizationRequest {
    pub(crate) client_id: String,
    pub(crate) params: std::collections::HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mtls_x5t_s256: Option<String>,
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
    #[serde(
        default = "crate::domain::empty_authorization_details",
        deserialize_with = "crate::domain::deserialize_authorization_details"
    )]
    pub(crate) authorization_details: Value,
    pub(crate) nonce: Option<String>,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) oidc_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) acr: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) userinfo_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) userinfo_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) id_token_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) id_token_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) code_challenge_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mtls_x5t_s256: Option<String>,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// 授权码在 Valkey 中的完整生命周期状态。
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum AuthorizationCodeState {
    Pending {
        payload: CodePayload,
    },
    Consuming {
        payload: CodePayload,
        consuming_at: DateTime<Utc>,
    },
    Consumed {
        marker: ConsumedAuthorizationCode,
    },
    Failed {
        failed_at: DateTime<Utc>,
        error: String,
    },
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
    pub(crate) authorization_details: Value,
    pub(crate) audiences: Vec<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) auth_time: Option<i64>,
    pub(crate) amr: Vec<String>,
    pub(crate) acr: Option<String>,
    pub(crate) userinfo_claims: Vec<String>,
    pub(crate) userinfo_claim_requests: Vec<OidcClaimRequest>,
    pub(crate) id_token_claims: Vec<String>,
    pub(crate) id_token_claim_requests: Vec<OidcClaimRequest>,
    pub(crate) include_refresh: bool,
    pub(crate) rotation: Option<(Uuid, Option<Uuid>)>,
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) refresh_token_dpop_jkt: Option<String>,
    pub(crate) mtls_x5t_s256: Option<String>,
    pub(crate) refresh_token_mtls_x5t_s256: Option<String>,
    pub(crate) authorization_code_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn code_payload_json(authorization_details: Value) -> Value {
        json!({
            "code_id": "code-1",
            "user_id": "018fd6c7-96f6-7c6a-b8aa-6c0b9c4c0d01",
            "client_id": "client-1",
            "redirect_uri": "https://client.example/callback",
            "redirect_uri_was_supplied": true,
            "scopes": ["openid", "offline_access"],
            "authorization_details": authorization_details,
            "nonce": null,
            "auth_time": 1780750000,
            "amr": ["password"],
            "issued_at": "2026-06-07T00:00:00Z",
            "expires_at": "2026-06-07T00:05:00Z"
        })
    }

    #[test]
    fn code_payload_defaults_missing_authorization_details_to_empty_array() {
        let mut value = code_payload_json(json!([]));
        value
            .as_object_mut()
            .expect("payload should be an object")
            .remove("authorization_details");

        let payload: CodePayload =
            serde_json::from_value(value).expect("missing authorization_details should parse");

        assert_eq!(payload.authorization_details, json!([]));
    }

    #[test]
    fn code_payload_normalizes_empty_internal_authorization_details_states() {
        for value in [Value::Null, json!({})] {
            let payload: CodePayload = serde_json::from_value(code_payload_json(value))
                .expect("empty internal authorization_details state should parse");

            assert_eq!(payload.authorization_details, json!([]));
        }
    }

    #[test]
    fn code_payload_rejects_non_array_authorization_details() {
        let error = serde_json::from_value::<CodePayload>(code_payload_json(json!({
            "type": "account_information"
        })))
        .expect_err("non-empty object authorization_details should be rejected");

        assert!(error.to_string().contains("authorization_details"));
    }

    #[test]
    fn authorization_code_state_survives_lua_empty_array_roundtrip_shape() {
        let raw = json!({
            "status": "pending",
            "payload": code_payload_json(json!({}))
        });

        let state: AuthorizationCodeState =
            serde_json::from_value(raw).expect("state with lua-shaped empty details should parse");
        let AuthorizationCodeState::Pending { payload } = state else {
            panic!("state should remain pending");
        };

        assert_eq!(payload.authorization_details, json!([]));
    }
}
