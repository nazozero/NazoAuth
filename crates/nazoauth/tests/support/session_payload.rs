//! Stored session payload fixture for HTTP tests, including historical records.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct SessionPayload {
    pub user_id: uuid::Uuid,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default)]
    pub pending_mfa: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
}
