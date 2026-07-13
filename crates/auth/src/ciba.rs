use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CibaRequestState {
    pub client_id: String,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_message: Option<String>,
    #[serde(default)]
    pub issued_at: i64,
    pub status: CibaStatus,
    pub interval_seconds: u64,
    pub expires_at: i64,
    pub retention_expires_at: i64,
    pub last_poll_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CibaStatus {
    Pending,
    Approved,
    Denied,
}
