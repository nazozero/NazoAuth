use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{deserialize_authorization_details, empty_authorization_details};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DeviceAuthorizationPayload {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_indicators: Vec<String>,
    #[serde(
        default = "empty_authorization_details",
        deserialize_with = "deserialize_authorization_details"
    )]
    pub authorization_details: Value,
    pub interval_seconds: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DeviceAuthorizationApproval {
    pub user_id: Uuid,
    pub subject: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DeviceAuthorizationState {
    Pending {
        payload: DeviceAuthorizationPayload,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_poll_at: Option<DateTime<Utc>>,
        #[serde(default)]
        slow_down_count: u32,
    },
    Approved {
        payload: DeviceAuthorizationPayload,
        approval: DeviceAuthorizationApproval,
        approved_at: DateTime<Utc>,
    },
    Denied {
        payload: DeviceAuthorizationPayload,
        denied_at: DateTime<Utc>,
    },
    Consumed {
        consumed_at: DateTime<Utc>,
    },
}
