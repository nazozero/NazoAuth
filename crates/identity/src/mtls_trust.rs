use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{TenantId, UserId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i16)]
pub enum MtlsTrustAnchorStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Revoked = 3,
}

impl MtlsTrustAnchorStatus {
    #[must_use]
    pub const fn code(self) -> i16 {
        self as i16
    }

    #[must_use]
    pub const fn from_code(code: i16) -> Option<Self> {
        match code {
            0 => Some(Self::Pending),
            1 => Some(Self::Approved),
            2 => Some(Self::Rejected),
            3 => Some(Self::Revoked),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewMtlsTrustAnchorRequest {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub client_id: String,
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MtlsTrustAnchorRequest {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub requester_email: Option<String>,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub status: i16,
    pub admin_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MtlsTrustAnchorRequestPage {
    pub total: i64,
    pub items: Vec<MtlsTrustAnchorRequest>,
}
