use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

/// Narrow family-authority row: grant ownership, sender constraints and the
/// current generation. The immutable contract payload lives in
/// `RefreshContractRow`; rotated generations only leave `SpentRefreshTokenRow`
/// proofs.
#[derive(Debug, diesel::Queryable, diesel::QueryableByName, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_refresh_families)]
pub(crate) struct RefreshFamilyRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) token_family_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) client_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) user_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    pub(crate) contract_blake3: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) current_member_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    pub(crate) current_token_blake3: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) current_audience: Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) current_issued_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) current_expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) current_id_token_sid: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) dpop_jkt: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) mtls_x5t_s256: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) client_attestation_jkt: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) reuse_detected_at: Option<DateTime<Utc>>,
}

#[derive(Debug, diesel::Queryable, diesel::QueryableByName, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_refresh_contracts)]
pub(crate) struct RefreshContractRow {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) contract: Value,
}

#[derive(Debug, diesel::Queryable, diesel::QueryableByName, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_refresh_spent_tokens)]
pub(crate) struct SpentRefreshTokenRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    pub(crate) refresh_token_blake3: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) token_family_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) member_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) spent_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, diesel::QueryableByName)]
pub(crate) struct BackchannelLogoutDeliveryRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) logout_uri: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) logout_token: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub(crate) attempts: i32,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) expires_at: DateTime<Utc>,
}
