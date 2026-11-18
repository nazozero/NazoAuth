use diesel::{Queryable, Selectable};
use jiff::Timestamp;
use serde_json::Value;
use uuid::Uuid;

/// Focused account read model. Password verifier material is intentionally
/// absent so non-authentication queries cannot retrieve it from PostgreSQL.
#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct PublicAccountRow {
    pub(crate) avatar_revision: i64,
    pub(crate) access_token_epoch: i64,
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) is_active: bool,
    pub(crate) mfa_enabled: bool,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) created_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) updated_at: Timestamp,
    pub(crate) email_verified: bool,
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_url: Option<String>,
    pub(crate) given_name: Option<String>,
    pub(crate) family_name: Option<String>,
    pub(crate) middle_name: Option<String>,
    pub(crate) nickname: Option<String>,
    pub(crate) profile_url: Option<String>,
    pub(crate) website_url: Option<String>,
    pub(crate) gender: Option<String>,
    pub(crate) birthdate: Option<String>,
    pub(crate) zoneinfo: Option<String>,
    pub(crate) locale: Option<String>,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
    pub(crate) address_formatted: Option<String>,
    pub(crate) address_street_address: Option<String>,
    pub(crate) address_locality: Option<String>,
    pub(crate) address_region: Option<String>,
    pub(crate) address_postal_code: Option<String>,
    pub(crate) address_country: Option<String>,
    pub(crate) phone_number: Option<String>,
    pub(crate) phone_number_verified: bool,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct PrincipalRow {
    pub(crate) access_token_epoch: i64,
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) is_active: bool,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
}

#[derive(Clone, Debug, Queryable, Selectable, serde::Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct SubjectClaimsRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) is_active: bool,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) updated_at: Timestamp,
    pub(crate) email_verified: bool,
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_url: Option<String>,
    pub(crate) given_name: Option<String>,
    pub(crate) family_name: Option<String>,
    pub(crate) middle_name: Option<String>,
    pub(crate) nickname: Option<String>,
    pub(crate) profile_url: Option<String>,
    pub(crate) website_url: Option<String>,
    pub(crate) gender: Option<String>,
    pub(crate) birthdate: Option<String>,
    pub(crate) zoneinfo: Option<String>,
    pub(crate) locale: Option<String>,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
    pub(crate) address_formatted: Option<String>,
    pub(crate) address_street_address: Option<String>,
    pub(crate) address_locality: Option<String>,
    pub(crate) address_region: Option<String>,
    pub(crate) address_postal_code: Option<String>,
    pub(crate) address_country: Option<String>,
    pub(crate) phone_number: Option<String>,
    pub(crate) phone_number_verified: bool,
}

#[derive(Clone, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct AuthenticationIdentityRow {
    pub(crate) id: Uuid,
    pub(crate) password_hash: String,
    pub(crate) is_active: bool,
}

impl std::fmt::Debug for AuthenticationIdentityRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticationIdentityRow([REDACTED])")
    }
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::user_passkey_credentials)]
pub(crate) struct PasskeyCredentialRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) credential_id: String,
    pub(crate) credential: Value,
    pub(crate) label: String,
    pub(crate) sign_count: i64,
    #[diesel(deserialize_as = jiff_diesel::NullableTimestamp)]
    pub(crate) last_used_at: Option<Timestamp>,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) created_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) updated_at: Timestamp,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::user_passkey_credentials)]
pub(crate) struct PasskeyCredentialSummaryRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) credential_id: String,
    pub(crate) label: String,
    pub(crate) sign_count: i64,
    #[diesel(deserialize_as = jiff_diesel::NullableTimestamp)]
    pub(crate) last_used_at: Option<Timestamp>,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) created_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) updated_at: Timestamp,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::external_identity_links)]
pub(crate) struct ExternalIdentityLinkRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) provider_type: String,
    pub(crate) provider_id: String,
    pub(crate) subject: String,
    pub(crate) email: String,
    pub(crate) claims: Value,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) created_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) updated_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::NullableTimestamp)]
    pub(crate) last_login_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::external_identity_links)]
pub(crate) struct ExternalIdentityLinkSummaryRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) provider_type: String,
    pub(crate) provider_id: String,
    pub(crate) subject: String,
    pub(crate) email: String,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) created_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::Timestamp)]
    pub(crate) updated_at: Timestamp,
    #[diesel(deserialize_as = jiff_diesel::NullableTimestamp)]
    pub(crate) last_login_at: Option<Timestamp>,
}
