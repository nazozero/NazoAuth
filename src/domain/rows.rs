//! Diesel 查询结果行模型。
// Row 结构体只描述数据库投影，不承载 handler 业务流程。
use chrono::{DateTime, Utc};
use diesel::{Queryable, QueryableByName, Selectable};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// users 表完整用户行。
#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct UserRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) username: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) email: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) display_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) avatar_url: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) given_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) family_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) middle_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) nickname: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) profile_url: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) website_url: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) gender: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) birthdate: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) zoneinfo: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) locale: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) role: String,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    pub(crate) admin_level: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_formatted: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_street_address: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_locality: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_region: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_postal_code: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_country: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) phone_number: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) phone_number_verified: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) email_verified: bool,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) password_hash: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) is_active: bool,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) updated_at: DateTime<Utc>,
}

/// oauth_clients 表完整客户端行。
#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::oauth_clients)]
pub(crate) struct ClientRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) client_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) client_secret_argon2_hash: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) redirect_uris: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) allowed_audiences: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) grant_types: Value,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) token_endpoint_auth_method: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) require_dpop_bound_tokens: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) is_active: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    pub(crate) jwks: Option<Value>,
}

/// oauth_tokens 表 token 行。
#[derive(Debug, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = crate::schema::oauth_tokens)]
pub(crate) struct TokenRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) token_family_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) client_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) user_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) issued_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) subject: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) dpop_jkt: Option<String>,
}

/// 当前用户已授权应用列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct MyApplicationRow {
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_name: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) last_scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) last_authorized_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    pub(crate) authorization_count: i32,
}

/// 当前用户访问接入申请列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct UserAccessRequestRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_name: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_url: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) request_description: String,
    #[diesel(sql_type = diesel::sql_types::SmallInt)]
    pub(crate) status: i16,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) admin_note: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) approved_client_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) resolved_at: Option<DateTime<Utc>>,
}

/// 管理端访问接入申请列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct AccessRequestRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) user_email: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_name: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_url: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) request_description: String,
    #[diesel(sql_type = diesel::sql_types::SmallInt)]
    pub(crate) status: i16,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) admin_note: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) approved_client_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) resolved_at: Option<DateTime<Utc>>,
}

/// 管理端授权记录列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct GrantRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) email: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_name: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) last_authorized_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    pub(crate) authorization_count: i32,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) last_scopes: Value,
}

/// 待处理访问申请去重查询行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct PendingAccessRequestRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_name: String,
}
