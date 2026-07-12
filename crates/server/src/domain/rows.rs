//! Diesel query rows for auth/runtime tables pending Domain Task 5 extraction.
use chrono::{DateTime, Utc};
use diesel::{Queryable, QueryableByName, Selectable};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// oauth_clients 表完整客户端行。
#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::oauth_clients)]
pub(crate) struct ClientRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) realm_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) organization_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) client_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) client_secret_hash: Option<String>,
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
    pub(crate) require_mtls_bound_tokens: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_dns: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_uri: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_ip: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_email: Value,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) allow_client_assertion_audience_array: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) allow_client_assertion_endpoint_audience: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) require_par_request_object: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) allow_authorization_code_without_pkce: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) is_active: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    pub(crate) jwks: Option<Value>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) introspection_encrypted_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) introspection_encrypted_response_enc: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) userinfo_signed_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) userinfo_encrypted_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) userinfo_encrypted_response_enc: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) authorization_signed_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) authorization_encrypted_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) authorization_encrypted_response_enc: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) post_logout_redirect_uris: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) backchannel_logout_uri: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) backchannel_logout_session_required: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) frontchannel_logout_uri: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) frontchannel_logout_session_required: bool,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) subject_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) sector_identifier_uri: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) sector_identifier_host: Option<String>,
}

/// oauth_tokens 表 token 行。
#[derive(Debug, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = crate::schema::oauth_tokens)]
pub(crate) struct TokenRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) token_family_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) client_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) user_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) audience: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) authorization_details: Value,
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
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) mtls_x5t_s256: Option<String>,
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

/// 待处理访问申请去重查询行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct PendingAccessRequestRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_name: String,
}
