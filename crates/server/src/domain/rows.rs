//! Diesel query rows for auth/runtime tables pending Domain Task 5 extraction.
use chrono::{DateTime, Utc};
use diesel::{Queryable, QueryableByName, Selectable};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

pub(crate) type ClientRow = nazo_auth::OAuthClient;

#[cfg(test)]
#[macro_export]
macro_rules! client_row {
    ($($field:tt)*) => {{
        $crate::domain::ClientRow::try_from($crate::domain::ClientRecord { $($field)* })
            .expect("test OAuth client record must contain valid string arrays")
    }};
}

/// oauth_clients 表完整客户端持久化记录（等待 Domain Task 5 迁移）。
#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::oauth_clients)]
pub(crate) struct ClientRecord {
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

impl TryFrom<ClientRecord> for ClientRow {
    type Error = serde_json::Error;

    fn try_from(value: ClientRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            tenant_id: value.tenant_id,
            realm_id: value.realm_id,
            organization_id: value.organization_id,
            registration: nazo_auth::ValidatedClientRegistration {
                client_id: value.client_id,
                client_name: value.client_name,
                client_type: value.client_type,
                redirect_uris: serde_json::from_value(value.redirect_uris)?,
                scopes: serde_json::from_value(value.scopes)?,
                allowed_audiences: serde_json::from_value(value.allowed_audiences)?,
                grant_types: serde_json::from_value(value.grant_types)?,
                token_endpoint_auth_method: value.token_endpoint_auth_method,
                require_dpop_bound_tokens: value.require_dpop_bound_tokens,
                tls_client_auth_subject_dn: value.tls_client_auth_subject_dn,
                tls_client_auth_cert_sha256: value.tls_client_auth_cert_sha256,
                tls_client_auth_san_dns: serde_json::from_value(value.tls_client_auth_san_dns)?,
                tls_client_auth_san_uri: serde_json::from_value(value.tls_client_auth_san_uri)?,
                tls_client_auth_san_ip: serde_json::from_value(value.tls_client_auth_san_ip)?,
                tls_client_auth_san_email: serde_json::from_value(value.tls_client_auth_san_email)?,
                allow_client_assertion_audience_array: value.allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience: value
                    .allow_client_assertion_endpoint_audience,
                require_par_request_object: value.require_par_request_object,
                allow_authorization_code_without_pkce: value.allow_authorization_code_without_pkce,
                jwks: value.jwks,
                introspection_encrypted_response_alg: value.introspection_encrypted_response_alg,
                introspection_encrypted_response_enc: value.introspection_encrypted_response_enc,
                userinfo_signed_response_alg: value.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: value.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: value.userinfo_encrypted_response_enc,
                authorization_signed_response_alg: value.authorization_signed_response_alg,
                authorization_encrypted_response_alg: value.authorization_encrypted_response_alg,
                authorization_encrypted_response_enc: value.authorization_encrypted_response_enc,
                post_logout_redirect_uris: serde_json::from_value(value.post_logout_redirect_uris)?,
                backchannel_logout_uri: value.backchannel_logout_uri,
                backchannel_logout_session_required: value.backchannel_logout_session_required,
                frontchannel_logout_uri: value.frontchannel_logout_uri,
                frontchannel_logout_session_required: value.frontchannel_logout_session_required,
                subject_type: value.subject_type,
                sector_identifier_uri: value.sector_identifier_uri,
                sector_identifier_host: value.sector_identifier_host,
            },
            require_mtls_bound_tokens: value.require_mtls_bound_tokens,
            is_active: value.is_active,
        })
    }
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
