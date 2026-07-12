use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

use crate::{DbPool, schema::oauth_clients};

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_clients)]
pub struct OAuthClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub realm_id: Uuid,
    pub organization_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub client_type: String,
    pub client_secret_hash: Option<String>,
    pub redirect_uris: Value,
    pub scopes: Value,
    pub allowed_audiences: Value,
    pub grant_types: Value,
    pub token_endpoint_auth_method: String,
    pub require_dpop_bound_tokens: bool,
    pub require_mtls_bound_tokens: bool,
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_cert_sha256: Option<String>,
    pub tls_client_auth_san_dns: Value,
    pub tls_client_auth_san_uri: Value,
    pub tls_client_auth_san_ip: Value,
    pub tls_client_auth_san_email: Value,
    pub allow_client_assertion_audience_array: bool,
    pub allow_client_assertion_endpoint_audience: bool,
    pub require_par_request_object: bool,
    pub allow_authorization_code_without_pkce: bool,
    pub is_active: bool,
    pub jwks: Option<Value>,
    pub introspection_encrypted_response_alg: Option<String>,
    pub introspection_encrypted_response_enc: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub authorization_signed_response_alg: Option<String>,
    pub authorization_encrypted_response_alg: Option<String>,
    pub authorization_encrypted_response_enc: Option<String>,
    pub post_logout_redirect_uris: Value,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: bool,
    pub subject_type: String,
    pub sector_identifier_uri: Option<String>,
    pub sector_identifier_host: Option<String>,
}

#[derive(Clone)]
pub struct OAuthClientRepository {
    pool: DbPool,
}

impl OAuthClientRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(oauth_clients::client_id.eq(client_id))
            .select(OAuthClient::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(map_error)
    }

    pub async fn by_id(&self, id: Uuid) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .find(id)
            .select(OAuthClient::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(map_error)
    }

    pub async fn active_mtls_candidates(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(
                oauth_clients::token_endpoint_auth_method
                    .eq_any(["tls_client_auth", "self_signed_tls_client_auth"]),
            )
            .filter(oauth_clients::client_type.eq("confidential"))
            .filter(oauth_clients::is_active.eq(true))
            .select(OAuthClient::as_select())
            .limit(limit)
            .load(&mut connection)
            .await
            .map_err(map_error)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
