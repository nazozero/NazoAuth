use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

use crate::{DbPool, schema::oauth_clients};

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_clients)]
struct OAuthClientRecord {
    id: Uuid,
    tenant_id: Uuid,
    realm_id: Uuid,
    organization_id: Uuid,
    client_id: String,
    client_name: String,
    client_type: String,
    redirect_uris: Value,
    scopes: Value,
    allowed_audiences: Value,
    grant_types: Value,
    token_endpoint_auth_method: String,
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_cert_sha256: Option<String>,
    tls_client_auth_san_dns: Value,
    tls_client_auth_san_uri: Value,
    tls_client_auth_san_ip: Value,
    tls_client_auth_san_email: Value,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    allow_authorization_code_without_pkce: bool,
    is_active: bool,
    jwks: Option<Value>,
    introspection_encrypted_response_alg: Option<String>,
    introspection_encrypted_response_enc: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    authorization_signed_response_alg: Option<String>,
    authorization_encrypted_response_alg: Option<String>,
    authorization_encrypted_response_enc: Option<String>,
    post_logout_redirect_uris: Value,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: bool,
    subject_type: String,
    sector_identifier_uri: Option<String>,
    sector_identifier_host: Option<String>,
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
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
    }

    pub async fn by_id(&self, id: Uuid) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .find(id)
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
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
            .select(OAuthClientRecord::as_select())
            .limit(limit)
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect()
    }

    /// Verifies a secret candidate while keeping the persisted digest private.
    pub async fn client_secret_matches(
        &self,
        id: Uuid,
        candidate: &str,
        pepper: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        let stored = oauth_clients::table
            .find(id)
            .select(oauth_clients::client_secret_hash)
            .first::<Option<String>>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .flatten();
        Ok(stored
            .is_some_and(|stored| nazo_auth::verify_client_secret_hash(candidate, &stored, pepper)))
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

impl OAuthClientRecord {
    fn into_domain(self) -> Result<OAuthClient, RepositoryError> {
        Ok(OAuthClient {
            id: self.id,
            tenant_id: self.tenant_id,
            realm_id: self.realm_id,
            organization_id: self.organization_id,
            registration: ValidatedClientRegistration {
                client_id: self.client_id,
                client_name: self.client_name,
                client_type: self.client_type,
                redirect_uris: string_array(self.redirect_uris, "redirect_uris")?,
                post_logout_redirect_uris: string_array(
                    self.post_logout_redirect_uris,
                    "post_logout_redirect_uris",
                )?,
                scopes: string_array(self.scopes, "scopes")?,
                allowed_audiences: string_array(self.allowed_audiences, "allowed_audiences")?,
                grant_types: string_array(self.grant_types, "grant_types")?,
                token_endpoint_auth_method: self.token_endpoint_auth_method,
                subject_type: self.subject_type,
                sector_identifier_uri: self.sector_identifier_uri,
                sector_identifier_host: self.sector_identifier_host,
                require_dpop_bound_tokens: self.require_dpop_bound_tokens,
                allow_client_assertion_audience_array: self.allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience: self
                    .allow_client_assertion_endpoint_audience,
                require_par_request_object: self.require_par_request_object,
                allow_authorization_code_without_pkce: self.allow_authorization_code_without_pkce,
                backchannel_logout_uri: self.backchannel_logout_uri,
                backchannel_logout_session_required: self.backchannel_logout_session_required,
                frontchannel_logout_uri: self.frontchannel_logout_uri,
                frontchannel_logout_session_required: self.frontchannel_logout_session_required,
                tls_client_auth_subject_dn: self.tls_client_auth_subject_dn,
                tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256,
                tls_client_auth_san_dns: string_array(
                    self.tls_client_auth_san_dns,
                    "tls_client_auth_san_dns",
                )?,
                tls_client_auth_san_uri: string_array(
                    self.tls_client_auth_san_uri,
                    "tls_client_auth_san_uri",
                )?,
                tls_client_auth_san_ip: string_array(
                    self.tls_client_auth_san_ip,
                    "tls_client_auth_san_ip",
                )?,
                tls_client_auth_san_email: string_array(
                    self.tls_client_auth_san_email,
                    "tls_client_auth_san_email",
                )?,
                jwks: self.jwks,
                introspection_encrypted_response_alg: self.introspection_encrypted_response_alg,
                introspection_encrypted_response_enc: self.introspection_encrypted_response_enc,
                userinfo_signed_response_alg: self.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc,
                authorization_signed_response_alg: self.authorization_signed_response_alg,
                authorization_encrypted_response_alg: self.authorization_encrypted_response_alg,
                authorization_encrypted_response_enc: self.authorization_encrypted_response_enc,
            },
            require_mtls_bound_tokens: self.require_mtls_bound_tokens,
            is_active: self.is_active,
        })
    }
}

fn string_array(value: Value, field: &str) -> Result<Vec<String>, RepositoryError> {
    serde_json::from_value(value).map_err(|error| {
        RepositoryError::Unexpected(format!("invalid OAuth client {field}: {error}"))
    })
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_client_string_arrays_reject_non_array_json() {
        assert!(
            string_array(
                Value::String("authorization_code".to_owned()),
                "grant_types"
            )
            .is_err()
        );
    }
}
