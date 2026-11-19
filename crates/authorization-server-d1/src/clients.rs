use crate::{
    D1Provider,
    db::{DbError, Statement},
    rows::ClientRow,
};
use nazo_auth::{
    AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort, LogoutClientRepositoryPort,
    LogoutDependencyError, LogoutFuture, OAuthClient, RegisteredLogoutClient,
};
use serde_json::json;
use uuid::Uuid;

impl From<DbError> for AdminClientPortError {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Unavailable => Self::Unavailable,
            DbError::CorruptData => Self::CorruptData,
        }
    }
}
impl From<DbError> for LogoutDependencyError {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Unavailable => Self::Unavailable,
            DbError::CorruptData => Self::Consistency,
        }
    }
}

impl AdminClientRepositoryPort for D1Provider {
    fn page(
        &self,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            let mut result=self.database.batch(vec![Statement::new("SELECT * FROM nazo_clients WHERE tenant_id=?1 ORDER BY id LIMIT ?2 OFFSET ?3",vec![json!(self.tenant_id),json!(limit),json!(offset)]),Statement::new("SELECT count(*) AS total FROM nazo_clients WHERE tenant_id=?1",vec![json!(self.tenant_id)])]).await?.into_iter();
            let rows = result
                .next()
                .ok_or(AdminClientPortError::CorruptData)?
                .rows
                .into_iter()
                .map(|row| {
                    serde_json::from_value::<ClientRow>(row)
                        .map_err(|_| AdminClientPortError::CorruptData)?
                        .into_domain()
                        .map_err(Into::into)
                })
                .collect::<Result<Vec<_>, AdminClientPortError>>()?;
            let total = result
                .next()
                .ok_or(AdminClientPortError::CorruptData)?
                .rows
                .first()
                .and_then(|row| row.get("total"))
                .and_then(serde_json::Value::as_i64)
                .ok_or(AdminClientPortError::CorruptData)?;
            Ok((rows, total))
        })
    }
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            self.client_row(client_id)
                .await?
                .map(|row| row.into_domain().map_err(Into::into))
                .transpose()
        })
    }
    fn insert_with_required_audit<'a>(
        &'a self,
        _client: &'a OAuthClient,
        _client_secret_hash: Option<&'a str>,
        _registration_access_token_blake3: Option<&'a str>,
        _actor_id: Uuid,
        _source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unavailable) })
    }
    fn update_with_required_audit<'a>(
        &'a self,
        _expected: &'a OAuthClient,
        _client: &'a OAuthClient,
        _actor_id: Uuid,
        _source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unavailable) })
    }
}
fn logout_client(client: OAuthClient) -> RegisteredLogoutClient {
    RegisteredLogoutClient {
        require_fapi2: client.security_policy.requires_fapi2_security(),
        id_token_signed_response_alg: client.registration.id_token_signed_response_alg,
        id: client.id,
        tenant_id: client.tenant_id,
        client_id: client.registration.client_id,
        active: client.is_active,
        redirect_uris: client.registration.redirect_uris,
        post_logout_redirect_uris: client.registration.post_logout_redirect_uris,
        backchannel_logout_uri: client.registration.backchannel_logout_uri,
        frontchannel_logout_uri: client.registration.frontchannel_logout_uri,
        frontchannel_logout_session_required: client
            .registration
            .frontchannel_logout_session_required,
        subject_type: client.registration.subject_type,
        sector_identifier_host: client.registration.sector_identifier_host,
    }
}
impl LogoutClientRepositoryPort for D1Provider {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            self.client_row(client_id)
                .await?
                .map(|row| row.into_domain().map(logout_client).map_err(Into::into))
                .transpose()
        })
    }
    fn by_client_ids<'a>(
        &'a self,
        tenant_id: Uuid,
        client_ids: &'a [&'a str],
    ) -> LogoutFuture<'a, Vec<RegisteredLogoutClient>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            let ids = serde_json::to_string(client_ids)
                .map_err(|_| LogoutDependencyError::Consistency)?;
            self.database.query::<ClientRow>("SELECT * FROM nazo_clients WHERE tenant_id=?1 AND client_id IN(SELECT value FROM json_each(?2))",vec![json!(self.tenant_id),json!(ids)]).await?.into_iter().map(|row|row.into_domain().map(logout_client).map_err(Into::into)).collect()
        })
    }
}
