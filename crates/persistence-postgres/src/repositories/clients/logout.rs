use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;

use crate::schema::oauth_clients;
use nazo_auth::{
    LogoutClientRepositoryPort, LogoutDependencyError, LogoutFuture, RegisteredLogoutClient,
};
use uuid::Uuid;

use super::base::OAuthClientRepository;
use super::{OAuthClientRecord, registered_logout_client};

impl LogoutClientRepositoryPort for OAuthClientRepository {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>> {
        Box::pin(async move {
            OAuthClientRepository::by_client_id(self, tenant_id, client_id)
                .await
                .map(|client| client.map(registered_logout_client))
                .map_err(|_| LogoutDependencyError::Unavailable)
        })
    }

    fn by_client_ids<'a>(
        &'a self,
        tenant_id: Uuid,
        client_ids: &'a [&'a str],
    ) -> LogoutFuture<'a, Vec<RegisteredLogoutClient>> {
        Box::pin(async move {
            if client_ids.is_empty() {
                return Ok(Vec::new());
            }
            let mut connection = self
                .connection()
                .await
                .map_err(|_| LogoutDependencyError::Unavailable)?;
            let rows = oauth_clients::table
                .filter(oauth_clients::tenant_id.eq(tenant_id))
                .filter(oauth_clients::client_id.eq_any(client_ids))
                .select(OAuthClientRecord::as_select())
                .load::<OAuthClientRecord>(&mut connection)
                .await
                .map_err(|_| LogoutDependencyError::Unavailable)?;
            drop(connection);
            rows.into_iter()
                .map(|row| {
                    row.into_domain()
                        .map(registered_logout_client)
                        .map_err(|_| LogoutDependencyError::Unavailable)
                })
                .collect()
        })
    }
}
