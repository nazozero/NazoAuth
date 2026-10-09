use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;

use crate::schema::oauth_clients;
use nazo_auth::{
    LogoutClientRepositoryPort, LogoutDependencyError, LogoutFuture, RegisteredLogoutClient,
};
use uuid::Uuid;

use super::base::OAuthClientRepository;
use super::mapping::string_array;

// Logout reads only its own policy and delivery facts; token/authentication
// metadata is neither an authority nor a prerequisite for ending a session.
#[derive(diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = oauth_clients)]
struct LogoutClientRecord {
    id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    is_active: bool,
    redirect_uris: serde_json::Value,
    post_logout_redirect_uris: serde_json::Value,
    backchannel_logout_uri: Option<String>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: bool,
    subject_type: String,
    sector_identifier_host: Option<String>,
}

impl LogoutClientRecord {
    fn into_domain(self) -> Result<RegisteredLogoutClient, LogoutDependencyError> {
        Ok(RegisteredLogoutClient {
            id: self.id,
            tenant_id: self.tenant_id,
            client_id: self.client_id,
            active: self.is_active,
            redirect_uris: string_array(self.redirect_uris, "redirect_uris")
                .map_err(|_| LogoutDependencyError::Unavailable)?,
            post_logout_redirect_uris: string_array(
                self.post_logout_redirect_uris,
                "post_logout_redirect_uris",
            )
            .map_err(|_| LogoutDependencyError::Unavailable)?,
            backchannel_logout_uri: self.backchannel_logout_uri,
            frontchannel_logout_uri: self.frontchannel_logout_uri,
            frontchannel_logout_session_required: self.frontchannel_logout_session_required,
            subject_type: self.subject_type,
            sector_identifier_host: self.sector_identifier_host,
        })
    }
}

impl LogoutClientRepositoryPort for OAuthClientRepository {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>> {
        Box::pin(async move {
            let mut connection = self
                .connection()
                .await
                .map_err(|_| LogoutDependencyError::Unavailable)?;
            let row = oauth_clients::table
                .filter(oauth_clients::tenant_id.eq(tenant_id))
                .filter(oauth_clients::client_id.eq(client_id))
                .select(LogoutClientRecord::as_select())
                .first::<LogoutClientRecord>(&mut connection)
                .await
                .optional()
                .map_err(|_| LogoutDependencyError::Unavailable)?;
            drop(connection);
            row.map(LogoutClientRecord::into_domain).transpose()
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
                .select(LogoutClientRecord::as_select())
                .load::<LogoutClientRecord>(&mut connection)
                .await
                .map_err(|_| LogoutDependencyError::Unavailable)?;
            drop(connection);
            rows.into_iter()
                .map(LogoutClientRecord::into_domain)
                .collect()
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/repositories/clients/logout.rs"]
mod tests;
