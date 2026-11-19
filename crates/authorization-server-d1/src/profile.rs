//! Account overview reads share the authorization grant owner.

use nazo_identity::{
    TenantId,
    ports::{GrantSummaryRepositoryPort, RepositoryFuture},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{D1Provider, db::DbError};

impl GrantSummaryRepositoryPort for D1Provider {
    fn authorized_client_count(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            #[derive(Deserialize)]
            struct Count {
                count: i64,
            }
            Ok(self
                .database
                .query::<Count>(
                    "SELECT COUNT(*) AS count FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2",
                    vec![json!(self.tenant_id), json!(user_id)],
                )
                .await?
                .pop()
                .ok_or(DbError::CorruptData)?
                .count)
        })
    }
}
