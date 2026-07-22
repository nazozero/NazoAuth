use crate::domain::{ClientRow, DatabaseUserFixture};

use chrono::Utc;

use nazo_identity::PublicAccount;

use serde_json::json;

impl TenantContext {
    pub(crate) fn includes_user(&self, user: &PublicAccount) -> bool {
        self.as_identity_context().is_some_and(|context| {
            context.matches_raw(user.tenant_id(), user.realm_id(), user.organization_id())
        })
    }

    pub(crate) fn includes_client(&self, client: &ClientRow) -> bool {
        self.as_identity_context().is_some_and(|context| {
            context.matches_raw(client.tenant_id, client.realm_id, client.organization_id)
        })
    }

    pub(crate) fn same_tenant(&self, tenant_id: Uuid) -> bool {
        self.as_identity_context().is_some_and(|context| {
            nazo_identity::TenantId::new(tenant_id)
                .is_ok_and(|tenant_id| context.same_tenant(tenant_id))
        })
    }
}
