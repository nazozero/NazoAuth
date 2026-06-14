use super::prelude::*;

pub(crate) const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);
pub(crate) const DEFAULT_REALM_ID: Uuid = Uuid::from_u128(2);
pub(crate) const DEFAULT_ORGANIZATION_ID: Uuid = Uuid::from_u128(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TenantContext {
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
}

impl Default for TenantContext {
    fn default() -> Self {
        Self {
            tenant_id: DEFAULT_TENANT_ID,
            realm_id: DEFAULT_REALM_ID,
            organization_id: DEFAULT_ORGANIZATION_ID,
        }
    }
}

impl TenantContext {
    pub(crate) fn includes_user(&self, user: &UserRow) -> bool {
        user.tenant_id == self.tenant_id
            && user.realm_id == self.realm_id
            && user.organization_id == self.organization_id
    }

    pub(crate) fn includes_client(&self, client: &ClientRow) -> bool {
        client.tenant_id == self.tenant_id
            && client.realm_id == self.realm_id
            && client.organization_id == self.organization_id
    }

    pub(crate) fn same_tenant(&self, tenant_id: Uuid) -> bool {
        tenant_id == self.tenant_id
    }
}

pub(crate) fn default_tenant_context() -> TenantContext {
    TenantContext::default()
}

#[cfg(test)]
mod tests;
