use nazo_identity::{
    OrganizationId, RealmId, TenantBoundaryDefinition, TenantContext, TenantDirectoryBinding,
    TenantId, TenantProvisioningRequest,
};
use uuid::Uuid;

pub(crate) fn provisioning(host: &str) -> TenantProvisioningRequest {
    let tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
        realm_id: RealmId::new(Uuid::now_v7()).unwrap(),
        organization_id: OrganizationId::new(Uuid::now_v7()).unwrap(),
    };
    TenantProvisioningRequest {
        tenant: TenantBoundaryDefinition {
            id: tenant.tenant_id,
            slug: format!("tenant-{}", tenant.tenant_id.as_uuid()),
            display_name: "Tenant".into(),
        },
        realm: TenantBoundaryDefinition {
            id: tenant.realm_id,
            slug: "realm".into(),
            display_name: "Realm".into(),
        },
        organization: TenantBoundaryDefinition {
            id: tenant.organization_id,
            slug: "organization".into(),
            display_name: "Organization".into(),
        },
        binding: TenantDirectoryBinding {
            tenant,
            runtime_revision: 1,
            issuer: format!("https://{host}"),
            external_host: host.into(),
        },
    }
}
