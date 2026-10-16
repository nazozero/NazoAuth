//! An admin actor in each isolated identity fixture schema.
use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};
use nazo_identity::TenantContext;
use nazo_persistence::control_plane::AdminIdentityAudit;
use uuid::Uuid;

pub fn audit() -> AdminIdentityAudit {
    AdminIdentityAudit {
        tenant: TenantContext::default_system(),
        actor_user_id: Uuid::from_u128(1),
        source_ip_hash: "fixture-source".to_owned(),
    }
}

pub async fn seed_actor(url: &str) {
    let audit = audit();
    let mut connection = AsyncPgConnection::establish(url).await.unwrap();
    sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash, role, admin_level) VALUES ($1,$2,$3,$4,'identity-admin','identity-admin@example.test','unused-test-hash','admin',10)")
        .bind::<SqlUuid, _>(audit.actor_user_id)
        .bind::<SqlUuid, _>(audit.tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(audit.tenant.realm_id.as_uuid())
        .bind::<SqlUuid, _>(audit.tenant.organization_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
}
