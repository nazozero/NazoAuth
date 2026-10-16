use crate::schema::users;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_persistence::control_plane::AdminIdentityAudit;

pub(crate) async fn authorize_actor(
    connection: &mut AsyncPgConnection,
    audit: &AdminIdentityAudit,
) -> anyhow::Result<()> {
    let current = users::table
        .filter(users::id.eq(audit.actor_user_id))
        .filter(users::tenant_id.eq(audit.tenant.tenant_id.as_uuid()))
        .filter(users::realm_id.eq(audit.tenant.realm_id.as_uuid()))
        .filter(users::organization_id.eq(audit.tenant.organization_id.as_uuid()))
        .filter(users::is_active.eq(true))
        .filter(users::role.eq("admin"))
        .filter(users::admin_level.gt(0))
        .select(users::id)
        .for_update()
        .first::<uuid::Uuid>(connection)
        .await
        .optional()?;
    if current.is_some() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "admin identity actor is no longer authorized in the current context"
        ))
    }
}

pub(crate) async fn append_outcome(
    connection: &mut AsyncPgConnection,
    event_type: &str,
    audit: &AdminIdentityAudit,
    mut fields: serde_json::Value,
) -> anyhow::Result<()> {
    let payload = fields
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("identity outcome fields must be an object"))?;
    payload.extend([
        (
            "schema_version".to_owned(),
            serde_json::json!(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION),
        ),
        (
            "event_category".to_owned(),
            serde_json::json!("administration"),
        ),
        (
            "tenant_id".to_owned(),
            serde_json::json!(audit.tenant.tenant_id.as_uuid()),
        ),
        (
            "realm_id".to_owned(),
            serde_json::json!(audit.tenant.realm_id.as_uuid()),
        ),
        (
            "organization_id".to_owned(),
            serde_json::json!(audit.tenant.organization_id.as_uuid()),
        ),
        (
            "actor_user_id".to_owned(),
            serde_json::json!(audit.actor_user_id),
        ),
        (
            "source_ip_hash".to_owned(),
            serde_json::json!(audit.source_ip_hash),
        ),
        ("outcome".to_owned(), serde_json::json!("success")),
    ]);
    let event = nazo_persistence::SecurityAuditEvent {
        event_id: uuid::Uuid::now_v7(),
        event_type: event_type.to_owned(),
        event_category: "administration".to_owned(),
        payload: fields,
        occurred_at: chrono::Utc::now(),
    };
    crate::repositories::audit_ledger::append_fresh_security_audit_on_connection(
        connection, &event,
    )
    .await?;
    Ok(())
}

pub(super) async fn append_slot(
    connection: &mut AsyncPgConnection,
    event_type: &str,
    audit: &AdminIdentityAudit,
    slot: &super::StoredControllerSlot,
) -> anyhow::Result<()> {
    append_outcome(
        connection,
        event_type,
        audit,
        serde_json::json!({
            "deployment_id":slot.deployment_id,"controller_id":slot.controller_id,"kid":slot.kid,
            "slot_index":slot.slot_index,"expires_at":slot.expires_at.to_rfc3339(),
        }),
    )
    .await
}
