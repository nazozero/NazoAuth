use crate::{rows::identity::PrincipalRow, schema::users};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_persistence::control_plane::AdminIdentityAudit;

pub(crate) async fn authorize_actor(
    connection: &mut AsyncPgConnection,
    audit: &AdminIdentityAudit,
) -> anyhow::Result<()> {
    let rows = users::table
        .filter(users::id.eq(audit.actor_user_id))
        .filter(users::tenant_id.eq(audit.tenant.tenant_id.as_uuid()))
        .filter(users::realm_id.eq(audit.tenant.realm_id.as_uuid()))
        .filter(users::organization_id.eq(audit.tenant.organization_id.as_uuid()))
        .select(PrincipalRow::as_select())
        .for_update()
        .load::<PrincipalRow>(connection)
        .await?;
    let current = rows
        .into_iter()
        .map(crate::convert::identity::principal_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!(error.0))?;
    if current
        .into_iter()
        .any(|principal| principal.active && principal.admin_level().is_some_and(|level| level > 0))
    {
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
    payload.extend(serde_json::json!({
        "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
        "event_category": "administration", "tenant_id": audit.tenant.tenant_id.as_uuid(),
        "realm_id": audit.tenant.realm_id.as_uuid(), "organization_id": audit.tenant.organization_id.as_uuid(),
        "actor_user_id": audit.actor_user_id, "source_ip_hash": audit.source_ip_hash, "outcome": "success"
    }).as_object().expect("fixed outcome object").clone());
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
