use nazo_auth::{
    AdminGrantFuture, AdminGrantPage, AdminGrantRepositoryPort, AdminGrantRevocation,
    AdminGrantRevokeError, AdminGrantRevokeFuture, AdminGrantView, AuthorizationPortError,
};
use nazo_identity::{
    TenantId,
    ports::{AuthorizedApplication, AuthorizedApplicationRepositoryPort, RepositoryFuture},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, timestamp},
};

const VIEW: &str = "SELECT g.user_id,u.email,c.client_id,json_extract(c.registration,'$.client_name') AS client_name,
    a.last_authorized_at,a.authorization_count,g.scopes,g.details
    FROM nazo_grants g JOIN nazo_users u ON u.tenant_id=g.tenant_id AND u.id=g.user_id
    JOIN nazo_clients c ON c.tenant_id=g.tenant_id AND c.id=g.client_id
    LEFT JOIN nazo_grant_activity a ON a.tenant_id=g.tenant_id AND a.user_id=g.user_id AND a.client_id=g.client_id";
#[derive(Deserialize)]
struct GrantView {
    user_id: Uuid,
    email: String,
    client_id: String,
    client_name: Option<String>,
    last_authorized_at: Option<i64>,
    authorization_count: Option<i32>,
    scopes: String,
    details: String,
}
impl GrantView {
    fn view(self) -> Result<AdminGrantView, DbError> {
        Ok(AdminGrantView {
            user_id: self.user_id,
            email: self.email,
            client_name: self.client_name.unwrap_or_else(|| self.client_id.clone()),
            client_id: self.client_id,
            last_authorized_at: timestamp(self.last_authorized_at.ok_or(DbError::CorruptData)?)?,
            authorization_count: self.authorization_count.ok_or(DbError::CorruptData)?,
            last_scopes: serde_json::from_str(&self.scopes).map_err(|_| DbError::CorruptData)?,
            last_authorization_details: serde_json::from_str(&self.details)
                .map_err(|_| DbError::CorruptData)?,
        })
    }
}
impl AuthorizedApplicationRepositoryPort for D1Provider {
    fn applications_for_user(
        &self,
        tenant: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.database.query::<GrantView>(&format!("{VIEW} WHERE g.tenant_id=?1 AND g.user_id=?2 ORDER BY a.last_authorized_at DESC,c.client_id"),vec![json!(self.tenant_id),json!(user_id)]).await?
                .into_iter().map(|row| {let row=row.view()?;Ok(AuthorizedApplication {client_id:row.client_id,client_name:row.client_name,last_scopes:json!(row.last_scopes),last_authorized_at:row.last_authorized_at,authorization_count:row.authorization_count})}).collect()
        })
    }
}
impl AdminGrantRepositoryPort for D1Provider {
    fn page(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AdminGrantFuture<'_, AdminGrantPage> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            let rows=self.database.batch(vec![
                Statement::new(format!("{VIEW} WHERE g.tenant_id=?1 ORDER BY a.last_authorized_at DESC,g.user_id,g.client_id LIMIT ?2 OFFSET ?3"),vec![json!(self.tenant_id),json!(limit.clamp(1,1000)),json!(offset.max(0))]),
                Statement::new("SELECT COUNT(*) AS total FROM nazo_grants WHERE tenant_id=?1",vec![json!(self.tenant_id)])]).await?;
            let grants = rows[0]
                .rows
                .iter()
                .cloned()
                .map(|row| {
                    serde_json::from_value::<GrantView>(row)
                        .map_err(|_| DbError::CorruptData)?
                        .view()
                })
                .collect::<Result<Vec<_>, DbError>>()?;
            let total = rows[1].rows[0]["total"]
                .as_i64()
                .ok_or(DbError::CorruptData)?;
            Ok(AdminGrantPage { total, grants })
        })
    }
    fn revoke_by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        client_id: &'a str,
        admin_user_id: Uuid,
    ) -> AdminGrantRevokeFuture<'a> {
        Box::pin(async move {
            let revoke = |error: DbError| AdminGrantRevokeError::Revoke(error.into());
            self.require_tenant(tenant_id).map_err(revoke)?;
            let event = Uuid::new_v4();
            let parameters = vec![
                json!(tenant_id),
                json!(user_id),
                json!(client_id),
                json!(admin_user_id),
                json!(event),
            ];
            let mut audit_parameters = parameters.clone();
            audit_parameters.push(json!(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION));
            let guard = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?5 AND event_type='admin_grant_revoked')";
            let mut result=self.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                    SELECT ?1,?5,'admin_grant_revoked','administration',{NOW},json_object(
                      'schema_version',?6,'event_category','administration','tenant_id',?1,'admin_user_id',?4,'actor_tenant_id',a.tenant_id,
                      'user_id',?2,'outcome','success','client_id',?3,
                      'revoked_refresh_tokens',(SELECT COUNT(*) FROM nazo_refresh_families WHERE tenant_id=?1 AND user_id=?2 AND client_id=c.id AND revoked_at IS NULL),
                      'removed_grants',(SELECT COUNT(*) FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND client_id=c.id))
                    FROM nazo_clients c JOIN nazo_users a ON a.tenant_id=?1 AND a.id=?4 AND a.active=1
                    WHERE c.tenant_id=?1 AND c.client_id=?3 AND json_extract(a.principal,'$.role.Admin.level')>0"),audit_parameters),
                Statement::new(format!("UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND user_id=?2 AND client_id=(SELECT id FROM nazo_clients WHERE tenant_id=?1 AND client_id=?3) AND revoked_at IS NULL AND {guard} RETURNING id"),parameters.clone()),
                Statement::new(format!("DELETE FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND client_id=(SELECT id FROM nazo_clients WHERE tenant_id=?1 AND client_id=?3) AND {guard} RETURNING client_id"),parameters.clone()),
                Statement::new(format!("UPDATE nazo_vci_access SET revoked_at=COALESCE(revoked_at,{NOW}) WHERE tenant_id=?1 AND subject_id=?2 AND client_id=?3 AND {guard}"),parameters.clone()),
                // Required audit and all revocations must describe one committed
                // result, including when a backend trigger ignores a mutation.
                Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?5) OR (
                    EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?5 AND event_type='admin_grant_revoked' AND category='administration'
                      AND json_extract(payload,'$.tenant_id')=?1 AND json_extract(payload,'$.admin_user_id')=?4
                      AND json_extract(payload,'$.user_id')=?2 AND json_extract(payload,'$.client_id')=?3 AND json_extract(payload,'$.outcome')='success')
                    AND NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND user_id=?2 AND client_id=(SELECT id FROM nazo_clients WHERE tenant_id=?1 AND client_id=?3) AND revoked_at IS NULL)
                    AND NOT EXISTS(SELECT 1 FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND client_id=(SELECT id FROM nazo_clients WHERE tenant_id=?1 AND client_id=?3))
                    AND NOT EXISTS(SELECT 1 FROM nazo_vci_access WHERE tenant_id=?1 AND subject_id=?2 AND client_id=?3 AND revoked_at IS NULL))
                    THEN 1 ELSE json_extract('grant revocation effects were not accepted','$') END",parameters.clone()),
                Statement::new("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?5) THEN 'committed'
                    WHEN NOT EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND client_id=?3) THEN 'client_missing' ELSE 'denied' END AS outcome",parameters),
            ]).await.map_err(revoke)?;
            let outcome = result
                .pop()
                .and_then(|row| row.rows.into_iter().next())
                .ok_or_else(|| revoke(DbError::CorruptData))?;
            match outcome["outcome"].as_str() {
                Some("client_missing") => Err(AdminGrantRevokeError::ClientNotFound),
                Some("committed") => Ok(AdminGrantRevocation {
                    revoked_refresh_tokens: result[1].rows.len(),
                    removed_grants: result[2].rows.len(),
                }),
                _ => Err(AdminGrantRevokeError::Revoke(
                    AuthorizationPortError::Unavailable,
                )),
            }
        })
    }
}
