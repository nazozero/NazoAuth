//! Administrator-owned client mutations under D1 transaction authority.

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, encode, validate_client_capabilities},
};
use nazo_auth::{AdminClientPortError as Error, OAuthClient};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId, UserId};
use serde_json::json;
use uuid::Uuid;

fn context(client: &OAuthClient) -> Result<TenantContext, Error> {
    Ok(TenantContext {
        tenant_id: TenantId::new(client.tenant_id).map_err(|_| Error::CorruptData)?,
        realm_id: RealmId::new(client.realm_id).map_err(|_| Error::CorruptData)?,
        organization_id: OrganizationId::new(client.organization_id)
            .map_err(|_| Error::CorruptData)?,
    })
}

fn audit(client: &OAuthClient, actor: Uuid, source: &str) -> Result<String, DbError> {
    encode(&json!({
        "schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"client_lifecycle",
        "tenant_id":client.tenant_id,"realm_id":client.realm_id,"organization_id":client.organization_id,
        "admin_user_id":actor,"client_pk":client.id,"client_id":client.client_id,"client_type":client.client_type,
        "grant_types":client.grant_types,"token_endpoint_auth_method":client.token_endpoint_auth_method,
        "outcome":"success","source_ip_hash":source,
    }))
}

impl D1Provider {
    pub(super) async fn insert_admin_client(
        &self,
        client: &OAuthClient,
        secret: Option<&str>,
        registration_token: Option<&str>,
        actor: Uuid,
        source: &str,
    ) -> Result<OAuthClient, Error> {
        self.require_tenant(client.tenant_id)?;
        validate_client_capabilities(client).map_err(|_| Error::CorruptData)?;
        let snapshot = self
            .admin_actor_snapshot(
                context(client)?,
                UserId::new(actor).map_err(|_| Error::CorruptData)?,
            )
            .await?;
        let event = Uuid::new_v4();
        let payload = audit(client, actor, source)?;
        let registration = encode(&client.registration)?;
        let admitted = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2)";
        let mut statements=vec![
            Statement::new(format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                 SELECT ?1,?2,'client_created','client_lifecycle',{NOW},?3
                 WHERE EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?4 AND principal=?5 AND epoch=?6 AND active=?7)
                   AND NOT EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND (id=?8 OR client_id=?9))
                 UNION ALL SELECT ?1,?2,'duplicate','client_lifecycle',{NOW},'{{}}' WHERE EXISTS(SELECT 1 FROM nazo_audit WHERE event_id=?2)
                 RETURNING event_id"),
                vec![json!(self.tenant_id),json!(event),json!(payload),json!(actor),json!(snapshot.principal),json!(snapshot.epoch),json!(snapshot.active),json!(client.id),json!(client.client_id)]),
            Statement::new(format!(
                "INSERT INTO nazo_clients(tenant_id,id,client_id,realm_id,organization_id,registration,secret_digest,epoch,active,require_mtls_bound_tokens)
                 SELECT ?1,?3,?4,?5,?6,?7,?8,0,?9,?10 WHERE {admitted}"),
                vec![json!(self.tenant_id),json!(event),json!(client.id),json!(client.client_id),json!(client.realm_id),json!(client.organization_id),json!(registration),json!(secret),json!(client.is_active),json!(client.require_mtls_bound_tokens)]),
        ];
        if let Some(token) = registration_token {
            statements.push(Statement::new(format!("INSERT INTO nazo_client_registrations(tenant_id,client_id,token_hash) SELECT ?1,?3,?4 WHERE {admitted}"),vec![json!(self.tenant_id),json!(event),json!(client.id),json!(token)]));
        }
        statements.push(Statement::new(
            "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2) OR (
                EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type='client_created' AND category='client_lifecycle' AND payload=?12)
                AND EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?3 AND client_id=?4 AND realm_id=?5 AND organization_id=?6 AND registration=?7 AND secret_digest IS ?8 AND epoch=0 AND active=?9 AND require_mtls_bound_tokens=?10)
                AND (?11 IS NULL OR EXISTS(SELECT 1 FROM nazo_client_registrations WHERE tenant_id=?1 AND client_id=?3 AND token_hash=?11)))
                THEN 1 ELSE json('client creation effects were not accepted') END",
            vec![json!(self.tenant_id),json!(event),json!(client.id),json!(client.client_id),json!(client.realm_id),json!(client.organization_id),json!(registration),json!(secret),json!(client.is_active),json!(client.require_mtls_bound_tokens),json!(registration_token),json!(payload)],
        ));
        let result = self.database.batch(statements).await?;
        if result.first().ok_or(Error::CorruptData)?.rows.is_empty() {
            return Err(Error::Conflict);
        }
        Ok(client.clone())
    }

    pub(super) async fn update_admin_client(
        &self,
        expected: &OAuthClient,
        client: &OAuthClient,
        actor: Uuid,
        source: &str,
    ) -> Result<OAuthClient, Error> {
        self.require_tenant(client.tenant_id)?;
        if expected.id != client.id
            || expected.tenant_id != client.tenant_id
            || expected.realm_id != client.realm_id
            || expected.organization_id != client.organization_id
            || expected.client_id != client.client_id
        {
            return Err(Error::CorruptData);
        }
        validate_client_capabilities(client).map_err(|_| Error::CorruptData)?;
        let current = self
            .client_row(&expected.client_id)
            .await?
            .ok_or(Error::Conflict)?;
        let registration = current.registration.clone();
        let epoch = current.epoch;
        let active = current.active;
        let mtls = current.require_mtls_bound_tokens;
        if current.into_domain()? != *expected {
            return Err(Error::Conflict);
        }
        let snapshot = self
            .admin_actor_snapshot(
                context(client)?,
                UserId::new(actor).map_err(|_| Error::CorruptData)?,
            )
            .await?;
        let event = Uuid::new_v4();
        let payload = audit(client, actor, source)?;
        let replacement = encode(&client.registration)?;
        let deactivate = expected.is_active && !client.is_active;
        let downgrade = expected.client_type == "confidential" && client.client_type == "public";
        let admitted = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?3)";
        let effect = || vec![json!(self.tenant_id), json!(client.id), json!(event)];
        let mut statements=vec![Statement::new(format!(
            "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
             SELECT ?1,?2,'client_updated','client_lifecycle',{NOW},?3
             WHERE EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?4 AND principal=?5 AND epoch=?6 AND active=?7)
               AND EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?8 AND registration=?9 AND epoch=?10 AND active=?11 AND realm_id=?12 AND organization_id=?13 AND require_mtls_bound_tokens=?14)
             UNION ALL SELECT ?1,?2,'duplicate','client_lifecycle',{NOW},'{{}}' WHERE EXISTS(SELECT 1 FROM nazo_audit WHERE event_id=?2)
             RETURNING event_id"),
            vec![json!(self.tenant_id),json!(event),json!(payload),json!(actor),json!(snapshot.principal),json!(snapshot.epoch),json!(snapshot.active),json!(client.id),json!(registration),json!(epoch),json!(active),json!(client.realm_id),json!(client.organization_id),json!(mtls)])];
        if downgrade {
            statements.push(Statement::new(format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                 SELECT tenant_id,lower(hex(randomblob(16))),'refresh_family_security_revoked','token_lifecycle',{NOW},
                   json_object('schema_version','nazo.audit.v1','event_category','token_lifecycle','tenant_id',tenant_id,
                     'token_family_id',id,'client_id',client_id,'reason','client_authentication_class_downgrade','mutation_id',?3)
                 FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=?2 AND revoked_at IS NULL AND {admitted}"),effect()));
            statements.push(Statement::new(format!(
                "SELECT CASE WHEN NOT ({admitted}) OR NOT EXISTS(
                    SELECT 1 FROM nazo_refresh_families f WHERE f.tenant_id=?1 AND f.client_id=?2 AND f.revoked_at IS NULL
                    AND NOT EXISTS(SELECT 1 FROM nazo_audit a WHERE a.tenant_id=f.tenant_id AND a.event_type='refresh_family_security_revoked' AND a.category='token_lifecycle'
                        AND json_extract(a.payload,'$.mutation_id')=?3 AND json_extract(a.payload,'$.token_family_id')=f.id
                        AND json_extract(a.payload,'$.client_id')=f.client_id AND json_extract(a.payload,'$.reason')='client_authentication_class_downgrade'))
                    THEN 1 ELSE json('client refresh revocation audit was not accepted') END"),effect()));
        }
        if downgrade || deactivate {
            statements.push(Statement::new(format!("UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND client_id=?2 AND revoked_at IS NULL AND {admitted}"),effect()));
        }
        let mut update = effect();
        update.extend([
            json!(replacement),
            json!(client.is_active),
            json!(i64::from(deactivate)),
            json!(downgrade),
            json!(client.require_mtls_bound_tokens),
        ]);
        statements.push(Statement::new(format!(
            "UPDATE nazo_clients SET registration=?4,active=?5,epoch=epoch+?6,require_mtls_bound_tokens=?8,secret_digest=CASE WHEN ?7 THEN NULL ELSE secret_digest END
             WHERE tenant_id=?1 AND id=?2 AND {admitted}"),update));
        if deactivate {
            statements.push(Statement::new(
                format!(
                    "DELETE FROM nazo_grants WHERE tenant_id=?1 AND client_id=?2 AND {admitted}"
                ),
                effect(),
            ));
        }
        statements.push(Statement::new(
            "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?3) OR (
                EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?3 AND event_type='client_updated' AND category='client_lifecycle' AND payload=?11)
                AND EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?2 AND registration=?4 AND active=?5 AND epoch=?6 AND require_mtls_bound_tokens=?7 AND (?8=0 OR secret_digest IS NULL))
                AND (?9=0 OR NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=?2 AND revoked_at IS NULL))
                AND (?10=0 OR NOT EXISTS(SELECT 1 FROM nazo_grants WHERE tenant_id=?1 AND client_id=?2)))
                THEN 1 ELSE json('client update effects were not accepted') END",
            vec![json!(self.tenant_id),json!(client.id),json!(event),json!(replacement),json!(client.is_active),json!(epoch+i64::from(deactivate)),json!(client.require_mtls_bound_tokens),json!(downgrade),json!(downgrade||deactivate),json!(deactivate),json!(payload)],
        ));
        let result = self.database.batch(statements).await?;
        if result.first().ok_or(Error::CorruptData)?.rows.is_empty() {
            return Err(Error::Conflict);
        }
        Ok(client.clone())
    }
}
