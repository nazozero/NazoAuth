//! Client access approvals with one D1 owner for credentials and Required audit.

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, UserRow, encode, timestamp, validate_client_capabilities},
};
use nazo_auth::{ApprovedClient, OAuthClient, PreparedClientRegistration};
use nazo_identity::{
    AccessRequest, AccessRequestPage, AccessRequestStatus, NewAccessRequest, TenantContext,
    TenantId, UserId,
    ports::{AccessRequestRepositoryPort, RepositoryError, RepositoryFuture},
};
use nazo_persistence::{AdminAccessRequestApproval, AdminAccessRequestStore};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

const FIELDS: &str = "r.id,r.tenant_id,r.user_id,r.site_name,r.site_url,r.request_description,r.status,r.admin_note,r.approved_client_id,r.created_at,r.resolved_at";
const VIEW: &str =
    "FROM nazo_access_requests r JOIN nazo_users u ON u.tenant_id=r.tenant_id AND u.id=r.user_id";
const AUTHORITY: &str = "EXISTS(SELECT 1 FROM nazo_access_requests WHERE tenant_id=?1 AND id=?2 AND user_id=?3 AND status=0)
    AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?4 AND principal=?5 AND epoch=?6 AND active=?7)
    AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?3 AND principal=?8 AND epoch=?9 AND active=?10)";
const ADMITTED: &str = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2)";

#[derive(Deserialize)]
struct Row {
    id: Uuid,
    tenant_id: TenantId,
    user_id: UserId,
    requester_email: Option<String>,
    site_name: String,
    site_url: String,
    request_description: String,
    status: i16,
    admin_note: Option<String>,
    approved_client_id: Option<Uuid>,
    created_at: i64,
    resolved_at: Option<i64>,
}

impl Row {
    fn public(self) -> Result<AccessRequest, RepositoryError> {
        Ok(AccessRequest {
            id: self.id,
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            requester_email: self.requester_email,
            site_name: self.site_name,
            site_url: self.site_url,
            request_description: self.request_description,
            status: AccessRequestStatus::from_code(self.status).ok_or(DbError::CorruptData)?,
            admin_note: self.admin_note,
            approved_client_id: self.approved_client_id,
            created_at: timestamp(self.created_at)?,
            resolved_at: self.resolved_at.map(timestamp).transpose()?,
        })
    }
}

struct Decision {
    request: AccessRequest,
    actor_id: UserId,
    actor: UserRow,
    requester: UserRow,
}

impl Decision {
    fn parameters(&self) -> Vec<Value> {
        vec![
            json!(self.request.tenant_id),
            json!(self.request.id),
            json!(self.request.user_id),
            json!(self.actor_id),
            json!(self.actor.principal),
            json!(self.actor.epoch),
            json!(self.actor.active),
            json!(self.requester.principal),
            json!(self.requester.epoch),
            json!(self.requester.active),
        ]
    }
}

impl D1Provider {
    async fn access_request(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> Result<Option<AccessRequest>, RepositoryError> {
        self.require_tenant(tenant.as_uuid())?;
        self.database.query::<Row>(
            &format!("SELECT {FIELDS},u.email AS requester_email {VIEW} WHERE r.tenant_id=?1 AND r.id=?2"),
            vec![json!(tenant),json!(id)],
        ).await?.into_iter().next().map(Row::public).transpose()
    }

    async fn access_decision(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: UserId,
        approve: bool,
    ) -> Result<Decision, RepositoryError> {
        let request = self
            .access_request(tenant.tenant_id, id)
            .await?
            .filter(|request| request.status == AccessRequestStatus::Pending)
            .ok_or(if approve {
                RepositoryError::AlreadyProcessed
            } else {
                RepositoryError::Conflict
            })?;
        let actor_row = self.admin_actor_snapshot(tenant, actor).await?;
        let requester = self
            .user_row(request.user_id.as_uuid())
            .await?
            .ok_or(DbError::CorruptData)?;
        let principal = requester.principal(tenant.tenant_id, request.user_id)?;
        if principal.tenant != tenant || (approve && !principal.active) {
            return Err(RepositoryError::Consistency(
                "access request owner is outside the accepting authority".into(),
            ));
        }
        Ok(Decision {
            request,
            actor_id: actor,
            actor: actor_row,
            requester,
        })
    }

    async fn access_delivery_matches(
        &self,
        owner: (TenantId, UserId),
        request: Uuid,
        approved: Uuid,
        client: &str,
        secret: Option<&str>,
    ) -> Result<bool, RepositoryError> {
        let (tenant, user) = owner;
        self.require_tenant(tenant.as_uuid())?;
        #[derive(Deserialize)]
        struct Match {
            matched: i64,
        }
        Ok(self.database.query::<Match>(
            "SELECT EXISTS(SELECT 1 FROM nazo_access_requests r JOIN nazo_clients c ON c.tenant_id=r.tenant_id AND c.id=r.approved_client_id
             WHERE r.tenant_id=?1 AND r.user_id=?2 AND r.id=?3 AND r.status=1 AND r.required_approval_event_id IS NOT NULL
             AND c.id=?4 AND c.client_id=?5 AND c.active=1 AND c.secret_digest IS ?6) AS matched",
            vec![json!(tenant),json!(user),json!(request),json!(approved),json!(client),json!(secret)],
        ).await?.into_iter().next().ok_or(DbError::CorruptData)?.matched!=0)
    }
}

impl AccessRequestRepositoryPort for D1Provider {
    fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Vec<AccessRequest>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.database.query::<Row>(&format!("SELECT {FIELDS},NULL AS requester_email FROM nazo_access_requests r WHERE r.tenant_id=?1 AND r.user_id=?2 ORDER BY r.created_at DESC,r.id DESC"),vec![json!(tenant),json!(user)]).await?.into_iter().map(Row::public).collect()
        })
    }

    fn create(&self, request: NewAccessRequest) -> RepositoryFuture<'_, AccessRequest> {
        Box::pin(async move {
            self.require_tenant(request.tenant_id.as_uuid())?;
            let id = Uuid::new_v4();
            let mut result=self.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_access_requests(tenant_id,id,user_id,site_name,site_url,request_description,status,created_at)
                    SELECT ?1,?2,?3,?4,?5,?6,0,{NOW} WHERE EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?3)"),
                    vec![json!(request.tenant_id),json!(id),json!(request.user_id),json!(request.site_name),json!(request.site_url),json!(request.request_description)]),
                Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?3)
                    OR EXISTS(SELECT 1 FROM nazo_access_requests WHERE tenant_id=?1 AND id=?2 AND user_id=?3 AND site_name=?4 AND site_url=?5 AND request_description=?6 AND status=0)
                    THEN 1 ELSE json_extract('access request insert was not accepted','$') END",
                    vec![json!(request.tenant_id),json!(id),json!(request.user_id),json!(request.site_name),json!(request.site_url),json!(request.request_description)]),
                Statement::new(format!("SELECT {FIELDS},NULL AS requester_email FROM nazo_access_requests r WHERE r.tenant_id=?1 AND r.id=?2"),vec![json!(request.tenant_id),json!(id)]),
            ]).await?;
            let row = result
                .pop()
                .and_then(|mut outcome| outcome.rows.pop())
                .ok_or(RepositoryError::NotFound)?;
            serde_json::from_value::<Row>(row)
                .map_err(|_| DbError::CorruptData)?
                .public()
        })
    }

    fn approved_delivery_with_required_audit_matches<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        request: Uuid,
        approved: Uuid,
        client: &'a str,
        secret: Option<&'a str>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.access_delivery_matches((tenant, user), request, approved, client, secret))
    }
}

impl AdminAccessRequestStore for D1Provider {
    fn approved_delivery_with_required_audit_matches<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        request: Uuid,
        approved: Uuid,
        client: &'a str,
        secret: Option<&'a str>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(self.access_delivery_matches((tenant, user), request, approved, client, secret))
    }

    fn approve_with_required_audit<'a>(
        &'a self,
        tenant: TenantContext,
        id: Uuid,
        actor: UserId,
        prepared: &'a PreparedClientRegistration,
        source: String,
    ) -> RepositoryFuture<'a, AdminAccessRequestApproval> {
        Box::pin(async move {
            if prepared.tenant != tenant {
                return Err(RepositoryError::Consistency(
                    "prepared client tenant does not match the approval".into(),
                ));
            }
            let decision = self.access_decision(tenant, id, actor, true).await?;
            let client = OAuthClient {
                id: Uuid::new_v4(),
                tenant_id: tenant.tenant_id.as_uuid(),
                realm_id: tenant.realm_id.as_uuid(),
                organization_id: tenant.organization_id.as_uuid(),
                registration: prepared.registration.clone(),
                require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
                is_active: true,
            };
            validate_client_capabilities(&client).map_err(|_| DbError::CorruptData)?;
            let event = Uuid::new_v4();
            let payload = encode(
                &json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"client_lifecycle","tenant_id":tenant.tenant_id,"request_id":id,"request_user_id":decision.request.user_id,"admin_user_id":actor,"approved_client_id":client.id,"client_id":client.client_id,"outcome":"success","source_ip_hash":source}),
            )?;
            let mut admission = decision.parameters();
            admission.extend([
                json!(client.id),
                json!(client.client_id),
                json!(event),
                json!(payload),
            ]);
            let eligible = format!(
                "{AUTHORITY} AND NOT EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND (id=?11 OR client_id=?12))"
            );
            let mut statements=vec![
                Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                    SELECT ?1,?13,'client_created','client_lifecycle',{NOW},?14 WHERE {eligible}"),admission.clone()),
                // Verify the accepting event before any related mutation. An
                // ignored Required write cannot masquerade as a lost CAS.
                Statement::new(format!("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?13 AND event_type='client_created' AND category='client_lifecycle' AND payload=?14)
                    OR (NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_id=?13) AND NOT ({eligible}))
                    THEN 1 ELSE json_extract('access approval audit was not accepted','$') END"),admission),
                Statement::new(format!("INSERT INTO nazo_clients(tenant_id,id,client_id,realm_id,organization_id,registration,secret_digest,epoch,active,require_mtls_bound_tokens)
                    SELECT ?1,?3,?4,?5,?6,?7,?8,0,1,?9 WHERE {ADMITTED}"),vec![json!(tenant.tenant_id),json!(event),json!(client.id),json!(client.client_id),json!(client.realm_id),json!(client.organization_id),json!(encode(&client.registration)?),json!(prepared.client_secret_hash),json!(client.require_mtls_bound_tokens)]),
            ];
            if let Some(token) = &prepared.registration_access_token_blake3 {
                statements.push(Statement::new(format!("INSERT INTO nazo_client_registrations(tenant_id,client_id,token_hash) SELECT ?1,?3,?4 WHERE {ADMITTED}"),vec![json!(tenant.tenant_id),json!(event),json!(client.id),json!(token)]));
            }
            statements.push(Statement::new(format!("UPDATE nazo_access_requests SET status=1,resolved_by_user_id=?4,approved_client_id=?5,required_approval_event_id=?2,decision_event_id=?2,resolved_at={NOW}
                WHERE tenant_id=?1 AND id=?3 AND status=0 AND {ADMITTED}"),vec![json!(tenant.tenant_id),json!(event),json!(id),json!(actor),json!(client.id)]));
            let request = &decision.request;
            statements.push(Statement::new(format!("SELECT CASE WHEN NOT ({ADMITTED}) OR (
                EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?3 AND client_id=?4 AND realm_id=?5 AND organization_id=?6 AND registration=?7 AND secret_digest IS ?8 AND require_mtls_bound_tokens=?9 AND active=1 AND epoch=0)
                AND EXISTS(SELECT 1 FROM nazo_access_requests WHERE tenant_id=?1 AND id=?10 AND user_id=?11 AND status=1 AND resolved_by_user_id=?12 AND approved_client_id=?3 AND required_approval_event_id=?2 AND decision_event_id=?2 AND resolved_at IS NOT NULL AND site_name=?13 AND site_url=?14 AND request_description=?15 AND created_at=?16 AND admin_note IS ?18)
                AND ((?17 IS NULL AND NOT EXISTS(SELECT 1 FROM nazo_client_registrations WHERE tenant_id=?1 AND client_id=?3)) OR EXISTS(SELECT 1 FROM nazo_client_registrations WHERE tenant_id=?1 AND client_id=?3 AND token_hash=?17)))
                THEN 1 ELSE json_extract('access approval effects were not accepted','$') END"),
                vec![json!(tenant.tenant_id),json!(event),json!(client.id),json!(client.client_id),json!(client.realm_id),json!(client.organization_id),json!(encode(&client.registration)?),json!(prepared.client_secret_hash),json!(client.require_mtls_bound_tokens),json!(id),json!(request.user_id),json!(actor),json!(request.site_name),json!(request.site_url),json!(request.request_description),json!(request.created_at.as_microsecond()),json!(prepared.registration_access_token_blake3),json!(request.admin_note)]));
            statements.push(Statement::new(format!("SELECT {FIELDS},u.email AS requester_email {VIEW} WHERE r.tenant_id=?1 AND r.id=?2 AND r.decision_event_id=?3"),vec![json!(tenant.tenant_id),json!(id),json!(event)]));
            statements.push(Statement::new("SELECT EXISTS(SELECT 1 FROM nazo_access_requests WHERE tenant_id=?1 AND id=?2 AND status=0) AS pending,EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND client_id=?3) AS duplicate",vec![json!(tenant.tenant_id),json!(id),json!(client.client_id)]));
            let mut result = self.database.batch(statements).await?;
            let state = result
                .pop()
                .and_then(|mut r| r.rows.pop())
                .ok_or(DbError::CorruptData)?;
            let row = result.pop().and_then(|mut r| r.rows.pop());
            match row {
                Some(row) => Ok(AdminAccessRequestApproval {
                    client: ApprovedClient {
                        id: client.id,
                        client_id: client.client_id.clone(),
                    },
                    request: serde_json::from_value::<Row>(row)
                        .map_err(|_| DbError::CorruptData)?
                        .public()?,
                }),
                None if state["pending"] == 0 => Err(RepositoryError::AlreadyProcessed),
                None if state["duplicate"] == 1 => Err(RepositoryError::Conflict),
                None => Err(RepositoryError::Consistency(
                    "approval authority changed before acceptance".into(),
                )),
            }
        })
    }

    fn reject_with_required_audit(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: UserId,
        note: String,
    ) -> RepositoryFuture<'_, AccessRequest> {
        Box::pin(async move {
            let decision = self.access_decision(tenant, id, actor, false).await?;
            let event = Uuid::new_v4();
            let payload = encode(
                &json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"administration","tenant_id":tenant.tenant_id,"request_id":id,"request_user_id":decision.request.user_id,"admin_user_id":actor,"outcome":"success"}),
            )?;
            let mut parameters = decision.parameters();
            parameters.extend([json!(event), json!(payload)]);
            let request = &decision.request;
            let mut result=self.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?11,'admin_access_request_rejected','administration',{NOW},?12 WHERE {AUTHORITY}"),parameters.clone()),
                Statement::new(format!("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?11 AND event_type='admin_access_request_rejected' AND category='administration' AND payload=?12)
                    OR (NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_id=?11) AND NOT ({AUTHORITY})) THEN 1 ELSE json_extract('access rejection audit was not accepted','$') END"),parameters),
                Statement::new(format!("UPDATE nazo_access_requests SET status=2,admin_note=?5,resolved_by_user_id=?4,resolved_at={NOW},decision_event_id=?2 WHERE tenant_id=?1 AND id=?3 AND status=0 AND {ADMITTED}"),vec![json!(tenant.tenant_id),json!(event),json!(id),json!(actor),json!(note)]),
                Statement::new(format!("SELECT CASE WHEN NOT ({ADMITTED}) OR EXISTS(SELECT 1 FROM nazo_access_requests WHERE tenant_id=?1 AND id=?3 AND user_id=?4 AND status=2 AND admin_note=?5 AND resolved_by_user_id=?6 AND resolved_at IS NOT NULL AND decision_event_id=?2 AND approved_client_id IS NULL AND required_approval_event_id IS NULL AND site_name=?7 AND site_url=?8 AND request_description=?9 AND created_at=?10)
                    THEN 1 ELSE json_extract('access rejection effects were not accepted','$') END"),vec![json!(tenant.tenant_id),json!(event),json!(id),json!(request.user_id),json!(note),json!(actor),json!(request.site_name),json!(request.site_url),json!(request.request_description),json!(request.created_at.as_microsecond())]),
                Statement::new(format!("SELECT {FIELDS},u.email AS requester_email {VIEW} WHERE r.tenant_id=?1 AND r.id=?2 AND r.decision_event_id=?3"),vec![json!(tenant.tenant_id),json!(id),json!(event)]),
            ]).await?;
            result
                .pop()
                .and_then(|mut r| r.rows.pop())
                .map(|row| {
                    serde_json::from_value::<Row>(row)
                        .map_err(|_| DbError::CorruptData)
                        .map_err(RepositoryError::from)
                        .and_then(Row::public)
                })
                .transpose()?
                .ok_or(RepositoryError::Conflict)
        })
    }

    fn page<'a>(
        &'a self,
        tenant: TenantId,
        limit: i64,
        offset: i64,
        search: Option<&'a str>,
        status: Option<AccessRequestStatus>,
    ) -> RepositoryFuture<'a, AccessRequestPage> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            if limit < 0 || offset < 0 {
                return Err(DbError::CorruptData.into());
            }
            let predicate = "r.tenant_id=?1 AND (?2 IS NULL OR r.status=?2) AND (?3 IS NULL OR instr(lower(u.email),lower(?3))>0 OR instr(lower(r.site_name),lower(?3))>0 OR instr(lower(r.site_url),lower(?3))>0)";
            let parameters = vec![
                json!(tenant),
                json!(status.map(AccessRequestStatus::code)),
                json!(search),
            ];
            let mut page = parameters.clone();
            page.extend([json!(limit), json!(offset)]);
            let mut result=self.database.batch(vec![
                Statement::new(format!("SELECT count(*) AS total {VIEW} WHERE {predicate}"),parameters),
                Statement::new(format!("SELECT {FIELDS},u.email AS requester_email {VIEW} WHERE {predicate} ORDER BY r.created_at DESC,r.id DESC LIMIT ?4 OFFSET ?5"),page),
            ]).await?;
            let items = result
                .pop()
                .ok_or(DbError::CorruptData)?
                .rows
                .into_iter()
                .map(|row| {
                    serde_json::from_value::<Row>(row)
                        .map_err(|_| DbError::CorruptData)
                        .map_err(RepositoryError::from)
                        .and_then(Row::public)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let total = result
                .pop()
                .and_then(|mut r| r.rows.pop())
                .and_then(|r| r["total"].as_i64())
                .ok_or(DbError::CorruptData)?;
            Ok(AccessRequestPage { total, items })
        })
    }

    fn by_id(&self, tenant: TenantId, id: Uuid) -> RepositoryFuture<'_, Option<AccessRequest>> {
        Box::pin(self.access_request(tenant, id))
    }
}
