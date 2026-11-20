//! Tenant-owned mTLS trust requests with atomic two-person review and audit.

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, timestamp},
};
use nazo_identity::{
    MtlsTrustAnchorRequest, MtlsTrustAnchorRequestPage, MtlsTrustAnchorStatus,
    NewMtlsTrustAnchorRequest, TenantId, UserId,
    ports::{MtlsTrustAnchorStore, RepositoryError, RepositoryFuture},
};
use nazo_persistence::SecurityAuditEvent;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

// Long-lived CA validity can exceed JavaScript's exact integer range in
// microseconds. Keep the INTEGER in SQLite and transport its decimal text.
const PROJECTION: &str = "r.id,r.tenant_id,r.user_id,u.email AS requester_email,c.client_id,r.certificate_pem,r.certificate_sha256,r.subject_dn,CAST(r.not_before AS TEXT) AS not_before,CAST(r.not_after AS TEXT) AS not_after,r.status,r.admin_note,r.created_at,r.resolved_at,r.revoked_at";
const JOINS: &str = "FROM nazo_mtls_trust_requests r JOIN nazo_users u ON u.tenant_id=r.tenant_id AND u.id=r.user_id JOIN nazo_clients c ON c.tenant_id=r.tenant_id AND c.id=r.client_id";

#[derive(Deserialize)]
struct RequestRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    requester_email: Option<String>,
    client_id: String,
    certificate_pem: String,
    certificate_sha256: String,
    subject_dn: String,
    not_before: String,
    not_after: String,
    status: i16,
    admin_note: Option<String>,
    created_at: i64,
    resolved_at: Option<i64>,
    revoked_at: Option<i64>,
}

struct TrustMutation<'a> {
    id: Uuid,
    version: Uuid,
    source_event_id: Uuid,
    actor: UserId,
    action: i16,
    note: Option<&'a str>,
    audit: &'a SecurityAuditEvent,
}

impl RequestRow {
    fn domain(self) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
        Ok(MtlsTrustAnchorRequest {
            id: self.id,
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            requester_email: self.requester_email,
            client_id: self.client_id,
            certificate_pem: self.certificate_pem,
            certificate_sha256: self.certificate_sha256,
            subject_dn: self.subject_dn,
            not_before: timestamp(self.not_before.parse().map_err(|_| DbError::CorruptData)?)?,
            not_after: timestamp(self.not_after.parse().map_err(|_| DbError::CorruptData)?)?,
            status: self.status,
            admin_note: self.admin_note,
            created_at: timestamp(self.created_at)?,
            resolved_at: self.resolved_at.map(timestamp).transpose()?,
            revoked_at: self.revoked_at.map(timestamp).transpose()?,
        })
    }
}

fn projection(value: Value) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
    serde_json::from_value::<RequestRow>(value)
        .map_err(|_| DbError::CorruptData)?
        .domain()
}

impl D1Provider {
    fn trust_source_event(&self, mutation: &TrustMutation<'_>) -> Statement {
        Statement::new(
            "INSERT INTO nazo_mtls_trust_events(tenant_id,id,request_id,actor_user_id,action,note,created_at) SELECT tenant_id,?7,id,?4,?5,?6,updated_at FROM nazo_mtls_trust_requests WHERE tenant_id=?1 AND id=?2 AND version=?3",
            vec![
                json!(self.tenant_id),
                json!(mutation.id),
                json!(mutation.version),
                json!(mutation.actor),
                json!(mutation.action),
                json!(mutation.note),
                json!(mutation.source_event_id),
            ],
        )
    }

    fn trust_required_audit(
        &self,
        event: &SecurityAuditEvent,
        id: Uuid,
        version: Uuid,
    ) -> Result<Statement, RepositoryError> {
        let mut params = self.audit_statement(event)?.params.to_vec();
        params.extend([json!(id), json!(version)]);
        Ok(Statement::new(
            "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM nazo_mtls_trust_requests WHERE tenant_id=?1 AND id=?7 AND version=?8)",
            params,
        ))
    }

    fn trust_projection(&self, id: Uuid, version: Uuid) -> Statement {
        Statement::new(
            format!(
                "SELECT {PROJECTION} {JOINS} WHERE r.tenant_id=?1 AND r.id=?2 AND r.version=?3"
            ),
            vec![json!(self.tenant_id), json!(id), json!(version)],
        )
    }

    fn trust_effect_guard(
        &self,
        mutation: &TrustMutation<'_>,
    ) -> Result<Statement, RepositoryError> {
        let mut params = self.audit_statement(mutation.audit)?.params.to_vec();
        params.extend([
            json!(mutation.id),
            json!(mutation.version),
            json!(mutation.source_event_id),
            json!(mutation.actor),
            json!(mutation.action),
            json!(mutation.note),
        ]);
        // A successful SQL statement can still have no effect (RAISE(IGNORE)).
        // Prove both Required records and the accepted state before the D1
        // batch commits; a post-commit projection alone cannot prove this.
        Ok(Statement::new(
            "SELECT CASE WHEN
                (NOT EXISTS(SELECT 1 FROM nazo_mtls_trust_requests WHERE tenant_id=?1 AND id=?7 AND version=?8)
                    AND NOT EXISTS(SELECT 1 FROM nazo_mtls_trust_events WHERE tenant_id=?1 AND id=?9)
                    AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2))
                OR (EXISTS(SELECT 1 FROM nazo_mtls_trust_requests r WHERE r.tenant_id=?1 AND r.id=?7 AND r.version=?8
                        AND r.status=?11 AND r.admin_note IS ?12 AND r.source='admin-session'
                        AND ((?11=0 AND r.user_id=?10 AND r.created_at=r.updated_at AND r.resolved_by_user_id IS NULL AND r.resolved_at IS NULL AND r.revoked_by_user_id IS NULL AND r.revoked_at IS NULL)
                            OR (?11 IN (1,2) AND r.resolved_by_user_id=?10 AND r.resolved_at=r.updated_at AND r.revoked_by_user_id IS NULL AND r.revoked_at IS NULL)
                            OR (?11=3 AND r.revoked_by_user_id=?10 AND r.revoked_at=r.updated_at))
                        AND EXISTS(SELECT 1 FROM nazo_mtls_trust_events e WHERE e.tenant_id=?1 AND e.id=?9 AND e.request_id=?7 AND e.actor_user_id=?10 AND e.action=?11 AND e.note IS ?12 AND e.created_at=r.updated_at))
                    AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type=?3 AND category=?4 AND occurred_at=?5 AND payload=?6))
                THEN 1 ELSE json('mTLS trust atomicity failure') END AS checked",
            params,
        ))
    }

    async fn mutate_trust(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        status: MtlsTrustAnchorStatus,
        note: Option<String>,
    ) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
        self.require_tenant(tenant.as_uuid())?;
        if note
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 1000)
        {
            return Err(RepositoryError::Conflict);
        }
        let snapshot = self
            .user_row(actor.as_uuid())
            .await?
            .ok_or(RepositoryError::Conflict)?;
        let principal = snapshot.principal(tenant, actor)?;
        if !principal.active || !principal.admin_level().is_some_and(|level| level > 0) {
            return Err(RepositoryError::Conflict);
        }
        let version = Uuid::new_v4();
        let params = vec![
            json!(self.tenant_id),
            json!(id),
            json!(actor),
            json!(status.code()),
            json!(note),
            json!(version),
            json!(snapshot.principal),
            json!(snapshot.epoch),
        ];
        let authority = "EXISTS(SELECT 1 FROM nazo_users a WHERE a.tenant_id=?1 AND a.id=?3 AND a.active=1 AND a.principal=?7 AND a.epoch=?8)";
        let update = if status == MtlsTrustAnchorStatus::Revoked {
            format!(
                "UPDATE nazo_mtls_trust_requests SET status=3,admin_note=?5,revoked_by_user_id=?3,revoked_at={NOW},updated_at={NOW},version=?6 WHERE tenant_id=?1 AND id=?2 AND status=1 AND source='admin-session' AND {authority} AND ?4=3"
            )
        } else {
            format!("UPDATE nazo_mtls_trust_requests SET status=?4,admin_note=?5,resolved_by_user_id=?3,resolved_at={NOW},updated_at={NOW},version=?6 WHERE tenant_id=?1 AND id=?2 AND status=0 AND user_id<>?3 AND source='admin-session' AND {authority}
                AND (?4<>1 OR (not_before<={NOW} AND not_after>{NOW}
                    AND EXISTS(SELECT 1 FROM nazo_clients c WHERE c.tenant_id=?1 AND c.id=nazo_mtls_trust_requests.client_id AND c.active=1)
                    AND (EXISTS(SELECT 1 FROM nazo_mtls_trust_requests existing WHERE existing.tenant_id=?1 AND existing.status=1 AND existing.not_before<={NOW} AND existing.not_after>{NOW} AND existing.certificate_sha256=nazo_mtls_trust_requests.certificate_sha256)
                        OR (SELECT count(DISTINCT active.certificate_sha256) FROM nazo_mtls_trust_requests active JOIN nazo_clients c ON c.tenant_id=active.tenant_id AND c.id=active.client_id WHERE active.tenant_id=?1 AND active.status=1 AND active.not_before<={NOW} AND active.not_after>{NOW} AND c.active=1)<128)
                    AND (SELECT count(*) FROM nazo_mtls_trust_requests active WHERE active.tenant_id=?1 AND active.client_id=nazo_mtls_trust_requests.client_id AND active.status=1 AND active.not_before<={NOW} AND active.not_after>{NOW})<8))")
        };
        let event_type = match status {
            MtlsTrustAnchorStatus::Approved => "mtls_trust_anchor_approved",
            MtlsTrustAnchorStatus::Rejected => "mtls_trust_anchor_rejected",
            MtlsTrustAnchorStatus::Revoked => "mtls_trust_anchor_revoked",
            MtlsTrustAnchorStatus::Pending => return Err(RepositoryError::Conflict),
        };
        let event = SecurityAuditEvent {
            event_id: Uuid::new_v4(),
            event_type: event_type.into(),
            event_category: "trust_lifecycle".into(),
            occurred_at: jiff::Timestamp::now(),
            payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"trust_lifecycle","tenant_id":self.tenant_id,"request_id":id,"admin_user_id":actor,"outcome":"success"}),
        };
        let mutation = TrustMutation {
            id,
            version,
            source_event_id: Uuid::new_v4(),
            actor,
            action: status.code(),
            note: note.as_deref(),
            audit: &event,
        };
        let state_guard = Statement::new(
            "SELECT CASE WHEN changes()=0 OR EXISTS(SELECT 1 FROM nazo_mtls_trust_requests WHERE tenant_id=?1 AND id=?2 AND status=?4 AND admin_note IS ?5 AND version=?6 AND source='admin-session'
                AND ((?4 IN (1,2) AND resolved_by_user_id=?3 AND resolved_at=updated_at AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
                    OR (?4=3 AND revoked_by_user_id=?3 AND revoked_at=updated_at)))
                THEN 1 ELSE json('mTLS trust decision effect failure') END AS checked",
            params[..6].to_vec(),
        );
        let mut results = self
            .database
            .batch(vec![
                Statement::new(update, params),
                state_guard,
                self.trust_source_event(&mutation),
                self.trust_required_audit(&event, id, version)?,
                self.trust_effect_guard(&mutation)?,
                self.trust_projection(id, version),
            ])
            .await?;
        results
            .pop()
            .ok_or(DbError::Unavailable)?
            .rows
            .into_iter()
            .next()
            .ok_or(RepositoryError::Conflict)
            .and_then(projection)
    }
}

impl MtlsTrustAnchorStore for D1Provider {
    fn create_for_owned_client(
        &self,
        request: NewMtlsTrustAnchorRequest,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(async move {
            self.require_tenant(request.tenant_id.as_uuid())?;
            // The shared key-management preparation boundary validates the X.509
            // certificate. Enforce the native adapter's persisted field shapes.
            if request.certificate_sha256.len() != 64
                || !request
                    .certificate_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || request.certificate_pem.len() > 16_384
                || !request
                    .certificate_pem
                    .starts_with("-----BEGIN CERTIFICATE-----")
                || !request
                    .certificate_pem
                    .contains("-----END CERTIFICATE-----")
                || request.subject_dn.is_empty()
                || request.subject_dn.len() > 2048
                || request.not_before >= request.not_after
            {
                return Err(RepositoryError::Conflict);
            }
            let id = Uuid::new_v4();
            let version = Uuid::new_v4();
            let params: std::sync::Arc<[Value]> = vec![
                json!(self.tenant_id),
                json!(request.user_id),
                json!(request.client_id),
                json!(id),
                json!(request.certificate_pem),
                json!(request.certificate_sha256),
                json!(request.subject_dn),
                json!(request.not_before.as_microsecond().to_string()),
                json!(request.not_after.as_microsecond().to_string()),
                json!(version),
            ]
            .into();
            let eligible = format!(
                "c.tenant_id=?1 AND c.client_id=?3 AND c.active=1 AND ((json_extract(c.registration,'$.token_endpoint_auth_method')='tls_client_auth' AND json_extract(c.registration,'$.tls_client_auth_cert_sha256') IS NOT NULL) OR c.require_mtls_bound_tokens=1) AND CAST(?8 AS INTEGER)<={NOW} AND CAST(?9 AS INTEGER)>{NOW} AND EXISTS(SELECT 1 FROM nazo_users u WHERE u.tenant_id=?1 AND u.id=?2 AND u.active=1) AND EXISTS(SELECT 1 FROM nazo_access_requests a WHERE a.tenant_id=?1 AND a.user_id=?2 AND a.approved_client_id=c.id AND a.status=1)"
            );
            let event = SecurityAuditEvent {
                event_id: Uuid::new_v4(),
                event_type: "mtls_trust_anchor_requested".into(),
                event_category: "trust_lifecycle".into(),
                occurred_at: jiff::Timestamp::now(),
                payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"trust_lifecycle","tenant_id":self.tenant_id,"request_id":id,"requester_user_id":request.user_id,"client_id":request.client_id,"certificate_sha256":request.certificate_sha256}),
            };
            let mutation = TrustMutation {
                id,
                version,
                source_event_id: Uuid::new_v4(),
                actor: request.user_id,
                action: 0,
                note: None,
                audit: &event,
            };
            let state_guard = Statement::new(
                "SELECT CASE WHEN changes()=0 OR EXISTS(SELECT 1 FROM nazo_mtls_trust_requests r JOIN nazo_clients c ON c.tenant_id=r.tenant_id AND c.id=r.client_id
                    WHERE r.tenant_id=?1 AND r.id=?4 AND r.user_id=?2 AND c.client_id=?3 AND r.certificate_pem=?5 AND r.certificate_sha256=?6 AND r.subject_dn=?7 AND r.not_before=CAST(?8 AS INTEGER) AND r.not_after=CAST(?9 AS INTEGER) AND r.version=?10
                        AND r.status=0 AND r.admin_note IS NULL AND r.resolved_by_user_id IS NULL AND r.resolved_at IS NULL AND r.revoked_by_user_id IS NULL AND r.revoked_at IS NULL AND r.created_at=r.updated_at AND r.source='admin-session')
                    THEN 1 ELSE json('mTLS trust request effect failure') END AS checked",
                params.clone(),
            );
            let mut results=self.database.batch(vec![
                Statement::new(format!("SELECT EXISTS(SELECT 1 FROM nazo_clients c WHERE {eligible}) AS eligible"),params[..9].to_vec()),
                Statement::new(format!("INSERT INTO nazo_mtls_trust_requests(tenant_id,id,user_id,client_id,certificate_pem,certificate_sha256,subject_dn,not_before,not_after,created_at,updated_at,version) SELECT ?1,?4,?2,c.id,?5,?6,?7,CAST(?8 AS INTEGER),CAST(?9 AS INTEGER),{NOW},{NOW},?10 FROM nazo_clients c WHERE {eligible}
                    AND (SELECT count(*) FROM nazo_mtls_trust_requests pending WHERE pending.tenant_id=?1 AND pending.client_id=c.id AND pending.status=0)<4
                    AND (SELECT count(*) FROM nazo_mtls_trust_requests pending WHERE pending.tenant_id=?1 AND pending.user_id=?2 AND pending.status=0)<16
                    AND NOT EXISTS(SELECT 1 FROM nazo_mtls_trust_requests existing WHERE existing.tenant_id=?1 AND existing.client_id=c.id AND existing.certificate_sha256=?6)"),params),
                state_guard,
                self.trust_source_event(&mutation),
                self.trust_required_audit(&event,id,version)?,
                self.trust_effect_guard(&mutation)?,
                self.trust_projection(id,version),
            ]).await?;
            if let Some(value) = results
                .pop()
                .ok_or(DbError::Unavailable)?
                .rows
                .into_iter()
                .next()
            {
                return projection(value);
            }
            if results[0]
                .rows
                .first()
                .and_then(|row| row["eligible"].as_i64())
                == Some(1)
            {
                Err(RepositoryError::Conflict)
            } else {
                Err(RepositoryError::NotFound)
            }
        })
    }

    fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Vec<MtlsTrustAnchorRequest>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.database.query::<RequestRow>(&format!("SELECT {PROJECTION} {JOINS} WHERE r.tenant_id=?1 AND r.user_id=?2 ORDER BY r.created_at DESC,r.id DESC"),vec![json!(self.tenant_id),json!(user)]).await?.into_iter().map(RequestRow::domain).collect()
        })
    }

    fn page(
        &self,
        tenant: TenantId,
        status: Option<MtlsTrustAnchorStatus>,
        limit: i64,
        offset: i64,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequestPage> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            if limit < 0 || offset < 0 {
                return Err(RepositoryError::Conflict);
            }
            let filter = "r.tenant_id=?1 AND (?2 IS NULL OR r.status=?2)";
            let params: std::sync::Arc<[Value]> = vec![
                json!(self.tenant_id),
                json!(status.map(MtlsTrustAnchorStatus::code)),
                json!(limit),
                json!(offset),
            ]
            .into();
            let results=self.database.batch(vec![
                Statement::new(format!("SELECT count(*) AS total {JOINS} WHERE {filter}"),params[..2].to_vec()),
                Statement::new(format!("SELECT {PROJECTION} {JOINS} WHERE {filter} ORDER BY r.created_at DESC,r.id DESC LIMIT ?3 OFFSET ?4"),params),
            ]).await?;
            let total = results[0]
                .rows
                .first()
                .and_then(|row| row["total"].as_i64())
                .ok_or(DbError::CorruptData)?;
            let items = results
                .into_iter()
                .nth(1)
                .ok_or(DbError::Unavailable)?
                .rows
                .into_iter()
                .map(projection)
                .collect::<Result<_, _>>()?;
            Ok(MtlsTrustAnchorRequestPage { total, items })
        })
    }

    fn by_id(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> RepositoryFuture<'_, Option<MtlsTrustAnchorRequest>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.database
                .query::<RequestRow>(
                    &format!("SELECT {PROJECTION} {JOINS} WHERE r.tenant_id=?1 AND r.id=?2"),
                    vec![json!(self.tenant_id), json!(id)],
                )
                .await?
                .into_iter()
                .next()
                .map(RequestRow::domain)
                .transpose()
        })
    }

    fn approve(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(self.mutate_trust(tenant, id, actor, MtlsTrustAnchorStatus::Approved, note))
    }
    fn reject(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(self.mutate_trust(tenant, id, actor, MtlsTrustAnchorStatus::Rejected, note))
    }
    fn revoke(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: UserId,
        note: String,
    ) -> RepositoryFuture<'_, MtlsTrustAnchorRequest> {
        Box::pin(self.mutate_trust(
            tenant,
            id,
            actor,
            MtlsTrustAnchorStatus::Revoked,
            Some(note),
        ))
    }

    fn active_bundle(
        &self,
        tenant: TenantId,
        client: Option<Uuid>,
    ) -> RepositoryFuture<'_, String> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            #[derive(Deserialize)]
            struct PemRow {
                certificate_pem: String,
            }
            let rows=self.database.query::<PemRow>(&format!("SELECT DISTINCT r.certificate_pem FROM nazo_mtls_trust_requests r JOIN nazo_clients c ON c.tenant_id=r.tenant_id AND c.id=r.client_id WHERE r.tenant_id=?1 AND r.status=1 AND r.not_before<={NOW} AND r.not_after>{NOW} AND (?2 IS NULL OR r.client_id=?2) AND c.active=1 AND (json_extract(c.registration,'$.token_endpoint_auth_method')='tls_client_auth' OR c.require_mtls_bound_tokens=1) ORDER BY r.certificate_pem LIMIT 129"),vec![json!(self.tenant_id),json!(client)]).await?;
            if rows.len() > 128 {
                return Err(RepositoryError::Conflict);
            }
            Ok(rows.into_iter().map(|row| row.certificate_pem).collect())
        })
    }
}
