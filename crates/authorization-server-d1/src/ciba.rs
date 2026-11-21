//! CIBA snapshots, deadline-aware CAS and durable ping claims on primary D1.

use nazo_auth::{
    CibaAtomicResult, CibaPingClaimBatch, CibaPingDelivery, CibaPingFinishOutcome,
    CibaPingFinishResult, CibaRequestState, CibaStateFuture, CibaStatePortError,
    CibaStateStorePort, CibaStateVersion, CibaStoredRequest,
};
use nazo_identity::{TenantId, UserId, ports::RepositoryFuture};
use nazo_oauth_server::ports::transient_state::{
    CibaPingDeliveryPort, TransientStateError, TransientStateFuture,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{UserRow, digest, encode},
};

fn state_error(error: DbError) -> CibaStatePortError {
    match error {
        DbError::Unavailable => CibaStatePortError::Unavailable,
        DbError::CorruptData => CibaStatePortError::CorruptData,
    }
}

fn delivery_error(error: DbError) -> TransientStateError {
    match error {
        DbError::Unavailable => TransientStateError::Unavailable,
        DbError::CorruptData => TransientStateError::CorruptData,
    }
}

#[derive(Deserialize)]
struct Snapshot {
    value: String,
    version: String,
    expires_at: i64,
}

impl CibaStateStorePort for D1Provider {
    type Version = CibaStateVersion;

    fn load<'a>(
        &'a self,
        auth_req_id: &'a str,
    ) -> CibaStateFuture<'a, Option<CibaStoredRequest<Self::Version>>> {
        Box::pin(async move {
            self.database.query::<Snapshot>(
                "SELECT value,version,expires_at FROM nazo_state WHERE tenant_id=?1 AND kind='ciba' AND key=?2 AND expires_at>unixepoch()",
                vec![json!(self.tenant_id),json!(digest(auth_req_id))],
            ).await.map_err(state_error)?.pop().map(|row| {
                let state: CibaRequestState = serde_json::from_str(&row.value)
                    .map_err(|_| CibaStatePortError::CorruptData)?;
                if state.retention_expires_at != row.expires_at {
                    return Err(CibaStatePortError::CorruptData);
                }
                Ok(CibaStoredRequest::new(state,
                    CibaStateVersion::new(row.version,row.expires_at)))
            }).transpose()
        })
    }

    fn create<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.create_with_authorization_deadline(auth_req_id, state, None)
    }

    fn create_with_authorization_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
        authorization_deadline: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            let mut state = state.clone();
            if let Some(notification) = &mut state.ping_notification {
                notification.auth_req_id = Some(auth_req_id.to_owned());
            }
            let params = vec![
                json!(self.tenant_id),
                json!(digest(auth_req_id)),
                json!(encode(&state).map_err(state_error)?),
                json!(Uuid::new_v4()),
                json!(state.retention_expires_at),
                json!(authorization_deadline),
            ];
            let result = self.database.batch(vec![
                Statement::new("INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) SELECT ?1,'ciba',?2,?3,?4,?5 WHERE ?5>unixepoch() AND (?6 IS NULL OR ?6>unixepoch()) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING key",params),
                Statement::new("SELECT ?1<=unixepoch() OR (?2 IS NOT NULL AND ?2<=unixepoch()) AS elapsed",vec![json!(state.retention_expires_at),json!(authorization_deadline)]),
            ]).await.map_err(state_error)?;
            atomic_result(&result).map_err(state_error)
        })
    }

    fn replace<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.replace_with_authorization_deadline(auth_req_id, version, state, None)
    }

    fn replace_with_authorization_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
        authorization_deadline: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            if state.retention_expires_at != version.retention_expires_at() {
                return Err(CibaStatePortError::CorruptData);
            }
            let result = self.database.batch(vec![
                Statement::new("UPDATE nazo_state SET value=?4,version=?5 WHERE tenant_id=?1 AND kind='ciba' AND key=?2 AND version=?3 AND expires_at=?6 AND expires_at>unixepoch() AND (?7 IS NULL OR ?7>unixepoch()) RETURNING key", vec![json!(self.tenant_id),json!(digest(auth_req_id)),json!(version.comparison_token()),json!(encode(state).map_err(state_error)?),json!(Uuid::new_v4()),json!(version.retention_expires_at()),json!(authorization_deadline)]),
                Statement::new("SELECT ?1<=unixepoch() OR (?2 IS NOT NULL AND ?2<=unixepoch()) AS elapsed",vec![json!(version.retention_expires_at()),json!(authorization_deadline)]),
            ]).await.map_err(state_error)?;
            atomic_result(&result).map_err(state_error)
        })
    }

    fn delete<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.delete_with_authorization_deadline(auth_req_id, version, None)
    }

    fn delete_with_authorization_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        authorization_deadline: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async move {
            let result = self.database.batch(vec![
                Statement::new("DELETE FROM nazo_state WHERE tenant_id=?1 AND kind='ciba' AND key=?2 AND version=?3 AND expires_at=?4 AND expires_at>unixepoch() AND (?5 IS NULL OR ?5>unixepoch()) RETURNING key",vec![json!(self.tenant_id),json!(digest(auth_req_id)),json!(version.comparison_token()),json!(version.retention_expires_at()),json!(authorization_deadline)]),
                Statement::new("SELECT ?1<=unixepoch() OR (?2 IS NOT NULL AND ?2<=unixepoch()) AS elapsed",vec![json!(version.retention_expires_at()),json!(authorization_deadline)]),
            ]).await.map_err(state_error)?;
            atomic_result(&result).map_err(state_error)
        })
    }
}

fn atomic_result(results: &[crate::db::Outcome]) -> Result<CibaAtomicResult, DbError> {
    if results
        .first()
        .is_some_and(|result| !result.rows.is_empty())
    {
        return Ok(CibaAtomicResult::Applied);
    }
    match results
        .last()
        .and_then(|result| result.rows.first())
        .and_then(|row| row.get("elapsed"))
        .and_then(Value::as_i64)
    {
        Some(1) => Ok(CibaAtomicResult::DeadlineElapsed),
        Some(0) => Ok(CibaAtomicResult::Conflict),
        _ => Err(DbError::CorruptData),
    }
}

impl nazo_persistence::CibaAccountStore for D1Provider {
    fn by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            #[derive(Deserialize)]
            struct AccountRow {
                id: UserId,
                #[serde(flatten)]
                account: UserRow,
            }
            self.database.query::<AccountRow>(
                "SELECT id,principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE tenant_id=?1 AND email=?2",
                vec![json!(self.tenant_id),json!(email)],
            ).await?.pop().map(|row|row.account.public_account(tenant_id,row.id).map_err(Into::into)).transpose()
        })
    }

    fn by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            self.user_row(user_id.as_uuid())
                .await?
                .map(|row| row.public_account(tenant_id, user_id).map_err(Into::into))
                .transpose()
        })
    }
}

impl CibaPingDeliveryPort for D1Provider {
    fn claim_due<'a>(
        &'a self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> TransientStateFuture<'a, CibaPingClaimBatch> {
        Box::pin(async move {
            if lock_until <= now || limit > 1_000 {
                return Err(TransientStateError::CorruptData);
            }
            #[derive(Deserialize)]
            struct Claim {
                key: String,
                value: String,
            }
            // The partial expression index is the queue. Updating a snapshot
            // and its queue position is therefore a single primary mutation.
            // Every claim changes the opaque version, fencing concurrent polls.
            // D1 binds JS numbers as REALs. Keep JSON deadlines integral for
            // CibaRequestState's integer deserialization.
            let rows = self.database.query::<Claim>(
                "UPDATE nazo_state SET value=CASE
                    WHEN expires_at<=unixepoch() OR json_extract(value,'$.expires_at')<=?2
                    THEN json_remove(json_set(value,'$.ping_notification.status','failed'),'$.ping_notification.next_attempt_at','$.ping_notification.client_notification_token')
                    ELSE json_set(value,'$.ping_notification.attempts',coalesce(json_extract(value,'$.ping_notification.attempts'),0)+1,'$.ping_notification.next_attempt_at',CAST(?3 AS INTEGER)) END,
                    version=?5
                 WHERE tenant_id=?1 AND kind='ciba' AND key IN (
                    SELECT key FROM nazo_state WHERE tenant_id=?1 AND kind='ciba'
                    AND json_extract(value,'$.ping_notification.status')='pending'
                    AND json_extract(value,'$.ping_notification.next_attempt_at')<=?2
                    ORDER BY json_extract(value,'$.ping_notification.next_attempt_at'),key LIMIT ?4)
                 RETURNING key,value",
                vec![json!(self.tenant_id),json!(now),json!(lock_until),json!(limit.min(4)),json!(Uuid::new_v4())],
            ).await.map_err(delivery_error)?;
            let scanned = rows.len();
            let mut deliveries = Vec::with_capacity(scanned);
            for row in rows {
                let state: CibaRequestState = serde_json::from_str(&row.value)
                    .map_err(|_| TransientStateError::CorruptData)?;
                let notification = state
                    .ping_notification
                    .ok_or(TransientStateError::CorruptData)?;
                if notification.status == nazo_auth::CibaPingNotificationStatus::Pending {
                    deliveries.push(CibaPingDelivery {
                        auth_req_id_hash: row.key,
                        auth_req_id: notification
                            .auth_req_id
                            .ok_or(TransientStateError::CorruptData)?,
                        endpoint: notification.endpoint,
                        client_notification_token: notification
                            .client_notification_token
                            .ok_or(TransientStateError::CorruptData)?,
                        attempts: notification.attempts,
                        expires_at: state.expires_at,
                    });
                }
            }
            Ok(CibaPingClaimBatch {
                scanned,
                deliveries,
            })
        })
    }

    fn finish<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async move {
            let (status, retry_at) = match outcome {
                CibaPingFinishOutcome::Delivered => ("delivered", None),
                CibaPingFinishOutcome::Failed => ("failed", None),
                CibaPingFinishOutcome::RetryAt(at) => ("pending", Some(at)),
            };
            let results=self.database.batch(vec![
                Statement::new("UPDATE nazo_state SET value=CASE WHEN ?6 IS NOT NULL THEN json_set(value,'$.ping_notification.next_attempt_at',CAST(?6 AS INTEGER)) ELSE json_remove(json_set(value,'$.ping_notification.status',?5),'$.ping_notification.next_attempt_at','$.ping_notification.client_notification_token') END,version=?7
                    WHERE tenant_id=?1 AND kind='ciba' AND key=?2 AND expires_at>unixepoch()
                    AND json_extract(value,'$.ping_notification.status')='pending'
                    AND json_extract(value,'$.ping_notification.attempts')=?3
                    AND json_extract(value,'$.ping_notification.auth_req_id')=?4 RETURNING key",
                    vec![json!(self.tenant_id),json!(delivery.auth_req_id_hash),json!(delivery.attempts),json!(delivery.auth_req_id),json!(status),json!(retry_at),json!(Uuid::new_v4())]),
                Statement::new("SELECT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='ciba' AND key=?2 AND expires_at>unixepoch()) AS present",vec![json!(self.tenant_id),json!(delivery.auth_req_id_hash)]),
            ]).await.map_err(delivery_error)?;
            if results[0].rows.is_empty() {
                match results[1]
                    .rows
                    .first()
                    .and_then(|row| row.get("present"))
                    .and_then(Value::as_i64)
                {
                    Some(1) => Ok(CibaPingFinishResult::Conflict),
                    Some(0) => Ok(CibaPingFinishResult::Missing),
                    _ => Err(TransientStateError::CorruptData),
                }
            } else {
                Ok(CibaPingFinishResult::Applied)
            }
        })
    }
}
