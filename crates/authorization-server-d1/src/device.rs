//! Device-code state, user-code mappings and approval receipts on primary D1.

use nazo_auth::{
    DeviceAtomicResult, DeviceAuthorizationState, DeviceCreateResult, DeviceGrantFuture,
    DeviceGrantPortError, DeviceGrantRepositoryPort, DeviceGrantWrite, DeviceStateFuture,
    DeviceStatePortError, DeviceStateReplacement, DeviceStateStorePort, DeviceStateVersion,
    StoredDeviceAuthorization,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Outcome, Statement},
    persistence::{NOW, digest, encode},
};

#[derive(Deserialize)]
struct DeviceRow {
    value: String,
    version: String,
}

#[derive(Deserialize)]
struct MappingRow {
    value: String,
}

fn user_code_key(value: &str) -> String {
    // The native store uses this same identity for formatted display codes
    // and the normalized codes passed by the shared verification handlers.
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect()
}

fn state_error(error: DbError) -> DeviceStatePortError {
    match error {
        DbError::Unavailable => DeviceStatePortError::Unavailable,
        DbError::CorruptData => DeviceStatePortError::CorruptData,
    }
}

fn grant_error(error: DbError) -> DeviceGrantPortError {
    match error {
        DbError::Unavailable => DeviceGrantPortError::Unavailable,
        DbError::CorruptData => DeviceGrantPortError::CorruptData,
    }
}

fn outcome(results: &[Outcome]) -> Result<&str, DbError> {
    results
        .last()
        .and_then(|result| result.rows.first())
        .and_then(|row| row.get("outcome"))
        .and_then(Value::as_str)
        .ok_or(DbError::CorruptData)
}

impl D1Provider {
    async fn device_snapshot(
        &self,
        device_hash: &str,
    ) -> Result<Option<StoredDeviceAuthorization<DeviceStateVersion>>, DbError> {
        let row: Option<DeviceRow> = self
            .database
            .query(
                "SELECT value,version FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND expires_at>unixepoch()",
                vec![json!(self.tenant_id), json!(device_hash)],
            )
            .await?
            .pop();
        row.map(|row| {
            let state = serde_json::from_str(&row.value).map_err(|_| DbError::CorruptData)?;
            Ok(StoredDeviceAuthorization::new(
                state,
                DeviceStateVersion::new(row.version),
            ))
        })
        .transpose()
    }

    async fn replace_device(
        &self,
        device_hash: &str,
        expected: &DeviceStateVersion,
        replacement: &DeviceAuthorizationState,
        user_code: Option<&str>,
        complete: bool,
    ) -> Result<DeviceStateReplacement<DeviceStateVersion>, DbError> {
        let next = Uuid::new_v4().to_string();
        let params: std::sync::Arc<[Value]> = vec![
            json!(self.tenant_id),
            json!(device_hash),
            json!(expected.comparison_token()),
            json!(user_code.map(user_code_key)),
            json!(next),
        ]
        .into();
        let mut update_params = params.to_vec();
        update_params.push(json!(encode(replacement)?));
        // Only value/version change: polling, claims and completion preserve
        // the deadline assigned atomically with the original user-code map.
        let mut statements = vec![Statement::new(
            "UPDATE nazo_state SET value=?6,version=?5 WHERE tenant_id=?1 AND kind='device' AND key=?2 AND version=?3 AND expires_at>unixepoch() AND (?4 IS NULL OR EXISTS(SELECT 1 FROM nazo_state AS mapping WHERE mapping.tenant_id=?1 AND mapping.kind='device_user' AND mapping.key=?4 AND mapping.value=?2 AND mapping.expires_at>unixepoch())) RETURNING version",
            update_params,
        )];
        if complete {
            statements.push(Statement::new(
                "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind='device_user' AND key=?4 AND value=?2 AND EXISTS(SELECT 1 FROM nazo_state AS device WHERE device.tenant_id=?1 AND device.kind='device' AND device.key=?2 AND device.version=?5)",
                params.clone(),
            ));
            statements.push(Statement::new(
                "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND version=?5)
                    OR NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device_user' AND key=?4 AND value=?2)
                    THEN 1 ELSE json('device completion did not retire its user code') END",
                params.clone(),
            ));
        }
        statements.push(Statement::new(
            "SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND version=?5) THEN 'applied' WHEN EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND version=?3 AND expires_at<=unixepoch()) THEN 'expired' ELSE 'conflict' END AS outcome",
            params,
        ));
        let results = self.database.batch(statements).await?;
        Ok(match outcome(&results)? {
            "applied" => DeviceStateReplacement::Applied(DeviceStateVersion::new(next)),
            "expired" => DeviceStateReplacement::DeadlineElapsed,
            "conflict" => DeviceStateReplacement::Conflict,
            _ => return Err(DbError::CorruptData),
        })
    }
}

fn atomic(replacement: DeviceStateReplacement<DeviceStateVersion>) -> DeviceAtomicResult {
    match replacement {
        DeviceStateReplacement::Applied(_) => DeviceAtomicResult::Applied,
        DeviceStateReplacement::Conflict => DeviceAtomicResult::Conflict,
        DeviceStateReplacement::DeadlineElapsed => DeviceAtomicResult::DeadlineElapsed,
    }
}

impl DeviceStateStorePort for D1Provider {
    type Version = DeviceStateVersion;

    fn create<'a>(
        &'a self,
        device_code: &'a str,
        user_code: &'a str,
        state: &'a DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> DeviceStateFuture<'a, DeviceCreateResult> {
        Box::pin(async move {
            if ttl_seconds == 0 {
                return Ok(DeviceCreateResult::DeadlineElapsed);
            }
            let ttl = i64::try_from(ttl_seconds).map_err(|_| DeviceStatePortError::CorruptData)?;
            let device_hash = digest(device_code);
            let version = Uuid::new_v4().to_string();
            let params: std::sync::Arc<[Value]> = vec![
                json!(self.tenant_id),
                json!(device_hash),
                json!(user_code_key(user_code)),
                json!(version),
            ]
            .into();
            let mut create_params = params.to_vec();
            create_params.extend([json!(encode(state).map_err(state_error)?), json!(ttl)]);
            let results = self.database.batch(vec![
                Statement::new("INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) SELECT ?1,'device',?2,?5,?4,unixepoch()+?6 WHERE NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device_user' AND key=?3 AND expires_at>unixepoch()) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING version", create_params),
                Statement::new("INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) SELECT ?1,'device_user',?3,?2,?4,expires_at FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND version=?4 ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING version", params.clone()),
                Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND version=?4)
                    OR EXISTS(SELECT 1 FROM nazo_state d JOIN nazo_state m ON m.tenant_id=d.tenant_id AND m.kind='device_user' AND m.key=?3 AND m.value=d.key AND m.version=d.version AND m.expires_at=d.expires_at
                        WHERE d.tenant_id=?1 AND d.kind='device' AND d.key=?2 AND d.version=?4)
                    THEN 1 ELSE json('device creation did not persist its user code') END",params.clone()),
                Statement::new("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND version=?4) THEN 'applied' WHEN EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device' AND key=?2 AND expires_at>unixepoch()) THEN 'device_collision' ELSE 'user_collision' END AS outcome", params),
            ]).await.map_err(state_error)?;
            match outcome(&results).map_err(state_error)? {
                "applied" => Ok(DeviceCreateResult::Applied),
                "device_collision" => Ok(DeviceCreateResult::DeviceCodeCollision),
                "user_collision" => Ok(DeviceCreateResult::UserCodeCollision),
                _ => Err(DeviceStatePortError::Unexpected),
            }
        })
    }

    fn load_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move {
            self.device_snapshot(&digest(device_code))
                .await
                .map_err(state_error)
        })
    }

    fn load_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move { self.device_snapshot(device_hash).await.map_err(state_error) })
    }

    fn resolve_user_code<'a>(
        &'a self,
        user_code: &'a str,
    ) -> DeviceStateFuture<'a, Option<String>> {
        Box::pin(async move {
            let row: Option<MappingRow> = self.database.query(
                "SELECT value FROM nazo_state WHERE tenant_id=?1 AND kind='device_user' AND key=?2 AND expires_at>unixepoch()",
                vec![json!(self.tenant_id), json!(user_code_key(user_code))],
            ).await.map_err(state_error)?.pop();
            Ok(row.map(|row| row.value))
        })
    }

    fn replace_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.replace_device(&digest(device_code), version, replacement, None, false)
                .await
                .map(atomic)
                .map_err(state_error)
        })
    }

    fn replace_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceStateReplacement<Self::Version>> {
        Box::pin(async move {
            self.replace_device(device_hash, version, replacement, None, false)
                .await
                .map_err(state_error)
        })
    }

    fn claim_decision<'a>(
        &'a self,
        device_hash: &'a str,
        user_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.replace_device(device_hash, version, replacement, Some(user_code), false)
                .await
                .map(atomic)
                .map_err(state_error)
        })
    }

    fn complete_decision<'a>(
        &'a self,
        device_hash: &'a str,
        user_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.replace_device(device_hash, version, replacement, Some(user_code), true)
                .await
                .map(atomic)
                .map_err(state_error)
        })
    }

    fn delete_user_code_if_matches<'a>(
        &'a self,
        user_code: &'a str,
        device_hash: &'a str,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            let rows: Vec<MappingRow> = self.database.query(
                "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind='device_user' AND key=?2 AND value=?3 AND expires_at>unixepoch() RETURNING value",
                vec![json!(self.tenant_id), json!(user_code_key(user_code)), json!(device_hash)],
            ).await.map_err(state_error)?;
            Ok(if rows.is_empty() {
                DeviceAtomicResult::Conflict
            } else {
                DeviceAtomicResult::Applied
            })
        })
    }
}

impl DeviceGrantRepositoryPort for D1Provider {
    fn upsert_grant<'a>(&'a self, write: DeviceGrantWrite<'a>) -> DeviceGrantFuture<'a, ()> {
        Box::pin(async move {
            self.require_tenant(write.tenant_id).map_err(grant_error)?;
            let version = Uuid::new_v4().to_string();
            let deadline = write.expires_at.as_microsecond();
            // Receipts use the shared seconds-based expiry index. Round up so
            // cleanup cannot erase the fence while the exact deadline is live.
            let retain_until =
                deadline.div_euclid(1_000_000) + i64::from(deadline.rem_euclid(1_000_000) != 0);
            let params: std::sync::Arc<[Value]> = vec![
                json!(self.tenant_id),
                json!(write.device_code_hash),
                json!(version),
                json!(deadline),
                json!(retain_until),
                json!(write.user_id),
                json!(write.client_id),
            ]
            .into();
            let mut grant_params = params.to_vec();
            grant_params.extend([
                json!(encode(&write.scopes).map_err(grant_error)?),
                json!(encode(&write.resource_indicators).map_err(grant_error)?),
                json!(encode(&write.authorization_details).map_err(grant_error)?),
            ]);
            let mut audit_params = params.to_vec();
            audit_params.push(json!(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION));
            let mut guard_params = grant_params.clone();
            guard_params.push(json!(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION));
            let principals = "EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?6 AND active=1) AND EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?7 AND active=1)";
            let results = self.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) SELECT ?1,'device_decision',?2,'null',?3,?5 WHERE ?4>{NOW} AND ({principals}) ON CONFLICT(tenant_id,kind,key) DO NOTHING RETURNING version"), params.clone()),
                Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                    SELECT ?1,?3,'device_grant_authorized','authorization',{NOW},json_object(
                      'schema_version',?8,'event_category','authorization','tenant_id',?1,'user_id',?6,
                      'client_id',c.client_id,'decision','approve','outcome','success',
                      'authorization_count',COALESCE((SELECT authorization_count FROM nazo_grant_activity WHERE tenant_id=?1 AND user_id=?6 AND client_id=?7),0)+1)
                    FROM nazo_clients c WHERE c.tenant_id=?1 AND c.id=?7
                      AND EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device_decision' AND key=?2 AND version=?3)"),audit_params),
                Statement::new("INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision) SELECT ?1,?6,?7,?8,?9,?10,?3 WHERE EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device_decision' AND key=?2 AND version=?3) ON CONFLICT(tenant_id,user_id,client_id) DO UPDATE SET scopes=excluded.scopes,resources=excluded.resources,details=excluded.details,revision=excluded.revision", grant_params),
                // Receipt, grant, canonical completion audit and history are one
                // transaction. An ignored write must not acknowledge approval.
                Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device_decision' AND key=?2 AND version=?3) OR (
                    EXISTS(SELECT 1 FROM nazo_audit a JOIN nazo_clients c ON c.tenant_id=a.tenant_id AND c.id=?7
                      WHERE a.tenant_id=?1 AND a.event_id=?3 AND a.event_type='device_grant_authorized' AND a.category='authorization'
                        AND json_extract(a.payload,'$.schema_version')=?11 AND json_extract(a.payload,'$.tenant_id')=?1
                        AND json_extract(a.payload,'$.user_id')=?6 AND json_extract(a.payload,'$.client_id')=c.client_id
                        AND json_extract(a.payload,'$.decision')='approve' AND json_extract(a.payload,'$.outcome')='success')
                    AND EXISTS(SELECT 1 FROM nazo_grants g JOIN nazo_grant_activity h ON h.tenant_id=g.tenant_id AND h.user_id=g.user_id AND h.client_id=g.client_id
                      JOIN nazo_audit a ON a.tenant_id=g.tenant_id AND a.event_id=g.revision
                      WHERE g.tenant_id=?1 AND g.user_id=?6 AND g.client_id=?7 AND g.revision=?3
                        AND g.scopes=?8 AND g.resources=?9 AND g.details=?10
                        AND h.last_authorized_at=a.occurred_at AND h.authorization_count=json_extract(a.payload,'$.authorization_count')))
                    THEN 1 ELSE json_extract('device grant completion was not accepted','$') END",guard_params),
                Statement::new(format!("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device_decision' AND key=?2 AND version=?3) THEN 'committed' WHEN NOT ({principals}) THEN 'principal' WHEN ?4<={NOW} THEN 'expired' WHEN EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='device_decision' AND key=?2) THEN 'committed' ELSE 'conflict' END AS outcome"), params),
            ]).await.map_err(grant_error)?;
            match outcome(&results).map_err(grant_error)? {
                "committed" => Ok(()),
                "principal" => Err(DeviceGrantPortError::Unexpected),
                "expired" | "conflict" => Err(DeviceGrantPortError::Conflict),
                _ => Err(DeviceGrantPortError::CorruptData),
            }
        })
    }
}
