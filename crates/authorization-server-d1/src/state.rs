//! Tenant-scoped state transitions. Every expiry decision uses the D1 clock.

use std::{borrow::Cow, future::Future, pin::Pin};

use jiff::Timestamp;
use nazo_auth::{
    AuthorizationCodeBeginResult, AuthorizationCodeState, AuthorizationCodeTransitionResult,
    AuthorizationFuture, AuthorizationPortError, AuthorizationRateDimension,
    AuthorizationStateSnapshot, AuthorizationStateStorePort, ClientAttestationProofWindow,
    ConsentPayload, DpopStateFuture, DpopStateStoreError, DpopStateStorePort,
    PushedAuthorizationRequest, RequestRateLimitBucket, RequestRateLimitError,
    RequestRateLimitFuture, RequestRateLimitPort, TokenFuture, TokenPortError, TokenStateStorePort,
};
use nazo_identity::{
    SessionId, SessionRotationOutcome, SessionSnapshot, SessionUpdateOutcome, SessionVersion,
    TenantId, UserId,
    ports::{
        LoginSessionCreate, LoginSessionPort, LoginThrottlePort, MfaAttemptThrottleDecision,
        MfaAttemptThrottlePort, RepositoryError, RepositoryFuture, SessionStorePort,
    },
    session::SessionRecord,
};
use nazo_oauth_server::ports::fapi_replay::{
    FapiHttpSignatureReplayConsumption, FapiHttpSignatureReplayStore,
    FapiHttpSignatureReplayStoreError,
};
use nazo_resource_server::{
    DpopNonceStorage, DpopNonceValidationResult, DpopReplayConsumption,
    DpopReplayConsumptionResult, DpopReplayKey, ProtectedResourceDependencyError,
    ResourceServerPortFuture,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Statement},
};

const LOAD: &str = "SELECT value, version FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch()";
const PUT: &str = "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,?4,?5,unixepoch()+?6) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at RETURNING version";
const INSERT: &str = "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,?4,?5,unixepoch()+?6) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING version";
const DELETE: &str =
    "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 RETURNING version";
const COMPARE_DELETE: &str = "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND version=?4 AND expires_at>unixepoch() RETURNING version";
const TAKE: &str = "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch() RETURNING value,version";
const REPLAY_ABSOLUTE: &str = "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) SELECT ?1,?2,?3,'null','',?4 WHERE unixepoch()>=?5 AND unixepoch()<?4 ON CONFLICT(tenant_id,kind,key) DO UPDATE SET expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING version";
const REPLAY: &str = "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,'null','',unixepoch()+?4) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING version";
const INCREMENT: &str = "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,'1','',unixepoch()+?4) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=CASE WHEN nazo_state.expires_at<=unixepoch() THEN '1' WHEN json_type(nazo_state.value)='integer' AND CAST(nazo_state.value AS INTEGER)>0 THEN CAST(CAST(nazo_state.value AS INTEGER)+1 AS TEXT) END,expires_at=CASE WHEN nazo_state.expires_at<=unixepoch() THEN excluded.expires_at ELSE nazo_state.expires_at END RETURNING value,version";
const CODE_STATUS: &str = "SELECT CASE WHEN json_valid(value) THEN json_extract(value,'$.status') END AS status FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch()";

#[derive(Deserialize)]
struct StateRow {
    value: String,
    version: String,
}

#[derive(Deserialize)]
struct VersionRow {
    #[serde(rename = "version")]
    _version: String,
}

#[derive(Deserialize)]
struct CodeStatus {
    status: Option<String>,
}

fn key(parts: &[&str]) -> String {
    let mut hash = blake3::Hasher::new();
    for part in parts {
        hash.update(&(part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().to_hex().to_string()
}

fn ttl(seconds: u64) -> Result<i64, DbError> {
    i64::try_from(seconds)
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or(DbError::CorruptData)
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|_| DbError::CorruptData)
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, DbError> {
    serde_json::from_str(value).map_err(|_| DbError::CorruptData)
}

fn authorization_error(error: DbError) -> AuthorizationPortError {
    match error {
        DbError::Unavailable => AuthorizationPortError::Unavailable,
        DbError::CorruptData => AuthorizationPortError::CorruptData,
    }
}

fn token_error(error: DbError) -> TokenPortError {
    match error {
        DbError::Unavailable => TokenPortError::Unavailable,
        DbError::CorruptData => TokenPortError::CorruptData,
    }
}

fn repository_error(error: DbError) -> RepositoryError {
    match error {
        DbError::Unavailable => RepositoryError::Unavailable,
        DbError::CorruptData => RepositoryError::Consistency("invalid D1 state".into()),
    }
}

impl D1Provider {
    fn state_params(&self, kind: &str, key: &str) -> Vec<Value> {
        vec![json!(self.tenant_id), json!(kind), json!(key)]
    }

    async fn state_load(&self, kind: &str, key: &str) -> Result<Option<StateRow>, DbError> {
        Ok(self
            .database
            .query(LOAD, self.state_params(kind, key))
            .await?
            .pop())
    }

    async fn state_put(
        &self,
        kind: &str,
        key: &str,
        value: String,
        seconds: u64,
        replace: bool,
    ) -> Result<bool, DbError> {
        let mut params = self.state_params(kind, key);
        params.extend([
            Value::String(value),
            json!(Uuid::new_v4()),
            json!(ttl(seconds)?),
        ]);
        let rows: Vec<VersionRow> = self
            .database
            .query(if replace { PUT } else { INSERT }, params)
            .await?;
        if replace && rows.is_empty() {
            return Err(DbError::Unavailable);
        }
        Ok(!rows.is_empty())
    }

    async fn state_delete(&self, kind: &str, key: &str) -> Result<bool, DbError> {
        let params: std::sync::Arc<[Value]> = self.state_params(kind, key).into();
        let results = self.database.batch(vec![
            Statement::new(DELETE, params.clone()),
            Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3) THEN 1 ELSE json('state deletion was not accepted') END", params),
        ]).await?;
        Ok(!results[0].rows.is_empty())
    }

    async fn state_compare_delete(
        &self,
        kind: &str,
        key: &str,
        expected: &str,
    ) -> Result<bool, DbError> {
        let mut params = self.state_params(kind, key);
        params.push(json!(expected));
        let rows: Vec<VersionRow> = self.database.query(COMPARE_DELETE, params).await?;
        Ok(!rows.is_empty())
    }

    async fn state_snapshot<T: DeserializeOwned>(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<AuthorizationStateSnapshot<T>>, DbError> {
        self.state_load(kind, key)
            .await?
            .map(|row| {
                Ok(AuthorizationStateSnapshot {
                    payload: decode(&row.value)?,
                    version: row.version,
                })
            })
            .transpose()
    }

    async fn preparation<T: Serialize + ?Sized>(
        &self,
        kind: &str,
        key: &str,
        value: &T,
        seconds: u64,
    ) -> Result<(), AuthorizationPortError> {
        let inserted = self
            .state_put(
                kind,
                key,
                encode(value).map_err(authorization_error)?,
                seconds,
                false,
            )
            .await
            .map_err(authorization_error)?;
        if inserted {
            Ok(())
        } else {
            Err(AuthorizationPortError::Conflict)
        }
    }

    async fn replay(&self, kind: &str, key: &str, seconds: u64) -> Result<bool, DbError> {
        let mut params = self.state_params(kind, key);
        params.push(json!(ttl(seconds)?));
        let rows: Vec<VersionRow> = self.database.query(REPLAY, params).await?;
        Ok(!rows.is_empty())
    }

    async fn replay_absolute(
        &self,
        kind: &str,
        key: &str,
        expires_at: i64,
        not_before: i64,
    ) -> Result<bool, DbError> {
        let mut params = self.state_params(kind, key);
        params.extend([json!(expires_at), json!(not_before)]);
        let rows: Vec<VersionRow> = self.database.query(REPLAY_ABSOLUTE, params).await?;
        Ok(!rows.is_empty())
    }

    async fn counter_increment(&self, kind: &str, key: &str, seconds: u64) -> Result<u64, DbError> {
        let mut params = self.state_params(kind, key);
        params.push(json!(ttl(seconds)?));
        let rows: Vec<StateRow> = self.database.query(INCREMENT, params).await?;
        rows.first()
            .ok_or(DbError::CorruptData)?
            .value
            .parse()
            .map_err(|_| DbError::CorruptData)
    }
}

impl AuthorizationStateStorePort for D1Provider {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>
    {
        Box::pin(async move {
            self.state_snapshot("par", &key(&[request_uri]))
                .await
                .map_err(authorization_error)
        })
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.state_compare_delete("par", &key(&[request_uri]), expected)
                .await
                .map_err(authorization_error)
        })
    }

    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.preparation("par", &key(&[request_uri]), payload, ttl_seconds)
                .await
        })
    }

    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>> {
        Box::pin(async move {
            self.state_snapshot("consent", request_id)
                .await
                .map_err(authorization_error)
        })
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.state_compare_delete("consent", request_id, expected)
                .await
                .map_err(authorization_error)
        })
    }

    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.preparation("consent", request_id, payload, ttl_seconds)
                .await
        })
    }

    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.state_put(
                "code",
                code_hash,
                encode(state).map_err(authorization_error)?,
                ttl_seconds,
                true,
            )
            .await
            .map(|_| ())
            .map_err(authorization_error)
        })
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.state_delete("code", code_hash)
                .await
                .map(|_| ())
                .map_err(authorization_error)
        })
    }

    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        Box::pin(async move {
            let rows: Vec<StateRow> = self
                .database
                .query(TAKE, self.state_params("reauth", &key(&[nonce])))
                .await
                .map_err(authorization_error)?;
            rows.first()
                .map(|row| decode(&row.value).map_err(authorization_error))
                .transpose()
        })
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.state_put(
                "reauth",
                &key(&[nonce]),
                started_at.to_string(),
                ttl_seconds,
                true,
            )
            .await
            .map(|_| ())
            .map_err(authorization_error)
        })
    }

    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay_absolute("jar", &key(&[client_id, jti]), expires_at, 0)
                .await
                .map_err(authorization_error)
        })
    }

    fn consume_client_attestation_proof<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        window: ClientAttestationProofWindow,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay_absolute(
                "client_attestation",
                &key(&[client_id, jti]),
                window.expires_at(),
                window.not_before(),
            )
            .await
            .map_err(authorization_error)
        })
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay("client_assertion", &key(&[client_id, jti]), ttl_seconds)
                .await
                .map_err(authorization_error)
        })
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay("jwt_bearer", &key(&[client_id, jti]), ttl_seconds)
                .await
                .map_err(authorization_error)
        })
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay_absolute("ciba_request", &key(&[client_id, jti]), expires_at, 0)
                .await
                .map_err(authorization_error)
        })
    }

    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay("dpop_replay", &key(&[thumbprint, jti]), ttl_seconds)
                .await
                .map_err(authorization_error)
        })
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.state_put(
                "dpop_nonce",
                &key(&[nonce]),
                "null".into(),
                ttl_seconds,
                true,
            )
            .await
            .map(|_| ())
            .map_err(authorization_error)
        })
    }

    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.state_load("dpop_nonce", &key(&[nonce]))
                .await
                .map(|row| row.is_some())
                .map_err(authorization_error)
        })
    }

    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        let kind = match dimension {
            AuthorizationRateDimension::Token => "rate_token",
            AuthorizationRateDimension::TokenManagement => "rate_management",
        };
        Box::pin(async move {
            self.counter_increment(kind, &key(&[subject.trim()]), window_seconds)
                .await
                .map_err(authorization_error)
        })
    }
}

impl TokenStateStorePort for D1Provider {
    fn load_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
    ) -> TokenFuture<'a, Option<AuthorizationCodeState>> {
        Box::pin(async move {
            self.state_load("code", code_hash)
                .await
                .map_err(token_error)?
                .map(|row| decode(&row.value).map_err(token_error))
                .transpose()
        })
    }

    fn begin_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        consuming_at: Timestamp,
    ) -> TokenFuture<'a, AuthorizationCodeBeginResult> {
        Box::pin(async move {
            let mut params = self.state_params("code", code_hash);
            params.push(json!(consuming_at));
            // JSON mutation touches only the storage state tag and timestamp.
            // The approved payload stays in the database without a Rust round trip.
            let mut results = self.database.batch(vec![
                Statement::new("UPDATE nazo_state SET value=json_set(value,'$.status','consuming','$.consuming_at',?4) WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch() AND CASE WHEN json_valid(value) THEN json_extract(value,'$.status')='pending' ELSE 0 END RETURNING value,version", params),
                Statement::new(CODE_STATUS, self.state_params("code", code_hash)),
            ]).await.map_err(token_error)?;
            if let Some(value) = results[0].rows.pop() {
                let row: StateRow =
                    serde_json::from_value(value).map_err(|_| TokenPortError::CorruptData)?;
                return match decode(&row.value) {
                    Ok(AuthorizationCodeState::Consuming { payload, .. }) => {
                        Ok(AuthorizationCodeBeginResult::Consuming(payload))
                    }
                    _ => Ok(AuthorizationCodeBeginResult::Malformed),
                };
            }
            let Some(value) = results[1].rows.pop() else {
                return Ok(AuthorizationCodeBeginResult::Missing);
            };
            let row: CodeStatus =
                serde_json::from_value(value).map_err(|_| TokenPortError::CorruptData)?;
            Ok(match row.status.as_deref() {
                Some("consuming") => AuthorizationCodeBeginResult::Busy,
                Some("consumed") => {
                    AuthorizationCodeBeginResult::Consumed(AuthorizationCodeState::Consumed)
                }
                Some("failed") => AuthorizationCodeBeginResult::Failed,
                _ => AuthorizationCodeBeginResult::Malformed,
            })
        })
    }

    fn mark_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, AuthorizationCodeTransitionResult> {
        Box::pin(async move {
            let mut params = self.state_params("code", code_hash);
            params.extend([
                Value::String(encode(replacement).map_err(token_error)?),
                json!(ttl(ttl_seconds).map_err(token_error)?),
            ]);
            let mut results = self.database.batch(vec![
                Statement::new("UPDATE nazo_state SET value=?4,expires_at=unixepoch()+?5 WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch() AND CASE WHEN json_valid(value) THEN json_extract(value,'$.status')='consuming' ELSE 0 END RETURNING version", params),
                Statement::new(CODE_STATUS, self.state_params("code", code_hash)),
            ]).await.map_err(token_error)?;
            if !results[0].rows.is_empty() {
                return Ok(AuthorizationCodeTransitionResult::Applied);
            }
            let Some(value) = results[1].rows.pop() else {
                return Ok(AuthorizationCodeTransitionResult::Missing);
            };
            let row: CodeStatus =
                serde_json::from_value(value).map_err(|_| TokenPortError::CorruptData)?;
            Ok(match row.status.as_deref() {
                Some("pending") => AuthorizationCodeTransitionResult::Pending,
                Some("consuming") => AuthorizationCodeTransitionResult::Consuming,
                Some("consumed") => AuthorizationCodeTransitionResult::Consumed,
                Some("failed") => AuthorizationCodeTransitionResult::Failed,
                _ => AuthorizationCodeTransitionResult::Malformed,
            })
        })
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.state_delete("code", code_hash)
                .await
                .map(|_| ())
                .map_err(token_error)
        })
    }

    fn increment_token_management_rate<'a>(
        &'a self,
        subject: &'a str,
        window_seconds: u64,
    ) -> TokenFuture<'a, u64> {
        Box::pin(async move {
            self.counter_increment("rate_management", &key(&[subject.trim()]), window_seconds)
                .await
                .map_err(token_error)
        })
    }

    fn store_native_sso<'a>(
        &'a self,
        secret: &'a str,
        value: &'a Value,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.state_put(
                "native_sso",
                &key(&[secret]),
                encode(value).map_err(token_error)?,
                ttl_seconds,
                true,
            )
            .await
            .map(|_| ())
            .map_err(token_error)
        })
    }

    fn load_native_sso<'a>(&'a self, secret: &'a str) -> TokenFuture<'a, Option<Value>> {
        Box::pin(async move {
            self.state_load("native_sso", &key(&[secret]))
                .await
                .map_err(token_error)?
                .map(|row| decode(&row.value).map_err(token_error))
                .transpose()
        })
    }
}

impl DpopStateStorePort for D1Provider {
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.replay("dpop_replay", &key(&[jkt, jti]), ttl_seconds)
                .await
                .map_err(|_| DpopStateStoreError)
        })
    }

    fn issue_nonce<'a>(&'a self, nonce: &'a str, ttl_seconds: u64) -> DpopStateFuture<'a, ()> {
        Box::pin(async move {
            self.state_put(
                "dpop_nonce",
                &key(&[nonce]),
                "null".into(),
                ttl_seconds,
                true,
            )
            .await
            .map(|_| ())
            .map_err(|_| DpopStateStoreError)
        })
    }

    fn validate_nonce<'a>(&'a self, nonce: &'a str) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.state_load("dpop_nonce", &key(&[nonce]))
                .await
                .map(|row| row.is_some())
                .map_err(|_| DpopStateStoreError)
        })
    }
}

impl DpopReplayConsumption for D1Provider {
    fn consume<'a>(
        &'a self,
        replay: DpopReplayKey<'a>,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopReplayConsumptionResult, ProtectedResourceDependencyError>,
    > {
        Box::pin(async move {
            self.replay_absolute(
                "dpop_replay",
                &key(&[replay.jkt, replay.jti]),
                replay.expires_at,
                0,
            )
            .await
            .map(|accepted| {
                if accepted {
                    DpopReplayConsumptionResult::Accepted
                } else {
                    DpopReplayConsumptionResult::Replay
                }
            })
            .map_err(|_| ProtectedResourceDependencyError::DpopReplayStoreUnavailable)
        })
    }
}

impl DpopNonceStorage for D1Provider {
    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a str,
        expires_at: i64,
    ) -> ResourceServerPortFuture<'a, Result<(), ProtectedResourceDependencyError>> {
        Box::pin(async move {
            let mut params = self.state_params("dpop_nonce", &key(&[nonce]));
            params.push(json!(expires_at));
            let rows: Vec<VersionRow> = self.database.query("INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,'null','',?4) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET expires_at=MAX(nazo_state.expires_at,excluded.expires_at) RETURNING version", params).await.map_err(|_| ProtectedResourceDependencyError::DpopNonceStoreUnavailable)?;
            if rows.is_empty() {
                return Err(ProtectedResourceDependencyError::DpopNonceStoreUnavailable);
            }
            Ok(())
        })
    }

    fn validate_nonce<'a>(
        &'a self,
        nonce: &'a str,
    ) -> ResourceServerPortFuture<
        'a,
        Result<DpopNonceValidationResult, ProtectedResourceDependencyError>,
    > {
        Box::pin(async move {
            self.state_load("dpop_nonce", &key(&[nonce]))
                .await
                .map(|row| {
                    if row.is_some() {
                        DpopNonceValidationResult::Accepted
                    } else {
                        DpopNonceValidationResult::Unknown
                    }
                })
                .map_err(|_| ProtectedResourceDependencyError::DpopNonceStoreUnavailable)
        })
    }
}

impl FapiHttpSignatureReplayStore for D1Provider {
    fn consume<'a>(
        &'a self,
        tenant_id: TenantId,
        fingerprint: &'a [u8],
        ttl_seconds: i64,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        FapiHttpSignatureReplayConsumption,
                        FapiHttpSignatureReplayStoreError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if tenant_id.as_uuid() != self.tenant_id || fingerprint.len() != 32 {
                return Err(FapiHttpSignatureReplayStoreError);
            }
            let ttl_seconds =
                u64::try_from(ttl_seconds).map_err(|_| FapiHttpSignatureReplayStoreError)?;
            let fingerprint: &[u8; 32] = fingerprint
                .try_into()
                .map_err(|_| FapiHttpSignatureReplayStoreError)?;
            self.replay(
                "fapi",
                &blake3::Hash::from_bytes(*fingerprint).to_hex(),
                ttl_seconds,
            )
            .await
            .map(|accepted| {
                if accepted {
                    FapiHttpSignatureReplayConsumption::Accepted
                } else {
                    FapiHttpSignatureReplayConsumption::Replay
                }
            })
            .map_err(|_| FapiHttpSignatureReplayStoreError)
        })
    }
}

impl RequestRateLimitPort for D1Provider {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        let kind = match bucket {
            RequestRateLimitBucket::Authentication => "rate_auth",
            RequestRateLimitBucket::Token => "rate_token",
            RequestRateLimitBucket::TokenManagement => "rate_management",
        };
        Box::pin(async move {
            self.counter_increment(kind, &key(&[subject.trim()]), window_seconds)
                .await
                .map_err(|_| RequestRateLimitError)
        })
    }
}

impl LoginThrottlePort for D1Provider {
    fn failure_count<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
    ) -> RepositoryFuture<'a, u64> {
        Box::pin(async move {
            self.state_load("login_failures", &key(&[source_ip, email]))
                .await
                .map_err(repository_error)?
                .map_or(Ok(0), |row| decode(&row.value).map_err(repository_error))
        })
    }

    fn record_failure<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
        window_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.counter_increment("login_failures", &key(&[source_ip, email]), window_seconds)
                .await
                .map(|_| ())
                .map_err(repository_error)
        })
    }

    fn clear_failure<'a>(&'a self, email: &'a str, source_ip: &'a str) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.state_delete("login_failures", &key(&[source_ip, email]))
                .await
                .map(|_| ())
                .map_err(repository_error)
        })
    }
}

impl MfaAttemptThrottlePort for D1Provider {
    fn reserve_attempt<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        window_seconds: u64,
        max_attempts: u64,
    ) -> RepositoryFuture<'a, MfaAttemptThrottleDecision> {
        Box::pin(async move {
            if tenant_id.as_uuid() != self.tenant_id {
                return Err(RepositoryError::Consistency(
                    "tenant boundary mismatch".into(),
                ));
            }
            let count = self
                .counter_increment(
                    "mfa_attempts",
                    &user_id.as_uuid().to_string(),
                    window_seconds,
                )
                .await
                .map_err(repository_error)?;
            Ok(if count > max_attempts {
                MfaAttemptThrottleDecision::Limited {
                    retry_after_seconds: window_seconds,
                }
            } else {
                MfaAttemptThrottleDecision::Allowed
            })
        })
    }

    fn clear_attempts<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            if tenant_id.as_uuid() != self.tenant_id {
                return Err(RepositoryError::Consistency(
                    "tenant boundary mismatch".into(),
                ));
            }
            self.state_delete("mfa_attempts", &user_id.as_uuid().to_string())
                .await
                .map(|_| ())
                .map_err(repository_error)
        })
    }
}

#[derive(Deserialize, Serialize)]
struct SessionWire<'a> {
    user_id: Uuid,
    authorization_epoch: i64,
    auth_time: i64,
    auth_time_micros: Option<i64>,
    amr: Cow<'a, [String]>,
    pending_mfa: bool,
    oidc_sid: Option<Cow<'a, str>>,
    logged_in_client_ids: Cow<'a, [String]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream: Option<Cow<'a, nazo_identity::session::UpstreamSession>>,
}

impl<'a> From<&'a SessionRecord> for SessionWire<'a> {
    fn from(value: &'a SessionRecord) -> Self {
        Self {
            user_id: value.user_id().as_uuid(),
            authorization_epoch: value.authorization_epoch(),
            auth_time: value.auth_time(),
            auth_time_micros: value.auth_time_micros(),
            amr: Cow::Borrowed(value.amr()),
            pending_mfa: value.pending_mfa(),
            oidc_sid: value.oidc_sid().map(Cow::Borrowed),
            logged_in_client_ids: Cow::Borrowed(value.logged_in_client_ids()),
            upstream: value.upstream().map(Cow::Borrowed),
        }
    }
}

impl TryFrom<SessionWire<'_>> for SessionRecord {
    type Error = DbError;

    fn try_from(wire: SessionWire<'_>) -> Result<Self, Self::Error> {
        let user_id = UserId::new(wire.user_id).map_err(|_| DbError::CorruptData)?;
        let mut record = Self::new(
            user_id,
            wire.authorization_epoch,
            wire.auth_time,
            wire.amr.into_owned(),
            wire.pending_mfa,
            wire.oidc_sid.map(Cow::into_owned),
        );
        if !record.restore_auth_time_micros(wire.auth_time_micros) {
            return Err(DbError::CorruptData);
        }
        record.set_upstream(wire.upstream.map(Cow::into_owned));
        for client in wire.logged_in_client_ids.into_owned() {
            record.add_logged_in_client(client);
        }
        Ok(record)
    }
}

impl D1Provider {
    /// Exchange an offline high-entropy setup ticket for a five-minute session
    /// used only to enroll the first WebAuthn credential. The claim fence,
    /// session and Required audit append commit in one D1 transaction.
    pub async fn claim_passkey_setup(
        &self,
        ticket_digest: &str,
        user_id: UserId,
        session_id: &str,
        now: Timestamp,
    ) -> Result<bool, RepositoryError> {
        if ticket_digest.len() != 64 || !ticket_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RepositoryError::Consistency(
                "invalid setup ticket digest".into(),
            ));
        }
        let claim_version = Uuid::new_v4().to_string();
        let mut session = SessionRecord::new(
            user_id,
            0,
            now.as_second(),
            vec!["bootstrap".into()],
            false,
            Some(Uuid::new_v4().to_string()),
        );
        session.record_authentication_at(now);
        let session_version = Uuid::new_v4().to_string();
        let session_key = key(&[session_id]);
        let event_id = Uuid::new_v4();
        let evidence = json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
            "event_category": "authentication",
            "tenant_id": self.tenant_id,
            "user_id": user_id.as_uuid(),
        });
        let result = self.database.batch(vec![
            Statement::new(
                "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) SELECT ?1,'passkey_setup_claim',?2,'null',?3,253402300799 FROM nazo_users WHERE tenant_id=?1 AND id=?4 AND active=1 AND NOT EXISTS(SELECT 1 FROM nazo_passkeys WHERE tenant_id=?1 AND user_id=?4) ON CONFLICT DO NOTHING RETURNING version",
                vec![json!(self.tenant_id), json!(ticket_digest), json!(claim_version), json!(user_id)],
            ),
            Statement::new(
                "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) SELECT ?1,'session',?4,json_set(?5,'$.authorization_epoch',epoch),?6,unixepoch()+300 FROM nazo_users WHERE tenant_id=?1 AND id=?7 AND active=1 AND EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='passkey_setup_claim' AND key=?2 AND version=?3) ON CONFLICT DO NOTHING RETURNING version",
                vec![json!(self.tenant_id), json!(ticket_digest), json!(claim_version), json!(session_key), json!(encode(&SessionWire::from(&session)).map_err(repository_error)?), json!(session_version), json!(user_id)],
            ),
            Statement::new(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?4,'passkey_setup_claimed','authentication',?5,?6 FROM nazo_state WHERE tenant_id=?1 AND kind='passkey_setup_claim' AND key=?2 AND version=?3 RETURNING sequence",
                vec![json!(self.tenant_id), json!(ticket_digest), json!(claim_version), json!(event_id), json!(now.as_microsecond()), json!(encode(&evidence).map_err(repository_error)?)],
            ),
            Statement::new(
                "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='passkey_setup_claim' AND key=?2 AND version=?3)
                    OR (EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?4 AND version=?5)
                        AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?6 AND event_type='passkey_setup_claimed'))
                    THEN 1 ELSE json('passkey setup atomicity failure') END AS checked",
                vec![json!(self.tenant_id), json!(ticket_digest), json!(claim_version), json!(session_key), json!(session_version), json!(event_id)],
            ),
        ]).await.map_err(repository_error)?;
        Ok(result[0].rows.len() == 1 && result[1].rows.len() == 1 && result[2].rows.len() == 1)
    }
}

const ADVANCE_UPSTREAM_SCOPE: &str = "
    INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at)
    VALUES (?1,'upstream_session',?2,?3,?4,?5)
    ON CONFLICT(tenant_id,kind,key) DO UPDATE SET
        value=CAST(MAX(CAST(nazo_state.value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT),
        expires_at=MAX(nazo_state.expires_at,excluded.expires_at)
";

impl D1Provider {
    fn advance_upstream_scope(&self, key: &str, cutoff: i64, retain_until: i64) -> Statement {
        Statement::new(
            ADVANCE_UPSTREAM_SCOPE,
            vec![
                json!(self.tenant_id),
                json!(key),
                json!(cutoff.to_string()),
                json!(Uuid::new_v4()),
                json!(retain_until),
            ],
        )
    }
}

impl LoginSessionPort for D1Provider {
    fn create<'a>(
        &'a self,
        session_id: &'a str,
        record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        Box::pin(async move {
            if let Some(upstream) = record.upstream() {
                let statements = upstream
                    .keys()
                    .map(|key| self.advance_upstream_scope(key, 0, upstream.expires_at))
                    .collect();
                self.database
                    .batch(statements)
                    .await
                    .map_err(repository_error)?;
            }
            self.state_put(
                "session",
                &key(&[session_id]),
                encode(&SessionWire::from(record)).map_err(repository_error)?,
                ttl_seconds,
                false,
            )
            .await
            .map(|created| {
                if created {
                    LoginSessionCreate::Created
                } else {
                    LoginSessionCreate::Collision
                }
            })
            .map_err(repository_error)
        })
    }

    fn revoke_upstream<'a>(
        &'a self,
        key: &'a str,
        cutoff: i64,
        retain_until: i64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.database
                .batch(vec![self.advance_upstream_scope(key, cutoff, retain_until)])
                .await
                .map_err(repository_error)?;
            Ok(())
        })
    }

    fn create_replacing<'a>(
        &'a self,
        previous_session_id: Option<&'a str>,
        session_id: &'a str,
        record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        Box::pin(async move {
            let new_key = key(&[session_id]);
            let version = Uuid::new_v4().to_string();
            let mut params = self.state_params("session", &new_key);
            params.extend([
                Value::String(encode(&SessionWire::from(record)).map_err(repository_error)?),
                json!(version),
                json!(ttl(ttl_seconds).map_err(repository_error)?),
            ]);
            let mut statements = vec![Statement::new(INSERT, params)];
            if let Some(previous) = previous_session_id.filter(|previous| *previous != session_id) {
                // The unique write revision proves insertion in this batch. A
                // collision never invalidates the previously active session.
                statements.push(Statement::new("DELETE FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?2 AND EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?3 AND version=?4)", vec![json!(self.tenant_id), json!(key(&[previous])), json!(new_key), json!(version)]));
                statements.push(Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?3 AND version=?4)
                    OR NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?2)
                    THEN 1 ELSE json('session replacement did not retire the previous session') END", vec![json!(self.tenant_id), json!(key(&[previous])), json!(new_key), json!(version)]));
            }
            let results = self
                .database
                .batch(statements)
                .await
                .map_err(repository_error)?;
            Ok(if results[0].rows.is_empty() {
                LoginSessionCreate::Collision
            } else {
                LoginSessionCreate::Created
            })
        })
    }
}

impl SessionStorePort for D1Provider {
    fn load<'a>(
        &'a self,
        session_id: &'a SessionId,
    ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        Box::pin(async move {
            let Some(row) = self
                .state_load("session", &key(&[session_id.as_str()]))
                .await
                .map_err(repository_error)?
            else {
                return Ok(None);
            };
            let wire: SessionWire<'_> = decode(&row.value).map_err(repository_error)?;
            if let Some(upstream) = &wire.upstream {
                if upstream.expires_at <= jiff::Timestamp::now().as_second() {
                    return Ok(None);
                }
                for key in upstream.keys() {
                    let active = self
                        .state_load("upstream_session", key)
                        .await
                        .map_err(repository_error)?
                        .and_then(|row| row.value.parse::<i64>().ok())
                        .is_some_and(|cutoff| cutoff < upstream.started_at);
                    if !active {
                        return Ok(None);
                    }
                }
            }
            Ok(Some(SessionSnapshot::new(
                wire.try_into().map_err(repository_error)?,
                SessionVersion::from_storage(row.version.into_bytes()),
            )))
        })
    }

    fn delete<'a>(&'a self, session_id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.state_delete("session", &key(&[session_id.as_str()]))
                .await
                .map_err(repository_error)
        })
    }

    fn rotate<'a>(
        &'a self,
        old_session_id: &'a SessionId,
        expected: &'a SessionVersion,
        new_session_id: &'a SessionId,
        replacement: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        Box::pin(async move {
            let old = key(&[old_session_id.as_str()]);
            let new = key(&[new_session_id.as_str()]);
            let expected = std::str::from_utf8(expected.storage_bytes())
                .map_err(|_| RepositoryError::Consistency("invalid session revision".into()))?;
            let results = self.database.batch(vec![
                Statement::new("DELETE FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?2 AND expires_at<=unixepoch()", vec![json!(self.tenant_id), json!(new)]),
                Statement::new("UPDATE nazo_state SET key=?4,value=?5,version=?6,expires_at=unixepoch()+?7 WHERE tenant_id=?1 AND kind='session' AND key=?2 AND version=?3 AND expires_at>unixepoch() AND NOT EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?4) RETURNING version", vec![json!(self.tenant_id), json!(old), json!(expected), json!(new), Value::String(encode(&SessionWire::from(replacement)).map_err(repository_error)?), json!(Uuid::new_v4()), json!(ttl(ttl_seconds).map_err(repository_error)?)]),
                Statement::new("SELECT version FROM nazo_state WHERE tenant_id=?1 AND kind='session' AND key=?2 AND version=?3 AND expires_at>unixepoch()", vec![json!(self.tenant_id), json!(old), json!(expected)]),
            ]).await.map_err(repository_error)?;
            Ok(if !results[1].rows.is_empty() {
                SessionRotationOutcome::Applied
            } else if !results[2].rows.is_empty() {
                SessionRotationOutcome::Collision
            } else {
                SessionRotationOutcome::Conflict
            })
        })
    }

    fn compare_and_set<'a>(
        &'a self,
        session_id: &'a SessionId,
        expected: &'a SessionVersion,
        replacement: &'a SessionRecord,
    ) -> RepositoryFuture<'a, SessionUpdateOutcome> {
        Box::pin(async move {
            let state_key = key(&[session_id.as_str()]);
            let expected = std::str::from_utf8(expected.storage_bytes())
                .map_err(|_| RepositoryError::Consistency("invalid session revision".into()))?;
            let results = self.database.batch(vec![
                Statement::new("UPDATE nazo_state SET value=?4,version=?5 WHERE tenant_id=?1 AND kind='session' AND key=?2 AND version=?3 AND expires_at>unixepoch() RETURNING version", vec![json!(self.tenant_id), json!(state_key), json!(expected), Value::String(encode(&SessionWire::from(replacement)).map_err(repository_error)?), json!(Uuid::new_v4())]),
                Statement::new("SELECT version FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch()", self.state_params("session", &state_key)),
            ]).await.map_err(repository_error)?;
            Ok(if !results[0].rows.is_empty() {
                SessionUpdateOutcome::Applied
            } else if results[1].rows.is_empty() {
                SessionUpdateOutcome::Missing
            } else {
                SessionUpdateOutcome::Conflict
            })
        })
    }
}
