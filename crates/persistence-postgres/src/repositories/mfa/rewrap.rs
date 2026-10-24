//! Adapter-owned TOTP key activation and bounded envelope migration.
use super::{
    MfaAuditError, MfaRepository,
    totp::{decode_totp_secret, protect_totp_secret},
};
use crate::{MfaTotpKeyRing, get_conn, pool::DiscardOnDrop};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Binary, Nullable, Text, Uuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_identity::{TenantId, UserId, ports::RepositoryError};

pub(crate) const BATCH_LIMIT: i64 = 256;

#[derive(QueryableByName)]
struct KeyState {
    #[diesel(sql_type = Text)]
    current_key_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    previous_key_id: Option<String>,
}
#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}
#[derive(QueryableByName)]
struct Credential {
    #[diesel(sql_type = Uuid)]
    id: uuid::Uuid,
    #[diesel(sql_type = Uuid)]
    tenant_id: uuid::Uuid,
    #[diesel(sql_type = Uuid)]
    user_id: uuid::Uuid,
    #[diesel(sql_type = Binary)]
    secret_ciphertext: Vec<u8>,
    #[diesel(sql_type = Text)]
    secret_key_id: String,
}
fn error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
impl MfaRepository {
    /// At adapter startup, require every retained envelope's key before changing
    /// the write key. A stale configuration cannot rotate back to the prior key.
    pub async fn activate_totp_key(&self) -> Result<(), RepositoryError> {
        let Some(keys) = &self.totp_keys else {
            return Ok(());
        };
        let mut guard = DiscardOnDrop(Some(
            get_conn(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?,
        ));
        let result = guard.connection().transaction::<_, MfaAuditError, _>(async move |connection| {
            sql_query("INSERT INTO mfa_totp_key_state (current_key_id) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind::<Text,_>(keys.current().id()).execute(connection).await.map_err(error)?;
            let state = sql_query("SELECT current_key_id, previous_key_id FROM mfa_totp_key_state WHERE singleton FOR UPDATE")
                .get_result::<KeyState>(connection).await.map_err(error)?;
            let previous = keys.previous().map(|key| key.id());
            let unavailable = sql_query("SELECT count(*)::bigint AS count FROM user_totp_credentials WHERE secret_key_id <> $1 AND ($2::text IS NULL OR secret_key_id <> $2)")
                .bind::<Text,_>(keys.current().id()).bind::<Nullable<Text>,_>(previous)
                .get_result::<Count>(connection).await.map_err(error)?.count;
            if unavailable != 0 {
                return Err(RepositoryError::Consistency(format!("{unavailable} TOTP envelopes still require a key absent from the configured key ring")).into());
            }
            if state.current_key_id != keys.current().id() {
                if previous != Some(state.current_key_id.as_str()) || state.previous_key_id.as_deref() == Some(keys.current().id()) {
                    return Err(RepositoryError::Consistency("TOTP rotation must advance from the active key; stale key configuration cannot become the writer".into()).into());
                }
                sql_query("UPDATE mfa_totp_key_state SET previous_key_id = current_key_id, current_key_id = $1 WHERE singleton")
                    .bind::<Text,_>(keys.current().id()).execute(connection).await.map_err(error)?;
            }
            Ok(())
        }).await.map_err(MfaAuditError::into_repository);
        guard.return_to_pool();
        result
    }

    /// One bounded batch; remaining references are checked at key activation.
    pub async fn rewrap_totp_batch(&self) -> Result<u64, RepositoryError> {
        let Some(keys) = &self.totp_keys else {
            return Ok(0);
        };
        let mut guard = DiscardOnDrop(Some(
            get_conn(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?,
        ));
        let result = rewrap_batch(guard.connection(), keys).await;
        guard.return_to_pool();
        result
    }
}

pub(crate) async fn rewrap_batch(
    connection: &mut AsyncPgConnection,
    keys: &MfaTotpKeyRing,
) -> Result<u64, RepositoryError> {
    let Some(previous) = keys.previous() else {
        return Ok(0);
    };
    connection.transaction::<_, MfaAuditError, _>(async move |connection| {
        let state = sql_query("SELECT current_key_id, previous_key_id FROM mfa_totp_key_state WHERE singleton FOR SHARE")
            .get_result::<KeyState>(connection).await.map_err(error)?;
        // A superseded instance may still finish other maintenance categories.
        if state.current_key_id != keys.current().id() { return Ok(0); }
        let rows = sql_query("SELECT id, tenant_id, user_id, secret_ciphertext, secret_key_id FROM user_totp_credentials WHERE secret_key_id = $1 ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED")
            .bind::<Text,_>(previous.id()).bind::<BigInt,_>(BATCH_LIMIT)
            .load::<Credential>(connection).await.map_err(error)?;
        let count = rows.len() as u64;
        for row in rows {
            let tenant = TenantId::new(row.tenant_id).map_err(|_| RepositoryError::Consistency("invalid TOTP tenant id".into()))?;
            let user = UserId::new(row.user_id).map_err(|_| RepositoryError::Consistency("invalid TOTP user id".into()))?;
            let mut plaintext = zeroize::Zeroizing::new(row.secret_ciphertext);
            let secret = decode_totp_secret(keys, tenant, user, &mut plaintext, &row.secret_key_id)?;
            let (ciphertext, key_id) = protect_totp_secret(keys, tenant, user, secret)?;
            // The locked credential UUID is the enrollment generation. Preserve
            // confirmation and replay counters; a replacement enrollment cannot
            // be overwritten by this transaction.
            sql_query("UPDATE user_totp_credentials SET secret_ciphertext = $1, secret_key_id = $2 WHERE id = $3 AND secret_key_id = $4")
                .bind::<Binary,_>(ciphertext).bind::<Text,_>(key_id)
                .bind::<Uuid,_>(row.id).bind::<Text,_>(row.secret_key_id)
                .execute(connection).await.map_err(error)?;
        }
        Ok(count)
    }).await.map_err(MfaAuditError::into_repository)
}
