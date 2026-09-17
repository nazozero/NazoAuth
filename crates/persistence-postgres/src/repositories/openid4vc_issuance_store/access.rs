use super::super::Openid4vciRepository;
use super::AccessRow;
use crate::get_conn;
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_openid4vci::{CredentialAccess, CredentialStoreError, CredentialStoreFuture};

pub(super) async fn access_upsert_on_connection(
    connection: &mut AsyncPgConnection,
    token_hash: &str,
    access: &CredentialAccess,
) -> Result<(), diesel::result::Error> {
    sql_query(
        // The IS DISTINCT FROM guard keeps an identical projection sync from
        // writing a new row version; a real change still updates the same four
        // columns, and the four identity conditions keep their original role.
        "INSERT INTO openid4vci_access_grants \
         (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,dpop_jkt,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (token_hash) DO UPDATE SET \
           credential_configuration_ids = EXCLUDED.credential_configuration_ids, \
           credential_identifiers = EXCLUDED.credential_identifiers, \
           dpop_jkt = EXCLUDED.dpop_jkt, expires_at = EXCLUDED.expires_at \
         WHERE openid4vci_access_grants.token_id = EXCLUDED.token_id \
           AND openid4vci_access_grants.tenant_id = EXCLUDED.tenant_id \
           AND openid4vci_access_grants.subject_id = EXCLUDED.subject_id \
           AND openid4vci_access_grants.client_id = EXCLUDED.client_id \
           AND (openid4vci_access_grants.credential_configuration_ids, \
                openid4vci_access_grants.credential_identifiers, \
                openid4vci_access_grants.dpop_jkt, \
                openid4vci_access_grants.expires_at) \
           IS DISTINCT FROM \
               (EXCLUDED.credential_configuration_ids, \
                EXCLUDED.credential_identifiers, \
                EXCLUDED.dpop_jkt, \
                EXCLUDED.expires_at)",
    )
    .bind::<sql_types::Uuid, _>(access.token_id)
    .bind::<sql_types::Text, _>(token_hash)
    .bind::<sql_types::Uuid, _>(access.tenant_id)
    .bind::<sql_types::Uuid, _>(access.subject_id)
    .bind::<sql_types::Text, _>(&access.client_id)
    .bind::<sql_types::Jsonb, _>(serde_json::json!(access.configuration_ids))
    .bind::<sql_types::Jsonb, _>(serde_json::json!(access.credential_identifiers))
    .bind::<sql_types::Nullable<sql_types::Text>, _>(access.dpop_jkt.as_deref())
    .bind::<sql_types::Timestamptz, _>(access.expires_at)
    .execute(connection)
    .await?;
    Ok(())
}

/// A racing identical insert can surface a unique violation on the `token_id`
/// primary key — a non-arbiter index — while the winner's `token_hash`
/// speculative insertion is still in flight. Once the winner commits, the same
/// single statement takes the `ON CONFLICT` path. Retry once to keep the
/// one-statement contract without reporting a false conflict.
async fn access_upsert_with_conflict_retry(
    connection: &mut AsyncPgConnection,
    token_hash: &str,
    access: &CredentialAccess,
) -> Result<(), diesel::result::Error> {
    match access_upsert_on_connection(connection, token_hash, access).await {
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => access_upsert_on_connection(connection, token_hash, access).await,
        result => result,
    }
}

fn is_unique_violation(error: &diesel::result::Error) -> bool {
    matches!(
        error,
        diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _,)
    )
}

impl Openid4vciRepository {
    pub(super) fn access_upsert<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            access_upsert_with_conflict_retry(&mut connection, token_hash, access)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn access_persist_pre_authorized<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
        registered_client_id: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let Some(client_id) = registered_client_id else {
                return access_upsert_with_conflict_retry(&mut connection, token_hash, access)
                    .await
                    .map_err(|_| CredentialStoreError::Unavailable);
            };
            if client_id != access.client_id {
                return Err(CredentialStoreError::InvalidTransition);
            }
            // A unique violation inside the transaction aborts it; replay the
            // whole transaction once so the client lock is re-acquired and the
            // same single upsert takes the committed-conflict path.
            let mut retries = 1_u8;
            let persisted = loop {
                let attempt = connection
                    .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                        let client_is_active = sql_query(
                            "SELECT is_active FROM oauth_clients \
                             WHERE tenant_id = $1 AND client_id = $2 FOR SHARE",
                        )
                        .bind::<sql_types::Uuid, _>(access.tenant_id)
                        .bind::<sql_types::Text, _>(client_id)
                        .get_result::<ActiveRow>(connection)
                        .await
                        .optional()?;
                        if client_is_active.map(|row| row.is_active) != Some(true) {
                            return Ok(false);
                        }
                        access_upsert_on_connection(connection, token_hash, access).await?;
                        Ok(true)
                    })
                    .await;
                match attempt {
                    Ok(persisted) => break persisted,
                    Err(error) if is_unique_violation(&error) && retries > 0 => {
                        retries -= 1;
                    }
                    Err(_) => return Err(CredentialStoreError::Unavailable),
                }
            };
            if !persisted {
                return Err(CredentialStoreError::ClientInactive);
            }
            Ok(())
        })
    }

    pub(super) fn access_resolve<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let row = sql_query(
                "SELECT token_id, tenant_id, subject_id, client_id, credential_configuration_ids, \
                 credential_identifiers, dpop_jkt, expires_at FROM openid4vci_access_grants \
                 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
            )
            .bind::<sql_types::Text, _>(token_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<AccessRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            row.map(TryInto::try_into)
                .transpose()
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }
}

#[derive(diesel::QueryableByName)]
struct ActiveRow {
    #[diesel(sql_type = sql_types::Bool)]
    is_active: bool,
}
