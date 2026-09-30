use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_openid4vci::{
    CredentialAuthorization, CredentialStoreError, CredentialStoreFuture, StoredCredentialOffer,
};
use uuid::Uuid;

use super::super::Openid4vciRepository;
use super::super::offer::{OfferRow, PreAuthorizedOfferRow};
use crate::get_conn;

impl Openid4vciRepository {
    pub(super) fn offer_lookup<'a>(
        &'a self,
        tenant_id: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let row = sql_query(
                "SELECT id,tenant_id,subject_id,credential_configuration_ids,grants_ciphertext,expires_at \
                 FROM openid4vci_offers WHERE tenant_id = $1 AND id = $2 \
                   AND consumed_at IS NULL AND expires_at > $3",
            )
            .bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Uuid, _>(id)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<OfferRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            drop(connection);
            row.map(|row| row.into_domain(&self.data_key)).transpose()
        })
    }

    pub(super) fn offer_consume_pre_authorized<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        Box::pin(async move {
            // Verification is CPU-bound and may queue behind the host's shared
            // password limit. Return the database connection before awaiting it.
            let row = {
                let mut connection = get_conn(&self.pool)
                    .await
                    .map_err(|_| CredentialStoreError::Unavailable)?;
                sql_query(
                    "SELECT id,tenant_id,subject_id,credential_configuration_ids,tx_code_hash,expires_at \
                     FROM openid4vci_offers WHERE tenant_id = $1 \
                       AND pre_authorized_code_hash = $2 \
                       AND consumed_at IS NULL AND expires_at > $3",
                )
                .bind::<sql_types::Uuid, _>(tenant_id)
                .bind::<sql_types::Text, _>(code_hash)
                .bind::<sql_types::Timestamptz, _>(now)
                .get_result::<PreAuthorizedOfferRow>(&mut connection)
                .await
                .optional()
                .map_err(|_| CredentialStoreError::Unavailable)?
            };
            let Some(row) = row else {
                return Ok(None);
            };
            let Some(subject_id) = row.subject_id else {
                return Ok(None);
            };
            // Decode before consumption so corrupt authorization state cannot
            // spend the offer and then fail while building its response.
            let configuration_ids =
                serde_json::from_value(row.credential_configuration_ids.clone())
                    .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let matches = match (row.tx_code_hash.as_deref(), tx_code) {
                (None, None) => true,
                (Some(expected), Some(presented)) => {
                    let expected = nazo_identity::PasswordHash::new(expected)
                        .map_err(|_| CredentialStoreError::InvalidTransition)?;
                    self.secret_verifier
                        .verify_secret(presented.to_owned(), expected)
                        .await
                        .map_err(|_| CredentialStoreError::Unavailable)?
                }
                _ => false,
            };
            if !matches {
                return Ok(None);
            }

            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            // Compare every authorization-bearing snapshot field. PostgreSQL
            // rechecks this predicate after a concurrent updater wins; only one
            // caller can consume the offer. Use the database clock here because
            // the offer may expire while password verification is queued.
            let consumed = sql_query(
                "UPDATE openid4vci_offers \
                 SET consumed_at = GREATEST($3, clock_timestamp(), created_at) \
                 WHERE tenant_id = $1 AND id = $2 AND consumed_at IS NULL \
                   AND expires_at > GREATEST($3, clock_timestamp()) \
                   AND pre_authorized_code_hash = $4 \
                   AND tx_code_hash IS NOT DISTINCT FROM $5 \
                   AND subject_id = $6 AND credential_configuration_ids = $7 \
                   AND expires_at = $8 \
                 RETURNING consumed_at",
            )
            .bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Uuid, _>(row.id)
            .bind::<sql_types::Timestamptz, _>(now)
            .bind::<sql_types::Text, _>(code_hash)
            .bind::<sql_types::Nullable<sql_types::Text>, _>(row.tx_code_hash.as_deref())
            .bind::<sql_types::Uuid, _>(subject_id)
            .bind::<sql_types::Jsonb, _>(&row.credential_configuration_ids)
            .bind::<sql_types::Timestamptz, _>(row.expires_at)
            .get_result::<ConsumedOfferRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            let Some(consumed) = consumed else {
                return Ok(None);
            };
            Ok(Some(CredentialAuthorization {
                tenant_id: row.tenant_id,
                subject_id,
                client_id: client_id.to_owned(),
                configuration_ids,
                credential_identifiers: Vec::new(),
                expires_at: (consumed.consumed_at + chrono::Duration::minutes(10))
                    .min(row.expires_at),
            }))
        })
    }
}

#[derive(QueryableByName)]
struct ConsumedOfferRow {
    #[diesel(sql_type = sql_types::Timestamptz)]
    consumed_at: DateTime<Utc>,
}
