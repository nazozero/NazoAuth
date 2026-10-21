use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vci::PreparedPreAuthorizedOffer;
use nazo_openid4vci::{
    CredentialAccess, CredentialAuthorization, CredentialStoreError, CredentialStoreFuture,
    StoredCredentialOffer,
};
use serde::Deserialize;
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

    pub(super) fn offer_prepare_pre_authorized<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<PreparedPreAuthorizedOffer>, CredentialStoreError>>
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
            let configuration_ids = Vec::<String>::deserialize(&row.credential_configuration_ids)
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

            let commit_token = serde_json::to_vec(&(code_hash, &row))
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            Ok(Some(PreparedPreAuthorizedOffer {
                commit_token,
                authorization: CredentialAuthorization {
                    tenant_id: row.tenant_id,
                    subject_id,
                    client_id: client_id.to_owned(),
                    configuration_ids,
                    credential_identifiers: Vec::new(),
                    expires_at: (now + chrono::Duration::minutes(10)).min(row.expires_at),
                },
            }))
        })
    }
    pub(super) fn offer_commit_pre_authorized<'a>(
        &'a self,
        prepared: &'a [u8],
        token_hash: &'a str,
        access: &'a CredentialAccess,
        registered_client_id: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let (code_hash, row): (String, PreAuthorizedOfferRow) =
                serde_json::from_slice(prepared)
                    .map_err(|_| CredentialStoreError::InvalidTransition)?;
            if row.tenant_id != access.tenant_id
                || row.subject_id != Some(access.subject_id)
                || row.credential_configuration_ids != serde_json::json!(access.configuration_ids)
                || !access.credential_identifiers.is_empty()
                || access.expires_at > row.expires_at
                || access.expires_at <= Utc::now()
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection.transaction::<(), OfferCommitError, _>(async move |connection| {
                // Follow the revocation lock order: subject, client/grant, offer.
                let active = sql_query("SELECT id FROM users WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE FOR SHARE")
                    .bind::<sql_types::Uuid, _>(access.tenant_id)
                    .bind::<sql_types::Uuid, _>(access.subject_id)
                    .get_result::<ActiveSubjectRow>(connection).await.optional()?;
                if active.is_none() {
                    return Err(CredentialStoreError::InvalidTransition.into());
                }
                super::access::persist_pre_authorized_on_connection(connection, token_hash, access, registered_client_id).await?;
                // Every authorization-bearing field is compared against the verified snapshot.
                // No password verification or signing is repeated while holding database locks.
                let consumed = sql_query(
                    "UPDATE openid4vci_offers SET consumed_at = GREATEST(clock_timestamp(), created_at), \
                     grants_ciphertext = ''::bytea, tx_code_hash = NULL \
                     WHERE tenant_id = $1 AND id = $2 AND consumed_at IS NULL \
                       AND expires_at > clock_timestamp() AND pre_authorized_code_hash = $3 \
                       AND tx_code_hash IS NOT DISTINCT FROM $4 AND subject_id = $5 \
                       AND credential_configuration_ids = $6 AND expires_at = $7")
                    .bind::<sql_types::Uuid, _>(row.tenant_id)
                    .bind::<sql_types::Uuid, _>(row.id)
                    .bind::<sql_types::Text, _>(&code_hash)
                    .bind::<sql_types::Nullable<sql_types::Text>, _>(row.tx_code_hash.as_deref())
                    .bind::<sql_types::Uuid, _>(access.subject_id)
                    .bind::<sql_types::Jsonb, _>(&row.credential_configuration_ids)
                    .bind::<sql_types::Timestamptz, _>(row.expires_at)
                    .execute(connection).await?;
                if consumed != 1 {
                    return Err(CredentialStoreError::InvalidTransition.into());
                }
                Ok(())
            }).await.map_err(|error| match error {
                OfferCommitError::Store(error) => error,
                OfferCommitError::Database => CredentialStoreError::Unavailable,
            })
        })
    }
}

#[derive(diesel::QueryableByName)]
struct ActiveSubjectRow {
    #[diesel(sql_type = sql_types::Uuid)]
    #[allow(dead_code)]
    id: Uuid,
}

#[derive(Debug)]
enum OfferCommitError {
    Store(CredentialStoreError),
    Database,
}

impl From<CredentialStoreError> for OfferCommitError {
    fn from(error: CredentialStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<diesel::result::Error> for OfferCommitError {
    fn from(_: diesel::result::Error) -> Self {
        Self::Database
    }
}
