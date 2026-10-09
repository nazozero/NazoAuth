use chrono::{DateTime, Utc};
use diesel::{sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vci::{
    CredentialStoreError, CredentialStoreFuture, DeferredCredential, DeferredCredentialClaim,
    StoredCredentialResponse,
};
use uuid::Uuid;

use super::super::Openid4vciRepository;
use super::super::crypto::map_stored_credential_error;
use super::{
    DeferredLeaseReceipt, DeferredLockedProjectionRow, LockedContinuationGrant,
    NewIssuanceResponse, decode_error, decode_selection, insert_issuance_response, protect_payload,
    response_encoding_name,
};
use crate::{get_conn, pool::DiscardOnDrop};

impl Openid4vciRepository {
    pub(super) fn deferred_store<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &serde_json::to_vec(&credential.payload)
                    .map_err(|_| CredentialStoreError::Unavailable)?,
            )?;
            sql_query(
                "INSERT INTO openid4vci_deferred_transactions \
                 (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                  holder_bindings, payload_ciphertext, ready_at, expires_at, authorization_id, credential_selection) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind::<sql_types::Uuid, _>(credential.id)
            .bind::<sql_types::Text, _>(&credential.transaction_hash)
            .bind::<sql_types::Uuid, _>(credential.access.token_id)
            .bind::<sql_types::Text, _>(&credential.configuration_id)
            .bind::<sql_types::Text, _>(credential.format.as_str())
            .bind::<sql_types::Jsonb, _>(serde_json::Value::Array(
                credential.holder_bindings.clone(),
            ))
            .bind::<sql_types::Binary, _>(protected_payload)
            .bind::<sql_types::Timestamptz, _>(credential.ready_at)
            .bind::<sql_types::Timestamptz, _>(credential.expires_at)
            .bind::<sql_types::Nullable<sql_types::Uuid>, _>(credential.access.authorization_id)
            .bind::<sql_types::Jsonb, _>(serde_json::json!(credential.selection))
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    pub(super) fn deferred_store_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &serde_json::to_vec(&credential.payload)
                    .map_err(|_| CredentialStoreError::Unavailable)?,
            )?;
            let response_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let id = credential.id;
            let transaction_hash = credential.transaction_hash.clone();
            let token_id = credential.access.token_id;
            let configuration_id = credential.configuration_id.clone();
            let format = credential.format.as_str().to_owned();
            let holder_bindings = serde_json::Value::Array(credential.holder_bindings.clone());
            let ready_at = credential.ready_at;
            let expires_at = credential.expires_at;
            let authorization_id = credential.access.authorization_id;
            let selection = serde_json::json!(credential.selection);
            let issuance_id = response.issuance_id;
            let response_token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let response_selection = serde_json::json!(response.selection);
            let dpop_nonce = response.dpop_nonce.clone();
            let response_expires_at = response.expires_at;
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_deferred_transactions \
                         (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                          holder_bindings, payload_ciphertext, ready_at, expires_at, authorization_id, credential_selection) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                    )
                    .bind::<sql_types::Uuid, _>(id)
                    .bind::<sql_types::Text, _>(&transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(&configuration_id)
                    .bind::<sql_types::Text, _>(&format)
                    .bind::<sql_types::Jsonb, _>(holder_bindings)
                    .bind::<sql_types::Binary, _>(protected_payload)
                    .bind::<sql_types::Timestamptz, _>(ready_at)
                    .bind::<sql_types::Timestamptz, _>(expires_at)
                    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(authorization_id)
                    .bind::<sql_types::Jsonb, _>(selection)
                    .execute(connection)
                    .await?;
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            selection: response_selection,
                            issuance_id,
                            token_id: response_token_id,
                            request_digest: &request_digest,
                            body_ciphertext: response_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at: response_expires_at,
                        },
                    )
                    .await?;
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn deferred_store_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &serde_json::to_vec(&credential.payload)
                    .map_err(|_| CredentialStoreError::Unavailable)?,
            )?;
            let id = credential.id;
            let transaction_hash = credential.transaction_hash.clone();
            let token_id = credential.access.token_id;
            let configuration_id = credential.configuration_id.clone();
            let format = credential.format.as_str().to_owned();
            let holder_bindings = serde_json::Value::Array(credential.holder_bindings.clone());
            let ready_at = credential.ready_at;
            let expires_at = credential.expires_at;
            let authorization_id = credential.access.authorization_id;
            let selection = serde_json::json!(credential.selection);
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_deferred_transactions \
                         (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                          holder_bindings, payload_ciphertext, ready_at, expires_at, authorization_id, credential_selection) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                    )
                    .bind::<sql_types::Uuid, _>(id)
                    .bind::<sql_types::Text, _>(&transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(&configuration_id)
                    .bind::<sql_types::Text, _>(&format)
                    .bind::<sql_types::Jsonb, _>(holder_bindings)
                    .bind::<sql_types::Binary, _>(protected_payload)
                    .bind::<sql_types::Timestamptz, _>(ready_at)
                    .bind::<sql_types::Timestamptz, _>(expires_at)
                    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(authorization_id)
                    .bind::<sql_types::Jsonb, _>(selection)
                    .execute(connection)
                    .await?;
                    let changed = sql_query(
                        "UPDATE openid4vci_nonces SET consumed_at = GREATEST($3, created_at), claim_id = NULL, claim_expires_at = NULL \
                         WHERE nonce_hash = $1 AND claim_id = $2 AND consumed_at IS NULL AND expires_at > $3",
                    )
                    .bind::<sql_types::Text, _>(nonce_hash)
                    .bind::<sql_types::Text, _>(claim_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn deferred_store_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &serde_json::to_vec(&credential.payload)
                    .map_err(|_| CredentialStoreError::Unavailable)?,
            )?;
            let response_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let id = credential.id;
            let transaction_hash = credential.transaction_hash.clone();
            let token_id = credential.access.token_id;
            let configuration_id = credential.configuration_id.clone();
            let format = credential.format.as_str().to_owned();
            let holder_bindings = serde_json::Value::Array(credential.holder_bindings.clone());
            let ready_at = credential.ready_at;
            let expires_at = credential.expires_at;
            let authorization_id = credential.access.authorization_id;
            let selection = serde_json::json!(credential.selection);
            let issuance_id = response.issuance_id;
            let response_token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let response_selection = serde_json::json!(response.selection);
            let dpop_nonce = response.dpop_nonce.clone();
            let response_expires_at = response.expires_at;
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_deferred_transactions \
                         (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                          holder_bindings, payload_ciphertext, ready_at, expires_at, authorization_id, credential_selection) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                    )
                    .bind::<sql_types::Uuid, _>(id)
                    .bind::<sql_types::Text, _>(&transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(&configuration_id)
                    .bind::<sql_types::Text, _>(&format)
                    .bind::<sql_types::Jsonb, _>(holder_bindings)
                    .bind::<sql_types::Binary, _>(protected_payload)
                    .bind::<sql_types::Timestamptz, _>(ready_at)
                    .bind::<sql_types::Timestamptz, _>(expires_at)
                    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(authorization_id)
                    .bind::<sql_types::Jsonb, _>(selection)
                    .execute(connection)
                    .await?;
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            selection: response_selection,
                            issuance_id,
                            token_id: response_token_id,
                            request_digest: &request_digest,
                            body_ciphertext: response_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at: response_expires_at,
                        },
                    )
                    .await?;
                    let changed = sql_query(
                        "UPDATE openid4vci_nonces SET consumed_at = GREATEST($3, created_at), claim_id = NULL, claim_expires_at = NULL \
                         WHERE nonce_hash = $1 AND claim_id = $2 AND consumed_at IS NULL AND expires_at > $3",
                    )
                    .bind::<sql_types::Text, _>(nonce_hash)
                    .bind::<sql_types::Text, _>(claim_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn deferred_claim_ready<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<
        'a,
        Result<nazo_openid4vci::DeferredClaimOutcome, CredentialStoreError>,
    > {
        Box::pin(async move {
            let connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let mut guarded = DiscardOnDrop(Some(connection));
            let result = guarded.connection()
                .transaction::<nazo_openid4vci::DeferredClaimOutcome, diesel::result::Error, _>(
                    async move |connection| {
                        // The unlocked hint discovers immutable lock identities only.
                        // A single ordered stream is fully aggregated before the
                        // dependent deferred locking subquery can execute. No outer
                        // reread borrows grant metadata from the statement snapshot.
                        let rows = sql_query(
                            "WITH hint AS MATERIALIZED ( \
                               SELECT id, token_id FROM openid4vci_deferred_transactions \
                               WHERE transaction_hash = $1 \
                             ), grants_locked AS MATERIALIZED ( \
                               SELECT grant_row.token_id, grant_row.authorization_id, \
                                      grant_row.mtls_x5t_s256, grant_row.tenant_id, \
                                      grant_row.subject_id, grant_row.client_id, grant_row.proof_origin, \
                                      grant_row.credential_configuration_ids, grant_row.credential_identifiers, \
                                      grant_row.dpop_jkt, grant_row.expires_at, grant_row.revoked_at \
                               FROM openid4vci_access_grants AS grant_row CROSS JOIN hint \
                               WHERE grant_row.token_id IN (hint.token_id, $2) \
                               ORDER BY grant_row.token_id FOR SHARE OF grant_row \
                             ), grants_complete AS MATERIALIZED ( \
                               SELECT COUNT(*) AS grant_count, \
                                      jsonb_agg(to_jsonb(grants_locked) ORDER BY token_id) AS grants \
                               FROM grants_locked \
                             ), deferred_locked AS MATERIALIZED ( \
                               SELECT owner.*, complete.grants \
                               FROM grants_complete AS complete CROSS JOIN hint \
                               CROSS JOIN LATERAL ( \
                                 SELECT deferred.* FROM openid4vci_deferred_transactions AS deferred \
                                 WHERE complete.grant_count = CASE WHEN hint.token_id = $2 THEN 1 ELSE 2 END \
                                   AND deferred.id = hint.id AND deferred.token_id = hint.token_id \
                                   AND deferred.transaction_hash = $1 AND deferred.consumed_at IS NULL \
                                 FOR UPDATE OF deferred \
                               ) AS owner \
                             ), timed AS MATERIALIZED ( \
                               SELECT deferred_locked.*, clock_timestamp() AS owner_now FROM deferred_locked \
                             ) \
                             SELECT id, transaction_hash, token_id, authorization_id, credential_selection, \
                                    credential_configuration_id, credential_format, holder_bindings, \
                                    payload_ciphertext, ready_at, expires_at, grants, owner_now, \
                                    claim_id AS observed_claim_id, claim_expires_at AS observed_claim_expires_at \
                             FROM timed"
                        )
                        .bind::<sql_types::Text, _>(transaction_hash)
                        .bind::<sql_types::Uuid, _>(token_id)
                        .load::<DeferredLockedProjectionRow>(connection)
                        .await?;
                        let mut rows = rows.into_iter();
                        let Some(row) = rows.next() else {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        };
                        if rows.next().is_some() {
                            return Err(diesel::result::Error::DeserializationError(Box::new(
                                std::io::Error::other("deferred locked projection is ambiguous"))));
                        }
                        let locked: Vec<LockedContinuationGrant> =
                            serde_json::from_value(row.grants).map_err(decode_error)?;
                        let accesses = locked.into_iter().map(|grant| {
                            Ok((nazo_openid4vci::CredentialAccess::try_from(grant.access)?, grant.revoked_at))
                        }).collect::<Result<Vec<_>, diesel::result::Error>>()?;
                        let Some((original, _)) = accesses.iter()
                            .find(|(access, _)| access.token_id == row.deferred.token_id) else {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        };
                        let Some((current, revoked_at)) = accesses.iter()
                            .find(|(access, _)| access.token_id == token_id) else {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        };
                        let selection = decode_selection(row.deferred.credential_selection.clone())?;
                        // One authority policy, after all relevant lock waits and
                        // before Pending/Busy classification or any lease write.
                        if row.deferred.authorization_id != original.authorization_id
                            || row.deferred.expires_at <= row.owner_now
                            || revoked_at.is_some()
                            || selection.as_ref().is_some_and(|selection| {
                                selection.configuration_id != row.deferred.credential_configuration_id
                            })
                            || !current.continues_access(original, selection.as_ref(), row.owner_now)
                        {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        }
                        if row.deferred.ready_at > row.owner_now {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Pending {
                                retry_at: row.deferred.ready_at,
                            });
                        }
                        if row.observed_claim_id.is_some() {
                            let expires_at = row.observed_claim_expires_at.ok_or_else(|| {
                                diesel::result::Error::DeserializationError(Box::new(
                                    std::io::Error::other("deferred lease expiry is missing")))
                            })?;
                            if expires_at > row.owner_now {
                                return Ok(nazo_openid4vci::DeferredClaimOutcome::Busy { retry_at: expires_at });
                            }
                        }
                        let current_expires_at = current.expires_at;
                        let original_token_id = original.token_id;
                        let deferred = row.deferred.into_domain(original.clone(), &self.data_key)?;
                        // The second data statement owns only the lease. Recheck
                        // temporal facts at acceptance; locks still protect all
                        // authorization and final-state facts. Drain RETURNING,
                        // then let transaction() await the full COMMIT reply.
                        let receipts = sql_query(
                            "WITH accepted AS MATERIALIZED (SELECT clock_timestamp() AS accepted_at) \
                             UPDATE openid4vci_deferred_transactions AS target \
                             SET claim_id = $4, claim_token_id = $3, \
                                 claim_expires_at = accepted.accepted_at + INTERVAL '5 minutes' \
                             FROM accepted WHERE target.id = $1 AND target.transaction_hash = $2 \
                               AND target.token_id = $5 AND target.consumed_at IS NULL \
                               AND target.ready_at <= accepted.accepted_at \
                               AND target.expires_at > accepted.accepted_at AND $6 > accepted.accepted_at \
                               AND (target.claim_id IS NULL OR target.claim_expires_at <= accepted.accepted_at) \
                             RETURNING target.id, target.claim_id, target.claim_token_id"
                        )
                        .bind::<sql_types::Uuid, _>(deferred.id)
                        .bind::<sql_types::Text, _>(transaction_hash)
                        .bind::<sql_types::Uuid, _>(token_id)
                        .bind::<sql_types::Text, _>(claim_id)
                        .bind::<sql_types::Uuid, _>(original_token_id)
                        .bind::<sql_types::Timestamptz, _>(current_expires_at)
                        .load::<DeferredLeaseReceipt>(connection)
                        .await?;
                        if receipts.is_empty() {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        }
                        if receipts.len() != 1 || receipts[0].id != deferred.id
                            || receipts[0].claim_id != claim_id || receipts[0].claim_token_id != token_id {
                            return Err(diesel::result::Error::RollbackTransaction);
                        }
                        Ok(nazo_openid4vci::DeferredClaimOutcome::Claimed(Box::new(DeferredCredentialClaim {
                            credential: deferred, claim_id: claim_id.to_owned(),
                        })))
                    },
                )
                .await;
            if result.is_ok() {
                guarded.return_to_pool();
            }
            result.map_err(map_stored_credential_error)
        })
    }

    pub(super) fn deferred_finalize<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_deferred_transactions \
                 SET consumed_at = GREATEST($4, ready_at), claim_id = NULL, claim_expires_at = NULL, claim_token_id = NULL \
                 WHERE transaction_hash = $1 AND COALESCE(claim_token_id, token_id) = $2 AND claim_id = $3 \
                   AND consumed_at IS NULL AND expires_at > $4",
            )
            .bind::<sql_types::Text, _>(transaction_hash)
            .bind::<sql_types::Uuid, _>(token_id)
            .bind::<sql_types::Text, _>(claim_id)
            .bind::<sql_types::Timestamptz, _>(now)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    pub(super) fn deferred_release<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_deferred_transactions \
                 SET claim_id = NULL, claim_expires_at = NULL, claim_token_id = NULL \
                 WHERE transaction_hash = $1 AND COALESCE(claim_token_id, token_id) = $2 AND claim_id = $3 \
                   AND consumed_at IS NULL",
            )
            .bind::<sql_types::Text, _>(transaction_hash)
            .bind::<sql_types::Uuid, _>(token_id)
            .bind::<sql_types::Text, _>(claim_id)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }
}
