use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vci::{
    CredentialStoreError, CredentialStoreFuture, DeferredCredential, DeferredCredentialClaim,
    StoredCredentialResponse,
};
use uuid::Uuid;

use super::super::Openid4vciRepository;
use super::access::access_authorizes_continuation;
use super::{
    DeferredClaimRow, DeferredIdentityRow, NewIssuanceResponse, decode_selection,
    insert_issuance_response, protect_payload, response_encoding_name, unprotect_payload,
};
use crate::get_conn;

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
                &credential.payload_ciphertext,
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
                &credential.payload_ciphertext,
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
                &credential.payload_ciphertext,
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
                &credential.payload_ciphertext,
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
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<
        'a,
        Result<nazo_openid4vci::DeferredClaimOutcome, CredentialStoreError>,
    > {
        Box::pin(async move {
            let claim_expires_at = now + chrono::Duration::minutes(5);
            let claim_id_owned = claim_id.to_owned();
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<nazo_openid4vci::DeferredClaimOutcome, diesel::result::Error, _>(
                    async move |connection| {
                        let current_token_id = token_id;
                        // Read immutable intent identity, then lock the grants before the transaction owner.
                        let identity = sql_query(
                            "SELECT deferred.token_id, deferred.credential_selection, \
                                    deferred.credential_configuration_id \
                             FROM openid4vci_deferred_transactions AS deferred \
                             JOIN openid4vci_access_grants AS source ON source.token_id = deferred.token_id \
                             WHERE deferred.transaction_hash = $1 AND deferred.consumed_at IS NULL \
                               AND deferred.expires_at > $2 \
                               AND deferred.authorization_id IS NOT DISTINCT FROM source.authorization_id",
                        )
                        .bind::<sql_types::Text, _>(transaction_hash)
                        .bind::<sql_types::Timestamptz, _>(now)
                        .get_result::<DeferredIdentityRow>(connection)
                        .await
                        .optional()?;
                        let Some(identity) = identity else {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        };
                        let selection = decode_selection(identity.credential_selection)?;
                        if selection.as_ref().is_some_and(|selection| {
                            selection.configuration_id != identity.credential_configuration_id
                        }) || !access_authorizes_continuation(
                            connection,
                            identity.token_id,
                            current_token_id,
                            selection.as_ref(),
                            now,
                        )
                        .await?
                        {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        }
                        let token_id = identity.token_id;
                        // Lock and classify the same owned live row in one SQL
                        // statement. Only the Claimed branch acquires a lease.
                        let row = sql_query(
                            "WITH observed AS MATERIALIZED ( \
                               SELECT deferred.id AS deferred_id, \
                                       deferred.authorization_id AS deferred_authorization_id, \
                                       deferred.credential_selection AS deferred_credential_selection, \
                                      deferred.transaction_hash AS deferred_transaction_hash, \
                                      deferred.token_id AS deferred_token_id, \
                                      deferred.credential_configuration_id AS deferred_configuration_id, \
                                      deferred.credential_format AS deferred_format, \
                                      deferred.holder_bindings AS deferred_holder_bindings, \
                                      deferred.payload_ciphertext AS deferred_payload_ciphertext, \
                                      deferred.ready_at AS deferred_ready_at, \
                                      deferred.expires_at AS deferred_expires_at, \
                                      deferred.claim_id AS observed_claim_id, \
                                      deferred.claim_expires_at AS observed_claim_expires_at, \
                                      access.token_id AS access_token_id, \
                                       access.authorization_id AS access_authorization_id, \
                                       access.mtls_x5t_s256 AS access_mtls_x5t_s256, \
                                      access.tenant_id AS access_tenant_id, \
                                      access.subject_id AS access_subject_id, \
                                      access.client_id AS access_client_id, \
                                      access.proof_origin AS access_proof_origin, \
                                      access.credential_configuration_ids AS access_configuration_ids, \
                                      access.credential_identifiers AS access_credential_identifiers, \
                                      access.dpop_jkt AS access_dpop_jkt, \
                                      access.expires_at AS access_expires_at \
                               FROM openid4vci_deferred_transactions AS deferred \
                               JOIN openid4vci_access_grants AS access ON access.token_id = deferred.token_id \
                               WHERE deferred.transaction_hash = $1 AND deferred.token_id = $2 \
                                 AND deferred.consumed_at IS NULL AND deferred.expires_at > $5 \
                               FOR UPDATE OF deferred \
                             ), claimed AS ( \
                               UPDATE openid4vci_deferred_transactions AS target \
                               SET claim_id = $3, claim_expires_at = $4, claim_token_id = $6 FROM observed \
                               WHERE target.id = observed.deferred_id AND observed.deferred_ready_at <= $5 \
                                 AND (observed.observed_claim_id IS NULL OR observed.observed_claim_expires_at <= $5) \
                               RETURNING target.id \
                             ) \
                             SELECT observed.*, \
                               CASE WHEN EXISTS (SELECT 1 FROM claimed) THEN 'claimed' \
                                    WHEN deferred_ready_at > $5 THEN 'pending' \
                                    WHEN observed_claim_id IS NOT NULL AND observed_claim_expires_at > $5 THEN 'busy' \
                                    ELSE 'inconsistent' END AS claim_outcome, \
                               CASE WHEN deferred_ready_at > $5 THEN deferred_ready_at \
                                    ELSE observed_claim_expires_at END AS retry_at \
                             FROM observed"
                        )
                        .bind::<sql_types::Text, _>(transaction_hash)
                        .bind::<sql_types::Uuid, _>(token_id)
                        .bind::<sql_types::Text, _>(claim_id)
                        .bind::<sql_types::Timestamptz, _>(claim_expires_at)
                        .bind::<sql_types::Timestamptz, _>(now)
                        .bind::<sql_types::Uuid, _>(current_token_id)
                        .get_result::<DeferredClaimRow>(connection)
                        .await
                        .optional()?;
                        let Some(row) = row else {
                            return Ok(nazo_openid4vci::DeferredClaimOutcome::Invalid);
                        };
                        if row.claim_outcome == "pending" || row.claim_outcome == "busy" {
                            let retry_at = row.retry_at.ok_or_else(|| {
                                diesel::result::Error::DeserializationError(Box::new(std::io::Error::other("deferred retry time is missing")))
                            })?;
                            return Ok(if row.claim_outcome == "pending" {
                                nazo_openid4vci::DeferredClaimOutcome::Pending { retry_at }
                            } else {
                                nazo_openid4vci::DeferredClaimOutcome::Busy { retry_at }
                            });
                        }
                        if row.claim_outcome != "claimed" {
                            return Err(diesel::result::Error::DeserializationError(Box::new(std::io::Error::other("deferred claim outcome is inconsistent"))));
                        }
                        let (deferred_row, access_row) = row.into_parts();
                        let mut deferred = deferred_row.into_domain(access_row.try_into()?)?;
                        deferred.payload_ciphertext = unprotect_payload(
                            &self.data_key,
                            deferred.id,
                            &deferred.payload_ciphertext,
                        )?;
                        Ok(nazo_openid4vci::DeferredClaimOutcome::Claimed(Box::new(DeferredCredentialClaim {
                            credential: deferred,
                            claim_id: claim_id_owned,
                        })))
                    },
                )
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
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
