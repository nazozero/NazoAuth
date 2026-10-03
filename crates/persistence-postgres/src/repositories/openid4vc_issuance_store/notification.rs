use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vci::{
    CredentialResponseEncoding, CredentialStoreError, CredentialStoreFuture, IssuanceNotification,
    NotificationHandle, StoredCredentialResponse,
};
use uuid::Uuid;

use super::super::Openid4vciRepository;
use super::access::access_authorizes_continuation;
use super::decode_selection;
use super::{
    IssuanceResponseRow, NewIssuanceResponse, insert_issuance_response, notification_event,
    protect_payload, response_encoding_name, unprotect_payload,
};
use crate::get_conn;

impl Openid4vciRepository {
    pub(super) fn notification_find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<Option<StoredCredentialResponse>, diesel::result::Error, _>(
                    async move |connection| {
                        let row = sql_query(
                            "SELECT issuance_id, token_id, request_digest, body_ciphertext, encoding, \
                                    status, dpop_nonce, expires_at, credential_selection \
                             FROM openid4vci_issuance_responses \
                             WHERE issuance_id = $1 AND request_digest = $2 AND expires_at > $3 \
                             FOR SHARE",
                        )
                        .bind::<sql_types::Uuid, _>(issuance_id)
                        .bind::<sql_types::Text, _>(request_digest)
                        .bind::<sql_types::Timestamptz, _>(now)
                        .get_result::<IssuanceResponseRow>(connection)
                        .await
                        .optional()?;
                        let Some(row) = row else {
                            return Ok(None);
                        };
                        let selection = decode_selection(row.credential_selection)?;
                        if !access_authorizes_continuation(
                            connection,
                            row.token_id,
                            token_id,
                            selection.as_ref(),
                            now,
                        )
                        .await?
                        {
                            return Ok(None);
                        }
                        let invalid = || diesel::result::Error::DeserializationError(
                            Box::new(std::io::Error::other("stored credential response is invalid")),
                        );
                        let encoding = match row.encoding.as_str() {
                            "json" => CredentialResponseEncoding::Json,
                            "jwt" => CredentialResponseEncoding::Jwt,
                            _ => return Err(invalid()),
                        };
                        let status = u16::try_from(row.status).map_err(|_| invalid())?;
                        if !matches!(status, 200 | 202) {
                            return Err(invalid());
                        }
                        Ok(Some(StoredCredentialResponse {
                            selection,
                            issuance_id: row.issuance_id,
                            token_id: row.token_id,
                            request_digest: row.request_digest,
                            body: unprotect_payload(&self.data_key, row.issuance_id, &row.body_ciphertext)?,
                            encoding,
                            status,
                            dpop_nonce: row.dpop_nonce,
                            expires_at: row.expires_at,
                        }))
                    },
                )
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let notification_id = handle.notification_id.clone();
            let notification_selection = serde_json::json!(handle.selection);
            let token_id = handle.token_id;
            let expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at, credential_selection) VALUES ($1,$2,$3,$4)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Timestamptz, _>(expires_at)
                    .bind::<sql_types::Jsonb, _>(notification_selection)
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
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_finalize_nonce_with_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let body_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let issuance_id = response.issuance_id;
            let token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let response_selection = serde_json::json!(response.selection);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let dpop_nonce = response.dpop_nonce.clone();
            let expires_at = response.expires_at;
            let notification_id = handle.notification_id.clone();
            let notification_selection = serde_json::json!(handle.selection);
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            selection: response_selection,
                            issuance_id,
                            token_id,
                            request_digest: &request_digest,
                            body_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at,
                        },
                    )
                    .await?;
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at, credential_selection) VALUES ($1,$2,$3,$4)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .bind::<sql_types::Jsonb, _>(notification_selection)
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
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_store_response<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let body_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let issuance_id = response.issuance_id;
            let token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let response_selection = serde_json::json!(response.selection);
            let dpop_nonce = response.dpop_nonce.clone();
            let expires_at = response.expires_at;
            let notification_id = handle.notification_id.clone();
            let notification_selection = serde_json::json!(handle.selection);
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            selection: response_selection,
                            issuance_id,
                            token_id,
                            request_digest: &request_digest,
                            body_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at,
                        },
                    )
                    .await?;
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at, credential_selection) VALUES ($1,$2,$3,$4)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .bind::<sql_types::Jsonb, _>(notification_selection)
                    .execute(connection)
                    .await?;
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let notification_id = handle.notification_id.clone();
            let notification_selection = serde_json::json!(handle.selection);
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at, credential_selection) VALUES ($1,$2,$3,$4)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .bind::<sql_types::Jsonb, _>(notification_selection)
                    .execute(connection)
                    .await?;
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
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_finalize_deferred_with_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let body_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let issuance_id = response.issuance_id;
            let response_token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let response_selection = serde_json::json!(response.selection);
            let dpop_nonce = response.dpop_nonce.clone();
            let response_expires_at = response.expires_at;
            let notification_id = handle.notification_id.clone();
            let notification_selection = serde_json::json!(handle.selection);
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            selection: response_selection,
                            issuance_id,
                            token_id: response_token_id,
                            request_digest: &request_digest,
                            body_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at: response_expires_at,
                        },
                    )
                    .await?;
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at, credential_selection) VALUES ($1,$2,$3,$4)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .bind::<sql_types::Jsonb, _>(notification_selection)
                    .execute(connection)
                    .await?;
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
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_record<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    let handle = sql_query(
                        "SELECT token_id, credential_selection FROM openid4vci_notifications \
                         WHERE notification_id = $1 AND expires_at > $2 FOR UPDATE",
                    )
                    .bind::<sql_types::Text, _>(&notification.notification_id)
                    .bind::<sql_types::Timestamptz, _>(notification.occurred_at)
                    .get_result::<NotificationIdentityRow>(connection)
                    .await
                    .optional()?;
                    let Some(handle) = handle else {
                        return Ok(false);
                    };
                    let selection = decode_selection(handle.credential_selection)?;
                    if !access_authorizes_continuation(
                        connection,
                        handle.token_id,
                        notification.token_id,
                        selection.as_ref(),
                        notification.occurred_at,
                    )
                    .await?
                    {
                        return Ok(false);
                    }
                    let changed = sql_query(
                        "UPDATE openid4vci_notifications \
                         SET event = $3, description = $4, occurred_at = COALESCE(occurred_at, $5) \
                         WHERE notification_id = $1 AND token_id = $2 AND expires_at > $5 \
                           AND (event IS NULL OR (event = $3 AND description IS NOT DISTINCT FROM $4))",
                    )
                    .bind::<sql_types::Text, _>(&notification.notification_id)
                    .bind::<sql_types::Uuid, _>(handle.token_id)
                    .bind::<sql_types::Text, _>(notification_event(&notification.event))
                    .bind::<sql_types::Nullable<sql_types::Text>, _>(notification.description.as_deref())
                    .bind::<sql_types::Timestamptz, _>(notification.occurred_at)
                    .execute(connection)
                    .await?;
                    Ok(changed == 1)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_issue_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_notifications \
                 (notification_id, token_id, expires_at, credential_selection) VALUES ($1,$2,$3,$4)",
            )
            .bind::<sql_types::Text, _>(&handle.notification_id)
            .bind::<sql_types::Uuid, _>(handle.token_id)
            .bind::<sql_types::Timestamptz, _>(handle.expires_at)
            .bind::<sql_types::Jsonb, _>(serde_json::json!(handle.selection))
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }
}

#[derive(diesel::QueryableByName)]
struct NotificationIdentityRow {
    #[diesel(sql_type = sql_types::Uuid)]
    token_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Jsonb>)]
    credential_selection: Option<serde_json::Value>,
}
