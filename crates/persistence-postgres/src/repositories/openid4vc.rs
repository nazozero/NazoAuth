use std::str::FromStr;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{DateTime, Utc};
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::{
    AuthorizationOfferPort, CredentialAccess, CredentialAuthorization, CredentialStoreError,
    CredentialStoreFuture, CredentialStorePort, DeferredCredential, IssuanceNotification,
    NonceRecord, NotificationHandle, StoredCredentialOffer,
};
use nazo_openid4vp::{
    PresentationResult, PresentationStoreError, PresentationStoreFuture, PresentationStorePort,
    PresentationTransaction, StoredPresentation,
};
use rand::Rng;
use uuid::Uuid;

use crate::DbPool;

#[derive(Clone)]
pub struct Openid4vciRepository {
    pool: DbPool,
    data_key: [u8; 32],
}

impl Openid4vciRepository {
    #[must_use]
    pub fn new(pool: DbPool, data_key: [u8; 32]) -> Self {
        Self { pool, data_key }
    }

    pub async fn insert_offer(
        &self,
        offer: &StoredCredentialOffer,
        issuer_state_hash: Option<&str>,
        pre_authorized_code_hash: Option<&str>,
        tx_code_hash: Option<&str>,
    ) -> Result<(), CredentialStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        sql_query(
            "INSERT INTO openid4vci_offers \
             (id,tenant_id,subject_id,credential_configuration_ids,grants_ciphertext,issuer_state_hash,pre_authorized_code_hash,tx_code_hash,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind::<sql_types::Uuid, _>(offer.id)
        .bind::<sql_types::Uuid, _>(offer.tenant_id)
        .bind::<sql_types::Nullable<sql_types::Uuid>, _>(offer.subject_id)
        .bind::<sql_types::Jsonb, _>(serde_json::json!(offer.credential_configuration_ids))
        .bind::<sql_types::Binary, _>(protect_payload(
            &self.data_key,
            offer.id,
            &serde_json::to_vec(&offer.grants).map_err(|_| CredentialStoreError::InvalidTransition)?,
        )?)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(issuer_state_hash)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(pre_authorized_code_hash)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(tx_code_hash)
        .bind::<sql_types::Timestamptz, _>(offer.expires_at)
        .execute(&mut connection)
        .await
        .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(())
    }
}

impl CredentialStorePort for Openid4vciRepository {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
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
                   AND openid4vci_access_grants.client_id = EXCLUDED.client_id",
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
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn offer<'a>(
        &'a self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let row = sql_query(
                "SELECT id,tenant_id,subject_id,credential_configuration_ids,grants_ciphertext,expires_at \
                 FROM openid4vci_offers WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2",
            )
            .bind::<sql_types::Uuid, _>(id)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<OfferRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            row.map(|row| row.into_domain(&self.data_key)).transpose()
        })
    }

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection.transaction::<Option<CredentialAuthorization>, diesel::result::Error, _>(async move |connection| {
                let row = sql_query(
                    "SELECT id,tenant_id,subject_id,credential_configuration_ids,tx_code_hash,expires_at \
                     FROM openid4vci_offers WHERE pre_authorized_code_hash = $1 \
                       AND consumed_at IS NULL AND expires_at > $2 FOR UPDATE",
                )
                .bind::<sql_types::Text, _>(code_hash)
                .bind::<sql_types::Timestamptz, _>(now)
                .get_result::<PreAuthorizedOfferRow>(connection)
                .await
                .optional()?;
                let Some(row) = row else { return Ok(None); };
                if !tx_code_matches(row.tx_code_hash.as_deref(), tx_code) { return Ok(None); }
                let Some(subject_id) = row.subject_id else { return Ok(None); };
                let configuration_ids = serde_json::from_value(row.credential_configuration_ids)
                    .map_err(decode_error)?;
                sql_query("UPDATE openid4vci_offers SET consumed_at = $2 WHERE id = $1")
                    .bind::<sql_types::Uuid, _>(row.id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .execute(connection)
                    .await?;
                Ok(Some(CredentialAuthorization {
                    tenant_id: row.tenant_id,
                    subject_id,
                    client_id: client_id.to_owned(),
                    configuration_ids,
                    credential_identifiers: Vec::new(),
                    expires_at: (now + chrono::Duration::minutes(10)).min(row.expires_at),
                }))
            }).await.map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_nonces (nonce_hash, expires_at) VALUES ($1, $2) \
                 ON CONFLICT (nonce_hash) DO NOTHING",
            )
            .bind::<sql_types::Text, _>(&nonce.nonce_hash)
            .bind::<sql_types::Timestamptz, _>(nonce.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn consume_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_nonces SET consumed_at = $2 \
                 WHERE nonce_hash = $1 AND consumed_at IS NULL AND expires_at > $2",
            )
            .bind::<sql_types::Text, _>(nonce_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
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

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
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
                  holder_bindings, payload_ciphertext, ready_at, expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
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
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn consume_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<Option<DeferredCredential>, diesel::result::Error, _>(async move |connection| {
                    let row = sql_query(
                        "UPDATE openid4vci_deferred_transactions SET consumed_at = $3 \
                         WHERE transaction_hash = $1 AND token_id = $2 AND consumed_at IS NULL \
                           AND ready_at <= $3 AND expires_at > $3 \
                         RETURNING id, transaction_hash, token_id, credential_configuration_id, \
                           credential_format, holder_bindings, payload_ciphertext, ready_at, expires_at",
                    )
                    .bind::<sql_types::Text, _>(transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .get_result::<DeferredRow>(connection)
                    .await
                    .optional()?;
                    let Some(row) = row else { return Ok(None); };
                    let access = sql_query(
                        "SELECT token_id, tenant_id, subject_id, client_id, credential_configuration_ids, \
                         credential_identifiers, dpop_jkt, expires_at FROM openid4vci_access_grants \
                         WHERE token_id = $1",
                    )
                    .bind::<sql_types::Uuid, _>(token_id)
                    .get_result::<AccessRow>(connection)
                    .await?;
                    let mut deferred = row.into_domain(access.try_into()? )?;
                    deferred.payload_ciphertext = unprotect_payload(
                        &self.data_key,
                        deferred.id,
                        &deferred.payload_ciphertext,
                    )?;
                    Ok(Some(deferred))
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_notifications \
                 SET event = $3, description = $4, occurred_at = $5 \
                 WHERE notification_id = $1 AND token_id = $2 AND event IS NULL AND expires_at > $5",
            )
            .bind::<sql_types::Text, _>(&notification.notification_id)
            .bind::<sql_types::Uuid, _>(notification.token_id)
            .bind::<sql_types::Text, _>(notification_event(&notification.event))
            .bind::<sql_types::Nullable<sql_types::Text>, _>(notification.description.as_deref())
            .bind::<sql_types::Timestamptz, _>(notification.occurred_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_notifications \
                 (notification_id, token_id, expires_at) VALUES ($1,$2,$3)",
            )
            .bind::<sql_types::Text, _>(&handle.notification_id)
            .bind::<sql_types::Uuid, _>(handle.token_id)
            .bind::<sql_types::Timestamptz, _>(handle.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }
}

impl AuthorizationOfferPort for Openid4vciRepository {
    fn consume_authorization_offer<'a>(
        &'a self,
        issuer_state_hash: &'a str,
        subject_id: Uuid,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<Option<CredentialAuthorization>, diesel::result::Error, _>(
                    async move |connection| {
                        let row = sql_query(
                            "SELECT id,tenant_id,subject_id,credential_configuration_ids,expires_at \
                             FROM openid4vci_offers WHERE issuer_state_hash = $1 \
                               AND subject_id = $2 AND consumed_at IS NULL AND expires_at > $3 FOR UPDATE",
                        )
                        .bind::<sql_types::Text, _>(issuer_state_hash)
                        .bind::<sql_types::Uuid, _>(subject_id)
                        .bind::<sql_types::Timestamptz, _>(now)
                        .get_result::<AuthorizationOfferRow>(connection)
                        .await
                        .optional()?;
                        let Some(row) = row else { return Ok(None); };
                        let configuration_ids = serde_json::from_value(row.credential_configuration_ids)
                            .map_err(decode_error)?;
                        sql_query("UPDATE openid4vci_offers SET consumed_at = $2 WHERE id = $1")
                            .bind::<sql_types::Uuid, _>(row.id)
                            .bind::<sql_types::Timestamptz, _>(now)
                            .execute(connection)
                            .await?;
                        Ok(Some(CredentialAuthorization {
                            tenant_id: row.tenant_id,
                            subject_id,
                            client_id: client_id.to_owned(),
                            configuration_ids,
                            credential_identifiers: Vec::new(),
                            expires_at: (now + chrono::Duration::minutes(10)).min(row.expires_at),
                        }))
                    },
                )
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }
}

#[derive(Clone)]
pub struct Openid4vpRepository {
    pool: DbPool,
    tenant_id: Uuid,
    data_key: [u8; 32],
}

impl Openid4vpRepository {
    #[must_use]
    pub fn new(pool: DbPool, tenant_id: Uuid, data_key: [u8; 32]) -> Self {
        Self {
            pool,
            tenant_id,
            data_key,
        }
    }
}

impl PresentationStorePort for Openid4vpRepository {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
    ) -> PresentationStoreFuture<'a, Result<(), PresentationStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let state_hash = blake3::hash(transaction.request.state.as_bytes())
                .to_hex()
                .to_string();
            let protected_private_key = transaction
                .response_encryption_private_key
                .as_deref()
                .map(|key| protect_result(&self.data_key, transaction.id, key))
                .transpose()?;
            sql_query(
                "INSERT INTO openid4vp_transactions \
                 (id, tenant_id, client_id_prefix, request_method, response_mode, \
                  wallet_authorization_endpoint, state_hash, request, request_object, request_uri, \
                  ephemeral_private_key_ciphertext, expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            )
            .bind::<sql_types::Uuid, _>(transaction.id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Text, _>(transaction.client_id_prefix.as_str())
            .bind::<sql_types::Text, _>(transaction.request_method.as_str())
            .bind::<sql_types::Text, _>(transaction.response_mode.as_str())
            .bind::<sql_types::Text, _>(&transaction.wallet_authorization_endpoint)
            .bind::<sql_types::Text, _>(state_hash)
            .bind::<sql_types::Jsonb, _>(
                serde_json::to_value(&transaction.request)
                    .map_err(|_| PresentationStoreError::InvalidTransition)?,
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(transaction.request_object.as_deref())
            .bind::<sql_types::Nullable<sql_types::Text>, _>(transaction.request_uri.as_deref())
            .bind::<sql_types::Nullable<sql_types::Binary>, _>(protected_private_key)
            .bind::<sql_types::Timestamptz, _>(transaction.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let row = load_presentation(&mut connection, transaction_id, now)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            row.map(|value| value.transaction_with_key(&self.data_key))
                .transpose()
        })
    }

    fn complete<'a>(
        &'a self,
        transaction_id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let encoded = serde_json::to_vec(result)
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
            let encoded = protect_result(&self.data_key, transaction_id, &encoded)?;
            let changed = sql_query(
                "UPDATE openid4vp_transactions SET result_ciphertext = $4, completed_at = $3 \
                 WHERE id = $1 AND state_hash = $2 AND completed_at IS NULL AND expires_at > $3",
            )
            .bind::<sql_types::Uuid, _>(transaction_id)
            .bind::<sql_types::Text, _>(state_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .bind::<sql_types::Binary, _>(encoded)
            .execute(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<StoredPresentation>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let row = load_presentation(&mut connection, transaction_id, now)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            row.map(|value| value.stored(&self.data_key)).transpose()
        })
    }
}

use diesel::OptionalExtension;

#[derive(QueryableByName)]
struct AccessRow {
    #[diesel(sql_type = sql_types::Uuid)]
    token_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    subject_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_id: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_identifiers: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    dpop_jkt: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct OfferRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    subject_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Binary)]
    grants_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

impl OfferRow {
    fn into_domain(
        self,
        data_key: &[u8; 32],
    ) -> Result<StoredCredentialOffer, CredentialStoreError> {
        let grants = unprotect_payload(data_key, self.id, &self.grants_ciphertext)
            .map_err(|_| CredentialStoreError::InvalidTransition)?;
        Ok(StoredCredentialOffer {
            id: self.id,
            tenant_id: self.tenant_id,
            subject_id: self.subject_id,
            credential_configuration_ids: serde_json::from_value(self.credential_configuration_ids)
                .map_err(|_| CredentialStoreError::InvalidTransition)?,
            grants: serde_json::from_slice(&grants)
                .map_err(|_| CredentialStoreError::InvalidTransition)?,
            expires_at: self.expires_at,
        })
    }
}

#[derive(QueryableByName)]
struct PreAuthorizedOfferRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    subject_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    tx_code_hash: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct AuthorizationOfferRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

fn tx_code_matches(expected: Option<&str>, presented: Option<&str>) -> bool {
    match (expected, presented) {
        (None, None) => true,
        (Some(expected), Some(presented)) => PasswordHash::new(expected).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(presented.as_bytes(), &hash)
                .is_ok()
        }),
        _ => false,
    }
}

impl TryFrom<AccessRow> for CredentialAccess {
    type Error = diesel::result::Error;
    fn try_from(row: AccessRow) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: row.token_id,
            tenant_id: row.tenant_id,
            subject_id: row.subject_id,
            client_id: row.client_id,
            configuration_ids: serde_json::from_value(row.credential_configuration_ids)
                .map_err(decode_error)?,
            credential_identifiers: serde_json::from_value(row.credential_identifiers)
                .map_err(decode_error)?,
            dpop_jkt: row.dpop_jkt,
            expires_at: row.expires_at,
        })
    }
}

#[derive(QueryableByName)]
struct DeferredRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    transaction_hash: String,
    #[diesel(sql_type = sql_types::Uuid)]
    token_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    credential_configuration_id: String,
    #[diesel(sql_type = sql_types::Text)]
    credential_format: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    holder_bindings: serde_json::Value,
    #[diesel(sql_type = sql_types::Binary)]
    payload_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    ready_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

impl DeferredRow {
    fn into_domain(
        self,
        access: CredentialAccess,
    ) -> Result<DeferredCredential, diesel::result::Error> {
        if self.token_id != access.token_id {
            return Err(diesel::result::Error::NotFound);
        }
        Ok(DeferredCredential {
            id: self.id,
            transaction_hash: self.transaction_hash,
            access,
            configuration_id: self.credential_configuration_id,
            format: CredentialFormat::from_str(&self.credential_format).map_err(|error| {
                decode_error(serde_json::Error::io(std::io::Error::other(error)))
            })?,
            holder_bindings: serde_json::from_value(self.holder_bindings).map_err(decode_error)?,
            payload_ciphertext: self.payload_ciphertext,
            ready_at: self.ready_at,
            expires_at: self.expires_at,
        })
    }
}

#[derive(QueryableByName)]
struct PresentationRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_id_prefix: String,
    #[diesel(sql_type = sql_types::Text)]
    request_method: String,
    #[diesel(sql_type = sql_types::Text)]
    response_mode: String,
    #[diesel(sql_type = sql_types::Text)]
    wallet_authorization_endpoint: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    request: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_object: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_uri: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    ephemeral_private_key_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    result_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    completed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
}

impl PresentationRow {
    fn transaction(&self) -> Result<PresentationTransaction, PresentationStoreError> {
        Ok(PresentationTransaction {
            id: self.id,
            client_id_prefix: parse_client_id_prefix(&self.client_id_prefix)?,
            request_method: self
                .request_method
                .parse()
                .map_err(|_| PresentationStoreError::InvalidTransition)?,
            response_mode: parse_response_mode(&self.response_mode)?,
            wallet_authorization_endpoint: self.wallet_authorization_endpoint.clone(),
            request: serde_json::from_value(self.request.clone())
                .map_err(|_| PresentationStoreError::InvalidTransition)?,
            request_object: self.request_object.clone(),
            request_uri: self.request_uri.clone(),
            response_encryption_private_key: None,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
    fn transaction_with_key(
        &self,
        data_key: &[u8; 32],
    ) -> Result<PresentationTransaction, PresentationStoreError> {
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        Ok(transaction)
    }
    fn stored(self, data_key: &[u8; 32]) -> Result<StoredPresentation, PresentationStoreError> {
        let decrypted = self
            .result_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        let completed = decrypted
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        if completed
            .as_ref()
            .map(|result: &PresentationResult| result.completed_at.timestamp_micros())
            != self
                .completed_at
                .map(|completed_at| completed_at.timestamp_micros())
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        Ok(StoredPresentation {
            transaction,
            completed,
        })
    }
}

async fn load_presentation(
    connection: &mut diesel_async::AsyncPgConnection,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<PresentationRow>, diesel::result::Error> {
    sql_query(
        "SELECT id, client_id_prefix, request_method, response_mode, wallet_authorization_endpoint, \
         request, request_object, request_uri, ephemeral_private_key_ciphertext, result_ciphertext, completed_at, expires_at, created_at \
         FROM openid4vp_transactions WHERE id = $1 AND expires_at > $2",
    )
    .bind::<sql_types::Uuid, _>(id)
    .bind::<sql_types::Timestamptz, _>(now)
    .get_result(connection)
    .await
    .optional()
}

fn parse_client_id_prefix(
    value: &str,
) -> Result<nazo_openid4vp::ClientIdPrefix, PresentationStoreError> {
    match value {
        "redirect_uri" => Ok(nazo_openid4vp::ClientIdPrefix::RedirectUri),
        "x509_san_dns" => Ok(nazo_openid4vp::ClientIdPrefix::X509SanDns),
        "x509_hash" => Ok(nazo_openid4vp::ClientIdPrefix::X509Hash),
        _ => Err(PresentationStoreError::InvalidTransition),
    }
}

fn parse_response_mode(
    value: &str,
) -> Result<nazo_openid4vp::ResponseMode, PresentationStoreError> {
    match value {
        "direct_post" => Ok(nazo_openid4vp::ResponseMode::DirectPost),
        "direct_post.jwt" => Ok(nazo_openid4vp::ResponseMode::DirectPostJwt),
        _ => Err(PresentationStoreError::InvalidTransition),
    }
}

fn notification_event(event: &nazo_openid4vci::NotificationEvent) -> &'static str {
    match event {
        nazo_openid4vci::NotificationEvent::CredentialAccepted => "credential_accepted",
        nazo_openid4vci::NotificationEvent::CredentialFailure => "credential_failure",
        nazo_openid4vci::NotificationEvent::CredentialDeleted => "credential_deleted",
    }
}

fn decode_error(error: serde_json::Error) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(Box::new(error))
}

fn protect_result(
    key: &[u8; 32],
    transaction_id: Uuid,
    plaintext: &[u8],
) -> Result<Vec<u8>, PresentationStoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PresentationStoreError::Unavailable)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(
        &cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: transaction_id.as_bytes(),
                },
            )
            .map_err(|_| PresentationStoreError::Unavailable)?,
    );
    Ok(protected)
}

fn protect_payload(
    key: &[u8; 32],
    transaction_id: Uuid,
    plaintext: &[u8],
) -> Result<Vec<u8>, CredentialStoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CredentialStoreError::Unavailable)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(
        &cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: transaction_id.as_bytes(),
                },
            )
            .map_err(|_| CredentialStoreError::Unavailable)?,
    );
    Ok(protected)
}

fn unprotect_payload(
    key: &[u8; 32],
    transaction_id: Uuid,
    protected: &[u8],
) -> Result<Vec<u8>, diesel::result::Error> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(diesel::result::Error::RollbackTransaction)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| diesel::result::Error::RollbackTransaction)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| diesel::result::Error::RollbackTransaction)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: transaction_id.as_bytes(),
            },
        )
        .map_err(|_| diesel::result::Error::RollbackTransaction)
}

fn unprotect_result(
    key: &[u8; 32],
    transaction_id: Uuid,
    protected: &[u8],
) -> Result<Vec<u8>, PresentationStoreError> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(PresentationStoreError::InvalidTransition)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| PresentationStoreError::Unavailable)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: transaction_id.as_bytes(),
            },
        )
        .map_err(|_| PresentationStoreError::InvalidTransition)
}
