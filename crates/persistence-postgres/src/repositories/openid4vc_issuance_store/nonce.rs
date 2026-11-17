use diesel::{sql_query, sql_types};
use diesel_async::RunQueryDsl;
use jiff::Timestamp;
use nazo_openid4vci::{CredentialStoreError, CredentialStoreFuture, NonceRecord};

use super::super::Openid4vciRepository;
use crate::get_conn;

impl Openid4vciRepository {
    pub(super) fn nonce_issue<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_nonces (nonce_hash, expires_at) VALUES ($1, $2) \
                 ON CONFLICT (nonce_hash) DO NOTHING",
            )
            .bind::<sql_types::Text, _>(&nonce.nonce_hash)
            .bind::<sql_types::Timestamptz, _>((nonce.expires_at).to_diesel())
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    pub(super) fn nonce_claim<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let claim_expires_at = now + jiff::SignedDuration::from_mins(5);
            let changed = sql_query(
                "UPDATE openid4vci_nonces SET claim_id = $2, claim_expires_at = $3 \
                 WHERE nonce_hash = $1 AND consumed_at IS NULL AND expires_at > $4 \
                   AND (claim_id IS NULL OR claim_expires_at <= $4)",
            )
            .bind::<sql_types::Text, _>(nonce_hash)
            .bind::<sql_types::Text, _>(claim_id)
            .bind::<sql_types::Timestamptz, _>((claim_expires_at).to_diesel())
            .bind::<sql_types::Timestamptz, _>((now).to_diesel())
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    pub(super) fn nonce_release<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        _now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_nonces SET claim_id = NULL, claim_expires_at = NULL \
                 WHERE nonce_hash = $1 AND claim_id = $2 AND consumed_at IS NULL",
            )
            .bind::<sql_types::Text, _>(nonce_hash)
            .bind::<sql_types::Text, _>(claim_id)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }
}

use jiff_diesel::ToDiesel as _;
