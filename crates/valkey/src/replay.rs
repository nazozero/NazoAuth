use crate::{Error, ValkeyConnection, command, keys};

const FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS: i64 = 5;

#[derive(Clone, Debug)]
pub struct ReplayStore {
    connection: ValkeyConnection,
}

impl ReplayStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    /// Atomically consumes a FAPI HTTP-signature fingerprint.
    ///
    /// `true` means this caller consumed it; `false` means it was already present.
    pub async fn consume_fapi_http_signature(
        &self,
        fingerprint: &[u8; 32],
        max_age_seconds: i64,
    ) -> Result<bool, Error> {
        let ttl_seconds = max_age_seconds
            .checked_add(FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS)
            .and_then(|ttl| u64::try_from(ttl).ok())
            .ok_or_else(|| Error::unexpected("invalid FAPI HTTP-signature replay TTL"))?;
        command::set_ex_nx(
            &self.connection,
            keys::fapi_http_signature_replay(fingerprint),
            "1",
            ttl_seconds,
        )
        .await
    }

    pub async fn consume_dpop(
        &self,
        jkt: &str,
        jti: &str,
        ttl_seconds: u64,
    ) -> Result<bool, Error> {
        self.consume_key(keys::dpop_replay(jkt, jti), ttl_seconds)
            .await
    }

    pub async fn issue_dpop_nonce(&self, nonce: &str, ttl_seconds: u64) -> Result<(), Error> {
        command::set_ex(&self.connection, keys::dpop_nonce(nonce), "1", ttl_seconds).await
    }

    pub async fn consume_dpop_nonce(&self, nonce: &str) -> Result<bool, Error> {
        Ok(command::take(&self.connection, keys::dpop_nonce(nonce))
            .await?
            .is_some())
    }

    pub async fn consume_private_key_jwt(
        &self,
        client_id: &str,
        jti: &str,
        ttl_seconds: u64,
    ) -> Result<bool, Error> {
        self.consume_key(keys::private_key_jwt_replay(client_id, jti), ttl_seconds)
            .await
    }

    pub async fn consume_jar(
        &self,
        client_id: &str,
        jti: &str,
        ttl_seconds: u64,
    ) -> Result<bool, Error> {
        self.consume_key(keys::jar_replay(client_id, jti), ttl_seconds)
            .await
    }

    pub async fn consume_jwt_bearer(
        &self,
        client_id: &str,
        jti: &str,
        ttl_seconds: u64,
    ) -> Result<bool, Error> {
        self.consume_key(keys::jwt_bearer_replay(client_id, jti), ttl_seconds)
            .await
    }

    async fn consume_key(&self, key: String, ttl_seconds: u64) -> Result<bool, Error> {
        command::set_ex_nx(&self.connection, key, "1", ttl_seconds).await
    }
}
