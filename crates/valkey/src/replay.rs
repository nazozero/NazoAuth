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
}
