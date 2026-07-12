use fred::prelude::{Client as ValkeyClient, Expiration, KeysInterface, SetOptions};

const FAPI_HTTP_SIGNATURE_REPLAY_PREFIX: &str = "fapi_http_signature_replay:";
pub(crate) const FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS: i64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayConsumption {
    Accepted,
    Replay,
    DependencyFailure,
}

pub(crate) fn fapi_http_signature_replay_key(fingerprint: &[u8; 32]) -> String {
    format!(
        "{FAPI_HTTP_SIGNATURE_REPLAY_PREFIX}{}",
        blake3::Hash::from_bytes(*fingerprint).to_hex()
    )
}

pub(crate) async fn consume_fapi_http_signature_replay(
    valkey: &ValkeyClient,
    fingerprint: &[u8; 32],
    max_age_seconds: i64,
) -> ReplayConsumption {
    let Some(ttl_seconds) = max_age_seconds
        .checked_add(FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS)
        .and_then(|ttl| u64::try_from(ttl).ok())
    else {
        return ReplayConsumption::DependencyFailure;
    };
    match valkey
        .set::<Option<String>, _, _>(
            fapi_http_signature_replay_key(fingerprint),
            "1",
            Some(Expiration::EX(ttl_seconds.min(i64::MAX as u64) as i64)),
            Some(SetOptions::NX),
            false,
        )
        .await
    {
        Ok(reply) => classify_fapi_http_signature_replay_reply(reply.as_deref()),
        Err(_) => ReplayConsumption::DependencyFailure,
    }
}

pub(crate) fn classify_fapi_http_signature_replay_reply(reply: Option<&str>) -> ReplayConsumption {
    match reply {
        Some("OK") => ReplayConsumption::Accepted,
        None => ReplayConsumption::Replay,
        Some(_) => ReplayConsumption::DependencyFailure,
    }
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/redis_keys.rs"]
mod tests;
