const FAPI_HTTP_SIGNATURE_REPLAY_PREFIX: &str = "fapi_http_signature_replay:";

pub(crate) fn fapi_http_signature_replay(fingerprint: &[u8; 32]) -> String {
    format!(
        "{FAPI_HTTP_SIGNATURE_REPLAY_PREFIX}{}",
        blake3::Hash::from_bytes(*fingerprint).to_hex()
    )
}
