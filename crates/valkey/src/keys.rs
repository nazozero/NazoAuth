const FAPI_HTTP_SIGNATURE_REPLAY_PREFIX: &str = "fapi_http_signature_replay:";

pub(crate) fn fapi_http_signature_replay(fingerprint: &[u8; 32]) -> String {
    format!(
        "{FAPI_HTTP_SIGNATURE_REPLAY_PREFIX}{}",
        blake3::Hash::from_bytes(*fingerprint).to_hex()
    )
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

pub(crate) fn dpop_replay(jkt: &str, jti: &str) -> String {
    format!("oauth:dpop:jti:{jkt}:{}", blake3_hex(jti))
}

pub(crate) fn dpop_nonce(nonce: &str) -> String {
    format!("oauth:dpop:nonce:{}", blake3_hex(nonce))
}

pub(crate) fn private_key_jwt_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:client_assertion:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}

pub(crate) fn jar_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:jar:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}

pub(crate) fn jwt_bearer_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:jwt_bearer:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}
