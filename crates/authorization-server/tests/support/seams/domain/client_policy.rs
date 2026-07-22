use serde_json::Value;

pub(crate) fn client_jwks_matching_encryption_key_count(jwks: &Value, alg: &str) -> usize {
    nazo_key_management::client_jwks_matching_encryption_key_count(jwks, alg)
}

pub(crate) fn client_jwks_contains_signing_key(jwks: &Value) -> bool {
    nazo_key_management::client_jwks_contains_signing_key(jwks)
}

pub(crate) fn validate_client_jwks(jwks: &Value) -> anyhow::Result<()> {
    nazo_key_management::validate_client_jwks(jwks).map_err(anyhow::Error::msg)
}

pub(crate) fn validate_self_signed_mtls_jwks(jwks: &Value) -> bool {
    nazo_key_management::validate_self_signed_mtls_jwks(jwks)
}

pub(crate) fn authorization_code_key(code: &str) -> String {
    format!(
        "oauth:auth_code:{}",
        crate::adapters::security::blake3_hex(code)
    )
}
