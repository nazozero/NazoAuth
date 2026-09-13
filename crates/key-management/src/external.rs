//! Local verification of signatures obtained through the external-key capability.

use crate::{ExternalSignRequest, model::ExternalSigningKey, signing_algorithm_name};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{SignError, Signature};
use nazo_crypto::jwt::VerificationKey as JwtVerificationKey;
use serde_json::Value;

pub(crate) async fn sign_external(
    external: &ExternalSigningKey,
    kid: &str,
    algorithm: nazo_crypto::jwt::Algorithm,
    public_jwk: &Value,
    signing_input: &[u8],
) -> Result<Signature, SignError> {
    std::str::from_utf8(signing_input).map_err(|_| SignError::SigningFailed)?;
    let signature = external
        .signer
        .sign(ExternalSignRequest {
            kid,
            algorithm,
            key_ref: &external.key_ref,
            signing_input,
        })
        .await
        .map_err(|_| SignError::SigningFailed)?;
    if signature.as_bytes().is_empty() {
        return Err(SignError::SigningFailed);
    }
    verify_external_jwt_signature(
        external,
        kid,
        algorithm,
        signing_input,
        signature.as_bytes(),
        public_jwk,
    )
    .map_err(|_| SignError::SigningFailed)?;
    Ok(signature)
}

fn verify_external_jwt_signature(
    external: &ExternalSigningKey,
    kid: &str,
    alg: nazo_crypto::jwt::Algorithm,
    signing_input: &[u8],
    signature: &[u8],
    public_jwk: &Value,
) -> nazo_crypto::Result<()> {
    let decoding_key = decoding_key_from_public_jwk(public_jwk, alg)
        .ok_or(nazo_crypto::CryptoError::InvalidKey)?;
    if nazo_crypto::signature::verify(alg, &decoding_key, signing_input, signature).is_err() {
        tracing::error!(
            kid,
            alg = ?alg,
            key_ref = %external.key_ref,
            "external signer returned a signature that failed local verification"
        );
        return Err(nazo_crypto::CryptoError::InvalidSignature);
    }
    Ok(())
}

pub(super) fn decoding_key_from_public_jwk(
    key: &Value,
    algorithm: nazo_crypto::jwt::Algorithm,
) -> Option<JwtVerificationKey> {
    let expected_algorithm = signing_algorithm_name(algorithm)?;
    if key
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|value| value != expected_algorithm)
        || key.get("d").is_some()
        || key
            .get("use")
            .and_then(Value::as_str)
            .is_some_and(|value| value != "sig")
    {
        return None;
    }
    match algorithm {
        nazo_crypto::jwt::Algorithm::EdDSA => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32 {
                return None;
            }
            JwtVerificationKey::from_ed_components(x).ok()
        }
        nazo_crypto::jwt::Algorithm::RS256 | nazo_crypto::jwt::Algorithm::PS256 => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let modulus = key.get("n")?.as_str()?;
            let exponent = key.get("e")?.as_str()?;
            if !nazo_auth::rsa_public_key_components_are_safe(
                &URL_SAFE_NO_PAD.decode(modulus).ok()?,
                &URL_SAFE_NO_PAD.decode(exponent).ok()?,
            ) {
                return None;
            }
            JwtVerificationKey::from_rsa_components(modulus, exponent).ok()
        }
        nazo_crypto::jwt::Algorithm::ES256 => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x")?.as_str()?;
            let y = key.get("y")?.as_str()?;
            let x_bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            let y_bytes = URL_SAFE_NO_PAD.decode(y).ok()?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return None;
            }
            let mut point = [0_u8; 65];
            point[0] = 4;
            point[1..33].copy_from_slice(&x_bytes);
            point[33..].copy_from_slice(&y_bytes);
            nazo_crypto::ec::normalize_p256_public_key(&point).ok()?;
            JwtVerificationKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "../tests/unit/external_semantics.rs"]
mod tests;
