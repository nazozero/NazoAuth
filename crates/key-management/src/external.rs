//! Local verification of signatures obtained through the external-key capability.

use crate::local::SigningBackend;
use crate::{ExternalSignRequest, model::ExternalSigningKey, signing_algorithm_name};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{SignError, Signature};
use serde_json::Value;
use std::{future::Future, pin::Pin};

pub(crate) struct ExternalBackend<'a> {
    pub(crate) external: &'a ExternalSigningKey,
    pub(crate) kid: &'a str,
    pub(crate) algorithm: jsonwebtoken::Algorithm,
    pub(crate) public_jwk: &'a Value,
}

impl SigningBackend for ExternalBackend<'_> {
    fn sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignError>> + Send + 'a>> {
        Box::pin(async move {
            let input = std::str::from_utf8(signing_input).map_err(|_| SignError::SigningFailed)?;
            let signature = self
                .external
                .signer
                .sign(ExternalSignRequest {
                    kid: self.kid,
                    algorithm: self.algorithm,
                    key_ref: &self.external.key_ref,
                    signing_input,
                })
                .await
                .map_err(|_| SignError::SigningFailed)?;
            if signature.as_bytes().is_empty() {
                return Err(SignError::SigningFailed);
            }
            let encoded = URL_SAFE_NO_PAD.encode(signature.as_bytes());
            verify_external_jwt_signature(
                self.external,
                self.kid,
                self.algorithm,
                input,
                &encoded,
                self.public_jwk,
            )
            .map_err(|_| SignError::SigningFailed)?;
            Ok(signature)
        })
    }
}

fn verify_external_jwt_signature(
    external: &ExternalSigningKey,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    signing_input: &str,
    signature: &str,
    public_jwk: &Value,
) -> jsonwebtoken::errors::Result<()> {
    let decoding_key = decoding_key_from_public_jwk(public_jwk, alg).ok_or_else(|| {
        jwt_provider_error("active external signer public JWK is not usable for verification")
    })?;
    match jsonwebtoken::crypto::verify(signature, signing_input.as_bytes(), &decoding_key, alg) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => {
            tracing::error!(
                kid,
                alg = ?alg,
                key_ref = %external.key_ref,
                "external signer returned a signature that failed local verification"
            );
            Err(jwt_provider_error(
                "external signer returned signature that does not verify with active public JWK",
            ))
        }
    }
}

pub(super) fn decoding_key_from_public_jwk(
    key: &Value,
    algorithm: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
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
        jsonwebtoken::Algorithm::EdDSA => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ed_components(x).ok()
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
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
            jsonwebtoken::DecodingKey::from_rsa_components(modulus, exponent).ok()
        }
        jsonwebtoken::Algorithm::ES256 => {
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
            p256::PublicKey::from_sec1_bytes(&point).ok()?;
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

pub(super) fn jwt_provider_error(message: impl Into<String>) -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::ErrorKind::Provider(message.into()).into()
}

#[cfg(test)]
#[path = "../tests/unit/external_semantics.rs"]
mod tests;
