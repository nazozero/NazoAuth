#![cfg_attr(not(test), allow(dead_code))]

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use uuid::Uuid;

use crate::domain::{ActiveSigningKey, ClientRow, HttpMessageSignature, Keyset};

use super::{jwt_decoding_key_from_jwk, sign_local_jwt_input};

fn http_algorithm(algorithm: jsonwebtoken::Algorithm) -> anyhow::Result<&'static str> {
    match algorithm {
        jsonwebtoken::Algorithm::EdDSA => Ok("ed25519"),
        jsonwebtoken::Algorithm::RS256 => Ok("rsa-v1_5-sha256"),
        jsonwebtoken::Algorithm::ES256 => Ok("ecdsa-p256-sha256"),
        _ => bail!("unsupported HTTP message signature algorithm"),
    }
}

fn jwt_algorithm(algorithm: &str) -> anyhow::Result<jsonwebtoken::Algorithm> {
    match algorithm {
        "ed25519" => Ok(jsonwebtoken::Algorithm::EdDSA),
        "rsa-v1_5-sha256" => Ok(jsonwebtoken::Algorithm::RS256),
        "ecdsa-p256-sha256" => Ok(jsonwebtoken::Algorithm::ES256),
        _ => bail!("unsupported HTTP message signature algorithm"),
    }
}

fn http_jwk_decoding_key(
    key: &Value,
    algorithm: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let expected_algorithm = match algorithm {
        jsonwebtoken::Algorithm::EdDSA => "EdDSA",
        jsonwebtoken::Algorithm::RS256 => "RS256",
        jsonwebtoken::Algorithm::ES256 => "ES256",
        _ => return None,
    };
    match key.get("alg") {
        None => {}
        Some(Value::String(value)) if value == expected_algorithm => {}
        Some(_) => return None,
    }
    match key.get("use") {
        None => {}
        Some(Value::String(value)) if value == "sig" => {}
        Some(_) => return None,
    }
    if ["d", "p", "q", "dp", "dq", "qi", "oth"]
        .iter()
        .any(|member| key.get(member).is_some())
    {
        return None;
    }
    if let Some(key_ops) = key.get("key_ops") {
        let operations = key_ops.as_array()?;
        if operations.len() != 1 || operations[0].as_str() != Some("verify") {
            return None;
        }
    }
    if algorithm == jsonwebtoken::Algorithm::RS256 {
        let modulus = URL_SAFE_NO_PAD.decode(key.get("n")?.as_str()?).ok()?;
        if unsigned_integer_bit_length(&modulus) < 2048 {
            return None;
        }
    }
    jwt_decoding_key_from_jwk(key, algorithm)
}

fn unsigned_integer_bit_length(bytes: &[u8]) -> usize {
    let Some((offset, first)) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0) else {
        return 0;
    };
    (bytes.len() - offset - 1) * 8 + (u8::BITS - first.leading_zeros()) as usize
}

impl Keyset {
    pub(crate) async fn sign_http_message(
        &self,
        signing_input: &[u8],
    ) -> anyhow::Result<HttpMessageSignature> {
        let algorithm = http_algorithm(self.active_alg)?;
        let signature = match &self.active_signing_key {
            ActiveSigningKey::LocalPkcs8Der(private_pkcs8_der) => {
                let encoded =
                    sign_local_jwt_input(self.active_alg, private_pkcs8_der, signing_input)?;
                URL_SAFE_NO_PAD
                    .decode(encoded)
                    .context("local signer returned invalid signature encoding")?
            }
            ActiveSigningKey::ExternalCommand(external) => {
                let verification_key = self
                    .verification_key(&self.active_kid)
                    .context("active signing key has no public JWK")?;
                super::keyset::sign_external_http_input(
                    external,
                    &self.active_kid,
                    self.active_alg,
                    signing_input,
                    &verification_key.public_jwk,
                )
                .await?
            }
        };
        Ok(HttpMessageSignature {
            kid: self.active_kid.clone(),
            algorithm,
            signature,
        })
    }
}

pub(crate) fn verify_client_http_message(
    client: &ClientRow,
    tenant_id: Uuid,
    client_id: &str,
    kid: &str,
    algorithm: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    if client.tenant_id != tenant_id || client.client_id != client_id {
        bail!("HTTP signature client binding mismatch");
    }
    let jwt_algorithm = jwt_algorithm(algorithm)?;
    let keys = client
        .jwks
        .as_ref()
        .and_then(|jwks| jwks.get("keys"))
        .and_then(serde_json::Value::as_array)
        .context("client has no usable JWK set")?;
    let mut matching = keys
        .iter()
        .filter(|key| key.get("kid").and_then(serde_json::Value::as_str) == Some(kid));
    let key = matching.next().context("client JWK kid not found")?;
    if matching.next().is_some() {
        bail!("client JWK kid is ambiguous");
    }
    let decoding_key = http_jwk_decoding_key(key, jwt_algorithm)
        .context("client JWK is not usable for HTTP signature verification")?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);
    if !jsonwebtoken::crypto::verify(
        &encoded_signature,
        signing_input,
        &decoding_key,
        jwt_algorithm,
    )
    .unwrap_or(false)
    {
        bail!("HTTP message signature verification failed");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/fapi_http_signatures.rs"]
mod tests;
