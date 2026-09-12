use anyhow::anyhow;
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey},
};
use der::{
    Encode,
    asn1::{Any, BitString, UintRef},
};
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

fn rsa_public_spki(n: &[u8], e: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pkcs1 = RsaPublicKey {
        modulus: UintRef::new(n)?,
        public_exponent: UintRef::new(e)?,
    }
    .to_der()?;
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
            parameters: Some(Any::null()),
        },
        subject_public_key: BitString::from_bytes(&pkcs1)?,
    }
    .to_der()?)
}

pub fn rsa_oaep_sha256_encrypt(n: &[u8], e: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let public = PublicEncryptingKey::from_der(&rsa_public_spki(n, e)?)
        .map_err(|_| anyhow!("invalid RSA public key"))?;
    let public =
        OaepPublicEncryptingKey::new(public).map_err(|_| anyhow!("invalid RSA-OAEP public key"))?;
    let mut ciphertext = vec![0; public.ciphertext_size()];
    Ok(public
        .encrypt(&OAEP_SHA256_MGF1SHA256, plaintext, &mut ciphertext, None)
        .map_err(|_| anyhow!("RSA-OAEP-256 encryption failed"))?
        .to_vec())
}

pub fn aes_256_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 16])> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("invalid AES-256-GCM key"))?,
    );
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("invalid AES-256-GCM nonce"))?;
    let mut ciphertext = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut ciphertext)
        .map_err(|_| anyhow!("AES-256-GCM encryption failed"))?;
    Ok((
        ciphertext,
        tag.as_ref().try_into().expect("AES-GCM tag is 16 bytes"),
    ))
}

pub fn aes_256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("invalid AES-256-GCM key"))?,
    );
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("invalid AES-256-GCM nonce"))?;
    let mut protected = Vec::with_capacity(ciphertext.len() + tag.len());
    protected.extend_from_slice(ciphertext);
    protected.extend_from_slice(tag);
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut protected)
        .map_err(|_| anyhow!("AES-256-GCM authentication failed"))?;
    Ok(plaintext.to_vec())
}

use crate::domain::rows::ClientRow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::{Algorithm, DecodingKey};
use nazo_auth::{Claims, rsa_public_key_components_are_safe};
use nazo_openid4vci::ProofError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
type HmacSha256 = Hmac<Sha256>;
const CLIENT_SECRET_HASH_VERSION: &str = "client-secret-v1";

enum SupportedClientJwtAlgorithm {
    EdDsa,
    Rsa,
    Ec,
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub fn client_secret_digest(secret: &str, pepper: &str, salt: &str) -> String {
    let mac = client_secret_mac(secret, pepper, salt);
    format!("{CLIENT_SECRET_HASH_VERSION}:{salt}:{mac}")
}

pub fn access_delivery_token(secret: &str, user_id: Uuid, request_id: Uuid) -> String {
    nazo_identity::access_delivery_token(secret, user_id, request_id)
}

fn client_secret_mac(secret: &str, pepper: &str, salt: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key");
    mac.update(salt.as_bytes());
    mac.update(b":");
    mac.update(secret.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

pub fn access_token_tenant_id(claims: &Claims) -> Option<Uuid> {
    claims.tenant_id.parse::<Uuid>().ok()
}

pub fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

pub fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn client_jwt_decoding_key(
    client: &ClientRow,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let keys = client.jwks.as_ref()?.get("keys")?.as_array()?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))?;
    jwt_decoding_key_from_jwk(key, alg)
}

pub fn jwt_decoding_key_from_jwk(
    key: &Value,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let (expected_alg, supported_alg) = supported_client_jwt_algorithm(alg)?;
    if let Some(key_alg) = key.get("alg").and_then(Value::as_str)
        && key_alg != expected_alg
    {
        return None;
    }
    if key.get("d").is_some() {
        return None;
    }
    if let Some(use_) = key.get("use").and_then(Value::as_str)
        && use_ != "sig"
    {
        return None;
    }
    match supported_alg {
        SupportedClientJwtAlgorithm::EdDsa => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ed_components(x).ok()
        }
        SupportedClientJwtAlgorithm::Rsa => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let n = key.get("n").and_then(Value::as_str)?;
            let e = key.get("e").and_then(Value::as_str)?;
            let modulus = URL_SAFE_NO_PAD.decode(n).ok()?;
            let exponent = URL_SAFE_NO_PAD.decode(e).ok()?;
            if !rsa_public_key_components_are_safe(&modulus, &exponent) {
                return None;
            }
            jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok()
        }
        SupportedClientJwtAlgorithm::Ec => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let y = key.get("y").and_then(Value::as_str)?;
            let x_bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            let y_bytes = URL_SAFE_NO_PAD.decode(y).ok()?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
    }
}

fn supported_client_jwt_algorithm(
    alg: jsonwebtoken::Algorithm,
) -> Option<(&'static str, SupportedClientJwtAlgorithm)> {
    match alg {
        jsonwebtoken::Algorithm::EdDSA => Some(("EdDSA", SupportedClientJwtAlgorithm::EdDsa)),
        jsonwebtoken::Algorithm::RS256 => Some(("RS256", SupportedClientJwtAlgorithm::Rsa)),
        jsonwebtoken::Algorithm::ES256 => Some(("ES256", SupportedClientJwtAlgorithm::Ec)),
        jsonwebtoken::Algorithm::PS256 => Some(("PS256", SupportedClientJwtAlgorithm::Rsa)),
        _ => None,
    }
}

pub fn decoding_key(jwk: &Value, algorithm: Algorithm) -> Result<DecodingKey, ProofError> {
    match algorithm {
        Algorithm::ES256 => DecodingKey::from_ec_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
        )
        .map_err(|_| ProofError::InvalidSignature),
        Algorithm::EdDSA => DecodingKey::from_ed_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
        )
        .map_err(|_| ProofError::InvalidSignature),
        _ => Err(ProofError::UnsupportedType),
    }
}
