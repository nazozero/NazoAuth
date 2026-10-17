use std::{
    borrow::Cow,
    io::{Read, Write},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use nazo_crypto::ec::{P256PublicJwk, P256SecretKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JweError {
    #[error("the JWE is malformed")]
    Malformed,
    #[error("the JWE uses an unsupported algorithm")]
    Unsupported,
    #[error("the JWE key is invalid")]
    InvalidKey,
    #[error("the JWE authentication tag is invalid")]
    AuthenticationFailed,
    #[error("the JWE compression payload is invalid or too large")]
    InvalidCompression,
}

#[derive(Clone)]
pub struct EphemeralEncryptionKey {
    secret: P256SecretKey,
}

impl EphemeralEncryptionKey {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret: P256SecretKey::generate(),
        }
    }

    #[must_use]
    pub fn public_jwk(&self) -> Value {
        let key = self.secret.public_key();
        let mut jwk = serde_json::to_value(P256PublicJwk::new(&key))
            .expect("P-256 public JWK is serializable");
        jwk["use"] = Value::String("enc".to_owned());
        jwk["alg"] = Value::String("ECDH-ES".to_owned());
        jwk
    }

    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, JweError> {
        P256SecretKey::from_secret_bytes(bytes)
            .map(|secret| Self { secret })
            .map_err(|_| JweError::InvalidKey)
    }

    pub fn derive(root_key: &[u8; 32], purpose: &[u8]) -> Result<Self, JweError> {
        for counter in 0_u32..=u32::MAX {
            let mut digest = Sha256::new();
            digest.update(b"NazoAuth OpenID4VC ECDH-ES\0");
            digest.update(root_key);
            digest.update(purpose);
            digest.update(counter.to_be_bytes());
            let bytes: [u8; 32] = digest.finalize().into();
            if let Ok(key) = Self::from_secret_bytes(&bytes) {
                return Ok(key);
            }
        }
        Err(JweError::InvalidKey)
    }

    pub fn decrypt(&self, compact: &str) -> Result<Vec<u8>, JweError> {
        decrypt_ecdh_es(compact, &self.secret, None)
    }

    pub fn decrypt_credential_request(
        &self,
        compact: &str,
        expected_kid: &str,
    ) -> Result<Vec<u8>, JweError> {
        decrypt_ecdh_es(compact, &self.secret, Some(expected_kid))
    }
}

/// Consumes the payload buffer for in-place A256GCM encryption and compact JWE encoding.
pub fn encrypt_ecdh_es(
    plaintext: Vec<u8>,
    recipient_jwk: &Value,
    content_type: Option<&str>,
) -> Result<String, JweError> {
    encrypt_ecdh_es_with_zip(plaintext, recipient_jwk, content_type, None, "A256GCM")
}

/// Consumes the payload buffer for in-place A128GCM encryption and compact JWE encoding.
pub fn encrypt_ecdh_es_a128(
    plaintext: Vec<u8>,
    recipient_jwk: &Value,
    content_type: Option<&str>,
) -> Result<String, JweError> {
    encrypt_ecdh_es_with_zip(plaintext, recipient_jwk, content_type, None, "A128GCM")
}

/// Compresses the payload, then encrypts the compression output in place with A256GCM.
pub fn encrypt_ecdh_es_deflate(
    plaintext: Vec<u8>,
    recipient_jwk: &Value,
    content_type: Option<&str>,
) -> Result<String, JweError> {
    encrypt_ecdh_es_with_zip(
        plaintext,
        recipient_jwk,
        content_type,
        Some("DEF"),
        "A256GCM",
    )
}

fn encrypt_ecdh_es_with_zip(
    mut plaintext: Vec<u8>,
    recipient_jwk: &Value,
    content_type: Option<&str>,
    zip: Option<&str>,
    enc: &str,
) -> Result<String, JweError> {
    let key_bits = match enc {
        "A128GCM" => 128,
        "A256GCM" => 256,
        _ => return Err(JweError::Unsupported),
    };
    let recipient = parse_recipient_public_jwk(recipient_jwk)?;
    let ephemeral = P256SecretKey::generate();
    let shared = ephemeral
        .agree(&recipient)
        .map_err(|_| JweError::InvalidKey)?;
    let key = concat_kdf(shared.as_slice(), enc, &[], &[], key_bits);
    let key = &key[..(key_bits / 8) as usize];
    let public_key = ephemeral.public_key();
    let header = ProtectedHeader {
        alg: "ECDH-ES",
        cty: content_type,
        enc,
        epk: P256PublicJwk::new(&public_key),
        kid: recipient_jwk.get("kid").and_then(Value::as_str),
        zip,
    };
    if zip == Some("DEF") {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&plaintext)
            .map_err(|_| JweError::InvalidCompression)?;
        plaintext = encoder.finish().map_err(|_| JweError::InvalidCompression)?;
    }
    let header = serde_json::to_vec(&header).map_err(|_| JweError::Malformed)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let capacity = [header.len(), 0, nonce.len(), plaintext.len(), 16]
        .into_iter()
        .map(|len| base64::encoded_len(len, false).expect("JWE segment is too large to encode"))
        .sum::<usize>()
        + 4;
    let mut compact = String::with_capacity(capacity);
    URL_SAFE_NO_PAD.encode_string(&header, &mut compact);
    let tag = nazo_crypto::aead::encrypt_in_place(key, &nonce, compact.as_bytes(), &mut plaintext)
        .map_err(jwe_aead_error)?;
    compact.push('.');
    for segment in [nonce.as_slice(), plaintext.as_slice(), tag.as_slice()] {
        compact.push('.');
        URL_SAFE_NO_PAD.encode_string(segment, &mut compact);
    }
    Ok(compact)
}

fn jwe_aead_error(error: nazo_crypto::CryptoError) -> JweError {
    match error {
        nazo_crypto::CryptoError::InvalidKey => JweError::InvalidKey,
        _ => JweError::AuthenticationFailed,
    }
}

fn decrypt_ecdh_es(
    compact: &str,
    recipient: &P256SecretKey,
    expected_kid: Option<&str>,
) -> Result<Vec<u8>, JweError> {
    let parts = compact_jwe_parts(compact).ok_or(JweError::Malformed)?;
    if !parts[1].is_empty() {
        return Err(JweError::Malformed);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| JweError::Malformed)?;
    let header: DecryptionHeader<'_> =
        serde_json::from_slice(&header_bytes).map_err(|_| JweError::Malformed)?;
    if header.alg != "ECDH-ES" {
        return Err(JweError::Unsupported);
    }
    let (enc, key_bits) = match header.enc.as_ref() {
        "A128GCM" => ("A128GCM", 128),
        "A256GCM" => ("A256GCM", 256),
        _ => return Err(JweError::Unsupported),
    };
    if let Some(expected_kid) = expected_kid
        && (header.kid.as_deref() != Some(expected_kid)
            || !matches!(header.cty.as_deref(), Some("json" | "application/json")))
    {
        return Err(JweError::Unsupported);
    }
    let jwk: EphemeralPublicJwk<'_> =
        serde_json::from_str(header.epk.get()).map_err(|_| JweError::InvalidKey)?;
    if jwk.alg.as_deref().is_some_and(|alg| alg != "ECDH-ES")
        || jwk.kty != "EC"
        || jwk.crv != "P-256"
    {
        return Err(JweError::InvalidKey);
    }
    let ephemeral = ec_point(&jwk.x, &jwk.y)?;
    let shared = recipient
        .agree(&ephemeral)
        .map_err(|_| JweError::InvalidKey)?;
    let apu = decode_party_info(header.apu.as_deref())?;
    let apv = decode_party_info(header.apv.as_deref())?;
    let key = concat_kdf(shared.as_slice(), enc, &apu, &apv, key_bits);
    let key = &key[..(key_bits / 8) as usize];
    let nonce: [u8; 12] = decode_array(parts[2]).ok_or(JweError::Malformed)?;
    let mut ciphertext = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|_| JweError::Malformed)?;
    let tag: [u8; 16] = decode_array(parts[4]).ok_or(JweError::Malformed)?;
    nazo_crypto::aead::decrypt_in_place(key, &nonce, parts[0].as_bytes(), &mut ciphertext, &tag)
        .map_err(jwe_aead_error)?;
    match header.zip.as_deref() {
        None => Ok(ciphertext),
        Some("DEF") => decompress_deflate(&ciphertext),
        Some(_) => Err(JweError::Unsupported),
    }
}

fn decompress_deflate(compressed: &[u8]) -> Result<Vec<u8>, JweError> {
    const MAX_DECOMPRESSED_BYTES: u64 = 1_048_576;
    let mut decoder = DeflateDecoder::new(compressed);
    let mut output = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|_| JweError::InvalidCompression)?;
    if output.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(JweError::InvalidCompression);
    }
    Ok(output)
}

#[derive(Deserialize)]
struct DecryptionHeader<'a> {
    #[serde(borrow)]
    alg: Cow<'a, str>,
    #[serde(borrow)]
    enc: Cow<'a, str>,
    #[serde(borrow)]
    epk: &'a serde_json::value::RawValue,
    #[serde(default, borrow, deserialize_with = "optional_string")]
    kid: Option<Cow<'a, str>>,
    #[serde(default, borrow, deserialize_with = "optional_string")]
    cty: Option<Cow<'a, str>>,
    #[serde(default, borrow, deserialize_with = "optional_string")]
    zip: Option<Cow<'a, str>>,
    #[serde(default, borrow, deserialize_with = "present_string")]
    apu: Option<Cow<'a, str>>,
    #[serde(default, borrow, deserialize_with = "present_string")]
    apv: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct EphemeralPublicJwk<'a> {
    #[serde(borrow)]
    kty: Cow<'a, str>,
    #[serde(borrow)]
    crv: Cow<'a, str>,
    #[serde(borrow)]
    x: Cow<'a, str>,
    #[serde(borrow)]
    y: Cow<'a, str>,
    #[serde(default, borrow, deserialize_with = "present_string")]
    alg: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct StringValue<'a>(#[serde(borrow)] Cow<'a, str>);

fn optional_string<'de, D>(deserializer: D) -> Result<Option<Cow<'de, str>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<StringValue<'_>>::deserialize(deserializer).map(|value| value.map(|value| value.0))
}

// Missing fields are optional; a present value must be a JSON string, not null.
fn present_string<'de, D>(deserializer: D) -> Result<Option<Cow<'de, str>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    StringValue::deserialize(deserializer).map(|value| Some(value.0))
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<&'a str>,
    enc: &'a str,
    epk: P256PublicJwk<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zip: Option<&'a str>,
}

fn parse_recipient_public_jwk(jwk: &Value) -> Result<[u8; 65], JweError> {
    if jwk.get("alg").and_then(Value::as_str) != Some("ECDH-ES") {
        return Err(JweError::InvalidKey);
    }
    parse_ec_public_jwk(jwk)
}

fn parse_ec_public_jwk(jwk: &Value) -> Result<[u8; 65], JweError> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(JweError::InvalidKey);
    }
    ec_point(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or(JweError::InvalidKey)?,
        jwk.get("y")
            .and_then(Value::as_str)
            .ok_or(JweError::InvalidKey)?,
    )
}

fn ec_point(x: &str, y: &str) -> Result<[u8; 65], JweError> {
    let mut point = [0_u8; 65];
    point[0] = 4;
    if URL_SAFE_NO_PAD.decode_slice(x, &mut point[1..33]).ok() != Some(32)
        || URL_SAFE_NO_PAD.decode_slice(y, &mut point[33..]).ok() != Some(32)
    {
        return Err(JweError::InvalidKey);
    }
    Ok(point)
}

fn decode_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    (URL_SAFE_NO_PAD.decode_slice(input, &mut bytes).ok()? == N).then_some(bytes)
}

fn decode_party_info(value: Option<&str>) -> Result<Vec<u8>, JweError> {
    value
        .map(|value| {
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| JweError::Malformed)
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn concat_kdf(
    shared_secret: &[u8],
    algorithm: &str,
    apu: &[u8],
    apv: &[u8],
    key_bits: u32,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(1_u32.to_be_bytes());
    digest.update(shared_secret);
    digest.update((algorithm.len() as u32).to_be_bytes());
    digest.update(algorithm.as_bytes());
    digest.update((apu.len() as u32).to_be_bytes());
    digest.update(apu);
    digest.update((apv.len() as u32).to_be_bytes());
    digest.update(apv);
    digest.update(key_bits.to_be_bytes());
    digest.finalize().into()
}

fn compact_jwe_parts(input: &str) -> Option<[&str; 5]> {
    let mut segments = input.split('.');
    let parts = [
        segments.next()?,
        segments.next()?,
        segments.next()?,
        segments.next()?,
        segments.next()?,
    ];
    segments.next().is_none().then_some(parts)
}

#[cfg(test)]
#[path = "../tests/unit/jwe.rs"]
mod tests;
