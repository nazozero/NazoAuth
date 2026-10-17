//! Client-bound compact JWE construction for encrypted OAuth and OIDC responses.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nazo_auth::{ClientJweKeyManagement, client_jwe_key_management_from_name};
use nazo_auth::{SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS};
use nazo_crypto::ec::{P256PublicJwk, P256SecretKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub struct ClientJweKey<'a> {
    pub kid: Option<&'a str>,
    pub alg: &'a str,
    pub enc: &'a str,
    pub jwk: &'a Value,
}

#[derive(Clone, Copy)]
pub enum JwePayloadKind {
    Claims,
    NestedJwt,
}

pub fn client_jwe_key<'a>(
    jwks: Option<&'a Value>,
    alg: Option<&'a str>,
    enc: Option<&'a str>,
    response_name: &str,
) -> anyhow::Result<Option<ClientJweKey<'a>>> {
    let Some(alg) = alg else {
        if enc.is_some() {
            anyhow::bail!("{response_name} JWE enc configured without alg");
        }
        return Ok(None);
    };
    let Some(enc) = enc else {
        anyhow::bail!("{response_name} JWE alg configured without enc");
    };
    if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&alg) {
        anyhow::bail!("unsupported {response_name} JWE alg");
    }
    if !SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.contains(&enc) {
        anyhow::bail!("unsupported {response_name} JWE enc");
    }
    let keys = jwks
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("{response_name} JWE client has no jwks"))?;
    let mut matching_keys = keys.iter().filter(|key| {
        key.get("use").and_then(Value::as_str) == Some("enc")
            && key.get("alg").and_then(Value::as_str) == Some(alg)
    });
    let Some(jwk) = matching_keys.next() else {
        anyhow::bail!("{response_name} JWE client has no matching encryption key");
    };
    if matching_keys.next().is_some() {
        anyhow::bail!("{response_name} JWE client has ambiguous encryption keys");
    }
    let kid = jwk
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.trim().is_empty());
    Ok(Some(ClientJweKey { kid, alg, enc, jwk }))
}

/// Consumes the response buffer for in-place encryption and compact JWE encoding.
pub fn encrypt_compact_jwe(
    key: &ClientJweKey<'_>,
    plaintext: Vec<u8>,
    payload_kind: JwePayloadKind,
) -> anyhow::Result<String> {
    let Some(alg) = client_jwe_key_management_from_name(key.alg) else {
        anyhow::bail!("unsupported client JWE policy");
    };
    if key.enc != "A256GCM" {
        anyhow::bail!("unsupported client JWE enc");
    }
    let mut protected_header = ProtectedHeader {
        alg: key.alg,
        cty: matches!(payload_kind, JwePayloadKind::NestedJwt).then_some("JWT"),
        enc: key.enc,
        epk: None,
        kid: key.kid,
        typ: matches!(payload_kind, JwePayloadKind::Claims).then_some("JWT"),
    };
    let public_key;
    let (cek, encrypted_key) = match alg {
        ClientJweKeyManagement::RsaOaep256 => {
            let cek = rand::random::<[u8; 32]>();
            let encrypted_key = rsa_oaep_256_encrypt_jwk(key.jwk, &cek)?;
            (cek, encrypted_key)
        }
        ClientJweKeyManagement::EcdhEsDirect => {
            let recipient = parse_p256_public_jwk(key.jwk)?;
            let ephemeral = P256SecretKey::generate();
            public_key = ephemeral.public_key();
            protected_header.epk = Some(P256PublicJwk::new(&public_key));
            return encrypt_compact_jwe_with_cek(
                &protected_header,
                &ecdh_derive_key(&ephemeral, &recipient, key.enc, 256)?,
                &[],
                plaintext,
            );
        }
        ClientJweKeyManagement::EcdhEsA128Kw | ClientJweKeyManagement::EcdhEsA256Kw => {
            let recipient = parse_p256_public_jwk(key.jwk)?;
            let ephemeral = P256SecretKey::generate();
            public_key = ephemeral.public_key();
            protected_header.epk = Some(P256PublicJwk::new(&public_key));
            let kek_bits = match alg {
                ClientJweKeyManagement::EcdhEsA128Kw => 128,
                ClientJweKeyManagement::EcdhEsA256Kw => 256,
                _ => unreachable!("alg was matched above"),
            };
            let kek = ecdh_derive_key(&ephemeral, &recipient, alg.name(), kek_bits)?;
            let cek = rand::random::<[u8; 32]>();
            let encrypted_key =
                nazo_crypto::key_wrap::aes_wrap(&kek[..(kek_bits / 8) as usize], &cek)?;
            return encrypt_compact_jwe_with_cek(
                &protected_header,
                &cek,
                &encrypted_key,
                plaintext,
            );
        }
    };
    encrypt_compact_jwe_with_cek(&protected_header, &cek, &encrypted_key, plaintext)
}

fn encrypt_compact_jwe_with_cek(
    protected_header: &ProtectedHeader<'_>,
    cek: &[u8],
    encrypted_key: &[u8],
    mut plaintext: Vec<u8>,
) -> anyhow::Result<String> {
    let header = serde_json::to_vec(protected_header)?;
    let iv = rand::random::<[u8; 12]>();
    let capacity = [
        header.len(),
        encrypted_key.len(),
        iv.len(),
        plaintext.len(),
        16,
    ]
    .into_iter()
    .map(|len| base64::encoded_len(len, false).expect("JWE segment is too large to encode"))
    .sum::<usize>()
        + 4;
    let mut compact = String::with_capacity(capacity);
    URL_SAFE_NO_PAD.encode_string(&header, &mut compact);
    let tag = nazo_crypto::aead::encrypt_in_place(cek, &iv, compact.as_bytes(), &mut plaintext)?;
    for segment in [
        encrypted_key,
        iv.as_slice(),
        plaintext.as_slice(),
        tag.as_slice(),
    ] {
        compact.push('.');
        URL_SAFE_NO_PAD.encode_string(segment, &mut compact);
    }
    Ok(compact)
}

fn rsa_oaep_256_encrypt_jwk(jwk: &Value, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let n = jwk
        .get("n")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("RSA JWE key missing n"))?;
    let e = jwk
        .get("e")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("RSA JWE key missing e"))?;
    Ok(nazo_crypto::key_wrap::rsa_oaep256_encrypt(
        &URL_SAFE_NO_PAD.decode(n)?,
        &URL_SAFE_NO_PAD.decode(e)?,
        plaintext,
    )?)
}

fn parse_p256_public_jwk(jwk: &Value) -> anyhow::Result<[u8; 65]> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk.get("d").is_some()
    {
        anyhow::bail!("ECDH JWE key must be a public P-256 key");
    }
    let x = decode_p256_coordinate(jwk, "x")?;
    let y = decode_p256_coordinate(jwk, "y")?;
    let mut point = [0_u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    Ok(point)
}

fn decode_p256_coordinate(jwk: &Value, name: &str) -> anyhow::Result<[u8; 32]> {
    let value = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("P-256 JWE key missing {name}"))?;
    let mut coordinate = [0; 32];
    if URL_SAFE_NO_PAD.decode_slice(value, &mut coordinate)? != coordinate.len() {
        anyhow::bail!("P-256 JWE key {name} has invalid length");
    }
    Ok(coordinate)
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<&'a str>,
    enc: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    epk: Option<P256PublicJwk<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
}

fn ecdh_derive_key(
    ephemeral: &P256SecretKey,
    recipient: &[u8; 65],
    algorithm: &str,
    key_bits: u32,
) -> anyhow::Result<[u8; 32]> {
    let shared = ephemeral.agree(recipient)?;
    Ok(concat_kdf(&shared[..], algorithm, &[], &[], key_bits))
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

#[cfg(test)]
#[path = "../../tests/unit/domain/client_jwe.rs"]
mod tests;
