//! Token Status List draft-21: authenticated list resolution and status evaluation.
use std::io::Read;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use ciborium::Value as Cbor;
use coset::AsCborValue;
use nazo_crypto::jwt::{Algorithm, Validation, VerificationKey, decode, decode_header};
use nazo_digital_credentials::{CredentialFormat, CredentialTrustError, PresentedCredential};
use serde_json::Value;

use super::super::crypto_helpers::{parse_x509, verify_openid4vc_chain_with_scoped};
use super::Openid4vcCredentialCrypto;

const INVALID: CredentialTrustError = CredentialTrustError::InvalidStatus;
const MAX_TOKEN_BYTES: usize = 128 * 1024;
const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;

pub(super) async fn verify(
    crypto: &Openid4vcCredentialCrypto,
    presentation: &PresentedCredential<'_>,
    status: &Value,
    issuer: &str,
    issuer_chain: &[Vec<u8>],
) -> Result<(), CredentialTrustError> {
    let reference = status
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    // An unsupported second mechanism or explicit delegated certificate cannot
    // silently disappear from the trust decision.
    if status.as_object().is_none_or(|object| object.len() != 1)
        || reference.keys().any(|key| key != "idx" && key != "uri")
    {
        return Err(INVALID);
    }
    let uri = reference
        .get("uri")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let index = reference
        .get("idx")
        .and_then(Value::as_u64)
        .ok_or(INVALID)?;
    let parsed = url::Url::parse(uri).map_err(|_| INVALID)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(INVALID);
    }
    let token = crypto
        .status_resolver
        .as_ref()
        .ok_or(INVALID)?
        .fetch(uri, presentation.format)
        .await?;
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(INVALID);
    }
    match presentation.format {
        CredentialFormat::SdJwtVc => verify_jwt(
            crypto,
            presentation,
            issuer_chain,
            issuer,
            uri,
            index,
            &token,
        ),
        CredentialFormat::MsoMdoc => {
            verify_cwt(crypto, presentation, issuer_chain, uri, index, &token)
        }
    }
}

fn verify_jwt(
    crypto: &Openid4vcCredentialCrypto,
    presentation: &PresentedCredential<'_>,
    issuer_chain: &[Vec<u8>],
    issuer: &str,
    uri: &str,
    index: u64,
    token: &[u8],
) -> Result<(), CredentialTrustError> {
    let token = std::str::from_utf8(token).map_err(|_| INVALID)?;
    let header = decode_header(token).map_err(|_| INVALID)?;
    if header.alg != Algorithm::ES256 || header.typ.as_deref() != Some("statuslist+jwt") {
        return Err(INVALID);
    }
    let raw_header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').next().ok_or(INVALID)?)
            .map_err(|_| INVALID)?,
    )
    .map_err(|_| INVALID)?;
    if raw_header
        .get("b64")
        .is_some_and(|v| v != &Value::Bool(true))
    {
        return Err(INVALID);
    }
    let chain = header
        .x5c
        .as_ref()
        .ok_or(INVALID)?
        .iter()
        .map(|der| STANDARD.decode(der).map_err(|_| INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let key = status_key(crypto, presentation, issuer_chain, &chain, Some(issuer))?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims = ["sub", "iat"].into_iter().map(str::to_owned).collect();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = decode::<Value>(token, &key, &validation)
        .map_err(|_| INVALID)?
        .claims;
    if claims.get("sub").and_then(Value::as_str) != Some(uri) {
        return Err(INVALID);
    }
    validate_times(
        number(claims.get("iat"))?,
        optional_number(claims.get("exp"))?,
        optional_number(claims.get("nbf"))?,
        optional_number(claims.get("ttl"))?,
        Utc::now().timestamp() as f64,
    )?;
    // There is no audience for this public list retrieval operation.
    if claims.get("aud").is_some() {
        return Err(INVALID);
    }
    if claims
        .get("iss")
        .is_some_and(|v| v.as_str() != Some(issuer))
    {
        return Err(INVALID);
    }
    let list = claims.get("status_list").ok_or(INVALID)?;
    let bits = list.get("bits").and_then(Value::as_u64).ok_or(INVALID)?;
    let compressed = URL_SAFE_NO_PAD
        .decode(list.get("lst").and_then(Value::as_str).ok_or(INVALID)?)
        .map_err(|_| INVALID)?;
    validate_aggregation(list.get("aggregation_uri"))?;
    validate_index(bits, index, &compressed)
}

fn verify_cwt(
    crypto: &Openid4vcCredentialCrypto,
    presentation: &PresentedCredential<'_>,
    issuer_chain: &[Vec<u8>],
    uri: &str,
    index: u64,
    token: &[u8],
) -> Result<(), CredentialTrustError> {
    let mut input = token;
    let value: Cbor = ciborium::from_reader(&mut input).map_err(|_| INVALID)?;
    if !input.is_empty() {
        return Err(INVALID);
    }
    let sign1 = match value {
        Cbor::Tag(18, inner) => coset::CoseSign1::from_cbor_value(*inner),
        _ => return Err(INVALID),
    }
    .map_err(|_| INVALID)?;
    let protected = &sign1.protected.header;
    if !matches!(
        protected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            coset::iana::Algorithm::ES256 | coset::iana::Algorithm::ESP256
        ))
    ) || !protected.crit.is_empty()
        || sign1.unprotected.alg.is_some()
        || sign1
            .unprotected
            .rest
            .iter()
            .any(|(key, _)| matches!(key, coset::Label::Int(16 | 33)))
    {
        return Err(INVALID);
    }
    let typ = protected
        .rest
        .iter()
        .find(|(key, _)| *key == coset::Label::Int(16))
        .map(|(_, v)| v)
        .ok_or(INVALID)?;
    // draft-21 has no assigned CoAP Content-Format ID; do not guess one.
    if typ.as_text() != Some("application/statuslist+cwt") {
        return Err(INVALID);
    }
    let certificate = protected
        .rest
        .iter()
        .find(|(key, _)| *key == coset::Label::Int(33))
        .map(|(_, v)| v)
        .ok_or(INVALID)?;
    let chain = match certificate {
        Cbor::Bytes(der) => vec![der.clone()],
        Cbor::Array(chain) => chain
            .iter()
            .map(|v| v.as_bytes().cloned().ok_or(INVALID))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(INVALID),
    };
    let key = status_key(crypto, presentation, issuer_chain, &chain, None)?;
    nazo_crypto::signature::verify(
        Algorithm::ES256,
        &key,
        &sign1.tbs_data(&[]),
        &sign1.signature,
    )
    .map_err(|_| INVALID)?;
    let mut payload = sign1.payload.as_deref().ok_or(INVALID)?;
    let claims: Cbor = ciborium::from_reader(&mut payload).map_err(|_| INVALID)?;
    if !payload.is_empty() {
        return Err(INVALID);
    }
    let claims = unique_map(&claims)?;
    let get = |n: i64| {
        claims
            .iter()
            .find(|(key, _)| key.as_integer().map(i128::from) == Some(i128::from(n)))
            .map(|(_, v)| v)
    };
    if get(2).and_then(Cbor::as_text) != Some(uri) || get(3).is_some() {
        return Err(INVALID);
    }
    if get(1).is_some_and(|v| v.as_text().is_none()) {
        return Err(INVALID);
    }
    // ISO mdoc requires an expiration time for the MSO revocation list.
    validate_times(
        cbor_number(get(6))?,
        Some(cbor_number(get(4))?),
        get(5).map(|v| cbor_number(Some(v))).transpose()?,
        get(65534)
            .map(|v| {
                v.as_integer()
                    .and_then(|n| u64::try_from(n).ok())
                    .map(|n| n as f64)
                    .ok_or(INVALID)
            })
            .transpose()?,
        Utc::now().timestamp() as f64,
    )?;
    let list = unique_map(get(65533).ok_or(INVALID)?)?;
    let get = |name: &str| {
        list.iter()
            .find(|(key, _)| key.as_text() == Some(name))
            .map(|(_, v)| v)
    };
    let bits = get("bits")
        .and_then(Cbor::as_integer)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(INVALID)?;
    if get("aggregation_uri").is_some_and(|v| v.as_text().is_none()) {
        return Err(INVALID);
    }
    validate_index(
        bits,
        index,
        get("lst").and_then(Cbor::as_bytes).ok_or(INVALID)?,
    )
}

/// Lists are authorized by the credential's issuer, not by arbitrary keys found
/// in a signed list. Same-key JWTs reuse the authenticated issuer chain. mdoc's
/// separate MSO-list signer must be issued directly by that same IACA.
fn status_key(
    crypto: &Openid4vcCredentialCrypto,
    presentation: &PresentedCredential<'_>,
    issuer_chain: &[Vec<u8>],
    chain: &[Vec<u8>],
    issuer: Option<&str>,
) -> Result<VerificationKey, CredentialTrustError> {
    if chain.is_empty() || chain.len() > 8 {
        return Err(INVALID);
    }
    let (_, leaf) = parse_x509(&chain[0], "status signer").map_err(|_| INVALID)?;
    if leaf.is_ca() || leaf.subject() == leaf.issuer() {
        return Err(INVALID);
    }
    let issuer_leaf = issuer_chain.first().ok_or(INVALID)?;
    let (_, credential_signer) =
        parse_x509(issuer_leaf, "credential signer").map_err(|_| INVALID)?;
    if presentation.format == CredentialFormat::SdJwtVc {
        // HAIP excludes trust anchors from x5c. Authenticate the presented chain,
        // then bind its signing key to the already authenticated credential key.
        let anchors = crypto.combined_trust_anchors(&presentation.additional_trust_anchors)?;
        if chain.iter().any(|der| anchors.contains(der)) {
            return Err(INVALID);
        }
        let anchor = verify_openid4vc_chain_with_scoped(
            chain,
            &anchors,
            &presentation.additional_trust_anchors,
        )
        .map_err(|_| INVALID)?;
        if leaf.public_key().raw != credential_signer.public_key().raw {
            return Err(INVALID);
        }
        crypto
            .current_revocation_policy()
            .check_chain_with_scoped_trust(
                issuer,
                chain,
                Utc::now(),
                presentation
                    .additional_trust_anchors
                    .iter()
                    .any(|der| der.as_slice() == anchor),
            )?;
    } else {
        let anchors = crypto.combined_trust_anchors(&presentation.additional_trust_anchors)?;
        let issuer = issuer_chain
            .iter()
            .skip(1)
            .chain(anchors.iter())
            .find(|der| {
                parse_x509(der, "IACA").is_ok_and(|(_, ca)| {
                    ca.is_ca()
                        && ca.subject() == credential_signer.issuer()
                        && nazo_crypto::certificate::verify_signature(
                            &credential_signer,
                            ca.public_key(),
                        )
                        .is_ok()
                })
            })
            .ok_or(INVALID)?;
        let (_, ca) = parse_x509(issuer, "IACA").map_err(|_| INVALID)?;
        if leaf.issuer() != ca.subject()
            || nazo_crypto::certificate::verify_signature(&leaf, ca.public_key()).is_err()
        {
            return Err(INVALID);
        }
        let usage = leaf.key_usage().map_err(|_| INVALID)?.ok_or(INVALID)?;
        if !usage.critical || usage.value.flags != 1 {
            return Err(INVALID);
        }
        let path: Vec<_> = chain
            .iter()
            .filter(|der| *der != issuer)
            .map(|der| nazo_crypto::certificate::CertificateDer::from(der.as_slice()))
            .collect();
        nazo_crypto::certificate::verify_document_signing_chain_at(
            &path,
            &nazo_crypto::certificate::CertificateDer::from(issuer.as_slice()),
            Utc::now().timestamp() as u64,
        )
        .map_err(|_| INVALID)?;
        crypto
            .current_revocation_policy()
            .check_chain_with_scoped_trust(
                None,
                chain,
                Utc::now(),
                presentation.additional_trust_anchors.contains(issuer),
            )?;
    }
    Ok(VerificationKey::from_ec_sec1(
        leaf.public_key().subject_public_key.data.as_ref(),
    ))
}

fn number(value: Option<&Value>) -> Result<f64, CredentialTrustError> {
    value
        .and_then(Value::as_f64)
        .filter(|n| n.is_finite())
        .ok_or(INVALID)
}
fn optional_number(value: Option<&Value>) -> Result<Option<f64>, CredentialTrustError> {
    value.map(|v| number(Some(v))).transpose()
}
fn cbor_number(value: Option<&Cbor>) -> Result<f64, CredentialTrustError> {
    match value {
        Some(Cbor::Integer(n)) => Ok(i128::from(*n) as f64),
        Some(Cbor::Float(n)) if n.is_finite() => Ok(*n),
        _ => Err(INVALID),
    }
}
fn validate_times(
    iat: f64,
    exp: Option<f64>,
    nbf: Option<f64>,
    ttl: Option<f64>,
    now: f64,
) -> Result<(), CredentialTrustError> {
    if iat > now + 60.0
        || exp.is_some_and(|exp| exp <= now || exp <= iat)
        || nbf.is_some_and(|nbf| nbf > now + 60.0)
        || ttl.is_some_and(|ttl| ttl <= 0.0)
    {
        return Err(INVALID);
    }
    Ok(())
}
fn validate_aggregation(value: Option<&Value>) -> Result<(), CredentialTrustError> {
    if value.is_some_and(|v| !v.is_string()) {
        return Err(INVALID);
    }
    Ok(())
}
fn unique_map(value: &Cbor) -> Result<&[(Cbor, Cbor)], CredentialTrustError> {
    let map = value.as_map().ok_or(INVALID)?;
    if map.len() > 64
        || map
            .iter()
            .enumerate()
            .any(|(i, (key, _))| map[..i].iter().any(|(previous, _)| previous == key))
    {
        return Err(INVALID);
    }
    Ok(map)
}
fn validate_index(bits: u64, index: u64, compressed: &[u8]) -> Result<(), CredentialTrustError> {
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(INVALID);
    }
    let byte_index = usize::try_from(index / (8 / bits)).map_err(|_| INVALID)?;
    if byte_index >= MAX_LIST_BYTES {
        return Err(INVALID);
    }
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut buffer = [0u8; 8192];
    let mut offset = 0usize;
    let mut value = None;
    loop {
        let count = decoder.read(&mut buffer).map_err(|_| INVALID)?;
        if count == 0 {
            break;
        }
        if offset + count > MAX_LIST_BYTES {
            return Err(INVALID);
        }
        if (offset..offset + count).contains(&byte_index) {
            value = Some(buffer[byte_index - offset]);
        }
        offset += count;
    }
    if decoder.total_in() != compressed.len() as u64 {
        return Err(INVALID);
    }
    let value = value.ok_or(INVALID)?;
    let shift = (index % (8 / bits)) * bits;
    if (u64::from(value) >> shift) & ((1 << bits) - 1) != 0 {
        return Err(INVALID);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/domain/openid4vc/credential_crypto/status.rs"]
mod tests;
