//! Token Status List draft-21: authenticated list resolution and status evaluation.
use std::io::Read;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ciborium::Value as Cbor;
use coset::AsCborValue;
use jiff::Timestamp;
use nazo_crypto::jwt::{Algorithm, Validation, VerificationKey, decode, decode_header};
use nazo_digital_credentials::{CredentialFormat, CredentialTrustError};
use serde_json::Value;

use super::super::crypto_helpers::{parse_x509, verify_openid4vc_chain_with_scoped};
use super::Openid4vcCredentialCrypto;

const INVALID: CredentialTrustError = CredentialTrustError::InvalidStatus;
const MAX_TOKEN_BYTES: usize = 128 * 1024;
const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;

/// Project only the supported authenticated MSO mechanism. General claim
/// projection must never decide whether an authenticated status field exists.
pub(super) fn mdoc_reference_to_json(
    status: nazo_mdoc::model::borrowed::MsoStatusRef<'_>,
) -> Result<Value, CredentialTrustError> {
    // The core parsed idx/uri and rejected duplicate keys. NazoAuth accepts one
    // status-list mechanism without delegated-signer or unknown members.
    let reference = status.status_list.ok_or(INVALID)?;
    let mut mechanisms = status.raw.map().map_err(|_| INVALID)?;
    if mechanisms.len() != 1 {
        return Err(INVALID);
    }
    let (_, fields) = mechanisms.next().ok_or(INVALID)?.map_err(|_| INVALID)?;
    if fields.map().map_err(|_| INVALID)?.len() != 2 {
        return Err(INVALID);
    }
    Ok(serde_json::json!({
        "status_list": {"idx": reference.idx, "uri": reference.uri}
    }))
}

/// Bounded response bytes associated with one validated reference. Signature and
/// trust checks remain pending until `verify` receives the credential's chain.
pub(super) struct ResolvedStatusList<'a> {
    format: CredentialFormat,
    uri: &'a str,
    index: u64,
    token: Vec<u8>,
}

pub(super) async fn resolve<'a>(
    crypto: &Openid4vcCredentialCrypto,
    format: CredentialFormat,
    status: &'a Value,
) -> Result<ResolvedStatusList<'a>, CredentialTrustError> {
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
        .fetch(uri, format)
        .await?;
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(INVALID);
    }
    Ok(ResolvedStatusList {
        format,
        uri,
        index,
        token,
    })
}

impl ResolvedStatusList<'_> {
    pub(super) fn verify(
        self,
        crypto: &Openid4vcCredentialCrypto,
        additional_trust_anchors: &[Vec<u8>],
        issuer: &str,
        issuer_chain: &[Vec<u8>],
    ) -> Result<(), CredentialTrustError> {
        match self.format {
            CredentialFormat::SdJwtVc => verify_jwt(
                crypto,
                additional_trust_anchors,
                issuer_chain,
                issuer,
                self.uri,
                self.index,
                &self.token,
            ),
            CredentialFormat::MsoMdoc => verify_cwt(
                crypto,
                additional_trust_anchors,
                issuer_chain,
                self.uri,
                self.index,
                &self.token,
            ),
        }
    }
}

fn verify_jwt(
    crypto: &Openid4vcCredentialCrypto,
    additional_trust_anchors: &[Vec<u8>],
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
    let key = status_key(
        crypto,
        CredentialFormat::SdJwtVc,
        additional_trust_anchors,
        issuer_chain,
        &chain,
        Some(issuer),
    )?;
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
        Timestamp::now().as_second() as f64,
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
    additional_trust_anchors: &[Vec<u8>],
    issuer_chain: &[Vec<u8>],
    uri: &str,
    index: u64,
    token: &[u8],
) -> Result<(), CredentialTrustError> {
    let sign1 = parse_cwt_sign1(token)?;
    let protected = &sign1.protected.header;
    if !matches!(
        protected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            coset::iana::Algorithm::ES256 | coset::iana::Algorithm::ESP256
        ))
    ) {
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
    let key = status_key(
        crypto,
        CredentialFormat::MsoMdoc,
        additional_trust_anchors,
        issuer_chain,
        &chain,
        None,
    )?;
    nazo_crypto::signature::verify(
        Algorithm::ES256,
        &key,
        &sign1.tbs_data(&[]),
        &sign1.signature,
    )
    .map_err(|_| INVALID)?;
    let claims = nazo_mdoc::cbor::data_item::decode_cbor(sign1.payload.as_deref().ok_or(INVALID)?)
        .map_err(|_| INVALID)?;
    let claims = bounded_map(&claims)?;
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
        Timestamp::now().as_second() as f64,
    )?;
    let list = bounded_map(get(65533).ok_or(INVALID)?)?;
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

fn parse_cwt_sign1(token: &[u8]) -> Result<coset::CoseSign1, CredentialTrustError> {
    use nazo_mdoc::cbor::data_item::decode_cbor;

    let Cbor::Tag(18, tagged) = decode_cbor(token).map_err(|_| INVALID)? else {
        return Err(INVALID);
    };
    let Cbor::Array(fields) = *tagged else {
        return Err(INVALID);
    };
    let [protected, unprotected, payload, signature]: [Cbor; 4] =
        fields.try_into().map_err(|_| INVALID)?;
    let (Cbor::Bytes(protected_bytes), Cbor::Bytes(payload), Cbor::Bytes(signature)) =
        (protected, payload, signature)
    else {
        return Err(INVALID);
    };
    // Decode protected headers separately without coset's generic bstr decoder:
    // it otherwise normalizes small Tag 2/3 values into native integer labels.
    let protected = decode_cbor(&protected_bytes).map_err(|_| INVALID)?;
    // The bounded raw decoder has already rejected duplicate map keys.
    let protected_fields = bounded_map(&protected)?;
    let unprotected_fields = bounded_map(&unprotected)?;
    if protected_fields
        .iter()
        .any(|(key, _)| !matches!(key.as_integer().map(i128::from), Some(1 | 4 | 16 | 33)))
        || unprotected_fields.iter().any(|(key, _)| {
            key.as_integer().map(i128::from) != Some(4)
                || protected_fields
                    .iter()
                    .any(|(protected_key, _)| protected_key == key)
        })
    {
        return Err(INVALID);
    }
    Ok(coset::CoseSign1 {
        protected: coset::ProtectedHeader {
            // Verification uses this exact received bstr, not a re-encoded map.
            original_data: Some(protected_bytes),
            header: coset::Header::from_cbor_value(protected).map_err(|_| INVALID)?,
        },
        unprotected: coset::Header::from_cbor_value(unprotected).map_err(|_| INVALID)?,
        payload: Some(payload),
        signature,
    })
}

/// Lists are authorized by the credential's issuer, not by arbitrary keys found
/// in a signed list. Same-key JWTs reuse the authenticated issuer chain. mdoc's
/// separate MSO-list signer must be issued directly by that same IACA.
fn status_key(
    crypto: &Openid4vcCredentialCrypto,
    format: CredentialFormat,
    additional_trust_anchors: &[Vec<u8>],
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
    if format == CredentialFormat::SdJwtVc {
        // HAIP excludes trust anchors from x5c. Authenticate the presented chain,
        // then bind its signing key to the already authenticated credential key.
        let trust_material = crypto.credential_trust_material(additional_trust_anchors)?;
        let anchors = trust_material.trust_anchors_der();
        if chain
            .iter()
            .any(|der| anchors.contains(der) || additional_trust_anchors.contains(der))
        {
            return Err(INVALID);
        }
        let anchor = verify_openid4vc_chain_with_scoped(chain, anchors, additional_trust_anchors)
            .map_err(|_| INVALID)?;
        if leaf.public_key().raw != credential_signer.public_key().raw {
            return Err(INVALID);
        }
        crypto
            .current_revocation_policy()
            .check_chain_with_scoped_trust(
                issuer,
                chain,
                Timestamp::now(),
                additional_trust_anchors
                    .iter()
                    .any(|der| der.as_slice() == anchor),
            )?;
    } else {
        let trust_material = crypto.credential_trust_material(additional_trust_anchors)?;
        let anchors = trust_material.trust_anchors_der();
        let issuer = issuer_chain
            .iter()
            .skip(1)
            .chain(anchors.iter())
            .chain(
                additional_trust_anchors
                    .iter()
                    .filter(|anchor| !anchors.contains(anchor)),
            )
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
            Timestamp::now().as_second() as u64,
        )
        .map_err(|_| INVALID)?;
        crypto
            .current_revocation_policy()
            .check_chain_with_scoped_trust(
                None,
                chain,
                Timestamp::now(),
                additional_trust_anchors.contains(issuer),
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
fn bounded_map(value: &Cbor) -> Result<&[(Cbor, Cbor)], CredentialTrustError> {
    let map = value.as_map().ok_or(INVALID)?;
    if map.len() > 64 {
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
