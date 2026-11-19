use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::{CoseKeyBuilder, iana};
use nazo_crypto::jwt::{Algorithm, VerificationKey as JwtVerificationKey};
use nazo_digital_credentials::CredentialTrustError;
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use serde_json::{Map, Value, json};

pub(super) fn decoding_key_trust(
    jwk: &Value,
    algorithm: Algorithm,
) -> Result<JwtVerificationKey, CredentialTrustError> {
    match algorithm {
        Algorithm::ES256 => JwtVerificationKey::from_ec_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding),
        Algorithm::EdDSA => JwtVerificationKey::from_ed_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding),
        _ => Err(CredentialTrustError::InvalidHolderBinding),
    }
}

pub(super) fn timestamp_claim(value: &Value, name: &str) -> Option<jiff::Timestamp> {
    jiff::Timestamp::from_second(value.get(name)?.as_i64()?).ok()
}

pub(crate) fn jwk_to_cose_key(jwk: &Value) -> Result<coset::CoseKey, CredentialTrustError> {
    match jwk.get("kty").and_then(Value::as_str) {
        Some("EC") if jwk.get("crv").and_then(Value::as_str) == Some("P-256") => {
            jwk_to_ec2_cose_key(jwk)
        }
        _ => Err(CredentialTrustError::InvalidHolderBinding),
    }
}

pub(super) fn jwk_to_ec2_cose_key(jwk: &Value) -> Result<coset::CoseKey, CredentialTrustError> {
    let x = URL_SAFE_NO_PAD
        .decode(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding)?;
    let y = URL_SAFE_NO_PAD
        .decode(
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding)?;
    Ok(CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y).build())
}

pub(super) fn json_to_cbor(value: &Value) -> Result<ciborium::Value, CredentialTrustError> {
    match value {
        Value::Null => Ok(ciborium::Value::Null),
        Value::Bool(value) => Ok(ciborium::Value::Bool(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(|value| ciborium::Value::Integer(value.into()))
            .or_else(|| {
                value
                    .as_u64()
                    .map(|value| ciborium::Value::Integer(value.into()))
            })
            .or_else(|| value.as_f64().map(ciborium::Value::Float))
            .ok_or(CredentialTrustError::InvalidEncoding),
        Value::String(value) => Ok(ciborium::Value::Text(value.clone())),
        Value::Array(values) => values
            .iter()
            .map(json_to_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(ciborium::Value::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((ciborium::Value::Text(key.clone()), json_to_cbor(value)?)))
            .collect::<Result<Vec<_>, _>>()
            .map(ciborium::Value::Map),
    }
}

/// Project the already validated, authenticated CBOR directly into the owned
/// JSON result. Signed envelopes, digest maps and binary claim input stay borrowed.
pub(super) fn cbor_to_json(
    value: nazo_mdoc::model::borrowed::CborValueRef<'_>,
) -> Result<Value, CredentialTrustError> {
    const INVALID: CredentialTrustError = CredentialTrustError::InvalidEncoding;
    match value.encoded()[0] >> 5 {
        0 | 1 => {
            let value = value.as_integer().ok_or(INVALID)?;
            i64::try_from(value)
                .map(|value| json!(value))
                .or_else(|_| u64::try_from(value).map(|value| json!(value)))
                .map_err(|_| INVALID)
        }
        2 => Ok(Value::String(
            URL_SAFE_NO_PAD.encode(value.as_bytes().ok_or(INVALID)?),
        )),
        3 => Ok(Value::String(value.as_text().ok_or(INVALID)?.to_owned())),
        4 => value
            .array()
            .map_err(|_| INVALID)?
            .map(|value| cbor_to_json(value.map_err(|_| INVALID)?))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        5 => value
            .map()
            .map_err(|_| INVALID)?
            .map(|entry| {
                let (key, value) = entry.map_err(|_| INVALID)?;
                Ok((
                    key.as_text().ok_or(INVALID)?.to_owned(),
                    cbor_to_json(value)?,
                ))
            })
            .collect::<Result<Map<_, _>, _>>()
            .map(Value::Object),
        6 => {
            let (tag, value) = value.tagged().map_err(|_| INVALID)?;
            let text = value.as_text().ok_or(INVALID)?;
            nazo_mdoc::cbor::validate_date_tag(tag, text).map_err(|_| INVALID)?;
            Ok(Value::String(text.to_owned()))
        }
        7 if value.is_null() => Ok(Value::Null),
        7 => {
            if let Some(value) = value.as_bool() {
                return Ok(Value::Bool(value));
            }
            value
                .as_float()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number)
                .ok_or(INVALID)
        }
        _ => Err(INVALID),
    }
}

pub(super) fn algorithm_name(algorithm: Algorithm) -> Option<&'static str> {
    match algorithm {
        Algorithm::ES256 => Some("ES256"),
        Algorithm::EdDSA => Some("EdDSA"),
        _ => None,
    }
}

pub(super) fn parse_pem_certificates(pem: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    CertificateDer::pem_slice_iter(pem)
        .map(|certificate| certificate.map(|certificate| certificate.as_ref().to_vec()))
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

pub(super) fn parse_x509<'a>(
    der: &'a [u8],
    description: &str,
) -> anyhow::Result<(&'a [u8], x509_parser::certificate::X509Certificate<'a>)> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("failed to parse {description}: {error}"))?;
    if !remainder.is_empty() {
        anyhow::bail!("{description} contains trailing DER data");
    }
    Ok((remainder, certificate))
}

pub(super) fn verify_openid4vc_chain<'a>(
    certificates: &[Vec<u8>],
    anchors: &'a [Vec<u8>],
) -> anyhow::Result<&'a [u8]> {
    verify_openid4vc_chain_with_scoped(certificates, anchors, &[])
}

pub(super) fn verify_openid4vc_chain_with_scoped<'a>(
    certificates: &[Vec<u8>],
    anchors: &'a [Vec<u8>],
    scoped: &'a [Vec<u8>],
) -> anyhow::Result<&'a [u8]> {
    let chain = certificates
        .iter()
        .enumerate()
        .filter(|(index, der)| *index == 0 || (!anchors.contains(der) && !scoped.contains(der)))
        .map(|(_, der)| CertificateDer::from(der.as_slice()))
        .collect::<Vec<_>>();
    let now = u64::try_from(jiff::Timestamp::now().as_second())?;
    let anchored = scoped
        .iter()
        .chain(anchors.iter().filter(|anchor| !scoped.contains(anchor)))
        .find(|anchor| {
            nazo_crypto::certificate::verify_document_signing_chain_at(
                &chain,
                &CertificateDer::from(anchor.as_slice()),
                now,
            )
            .is_ok()
        });
    let Some(anchored) = anchored else {
        anyhow::bail!(
            "OpenID4VC signing certificate is not anchored by the configured trust store"
        );
    };
    // A presented configured anchor is a chain fact only when it is the
    // actual authenticated terminus. Do not admit ignored, unrelated anchors
    // into later revocation or trusted-authority projections.
    if certificates.iter().enumerate().skip(1).any(|(index, der)| {
        (anchors.contains(der) || scoped.contains(der))
            && (index + 1 != certificates.len() || der.as_slice() != anchored.as_slice())
    }) {
        anyhow::bail!("OpenID4VC presented chain contains an unused configured anchor");
    }
    Ok(anchored.as_slice())
}
