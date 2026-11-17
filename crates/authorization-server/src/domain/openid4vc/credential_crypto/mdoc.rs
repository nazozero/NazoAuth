use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::CborSerializable;
use jiff::Timestamp;
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{
    CredentialFormat, CredentialSignInput, CredentialTrustError, HolderBinding,
    PresentedCredential, VerifiedCredential,
};
use nazo_mdoc::{
    Timestamp as MdocTimestamp,
    builder::DocumentBuilder,
    model::types::{CoseAlgorithm, ValidityInfo},
    session::SessionTranscript,
    verifier::{VerificationOptions, verify_presentation},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::super::crypto_helpers::{
    cbor_to_json, json_to_cbor, jwk_to_cose_key, validate_mdoc_date_tag,
};
use super::{MdocStatusIssuancePolicy, Openid4vcCredentialCrypto, status};

const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

pub(super) fn to_protocol_time(value: Timestamp) -> Result<MdocTimestamp, CredentialTrustError> {
    if value.subsec_nanosecond() >= 1_000_000_000 {
        // Chrono uses excess nanoseconds for a leap second. Never interpret
        // those as an ordinary Unix instant in the following second.
        MdocTimestamp::parse_rfc3339(&value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
            .map_err(|_| CredentialTrustError::InvalidValidity)
    } else {
        MdocTimestamp::from_unix_nanos(
            i128::from(value.as_second()) * 1_000_000_000 + i128::from(value.subsec_nanosecond()),
        )
        .map_err(|_| CredentialTrustError::InvalidValidity)
    }
}

pub(super) fn from_protocol_time(value: MdocTimestamp) -> Result<Timestamp, CredentialTrustError> {
    if let Some(nanos) = value.unix_nanos() {
        let seconds = i64::try_from(nanos.div_euclid(1_000_000_000))
            .map_err(|_| CredentialTrustError::InvalidValidity)?;
        let nanoseconds = u32::try_from(nanos.rem_euclid(1_000_000_000))
            .map_err(|_| CredentialTrustError::InvalidValidity)?;
        Timestamp::new(seconds, nanoseconds).ok_or(CredentialTrustError::InvalidValidity)
    } else {
        let text = value
            .format_rfc3339()
            .map_err(|_| CredentialTrustError::InvalidValidity)?;
        (&text)
            .parse::<jiff::Timestamp>()
            .map(|value| value)
            .map_err(|_| CredentialTrustError::InvalidValidity)
    }
}

pub(super) async fn sign(
    crypto: &Openid4vcCredentialCrypto,
    input: &CredentialSignInput,
) -> Result<String, CredentialTrustError> {
    let Some(HolderBinding::Jwk { jwk }) = input.payload.holder_binding.as_ref() else {
        return Err(CredentialTrustError::InvalidHolderBinding);
    };
    let namespaces = input
        .payload
        .subject_claims
        .as_object()
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    if input.status.is_some()
        && crypto.mdoc_status_issuance != MdocStatusIssuancePolicy::PublishedTokenStatusList
    {
        return Err(CredentialTrustError::InvalidStatus);
    }
    let resolved_status = match input.status.as_ref() {
        Some(reference) => {
            Some(status::resolve(crypto, CredentialFormat::MsoMdoc, reference).await?)
        }
        None => None,
    };
    let lease = crypto
        .prepare_signing()
        .map_err(|_| CredentialTrustError::Unavailable)?;
    let signing_material = crypto
        .signing_material(lease)
        .map_err(|_| CredentialTrustError::Unavailable)?;
    let (remainder, certificate) = x509_parser::parse_x509_certificate(signing_material.leaf_der())
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    if !remainder.is_empty() {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    validate_mdl_issuing_country(&certificate, &input.payload.credential_type, namespaces)?;
    let not_before =
        MdocTimestamp::from_unix_seconds(certificate.validity().not_before.timestamp())
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let not_after = MdocTimestamp::from_unix_seconds(certificate.validity().not_after.timestamp())
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    // The public certificate cohort boundary preserves privacy rounding without
    // extending the credential deadline or predating the selected signing key.
    let signed = to_protocol_time(input.issued_at)?.max(not_before);
    let expires_at = to_protocol_time(input.expires_at)?;
    if signed >= expires_at || signed > not_after {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    // The application's certificate path engine consumes ordinary Unix seconds.
    // Reject this unsupported signing instant instead of issuing a credential
    // that the same application would have to fold during trust validation.
    if signed.is_leap_second() {
        return Err(CredentialTrustError::InvalidValidity);
    }
    let mut builder = DocumentBuilder::new(&input.payload.credential_type)
        .device_key(jwk_to_cose_key(jwk)?)
        .validity(ValidityInfo {
            signed,
            valid_from: signed,
            valid_until: expires_at,
            expected_update: None,
        });
    if let Some(resolved_status) = resolved_status {
        // Fetch before selecting a lease. Authenticate the already published
        // list against that exact signing chain immediately before preparation.
        resolved_status.verify(
            crypto,
            &[],
            &input.payload.issuer,
            &signing_material.certificate_chain_der,
        )?;
        builder = builder.status_raw(json_to_cbor(
            input.status.as_ref().expect("resolved status reference"),
        )?);
    }
    for (namespace, values) in namespaces {
        let object = values
            .as_object()
            .ok_or(CredentialTrustError::InvalidEncoding)?;
        let entries = object
            .iter()
            .map(|(name, value)| {
                Ok((
                    name.as_str(),
                    mdoc_element_to_cbor(&input.payload.credential_type, namespace, name, value)?,
                ))
            })
            .collect::<Result<Vec<_>, CredentialTrustError>>()?;
        builder = builder.add_namespace(namespace, entries);
    }
    let prepared = builder
        .prepare(CoseAlgorithm::ES256, signing_material.certificate_chain_der)
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let signature = signing_material
        .lease
        .sign(SignRequest {
            purpose: SigningPurpose::Credential,
            algorithm: "ES256",
            signing_input: prepared.signing_input(),
        })
        .await
        .map_err(|_| CredentialTrustError::Unavailable)?;
    let document = prepared
        .finish(signature.into_bytes())
        .map_err(|_| CredentialTrustError::InvalidSignature)?;
    Ok(URL_SAFE_NO_PAD.encode(
        document
            .to_issuer_signed_cbor()
            .map_err(|_| CredentialTrustError::InvalidEncoding)?,
    ))
}

fn validate_mdl_issuing_country(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    credential_type: &str,
    namespaces: &Map<String, Value>,
) -> Result<(), CredentialTrustError> {
    if credential_type != MDL_DOCTYPE {
        return Ok(());
    }

    let mut country_attributes = certificate.subject().iter_country();
    let Some(country_attribute) = country_attributes.next() else {
        return Err(CredentialTrustError::InvalidEncoding);
    };
    if country_attributes.next().is_some() {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    let Some(country) = country_attribute.as_str().ok() else {
        return Err(CredentialTrustError::InvalidEncoding);
    };
    let issuing_country = namespaces
        .get(MDL_NAMESPACE)
        .and_then(Value::as_object)
        .and_then(|namespace| namespace.get("issuing_country"))
        .and_then(Value::as_str);
    if issuing_country != Some(country) {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    Ok(())
}

pub(super) fn mdoc_element_to_cbor(
    doc_type: &str,
    namespace: &str,
    element: &str,
    value: &Value,
) -> Result<ciborium::Value, CredentialTrustError> {
    if doc_type != MDL_DOCTYPE || namespace != MDL_NAMESPACE {
        return json_to_cbor(value);
    }
    match element {
        "portrait" | "signature_usual_mark" => {
            let encoded = value
                .as_str()
                .ok_or(CredentialTrustError::InvalidEncoding)?;
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map(ciborium::Value::Bytes)
                .map_err(|_| CredentialTrustError::InvalidEncoding)
        }
        "birth_date" => mdoc_date(value, true),
        "issue_date" | "expiry_date" => {
            mdoc_date(value, value.as_str().is_some_and(|date| date.len() == 10))
        }
        "portrait_capture_date" => mdoc_date(value, false),
        "driving_privileges" => {
            let privileges = value
                .as_array()
                .ok_or(CredentialTrustError::InvalidEncoding)?;
            privileges
                .iter()
                .map(|privilege| {
                    let fields = privilege
                        .as_object()
                        .ok_or(CredentialTrustError::InvalidEncoding)?;
                    let fields = fields
                        .iter()
                        .map(|(name, value)| {
                            let encoded = if matches!(name.as_str(), "issue_date" | "expiry_date") {
                                // ISO 18013-5 §7.2.4 uses full-date here, even though the
                                // top-level issue/expiry dates also permit tdate.
                                mdoc_date(value, true)?
                            } else {
                                json_to_cbor(value)?
                            };
                            Ok((ciborium::Value::Text(name.clone()), encoded))
                        })
                        .collect::<Result<Vec<_>, CredentialTrustError>>()?;
                    Ok(ciborium::Value::Map(fields))
                })
                .collect::<Result<Vec<_>, CredentialTrustError>>()
                .map(ciborium::Value::Array)
        }
        _ => json_to_cbor(value),
    }
}

fn mdoc_date(value: &Value, full_date: bool) -> Result<ciborium::Value, CredentialTrustError> {
    let text = value
        .as_str()
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    let tag = if full_date { 1004 } else { 0 };
    validate_mdoc_date_tag(tag, text)?;
    Ok(ciborium::Value::Tag(
        tag,
        Box::new(ciborium::Value::Text(text.to_owned())),
    ))
}

/// Authenticate protocol bytes first. Only this application owner completes
/// certificate path, certificate revocation and credential-status policy.
pub(super) fn verify(
    crypto: &Openid4vcCredentialCrypto,
    presentation: &PresentedCredential<'_>,
) -> Result<(VerifiedCredential, Vec<Vec<u8>>), CredentialTrustError> {
    // Bound the base64 allocation at the public credential boundary as well as
    // the decoded CBOR inside the protocol parser.
    let max_bytes = nazo_mdoc::cbor::raw::Limits::default().max_bytes;
    if presentation.encoded.len() > max_bytes.div_ceil(3) * 4 {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(presentation.encoded.as_bytes())
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let transcript_bytes = presentation
        .mdoc_session_transcript
        .as_deref()
        .ok_or(CredentialTrustError::InvalidHolderBinding)?;
    // PresentationService creates these bytes from its retained Final request;
    // enforce CBOR/profile structure here without re-encoding the signed bytes.
    let transcript = SessionTranscript::from_cbor(transcript_bytes)
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let mut documents = verify_presentation(
        &bytes,
        &transcript,
        &VerificationOptions {
            now: to_protocol_time(Timestamp::now())?,
            max_documents: 1,
        },
    )
    .map_err(|error| match error {
        nazo_mdoc::MdocError::DeviceAuth(_)
        | nazo_mdoc::MdocError::Session(_)
        | nazo_mdoc::MdocError::DocumentCount { .. } => CredentialTrustError::InvalidSessionBinding,
        nazo_mdoc::MdocError::Signature(_) | nazo_mdoc::MdocError::Disclosure(_) => {
            CredentialTrustError::InvalidSignature
        }
        nazo_mdoc::MdocError::Validity(_) => CredentialTrustError::InvalidValidity,
        nazo_mdoc::MdocError::Certificate(_) => CredentialTrustError::UntrustedIssuer,
        _ => CredentialTrustError::InvalidEncoding,
    })?;
    // HAIP carries each credential in its own DeviceResponse. The core enforces
    // max_documents during parsing; an empty response provides no evidence.
    let pending = documents
        .pop()
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    let trust_anchors = crypto.combined_trust_anchors(&presentation.additional_trust_anchors)?;
    verify_mdoc_issuer_certificate_chain(
        pending.certificates(),
        pending
            .mso()
            .validity_info
            .signed
            .unix_seconds()
            .ok_or(CredentialTrustError::InvalidValidity)?,
        &trust_anchors,
        &presentation.additional_trust_anchors,
        &crypto.current_revocation_policy(),
    )?;
    let holder_key = mdoc_holder_key(
        pending
            .device_key()
            .clone()
            .to_vec()
            .map_err(|_| CredentialTrustError::InvalidHolderBinding)?,
    );
    let (document, mso, certificates) = pending.into_parts();
    let status = mso
        .status
        .map(|status| status::mdoc_reference_to_json(status.raw))
        .transpose()?;
    let mut namespaces = Map::new();
    for (namespace, items) in document.issuer_signed.name_spaces {
        let mut claims = Map::new();
        for item in items {
            claims.insert(item.element_identifier, cbor_to_json(item.element_value)?);
        }
        namespaces.insert(namespace, Value::Object(claims));
    }
    Ok((
        VerifiedCredential {
            format: CredentialFormat::MsoMdoc,
            issuer: URL_SAFE_NO_PAD.encode(Sha256::digest(&certificates[0])),
            issuer_chain_authority_key_identifiers:
                super::certificates::issuer_authority_key_identifiers(&certificates)?,
            credential_type: mso.doc_type,
            claims: Value::Object(namespaces),
            holder_key: Some(holder_key),
            issued_at: Some(from_protocol_time(mso.validity_info.signed)?),
            expires_at: Some(from_protocol_time(mso.validity_info.valid_until)?),
            status,
        },
        certificates,
    ))
}

fn verify_mdoc_issuer_certificate_chain(
    certificates: &[Vec<u8>],
    signed_at: i64,
    trust_anchors: &[Vec<u8>],
    scoped_trust_anchors: &[Vec<u8>],
    revocation_policy: &nazo_digital_credentials::CertificateRevocationPolicy,
) -> Result<(), CredentialTrustError> {
    if certificates.is_empty() {
        return Err(CredentialTrustError::UntrustedIssuer);
    }
    let direct_scoped_trust_anchor =
        verify_direct_scoped_trust_anchor(certificates, scoped_trust_anchors, signed_at)?;
    let scoped_anchor_authenticated = if direct_scoped_trust_anchor {
        true
    } else {
        let anchor = verify_certificate_chain_with_scoped_at(
            certificates,
            trust_anchors,
            scoped_trust_anchors,
            signed_at,
        )?
        .ok_or(CredentialTrustError::UntrustedIssuer)?;
        scoped_trust_anchors
            .iter()
            .any(|candidate| candidate.as_slice() == anchor)
    };
    revocation_policy.check_chain_with_scoped_trust(
        None,
        certificates,
        Timestamp::now(),
        scoped_anchor_authenticated,
    )
}

/// Accept a single self-signed IACA only when an explicit, scoped trust policy
/// pins that exact certificate. The ordinary mdoc chain path remains strict and
/// continues to require a non-CA Document Signer leaf.
pub(super) fn verify_direct_scoped_trust_anchor(
    certificates: &[Vec<u8>],
    scoped_trust_anchors: &[Vec<u8>],
    unix_time: i64,
) -> Result<bool, CredentialTrustError> {
    let [certificate] = certificates else {
        return Ok(false);
    };
    if !scoped_trust_anchors.contains(certificate) {
        return Ok(false);
    }
    let at = x509_parser::time::ASN1Time::from_timestamp(unix_time)
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let (_, anchor) = x509_parser::parse_x509_certificate(certificate)
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    Ok(anchor.is_ca()
        && anchor.validity().is_valid_at(at)
        && anchor.issuer() == anchor.subject()
        && nazo_crypto::certificate::verify_signature(&anchor, anchor.public_key()).is_ok())
}

pub(super) fn verify_certificate_chain_with_scoped_at<'a>(
    certificates: &[Vec<u8>],
    anchors: &'a [Vec<u8>],
    scoped: &'a [Vec<u8>],
    unix_time: i64,
) -> Result<Option<&'a [u8]>, CredentialTrustError> {
    let unix_seconds =
        u64::try_from(unix_time).map_err(|_| CredentialTrustError::InvalidEncoding)?;
    for anchor in scoped
        .iter()
        .chain(anchors.iter().filter(|anchor| !scoped.contains(anchor)))
    {
        let path = if certificates.last() == Some(anchor) {
            &certificates[..certificates.len() - 1]
        } else {
            certificates
        };
        let chain: Vec<_> = path
            .iter()
            .map(|der| nazo_crypto::certificate::CertificateDer::from(der.as_slice()))
            .collect();
        if nazo_crypto::certificate::verify_document_signing_chain_at(
            &chain,
            &nazo_crypto::certificate::CertificateDer::from(anchor.as_slice()),
            unix_seconds,
        )
        .is_ok()
        {
            return Ok(Some(anchor));
        }
    }
    Ok(None)
}

fn mdoc_holder_key(encoded: Vec<u8>) -> Value {
    Value::Object(Map::from_iter([(
        "cose_key".to_owned(),
        Value::String(URL_SAFE_NO_PAD.encode(encoded)),
    )]))
}
