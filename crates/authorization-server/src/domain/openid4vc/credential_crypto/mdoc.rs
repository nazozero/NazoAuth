use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::CborSerializable;
use jiff::Timestamp;
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{
    CredentialFormat, CredentialSignInput, CredentialTrustError, HolderBinding,
    PresentedCredential, VerifiedCredential,
};
use nazo_key_management::Openid4vcCertificates;
use nazo_mdoc::{
    Timestamp as MdocTimestamp,
    builder::DocumentBuilder,
    certificate::{
        check_iaca_link_profile, check_iaca_profile, check_issuer_binding,
        check_x5chain_root_exclusion,
    },
    model::types::{CoseAlgorithm, ValidityInfo},
    session::SessionTranscript,
    verifier::{VerificationOptions, verify_presentation_borrowed},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::super::crypto_helpers::{cbor_to_json, json_to_cbor, jwk_to_cose_key, parse_x509};
use super::{MdocStatusIssuancePolicy, Openid4vcCredentialCrypto, status};

const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

pub(super) fn to_protocol_time(value: Timestamp) -> Result<MdocTimestamp, CredentialTrustError> {
    MdocTimestamp::from_unix_nanos(value.as_nanosecond())
        .map_err(|_| CredentialTrustError::InvalidValidity)
}

pub(super) fn from_protocol_time(value: MdocTimestamp) -> Result<Timestamp, CredentialTrustError> {
    // The protocol type preserves leap seconds, whereas application deadlines
    // are POSIX instants. Reject an unrepresentable instant at this boundary;
    // never silently fold a signed leap second into an adjacent second.
    let nanos = value
        .unix_nanos()
        .ok_or(CredentialTrustError::InvalidValidity)?;
    Timestamp::from_nanosecond(nanos).map_err(|_| CredentialTrustError::InvalidValidity)
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
    check_mdoc_issuer_profiles(
        &certificate,
        signing_material.certificate_chain_der(),
        signing_material.trust_anchor_der(),
        signing_material.lease.certificates().trust_anchors_der(),
        &[],
        |der| signing_material.lease.certificates().mdoc_iaca_root_admitted(der),
        |_| {},
    )?;
    // The configured mDL dataset requires a country. The protocol core validates
    // every supplied mDL value and binds country/jurisdiction to the signer.
    if input.payload.credential_type == MDL_DOCTYPE
        && namespaces
            .get(MDL_NAMESPACE)
            .and_then(|namespace| namespace.get("issuing_country"))
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(CredentialTrustError::InvalidEncoding);
    }
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
            signing_material.certificate_chain_der(),
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
        .prepare(
            CoseAlgorithm::ES256,
            signing_material.certificate_chain_der().to_vec(),
        )
        .map_err(|error| match error {
            nazo_mdoc::MdocError::CertificateProfile(_) => CredentialTrustError::UntrustedIssuer,
            _ => CredentialTrustError::InvalidEncoding,
        })?;
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
    // Map the application's JSON representation. The builder validates the
    // selected mDL type and date once before exposing external signing input.
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
    now: jiff::Timestamp,
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
    let mut documents = verify_presentation_borrowed(
        &bytes,
        &transcript,
        &VerificationOptions {
            now: to_protocol_time(now)?,
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
        nazo_mdoc::MdocError::Certificate(_) | nazo_mdoc::MdocError::CertificateProfile(_) => {
            CredentialTrustError::UntrustedIssuer
        }
        _ => CredentialTrustError::InvalidEncoding,
    })?;
    // HAIP carries each credential in its own DeviceResponse. The core enforces
    // max_documents during parsing; an empty response provides no evidence.
    let pending = documents
        .pop()
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    let trust_material =
        crypto.credential_trust_material(&presentation.additional_trust_anchors)?;
    let issuer_chain_authority_key_identifiers = verify_mdoc_issuer_certificate_chain(
        pending.certificates(),
        pending.leaf_certificate(),
        now,
        &trust_material,
        &presentation.additional_trust_anchors,
        &crypto.current_revocation_policy(),
    )?;
    let (document, mso, certificates) = pending.into_parts();
    let holder_key = mdoc_holder_key(
        mso.device_key_info
            .device_key
            .into_owned()
            .map_err(|_| CredentialTrustError::InvalidHolderBinding)?
            .to_vec()
            .map_err(|_| CredentialTrustError::InvalidHolderBinding)?,
    );
    let status = mso.status.map(status::mdoc_reference_to_json).transpose()?;
    let mut namespaces = Map::new();
    for (namespace, items) in document.issuer_signed.name_spaces {
        let mut claims = Map::new();
        for item in items {
            claims.insert(
                item.element_identifier.to_owned(),
                cbor_to_json(item.element_value)?,
            );
        }
        namespaces.insert(namespace.to_owned(), Value::Object(claims));
    }
    let credential = VerifiedCredential {
        format: CredentialFormat::MsoMdoc,
        issuer: URL_SAFE_NO_PAD.encode(Sha256::digest(certificates[0])),
        issuer_chain_authority_key_identifiers,
        credential_type: mso.doc_type.to_owned(),
        claims: Value::Object(namespaces),
        holder_key: Some(holder_key),
        issued_at: Some(from_protocol_time(mso.validity_info.signed)?),
        expires_at: Some(from_protocol_time(mso.validity_info.valid_until)?),
        status,
    };
    // Only credential-status verification retains the chain after this decoded
    // presentation is released. Ordinary verification keeps every DER borrowed.
    let retained_certificates = if credential.status.is_some() {
        certificates.into_iter().map(<[u8]>::to_vec).collect()
    } else {
        Vec::new()
    };
    Ok((credential, retained_certificates))
}

fn verify_mdoc_issuer_certificate_chain(
    certificates: &[impl AsRef<[u8]>],
    leaf: &x509_parser::certificate::X509Certificate<'_>,
    now: jiff::Timestamp,
    trust_anchors: &Openid4vcCertificates,
    scoped_trust_anchors: &[Vec<u8>],
    revocation_policy: &nazo_digital_credentials::CertificateRevocationPolicy,
) -> Result<Vec<Vec<u8>>, CredentialTrustError> {
    // ISO 18013-5 §9.3.1 separately requires MSO.signed within the DS validity
    // interval (checked by the core). The RFC 5280 path and revocation checks
    // use this presentation's one current-time observation, never MSO.signed.
    // Jiff already guarantees a POSIX instant here; protocol leap seconds are
    // rejected at the protocol/application boundary in from_protocol_time.
    let anchor = verify_certificate_chain_with_scoped_at(
        certificates,
        trust_anchors.trust_anchors_der(),
        scoped_trust_anchors,
        now.as_second(),
    )?
    .ok_or(CredentialTrustError::UntrustedIssuer)?;
    // Compare against the actual authenticated issuing CA, including an IACA
    // link when present. A matching name in some other loaded anchor is no proof.
    let mut identifiers = Vec::new();
    super::certificates::append_authority_key_identifiers(leaf, &mut identifiers);
    check_mdoc_issuer_profiles(
        leaf,
        certificates,
        anchor,
        trust_anchors.trust_anchors_der(),
        scoped_trust_anchors,
        |der| trust_anchors.mdoc_iaca_root_admitted(der),
        |certificate| {
            super::certificates::append_authority_key_identifiers(certificate, &mut identifiers);
        },
    )?;
    let scoped_anchor_authenticated = scoped_trust_anchors
        .iter()
        .any(|candidate| candidate.as_slice() == anchor);
    revocation_policy.check_chain_with_scoped_trust(
        None,
        certificates,
        now,
        scoped_anchor_authenticated,
    )?;
    Ok(identifiers)
}

/// Select rollover evidence from deployment trust material after the path engine
/// authenticates the exact presented chain. ISO field relationships belong to
/// nazo-mdoc; root admission, signatures and evidence availability belong here.
pub(super) fn check_mdoc_issuer_profiles(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
    certificates: &[impl AsRef<[u8]>],
    anchor_der: &[u8],
    configured_roots: &[Vec<u8>],
    scoped_roots: &[Vec<u8>],
    admitted_root: impl Fn(&[u8]) -> Option<bool>,
    mut on_presented_ca: impl FnMut(&x509_parser::certificate::X509Certificate<'_>),
) -> Result<(), CredentialTrustError> {
    const INVALID: CredentialTrustError = CredentialTrustError::UntrustedIssuer;
    let (_, root) = parse_x509(anchor_der, "mdoc IACA root").map_err(|_| INVALID)?;
    // Configured IACA roots were authenticated at generation admission. Scoped
    // roots arrive per request and must still pass their own profile/signature.
    if !admitted_root(anchor_der).unwrap_or_else(|| {
        check_iaca_profile(&root).is_ok()
            && nazo_crypto::certificate::verify_signature(&root, root.public_key()).is_ok()
    }) {
        return Err(INVALID);
    }
    check_x5chain_root_exclusion(certificates, anchor_der).map_err(|_| INVALID)?;
    let links = &certificates[1..];
    if let Some((first, rest)) = links.split_first() {
        let (_, mut link) = parse_x509(first.as_ref(), "mdoc IACA link").map_err(|_| INVALID)?;
        check_issuer_binding(leaf, &link).map_err(|_| INVALID)?;
        let mut new_root = rollover_root(&link, configured_roots, scoped_roots, &admitted_root)?;
        for der in rest {
            let (_, issuer) = parse_x509(der.as_ref(), "mdoc IACA link").map_err(|_| INVALID)?;
            let old_root = rollover_root(&issuer, configured_roots, scoped_roots, &admitted_root)?;
            check_iaca_link_profile(&link, &old_root, &new_root).map_err(|_| INVALID)?;
            on_presented_ca(&link);
            link = issuer;
            new_root = old_root;
        }
        check_iaca_link_profile(&link, &root, &new_root).map_err(|_| INVALID)?;
        on_presented_ca(&link);
    } else {
        check_issuer_binding(leaf, &root).map_err(|_| INVALID)?;
    }
    Ok(())
}

fn rollover_root<'a>(
    link: &x509_parser::certificate::X509Certificate<'_>,
    configured: &'a [Vec<u8>],
    scoped: &'a [Vec<u8>],
    admitted_root: &impl Fn(&[u8]) -> Option<bool>,
) -> Result<x509_parser::certificate::X509Certificate<'a>, CredentialTrustError> {
    const INVALID: CredentialTrustError = CredentialTrustError::UntrustedIssuer;
    for der in scoped.iter().chain(configured) {
        let Ok((_, root)) = parse_x509(der, "mdoc rollover root") else {
            continue;
        };
        if root.subject().as_raw() == link.subject().as_raw()
            && root.public_key().raw == link.public_key().raw
            && root.issuer().as_raw() == root.subject().as_raw()
        {
            if !admitted_root(der).unwrap_or_else(|| {
                check_iaca_profile(&root).is_ok()
                    && nazo_crypto::certificate::verify_signature(&root, root.public_key()).is_ok()
            }) {
                return Err(INVALID);
            }
            return Ok(root);
        }
    }
    Err(INVALID)
}

pub(super) fn verify_certificate_chain_with_scoped_at<'a>(
    certificates: &[impl AsRef<[u8]>],
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
        let path = if certificates
            .last()
            .is_some_and(|certificate| certificate.as_ref() == anchor.as_slice())
        {
            &certificates[..certificates.len() - 1]
        } else {
            certificates
        };
        let chain: Vec<_> = path
            .iter()
            .map(|der| nazo_crypto::certificate::CertificateDer::from(der.as_ref()))
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
