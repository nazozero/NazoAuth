//! ISO 18013-5 certificate profiles at credential and material-admission boundaries.
//!
//! These checks inspect certificate fields. Signature/path validation, current
//! time, revocation, and authority selection remain with the caller's existing
//! X.509 engine. Serial-number entropy and contact-address reachability cannot
//! be established from a received certificate.

use std::collections::HashSet;

use iri_string::types::UriStr;
use jiff::{Span, Timestamp, tz::Offset};
use sha1::{Digest as _, Sha1};
use x509_parser::{
    certificate::X509Certificate,
    der_parser::{
        asn1_rs::{Any, Class, Tag},
        oid,
    },
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    x509::X509Version,
};

use crate::CredentialTrustError;

const INVALID: CredentialTrustError = CredentialTrustError::UntrustedIssuer;

/// Checks the additional DS constraints in ISO 18013-5:2021 Annex B.1.1/B.1.4.
/// The protocol core owns SPKI/key encoding; the existing RFC 5280 engine owns
/// version 3, matching signature identifiers and exact issuer/subject path names.
/// This is a profile check, not an authenticated-path or revocation result.
pub fn check_mdoc_document_signer_profile(
    certificate: &X509Certificate<'_>,
) -> Result<(), CredentialTrustError> {
    check_profile(certificate, false)
}

/// Checks a newly admitted IACA root's ISO 18013-5 Annex B.1.2 profile.
/// Its owner separately verifies the self-signature, current validity, tenant
/// authority and real CRL publication binding. Brainpool keys are unsupported.
pub fn check_mdoc_iaca_profile(
    certificate: &X509Certificate<'_>,
) -> Result<(), CredentialTrustError> {
    check_profile(certificate, true)
}

fn check_profile(
    certificate: &X509Certificate<'_>,
    iaca: bool,
) -> Result<(), CredentialTrustError> {
    let serial = certificate.raw_serial();
    let duration = certificate.validity().not_after.timestamp()
        - certificate.validity().not_before.timestamp();
    if serial.is_empty()
        || serial.len() > 20
        || serial[0] & 0x80 != 0
        || serial.iter().all(|byte| *byte == 0)
        || certificate.is_ca() != iaca
        || duration < 0
        || (!iaca && duration > 457 * 24 * 60 * 60)
        || ![
            oid!(1.2.840.10045.4.3.2),
            oid!(1.2.840.10045.4.3.3),
            oid!(1.2.840.10045.4.3.4),
        ]
        .contains(&certificate.signature_algorithm.algorithm)
    {
        return Err(INVALID);
    }
    if iaca {
        // RFC 5280 certificate validity uses whole seconds. Reject fractions
        // before converting to Unix seconds for the calendar-year bound.
        if certificate.validity().not_before.to_datetime().nanosecond() != 0
            || certificate.validity().not_after.to_datetime().nanosecond() != 0
        {
            return Err(INVALID);
        }
        let not_before =
            Timestamp::from_second(certificate.validity().not_before.timestamp())
                .map_err(|_| INVALID)?;
        // Calendar years, including February month-end clamping; not a fixed
        // 7305-day approximation that changes at Gregorian century boundaries.
        let latest = Offset::UTC
            .to_datetime(not_before)
            .checked_add(Span::new().years(20))
            .map_err(|_| INVALID)?;
        let latest = Offset::UTC.to_timestamp(latest).map_err(|_| INVALID)?;
        if certificate.version() != X509Version::V3
            || certificate.signature_algorithm != certificate.tbs_certificate.signature
            || certificate.subject().as_raw() != certificate.issuer().as_raw()
            || certificate.validity().not_after.timestamp() > latest.as_second()
        {
            return Err(INVALID);
        }
        let spki = certificate.public_key();
        let parameters = spki.algorithm.parameters.as_ref().ok_or(INVALID)?;
        if spki.algorithm.algorithm != oid!(1.2.840.10045.2.1)
            || parameters.class() != Class::Universal
            || parameters.header.assert_primitive().is_err()
            || spki.subject_public_key.unused_bits != 0
        {
            return Err(INVALID);
        }
        let curve = parameters.as_oid().map_err(|_| INVALID)?;
        let width = if curve == oid!(1.2.840.10045.3.1.7) {
            32
        } else if curve == oid!(1.3.132.0.34) {
            48
        } else if curve == oid!(1.3.132.0.35) {
            66
        } else {
            return Err(INVALID);
        };
        let point = spki.subject_public_key.data.as_ref();
        if point.first() != Some(&4) || point.len() != 1 + 2 * width {
            return Err(INVALID);
        }
        // The existing self-signature verifier validates this point using the
        // selected curve; this profile does not implement curve arithmetic.
    }
    subject_country(certificate)?;
    if certificate.subject().iter_common_name().next().is_none() {
        return Err(INVALID);
    }
    for attribute in certificate.subject().iter_attributes() {
        if attribute.attr_type() == &oid!(2.5.4.5) {
            check_name_string(attribute.attr_value(), true)?;
        } else if [
            oid!(2.5.4.3),  // commonName
            oid!(2.5.4.4),  // surname
            oid!(2.5.4.7),  // localityName
            oid!(2.5.4.8),  // stateOrProvinceName
            oid!(2.5.4.9),  // streetAddress
            oid!(2.5.4.10), // organizationName
            oid!(2.5.4.11), // organizationalUnitName
            oid!(2.5.4.12), // title
            oid!(2.5.4.41), // name
            oid!(2.5.4.42), // givenName
            oid!(2.5.4.43), // initials
            oid!(2.5.4.44), // generationQualifier
            oid!(2.5.4.65), // pseudonym
        ]
        .contains(attribute.attr_type())
        {
            check_name_string(attribute.attr_value(), false)?;
        }
    }

    let mut seen = HashSet::with_capacity(certificate.extensions().len());
    let (mut ku, mut eku, mut ski, mut aki, mut ian, mut crldp, mut constraints) =
        (false, iaca, false, iaca, false, false, !iaca);
    for extension in certificate.extensions() {
        if !seen.insert(&extension.oid)
            || [
                oid!(2.5.29.33), // PolicyMappings
                oid!(2.5.29.30), // NameConstraints
                oid!(2.5.29.36), // PolicyConstraints
                oid!(2.5.29.54), // InhibitAnyPolicy
                oid!(2.5.29.46), // FreshestCRL
            ]
            .contains(&extension.oid)
            || (extension.critical
                && extension.oid != oid!(2.5.29.15)
                && extension.oid
                    != if iaca {
                        oid!(2.5.29.19)
                    } else {
                        oid!(2.5.29.37)
                    })
        {
            return Err(INVALID);
        }
        match extension.parsed_extension() {
            ParsedExtension::KeyUsage(value) => {
                if !extension.critical || value.flags != if iaca { 0x60 } else { 1 } {
                    return Err(INVALID);
                }
                ku = true;
            }
            ParsedExtension::ExtendedKeyUsage(value) if !iaca => {
                if !extension.critical || !value.other.contains(&oid!(1.0.18013.5.1.2)) {
                    return Err(INVALID);
                }
                eku = true;
            }
            ParsedExtension::SubjectKeyIdentifier(value) => {
                if value.0
                    != Sha1::digest(certificate.public_key().subject_public_key.data.as_ref())
                        .as_slice()
                {
                    return Err(INVALID);
                }
                ski = true;
            }
            ParsedExtension::AuthorityKeyIdentifier(value) if !iaca => {
                if value
                    .key_identifier
                    .as_ref()
                    .is_none_or(|id| id.0.is_empty())
                {
                    return Err(INVALID);
                }
                aki = true;
            }
            ParsedExtension::BasicConstraints(value) if iaca => {
                if !extension.critical || !value.ca || value.path_len_constraint != Some(0) {
                    return Err(INVALID);
                }
                constraints = true;
            }
            ParsedExtension::IssuerAlternativeName(value) => {
                for name in &value.general_names {
                    match name {
                        GeneralName::URI(uri) => {
                            UriStr::new(uri).map_err(|_| INVALID)?;
                            ian = true;
                        }
                        GeneralName::RFC822Name(email) => {
                            if email.is_empty() || !email.is_ascii() {
                                return Err(INVALID);
                            }
                            ian = true;
                        }
                        _ => {}
                    }
                }
                if !ian {
                    return Err(INVALID);
                }
            }
            ParsedExtension::CRLDistributionPoints(value) => {
                if value.points.is_empty() {
                    return Err(INVALID);
                }
                for point in &value.points {
                    let Some(DistributionPointName::FullName(names)) = &point.distribution_point
                    else {
                        return Err(INVALID);
                    };
                    if point.reasons.is_some() || point.crl_issuer.is_some() {
                        return Err(INVALID);
                    }
                    let mut has_uri = false;
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            UriStr::new(uri).map_err(|_| INVALID)?;
                            has_uri = true;
                        }
                    }
                    if !has_uri {
                        return Err(INVALID);
                    }
                }
                crldp = true;
            }
            ParsedExtension::ParseError { .. } => return Err(INVALID),
            _ => {} // Annex B permits further non-critical extensions.
        }
    }
    if !(ku && eku && ski && aki && ian && crldp && constraints) {
        return Err(INVALID);
    }
    Ok(())
}

fn check_name_string(value: &Any<'_>, printable_only: bool) -> Result<(), CredentialTrustError> {
    if value.class() != Class::Universal || value.header.assert_primitive().is_err() {
        return Err(INVALID);
    }
    match value.tag() {
        Tag::PrintableString => value.as_printablestring().map(|_| ()).map_err(|_| INVALID),
        Tag::Utf8String if !printable_only => {
            value.as_utf8string().map(|_| ()).map_err(|_| INVALID)
        }
        _ => Err(INVALID),
    }
}

/// Checks DS-to-IACA field bindings after authenticating the actual path.
/// Pass the certificate that actually issued the DS, including an authenticated
/// IACA link when present; an unrelated certificate from a trust store is not a
/// substitute. The caller also checks the DS profile and the path signatures.
pub fn check_mdoc_issuer_binding(
    leaf: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), CredentialTrustError> {
    if subject_country(leaf)? != subject_country(issuer)? {
        return Err(INVALID);
    }
    if let Some(state) = subject_state(issuer)?
        && subject_state(leaf)? != Some(state)
    {
        return Err(INVALID);
    }
    let aki = leaf
        .get_extension_unique(&oid!(2.5.29.35))
        .map_err(|_| INVALID)?
        .ok_or(INVALID)?;
    let ski = issuer
        .get_extension_unique(&oid!(2.5.29.14))
        .map_err(|_| INVALID)?
        .ok_or(INVALID)?;
    let (
        ParsedExtension::AuthorityKeyIdentifier(aki_value),
        ParsedExtension::SubjectKeyIdentifier(ski_value),
    ) = (aki.parsed_extension(), ski.parsed_extension())
    else {
        return Err(INVALID);
    };
    if aki.critical
        || ski.critical
        || aki_value.key_identifier.as_ref().map(|value| value.0) != Some(ski_value.0)
        || ski_value.0
            != Sha1::digest(issuer.public_key().subject_public_key.data.as_ref()).as_slice()
    {
        return Err(INVALID);
    }
    Ok(())
}

fn subject_country<'a>(
    certificate: &'a X509Certificate<'_>,
) -> Result<&'a str, CredentialTrustError> {
    let mut countries = certificate.subject().iter_country();
    let attribute = countries.next().ok_or(INVALID)?;
    if countries.next().is_some() {
        return Err(INVALID);
    }
    check_name_string(attribute.attr_value(), true)?;
    let value = attribute.as_str().map_err(|_| INVALID)?;
    // ISO 18013-5 §7.3 also permits user-assigned/recognized country codes.
    // Authentic registration is an authority policy, not a hardcoded country list.
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(INVALID);
    }
    Ok(value)
}

fn subject_state<'a>(
    certificate: &'a X509Certificate<'_>,
) -> Result<Option<&'a str>, CredentialTrustError> {
    let mut states = certificate.subject().iter_state_or_province();
    let state = states
        .next()
        .map(|attribute| {
            check_name_string(attribute.attr_value(), false)?;
            attribute.as_str().map_err(|_| INVALID)
        })
        .transpose()?;
    if states.next().is_some() {
        return Err(INVALID);
    }
    Ok(state)
}
