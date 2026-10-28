//! COSE key and signature utilities for mdoc.

use crate::error::MdocError;
use coset::{iana, RegisteredLabelWithPrivate};

pub mod key;
mod verify;

pub use key::{cose_alg_to_name, CoseKeyExt};
pub use verify::verify_cose_signature;

/// Validate the COSE critical-header contract implemented by this crate.
///
/// RFC 9052 requires every entry in `crit` to name a protected header that the
/// recipient understands and processes. mdoc-rs currently processes only the
/// protected `alg` header, so all other assigned, text, and private-use labels
/// fail closed. A `crit` parameter in the unprotected bucket is always invalid.
pub(crate) fn validate_critical_headers(
    protected: &coset::ProtectedHeader,
    unprotected: &coset::Header,
) -> Result<(), MdocError> {
    if !unprotected.crit.is_empty() {
        return Err(MdocError::Cose(
            "critical headers must be in the protected header bucket".to_string(),
        ));
    }

    for label in &protected.header.crit {
        match label {
            RegisteredLabelWithPrivate::Assigned(iana::HeaderParameter::Alg) => {
                if protected.header.alg.is_none() {
                    return Err(MdocError::Cose(
                        "critical alg header is not present in the protected bucket".to_string(),
                    ));
                }
            }
            RegisteredLabelWithPrivate::Assigned(parameter) => {
                return Err(MdocError::Cose(format!(
                    "unsupported critical COSE header parameter: {parameter:?}"
                )));
            }
            RegisteredLabelWithPrivate::PrivateUse(value) => {
                return Err(MdocError::Cose(format!(
                    "unsupported private-use critical COSE header parameter: {value}"
                )));
            }
            RegisteredLabelWithPrivate::Text(value) => {
                return Err(MdocError::Cose(format!(
                    "unsupported text critical COSE header parameter: {value}"
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CborSerializable;

    #[test]
    fn accepts_present_protected_alg_as_understood_critical_header() {
        let protected = coset::ProtectedHeader {
            original_data: None,
            header: coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .add_critical(iana::HeaderParameter::Alg)
                .build(),
        };

        assert!(validate_critical_headers(&protected, &coset::Header::default()).is_ok());
    }

    #[test]
    fn rejects_private_use_critical_header() {
        let protected = coset::ProtectedHeader {
            original_data: None,
            header: coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(-65_537))
                .build(),
        };

        let error = validate_critical_headers(&protected, &coset::Header::default())
            .expect_err("private-use critical labels are not implemented");
        assert!(error.to_string().contains("private-use critical"));
    }

    #[test]
    fn rejects_critical_header_from_unprotected_bucket() {
        let protected = coset::ProtectedHeader::default();
        let unprotected = coset::HeaderBuilder::new()
            .add_critical(iana::HeaderParameter::Alg)
            .build();

        let error = validate_critical_headers(&protected, &unprotected)
            .expect_err("crit is required to be integrity protected");
        assert!(error.to_string().contains("protected header bucket"));
    }

    #[test]
    fn rejects_critical_alg_when_alg_header_is_absent() {
        let protected = coset::ProtectedHeader {
            original_data: None,
            header: coset::HeaderBuilder::new()
                .add_critical(iana::HeaderParameter::Alg)
                .build(),
        };

        let error = validate_critical_headers(&protected, &coset::Header::default())
            .expect_err("a critical label must name a present protected header");
        assert!(error.to_string().contains("is not present"));
    }

    #[test]
    fn serialized_empty_critical_array_is_rejected_during_cose_parse() {
        // COSE_Sign1 = [h'a10280', {}, nil, h'']: protected { 2: [] }.
        let encoded = [0x84, 0x43, 0xa1, 0x02, 0x80, 0xa0, 0xf6, 0x40];

        assert!(coset::CoseSign1::from_slice(&encoded).is_err());
    }

    #[test]
    fn serialized_private_use_critical_header_is_parsed_then_rejected() {
        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(-65_537))
            .build();
        let encoded = coset::CoseSign1Builder::new()
            .protected(protected)
            .signature(vec![0; 64])
            .build()
            .to_vec()
            .expect("serialize private-use critical header");
        let parsed = coset::CoseSign1::from_slice(&encoded)
            .expect("coset 0.4 represents private-use critical labels");

        let error = validate_critical_headers(&parsed.protected, &parsed.unprotected)
            .expect_err("mdoc-rs does not implement this private-use header");
        assert!(error.to_string().contains("private-use critical"));
    }
}
