//! Interop test against the ISO/IEC 18013-5 Annex D example mDL (improvement #1).
//!
//! Validates the verifier against a *genuine conformant issuer* (the "utopia ds"
//! credential), not just our own self-issued material:
//!
//! - the credential parses without error,
//! - every disclosed attribute's digest matches the Tag-24-wrapped MSO digest
//!   (audit MEDIUM-1 — the one item the audit could not confirm without a real
//!   interop vector),
//! - full-date (Tag 1004) and tdate (Tag 0) values parse, and
//! - the issuer COSE_Sign1 signature verifies against the leaf in the x5chain.
//!
//! The vector's IACA root ("utopia iaca") is not embedded in the x5chain and the
//! MSO is long expired (validUntil 2021-10-01), so a full `is_valid` verdict at
//! today's date is *expected to be false*. We therefore split the checks:
//! (a) parse + digests + issuer signature (this file), vs (b) full is_valid,
//! which would additionally require the matching anchor and a session transcript.
#![cfg(all(feature = "issue", feature = "tsp"))]

use mdoc_rs::verifier::{CheckId, VerificationStatus, Verifier, VerifyOptions};

const ANNEX_D_MDL_HEX: &str = include_str!("vectors/iso_18013_5_annex_d_mdl.hex");

fn vector_bytes() -> Vec<u8> {
    hex::decode(ANNEX_D_MDL_HEX.trim()).expect("vector is valid hex")
}

#[test]
fn annex_d_mdl_parses() {
    // Exercise the hex convenience entry point (improvement #11) directly.
    let mdoc = mdoc_rs::parse_hex(ANNEX_D_MDL_HEX).expect("Annex D mDL must parse");
    assert_eq!(mdoc.version, "1.0");
    assert_eq!(mdoc.documents.len(), 1);
    let doc = &mdoc.documents[0];
    assert_eq!(doc.doc_type, "org.iso.18013.5.1.mDL");

    // The issuer-signed namespace and a known attribute are present.
    let ns = &doc.issuer_signed.name_spaces["org.iso.18013.5.1"];
    let family = ns
        .iter()
        .find(|i| i.element_identifier == "family_name")
        .expect("family_name present");
    assert_eq!(
        family.element_value,
        ciborium::Value::Text("Doe".into()),
        "family_name should decode to \"Doe\""
    );

    // The MSO decodes, including the full-date / tdate values and deviceKey.
    let mso = doc.issuer_signed.issuer_auth.mso().expect("MSO decodes");
    assert_eq!(mso.doc_type, "org.iso.18013.5.1.mDL");
    assert!(mso.device_key_info.is_some(), "deviceKey present in MSO");
    // validityInfo dates (Tag 0 tdate) parsed.
    assert_eq!(
        mso.validity_info.valid_until.to_rfc3339(),
        "2021-10-01T13:30:02+00:00"
    );
}

#[test]
fn annex_d_mdl_digests_match_and_issuer_signature_valid() {
    let bytes = vector_bytes();

    // Chain validation is disabled: the utopia IACA root is not in the vector's
    // x5chain. We still exercise digest matching and issuer-signature validity
    // against the genuine issuer.
    let opts = VerifyOptions {
        disable_certificate_chain_validation: true,
        ..Default::default()
    };
    let result = Verifier::new(vec![])
        .verify(&bytes, &opts)
        .expect("verify runs");

    // (a) Every disclosed attribute's digest matches the signed MSO (MEDIUM-1).
    let digest_checks: Vec<_> = result
        .assessments
        .iter()
        .filter(|a| a.id == CheckId::AttributeDigestMatch)
        .collect();
    assert!(!digest_checks.is_empty(), "digest checks must run");
    for a in &digest_checks {
        assert_eq!(
            a.status,
            VerificationStatus::Passed,
            "attribute digest must match against the real issuer: {a:?}"
        );
    }

    // (a) The issuer COSE_Sign1 signature verifies against the x5chain leaf.
    let sig = result
        .assessments
        .iter()
        .find(|a| a.id == CheckId::IssuerSignatureValidity)
        .expect("issuer signature check ran");
    assert_eq!(
        sig.status,
        VerificationStatus::Passed,
        "issuer signature must verify: {sig:?}"
    );

    // (b) Full validity is NOT expected: the MSO is long expired, so the overall
    // verdict fails closed on MSO validity-at-verification-time.
    assert!(
        !result.is_valid,
        "expired Annex D credential must not be overall-valid today"
    );
    let validity = result
        .assessments
        .iter()
        .find(|a| a.id == CheckId::MsoValidityAtVerificationTime)
        .expect("validity check ran");
    assert_eq!(
        validity.status,
        VerificationStatus::Failed,
        "expired MSO must fail the validity check"
    );
}
