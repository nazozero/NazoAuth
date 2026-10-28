//! Round-trip test: issue → verify selective disclosure on an mdoc document.
#![cfg(feature = "issue")]

use chrono::{Duration, Utc};
use mdoc_rs::builder::{CoseSigner, DocumentBuilder};
use mdoc_rs::disclosure;
use mdoc_rs::error::MdocError;
use mdoc_rs::model::types::{DigestAlgorithm, ValidityInfo};

/// Test P-256 signer that uses a dummy certificate.
struct TestSigner {
    signing_key: p256::ecdsa::SigningKey,
    /// A minimal dummy DER certificate (not valid X.509, just enough bytes for testing).
    cert_der: Vec<u8>,
}

impl TestSigner {
    fn new() -> Self {
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();

        // Use the public key SEC1 bytes as a dummy "certificate" for the test.
        // Real usage would have a proper X.509 certificate.
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = p256::PublicKey::from(verifying_key)
            .to_sec1_bytes()
            .to_vec();

        Self {
            signing_key,
            cert_der: pub_bytes,
        }
    }
}

impl CoseSigner for TestSigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, MdocError> {
        use signature::Signer;
        let sig: p256::ecdsa::Signature = self
            .signing_key
            .try_sign(tbs)
            .map_err(|e| MdocError::Signature(e.to_string()))?;
        // Return raw r||s for COSE (64 bytes for P-256)
        Ok(sig.to_bytes().to_vec())
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }
}

#[test]
fn issue_and_verify_disclosure() {
    let signer = TestSigner::new();

    let now = Utc::now();
    let validity = ValidityInfo {
        signed: now,
        valid_from: now,
        valid_until: now + Duration::days(365),
        expected_update: None,
    };

    // Build a minimal mDL document
    let doc = DocumentBuilder::new("org.iso.18013.5.1.mDL")
        .add_namespace(
            "org.iso.18013.5.1",
            vec![
                (
                    "family_name",
                    ciborium::Value::Text("Lindqvist".to_string()),
                ),
                ("given_name", ciborium::Value::Text("Anna".to_string())),
                (
                    "birth_date",
                    ciborium::Value::Tag(
                        1004,
                        Box::new(ciborium::Value::Text("1990-01-15".to_string())),
                    ),
                ),
                ("issuing_country", ciborium::Value::Text("SE".to_string())),
            ],
        )
        .validity(validity)
        .digest_algorithm(DigestAlgorithm::Sha256)
        .sign(&signer)
        .expect("document signing should succeed");

    // Verify the document type
    assert_eq!(doc.doc_type, "org.iso.18013.5.1.mDL");

    // Verify the MSO is parseable
    let mso = doc
        .issuer_signed
        .issuer_auth
        .mso()
        .expect("MSO should parse");
    assert_eq!(mso.version, "1.0");
    assert_eq!(mso.digest_algorithm, DigestAlgorithm::Sha256);
    assert_eq!(mso.doc_type, "org.iso.18013.5.1.mDL");

    // Verify valueDigests has the right namespace
    assert!(mso.value_digests.contains_key("org.iso.18013.5.1"));
    let ns_digests = &mso.value_digests["org.iso.18013.5.1"];
    assert_eq!(ns_digests.len(), 4, "four digest entries");

    // Verify selective disclosure — all digests should match
    let results = disclosure::verify_disclosure(&doc.issuer_signed.name_spaces, &mso)
        .expect("disclosure verification should succeed");

    assert_eq!(results.len(), 1, "one namespace");
    let ns_result = &results[0];
    assert_eq!(ns_result.namespace, "org.iso.18013.5.1");
    assert!(ns_result.is_valid, "all digests should match");
    assert_eq!(ns_result.attributes.len(), 4, "four attributes");

    for attr in &ns_result.attributes {
        assert!(
            attr.digest_matches,
            "digest for '{}' should match (reason: {:?})",
            attr.element_identifier, attr.reason
        );
    }

    // Verify we can extract the "certificate" from x5chain
    let cert_der = doc
        .issuer_signed
        .issuer_auth
        .certificate_der()
        .expect("certificate should be extractable");
    assert!(!cert_der.is_empty());

    // Verify the COSE_Sign1 signature field is non-empty
    assert!(!doc
        .issuer_signed
        .issuer_auth
        .cose_sign1
        .signature
        .is_empty());
}

#[test]
fn issue_pid_document() {
    let signer = TestSigner::new();

    let now = Utc::now();
    let validity = ValidityInfo {
        signed: now,
        valid_from: now,
        valid_until: now + Duration::days(30),
        expected_update: None,
    };

    let doc = DocumentBuilder::new("eu.europa.ec.eudiw.pid.1")
        .add_namespace(
            "eu.europa.ec.eudiw.pid.1",
            vec![
                ("family_name", ciborium::Value::Text("Svensson".to_string())),
                ("given_name", ciborium::Value::Text("Erik".to_string())),
                ("age_over_18", ciborium::Value::Bool(true)),
            ],
        )
        .validity(validity)
        .sign(&signer)
        .expect("PID document signing should succeed");

    assert_eq!(doc.doc_type, "eu.europa.ec.eudiw.pid.1");

    // Check attribute values are preserved
    let ns = doc
        .issuer_signed
        .name_spaces
        .get("eu.europa.ec.eudiw.pid.1")
        .expect("namespace should exist");
    assert_eq!(ns.len(), 3);

    let family = ns
        .iter()
        .find(|i| i.element_identifier == "family_name")
        .unwrap();
    assert_eq!(family.element_value.as_text().unwrap(), "Svensson");

    let age = ns
        .iter()
        .find(|i| i.element_identifier == "age_over_18")
        .unwrap();
    assert!(age.element_value.as_bool().unwrap());

    // Verify disclosure
    let mso = doc.issuer_signed.issuer_auth.mso().unwrap();
    let results = disclosure::verify_disclosure(&doc.issuer_signed.name_spaces, &mso).unwrap();
    assert!(results[0].is_valid);
}

#[test]
fn mso_validity_dates_parsed() {
    let signer = TestSigner::new();

    let now = Utc::now();
    let valid_from = now - Duration::hours(1);
    let valid_until = now + Duration::days(90);

    let validity = ValidityInfo {
        signed: now,
        valid_from,
        valid_until,
        expected_update: None,
    };

    let doc = DocumentBuilder::new("org.iso.18013.5.1.mDL")
        .add_namespace(
            "org.iso.18013.5.1",
            vec![("family_name", ciborium::Value::Text("Test".to_string()))],
        )
        .validity(validity)
        .sign(&signer)
        .expect("signing should succeed");

    let mso = doc.issuer_signed.issuer_auth.mso().unwrap();

    // Validity dates should be parsed (not just Utc::now() placeholders)
    assert!(mso.validity_info.valid_from < Utc::now());
    assert!(mso.validity_info.valid_until > Utc::now());
    assert!(mso.validity_info.signed <= Utc::now());
}
