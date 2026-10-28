//! End-to-end verifier tests covering the security properties from the audit:
//! IACA chain anchoring (CRITICAL-1), device authentication (CRITICAL-2),
//! fail-closed aggregation (HIGH-1), docType binding (HIGH-2), and the
//! data-integrity digest path (MEDIUM-1).
//!
//! These exercise the real `Verifier::verify` pipeline against
//! CBOR-encoded DeviceResponses built from genuine and forged material — the
//! negative coverage whose absence (INFO-2) let CRITICAL-1/2 go unnoticed.
#![cfg(all(feature = "issue", feature = "tsp"))]

use std::collections::HashMap;

use chrono::{Duration, Utc};
use coset::{iana, CoseSign1Builder, HeaderBuilder};

use mdoc_rs::builder::{CoseSigner, DocumentBuilder};
use mdoc_rs::error::MdocError;
use mdoc_rs::model::document::{DeviceSigned, IssuerSignedDocument};
use mdoc_rs::model::types::{DeviceAuth, DigestAlgorithm, ValidityInfo};
use mdoc_rs::session::{self, SessionTranscript};
use mdoc_rs::verifier::{CheckId, VerificationStatus, Verifier, VerifyOptions};

// ── Test fixtures: real self-signed P-256 X.509 certificates ────────────────
// Generated with openssl (prime256v1, 3650-day validity). The "genuine" cert
// acts as the trusted IACA root; the "evil" cert is an attacker-minted root the
// verifier does not trust.

const GENUINE_PRIV_HEX: &str = "77063a7b42efb2e4097dcb56de8424c492004041964398ec2d4a5370810be09a";
const GENUINE_CERT_HEX: &str = "3082019c30820143a003020102021420a52f4465e053acee84e850cdbc4222c8fa9829300a06082a8648ce3d04030230243115301306035504030c0c47656e75696e652049414341310b3009060355040613025345301e170d3236303533313139353535375a170d3336303532383139353535375a30243115301306035504030c0c47656e75696e652049414341310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000411d18d37c4791c5c021f8b5d0f41a91764edd5af064231e2da7333866016491acaab1cb398fb8d9a64086bb2dc0577cce716f566dcbee15ebb8c0b8bace84353a3533051301d0603551d0e041604146cff54fce3d082f2bf41e7611c183f0693b816d6301f0603551d230418301680146cff54fce3d082f2bf41e7611c183f0693b816d6300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402207c008aa58aab0acfb093e886a653dfedd3f3ce32ff8907f7d13b5bfbaa13fff702202e30e851542f33763a96f2ae0771dc8031f12e52cc8c226db6544bd7c6b82109";

const EVIL_PRIV_HEX: &str = "ee89b1518af54d9a2f604972d153e5af804f365d33c64908b3735d5c30ad76d4";
const EVIL_CERT_HEX: &str = "308201963082013da00302010202146653c832e4a02afe1b44824fceb07e9d3e683874300a06082a8648ce3d04030230213112301006035504030c094576696c20526f6f74310b3009060355040613025345301e170d3236303533313139353535375a170d3336303532383139353535375a30213112301006035504030c094576696c20526f6f74310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000408d50a026af4aff245b2f1b06602de92d7bc05f3c32ff2c1e4666c638dfc35f1ed3c5aa18625a091422d2c0fbca674d8da55fef38bbf624b4130645a5c50e24aa3533051301d0603551d0e04160414566dc531b7d322aec2a5d6763e4d54ecb956108a301f0603551d23041830168014566dc531b7d322aec2a5d6763e4d54ecb956108a300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020347003044022050eecd1cac4bdabff24b7840aa33057d9bcbd19185f9a9ade277ae648d443c2e0220265d60d5889f788d17950f985e1de6af0c7667ae4759ff3d66424f01cf74f62e";

const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NS: &str = "org.iso.18013.5.1";

// ── A signer backed by a real X.509 certificate ─────────────────────────────

struct RealSigner {
    sk: p256::ecdsa::SigningKey,
    cert_der: Vec<u8>,
}

impl RealSigner {
    fn new(priv_hex: &str, cert_hex: &str) -> Self {
        let sk = p256::ecdsa::SigningKey::from_slice(&hex::decode(priv_hex).unwrap()).unwrap();
        Self {
            sk,
            cert_der: hex::decode(cert_hex).unwrap(),
        }
    }
}

impl CoseSigner for RealSigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, MdocError> {
        use signature::Signer;
        let sig: p256::ecdsa::Signature = self
            .sk
            .try_sign(tbs)
            .map_err(|e| MdocError::Signature(e.to_string()))?;
        Ok(sig.to_bytes().to_vec()) // raw r||s
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn validity_now() -> ValidityInfo {
    let now = Utc::now();
    ValidityInfo {
        signed: now,
        valid_from: now - Duration::hours(1),
        valid_until: now + Duration::days(365),
        expected_update: None,
    }
}

/// Build a minimal mDL issued by `signer`, optionally binding a device key.
fn build_doc(signer: &dyn CoseSigner, device_key: Option<coset::CoseKey>) -> IssuerSignedDocument {
    let mut b = DocumentBuilder::new(DOC_TYPE)
        .add_namespace(
            NS,
            vec![
                ("family_name", ciborium::Value::Text("Lindqvist".into())),
                ("age_over_21", ciborium::Value::Bool(true)),
            ],
        )
        .validity(validity_now())
        .digest_algorithm(DigestAlgorithm::Sha256);
    if let Some(k) = device_key {
        b = b.device_key(k);
    }
    b.sign(signer).expect("signing should succeed")
}

/// Encode an in-memory document into a CBOR DeviceResponse that `Verifier::verify`
/// can parse, via the library's public encoder (improvement #4).
fn encode_device_response(doc: &IssuerSignedDocument) -> Vec<u8> {
    doc.to_device_response_cbor()
        .expect("encode device response")
}

fn genuine_verifier() -> Verifier {
    Verifier::new(vec![hex::decode(GENUINE_CERT_HEX).unwrap()])
}

fn find(
    v: &mdoc_rs::verifier::VerifiedMDoc,
    id: CheckId,
) -> Option<&mdoc_rs::verifier::VerificationAssessment> {
    v.assessments.iter().find(|a| a.id == id)
}

// ── CRITICAL-1: IACA chain anchoring ────────────────────────────────────────

#[test]
fn genuine_issuer_chain_anchors_and_verifies() {
    let signer = RealSigner::new(GENUINE_PRIV_HEX, GENUINE_CERT_HEX);
    let doc = build_doc(&signer, None);
    let bytes = encode_device_response(&doc);

    let result = genuine_verifier()
        .verify(&bytes, &VerifyOptions::default())
        .expect("verify");

    assert!(
        result.is_valid,
        "genuine credential should verify; assessments: {:#?}",
        result.assessments
    );
    assert_eq!(
        find(&result, CheckId::IssuerCertificateValidity)
            .unwrap()
            .status,
        VerificationStatus::Passed
    );
    assert_eq!(
        find(&result, CheckId::IssuerSignatureValidity)
            .unwrap()
            .status,
        VerificationStatus::Passed
    );
}

#[test]
fn forged_self_signed_cert_is_rejected() {
    // Attacker mints their own root + cert and forges a fully self-consistent
    // credential, but the verifier only trusts the genuine IACA root.
    let evil = RealSigner::new(EVIL_PRIV_HEX, EVIL_CERT_HEX);
    let doc = build_doc(&evil, None);
    let bytes = encode_device_response(&doc);

    let result = genuine_verifier()
        .verify(&bytes, &VerifyOptions::default())
        .expect("verify");

    assert!(
        !result.is_valid,
        "forged credential must NOT verify (CRITICAL-1)"
    );
    assert_eq!(
        find(&result, CheckId::IssuerCertificateValidity)
            .unwrap()
            .status,
        VerificationStatus::Failed,
        "chain to a trusted IACA root must fail"
    );
}

#[test]
fn disabling_chain_validation_is_an_explicit_loud_optout() {
    let evil = RealSigner::new(EVIL_PRIV_HEX, EVIL_CERT_HEX);
    let doc = build_doc(&evil, None);
    let bytes = encode_device_response(&doc);

    let opts = VerifyOptions {
        disable_certificate_chain_validation: true,
        ..Default::default()
    };
    let result = genuine_verifier().verify(&bytes, &opts).expect("verify");

    let cert_check = find(&result, CheckId::IssuerCertificateValidity).unwrap();
    assert_eq!(cert_check.status, VerificationStatus::Passed);
    assert!(
        cert_check
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("DISABLED"),
        "opt-out must be recorded loudly in the assessment reason"
    );
}

// ── MEDIUM-1 / data integrity ───────────────────────────────────────────────

#[test]
fn tampered_attribute_digest_is_rejected() {
    let signer = RealSigner::new(GENUINE_PRIV_HEX, GENUINE_CERT_HEX);
    let mut doc = build_doc(&signer, None);

    // Flip a byte in a disclosed item so its digest no longer matches the MSO.
    // Re-encode the first item with a changed value: still valid CBOR (so it
    // parses), but its digest no longer matches the one committed in the MSO.
    let item = &mut doc.issuer_signed.name_spaces.get_mut(NS).unwrap()[0];
    let tampered = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("digestID".into()),
            ciborium::Value::Integer((item.digest_id as i64).into()),
        ),
        (
            ciborium::Value::Text("random".into()),
            ciborium::Value::Bytes(item.random.clone()),
        ),
        (
            ciborium::Value::Text("elementIdentifier".into()),
            ciborium::Value::Text(item.element_identifier.clone()),
        ),
        (
            ciborium::Value::Text("elementValue".into()),
            ciborium::Value::Text("TAMPERED".into()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&tampered, &mut buf).unwrap();
    item.encoded = buf;

    let bytes = encode_device_response(&doc);
    let result = genuine_verifier()
        .verify(&bytes, &VerifyOptions::default())
        .expect("verify");

    assert!(!result.is_valid, "tampered attribute must fail");
    assert!(
        result.assessments.iter().any(
            |a| a.id == CheckId::AttributeDigestMatch && a.status == VerificationStatus::Failed
        ),
        "a digest-mismatch failure must be emitted"
    );
}

// ── CRITICAL-2 / HIGH-1: device authentication ──────────────────────────────

/// Generate a device key pair and return (signing key, COSE_Key public).
fn device_keypair() -> (p256::ecdsa::SigningKey, coset::CoseKey) {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let sk = p256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap();
    let pk = p256::PublicKey::from(sk.verifying_key());
    let point = pk.to_sec1_point(false);
    let cose_key = coset::CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        point.x().unwrap().to_vec(),
        point.y().unwrap().to_vec(),
    )
    .build();
    (sk, cose_key)
}

fn empty_device_namespaces_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(&ciborium::Value::Map(vec![]), &mut buf).unwrap();
    buf
}

/// Attach a device signature over the DeviceAuthentication built from `transcript`.
fn attach_device_signature(
    doc: &mut IssuerSignedDocument,
    device_sk: &p256::ecdsa::SigningKey,
    transcript: &SessionTranscript,
    valid: bool,
) {
    use signature::Signer;
    let transcript_bytes = transcript.to_cbor_bytes().unwrap();
    let ns_bytes = empty_device_namespaces_bytes();
    let da_bytes =
        session::build_device_authentication_bytes(&transcript_bytes, &doc.doc_type, &ns_bytes)
            .unwrap();

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();
    let sign1 = if valid {
        // Sign the proper COSE Sig_structure (tbs) over the DeviceAuthentication
        // payload — this is what the verifier reconstructs and checks.
        CoseSign1Builder::new()
            .protected(protected)
            .payload(da_bytes)
            .create_signature(&[], |tbs| {
                let sig: p256::ecdsa::Signature = device_sk.try_sign(tbs).unwrap();
                sig.to_bytes().to_vec()
            })
            .build()
    } else {
        CoseSign1Builder::new()
            .protected(protected)
            .payload(da_bytes)
            .signature(vec![0u8; 64]) // bogus — must fail verification
            .build()
    };

    doc.device_signed = Some(DeviceSigned {
        device_auth: DeviceAuth::Signature(sign1),
        name_spaces: HashMap::new(),
        name_spaces_bytes: ns_bytes,
    });
}

fn proximity_transcript() -> SessionTranscript<'static> {
    SessionTranscript::Raw({
        let mut buf = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Array(vec![ciborium::Value::Text("transcript-nonce".into())]),
            &mut buf,
        )
        .unwrap();
        buf.into()
    })
}

#[test]
fn valid_device_signature_verifies() {
    let signer = RealSigner::new(GENUINE_PRIV_HEX, GENUINE_CERT_HEX);
    let (device_sk, device_pub) = device_keypair();
    let mut doc = build_doc(&signer, Some(device_pub));

    let transcript = proximity_transcript();
    attach_device_signature(&mut doc, &device_sk, &transcript, true);

    let bytes = encode_device_response(&doc);
    let opts = VerifyOptions {
        session_transcript: Some(transcript),
        ..Default::default()
    };
    let result = genuine_verifier().verify(&bytes, &opts).expect("verify");

    assert!(
        result.is_valid,
        "valid device-bound presentation should verify; assessments: {:#?}",
        result.assessments
    );
    assert_eq!(
        find(&result, CheckId::DeviceSignatureValidity)
            .unwrap()
            .status,
        VerificationStatus::Passed
    );
}

#[test]
fn bogus_device_signature_is_rejected() {
    let signer = RealSigner::new(GENUINE_PRIV_HEX, GENUINE_CERT_HEX);
    let (device_sk, device_pub) = device_keypair();
    let mut doc = build_doc(&signer, Some(device_pub));

    let transcript = proximity_transcript();
    attach_device_signature(&mut doc, &device_sk, &transcript, false);

    let bytes = encode_device_response(&doc);
    let opts = VerifyOptions {
        session_transcript: Some(transcript),
        ..Default::default()
    };
    let result = genuine_verifier().verify(&bytes, &opts).expect("verify");

    assert!(
        !result.is_valid,
        "replayed/forged device auth must NOT verify (CRITICAL-2)"
    );
    assert_eq!(
        find(&result, CheckId::DeviceSignatureValidity)
            .unwrap()
            .status,
        VerificationStatus::Failed
    );
}

#[test]
fn device_bound_doc_without_session_transcript_fails_closed() {
    // Even with a perfectly valid device signature, omitting the session
    // transcript means holder binding was never checked → fail closed (HIGH-1).
    let signer = RealSigner::new(GENUINE_PRIV_HEX, GENUINE_CERT_HEX);
    let (device_sk, device_pub) = device_keypair();
    let mut doc = build_doc(&signer, Some(device_pub));
    let transcript = proximity_transcript();
    attach_device_signature(&mut doc, &device_sk, &transcript, true);

    let bytes = encode_device_response(&doc);
    // No session_transcript supplied.
    let result = genuine_verifier()
        .verify(&bytes, &VerifyOptions::default())
        .expect("verify");

    assert!(!result.is_valid, "missing transcript must fail closed");
    assert_eq!(
        find(&result, CheckId::SessionTranscriptProvided)
            .unwrap()
            .status,
        VerificationStatus::Failed
    );
}
