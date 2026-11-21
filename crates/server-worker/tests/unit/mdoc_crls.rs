#![cfg(not(target_arch = "wasm32"))]

use super::*;

// Only public certificate/CRL artifacts are retained. The native IACA signing
// key was used offline and is not part of the Worker or these fixtures.
const PUBLIC: &str = include_str!("../fixtures/mdoc/public.json");
const GOOD_CRL: &[u8] = include_bytes!("../fixtures/mdoc/good.crl.der");
const REVOKED_CRL: &[u8] = include_bytes!("../fixtures/mdoc/revoked.crl.der");
const ISSUER: &str = "https://free-test-206.nazoauth.com";
const ISSUER_ID: &str = "f311a5d7ed5f5c8236011739a7e3348d644e94aff48404ced0c7af9e862d3baa";

fn public() -> Openid4vcPublicMaterial {
    serde_json::from_str(PUBLIC).unwrap()
}

fn publication(public: &Openid4vcPublicMaterial, der: &'static [u8]) -> PublishedCrl {
    PublishedCrl {
        der: Bytes::from_static(der),
        der_sha256: Sha256::digest(der).into(),
        public_material_hash: blake3::hash(&serde_json::to_vec(public).unwrap()),
    }
}

fn now() -> Timestamp {
    let (_, crl) = x509_parser::parse_x509_crl(GOOD_CRL).unwrap();
    Timestamp::from_second(crl.last_update().timestamp() + 1).unwrap()
}

#[test]
fn crl_number_extension_requires_complete_canonical_positive_der() {
    for encoded in [
        vec![],
        vec![0x02, 0x00],
        vec![0x02, 0x01, 0x00],
        vec![0x02, 0x01, 0x80],
        vec![0x02, 0x01, 0xff],
        vec![0x02, 0x02, 0x00, 0x01],
        vec![0x02, 0x01, 0x01, 0x00],
        vec![0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
        vec![0x22, 0x01, 0x01],
        vec![0x82, 0x01, 0x01],
        vec![0x02, 0x81, 0x01, 0x01],
        vec![0x1f, 0x02, 0x01, 0x01],
    ] {
        assert!(publication_number(&encoded).is_err(), "{encoded:02x?}");
    }
    assert_eq!(
        publication_number(&[0x02, 0x02, 0x00, 0x80])
            .unwrap()
            .to_fixed_hex(),
        format!("{:040x}", 128),
    );
}

#[test]
fn crl_number_der_length_counts_the_positive_sign_octet() {
    let mut largest = vec![0x02, 20, 0x7f];
    largest.extend([0xff; 19]);
    assert_eq!(
        publication_number(&largest).unwrap().to_fixed_hex(),
        format!("7{}", "f".repeat(39)),
    );
    let mut padded = vec![0x02, 20, 0x00, 0x80];
    padded.extend([0x00; 18]);
    assert!(publication_number(&padded).is_ok());
    let mut oversized = vec![0x02, 21, 0x00, 0x80];
    oversized.extend([0x00; 19]);
    assert!(publication_number(&oversized).is_err());
    let mut unpadded_oversized = vec![0x02, 21, 0x01];
    unpadded_oversized.extend([0x00; 20]);
    assert!(publication_number(&unpadded_oversized).is_err());
}

#[test]
fn signed_crl_is_bound_to_the_exact_public_authority_and_current_ds() {
    let public = public();
    let verified = validate_publication(
        &public,
        ISSUER,
        ISSUER_ID,
        &publication(&public, GOOD_CRL),
        now(),
    )
    .unwrap();
    assert_eq!(
        verified.number.to_fixed_hex(),
        format!("{:040x}", u128::from(u64::MAX) + 5),
    );
    assert!(
        validate_publication(
            &public,
            "https://other.example",
            ISSUER_ID,
            &publication(&public, GOOD_CRL),
            now()
        )
        .is_err()
    );
    assert!(
        validate_publication(
            &public,
            ISSUER,
            &"0".repeat(64),
            &publication(&public, GOOD_CRL),
            now()
        )
        .is_err()
    );
}

#[test]
fn signed_crl_rejects_future_expired_and_out_of_snapshot_windows() {
    let mut public = public();
    let (_, crl) = x509_parser::parse_x509_crl(GOOD_CRL).unwrap();
    let before = Timestamp::from_second(crl.last_update().timestamp() - 1).unwrap();
    let deadline = Timestamp::from_second(crl.next_update().unwrap().timestamp()).unwrap();
    for invalid_now in [before, deadline] {
        assert!(
            validate_publication(
                &public,
                ISSUER,
                ISSUER_ID,
                &publication(&public, GOOD_CRL),
                invalid_now
            )
            .is_err()
        );
    }
    public.revocation_snapshot.as_mut().unwrap().next_update =
        deadline - jiff::SignedDuration::from_secs(1);
    assert!(
        validate_publication(
            &public,
            ISSUER,
            ISSUER_ID,
            &publication(&public, GOOD_CRL),
            now()
        )
        .is_err()
    );
    public.revocation_snapshot.as_mut().unwrap().next_update = now();
    assert!(
        validate_publication(
            &public,
            ISSUER,
            ISSUER_ID,
            &publication(&public, GOOD_CRL),
            now()
        )
        .is_err()
    );
}

#[test]
fn signed_crl_rejects_signature_tampering_and_trailing_data() {
    let public = public();
    let mut tampered = GOOD_CRL.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let mut trailing = GOOD_CRL.to_vec();
    trailing.push(0);
    for bytes in [tampered, trailing] {
        let mut artifact = publication(&public, GOOD_CRL);
        artifact.der = bytes.into();
        assert!(validate_publication(&public, ISSUER, ISSUER_ID, &artifact, now()).is_err());
    }
}

#[test]
fn changed_authority_generation_invalidates_an_otherwise_valid_crl() {
    let mut public = public();
    let artifact = publication(&public, GOOD_CRL);
    public.signing_kid.push_str("-new-generation");
    let error = validate_publication(&public, ISSUER, ISSUER_ID, &artifact, now())
        .err()
        .expect("tampered CRL must be rejected");
    assert_eq!(error.to_string(), "mdoc CRL authority generation changed");
}

#[test]
fn revoked_ds_requires_the_exact_serial_and_recorded_revocation_time() {
    let mut public = public();
    let (_, crl) = x509_parser::parse_x509_crl(REVOKED_CRL).unwrap();
    let recorded_time = Timestamp::from_second(
        crl.tbs_cert_list.revoked_certificates[0]
            .revocation_date
            .timestamp(),
    )
    .unwrap();
    assert!(
        validate_publication(
            &public,
            ISSUER,
            ISSUER_ID,
            &publication(&public, REVOKED_CRL),
            now()
        )
        .is_err()
    );
    let identity = certificate_identity(&certificates(&public.certificate_chain_pem).unwrap()[0]);
    let entry = public
        .revocation_snapshot
        .as_mut()
        .unwrap()
        .entries
        .iter_mut()
        .find(|entry| entry.issuer == ISSUER && entry.certificate == identity)
        .unwrap();
    entry.status = CertificateRevocationStatus::Revoked;
    entry.revoked_at = Some(recorded_time);
    validate_publication(
        &public,
        ISSUER,
        ISSUER_ID,
        &publication(&public, REVOKED_CRL),
        now(),
    )
    .unwrap();
    assert!(
        validate_publication(
            &public,
            ISSUER,
            ISSUER_ID,
            &publication(&public, GOOD_CRL),
            now()
        )
        .is_err()
    );
    public
        .revocation_snapshot
        .as_mut()
        .unwrap()
        .entries
        .iter_mut()
        .find(|entry| entry.issuer == ISSUER && entry.certificate == identity)
        .unwrap()
        .revoked_at = Some(recorded_time + jiff::SignedDuration::from_secs(1));
    assert!(
        validate_publication(
            &public,
            ISSUER,
            ISSUER_ID,
            &publication(&public, REVOKED_CRL),
            now()
        )
        .is_err()
    );
}
