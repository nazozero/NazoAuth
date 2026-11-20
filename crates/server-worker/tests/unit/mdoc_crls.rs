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
        public_material_hash: blake3::hash(&serde_json::to_vec(public).unwrap()),
    }
}

fn now() -> Timestamp {
    let (_, crl) = x509_parser::parse_x509_crl(GOOD_CRL).unwrap();
    Timestamp::from_second(crl.last_update().timestamp() + 1).unwrap()
}

#[test]
fn signed_crl_is_bound_to_the_exact_public_authority_and_current_ds() {
    let public = public();
    validate_publication(
        &public,
        ISSUER,
        ISSUER_ID,
        &publication(&public, GOOD_CRL),
        now(),
    )
    .unwrap();
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
    let error = validate_publication(&public, ISSUER, ISSUER_ID, &artifact, now()).unwrap_err();
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
