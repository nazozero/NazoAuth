#![cfg(feature = "x509")]

use nazo_crypto::certificate::{self as certs, CertificateDer};

const NOW: u64 = 1_800_000_000;

fn ca(name: &str, path_length: u8) -> certs::CertificateParams {
    let mut params = certs::CertificateParams::default();
    params
        .distinguished_name
        .push(certs::DnType::CommonName, name);
    params.is_ca = certs::IsCa::Ca(certs::BasicConstraints::Constrained(path_length));
    params.key_usages = vec![certs::KeyUsagePurpose::KeyCertSign];
    params
}

#[test]
fn document_signing_checks_the_path_without_requiring_a_tls_eku() {
    let root_key = certs::generate_p256_private_key_pem().unwrap();
    let root = certs::self_signed(ca("root", 3), &root_key).unwrap();
    for case in ["valid", "pathlen", "keyusage", "nameconstraint", "critical"] {
        let issuer_key = certs::generate_p256_private_key_pem().unwrap();
        let mut issuer = ca("intermediate", if case == "pathlen" { 0 } else { 1 });
        if case == "keyusage" {
            issuer.key_usages = vec![certs::KeyUsagePurpose::DigitalSignature];
        }
        if case == "nameconstraint" {
            issuer.name_constraints = Some(rcgen::NameConstraints {
                permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("allowed.example".into())],
                excluded_subtrees: Vec::new(),
            });
        }
        let issuer = certs::sign(issuer, &issuer_key, &root, &root_key).unwrap();
        let leaf_key = certs::generate_p256_private_key_pem().unwrap();
        let mut leaf = certs::CertificateParams::new(vec!["document.example".to_owned()]).unwrap();
        leaf.key_usages = vec![certs::KeyUsagePurpose::DigitalSignature];
        // ISO mdoc document signing is not TLS client or server authentication.
        leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(vec![
            1, 0, 18013, 5, 1, 2,
        ])];
        if case == "critical" {
            let mut extension =
                certs::CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![0x05, 0x00]);
            extension.set_criticality(true);
            leaf.custom_extensions.push(extension);
        }
        let chain = if case == "pathlen" {
            let sub_key = certs::generate_p256_private_key_pem().unwrap();
            let sub = certs::sign(ca("sub-ca", 0), &sub_key, &issuer, &issuer_key).unwrap();
            vec![
                certs::sign(leaf, &leaf_key, &sub, &sub_key).unwrap(),
                sub,
                issuer,
            ]
        } else {
            vec![
                certs::sign(leaf, &leaf_key, &issuer, &issuer_key).unwrap(),
                issuer,
            ]
        };
        let chain: Vec<_> = chain.into_iter().map(CertificateDer::from).collect();
        assert_eq!(
            certs::verify_document_signing_chain_at(&chain, &root.as_slice().into(), NOW).is_ok(),
            case == "valid",
            "{case}",
        );
        if case == "valid" {
            let mut out_of_order = chain.clone();
            out_of_order.swap(0, 1);
            assert!(
                certs::verify_document_signing_chain_at(
                    &out_of_order,
                    &root.as_slice().into(),
                    NOW
                )
                .is_err()
            );
        }
    }
}
