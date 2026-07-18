use chrono::Utc;
use nazo_key_management::{MtlsTrustAnchorError, validate_mtls_trust_anchor};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};

fn certificate(ca: bool, include_key_cert_sign: bool) -> (PKey<Private>, X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).expect("RSA key")).expect("private key");
    let mut name = X509NameBuilder::new().expect("subject builder");
    name.append_entry_by_text("CN", "Trust Anchor Boundary Test")
        .expect("subject CN");
    let name = name.build();
    let mut builder = X509::builder().expect("certificate builder");
    builder.set_version(2).expect("X.509 v3");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&key).expect("public key");
    let not_before = Asn1Time::from_unix(Utc::now().timestamp() - 60).expect("not before");
    let not_after = Asn1Time::from_unix(Utc::now().timestamp() + 3600).expect("not after");
    builder.set_not_before(&not_before).expect("not before");
    builder.set_not_after(&not_after).expect("not after");
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if ca {
        constraints.ca();
    }
    builder
        .append_extension(constraints.build().expect("basic constraints"))
        .expect("append constraints");
    let mut usage = KeyUsage::new();
    usage.critical();
    if include_key_cert_sign {
        usage.key_cert_sign().crl_sign();
    } else {
        usage.digital_signature();
    }
    builder
        .append_extension(usage.build().expect("key usage"))
        .expect("append key usage");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("self-sign certificate");
    (key, builder.build())
}

#[test]
fn accepts_current_strong_ca_and_canonicalizes_pem() {
    let (_, certificate) = certificate(true, true);
    let pem = String::from_utf8(certificate.to_pem().expect("PEM")).expect("UTF-8 PEM");

    let validated = validate_mtls_trust_anchor(&pem).expect("valid CA");

    assert_eq!(validated.certificate_sha256.len(), 64);
    assert!(validated.subject_dn.contains("Trust Anchor Boundary Test"));
    assert!(
        validated
            .certificate_pem
            .ends_with("-----END CERTIFICATE-----\n")
    );
    assert!(validated.not_before < validated.not_after);
}

#[test]
fn rejects_leaf_and_ca_without_key_cert_sign() {
    let (_, leaf) = certificate(false, false);
    let leaf = String::from_utf8(leaf.to_pem().expect("leaf PEM")).expect("UTF-8 PEM");
    assert_eq!(
        validate_mtls_trust_anchor(&leaf),
        Err(MtlsTrustAnchorError::NotCertificateAuthority)
    );

    let (_, ca) = certificate(true, false);
    let ca = String::from_utf8(ca.to_pem().expect("CA PEM")).expect("UTF-8 PEM");
    assert_eq!(
        validate_mtls_trust_anchor(&ca),
        Err(MtlsTrustAnchorError::InvalidKeyUsage)
    );
}

#[test]
fn rejects_multiple_certificates_and_oversized_input() {
    let (_, certificate) = certificate(true, true);
    let pem = String::from_utf8(certificate.to_pem().expect("PEM")).expect("UTF-8 PEM");
    assert_eq!(
        validate_mtls_trust_anchor(&format!("{pem}{pem}")),
        Err(MtlsTrustAnchorError::InvalidPem)
    );
    assert_eq!(
        validate_mtls_trust_anchor(&"A".repeat(16 * 1024 + 1)),
        Err(MtlsTrustAnchorError::TooLarge)
    );
}
