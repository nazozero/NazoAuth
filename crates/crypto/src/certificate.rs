//! X.509 issuance and signature checks behind the crypto boundary.
//!
//! Verification is portable. Native certificate provisioning is an explicit
//! host capability selected with `certificate-issuance`.

#[cfg(feature = "certificate-issuance")]
pub use rcgen::string::PrintableString;
#[cfg(feature = "certificate-issuance")]
pub use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CustomExtension, DistinguishedName, DnType, DnValue, IsCa, KeyIdMethod, KeyUsagePurpose,
    RevokedCertParams, SerialNumber,
};
pub use rustls_pki_types::CertificateDer;

#[cfg(feature = "certificate-issuance")]
mod issuance;
#[cfg(feature = "certificate-issuance")]
pub use issuance::{
    generate_p256_private_key_pem, public_key_from_pem, self_signed, sign, sign_crl,
};

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod portable;

use std::time::Duration;

use crate::CryptoError;

/// Checks only this certificate's signature against the given issuer key.
/// Issuer/name/CA/time/revocation/anchor selection stays with the caller.
pub fn verify_signature(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    issuer_public_key: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
) -> crate::Result<()> {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        certificate
            .verify_signature(Some(issuer_public_key))
            .map_err(|_| CryptoError::InvalidSignature)
    }
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        portable::verify_certificate_signature(certificate, issuer_public_key)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// Validates an ordered document-signing certificate path against one explicit
/// trust anchor. The chain excludes that anchor. WebPKI owns path length, name
/// constraints, critical extensions, validity and signatures; KeyUsage is
/// checked here because WebPKI intentionally does not enforce that extension.
/// Application-specific EKU and revocation policy remain with the consumer.
pub fn verify_document_signing_chain_at(
    chain: &[CertificateDer<'_>],
    anchor: &CertificateDer<'_>,
    unix_seconds: u64,
) -> crate::Result<()> {
    use rustls_pki_types::UnixTime;
    use x509_parser::time::ASN1Time;

    let time = ASN1Time::from_timestamp(
        i64::try_from(unix_seconds).map_err(|_| CryptoError::InvalidInput)?,
    )
    .map_err(|_| CryptoError::InvalidInput)?;
    let (leaf, intermediates) = chain.split_first().ok_or(CryptoError::InvalidInput)?;
    for (index, der) in chain.iter().chain(std::iter::once(anchor)).enumerate() {
        let (remainder, certificate) = x509_parser::parse_x509_certificate(der.as_ref())
            .map_err(|_| CryptoError::InvalidInput)?;
        if !remainder.is_empty()
            || !certificate.validity().is_valid_at(time)
            || certificate.is_ca() != (index > 0)
        {
            return Err(CryptoError::InvalidInput);
        }
        if let Some(usage) = certificate
            .key_usage()
            .map_err(|_| CryptoError::InvalidInput)?
            && !(if index == 0 {
                usage.value.digital_signature()
            } else {
                usage.value.key_cert_sign()
            })
        {
            return Err(CryptoError::InvalidInput);
        }
    }
    let anchor = webpki::anchor_from_trusted_cert(anchor).map_err(|_| CryptoError::InvalidInput)?;
    let roots = [anchor];
    let leaf = webpki::EndEntityCert::try_from(leaf).map_err(|_| CryptoError::InvalidInput)?;
    // Every supplied intermediate must be on the authenticated path, in wire
    // order. Consumers use that same chain for revocation and authority facts.
    let exact_path = |path: &webpki::VerifiedPath<'_>| {
        if path
            .intermediate_certificates()
            .map(|cert| cert.der())
            .eq(intermediates
                .iter()
                .map(|der| CertificateDer::from_slice(der)))
        {
            Ok(())
        } else {
            Err(webpki::Error::UnknownIssuer)
        }
    };
    leaf.verify_for_usage(
        verification_algorithms(),
        &roots,
        intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(unix_seconds)),
        DocumentSigningEku,
        None,
        Some(&exact_path),
    )
    .map(|_| ())
    .map_err(|_| CryptoError::InvalidSignature)
}

// Document signing has no universal TLS client/server EKU. Consume and validate
// the extension's DER without inventing a TLS purpose for VC credentials.
struct DocumentSigningEku;

impl webpki::ExtendedKeyUsageValidator for DocumentSigningEku {
    fn validate(&self, usages: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for usage in usages {
            usage?;
        }
        Ok(())
    }
}

/// Standard client-certificate chain verification against PEM trust anchors
/// at a caller-supplied Unix time.
pub fn verify_client_chain_at(
    chain_der: &[CertificateDer<'_>],
    anchors_pem: &str,
    unix_seconds: u64,
) -> crate::Result<()> {
    use rustls_pki_types::{UnixTime, pem::PemObject as _};

    let certificates = CertificateDer::pem_slice_iter(anchors_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CryptoError::InvalidInput)?;
    let roots = certificates
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CryptoError::InvalidInput)?;
    if roots.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    let (leaf, intermediates) = chain_der.split_first().ok_or(CryptoError::InvalidInput)?;
    webpki::EndEntityCert::try_from(leaf)
        .map_err(|_| CryptoError::InvalidSignature)?
        .verify_for_usage(
            verification_algorithms(),
            &roots,
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(unix_seconds)),
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .map(|_| ())
        .map_err(|_| CryptoError::InvalidSignature)
}

fn verification_algorithms()
-> &'static [&'static dyn rustls_pki_types::SignatureVerificationAlgorithm] {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        use webpki::aws_lc_rs as algorithms;

        // Preserve the AWS-LC certificate algorithms previously selected by
        // rustls without constructing a TLS provider for each verification.
        static ALGORITHMS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
            algorithms::ECDSA_P256_SHA256,
            algorithms::ECDSA_P256_SHA384,
            algorithms::ECDSA_P256_SHA512,
            algorithms::ECDSA_P384_SHA256,
            algorithms::ECDSA_P384_SHA384,
            algorithms::ECDSA_P384_SHA512,
            algorithms::ECDSA_P521_SHA256,
            algorithms::ECDSA_P521_SHA384,
            algorithms::ECDSA_P521_SHA512,
            algorithms::ED25519,
            algorithms::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            algorithms::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            algorithms::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            algorithms::RSA_PKCS1_2048_8192_SHA256,
            algorithms::RSA_PKCS1_2048_8192_SHA384,
            algorithms::RSA_PKCS1_2048_8192_SHA512,
            algorithms::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
            algorithms::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
            algorithms::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
            algorithms::ML_DSA_44,
            algorithms::ML_DSA_65,
            algorithms::ML_DSA_87,
        ];
        ALGORITHMS
    }
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        portable::ALGORITHMS
    }
}
