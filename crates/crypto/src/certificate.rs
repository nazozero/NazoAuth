//! X.509 issuance and signature checks behind the crypto boundary.
//!
//! Certificate profile DTOs are the same upstream types the codebase already
//! used; private keys, issuers, and the native chain verifier stay private.

pub use rcgen::string::PrintableString;
pub use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CustomExtension, DistinguishedName, DnType, DnValue, IsCa, KeyIdMethod, KeyUsagePurpose,
    RevokedCertParams, SerialNumber,
};

use std::sync::Arc;
use std::time::Duration;

use crate::CryptoError;

pub fn generate_p256_private_key_pem() -> crate::Result<String> {
    Ok(rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|_| CryptoError::OperationFailed)?
        .serialize_pem())
}

pub fn public_key_from_pem(private_key_pem: &str) -> crate::Result<Vec<u8>> {
    Ok(rcgen::KeyPair::from_pem(private_key_pem)
        .map_err(|_| CryptoError::InvalidKey)?
        .public_key_raw()
        .to_vec())
}

pub fn self_signed(params: CertificateParams, private_key_pem: &str) -> crate::Result<Vec<u8>> {
    let key = rcgen::KeyPair::from_pem(private_key_pem).map_err(|_| CryptoError::InvalidKey)?;
    Ok(rcgen::CertifiedIssuer::self_signed(params, key)
        .map_err(|_| CryptoError::OperationFailed)?
        .der()
        .to_vec())
}

pub fn sign(
    params: CertificateParams,
    subject_key_pem: &str,
    issuer_certificate_der: &[u8],
    issuer_key_pem: &str,
) -> crate::Result<Vec<u8>> {
    let subject_key =
        rcgen::KeyPair::from_pem(subject_key_pem).map_err(|_| CryptoError::InvalidKey)?;
    let issuer_key =
        rcgen::KeyPair::from_pem(issuer_key_pem).map_err(|_| CryptoError::InvalidKey)?;
    let issuer = rcgen::Issuer::from_ca_cert_der(&issuer_certificate_der.into(), issuer_key)
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(params
        .signed_by(&subject_key, &issuer)
        .map_err(|_| CryptoError::OperationFailed)?
        .der()
        .to_vec())
}

pub fn sign_crl(
    params: CertificateRevocationListParams,
    issuer_certificate_der: &[u8],
    issuer_key_pem: &str,
) -> crate::Result<Vec<u8>> {
    let issuer_key =
        rcgen::KeyPair::from_pem(issuer_key_pem).map_err(|_| CryptoError::InvalidKey)?;
    let issuer = rcgen::Issuer::from_ca_cert_der(&issuer_certificate_der.into(), issuer_key)
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(params
        .signed_by(&issuer)
        .map_err(|_| CryptoError::OperationFailed)?
        .der()
        .to_vec())
}

/// Checks only this certificate's signature against the given issuer key.
/// Issuer/name/CA/time/revocation/anchor selection stays with the caller.
pub fn verify_signature(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    issuer_public_key: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
) -> crate::Result<()> {
    certificate
        .verify_signature(Some(issuer_public_key))
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Standard client-certificate chain verification against PEM trust anchors
/// at a caller-supplied Unix time.
pub fn verify_client_chain_at(
    chain_der: &[Vec<u8>],
    anchors_pem: &str,
    unix_seconds: u64,
) -> crate::Result<()> {
    use rustls::pki_types::{CertificateDer, UnixTime, pem::PemObject as _};

    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(anchors_pem.as_bytes()) {
        let certificate = certificate.map_err(|_| CryptoError::InvalidInput)?;
        roots
            .add(certificate)
            .map_err(|_| CryptoError::InvalidInput)?;
    }
    if roots.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|_| CryptoError::OperationFailed)?;
    if chain_der.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    for der in chain_der {
        let (remainder, _) =
            x509_parser::parse_x509_certificate(der).map_err(|_| CryptoError::InvalidInput)?;
        if !remainder.is_empty() {
            return Err(CryptoError::InvalidInput);
        }
    }
    let chain = chain_der
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect::<Vec<_>>();
    let (leaf, intermediates) = chain.split_first().expect("chain is non-empty");
    verifier
        .verify_client_cert(
            leaf,
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(unix_seconds)),
        )
        .map(|_| ())
        .map_err(|_| CryptoError::InvalidSignature)
}
