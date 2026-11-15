//! Native certificate provisioning used by the host key controller.

use super::{CertificateParams, CertificateRevocationListParams};
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
    let (_, certificate) = x509_parser::parse_x509_certificate(issuer_certificate_der)
        .map_err(|_| CryptoError::InvalidInput)?;
    if issuer_key.public_key_raw() != certificate.public_key().subject_public_key.data.as_ref() {
        return Err(CryptoError::InvalidKey);
    }
    let issuer = rcgen::Issuer::from_ca_cert_der(&issuer_certificate_der.into(), issuer_key)
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(params
        .signed_by(&issuer)
        .map_err(|_| CryptoError::OperationFailed)?
        .der()
        .to_vec())
}
