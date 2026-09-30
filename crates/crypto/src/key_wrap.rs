//! RSA key transport (fixed JWA RSA-OAEP-256) and RFC 3394 AES key wrap.

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    key_wrap::{AES_128, AES_256, AesKek, KeyWrap as _},
    rsa::{
        KeyPair, KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey,
        OaepPublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
    },
    signature::KeyPair as _,
};
use der::{
    Encode as _,
    asn1::{Any, BitString, UintRef},
};
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

use crate::CryptoError;

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

fn rsa_public_spki(n: &[u8], e: &[u8]) -> crate::Result<Vec<u8>> {
    let pkcs1 = RsaPublicKey {
        modulus: UintRef::new(n).map_err(|_| CryptoError::InvalidKey)?,
        public_exponent: UintRef::new(e).map_err(|_| CryptoError::InvalidKey)?,
    }
    .to_der()
    .map_err(|_| CryptoError::InvalidKey)?;
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
            parameters: Some(Any::null()),
        },
        subject_public_key: BitString::from_bytes(&pkcs1).map_err(|_| CryptoError::InvalidKey)?,
    }
    .to_der()
    .map_err(|_| CryptoError::InvalidKey)
}

pub fn generate_rsa_pkcs8_der(bits: usize) -> crate::Result<Vec<u8>> {
    let size = match bits {
        2048 => KeySize::Rsa2048,
        3072 => KeySize::Rsa3072,
        4096 => KeySize::Rsa4096,
        _ => return Err(CryptoError::InvalidInput),
    };
    let key = KeyPair::generate(size).map_err(|_| CryptoError::OperationFailed)?;
    Ok(AsDer::<Pkcs8V1Der<'static>>::as_der(&key)
        .map_err(|_| CryptoError::OperationFailed)?
        .as_ref()
        .to_vec())
}

pub fn rsa_public_components(private_der: &[u8]) -> crate::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let key = KeyPair::from_pkcs8(private_der).map_err(|_| CryptoError::InvalidKey)?;
    let public = key.public_key();
    let public_der = AsDer::as_der(public)
        .map_err(|_| CryptoError::OperationFailed)?
        .as_ref()
        .to_vec();
    Ok((
        public.modulus().big_endian_without_leading_zero().to_vec(),
        public.exponent().big_endian_without_leading_zero().to_vec(),
        public_der,
    ))
}

pub fn rsa_oaep256_encrypt(n: &[u8], e: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let public = PublicEncryptingKey::from_der(&rsa_public_spki(n, e)?)
        .map_err(|_| CryptoError::InvalidKey)?;
    let public = OaepPublicEncryptingKey::new(public).map_err(|_| CryptoError::InvalidKey)?;
    let mut ciphertext = vec![0; public.ciphertext_size()];
    Ok(public
        .encrypt(&OAEP_SHA256_MGF1SHA256, plaintext, &mut ciphertext, None)
        .map_err(|_| CryptoError::OperationFailed)?
        .to_vec())
}

/// Prepared RSA-OAEP-256 recipient key. The backend and private material stay
/// inside the crypto boundary while a published generation reuses this handle.
pub struct RsaOaep256PrivateKey {
    inner: OaepPrivateDecryptingKey,
}

impl RsaOaep256PrivateKey {
    pub fn from_pkcs8(private_der: &[u8]) -> crate::Result<Self> {
        let private =
            PrivateDecryptingKey::from_pkcs8(private_der).map_err(|_| CryptoError::InvalidKey)?;
        let inner = OaepPrivateDecryptingKey::new(private).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { inner })
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        let mut plaintext = vec![0; self.inner.min_output_size()];
        Ok(self
            .inner
            .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
            .map_err(|_| CryptoError::AuthenticationFailed)?
            .to_vec())
    }
}

pub fn aes_wrap(kek: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = match kek.len() {
        16 => &AES_128,
        32 => &AES_256,
        _ => return Err(CryptoError::InvalidKey),
    };
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidInput);
    }
    let mut output = vec![0_u8; plaintext.len() + 8];
    let wrapped = AesKek::new(cipher, kek)
        .map_err(|_| CryptoError::InvalidKey)?
        .wrap(plaintext, &mut output)
        .map_err(|_| CryptoError::OperationFailed)?;
    Ok(wrapped.to_vec())
}
