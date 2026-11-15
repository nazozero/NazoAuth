use aes_kw::{KeyInit as _, KwAes128, KwAes256};
use rsa::{
    BoxedUint, PrivateKey, PublicKey,
    pkcs1::EncodeRsaPrivateKey as _,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _},
    traits::PublicKeyParts as _,
};

use crate::CryptoError;

fn private_key(private_der: &[u8]) -> crate::Result<PrivateKey> {
    let key = PrivateKey::from_pkcs8_der(private_der).map_err(|_| CryptoError::InvalidKey)?;
    if !(2048..=8192).contains(&key.n().bit_width_vartime()) {
        return Err(CryptoError::InvalidKey);
    }
    // Do not silently repair malformed CRT coefficients during key import.
    let input =
        pkcs8::PrivateKeyInfoRef::try_from(private_der).map_err(|_| CryptoError::InvalidKey)?;
    if key
        .to_pkcs1_der()
        .map_err(|_| CryptoError::InvalidKey)?
        .as_bytes()
        != input.private_key.as_bytes()
    {
        return Err(CryptoError::InvalidKey);
    }
    Ok(key)
}

pub fn generate_rsa_pkcs8_der(bits: usize) -> crate::Result<Vec<u8>> {
    if !matches!(bits, 2048 | 3072 | 4096) {
        return Err(CryptoError::InvalidInput);
    }
    let key = PrivateKey::new(&mut rand::rng(), bits).map_err(|_| CryptoError::OperationFailed)?;
    Ok(key
        .to_pkcs8_der()
        .map_err(|_| CryptoError::OperationFailed)?
        .as_bytes()
        .to_vec())
}

pub fn rsa_public_components(private_der: &[u8]) -> crate::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let key = private_key(private_der)?;
    let public = PublicKey::from(&key);
    Ok((
        public.n().to_be_bytes_trimmed_vartime().into_vec(),
        public.e().to_be_bytes_trimmed_vartime().into_vec(),
        public
            .to_public_key_der()
            .map_err(|_| CryptoError::OperationFailed)?
            .into_vec(),
    ))
}

pub fn rsa_oaep256_encrypt(n: &[u8], e: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let public = PublicKey::new_with_size_limits(
        BoxedUint::from_be_slice_vartime(n),
        BoxedUint::from_be_slice_vartime(e),
        2048..=8192,
    )
    .map_err(|_| CryptoError::InvalidKey)?;
    public
        .oaep_encrypt::<sha2::Sha256>(plaintext)
        .map_err(|_| CryptoError::OperationFailed)
}

/// Prepared RSA-OAEP-256 recipient key with cached private-key validation and CRT data.
pub struct RsaOaep256PrivateKey {
    inner: PrivateKey,
}

impl RsaOaep256PrivateKey {
    pub fn from_pkcs8(private_der: &[u8]) -> crate::Result<Self> {
        Ok(Self {
            inner: private_key(private_der)?,
        })
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        // `rsa/getrandom` enables mandatory secure blinding on this operation.
        self.inner
            .oaep_decrypt::<sha2::Sha256>(ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

/// RFC 3394 wrapping of an AES-256 content-encryption key with an AES-128/256 KEK.
pub fn aes_wrap(kek: &[u8], key: &[u8; 32]) -> crate::Result<[u8; 40]> {
    let mut output = [0_u8; 40];
    match kek.len() {
        16 => KwAes128::new_from_slice(kek)
            .map_err(|_| CryptoError::InvalidKey)?
            .wrap_key(key, &mut output),
        32 => KwAes256::new_from_slice(kek)
            .map_err(|_| CryptoError::InvalidKey)?
            .wrap_key(key, &mut output),
        _ => return Err(CryptoError::InvalidKey),
    }
    .map_err(|_| CryptoError::OperationFailed)?;
    Ok(output)
}
