//! Raw JWS signature generation and verification for the four supported
//! algorithms (EdDSA, RS256, PS256, ES256).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::EncodePrivateKey as _;

use crate::CryptoError;
use crate::jwt::{Algorithm, VerificationKey};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use aws_lc_rs::{
    rsa::KeyPair as RsaKeyPair,
    signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair as _},
};
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use {
    ed25519_dalek::SigningKey as Ed25519KeyPair, p256::ecdsa::SigningKey as EcdsaKeyPair,
    rsa::PrivateKey as RsaKeyPair,
};

/// Local signing material prepared once per key generation.
///
/// Each algorithm retains its backend's parsed key pair. DER parsing and
/// private-key validation happen at construction; every request borrows the
/// same immutable material without recreating a provider signer.
pub struct PreparedSigningKey {
    algorithm: Algorithm,
    key: PreparedKey,
}

enum PreparedKey {
    Ed25519(Ed25519KeyPair),
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

impl PreparedSigningKey {
    /// Prepares signing material from the existing private-key DER bytes.
    ///
    /// Invalid DER fails here with `InvalidKey`, so an unusable generation
    /// cannot be published.
    pub fn new(algorithm: Algorithm, private_der: &[u8]) -> crate::Result<Self> {
        let key = match algorithm {
            Algorithm::EdDSA => PreparedKey::Ed25519(prepare_ed25519(private_der)?),
            Algorithm::ES256 => PreparedKey::Ec(prepare_ec(private_der)?),
            Algorithm::RS256 | Algorithm::PS256 => PreparedKey::Rsa(prepare_rsa(private_der)?),
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        };
        Ok(Self { algorithm, key })
    }

    /// Signs `message` and returns the raw signature bytes.
    ///
    /// Callers that assemble a JWT apply Base64url once at the final assembly
    /// point; raw-signature consumers keep the `Vec<u8>`.
    pub fn sign(&self, message: &[u8]) -> crate::Result<Vec<u8>> {
        match &self.key {
            PreparedKey::Ed25519(pair) => Ok(sign_ed25519(pair, message)),
            PreparedKey::Ec(pair) => sign_ec(pair, message),
            PreparedKey::Rsa(pair) => sign_rsa(pair, self.algorithm, message),
        }
    }

    /// Exports the mathematical public JWK members from the retained key pair.
    #[must_use]
    pub fn public_jwk(&self) -> serde_json::Value {
        match &self.key {
            PreparedKey::Ed25519(pair) => {
                #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
                let public = pair.public_key().as_ref();
                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                let public = pair.verifying_key().to_bytes();
                let mut jwk = serde_json::json!({"kty": "OKP", "crv": "Ed25519"});
                jwk["x"] = URL_SAFE_NO_PAD.encode(public).into();
                jwk
            }
            PreparedKey::Ec(pair) => {
                #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
                let public = pair.public_key();
                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                let public = pair.verifying_key().to_sec1_point(false);
                let point: &[u8] = public.as_ref();
                let mut jwk = serde_json::json!({"kty": "EC", "crv": "P-256"});
                jwk["x"] = URL_SAFE_NO_PAD.encode(&point[1..33]).into();
                jwk["y"] = URL_SAFE_NO_PAD.encode(&point[33..]).into();
                jwk
            }
            PreparedKey::Rsa(pair) => {
                #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
                let (n, e) = (
                    pair.public_key()
                        .modulus()
                        .big_endian_without_leading_zero(),
                    pair.public_key()
                        .exponent()
                        .big_endian_without_leading_zero(),
                );
                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                let (n, e) = {
                    use rsa::traits::PublicKeyParts as _;
                    (pair.n_bytes(), pair.e_bytes())
                };
                let mut jwk = serde_json::json!({"kty": "RSA"});
                jwk["n"] = URL_SAFE_NO_PAD.encode(n).into();
                jwk["e"] = URL_SAFE_NO_PAD.encode(e).into();
                jwk
            }
        }
    }
}

impl std::fmt::Debug for PreparedSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn prepare_ed25519(private_der: &[u8]) -> crate::Result<Ed25519KeyPair> {
    Ed25519KeyPair::from_pkcs8(private_der).map_err(|_| CryptoError::InvalidKey)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn prepare_ed25519(private_der: &[u8]) -> crate::Result<Ed25519KeyPair> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;

    Ed25519KeyPair::from_pkcs8_der(private_der).map_err(|_| CryptoError::InvalidKey)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn sign_ed25519(pair: &Ed25519KeyPair, message: &[u8]) -> Vec<u8> {
    pair.sign(message).as_ref().to_vec()
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn sign_ed25519(pair: &Ed25519KeyPair, message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;

    pair.sign(message).to_bytes().to_vec()
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn prepare_ec(private_der: &[u8]) -> crate::Result<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        private_der,
    )
    .map_err(|_| CryptoError::InvalidKey)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn prepare_ec(private_der: &[u8]) -> crate::Result<EcdsaKeyPair> {
    use p256::pkcs8::DecodePrivateKey as _;

    EcdsaKeyPair::from_pkcs8_der(private_der).map_err(|_| CryptoError::InvalidKey)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn sign_ec(pair: &EcdsaKeyPair, message: &[u8]) -> crate::Result<Vec<u8>> {
    pair.sign(&aws_lc_rs::rand::SystemRandom::new(), message)
        .map(|signature| signature.as_ref().to_vec())
        .map_err(|_| CryptoError::OperationFailed)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn sign_ec(pair: &EcdsaKeyPair, message: &[u8]) -> crate::Result<Vec<u8>> {
    Ok(pair.sign_recoverable(message).0.to_vec())
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn prepare_rsa(private_der: &[u8]) -> crate::Result<RsaKeyPair> {
    RsaKeyPair::from_der(private_der).map_err(|_| CryptoError::InvalidKey)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn prepare_rsa(private_der: &[u8]) -> crate::Result<RsaKeyPair> {
    use rsa::{
        pkcs1::{DecodeRsaPrivateKey as _, EncodeRsaPrivateKey as _},
        traits::PublicKeyParts as _,
    };

    let pair = RsaKeyPair::from_pkcs1_der(private_der).map_err(|_| CryptoError::InvalidKey)?;
    if !(2048..=8192).contains(&pair.n().bit_width_vartime()) {
        return Err(CryptoError::InvalidKey);
    }
    // RustCrypto recomputes the CRT coefficients on import. Preserve AWS-LC's
    // rejection of inconsistent encoded coefficients before publishing a key.
    if pair
        .to_pkcs1_der()
        .map_err(|_| CryptoError::InvalidKey)?
        .as_bytes()
        != private_der
    {
        return Err(CryptoError::InvalidKey);
    }
    Ok(pair)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn sign_rsa(pair: &RsaKeyPair, algorithm: Algorithm, message: &[u8]) -> crate::Result<Vec<u8>> {
    let padding: &'static dyn aws_lc_rs::signature::RsaEncoding = match algorithm {
        Algorithm::RS256 => &aws_lc_rs::signature::RSA_PKCS1_SHA256,
        Algorithm::PS256 => &aws_lc_rs::signature::RSA_PSS_SHA256,
        _ => unreachable!("RSA key is only stored for RSA algorithms"),
    };
    let mut signature = vec![0; pair.public_modulus_len()];
    pair.sign(
        padding,
        &aws_lc_rs::rand::SystemRandom::new(),
        message,
        &mut signature,
    )
    .map_err(|_| CryptoError::OperationFailed)?;
    Ok(signature)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn sign_rsa(pair: &RsaKeyPair, algorithm: Algorithm, message: &[u8]) -> crate::Result<Vec<u8>> {
    // The maintained RSA backend uses secure blinding for both private operations;
    // PSS uses a SHA-256-sized salt, matching the JWA/AWS-LC signature semantics.
    match algorithm {
        Algorithm::RS256 => pair.pkcs1v15_sign::<sha2::Sha256>(message),
        Algorithm::PS256 => pair.pss_sign::<sha2::Sha256>(message),
        _ => unreachable!("RSA key is only stored for RSA algorithms"),
    }
    .map_err(|_| CryptoError::OperationFailed)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn verify(
    algorithm: Algorithm,
    key: &VerificationKey,
    message: &[u8],
    signature: &[u8],
) -> crate::Result<()> {
    use aws_lc_rs::signature as backend;
    use jsonwebtoken::DecodingKeyKind;

    match algorithm {
        Algorithm::EdDSA | Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {}
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    }
    if key.inner.family() != algorithm.family() {
        return Err(CryptoError::InvalidInput);
    }
    // Borrow the retained key and raw signature directly. The JWT provider's
    // factory clones the key and boxes a verifier whose interface requires Vec.
    let result = match algorithm {
        Algorithm::EdDSA | Algorithm::ES256 => {
            let bytes = key
                .inner
                .try_get_as_bytes()
                .map_err(|_| CryptoError::InvalidInput)?;
            let verifier: &dyn backend::VerificationAlgorithm = match algorithm {
                Algorithm::EdDSA => &backend::ED25519,
                _ => &backend::ECDSA_P256_SHA256_FIXED,
            };
            verifier.verify_sig(bytes, message, signature)
        }
        Algorithm::RS256 | Algorithm::PS256 => {
            let parameters = match algorithm {
                Algorithm::RS256 => &backend::RSA_PKCS1_2048_8192_SHA256,
                _ => &backend::RSA_PSS_2048_8192_SHA256,
            };
            match key.inner.kind() {
                DecodingKeyKind::SecretOrDer(bytes) => {
                    backend::UnparsedPublicKey::new(parameters, bytes).verify(message, signature)
                }
                DecodingKeyKind::RsaModulusExponent { n, e } => {
                    backend::RsaPublicKeyComponents { n, e }.verify(parameters, message, signature)
                }
            }
        }
        _ => unreachable!("unsupported algorithms were rejected above"),
    };
    result.map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub fn verify(
    algorithm: Algorithm,
    key: &VerificationKey,
    message: &[u8],
    signature: &[u8],
) -> crate::Result<()> {
    use p256::ecdsa::signature::Verifier as _;

    match algorithm {
        Algorithm::EdDSA | Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {}
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    }
    if key.inner.family() != algorithm.family() {
        return Err(CryptoError::InvalidInput);
    }
    match algorithm {
        Algorithm::EdDSA => {
            let bytes = key
                .inner
                .try_get_as_bytes()
                .map_err(|_| CryptoError::InvalidInput)?;
            let bytes = bytes.as_array().ok_or(CryptoError::InvalidSignature)?;
            let verifier = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidSignature)?;
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifier
                .verify(message, &signature)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        Algorithm::ES256 => {
            let bytes = key
                .inner
                .try_get_as_bytes()
                .map_err(|_| CryptoError::InvalidInput)?;
            let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map_err(|_| CryptoError::InvalidSignature)?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::InvalidSignature)?;
            verifier
                .verify(message, &signature)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        Algorithm::RS256 | Algorithm::PS256 => {
            let public = rsa_verification_key(&key.inner)?;
            match algorithm {
                Algorithm::RS256 => public.pkcs1v15_verify::<sha2::Sha256>(message, signature),
                _ => public.pss_verify::<sha2::Sha256>(message, signature),
            }
            .map_err(|_| CryptoError::InvalidSignature)
        }
        _ => unreachable!("unsupported algorithms were rejected above"),
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn rsa_verification_key(key: &jsonwebtoken::DecodingKey) -> crate::Result<rsa::PublicKey> {
    use jsonwebtoken::DecodingKeyKind;
    use rsa::BoxedUint;

    match key.kind() {
        DecodingKeyKind::SecretOrDer(_) => Err(CryptoError::InvalidSignature),
        DecodingKeyKind::RsaModulusExponent { n, e } => {
            if n.first().is_none_or(|byte| *byte == 0) || e.first().is_none_or(|byte| *byte == 0) {
                return Err(CryptoError::InvalidSignature);
            }
            rsa::PublicKey::new_with_size_limits(
                BoxedUint::from_be_slice_vartime(n),
                BoxedUint::from_be_slice_vartime(e),
                2048..=8192,
            )
            .map_err(|_| CryptoError::InvalidSignature)
        }
    }
}

pub fn generate_private_key(algorithm: Algorithm) -> crate::Result<Vec<u8>> {
    match algorithm {
        Algorithm::EdDSA => {
            let seed: [u8; 32] = rand::random();
            Ok(ed25519_pkcs8_private_der(&seed))
        }
        Algorithm::RS256 | Algorithm::PS256 => {
            let pkcs8 = crate::key_wrap::generate_rsa_pkcs8_der(2048)?;
            let private_key = pkcs8::PrivateKeyInfoRef::try_from(pkcs8.as_slice())
                .map_err(|_| CryptoError::OperationFailed)?;
            Ok(private_key.private_key.as_bytes().to_vec())
        }
        Algorithm::ES256 => {
            let secret_key =
                p256::SecretKey::try_generate().map_err(|_| CryptoError::OperationFailed)?;
            Ok(secret_key
                .to_pkcs8_der()
                .map_err(|_| CryptoError::OperationFailed)?
                .as_bytes()
                .to_vec())
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

pub fn public_jwk(algorithm: Algorithm, private_der: &[u8]) -> crate::Result<serde_json::Value> {
    Ok(PreparedSigningKey::new(algorithm, private_der)?.public_jwk())
}

fn ed25519_pkcs8_private_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    der.extend_from_slice(seed);
    der
}
