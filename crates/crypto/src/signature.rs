//! Raw JWS signature generation and verification for the four supported
//! algorithms (EdDSA, RS256, PS256, ES256).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::EncodePrivateKey as _;

use crate::CryptoError;
use crate::jwt::{Algorithm, VerificationKey};

/// Local signing material prepared once per key generation.
///
/// RSA algorithms retain the provider's parsed `RsaKeyPair`: DER parsing and
/// private-key validation happen once at construction, so the request-time
/// `sign` path never re-parses the key. Other algorithms keep the byte
/// `EncodingKey` — their provider signer is created inside the synchronous
/// `sign` call and dropped before it returns, so it never crosses an `await`
/// and is never shared or cached.
pub struct PreparedSigningKey {
    algorithm: Algorithm,
    key: PreparedKey,
}

enum PreparedKey {
    /// Parsed native RSA key pair shared immutably across all signatures of
    /// this generation. `aws_lc_rs::rsa::KeyPair` is `Send + Sync` upstream.
    Rsa(aws_lc_rs::rsa::KeyPair),
    /// Byte-wrapping key for algorithms still on the provider path.
    Provider(jsonwebtoken::EncodingKey),
}

impl PreparedSigningKey {
    /// Prepares signing material from the existing private-key DER bytes.
    ///
    /// For RS256/PS256 this performs the real parse once: invalid DER fails
    /// here with `InvalidKey`, so an unusable generation cannot be published.
    /// Other algorithms keep the provider factory probe, which validates that
    /// this material can produce a signer before it is retained.
    pub fn new(algorithm: Algorithm, private_der: &[u8]) -> crate::Result<Self> {
        let key = match algorithm {
            Algorithm::RS256 | Algorithm::PS256 => PreparedKey::Rsa(
                aws_lc_rs::rsa::KeyPair::from_der(private_der)
                    .map_err(|_| CryptoError::InvalidKey)?,
            ),
            Algorithm::EdDSA | Algorithm::ES256 => {
                let key = encoding_key(algorithm, private_der)?;
                (jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.signer_factory)(&algorithm, &key)
                    .map_err(|_| CryptoError::InvalidKey)?;
                PreparedKey::Provider(key)
            }
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
            PreparedKey::Rsa(pair) => {
                let padding: &'static dyn aws_lc_rs::signature::RsaEncoding = match self.algorithm {
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
            PreparedKey::Provider(key) => {
                let signer = (jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.signer_factory)(
                    &self.algorithm,
                    key,
                )
                .map_err(|_| CryptoError::InvalidKey)?;
                signer
                    .try_sign(message)
                    .map_err(|_| CryptoError::OperationFailed)
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

pub fn verify(
    algorithm: Algorithm,
    key: &VerificationKey,
    message: &[u8],
    signature: &[u8],
) -> crate::Result<()> {
    match algorithm {
        Algorithm::EdDSA | Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {}
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    }
    let encoded = URL_SAFE_NO_PAD.encode(signature);
    match jsonwebtoken::crypto::verify(&encoded, message, &key.inner, algorithm) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CryptoError::InvalidSignature),
        Err(_) => Err(CryptoError::InvalidInput),
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
    match algorithm {
        Algorithm::EdDSA => {
            let seed = ed25519_seed_from_pkcs8(private_der).ok_or(CryptoError::InvalidKey)?;
            let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            Ok(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(public_key),
            }))
        }
        Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 => {
            let key = encoding_key(algorithm, private_der)?;
            let jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&key, algorithm)
                .map_err(|_| CryptoError::InvalidKey)?;
            let value = serde_json::to_value(jwk).map_err(|_| CryptoError::OperationFailed)?;
            let object = value.as_object().ok_or(CryptoError::OperationFailed)?;
            let mut public = serde_json::Map::new();
            for member in ["kty", "n", "e", "crv", "x", "y"] {
                if let Some(value) = object.get(member) {
                    public.insert(member.to_owned(), value.clone());
                }
            }
            Ok(serde_json::Value::Object(public))
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn encoding_key(
    algorithm: Algorithm,
    private_der: &[u8],
) -> crate::Result<jsonwebtoken::EncodingKey> {
    match algorithm {
        Algorithm::EdDSA => Ok(jsonwebtoken::EncodingKey::from_ed_der(private_der)),
        Algorithm::RS256 | Algorithm::PS256 => {
            Ok(jsonwebtoken::EncodingKey::from_rsa_der(private_der))
        }
        Algorithm::ES256 => Ok(jsonwebtoken::EncodingKey::from_ec_der(private_der)),
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
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

fn ed25519_seed_from_pkcs8(der: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    if der.len() != PREFIX.len() + 32 || !der.starts_with(PREFIX) {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[PREFIX.len()..]);
    Some(seed)
}
