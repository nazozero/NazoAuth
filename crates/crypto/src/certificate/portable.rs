//! WebPKI's existing signature-verification interface backed by portable
//! algorithms. Path construction, DER, constraints and purpose remain WebPKI's.

use p256::ecdsa::signature::{Verifier as _, hazmat::PrehashVerifier as _};
use rsa::{pkcs1::DecodeRsaPublicKey as _, traits::PublicKeyParts as _};
use rustls_pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};
use sha2::Digest as _;

#[derive(Clone, Copy, Debug)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    P256(Hash),
    P384(Hash),
    P521(Hash),
    RsaPkcs1(Hash),
    RsaPss(Hash),
    Ed25519,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[derive(Debug)]
struct Algorithm {
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    kind: Kind,
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify(self.kind, public_key, message, signature)
    }
}

macro_rules! algorithm {
    ($key:ident, $signature:ident, $kind:expr) => {
        &Algorithm {
            public_key: alg_id::$key,
            signature: alg_id::$signature,
            kind: $kind,
        }
    };
}

// RFC 4055 requires accepting absent as well as NULL parameters for these
// signature AlgorithmIdentifiers. Public-key AlgorithmIdentifiers stay exact.
const RSA_SHA256_ABSENT: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
const RSA_SHA384_ABSENT: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);
const RSA_SHA512_ABSENT: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);

pub(super) static ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
    algorithm!(ECDSA_P256, ECDSA_SHA256, Kind::P256(Hash::Sha256)),
    algorithm!(ECDSA_P256, ECDSA_SHA384, Kind::P256(Hash::Sha384)),
    algorithm!(ECDSA_P256, ECDSA_SHA512, Kind::P256(Hash::Sha512)),
    algorithm!(ECDSA_P384, ECDSA_SHA256, Kind::P384(Hash::Sha256)),
    algorithm!(ECDSA_P384, ECDSA_SHA384, Kind::P384(Hash::Sha384)),
    algorithm!(ECDSA_P384, ECDSA_SHA512, Kind::P384(Hash::Sha512)),
    algorithm!(ECDSA_P521, ECDSA_SHA256, Kind::P521(Hash::Sha256)),
    algorithm!(ECDSA_P521, ECDSA_SHA384, Kind::P521(Hash::Sha384)),
    algorithm!(ECDSA_P521, ECDSA_SHA512, Kind::P521(Hash::Sha512)),
    algorithm!(ED25519, ED25519, Kind::Ed25519),
    algorithm!(RSA_ENCRYPTION, RSA_PSS_SHA256, Kind::RsaPss(Hash::Sha256)),
    algorithm!(RSA_ENCRYPTION, RSA_PSS_SHA384, Kind::RsaPss(Hash::Sha384)),
    algorithm!(RSA_ENCRYPTION, RSA_PSS_SHA512, Kind::RsaPss(Hash::Sha512)),
    algorithm!(
        RSA_ENCRYPTION,
        RSA_PKCS1_SHA256,
        Kind::RsaPkcs1(Hash::Sha256)
    ),
    algorithm!(
        RSA_ENCRYPTION,
        RSA_PKCS1_SHA384,
        Kind::RsaPkcs1(Hash::Sha384)
    ),
    algorithm!(
        RSA_ENCRYPTION,
        RSA_PKCS1_SHA512,
        Kind::RsaPkcs1(Hash::Sha512)
    ),
    &Algorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: RSA_SHA256_ABSENT,
        kind: Kind::RsaPkcs1(Hash::Sha256),
    },
    &Algorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: RSA_SHA384_ABSENT,
        kind: Kind::RsaPkcs1(Hash::Sha384),
    },
    &Algorithm {
        public_key: alg_id::RSA_ENCRYPTION,
        signature: RSA_SHA512_ABSENT,
        kind: Kind::RsaPkcs1(Hash::Sha512),
    },
    algorithm!(ML_DSA_44, ML_DSA_44, Kind::MlDsa44),
    algorithm!(ML_DSA_65, ML_DSA_65, Kind::MlDsa65),
    algorithm!(ML_DSA_87, ML_DSA_87, Kind::MlDsa87),
];

fn verify(
    kind: Kind,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    macro_rules! ec {
        ($curve:ident, $hash:expr) => {{
            // RFC 5480 encodings accepted by the native WebPKI provider.
            if !matches!(key.first(), Some(2..=4)) {
                return Err(InvalidSignature);
            }
            let key =
                $curve::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| InvalidSignature)?;
            let signature =
                $curve::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
            match $hash {
                Hash::Sha256 => key.verify_prehash(&sha2::Sha256::digest(message), &signature),
                Hash::Sha384 => key.verify_prehash(&sha2::Sha384::digest(message), &signature),
                Hash::Sha512 => key.verify_prehash(&sha2::Sha512::digest(message), &signature),
                Hash::Sha1 => return Err(InvalidSignature),
            }
            .map_err(|_| InvalidSignature)
        }};
    }
    macro_rules! rsa {
        ($method:ident, $hash:expr) => {{
            let key = rsa::PublicKey::from_pkcs1_der(key).map_err(|_| InvalidSignature)?;
            // The bare X.509 signature API retains its legacy SHA-1 floor;
            // certificate paths never include SHA-1 in ALGORITHMS.
            let minimum = if matches!($hash, Hash::Sha1) {
                1024
            } else {
                2048
            };
            if key.n().bit_width_vartime() < minimum {
                return Err(InvalidSignature);
            }
            match $hash {
                Hash::Sha1 => key.$method::<sha1::Sha1>(message, signature),
                Hash::Sha256 => key.$method::<sha2::Sha256>(message, signature),
                Hash::Sha384 => key.$method::<sha2::Sha384>(message, signature),
                Hash::Sha512 => key.$method::<sha2::Sha512>(message, signature),
            }
            .map_err(|_| InvalidSignature)
        }};
    }
    macro_rules! ml_dsa {
        ($params:ident) => {{
            let key = ml_dsa::VerifyingKey::<ml_dsa::$params>::decode(
                key.try_into().map_err(|_| InvalidSignature)?,
            );
            let signature = ml_dsa::Signature::<ml_dsa::$params>::try_from(signature)
                .map_err(|_| InvalidSignature)?;
            key.verify(message, &signature)
                .map_err(|_| InvalidSignature)
        }};
    }
    match kind {
        Kind::P256(hash) => ec!(p256, hash),
        Kind::P384(hash) => ec!(p384, hash),
        Kind::P521(hash) => ec!(p521, hash),
        Kind::RsaPkcs1(hash) => rsa!(pkcs1v15_verify, hash),
        Kind::RsaPss(hash) => rsa!(pss_verify, hash),
        Kind::Ed25519 => {
            let bytes = key.as_array().ok_or(InvalidSignature)?;
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| InvalidSignature)?;
            let signature =
                ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
            key.verify(message, &signature)
                .map_err(|_| InvalidSignature)
        }
        Kind::MlDsa44 => ml_dsa!(MlDsa44),
        Kind::MlDsa65 => ml_dsa!(MlDsa65),
        Kind::MlDsa87 => ml_dsa!(MlDsa87),
    }
}

/// Mirrors x509-parser's standalone signature operation, including its
/// historical SHA-1 compatibility. This is deliberately not PKIX validation.
pub(super) fn verify_certificate_signature(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    issuer: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
) -> Result<(), InvalidSignature> {
    use x509_parser::oid_registry::{
        OID_EC_P256, OID_NIST_EC_P384, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384,
        OID_NIST_HASH_SHA512, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA, OID_PKCS1_SHA256WITHRSA,
        OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SHA1_WITH_RSA,
        OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ED25519,
    };
    use x509_parser::signature_algorithm::RsaSsaPssParams;

    let algorithm = &certificate.signature_algorithm;
    let oid = &algorithm.algorithm;
    let kind = if *oid == OID_PKCS1_SHA1WITHRSA || *oid == OID_SHA1_WITH_RSA {
        Kind::RsaPkcs1(Hash::Sha1)
    } else if *oid == OID_PKCS1_SHA256WITHRSA {
        Kind::RsaPkcs1(Hash::Sha256)
    } else if *oid == OID_PKCS1_SHA384WITHRSA {
        Kind::RsaPkcs1(Hash::Sha384)
    } else if *oid == OID_PKCS1_SHA512WITHRSA {
        Kind::RsaPkcs1(Hash::Sha512)
    } else if *oid == OID_PKCS1_RSASSAPSS {
        let parameters = algorithm.parameters.as_ref().ok_or(InvalidSignature)?;
        let parameters = RsaSsaPssParams::try_from(parameters).map_err(|_| InvalidSignature)?;
        let hash = parameters.hash_algorithm_oid();
        Kind::RsaPss(if *hash == OID_NIST_HASH_SHA256 {
            Hash::Sha256
        } else if *hash == OID_NIST_HASH_SHA384 {
            Hash::Sha384
        } else if *hash == OID_NIST_HASH_SHA512 {
            Hash::Sha512
        } else {
            return Err(InvalidSignature);
        })
    } else if *oid == OID_SIG_ECDSA_WITH_SHA256 || *oid == OID_SIG_ECDSA_WITH_SHA384 {
        let curve = issuer
            .algorithm
            .parameters
            .as_ref()
            .ok_or(InvalidSignature)?
            .as_oid()
            .map_err(|_| InvalidSignature)?;
        let hash = if *oid == OID_SIG_ECDSA_WITH_SHA256 {
            Hash::Sha256
        } else {
            Hash::Sha384
        };
        if curve == OID_EC_P256 {
            Kind::P256(hash)
        } else if curve == OID_NIST_EC_P384 {
            Kind::P384(hash)
        } else {
            return Err(InvalidSignature);
        }
    } else if *oid == OID_SIG_ED25519 {
        Kind::Ed25519
    } else {
        return Err(InvalidSignature);
    };
    verify(
        kind,
        issuer.subject_public_key.data.as_ref(),
        certificate.tbs_certificate.as_ref(),
        certificate.signature_value.data.as_ref(),
    )
}

#[cfg(test)]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[path = "../../tests/unit/certificate/portable.rs"]
mod tests;
