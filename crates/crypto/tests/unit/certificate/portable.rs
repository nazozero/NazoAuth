use super::*;
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{self as aws, KeyPair as _},
};

const MESSAGE: &[u8] = b"NazoAuth portable certificate signature";

fn check_pair(
    key_algorithm: AlgorithmIdentifier,
    signature_algorithm: AlgorithmIdentifier,
    public_key: &[u8],
    signature: &[u8],
) {
    let native = rustls::crypto::aws_lc_rs::default_provider()
        .signature_verification_algorithms
        .all;
    let find = |algorithms: &'static [&'static dyn SignatureVerificationAlgorithm]| {
        *algorithms
            .iter()
            .find(|algorithm| {
                algorithm.public_key_alg_id() == key_algorithm
                    && algorithm.signature_alg_id() == signature_algorithm
            })
            .unwrap()
    };
    for backend in [find(ALGORITHMS), find(native)] {
        assert!(
            backend
                .verify_signature(public_key, MESSAGE, signature)
                .is_ok(),
            "{backend:?}"
        );
        assert!(
            backend
                .verify_signature(public_key, b"changed certificate", signature)
                .is_err(),
            "{backend:?}"
        );
        assert!(
            backend
                .verify_signature(public_key, MESSAGE, &signature[..signature.len() - 1])
                .is_err(),
            "{backend:?}"
        );
        assert!(
            backend.verify_signature(&[], MESSAGE, signature).is_err(),
            "{backend:?}"
        );
    }
}

#[test]
fn portable_certificate_algorithm_identifiers_match_native() {
    let identifiers = |algorithms: &[&dyn SignatureVerificationAlgorithm]| {
        let mut ids: Vec<_> = algorithms
            .iter()
            .map(|algorithm| {
                (
                    algorithm.public_key_alg_id().as_ref().to_vec(),
                    algorithm.signature_alg_id().as_ref().to_vec(),
                )
            })
            .collect();
        ids.sort();
        ids
    };
    let previous = rustls::crypto::aws_lc_rs::default_provider()
        .signature_verification_algorithms
        .all;
    assert_eq!(identifiers(ALGORITHMS), identifiers(previous));
    assert_eq!(
        identifiers(super::super::verification_algorithms()),
        identifiers(previous)
    );
}

#[test]
fn portable_ec_certificate_signatures_match_all_native_curve_hash_pairs() {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;

    macro_rules! cases {
        ($curve:ident, $bytes:expr, $key_algorithm:expr) => {{
            let key = $curve::ecdsa::SigningKey::from_slice(&$bytes).unwrap();
            let public_key = key.verifying_key().to_sec1_point(false);
            for (digest, algorithm) in [
                (sha2::Sha256::digest(MESSAGE).to_vec(), alg_id::ECDSA_SHA256),
                (sha2::Sha384::digest(MESSAGE).to_vec(), alg_id::ECDSA_SHA384),
                (sha2::Sha512::digest(MESSAGE).to_vec(), alg_id::ECDSA_SHA512),
            ] {
                let signature: $curve::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
                let signature = signature.to_der();
                check_pair(
                    $key_algorithm,
                    algorithm,
                    public_key.as_bytes(),
                    signature.as_bytes(),
                );
                let compressed = key.verifying_key().to_sec1_point(true);
                check_pair(
                    $key_algorithm,
                    algorithm,
                    compressed.as_bytes(),
                    signature.as_bytes(),
                );
            }
        }};
    }
    cases!(p256, [7; 32], alg_id::ECDSA_P256);
    cases!(p384, [7; 48], alg_id::ECDSA_P384);
    cases!(p521, [1; 66], alg_id::ECDSA_P521);
}

#[test]
fn portable_rsa_certificate_signatures_match_pkcs1_and_pss() {
    use aws_lc_rs::encoding::AsDer as _;
    use rsa::pkcs8::DecodePrivateKey as _;

    let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let rng = SystemRandom::new();
    let mut signature = vec![0; key.public_modulus_len()];
    let algorithms: &[(
        &dyn aws::RsaEncoding,
        AlgorithmIdentifier,
        Option<AlgorithmIdentifier>,
    )] = &[
        (
            &aws::RSA_PKCS1_SHA256,
            alg_id::RSA_PKCS1_SHA256,
            Some(RSA_SHA256_ABSENT),
        ),
        (
            &aws::RSA_PKCS1_SHA384,
            alg_id::RSA_PKCS1_SHA384,
            Some(RSA_SHA384_ABSENT),
        ),
        (
            &aws::RSA_PKCS1_SHA512,
            alg_id::RSA_PKCS1_SHA512,
            Some(RSA_SHA512_ABSENT),
        ),
        (&aws::RSA_PSS_SHA256, alg_id::RSA_PSS_SHA256, None),
        (&aws::RSA_PSS_SHA384, alg_id::RSA_PSS_SHA384, None),
        (&aws::RSA_PSS_SHA512, alg_id::RSA_PSS_SHA512, None),
    ];
    for (encoding, algorithm, absent) in algorithms {
        key.sign(*encoding, &rng, MESSAGE, &mut signature).unwrap();
        check_pair(
            alg_id::RSA_ENCRYPTION,
            *algorithm,
            key.public_key().as_ref(),
            &signature,
        );
        if let Some(absent) = absent {
            check_pair(
                alg_id::RSA_ENCRYPTION,
                *absent,
                key.public_key().as_ref(),
                &signature,
            );
        }
    }

    // The standalone signature API retains legacy SHA-1 support; the path
    // algorithms above must not acquire that compatibility algorithm.
    let der = key.as_der().unwrap();
    let legacy = rsa::PrivateKey::from_pkcs8_der(der.as_ref()).unwrap();
    let signature = legacy.pkcs1v15_sign::<sha1::Sha1>(MESSAGE).unwrap();
    let public = key.public_key().as_ref();
    verify(Kind::RsaPkcs1(Hash::Sha1), public, MESSAGE, &signature).unwrap();
    aws::UnparsedPublicKey::new(&aws::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY, public)
        .verify(MESSAGE, &signature)
        .unwrap();
}

#[test]
fn portable_ed25519_and_ml_dsa_certificate_signatures_match_native() {
    let ed = aws::Ed25519KeyPair::generate().unwrap();
    check_pair(
        alg_id::ED25519,
        alg_id::ED25519,
        ed.public_key().as_ref(),
        ed.sign(MESSAGE).as_ref(),
    );
    for (signer, algorithm) in [
        (&aws::ML_DSA_44_SIGNING, alg_id::ML_DSA_44),
        (&aws::ML_DSA_65_SIGNING, alg_id::ML_DSA_65),
        (&aws::ML_DSA_87_SIGNING, alg_id::ML_DSA_87),
    ] {
        let key = aws::PqdsaKeyPair::generate(signer).unwrap();
        let mut signature = vec![0; signer.signature_len()];
        let len = key.sign(MESSAGE, &mut signature).unwrap();
        signature.truncate(len);
        check_pair(algorithm, algorithm, key.public_key().as_ref(), &signature);
    }
}

#[test]
fn portable_standalone_certificate_signatures_match_existing_operation() {
    for algorithm in [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ECDSA_P521_SHA512,
        &rcgen::PKCS_ED25519,
        &rcgen::PKCS_RSA_SHA256,
        &rcgen::PKCS_RSA_SHA384,
        &rcgen::PKCS_RSA_SHA512,
    ] {
        let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
        let certificate = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.der()).unwrap();
        assert_eq!(
            verify_certificate_signature(&parsed, parsed.public_key()).is_ok(),
            parsed.verify_signature(Some(parsed.public_key())).is_ok(),
            "{algorithm:?}"
        );
        let wrong_key = rcgen::KeyPair::generate_for(algorithm).unwrap();
        let wrong = rcgen::CertificateParams::default()
            .self_signed(&wrong_key)
            .unwrap();
        let (_, wrong) = x509_parser::parse_x509_certificate(wrong.der()).unwrap();
        assert!(
            verify_certificate_signature(&parsed, wrong.public_key()).is_err(),
            "{algorithm:?}"
        );
    }
}

#[test]
fn portable_ed25519_encoding_policy_matches_native() {
    // Preserve the existing Ed25519 verification equation and encoding policy.
    // A platform switch must not silently select Dalek's additional strict mode.
    let mut key = [0; 32];
    key[0] = 1;
    let mut signature = [0; 64];
    signature[0] = 1;
    let native = aws::UnparsedPublicKey::new(&aws::ED25519, key);
    assert_eq!(
        verify(Kind::Ed25519, &key, MESSAGE, &signature).is_ok(),
        native.verify(MESSAGE, &signature).is_ok(),
    );
    signature[63] = 0xff;
    assert!(verify(Kind::Ed25519, &key, MESSAGE, &signature).is_err());
    assert!(native.verify(MESSAGE, &signature).is_err());
}
