//! COSE signature verification using RustCrypto.

use crate::cose::key::{algorithms, CoseKeyExt};
use crate::error::MdocError;

/// Verify a COSE signature given the to-be-signed data, signature bytes, and a COSE_Key.
///
/// Supports ES256 (P-256), ES384 (P-384), ES512 (P-521), and EdDSA (Ed25519).
pub fn verify_cose_signature(
    tbs_data: &[u8],
    signature: &[u8],
    cose_key: &coset::CoseKey,
    alg_id: i64,
) -> Result<bool, MdocError> {
    match alg_id {
        algorithms::ES256 => verify_ecdsa_p256(tbs_data, signature, cose_key),
        algorithms::ES384 => verify_ecdsa_p384(tbs_data, signature, cose_key),
        algorithms::ES512 => verify_ecdsa_p521(tbs_data, signature, cose_key),
        algorithms::EDDSA => verify_ed25519(tbs_data, signature, cose_key),
        _ => Err(MdocError::UnsupportedAlgorithm(format!(
            "COSE algorithm {alg_id}"
        ))),
    }
}

fn verify_ecdsa_p256(
    tbs_data: &[u8],
    signature: &[u8],
    cose_key: &coset::CoseKey,
) -> Result<bool, MdocError> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use signature::Verifier;

    let pub_bytes = cose_key.public_key_bytes()?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_bytes)
        .map_err(|e| MdocError::Signature(format!("P-256 key: {e}")))?;

    // ISO 18013-5 / COSE mandate the fixed-length raw r||s form (32+32 for
    // P-256). DER-encoded signatures are NOT accepted: doing so would widen the
    // parsing surface and admit non-canonical encodings a conformant COSE
    // verifier rejects (MEDIUM-2).
    if signature.len() != 64 {
        return Err(MdocError::Signature(format!(
            "ES256 signature must be 64-byte raw r||s, got {} bytes",
            signature.len()
        )));
    }
    let sig = Signature::from_slice(signature)
        .map_err(|e| MdocError::Signature(format!("P-256 sig: {e}")))?;

    Ok(verifying_key.verify(tbs_data, &sig).is_ok())
}

fn verify_ecdsa_p384(
    tbs_data: &[u8],
    signature: &[u8],
    cose_key: &coset::CoseKey,
) -> Result<bool, MdocError> {
    use p384::ecdsa::{Signature, VerifyingKey};
    use signature::Verifier;

    let pub_bytes = cose_key.public_key_bytes()?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_bytes)
        .map_err(|e| MdocError::Signature(format!("P-384 key: {e}")))?;

    // COSE mandates raw r||s (48+48 for P-384); reject DER (MEDIUM-2).
    if signature.len() != 96 {
        return Err(MdocError::Signature(format!(
            "ES384 signature must be 96-byte raw r||s, got {} bytes",
            signature.len()
        )));
    }
    let sig = Signature::from_slice(signature)
        .map_err(|e| MdocError::Signature(format!("P-384 sig: {e}")))?;

    Ok(verifying_key.verify(tbs_data, &sig).is_ok())
}

fn verify_ecdsa_p521(
    tbs_data: &[u8],
    signature: &[u8],
    cose_key: &coset::CoseKey,
) -> Result<bool, MdocError> {
    use p521::ecdsa::{Signature, VerifyingKey};
    use signature::Verifier;

    let pub_bytes = cose_key.public_key_bytes()?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_bytes)
        .map_err(|e| MdocError::Signature(format!("P-521 key: {e}")))?;

    // COSE mandates raw r||s; P-521 field elements are 66 bytes each (521 bits
    // rounded up), so the signature is 132 bytes. Reject DER (MEDIUM-2).
    if signature.len() != 132 {
        return Err(MdocError::Signature(format!(
            "ES512 signature must be 132-byte raw r||s, got {} bytes",
            signature.len()
        )));
    }
    // Raw r||s concatenation (66+66 bytes for P-521).
    let sig = Signature::from_slice(signature)
        .map_err(|e| MdocError::Signature(format!("P-521 sig: {e}")))?;

    Ok(verifying_key.verify(tbs_data, &sig).is_ok())
}

fn verify_ed25519(
    tbs_data: &[u8],
    signature: &[u8],
    cose_key: &coset::CoseKey,
) -> Result<bool, MdocError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pub_bytes = cose_key.public_key_bytes()?;

    if pub_bytes.len() != 32 {
        return Err(MdocError::Signature(format!(
            "Ed25519 key must be 32 bytes, got {}",
            pub_bytes.len()
        )));
    }

    let key_bytes: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| MdocError::Signature("Ed25519 key length".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| MdocError::Signature(format!("Ed25519 key: {e}")))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| MdocError::Signature("Ed25519 signature must be 64 bytes".to_string()))?;

    let sig = Signature::from_bytes(&sig_bytes);

    Ok(verifying_key.verify(tbs_data, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToSec1Point;

    fn p256_cose_key() -> coset::CoseKey {
        let sk = p256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap();
        let pk = p256::PublicKey::from(sk.verifying_key());
        let point = pk.to_sec1_point(false);
        coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .build()
    }

    #[test]
    fn der_encoded_es256_signature_is_rejected() {
        // MEDIUM-2: only fixed-length raw r||s is accepted; a DER-length
        // signature (e.g. 70/71/72 bytes) must be rejected, not parsed.
        let key = p256_cose_key();
        for len in [70usize, 71, 72] {
            let der_like = vec![0x30u8; len];
            let res = verify_cose_signature(b"message", &der_like, &key, algorithms::ES256);
            assert!(
                res.is_err(),
                "DER-length ({len}) signature must be rejected"
            );
        }
    }

    #[test]
    fn raw_rs_length_is_required() {
        let key = p256_cose_key();
        // 63 bytes (one short of raw r||s) must be rejected.
        assert!(verify_cose_signature(b"m", &[0u8; 63], &key, algorithms::ES256).is_err());
    }

    // ── ES512 / P-521 known-answer vector ───────────────────────────────────
    // P-521 ECDSA signature over the message below, produced with OpenSSL
    // (`openssl dgst -sha512 -sign`) over a freshly generated secp521r1 key.
    // p521 0.13 cannot derive a verifying key from a generated signing key, so
    // we pin a real vector to exercise the verification arm end to end.
    const P521_POINT_HEX: &str = "04004d094025302ae8650de954e88b7c9ece537f8805e1a6aa93ea81c24f2b937f2bdf111a3eb19c4cfa6e64cf57057d2ad72be45ec1c321495fa0d0287cbc96bfe6aa003c7a4aa96e1bec02d00343916609d9ab1373b82bae8dac7b1a1b9ab202784eec97fc03add136303f9abe94199f0189abef977830d4ce6f6b12e8d97f609e0b8b39";
    const P521_SIG_HEX: &str = "0012fcd041336a469dfb0a421cda7bb0e5964b1dadc586e57508adb26daa1de4bcac002a1bf4b689bf582b9a7b37570f9fb1dcc919433f4991ecdace09864cc022e901c9be99673eb84c97aff057549b655f1bd363413a0ce9a0e4f19abec89bddd746502af21a8907ec5c30d143196ba337fe2c26356a3707c741e43c975cd063413680";
    const P521_MSG: &[u8] = b"device authentication bytes";

    fn p521_cose_key() -> coset::CoseKey {
        let point = hex::decode(P521_POINT_HEX).unwrap();
        // Uncompressed SEC1 point: 0x04 || x(66) || y(66).
        let x = point[1..67].to_vec();
        let y = point[67..133].to_vec();
        coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_521, x, y).build()
    }

    #[test]
    fn es512_known_answer_verifies() {
        let key = p521_cose_key();
        let sig = hex::decode(P521_SIG_HEX).unwrap();
        assert_eq!(sig.len(), 132, "P-521 raw r||s is 132 bytes");
        assert!(
            verify_cose_signature(P521_MSG, &sig, &key, algorithms::ES512).unwrap(),
            "valid ES512 signature must verify"
        );
        // Flipping a low byte keeps r/s parseable as in-range scalars but
        // breaks the signature, so verification returns Ok(false).
        let mut bad = sig.clone();
        bad[131] ^= 0x01;
        assert!(!verify_cose_signature(P521_MSG, &bad, &key, algorithms::ES512).unwrap());
    }

    #[test]
    fn es512_rejects_wrong_length() {
        let key = p521_cose_key();
        // 131 bytes (one short of raw r||s) must be rejected, not parsed.
        assert!(verify_cose_signature(b"m", &[0u8; 131], &key, algorithms::ES512).is_err());
    }
}
