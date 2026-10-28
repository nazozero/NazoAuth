//! COSE Key conversion utilities.
//!
//! Convert between `coset::CoseKey` and RustCrypto types for signature
//! verification and ECDH operations.

use crate::error::MdocError;
use coset::iana;

/// Extension trait for `coset::CoseKey` with mdoc-specific operations.
pub trait CoseKeyExt {
    /// Extract the raw public key bytes (uncompressed point for EC2, or raw for OKP).
    fn public_key_bytes(&self) -> Result<Vec<u8>, MdocError>;

    /// Get the COSE algorithm identifier.
    fn algorithm(&self) -> Result<i64, MdocError>;

    /// Get the curve identifier.
    fn curve(&self) -> Result<i64, MdocError>;
}

impl CoseKeyExt for coset::CoseKey {
    fn public_key_bytes(&self) -> Result<Vec<u8>, MdocError> {
        let kty = self.kty.clone();

        match kty {
            coset::KeyType::Assigned(iana::KeyType::EC2) => {
                // EC2 key: extract x and y coordinates
                let x = get_param(&self.params, iana::Ec2KeyParameter::X as i64)?;
                let y = get_param(&self.params, iana::Ec2KeyParameter::Y as i64)?;
                // Uncompressed point: 0x04 || x || y
                let mut bytes = Vec::with_capacity(1 + x.len() + y.len());
                bytes.push(0x04);
                bytes.extend_from_slice(&x);
                bytes.extend_from_slice(&y);
                Ok(bytes)
            }
            coset::KeyType::Assigned(iana::KeyType::OKP) => {
                // OKP key: extract x coordinate (raw public key)
                let x = get_param(&self.params, iana::OkpKeyParameter::X as i64)?;
                Ok(x)
            }
            _ => Err(MdocError::Cose(format!("unsupported key type: {:?}", kty))),
        }
    }

    fn algorithm(&self) -> Result<i64, MdocError> {
        match &self.alg {
            Some(coset::Algorithm::Assigned(a)) => Ok(*a as i64),
            Some(coset::Algorithm::PrivateUse(v)) => Ok(*v),
            _ => Err(MdocError::Cose("missing algorithm in COSE key".to_string())),
        }
    }

    fn curve(&self) -> Result<i64, MdocError> {
        let kty = self.kty.clone();
        match kty {
            coset::KeyType::Assigned(iana::KeyType::EC2) => {
                // Look for crv parameter (label -1)
                for (label, value) in &self.params {
                    if let coset::Label::Int(-1) = label {
                        if let ciborium::Value::Integer(crv) = value {
                            return Ok({
                                let v: i128 = (*crv).into();
                                v
                            } as i64);
                        }
                    }
                }
                Err(MdocError::Cose("missing curve in EC2 key".to_string()))
            }
            coset::KeyType::Assigned(iana::KeyType::OKP) => {
                for (label, value) in &self.params {
                    if let coset::Label::Int(-1) = label {
                        if let ciborium::Value::Integer(crv) = value {
                            return Ok(i128::from(*crv) as i64);
                        }
                    }
                }
                Err(MdocError::Cose("missing curve in OKP key".to_string()))
            }
            _ => Err(MdocError::Cose(format!("unsupported key type: {:?}", kty))),
        }
    }
}

/// Extract a byte-string parameter from COSE key params by label.
fn get_param(params: &[(coset::Label, ciborium::Value)], label: i64) -> Result<Vec<u8>, MdocError> {
    for (l, v) in params {
        if let coset::Label::Int(n) = l {
            if *n == label {
                if let ciborium::Value::Bytes(b) = v {
                    return Ok(b.clone());
                }
            }
        }
    }
    Err(MdocError::Cose(format!(
        "missing COSE key parameter with label {label}"
    )))
}

/// Map COSE algorithm identifier to human-readable name.
pub fn cose_alg_to_name(alg: i64) -> &'static str {
    match alg {
        -7 => "ES256",
        -35 => "ES384",
        -36 => "ES512",
        -8 => "EdDSA",
        5 => "HMAC256",
        6 => "HMAC384",
        7 => "HMAC512",
        _ => "unknown",
    }
}

/// Build an EC2 `coset::CoseKey` from an uncompressed SEC1 public point
/// (`0x04 || x || y`).
///
/// `curve_id` is a COSE curve identifier (see [`curves`]): P-256 (1), P-384 (2),
/// or P-521 (3). Smooths device-key input during issuance, where callers
/// otherwise have to hand-assemble a `CoseKeyBuilder` (improvement #9).
pub fn cose_key_from_sec1_bytes(curve_id: i64, point: &[u8]) -> Result<coset::CoseKey, MdocError> {
    let (curve, coord_len) = match curve_id {
        curves::P256 => (iana::EllipticCurve::P_256, 32usize),
        curves::P384 => (iana::EllipticCurve::P_384, 48),
        curves::P521 => (iana::EllipticCurve::P_521, 66),
        other => {
            return Err(MdocError::Cose(format!(
                "unsupported curve id {other} (expected P-256/384/521)"
            )))
        }
    };

    if point.len() != 1 + 2 * coord_len || point[0] != 0x04 {
        return Err(MdocError::Cose(format!(
            "expected uncompressed SEC1 point (0x04 + {} bytes), got {} bytes",
            2 * coord_len,
            point.len()
        )));
    }

    let x = point[1..1 + coord_len].to_vec();
    let y = point[1 + coord_len..].to_vec();
    Ok(coset::CoseKeyBuilder::new_ec2_pub_key(curve, x, y).build())
}

/// Build an EC2 `coset::CoseKey` from a PEM-encoded `SubjectPublicKeyInfo`
/// (the `-----BEGIN PUBLIC KEY-----` form), mapping the named curve
/// (P-256/384/521) to the COSE `crv` (improvement #9).
pub fn cose_key_from_pem(pem: &str) -> Result<coset::CoseKey, MdocError> {
    use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
    use der::DecodePem;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::from_pem(pem.as_bytes())
        .map_err(|e| MdocError::Cose(format!("parse SubjectPublicKeyInfo PEM: {e}")))?;

    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(MdocError::Cose(format!(
            "not an EC public key (algorithm OID {})",
            spki.algorithm.oid
        )));
    }

    // The named-curve OID is carried in the algorithm parameters.
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| MdocError::Cose("EC public key missing curve parameters".to_string()))?
        .decode_as::<der::asn1::ObjectIdentifier>()
        .map_err(|e| MdocError::Cose(format!("decode EC curve OID: {e}")))?;

    let curve_id = match curve_oid {
        SECP_256_R_1 => curves::P256,
        SECP_384_R_1 => curves::P384,
        SECP_521_R_1 => curves::P521,
        other => {
            return Err(MdocError::Cose(format!("unsupported EC curve OID {other}")));
        }
    };

    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| MdocError::Cose("EC public key is not byte-aligned".to_string()))?;

    cose_key_from_sec1_bytes(curve_id, point)
}

/// COSE curve identifiers.
pub mod curves {
    pub const P256: i64 = 1;
    pub const P384: i64 = 2;
    pub const P521: i64 = 3;
    pub const ED25519: i64 = 6;
}

/// COSE algorithm identifiers.
pub mod algorithms {
    pub const ES256: i64 = -7;
    pub const ES384: i64 = -35;
    pub const ES512: i64 = -36;
    pub const EDDSA: i64 = -8;
    pub const HMAC256: i64 = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkkMIHcZAXvdMoVYC+SWxjqo52Vx3\ncf7F60N4hHF0YU3gPJY8I8C4Cbzfgy95fmgo8ixHpts1CeArK45q9hMsVA==\n-----END PUBLIC KEY-----\n";
    const P521_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBQF1zqB0Ee3LO98QLvzquEuZMJLQJ\n4H694x92BAEW84Cnap0V9bRe6jtbNFxStdd94m61Peyzq9IaeflZe9J+/n4Aet1R\nBDyAT7NBFVFQ5dgg6i0XMdlgh3n/fTAHkXxTmL7KcmuDXhoD3gw1bnBMnbqQmgmy\nf8FgQTm9YZArU6O1voU=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn pem_p256_maps_to_p256_curve() {
        let key = cose_key_from_pem(P256_PUB_PEM).expect("parse P-256 PEM");
        assert_eq!(key.curve().unwrap(), curves::P256);
        // public_key_bytes returns 0x04 || x(32) || y(32) = 65 bytes.
        assert_eq!(key.public_key_bytes().unwrap().len(), 65);
    }

    #[test]
    fn pem_p521_maps_to_p521_curve() {
        let key = cose_key_from_pem(P521_PUB_PEM).expect("parse P-521 PEM");
        assert_eq!(key.curve().unwrap(), curves::P521);
        // 0x04 || x(66) || y(66) = 133 bytes.
        assert_eq!(key.public_key_bytes().unwrap().len(), 133);
    }

    #[test]
    fn sec1_round_trips_through_cose_key() {
        // Build from PEM, extract SEC1, rebuild from SEC1, expect the same point.
        let from_pem = cose_key_from_pem(P256_PUB_PEM).unwrap();
        let sec1 = from_pem.public_key_bytes().unwrap();
        let from_sec1 = cose_key_from_sec1_bytes(curves::P256, &sec1).unwrap();
        assert_eq!(
            from_sec1.public_key_bytes().unwrap(),
            sec1,
            "round trip must preserve the point"
        );
    }

    #[test]
    fn sec1_rejects_wrong_length() {
        // 0x04 prefix but too short for P-256.
        assert!(cose_key_from_sec1_bytes(curves::P256, &[0x04; 40]).is_err());
    }
}
