//! COSE_Key (RFC 8152) parsing - narrow to the algorithms passkeys
//! actually use: ES256 (EC2 / P-256) and EdDSA (OKP / Ed25519).
//!
//! Key layout (CBOR map):
//! ```text
//!   1 (kty):       EC2=2, OKP=1
//!   3 (alg):       -7 = ES256, -8 = EdDSA, ...
//!  -1 (crv):       P-256=1, Ed25519=6
//!  -2 (x):         bstr (32 bytes for both)
//!  -3 (y):         bstr (P-256 only)
//! ```

use ciborium::value::Value as CborValue;

use crate::error::{Error, Result};

pub(crate) const ALG_ES256: i64 = -7;
pub(crate) const ALG_EDDSA: i64 = -8;

const KTY: i64 = 1;
const ALG: i64 = 3;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;

const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

#[derive(Debug, Clone)]
pub(crate) enum CoseKey {
    /// ECDSA on the NIST P-256 curve, hashed with SHA-256.
    /// `x` + `y` are the uncompressed-point coordinates, 32 bytes each.
    Es256 { x: [u8; 32], y: [u8; 32] },
    /// Ed25519 with EdDSA. `key` is the 32-byte compressed public key.
    Ed25519 { key: [u8; 32] },
}

impl CoseKey {
    /// Parse a COSE_Key CBOR blob (as stored in our DB or as carried
    /// in `attestedCredentialData.credentialPublicKey`).
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let v: CborValue =
            ciborium::de::from_reader(bytes).map_err(|e| Error::Cbor(format!("cose: {e}")))?;
        let map = match v {
            CborValue::Map(m) => m,
            _ => return Err(Error::Cbor("cose: top-level not a map".into())),
        };

        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;

        for (k, val) in map {
            let key = match k {
                CborValue::Integer(i) => i128::from(i) as i64,
                _ => continue, // ignore string-keyed extensions
            };
            match key {
                KTY => kty = i64_of(&val),
                ALG => alg = i64_of(&val),
                CRV => crv = i64_of(&val),
                X => x = bytes_of(&val),
                Y => y = bytes_of(&val),
                _ => {} // ignore unknown
            }
        }

        let kty = kty.ok_or_else(|| Error::Cbor("cose: missing kty".into()))?;
        let alg = alg.ok_or_else(|| Error::Cbor("cose: missing alg".into()))?;

        match (kty, alg) {
            (KTY_EC2, ALG_ES256) => {
                if crv != Some(CRV_P256) {
                    return Err(Error::Cbor("cose: ES256 expects crv=P-256".into()));
                }
                let xb = x.ok_or_else(|| Error::Cbor("cose: missing x".into()))?;
                let yb = y.ok_or_else(|| Error::Cbor("cose: missing y".into()))?;
                if xb.len() != 32 || yb.len() != 32 {
                    return Err(Error::Cbor("cose: P-256 coords must be 32 bytes".into()));
                }
                let mut xa = [0u8; 32];
                let mut ya = [0u8; 32];
                xa.copy_from_slice(&xb);
                ya.copy_from_slice(&yb);
                Ok(Self::Es256 { x: xa, y: ya })
            }
            (KTY_OKP, ALG_EDDSA) => {
                if crv != Some(CRV_ED25519) {
                    return Err(Error::Cbor("cose: EdDSA expects crv=Ed25519".into()));
                }
                let xb = x.ok_or_else(|| Error::Cbor("cose: missing x".into()))?;
                if xb.len() != 32 {
                    return Err(Error::Cbor("cose: Ed25519 key must be 32 bytes".into()));
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(&xb);
                Ok(Self::Ed25519 { key: k })
            }
            _ => Err(Error::UnsupportedAlg(alg)),
        }
    }

    pub(crate) fn alg(&self) -> i64 {
        match self {
            Self::Es256 { .. } => ALG_ES256,
            Self::Ed25519 { .. } => ALG_EDDSA,
        }
    }
}

fn i64_of(v: &CborValue) -> Option<i64> {
    match v {
        CborValue::Integer(i) => Some(i128::from(*i) as i64),
        _ => None,
    }
}

fn bytes_of(v: &CborValue) -> Option<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ES256 COSE key and round-trip it.
    #[test]
    fn parse_es256_key() {
        // CBOR for { 1: 2, 3: -7, -1: 1, -2: h'<32x>', -3: h'<32y>' }
        // 5-entry map (0xa5), small ints fit in single bytes.
        let mut cbor = vec![0xa5];
        // 1: 2
        cbor.extend_from_slice(&[0x01, 0x02]);
        // 3: -7  (negative integer -7 encodes as major-1 value 6 = 0x26)
        cbor.extend_from_slice(&[0x03, 0x26]);
        // -1: 1
        cbor.extend_from_slice(&[0x20, 0x01]);
        // -2: bytes(32 of 0xAA)
        cbor.extend_from_slice(&[0x21, 0x58, 0x20]);
        cbor.extend(std::iter::repeat_n(0xAA, 32));
        // -3: bytes(32 of 0xBB)
        cbor.extend_from_slice(&[0x22, 0x58, 0x20]);
        cbor.extend(std::iter::repeat_n(0xBB, 32));
        let parsed = CoseKey::parse(&cbor).unwrap();
        match parsed {
            CoseKey::Es256 { x, y } => {
                assert_eq!(x, [0xAA; 32]);
                assert_eq!(y, [0xBB; 32]);
            }
            _ => panic!("expected ES256"),
        }
    }
}
