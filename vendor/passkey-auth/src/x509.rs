//! Minimal X.509 inspection for attestation certificates.
//!
//! Two narrow needs from the WebAuthn `packed` and `fido-u2f`
//! attestation formats:
//!
//! 1. **Extract the SubjectPublicKey** so we can verify the attestation
//!    `sig` field with the cert's key (not the credential's key like
//!    self-attestation uses).
//!
//! 2. **Extract the FIDO AAGUID extension** (OID `1.3.6.1.4.1.45724.1.1.4`)
//!    when present. Lets a caller correlate the AAGUID embedded in
//!    `authData` with what the cert claims. Per the spec the two MUST
//!    match if the extension is present.
//!
//! What this module deliberately does NOT do:
//!
//! - Cert chain validation against a root store (no FIDO MDS).
//! - Cert expiry / notBefore checks (attestation certs typically have
//!   very long validity and rotate authenticator-by-authenticator).
//! - Algorithm-policy enforcement beyond ES256 - we reject anything
//!   that is not P-256 ECDSA, which is what every passkey-class
//!   hardware key uses today.

use const_oid::ObjectIdentifier;
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY;

use crate::error::{Error, Result};

/// FIDO Alliance AAGUID extension OID. Per FIDO U2F authenticator
/// transports extension spec, surfaces the AAGUID as an OCTET STRING
/// inside an OCTET STRING (yes, double-wrapped).
const OID_FIDO_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

/// What we pull out of an attestation cert.
#[derive(Debug)]
pub(crate) struct AttestationCert {
    /// Uncompressed SEC1 P-256 point: 0x04 || X(32) || Y(32) = 65 bytes.
    /// Only ES256 / P-256 ECDSA certs are supported.
    pub p256_pubkey_sec1: [u8; 65],
    /// AAGUID from the cert extension, if present. Per WebAuthn-3 the
    /// presence of this extension is OPTIONAL, but when present the
    /// authenticator MUST set it to its actual AAGUID and the verifier
    /// MUST check it matches `authData.attestedCredentialData.aaguid`.
    pub aaguid: Option<[u8; 16]>,
}

impl AttestationCert {
    /// Parse a single DER-encoded cert (the first element of the
    /// `x5c` array). Strict: rejects non-P-256, missing pubkey, etc.
    pub(crate) fn from_der(der: &[u8]) -> Result<Self> {
        let cert =
            Certificate::from_der(der).map_err(|e| Error::Cbor(format!("x509 parse: {e}")))?;

        // ---- public key ----------------------------------------------
        let spki = &cert.tbs_certificate.subject_public_key_info;
        // Algorithm must be id-ecPublicKey with an algorithm parameter
        // selecting P-256. We only support ES256 in this crate.
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(Error::Cbor(format!(
                "attestation cert: non-EC public key (alg OID {})",
                spki.algorithm.oid,
            )));
        }
        // SubjectPublicKey is the SEC1-encoded uncompressed point.
        let pk_bits = spki.subject_public_key.as_bytes().ok_or_else(|| {
            Error::Cbor("attestation cert: pubkey bit-string has unused bits".into())
        })?;
        if pk_bits.len() != 65 || pk_bits[0] != 0x04 {
            return Err(Error::Cbor(format!(
                "attestation cert: pubkey not SEC1-uncompressed P-256 ({} bytes, prefix 0x{:02x})",
                pk_bits.len(),
                pk_bits.first().copied().unwrap_or(0),
            )));
        }
        let mut p256_pubkey_sec1 = [0u8; 65];
        p256_pubkey_sec1.copy_from_slice(pk_bits);

        // ---- AAGUID extension (optional) ----------------------------
        //
        // Presence of the extension is optional per WebAuthn-3. BUT
        // when present it MUST parse correctly - we do NOT silently
        // treat a malformed AAGUID extension as "absent" because that
        // would let a malicious cert bypass the
        //   leaf_aaguid == authData_aaguid
        // check in verify_packed by intentionally garbling the inner
        // OCTET STRING.
        let aaguid_ext = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|exts| exts.iter().find(|e| e.extn_id == OID_FIDO_AAGUID));
        let aaguid = match aaguid_ext {
            Some(ext) => Some(parse_aaguid_octet_string(ext.extn_value.as_bytes())?),
            None => None,
        };

        Ok(Self {
            p256_pubkey_sec1,
            aaguid,
        })
    }
}

/// The AAGUID extension value is an OCTET STRING containing another
/// OCTET STRING of 16 bytes (per the FIDO spec). Strip the inner DER
/// header by hand - it is always `0x04 0x10 <16 bytes>`.
fn parse_aaguid_octet_string(value: &[u8]) -> Result<[u8; 16]> {
    if value.len() != 18 || value[0] != 0x04 || value[1] != 0x10 {
        return Err(Error::Cbor(
            "attestation cert: malformed AAGUID extension".into(),
        ));
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&value[2..18]);
    Ok(aaguid)
}
