//! Session transcript construction (ISO 18013-5 §9.1.5).

use std::borrow::Cow;

use crate::cbor::data_item;
use crate::error::MdocError;

/// Session transcript for device authentication binding.
#[derive(Clone, Debug)]
pub enum SessionTranscript<'a> {
    /// ISO 18013-5 proximity mode (NFC/BLE).
    Proximity {
        device_engagement: Vec<u8>,
        e_reader_key: Vec<u8>,
    },
    /// ISO 18013-7 online mode (OpenID4VP).
    Oid4vp {
        mdoc_nonce: String,
        client_id: String,
        response_uri: String,
        verifier_nonce: String,
    },
    /// WebAPI mode.
    WebApi {
        device_engagement: Vec<u8>,
        reader_engagement: Vec<u8>,
        e_reader_key: Vec<u8>,
    },
    /// Pre-encoded transcript bytes.
    Raw(Cow<'a, [u8]>),
}

impl SessionTranscript<'_> {
    /// Encode the session transcript to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Cow<'_, [u8]>, MdocError> {
        let value = match self {
            Self::Proximity {
                device_engagement,
                e_reader_key,
            } => ciborium::Value::Array(vec![
                data_item::wrap_tag24(device_engagement),
                data_item::wrap_tag24(e_reader_key),
                ciborium::Value::Null,
            ]),
            Self::Oid4vp {
                mdoc_nonce,
                client_id,
                response_uri,
                verifier_nonce,
            } => {
                // OID4VP session transcript: [null, null, [mdocNonce, clientId, responseUri, verifierNonce]]
                ciborium::Value::Array(vec![
                    ciborium::Value::Null,
                    ciborium::Value::Null,
                    ciborium::Value::Array(vec![
                        ciborium::Value::Text(mdoc_nonce.clone()),
                        ciborium::Value::Text(client_id.clone()),
                        ciborium::Value::Text(response_uri.clone()),
                        ciborium::Value::Text(verifier_nonce.clone()),
                    ]),
                ])
            }
            Self::WebApi {
                device_engagement,
                reader_engagement,
                e_reader_key,
            } => ciborium::Value::Array(vec![
                data_item::wrap_tag24(device_engagement),
                data_item::wrap_tag24(e_reader_key),
                data_item::wrap_tag24(reader_engagement),
            ]),
            Self::Raw(bytes) => {
                return Ok(Cow::Borrowed(bytes));
            }
        };

        data_item::encode_cbor(&value).map(Cow::Owned)
    }
}

/// Build the `DeviceAuthentication` CBOR structure (ISO 18013-5 §9.1.3.1).
///
/// ```text
/// DeviceAuthentication = [
///   "DeviceAuthentication",
///   SessionTranscript,
///   DocType,
///   DeviceNameSpacesBytes
/// ]
/// ```
pub fn build_device_authentication_bytes(
    session_transcript_bytes: &[u8],
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
) -> Result<Vec<u8>, MdocError> {
    let transcript: ciborium::Value = ciborium::from_reader(session_transcript_bytes)
        .map_err(|e| MdocError::Session(format!("decode session transcript: {e}")))?;

    let value = ciborium::Value::Array(vec![
        ciborium::Value::Text("DeviceAuthentication".to_string()),
        transcript,
        ciborium::Value::Text(doc_type.to_string()),
        data_item::wrap_tag24(device_name_spaces_bytes),
    ]);

    data_item::encode_cbor(&value)
}

/// Derive the ephemeral MAC key using ECDH + HKDF (ISO 18013-5 §9.1.1.5).
///
/// 1. ECDH(device_private, reader_public) → shared_secret
/// 2. salt = SHA-256(session_transcript_bytes)
/// 3. HKDF-SHA256(ikm=shared_secret, salt=salt, info="EMacKey", len=32)
pub fn derive_ephemeral_mac_key(
    shared_secret: &[u8],
    session_transcript_bytes: &[u8],
) -> Result<[u8; 32], MdocError> {
    use hkdf::Hkdf;
    use sha2::Digest;

    let salt = sha2::Sha256::digest(session_transcript_bytes);
    let hk = Hkdf::<sha2::Sha256>::new(Some(&salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"EMacKey", &mut okm)
        .map_err(|e| MdocError::Session(format!("HKDF expand: {e}")))?;
    Ok(okm)
}
