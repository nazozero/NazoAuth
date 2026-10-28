//! DeviceResponse builder for presentations (feature: `issue`).

use std::collections::HashMap;

use crate::cbor::data_item;
use crate::error::MdocError;
use crate::model::document::{DeviceSigned, IssuerSignedDocument};
use crate::model::mdoc::{MDoc, MDocStatus};
use crate::model::types::DeviceAuth;
use crate::session::{self, SessionTranscript};

/// Builder for creating device response presentations with selective disclosure.
pub struct DeviceResponseBuilder<'a> {
    documents: Vec<IssuerSignedDocument>,
    session_transcript: Option<SessionTranscript<'a>>,
    device_name_spaces: HashMap<String, HashMap<String, ciborium::Value>>,
    auth_method: Option<DeviceAuthMethod>,
}

enum DeviceAuthMethod {
    Signature {
        device_key_der: Vec<u8>,
        algorithm: i64,
    },
    Mac {
        device_key_der: Vec<u8>,
        reader_pub_key_der: Vec<u8>,
    },
}

impl<'a> DeviceResponseBuilder<'a> {
    /// Create a builder from existing issuer-signed documents.
    pub fn from_documents(documents: Vec<IssuerSignedDocument>) -> Self {
        Self {
            documents,
            session_transcript: None,
            device_name_spaces: HashMap::new(),
            auth_method: None,
        }
    }

    /// Set the session transcript.
    pub fn session_transcript(mut self, transcript: SessionTranscript<'a>) -> Self {
        self.session_transcript = Some(transcript);
        self
    }

    /// Add device-provided attributes.
    pub fn add_device_namespace(
        mut self,
        namespace: &str,
        data: HashMap<String, ciborium::Value>,
    ) -> Self {
        self.device_name_spaces.insert(namespace.to_string(), data);
        self
    }

    /// Authenticate with a device signature (COSE_Sign1).
    pub fn authenticate_with_signature(
        mut self,
        device_key_der: Vec<u8>,
        cose_algorithm: i64,
    ) -> Self {
        self.auth_method = Some(DeviceAuthMethod::Signature {
            device_key_der,
            algorithm: cose_algorithm,
        });
        self
    }

    /// Authenticate with a MAC (COSE_Mac0 via ECDH).
    pub fn authenticate_with_mac(
        mut self,
        device_key_der: Vec<u8>,
        reader_pub_key_der: Vec<u8>,
    ) -> Self {
        self.auth_method = Some(DeviceAuthMethod::Mac {
            device_key_der,
            reader_pub_key_der,
        });
        self
    }

    /// Build the device response.
    pub fn build(self) -> Result<MDoc, MdocError> {
        let transcript = self
            .session_transcript
            .ok_or_else(|| MdocError::Issuance("missing session transcript".to_string()))?;

        let auth = self
            .auth_method
            .ok_or_else(|| MdocError::Issuance("missing authentication method".to_string()))?;

        let transcript_bytes = transcript.to_cbor_bytes()?;

        let mut result_documents = Vec::new();

        for mut doc in self.documents {
            // Build DeviceNameSpaces CBOR
            let device_ns_cbor = if self.device_name_spaces.is_empty() {
                ciborium::Value::Map(vec![])
            } else {
                let entries: Vec<(ciborium::Value, ciborium::Value)> = self
                    .device_name_spaces
                    .iter()
                    .map(|(ns, elems)| {
                        let elem_entries: Vec<(ciborium::Value, ciborium::Value)> = elems
                            .iter()
                            .map(|(k, v)| (ciborium::Value::Text(k.clone()), v.clone()))
                            .collect();
                        (
                            ciborium::Value::Text(ns.clone()),
                            ciborium::Value::Map(elem_entries),
                        )
                    })
                    .collect();
                ciborium::Value::Map(entries)
            };

            let device_ns_bytes = data_item::encode_cbor(&device_ns_cbor)?;

            // Build DeviceAuthentication bytes
            let device_auth_bytes = session::build_device_authentication_bytes(
                &transcript_bytes,
                &doc.doc_type,
                &device_ns_bytes,
            )?;

            // Create the device authentication
            let device_auth = match &auth {
                DeviceAuthMethod::Signature {
                    device_key_der,
                    algorithm,
                } => build_device_signature(device_key_der, *algorithm, &device_auth_bytes)?,
                DeviceAuthMethod::Mac {
                    device_key_der,
                    reader_pub_key_der,
                } => build_device_mac(
                    device_key_der,
                    reader_pub_key_der,
                    &transcript_bytes,
                    &device_auth_bytes,
                )?,
            };

            doc.device_signed = Some(DeviceSigned {
                device_auth,
                name_spaces: self.device_name_spaces.clone(),
                // Preserve the exact inner DeviceNameSpaces bytes used to build
                // DeviceAuthentication, so a later verifier reconstructs the
                // identical signed/MAC'd structure.
                name_spaces_bytes: device_ns_bytes.clone(),
            });

            result_documents.push(doc);
        }

        Ok(MDoc {
            version: "1.0".to_string(),
            status: MDocStatus::Ok,
            documents: result_documents,
        })
    }
}

/// Create a COSE_Sign1 device signature over DeviceAuthentication.
fn build_device_signature(
    device_key_der: &[u8],
    algorithm: i64,
    device_auth_bytes: &[u8],
) -> Result<DeviceAuth, MdocError> {
    use crate::cose::key::algorithms;
    use coset::iana;

    let alg = match algorithm {
        algorithms::ES256 => iana::Algorithm::ES256,
        algorithms::ES384 => iana::Algorithm::ES384,
        algorithms::EDDSA => iana::Algorithm::EdDSA,
        other => {
            return Err(MdocError::Issuance(format!(
                "unsupported device auth algorithm: {other}"
            )));
        }
    };

    let protected = coset::HeaderBuilder::new().algorithm(alg).build();

    // Sign with device private key
    let signature = sign_with_device_key(device_key_der, algorithm, device_auth_bytes)?;

    // Build COSE_Sign1 with detached payload (payload = None)
    let sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(device_auth_bytes.to_vec())
        .signature(signature)
        .build();

    Ok(DeviceAuth::Signature(sign1))
}

/// Create a COSE_Mac0 device MAC using ECDH-derived ephemeral key.
fn build_device_mac(
    device_key_der: &[u8],
    reader_pub_key_der: &[u8],
    transcript_bytes: &[u8],
    device_auth_bytes: &[u8],
) -> Result<DeviceAuth, MdocError> {
    use coset::iana;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Derive shared secret via ECDH
    let shared_secret = ecdh_shared_secret(device_key_der, reader_pub_key_der)?;

    // Derive ephemeral MAC key
    let mac_key = session::derive_ephemeral_mac_key(&shared_secret, transcript_bytes)?;

    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::HMAC_256_256)
        .build();

    // Build MAC structure
    let mac_structure = coset::mac_structure_data(
        coset::MacContext::CoseMac0,
        coset::ProtectedHeader {
            original_data: None,
            header: protected.clone(),
        },
        &[],
        device_auth_bytes,
    );

    // Compute HMAC-SHA256
    let mut hmac = Hmac::<Sha256>::new_from_slice(&mac_key)
        .map_err(|e| MdocError::Issuance(format!("HMAC init: {e}")))?;
    hmac.update(&mac_structure);
    let tag = hmac.finalize().into_bytes().to_vec();

    let mac0 = coset::CoseMac0Builder::new()
        .protected(protected)
        .payload(device_auth_bytes.to_vec())
        .tag(tag)
        .build();

    Ok(DeviceAuth::Mac(mac0))
}

/// Sign data with a device private key (ES256/ES384/EdDSA).
fn sign_with_device_key(key_der: &[u8], algorithm: i64, data: &[u8]) -> Result<Vec<u8>, MdocError> {
    use crate::cose::key::algorithms;

    match algorithm {
        algorithms::ES256 => {
            use p256::ecdsa::{Signature, SigningKey};
            use signature::Signer;

            let sk = SigningKey::from_slice(key_der)
                .map_err(|e| MdocError::Issuance(format!("P-256 signing key: {e}")))?;
            let sig: Signature = sk
                .try_sign(data)
                .map_err(|e| MdocError::Issuance(format!("P-256 sign: {e}")))?;
            // Return raw r||s format for COSE
            Ok(sig.to_bytes().to_vec())
        }
        algorithms::ES384 => {
            use p384::ecdsa::{Signature, SigningKey};
            use signature::Signer;

            let sk = SigningKey::from_slice(key_der)
                .map_err(|e| MdocError::Issuance(format!("P-384 signing key: {e}")))?;
            let sig: Signature = sk
                .try_sign(data)
                .map_err(|e| MdocError::Issuance(format!("P-384 sign: {e}")))?;
            Ok(sig.to_bytes().to_vec())
        }
        algorithms::EDDSA => {
            use ed25519_dalek::{Signer, SigningKey};

            let key_bytes: [u8; 32] = key_der
                .try_into()
                .map_err(|_| MdocError::Issuance("Ed25519 key must be 32 bytes".to_string()))?;
            let sk = SigningKey::from_bytes(&key_bytes);
            let sig = sk.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(MdocError::Issuance(format!(
            "unsupported signing algorithm: {algorithm}"
        ))),
    }
}

/// Perform ECDH to get shared secret (P-256 only for now).
fn ecdh_shared_secret(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, MdocError> {
    use p256::{PublicKey, SecretKey};

    let sk = SecretKey::from_slice(private_key)
        .map_err(|e| MdocError::Issuance(format!("ECDH private key: {e}")))?;

    let pk = PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| MdocError::Issuance(format!("ECDH public key: {e}")))?;

    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}
